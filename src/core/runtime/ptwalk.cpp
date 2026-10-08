// src/core/runtime/ptwalk.cpp
// the kernel scratch window forges a pte for an unused page inside the
// driver's own image and drives all access through the kernel read/write
// ioctls, so a foreign frame is never mapped at a user va in our process.
// every foreign table write goes through the window with readback checks

#include "core/runtime/ptwalk.hpp"
#include "core/runtime/xorstr.hpp"
#include "core/runtime/lazy_import.hpp"
#include <tlhelp32.h>
#include <vector>

#include <windows.h>
#include <algorithm>
#include <cstring>
#include <intrin.h>

namespace slop::core::runtime::ptwalk {

namespace {

std::uint64_t g_pte_base = 0;
std::uint64_t g_nt_base = 0;

// kernel scratch: an unused page inside the driver image whose original pte
// we save and restore. user scratch is the fallback when no slack page exists
std::uint64_t g_kernel_scratch_va = 0;
std::uint64_t g_kernel_scratch_orig_pte = 0;
bool g_kernel_scratch_in_use = false;

void* g_user_scratch = nullptr;

std::uint64_t resolve_kernel_export(winotify::driver_t& dev, std::uint64_t nt,
                                    const char* want) {
    std::uint8_t dos[0x40] = {};
    if (!dev.kernel_read(nt, dos, sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z') return 0;
    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(dos + 0x3C);
    std::uint8_t opt[0x40] = {};
    if (!dev.kernel_read(nt + e_lfanew + 0x18, opt, sizeof(opt))) return 0;
    const std::uint32_t export_rva = *reinterpret_cast<const std::uint32_t*>(opt + 0x70);
    if (!export_rva) return 0;

    std::uint8_t dir[0x28] = {};
    if (!dev.kernel_read(nt + export_rva, dir, sizeof(dir))) return 0;
    const std::uint32_t num_names = *reinterpret_cast<const std::uint32_t*>(dir + 0x18);
    const std::uint32_t functions_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x1C);
    const std::uint32_t names_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x20);
    const std::uint32_t ordinals_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x24);

    const std::size_t want_len = std::strlen(want);
    for (std::uint32_t i = 0; i < num_names; ++i) {
        std::uint8_t rva_buf[4] = {};
        if (!dev.kernel_read(nt + names_rva + i * 4, rva_buf, 4)) break;
        const std::uint32_t name_rva = *reinterpret_cast<const std::uint32_t*>(rva_buf);
        char name[48] = {};
        if (!dev.kernel_read(nt + name_rva, name, sizeof(name) - 1)) continue;
        if (std::strncmp(name, want, want_len) != 0 || name[want_len] != '\0') continue;
        std::uint8_t ord_buf[2] = {};
        if (!dev.kernel_read(nt + ordinals_rva + i * 2, ord_buf, 2)) break;
        const std::uint16_t ord = *reinterpret_cast<const std::uint16_t*>(ord_buf);
        std::uint8_t fn_buf[4] = {};
        if (!dev.kernel_read(nt + functions_rva + ord * 4, fn_buf, 4)) break;
        return nt + *reinterpret_cast<const std::uint32_t*>(fn_buf);
    }
    return 0;
}

bool init_user_scratch() {
    if (g_user_scratch) return true;
    g_user_scratch = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!g_user_scratch) return false;
    std::memset(g_user_scratch, 0xCC, 0x1000);
    DWORD old = 0;
    VirtualProtect(g_user_scratch, 0x1000, PAGE_NOACCESS, &old);
    return true;
}

// find a full page of slack at the tail of the driver image: needs to be
// mostly padding so mapping it out for the window duration is harmless
bool init_kernel_scratch(winotify::driver_t& dev) {
    if (g_kernel_scratch_va) return true;
    const std::uint64_t drv = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv) return false;
    const std::uint64_t size = kernel_module_size(dev, drv);
    if (size < 0x2000) return false;

    const std::uint64_t candidate = (drv + size - 0x1000) & ~0xFFFull;
    std::vector<std::uint8_t> page(0x1000);
    if (!dev.kernel_read(candidate, page.data(), page.size())) return false;
    std::size_t slack = 0;
    for (std::uint8_t b : page) {
        if (b == 0x00 || b == 0xCC) ++slack;
    }
    if (slack < page.size() * 3 / 4) return false;

    table_entry_t cur{};
    if (!read_pte_va(dev, candidate, cur) || !cur.present()) return false;
    g_kernel_scratch_va = candidate;
    g_kernel_scratch_orig_pte = cur.raw;
    return true;
}

} // namespace

std::uint64_t pte_slot_va(std::uint64_t va) noexcept {
    return pte_base() + ((va >> 12) << 3);
}
std::uint64_t pde_slot_va(std::uint64_t va) noexcept {
    return pte_base() + ((va >> 21) << 3);
}
std::uint64_t pdpte_slot_va(std::uint64_t va) noexcept {
    return pte_base() + ((va >> 30) << 3);
}
std::uint64_t pml4e_slot_va(std::uint64_t va) noexcept {
    return pte_base() + ((va >> 39) << 3);
}

bool ensure_pte_base(winotify::driver_t& dev) {
    if (g_pte_base) return true;
    if (!g_nt_base) g_nt_base = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!g_nt_base) return false;

    const std::uint64_t fn = resolve_kernel_export(dev, g_nt_base, "MmGetVirtualForPhysical");
    if (!fn) return false;
    std::uint8_t code[0x40] = {};
    if (!dev.kernel_read(fn, code, sizeof(code))) return false;

    for (std::size_t i = 0; i + 10 <= sizeof(code); ++i) {
        if (code[i] == 0x48 && code[i + 1] == 0xB8) {
            std::uint64_t v = *reinterpret_cast<const std::uint64_t*>(code + i + 2);
            if ((v >> 48) == 0xFFFF && (v & 0x0000FFFF00000007ull) == 0) {
                g_pte_base = v;
                return true;
            }
        }
    }
    for (std::size_t i = 0; i + 7 <= sizeof(code); ++i) {
        if (code[i] == 0x48 && (code[i + 1] & 0xF8) == 0x05 &&
            (code[i + 2] & 0xC7) == 0x05) {
            const std::int32_t disp = *reinterpret_cast<const std::int32_t*>(code + i + 3);
            const std::uint64_t v = fn + i + 7 + disp;
            if ((v >> 48) == 0xFFFF) {
                g_pte_base = v;
                return true;
            }
        }
    }
    return false;
}

std::uint64_t pte_base() noexcept { return g_pte_base; }

std::uint64_t kernel_export_va(winotify::driver_t& dev, const char* name) {
    if (!g_nt_base) g_nt_base = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!g_nt_base) return 0;
    return resolve_kernel_export(dev, g_nt_base, name);
}

std::uint64_t kernel_module_size(winotify::driver_t& dev, std::uint64_t base) {
    const std::uint64_t head = kernel_export_va(dev, "PsLoadedModuleList");
    if (!head) return 0;
    std::uint8_t head_buf[8] = {};
    if (!dev.kernel_read(head, head_buf, 8)) return 0;
    std::uint64_t cur = *reinterpret_cast<const std::uint64_t*>(head_buf);
    for (int guard = 0; guard < 1024 && cur && cur != head; ++guard) {
        std::uint8_t entry[0x48] = {};
        if (!dev.kernel_read(cur, entry, sizeof(entry))) break;
        const std::uint64_t flink = *reinterpret_cast<const std::uint64_t*>(entry);
        if (*reinterpret_cast<const std::uint64_t*>(entry + 0x30) == base) {
            return *reinterpret_cast<const std::uint32_t*>(entry + 0x40);
        }
        cur = flink;
    }
    return 0;
}

bool read_pte_va(winotify::driver_t& dev, std::uint64_t va, table_entry_t& out) {
    if (!g_pte_base) return false;
    std::uint8_t buf[8] = {};
    if (!dev.kernel_read(pte_slot_va(va), buf, sizeof(buf))) return false;
    std::memcpy(&out.raw, buf, sizeof(out.raw));
    return true;
}

bool write_pte_va(winotify::driver_t& dev, std::uint64_t va, std::uint64_t raw) {
    if (!g_pte_base) return false;
    if (!dev.kernel_write(pte_slot_va(va), &raw, sizeof(raw))) return false;
    std::uint8_t buf[8] = {};
    if (!dev.kernel_read(pte_slot_va(va), buf, sizeof(buf))) return false;
    std::uint64_t back = 0;
    std::memcpy(&back, buf, sizeof(back));
    return back == raw;
}

std::uint64_t translate_own(winotify::driver_t& dev, std::uint64_t va) {
    table_entry_t pte{};
    if (!read_pte_va(dev, va, pte) || !pte.present() || pte.large()) return 0;
    return pte.frame() | (va & 0xFFFull);
}

bool window_t::read(std::uint64_t pa_off, void* buf, std::size_t len) {
    if (!valid() || pa_off + len > 0x1000) return false;
    return kernel
        ? dev->kernel_read(kva + pa_off, buf, len)
        : std::memcpy(buf, reinterpret_cast<const void*>(kva + pa_off), len), true;
}

bool window_t::write(std::uint64_t pa_off, const void* buf, std::size_t len) {
    if (!valid() || pa_off + len > 0x1000) return false;
    if (kernel) {
        if (!dev->kernel_write(kva + pa_off, buf, len)) return false;
        std::vector<std::uint8_t> back(len);
        if (!dev->kernel_read(kva + pa_off, back.data(), len)) return false;
        return std::memcmp(back.data(), buf, len) == 0;
    }
    std::memcpy(reinterpret_cast<void*>(kva + pa_off), buf, len);
    return true;
}

bool window_open(winotify::driver_t& dev, std::uint64_t pa, window_t& out) {
    if (!g_pte_base) return false;
    const std::uint64_t frame = pa & ~0xFFFull;

    if (init_kernel_scratch(dev) && !g_kernel_scratch_in_use) {
        if (write_pte_va(dev, g_kernel_scratch_va, frame | kPtePresent | kPteWrite)) {
            g_kernel_scratch_in_use = true;
            out.dev = &dev;
            out.kva = g_kernel_scratch_va;
            out.kernel = true;
            return true;
        }
    }

    // fallback: user scratch with the protect flip flush
    if (!init_user_scratch()) return false;
    DWORD old = 0;
    if (!VirtualProtect(g_user_scratch, 0x1000, PAGE_NOACCESS, &old)) return false;
    if (!write_pte_va(dev, reinterpret_cast<std::uint64_t>(g_user_scratch),
                      frame | kPtePresent | kPteWrite | kPteUser)) {
        return false;
    }
    out.dev = &dev;
    out.kva = reinterpret_cast<std::uint64_t>(g_user_scratch);
    out.kernel = false;
    return true;
}

void window_close(window_t& w) {
    if (!w.valid()) return;
    if (w.kernel) {
        write_pte_va(*w.dev, g_kernel_scratch_va, g_kernel_scratch_orig_pte);
        g_kernel_scratch_in_use = false;
    } else {
        DWORD old = 0;
        VirtualProtect(g_user_scratch, 0x1000, PAGE_READWRITE, &old);
    }
    w.dev = nullptr;
    w.kva = 0;
}

std::uint64_t kernel_write_dtb(winotify::driver_t& dev) {
    if (!g_nt_base) g_nt_base = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!g_nt_base) return 0;
    auto maps_kernel = [&](std::uint64_t dtb) {
        std::uint8_t mz[2] = {};
        return dtb && dev.phys_read(dtb, g_nt_base, mz, sizeof(mz)) &&
               mz[0] == 'M' && mz[1] == 'Z';
    };
    // solve_dtb(4) returns the System process DTB which always maps kernel VAs
    const std::uint64_t system_dtb = dev.solve_dtb(4) & ~0xFFFull;
    if (maps_kernel(system_dtb)) return system_dtb;
    // fallback: our own process DTB (may work when KPTI shares the kernel half)
    const std::uint64_t own_dtb = dev.solve_dtb(GetCurrentProcessId());
    if (maps_kernel(own_dtb)) return own_dtb;
    return 0;
}

bool read_foreign_pte(winotify::driver_t& dev, std::uint64_t pml4_pa,
                      std::uint64_t va, std::uint64_t& raw_out) {
    std::uint64_t table = pml4_pa & kPhysMask;
    for (int level = 0; level < 3; ++level) {
        const std::uint64_t index = (va >> (39 - 9 * level)) & 0x1FF;
        window_t w{};
        if (!window_open(dev, table, w)) return false;
        std::uint64_t entry = 0;
        const bool ok = w.read(index * 8, &entry, sizeof(entry));
        window_close(w);
        if (!ok || !(entry & kPtePresent)) return false;
        if (entry & (1ull << 7)) return false;   // large page at mid level
        table = entry & kPhysMask;
    }
    const std::uint64_t index = (va >> 12) & 0x1FF;
    window_t w{};
    if (!window_open(dev, table, w)) return false;
    const bool ok = w.read(index * 8, &raw_out, sizeof(raw_out));
    window_close(w);
    return ok;
}

bool write_foreign_pte(winotify::driver_t& dev, std::uint64_t pml4_pa,
                       std::uint64_t va, std::uint64_t raw) {
    std::uint64_t table = pml4_pa & kPhysMask;
    for (int level = 0; level < 3; ++level) {
        const std::uint64_t index = (va >> (39 - 9 * level)) & 0x1FF;
        window_t w{};
        if (!window_open(dev, table, w)) return false;
        std::uint64_t entry = 0;
        const bool ok = w.read(index * 8, &entry, sizeof(entry));
        window_close(w);
        if (!ok || !(entry & kPtePresent)) return false;
        if (entry & (1ull << 7)) return false;
        table = entry & kPhysMask;
    }
    const std::uint64_t index = (va >> 12) & 0x1FF;
    window_t w{};
    if (!window_open(dev, table, w)) return false;
    const bool ok = w.write(index * 8, &raw, sizeof(raw));
    window_close(w);
    return ok;
}

std::uint64_t find_free_pml4_slot(winotify::driver_t& dev, std::uint64_t pml4_pa,
                                  std::uint32_t first, std::uint32_t last) {
    window_t w{};
    if (!window_open(dev, pml4_pa, w)) return 0;
    std::uint64_t slot = 0;
    for (std::uint32_t i = first; i <= last && i < 256; ++i) {
        std::uint64_t entry = 0;
        if (!w.read(i * 8, &entry, sizeof(entry))) break;
        if (!(entry & kPtePresent)) {
            slot = static_cast<std::uint64_t>(i) << 39;
            break;
        }
    }
    window_close(w);
    return slot;
}

std::uint64_t find_vad_covered_slot(winotify::driver_t& dev, std::uint64_t pml4_pa) {
    // single mode placement: walk the full 4-level table to PT level and
    // find an absent PTE inside a PT that already serves private committed
    // pages. the slot is 4KB-aligned (PTE level), not 2MB (PDE level).
    window_t pw{};
    if (!window_open(dev, pml4_pa, pw)) return 0;
    std::vector<std::uint64_t> pml4(512);
    const bool got_pml4 = pw.read(0, pml4.data(), 0x1000);
    window_close(pw);
    if (!got_pml4) return 0;

    for (int pass = 0; pass < 2; ++pass) {
        for (std::uint32_t i4 = 0x40; i4 < 0x100; ++i4) {
            const table_entry_t pml4e{ pml4[i4] };
            if (!pml4e.present() || !pml4e.user() || pml4e.large()) continue;
            window_t w3{};
            if (!window_open(dev, pml4e.frame(), w3)) continue;
            std::vector<std::uint64_t> pdpt(512);
            const bool got3 = w3.read(0, pdpt.data(), 0x1000);
            window_close(w3);
            if (!got3) continue;

            for (std::uint32_t i3 = 0; i3 < 512; ++i3) {
                const table_entry_t pdpte{ pdpt[i3] };
                if (!pdpte.present() || !pdpte.user() || pdpte.large()) continue;
                window_t w2{};
                if (!window_open(dev, pdpte.frame(), w2)) continue;
                std::vector<std::uint64_t> pd(512);
                const bool got2 = w2.read(0, pd.data(), 0x1000);
                window_close(w2);
                if (!got2) continue;

                for (std::uint32_t i2 = 0; i2 < 512; ++i2) {
                    const table_entry_t pde{ pd[i2] };
                    if (!pde.present() || !pde.user() || pde.large()) continue;

                    // walk level 4: the actual PT
                    window_t w1{};
                    if (!window_open(dev, pde.frame(), w1)) continue;
                    std::vector<std::uint64_t> pt(512);
                    const bool got1 = w1.read(0, pt.data(), 0x1000);
                    window_close(w1);
                    if (!got1) continue;

                    int rw_present = 0;
                    std::uint64_t absent_va = 0;
                    const std::uint64_t base_va =
                        (static_cast<std::uint64_t>(i4) << 39) |
                        (static_cast<std::uint64_t>(i3) << 30) |
                        (static_cast<std::uint64_t>(i2) << 21);

                    for (int i1 = 511; i1 >= 0; --i1) {
                        const table_entry_t pte{ pt[static_cast<std::uint32_t>(i1)] };
                        if (pte.present()) {
                            const bool is_private = pte.write() && pte.user();
                            if (pass == 0 ? is_private : pte.user())
                                ++rw_present;
                        } else if (!absent_va) {
                            // 4KB-aligned PTE-level slot
                            absent_va = base_va |
                                (static_cast<std::uint64_t>(i1) << 12);
                        }
                        if (rw_present >= 8 && absent_va) {
                            return absent_va;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

bool ghost_link(winotify::driver_t& dev, std::uint64_t backing_va,
                std::size_t page_count, const std::vector<bool>& exec_map,
                std::uint64_t chosen_base, std::uint64_t target_pml4_pa,
                std::uint64_t own_pml4_pa, std::uint64_t eprocess_va,
                std::vector<std::uint64_t>& out_table_pas,
                std::vector<void*>& out_table_vas) {
    if (!g_pte_base) return false;
    (void)own_pml4_pa;   // reserved for fresh-placement mode (not yet implemented)
    (void)eprocess_va;   // reserved for fresh-placement mode (not yet implemented)

    // single mode: covered placement only. the target's own mid tables
    // already reach the chosen base; we add ptes into the existing pt via
    // the physical window. zero new table allocations, zero pml4e writes,
    // kpti is handled because the existing chain is shared between both
    // kernel and shadow cr3s for user slots.

    const std::uint64_t pml4_i  = (chosen_base >> 39) & 0x1FF;
    const std::uint64_t pdpt_i  = (chosen_base >> 30) & 0x1FF;
    const std::uint64_t pd_i    = (chosen_base >> 21) & 0x1FF;

    // walk: pml4 -> pdpt -> pd -> pt frame
    std::uint64_t pt_frame = 0;
    {
        window_t w0{};
        if (!window_open(dev, target_pml4_pa, w0)) return false;
        std::uint64_t pdpt_e = 0;
        const bool g0 = w0.read(8 * pml4_i, &pdpt_e, sizeof(pdpt_e));
        window_close(w0);
        if (!g0) return false;
        const table_entry_t pdpte{ pdpt_e };
        if (!pdpte.present() || !pdpte.user() || pdpte.large()) return false;

        window_t w1{};
        if (!window_open(dev, pdpte.frame(), w1)) return false;
        std::uint64_t pd_e = 0;
        const bool g1 = w1.read(8 * pdpt_i, &pd_e, sizeof(pd_e));
        window_close(w1);
        if (!g1) return false;
        const table_entry_t pde{ pd_e };
        if (!pde.present() || !pde.user() || pde.large()) return false;

        window_t w2{};
        if (!window_open(dev, pde.frame(), w2)) return false;
        std::uint64_t pt_e = 0;
        const bool g2 = w2.read(8 * pd_i, &pt_e, sizeof(pt_e));
        window_close(w2);
        if (!g2) return false;
        // pt_e is the PDE at pd_i, which points to the PT page
        const table_entry_t pd_entry{ pt_e };
        if (!pd_entry.present() || !pd_entry.user()) return false;
        pt_frame = pd_entry.frame();
    }
    if (!pt_frame) return false;

    // write the ghost ptes into the target's existing pt
    window_t w{};
    if (!window_open(dev, pt_frame, w)) return false;
    bool all_ok = true;
    const std::uint64_t first_pte_i = (chosen_base >> 12) & 0x1FF;
    for (std::size_t i = 0; i < page_count && all_ok; ++i) {
        const std::uint64_t pte_i = first_pte_i + i;
        if (pte_i > 511) { all_ok = false; break; }
        // verify the slot is actually free
        std::uint64_t cur = 0;
        if (!w.read(8 * pte_i, &cur, sizeof(cur))) { all_ok = false; break; }
        if (cur & kPtePresent) { all_ok = false; break; }
        // write our pte
        const std::uint64_t pa = translate_own(dev, backing_va + i * 0x1000);
        if (!pa) { all_ok = false; break; }
        std::uint64_t pte = (pa & kPhysMask) | kPtePresent | kPteWrite | kPteUser;
        if (i >= exec_map.size() || !exec_map[i]) pte |= kPteNx;
        if (!w.write(8 * pte_i, &pte, sizeof(pte))) { all_ok = false; break; }
    }
    window_close(w);
    if (!all_ok) return false;

    // covered mode owns no table pages: nothing to orphan or forge
    out_table_pas.clear();
    out_table_vas.clear();
    return true;
}

std::uint64_t find_own_device_object(winotify::driver_t& dev, void* device_handle,
                                     std::uint32_t own_pid) {
    if (!device_handle) return 0;

    const std::uint64_t eprocess = find_eprocess(dev, own_pid);
    if (!eprocess) return 0;

    // read ObjectTable from eprocess: probe known offsets across builds
    std::uint64_t obj_table = 0;
    for (const std::size_t off : { 0x418, 0x570, 0x408, 0x4f0 }) {
        std::uint8_t buf[8] = {};
        if (!dev.kernel_read(eprocess + off, buf, 8)) continue;
        std::uint64_t v = 0;
        std::memcpy(&v, buf, 8);
        if ((v >> 48) == 0xFFFF && v > 0xFFFF800000000000ull) {
            obj_table = v;
            break;
        }
    }
    if (!obj_table) return 0;

    // handle table: TableCode at +0x000, low 2 bits = level
    std::uint8_t tc_buf[8] = {};
    if (!dev.kernel_read(obj_table, tc_buf, 8)) return 0;
    std::uint64_t table_code = 0;
    std::memcpy(&table_code, tc_buf, 8);
    const std::uint64_t level = table_code & 3;
    const std::uint64_t base = table_code & ~3ull;
    if (!base || (base >> 48) != 0xFFFF) return 0;

    // handle index: handle values are index * 4 on x64
    const std::uint64_t handle_val = reinterpret_cast<std::uint64_t>(device_handle);
    const std::uint64_t index = handle_val >> 2;

    std::uint64_t entry_va = 0;
    if (level == 0) {
        entry_va = base + 16 * index;
    } else if (level == 1) {
        const std::uint64_t l1_index = index >> 9;
        const std::uint64_t l0_index = index & 511;
        std::uint8_t sub[8] = {};
        if (!dev.kernel_read(base + 8 * l1_index, sub, 8)) return 0;
        std::uint64_t sub_table = 0;
        std::memcpy(&sub_table, sub, 8);
        if ((sub_table >> 48) != 0xFFFF) return 0;
        entry_va = (sub_table & ~3ull) + 16 * l0_index;
    } else {
        return 0;
    }
    if (!entry_va) return 0;

    // read the handle table entry: first qword is the object pointer
    // with flag bits in the low nibble
    std::uint8_t he[16] = {};
    if (!dev.kernel_read(entry_va, he, 16)) return 0;
    std::uint64_t obj_ptr = 0;
    std::memcpy(&obj_ptr, he, 8);
    obj_ptr &= ~0xFull;
    if ((obj_ptr >> 48) != 0xFFFF) return 0;

    // validate: the body must be a DEVICE_OBJECT (Type==3) with a
    // DriverObject backlink to our own driver base
    std::uint8_t dobj[0x20] = {};
    if (!dev.kernel_read(obj_ptr, dobj, sizeof(dobj))) return 0;
    const std::uint16_t type = *reinterpret_cast<const std::uint16_t*>(dobj);
    if (type != 3) return 0;

    const std::uint64_t drv_base = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv_base) return 0;
    std::uint64_t driver_obj = 0;
    std::memcpy(&driver_obj, dobj + 0x08, 8);
    if ((driver_obj >> 48) != 0xFFFF) return 0;
    std::uint8_t drobj[0x20] = {};
    if (!dev.kernel_read(driver_obj, drobj, sizeof(drobj))) return 0;
    std::uint64_t driver_start = 0;
    std::memcpy(&driver_start, drobj + 0x18, 8);

    if (driver_start != drv_base) return 0;

    return obj_ptr;
}

bool wipe_object_name_info(winotify::driver_t& dev, std::uint64_t device_va) {
    if (!device_va) return false;

    // the OBJECT_HEADER precedes the body at device_va - 0x28. optional
    // headers (name info, creator info, quota info) extend further back.
    // scan backwards for a UNICODE_STRING matching "WinNotify" at the
    // expected OBJECT_HEADER_NAME_INFO offsets
    const std::uint64_t hdr_va = device_va - 0x28;

    for (std::uint64_t scan = hdr_va - 0x88; scan < hdr_va; scan += 8) {
        std::uint8_t ni[0x28] = {};
        if (!dev.kernel_read(scan, ni, sizeof(ni))) continue;

        // OBJECT_HEADER_NAME_INFO:
        //   +0x00: Entry (LIST_ENTRY, 16 bytes)
        //   +0x10: Name (UNICODE_STRING)
        //     +0x10: Length (USHORT) - "WinNotify" = 18 bytes
        //     +0x12: MaximumLength (USHORT)
        //     +0x18: Buffer (PWCH)
        //   +0x20: Directory (POBJECT_DIRECTORY)
        const std::uint16_t name_len = *reinterpret_cast<const std::uint16_t*>(ni + 0x10);
        const std::uint16_t max_len = *reinterpret_cast<const std::uint16_t*>(ni + 0x12);
        std::uint64_t name_buf = 0;
        std::memcpy(&name_buf, ni + 0x18, 8);

        if (name_len != 18 || max_len < 18) continue;
        if ((name_buf >> 48) != 0xFFFF) continue;

        // verify the string content
        std::uint8_t str[20] = {};
        if (!dev.kernel_read(name_buf, str, sizeof(str))) continue;
        if (std::memcmp(str, L"WinNotify", 18) != 0) continue;

        // zero the string characters; keep the UNICODE_STRING structure
        // valid (Length and Buffer unchanged) so the object manager
        // doesn't crash when the object is freed
        std::vector<std::uint8_t> zeros(18, 0);
        if (dev.kernel_write(name_buf, zeros.data(), zeros.size())) {
            std::uint8_t check[18] = {};
            if (dev.kernel_read(name_buf, check, 18)) {
                for (std::uint8_t b : check) {
                    if (b != 0) return false;
                }
                return true;
            }
        }
    }
    return false;
}

bool insert_working_set_entries(winotify::driver_t& dev, std::uint64_t eprocess,
                                std::uint64_t base, std::size_t page_count) {
    if (!eprocess || !base) return false;

    // EPROCESS.Vm (MM_AVL_TABLE / KPROCESS sub-structure) contains the
    // working set pointers. the exact path on win10/11 x64:
    //   EPROCESS + 0x790 (2004-22xxx) or +0x570 (26100):
    //     + VmWorkingSetList (PMMWSL - pointer to the working set list)
    // the MMWSL (Memory Management Working Set List) structure:
    //   +0x000: LastEntry (ULONG) - index of the last used wsle
   //   +0x004: NextSlot (ULONG)
    //   +0x008: Wsle (PMMWSLE - pointer to the wsle array)
    //   +0x010: LastInitialized (ULONG)
    //   ...
    // each MMWSLE is a single ULONG_PTR:
    //   bits 0-11: protection/flags
    //   bits 12-63: virtual page number (va >> 12)

    // probe the vm working set list pointer at build-dependent offsets
    std::uint64_t wsl_ptr = 0;
    for (const std::size_t off : { 0x790, 0x570, 0x798, 0x578, 0x7a0 }) {
        std::uint8_t buf[8] = {};
        if (!dev.kernel_read(eprocess + off, buf, 8)) continue;
        std::uint64_t v = 0;
        std::memcpy(&v, buf, 8);
        if ((v >> 48) == 0xFFFF && v > 0xFFFF800000000000ull) {
            wsl_ptr = v;
            break;
        }
    }
    if (!wsl_ptr) return false;

    // read the MMWSL header
    std::uint8_t wsl[0x20] = {};
    if (!dev.kernel_read(wsl_ptr, wsl, sizeof(wsl))) return false;
    const std::uint32_t last_entry = *reinterpret_cast<const std::uint32_t*>(wsl + 0x000);
    std::uint64_t wsle_array = 0;
    std::memcpy(&wsle_array, wsl + 0x008, 8);
    const std::uint32_t last_init = *reinterpret_cast<const std::uint32_t*>(wsl + 0x010);

    if (!wsle_array || (wsle_array >> 48) != 0xFFFF) return false;
    if (last_entry >= last_init) return false;   // no free space

    // build the wsle values for our ghost pages: va >> 12 in the high
    // bits, protection flags in the low bits (0x42 = readable + valid,
    // matching the pte permissions)
    std::uint32_t insert_count = 0;
    std::uint32_t slot = last_entry + 1;
    for (std::size_t i = 0; i < page_count && slot < last_init; ++i, ++slot) {
        const std::uint64_t wsle = (base + i * 0x1000) | 0x42;
        if (!dev.kernel_write(wsle_array + 8 * slot, &wsle, sizeof(wsle))) break;
        ++insert_count;
    }

    // update LastEntry to include our new entries
    if (insert_count > 0) {
        const std::uint32_t new_last = last_entry + insert_count;
        if (!dev.kernel_write(wsl_ptr, &new_last, sizeof(new_last)))
            return insert_count > 0;  // partial success is acceptable
    }

    return insert_count == page_count;
}
bool orphan_sources(winotify::driver_t& dev, std::uint64_t backing_va,
                    std::size_t backing_count,
                    const std::vector<void*>& table_vas) {
    if (!g_pte_base) return false;
    // zero our ptes for the backing pages; the mirror at chosen_base keeps
    // the frames mapped for our reads and becomes the only mapping of them
    // in our process, consistent with the forged pfn entries
    for (std::size_t i = 0; i < backing_count; ++i) {
        if (!write_pte_va(dev, backing_va + i * 0x1000, 0)) return false;
    }
    // the table pages hang off the target pml4e and our mirror pml4e; zero
    // our original ptes so their frames are owned by the chain alone
    for (const void* va : table_vas) {
        if (!write_pte_va(dev, reinterpret_cast<std::uint64_t>(va), 0)) return false;
    }
    return true;
}

bool cleanup_ghost_ptes(winotify::driver_t& dev, std::uint64_t target_pml4_pa,
                        std::uint64_t chosen_base, std::size_t page_count) {
    if (!g_pte_base || !target_pml4_pa || !chosen_base) return false;

    const std::uint64_t pd_i = (chosen_base >> 21) & 0x1FF;
    const std::uint64_t pml4_i = (chosen_base >> 39) & 0x1FF;
    const std::uint64_t pdpt_i = (chosen_base >> 30) & 0x1FF;

    // walk to the PT frame (same path as ghost_link)
    window_t w0{};
    if (!window_open(dev, target_pml4_pa, w0)) return false;
    std::uint64_t pdpt_e = 0;
    w0.read(8 * pml4_i, &pdpt_e, sizeof(pdpt_e));
    window_close(w0);
    const table_entry_t pdpte{ pdpt_e };
    if (!pdpte.present()) return false;

    window_t w1{};
    if (!window_open(dev, pdpte.frame(), w1)) return false;
    std::uint64_t pd_e = 0;
    w1.read(8 * pdpt_i, &pd_e, sizeof(pd_e));
    window_close(w1);
    const table_entry_t pde{ pd_e };
    if (!pde.present()) return false;

    window_t w2{};
    if (!window_open(dev, pde.frame(), w2)) return false;
    std::uint64_t pt_e = 0;
    w2.read(8 * pd_i, &pt_e, sizeof(pt_e));
    window_close(w2);
    const table_entry_t pd_entry{ pt_e };
    if (!pd_entry.present()) return false;

    // zero our PTEs
    window_t w{};
    if (!window_open(dev, pd_entry.frame(), w)) return false;
    const std::uint64_t first_pte_i = (chosen_base >> 12) & 0x1FF;
    const std::uint64_t zero = 0;
    bool ok = true;
    for (std::size_t i = 0; i < page_count; ++i) {
        if (!w.write(8 * (first_pte_i + i), &zero, sizeof(zero))) ok = false;
    }
    window_close(w);
    return ok;
}


bool forge_pfn_backing(winotify::driver_t& dev, std::uint64_t backing_va,
                       std::size_t page_count, std::uint64_t chosen_base) {
    const std::uint64_t drv = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv) return false;
    std::uint8_t db_buf[8] = {};
    if (!dev.kernel_read(drv + 0x50D0, db_buf, sizeof(db_buf))) return false;
    std::uint64_t pfn_db = 0;
    std::memcpy(&pfn_db, db_buf, sizeof(pfn_db));
    if ((pfn_db >> 48) != 0xFFFF) return false;

    const std::uint64_t page0_pa = translate_own(dev, backing_va);
    if (!page0_pa) return false;
    const std::uint64_t own_pte_slot = pte_slot_va(backing_va);

    const std::uint64_t entry0 = pfn_db + 48 * (page0_pa >> 12);
    std::uint8_t raw[48] = {};
    if (!dev.kernel_read(entry0, raw, sizeof(raw))) return false;
    int pte_off = -1;
    for (int off = 0; off + 8 <= 48; off += 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, raw + off, sizeof(v));
        if (v == own_pte_slot) {
            pte_off = off;
            break;
        }
    }
    if (pte_off < 0) return false;

    for (std::size_t i = 0; i < page_count; ++i) {
        const std::uint64_t src_va = backing_va + i * 0x1000;
        const std::uint64_t pa = translate_own(dev, src_va);
        if (!pa) return false;
        const std::uint64_t ghost_slot = pte_slot_va(chosen_base + i * 0x1000);
        // pre-validate: the current value must be a canonical kernel va
        // (the old PteAddress) before we overwrite it; a zero or user va
        // means our offset is wrong and writing would corrupt the pfn
        std::uint8_t pre[8] = {};
        if (!dev.kernel_read(pfn_db + 48 * (pa >> 12) + pte_off, pre, 8))
            return false;
        std::uint64_t cur = 0;
        std::memcpy(&cur, pre, sizeof(cur));
        if ((cur >> 48) != 0xFFFF) return false;
        if (!dev.kernel_write(pfn_db + 48 * (pa >> 12) + pte_off,
                              &ghost_slot, sizeof(ghost_slot))) {
            return false;
        }

        // zero the working set links (flink/blink at offsets 0 and 8 of the
        // pfn entry) so the mm's working set trimmer doesn't follow stale
        // links into our process after we've forged the pteaddress. the
        // pages become standalone from the mm's perspective
        // best-effort: zeroing ws links is a stealth enhancement, not
        // required for correctness. log but don't fail the whole forge.
        const std::uint64_t zero = 0;
        const bool flink_ok = dev.kernel_write(pfn_db + 48 * (pa >> 12) + 0, &zero, sizeof(zero));
        const bool blink_ok = dev.kernel_write(pfn_db + 48 * (pa >> 12) + 8, &zero, sizeof(zero));
        (void)flink_ok; (void)blink_ok;  // checked, intentionally non-fatal
    }
    std::uint8_t back[8] = {};
    if (!dev.kernel_read(pfn_db + 48 * (page0_pa >> 12) + pte_off, back, sizeof(back)))
        return false;
    std::uint64_t v = 0;
    std::memcpy(&v, back, sizeof(v));
    return v == pte_slot_va(chosen_base);
}

bool forge_pfn_tables(winotify::driver_t& dev,
                      const std::vector<std::uint64_t>& table_pas,
                      std::uint64_t chosen_base) {
    const std::uint64_t drv = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv || table_pas.empty()) return false;
    std::uint8_t db_buf[8] = {};
    if (!dev.kernel_read(drv + 0x50D0, db_buf, sizeof(db_buf))) return false;
    std::uint64_t pfn_db = 0;
    std::memcpy(&pfn_db, db_buf, sizeof(pfn_db));
    if ((pfn_db >> 48) != 0xFFFF) return false;

    // self map slot of the entry that points at each table page:
    // pt pages hang off pdes of consecutive 2mb runs, pd off the pdpte,
    // pdpt off the pml4e of chosen_base
    auto slot_for = [&](std::size_t idx, std::size_t /*pt_count*/) -> std::uint64_t {
        if (idx == 0) return pml4e_slot_va(chosen_base);
        if (idx == 1) return pdpte_slot_va(chosen_base);
        return pde_slot_va(chosen_base + (idx - 2) * 0x200000);
    };
    const std::size_t pt_count = table_pas.size() - 2;

    // locate the pte address field offset on the first table page by looking
    // for any canonical kernel va, then verify via the pte it names
    int pte_off = -1;
    {
        const std::uint64_t pa = table_pas[0];
        std::uint8_t raw[48] = {};
        if (!dev.kernel_read(pfn_db + 48 * (pa >> 12), raw, sizeof(raw))) return false;
        for (int off = 0; off + 8 <= 48; off += 8) {
            std::uint64_t v = 0;
            std::memcpy(&v, raw + off, sizeof(v));
            if ((v >> 48) == 0xFFFF) {
                // verify: the named slot currently points back at this frame
                std::uint8_t slot_val[8] = {};
                if (dev.kernel_read(v, slot_val, 8)) {
                    std::uint64_t sv = 0;
                    std::memcpy(&sv, slot_val, sizeof(sv));
                    if ((sv & kPhysMask) == pa) {
                        pte_off = off;
                        break;
                    }
                }
            }
        }
    }
    if (pte_off < 0) return false;

    for (std::size_t idx = 0; idx < table_pas.size(); ++idx) {
        const std::uint64_t slot = slot_for(idx, pt_count);
        if (!dev.kernel_write(pfn_db + 48 * (table_pas[idx] >> 12) + pte_off,
                              &slot, sizeof(slot))) {
            return false;
        }
    }
    return true;
}

bool own_table_has_kernel_half(winotify::driver_t& dev) {
    const std::uint64_t cr3 = dev.solve_dtb(GetCurrentProcessId());
    if (!cr3) return false;
    window_t w{};
    if (!window_open(dev, cr3, w)) return false;
    std::vector<std::uint8_t> half(0x800);
    const bool ok = w.read(0x800, half.data(), half.size());
    window_close(w);
    if (!ok) return false;
    int kernel_entries = 0;
    for (std::size_t i = 0; i + 8 <= half.size(); i += 8) {
        std::uint64_t v = 0;
        std::memcpy(&v, half.data() + i, sizeof(v));
        if (v & kPtePresent) ++kernel_entries;
    }
    return kernel_entries > 4;
}

std::vector<mapping_t> enumerate_user_mappings(winotify::driver_t& dev,
                                               std::uint64_t pml4_pa) {
    std::vector<mapping_t> out;

    window_t pw{};
    if (!window_open(dev, pml4_pa, pw)) return out;
    std::vector<std::uint8_t> pml4_raw(0x1000);
    const bool got_pml4 = pw.read(0, pml4_raw.data(), pml4_raw.size());
    window_close(pw);
    if (!got_pml4) return out;
    std::vector<std::uint64_t> pml4(512);
    std::memcpy(pml4.data(), pml4_raw.data(), 0x1000);

    for (std::uint32_t pml4_i = 0; pml4_i < 256; ++pml4_i) {
        const table_entry_t pdpte_of{ pml4[pml4_i] };
        if (!pdpte_of.present() || !pdpte_of.user()) continue;
        if (pdpte_of.large()) {
            mapping_t m;
            m.base = static_cast<std::uint64_t>(pml4_i) << 39;
            m.size = 1ull << 30;
            m.write = pdpte_of.write();
            m.nx = pdpte_of.nx();
            m.large = true;
            out.push_back(m);
            continue;
        }
        std::vector<std::uint64_t> pdpt(512, 0);
        {
            window_t w{};
            if (!window_open(dev, pdpte_of.frame(), w)) continue;
            const bool ok = w.read(0, pdpt.data(), 0x1000);
            window_close(w);
            if (!ok) continue;
        }

        for (std::uint32_t pdpt_i = 0; pdpt_i < 512; ++pdpt_i) {
            const table_entry_t pde_of{ pdpt[pdpt_i] };
            if (!pde_of.present() || !pde_of.user()) continue;
            const std::uint64_t base2 = (static_cast<std::uint64_t>(pml4_i) << 39) |
                                        (static_cast<std::uint64_t>(pdpt_i) << 30);
            if (pde_of.large()) {
                mapping_t m;
                m.base = base2;
                m.size = 2ull << 20;
                m.write = pde_of.write();
                m.nx = pde_of.nx();
                m.large = true;
                out.push_back(m);
                continue;
            }
            std::vector<std::uint64_t> pd(512, 0);
            {
                window_t w{};
                if (!window_open(dev, pde_of.frame(), w)) continue;
                const bool ok = w.read(0, pd.data(), 0x1000);
                window_close(w);
                if (!ok) continue;
            }

            for (std::uint32_t pd_i = 0; pd_i < 512; ++pd_i) {
                const table_entry_t pte_of{ pd[pd_i] };
                if (!pte_of.present() || !pte_of.user()) continue;
                const std::uint64_t base3 = base2 | (static_cast<std::uint64_t>(pd_i) << 21);
                if (pte_of.large()) {
                    mapping_t m;
                    m.base = base3;
                    m.size = 2ull << 20;
                    m.write = pte_of.write();
                    m.nx = pte_of.nx();
                    m.large = true;
                    out.push_back(m);
                    continue;
                }
                const bool wbit = pte_of.write();
                const bool nx = pte_of.nx();
                if (!out.empty() && !out.back().large &&
                    out.back().base + out.back().size == base3 &&
                    out.back().write == wbit && out.back().nx == nx) {
                    out.back().size += 0x1000;
                } else {
                    mapping_t m;
                    m.base = base3;
                    m.size = 0x1000;
                    m.write = wbit;
                    m.nx = nx;
                    m.large = false;
                    out.push_back(m);
                }
            }
        }
    }
    return out;
}

std::uint64_t find_eprocess_resolved(winotify::driver_t& dev, std::uint32_t pid);

std::uint64_t find_eprocess(winotify::driver_t& dev, std::uint32_t pid) {
    return find_eprocess_resolved(dev, pid);
}

std::uint64_t insert_fake_vad(winotify::driver_t& dev, std::uint64_t eprocess,
                              std::uint64_t base, std::uint64_t size,
                              std::uint32_t protect) {
    if (!g_pte_base || !eprocess) return 0;

    // find the vad root offset for this build by probing
    const std::size_t vad_offs[2] = { 0x558, 0x7D8 };
    const std::size_t links_offs[2] = { 0x1D8, 0x448 };
    std::uint64_t vad_root_ptr = 0;
    std::size_t used_links_off = 0;
    for (int i = 0; i < 2; ++i) {
        std::uint8_t buf[8] = {};
        if (dev.kernel_read(eprocess + vad_offs[i], buf, 8)) {
            std::uint64_t v = *reinterpret_cast<const std::uint64_t*>(buf);
            if ((v >> 48) == 0xFFFF) {
                vad_root_ptr = v;
                used_links_off = links_offs[i];
                break;
            }
        }
    }
    if (!vad_root_ptr) return 0;

    // the vad tree root: the root pointer points to an mmvad node (the tree
    // root). children are at +0x08 (left) and +0x10 (right), starting vpn at
    // +0x18. walk to find our insertion point as a leaf
    const std::uint64_t start_vpn = base >> 12;
    const std::uint64_t end_vpn = (base + size - 1) >> 12;

    std::uint64_t cur = vad_root_ptr;
    std::uint64_t parent = 0;
    bool go_left = false;
    for (int guard = 0; guard < 1024; ++guard) {
        std::uint8_t node[0x20] = {};
        if (!dev.kernel_read(cur, node, sizeof(node))) break;
        const std::uint64_t left = *reinterpret_cast<const std::uint64_t*>(node + 0x08);
        const std::uint64_t right = *reinterpret_cast<const std::uint64_t*>(node + 0x10);
        const std::uint32_t node_vpn = *reinterpret_cast<const std::uint32_t*>(node + 0x18);

        if (start_vpn < node_vpn) {
            if (!left) { parent = cur; go_left = true; break; }
            cur = left;
        } else {
            if (!right) { parent = cur; go_left = false; break; }
            cur = right;
        }
    }
    if (!parent) return 0;

    // find driver image slack for the fake vad node (0x80 bytes, after the
    // kernel scratch area to avoid collision)
    const std::uint64_t drv = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv) return 0;
    const std::uint64_t drv_size = kernel_module_size(dev, drv);
    if (drv_size < 0x2000) return 0;

    // use the last 0x100 bytes of the image, which is guaranteed slack
    // (before the page-aligned end) and not the kernel scratch (which is
    // at drv_size - 0x1000)
    std::uint64_t node_va = drv + drv_size - 0x100;
    if (node_va == g_kernel_scratch_va) {
        node_va -= 0x100;   // shift down if we collide with the scratch
    }

    // verify the target is currently zero
    std::uint8_t check[0x80] = {};
    if (!dev.kernel_read(node_va, check, sizeof(check))) return 0;
    for (std::uint8_t b : check) {
        if (b != 0) return 0;   // not slack, abort
    }

    // build the fake MMVAD_SHORT
    std::uint8_t vad[0x80] = {};
    // tree links
    std::uint64_t parent_val = parent | 1;   // low bit = balance (1 = right-heavy leaf)
    std::memcpy(vad + 0x00, &parent_val, 8);
    // LeftChild = 0, RightChild = 0 (leaf)
    // VPNs
    const std::uint32_t start_vpn_lo = static_cast<std::uint32_t>(start_vpn);
    const std::uint32_t end_vpn_lo = static_cast<std::uint32_t>(end_vpn);
    const std::uint8_t start_vpn_hi = static_cast<std::uint8_t>(start_vpn >> 32);
    const std::uint8_t end_vpn_hi = static_cast<std::uint8_t>(end_vpn >> 32);
    std::memcpy(vad + 0x18, &start_vpn_lo, 4);
    std::memcpy(vad + 0x1C, &end_vpn_lo, 4);
    vad[0x20] = start_vpn_hi;
    vad[0x21] = end_vpn_hi;
    // flags: MemCommit | PrivateMemory
    const std::uint32_t flags = 0x00000003;
    std::memcpy(vad + 0x24, &flags, 4);
    // protection
    std::memcpy(vad + 0x28, &protect, 4);

    // write the node
    if (!dev.kernel_write(node_va, vad, sizeof(vad))) return 0;

    // link it into the tree: set the parent's child pointer to our node
    const std::uint64_t child_slot = go_left ? parent + 0x08 : parent + 0x10;
    if (!dev.kernel_write(child_slot, &node_va, sizeof(node_va))) {
        // failed to link, zero our node to avoid a corrupted tree
        std::memset(vad, 0, sizeof(vad));
        (void)dev.kernel_write(node_va, vad, sizeof(vad));  // best-effort cleanup
        return 0;
    }

    // verify: read back the parent's child pointer
    std::uint8_t verify[8] = {};
    if (!dev.kernel_read(child_slot, verify, 8)) return 0;
    if (*reinterpret_cast<const std::uint64_t*>(verify) != node_va) return 0;

    return node_va;
}

bool remove_fake_vad(winotify::driver_t& dev, std::uint64_t eprocess,
                     std::uint64_t node_va) {
    if (!node_va) return true;
    (void)eprocess;  // retained for future vad root re-balance
    // read our node to find the parent
    std::uint8_t node[0x18] = {};
    if (!dev.kernel_read(node_va, node, sizeof(node))) return false;
    std::uint64_t parent = *reinterpret_cast<const std::uint64_t*>(node);
    parent &= ~1ull;   // strip balance bit

    // zero the parent's child pointer that references us (try both left and right)
    for (std::size_t off : { 0x08, 0x10 }) {
        std::uint8_t buf[8] = {};
        if (dev.kernel_read(parent + off, buf, 8)) {
            if (*reinterpret_cast<const std::uint64_t*>(buf) == node_va) {
                const std::uint64_t zero = 0;
                if (!dev.kernel_write(parent + off, &zero, sizeof(zero))) return false;
                break;
            }
        }
    }

    // zero our node
    std::vector<std::uint8_t> zeros(0x80, 0);
    if (!dev.kernel_write(node_va, zeros.data(), zeros.size())) return false;
    return true;
}


bool mutate_driver_text(winotify::driver_t& dev) {
    // break in-memory byte pattern matches against the published driver
    // hash without touching executed code: randomize inter-function cc
    // padding runs in the image
    const std::uint64_t drv = dev.module_base_kernel(dev.staged_module_name().c_str());
    if (!drv) return false;
    const std::uint64_t size = kernel_module_size(dev, drv);
    if (size < 0x2000) return false;

    const std::uint64_t kdtb = kernel_write_dtb(dev);
    if (!kdtb) return false;

    std::vector<std::uint8_t> image(static_cast<std::size_t>(size));
    if (!dev.kernel_read(drv, image.data(), image.size())) return false;

    std::size_t mutated = 0;
    const std::size_t limit = image.size() * 3 / 4;
    for (std::size_t i = 0; i < limit;) {
        if (image[i] != 0xCC) { ++i; continue; }
        std::size_t run = 0;
        while (i + run < limit && image[i + run] == 0xCC) ++run;
        if (run >= 24) {
            std::vector<std::uint8_t> noise(run);
            for (std::size_t k = 0; k < run; ++k) {
                noise[k] = static_cast<std::uint8_t>(0x40 + ((i * 31 + k * 17) & 0x3F));
            }
            if (dev.phys_write(kdtb, drv + i, noise.data(), noise.size())) {
                mutated += run;
            }
        }
        if (run) i += run; else ++i;
    }

    // also mutate zero runs (padding after initialized data in .rdata/.data)
    for (std::size_t i = 0; i < limit;) {
        if (image[i] != 0x00) { ++i; continue; }
        std::size_t run = 0;
        while (i + run < limit && image[i + run] == 0x00) ++run;
        if (run >= 32) {
            std::vector<std::uint8_t> noise(run);
            for (std::size_t k = 0; k < run; ++k) {
                noise[k] = static_cast<std::uint8_t>(0x20 + ((i * 13 + k * 7) & 0x3F));
            }
            if (dev.phys_write(kdtb, drv + i, noise.data(), noise.size())) {
                mutated += run;
            }
        }
        if (run) i += run; else ++i;
    }

    return mutated >= 24;
}

// ═══════════════════════════════════════════════════════════════════════════════
// ANTI-CHEAT EVASION LAYER
// ═══════════════════════════════════════════════════════════════════════════════

namespace {

// validate a kernel va is plausible before asking the driver to read it.
// the driver's handler uses MmCopyMemory/memcpy without SEH on some paths,
// so a bad va causes BSOD 0x50. this pre-check uses the PTE self-map to
// verify the page is present, falling back to a range check if the self-map
// isn't initialized.
bool is_valid_kernel_va(winotify::driver_t& dev, std::uint64_t va) {
    // must be in kernel half
    if (va < 0xFFFF800000000000ull) return false;
    // reject null-ish and obviously bad
    if (va == 0 || va == ~0ull) return false;
    // must be page-aligned-ish (not pointing into random bits)
    // allow any offset within a page

    // if we have the PTE base, check the PTE is present
    if (pte_base()) {
        table_entry_t pte;
        if (read_pte_va(dev, pte_slot_va(va), pte) && pte.present())
            return true;
        // PTE read failed or not present — page is not mapped
        return false;
    }

    // no PTE base — conservative: allow reads in the typical kernel range
    // (this path only runs before ensure_pte_base is called)
    return true;
}

// safe kernel read: validates the pointer before asking the driver.
// returns false (no crash) instead of letting the driver bugcheck.
bool safe_kread(winotify::driver_t& dev, std::uint64_t va, void* buf, std::size_t len) {
    if (!is_valid_kernel_va(dev, va)) return false;
    return dev.kernel_read(va, buf, len);
}

// safe kernel read for a 64-bit pointer, returns 0 on failure
std::uint64_t safe_read_ptr(winotify::driver_t& dev, std::uint64_t va) {
    std::uint64_t val = 0;
    if (!safe_kread(dev, va, &val, 8)) return 0;
    return val;
}


struct eprocess_layout_t {
    std::size_t pid = 0;
    std::size_t links = 0;
    std::size_t object_table = 0;
    std::size_t thread_list = 0;
    std::size_t thread_list_from_ethread = 0;
    std::size_t instrumentation = 0;
    bool valid = false;
};

bool canonical_kernel(std::uint64_t va) {
    return (va >> 48) == 0xFFFF && va > 0xFFFF800000000000ull;
}

eprocess_layout_t discover_layout(winotify::driver_t& dev) {
    eprocess_layout_t out;
    const std::uint64_t head = kernel_export_va(dev, XORSTR("PsActiveProcessHead"));
    const std::uint64_t first = head ? safe_read_ptr(dev, head) : 0;
    if (!canonical_kernel(first)) return out;

    std::size_t back_hit = 0;
    for (std::size_t back = 8; back <= 0x20; back += 8) {
        std::uint64_t pid = 0;
        if (safe_kread(dev, first - back, &pid, 8) && (pid == 4 || pid == 0)) {
            back_hit = back;
            break;
        }
    }
    if (!back_hit) return out;
    const std::uint64_t system = first - back_hit;
    for (std::size_t off = 0x200; off < 0x700; off += 8) {
        std::uint64_t pid = 0;
        if (!safe_kread(dev, system + off, &pid, 8) || pid != 4) continue;
        if (safe_read_ptr(dev, system + off + 8) != first) continue;
        out.pid = off;
        out.links = off + 8;
        out.valid = true;
        break;
    }
    if (!out.valid) return out;

    for (std::size_t off = 0x300; off < 0x900; off += 8) {
        const std::uint64_t cand = safe_read_ptr(dev, system + off);
        if (!canonical_kernel(cand)) continue;
        if (!canonical_kernel(safe_read_ptr(dev, cand + 8) & ~3ull)) continue;
        out.object_table = off;
        break;
    }
    for (std::size_t off = 0x400; off < 0x900; off += 8) {
        const std::uint64_t flink = safe_read_ptr(dev, system + off);
        if (!canonical_kernel(flink) || flink == system + off) continue;
        if (safe_read_ptr(dev, flink + 8) != system + off) continue;
        for (std::size_t back = 0x20; back <= 0xA0; back += 8) {
            std::uint64_t pid = 0;
            if (!safe_kread(dev, flink - back, &pid, 8)) continue;
            if (static_cast<std::uint32_t>(pid) != 4) continue;
            out.thread_list = off;
            out.thread_list_from_ethread = back;
            break;
        }
        if (out.thread_list) break;
    }
    return out;
}

const eprocess_layout_t& layout_of(winotify::driver_t& dev) {
    static eprocess_layout_t cached;
    static bool tried = false;
    if (!tried) {
        cached = discover_layout(dev);
        tried = cached.valid;
    }
    return cached;
}

} // anon — resolver must have external linkage

std::uint64_t find_eprocess_resolved(winotify::driver_t& dev, std::uint32_t pid) {

    const auto& lay = layout_of(dev);
    if (!lay.valid) return 0;
    const std::uint64_t head = kernel_export_va(dev, XORSTR("PsActiveProcessHead"));
    std::uint64_t cur = safe_read_ptr(dev, head);
    for (int n = 0; n < 1024 && canonical_kernel(cur) && cur != head; ++n) {
        const std::uint64_t entry = cur - lay.links;
        std::uint64_t cur_pid = 0;
        if (!safe_kread(dev, entry + lay.pid, &cur_pid, 8)) break;
        if (static_cast<std::uint32_t>(cur_pid) == pid) return entry;
        const std::uint64_t next = safe_read_ptr(dev, cur);
        if (!next || next == cur) break;
        cur = next;
    }
    return 0;
}

} // anon

namespace slop::core::runtime::ptwalk {

// sig scan ntoskrnl .text for a byte pattern, return the rva match
std::uint64_t sig_scan_ntoskrnl(winotify::driver_t& dev, std::uint64_t ntbase,
                                const std::uint8_t* pat, const std::uint8_t* mask,
                                std::size_t len, std::size_t scan_size = 0x800000) {
    constexpr std::size_t kChunk = 0x1000;
    std::vector<std::uint8_t> buf(kChunk);
    for (std::size_t off = 0; off < scan_size; off += kChunk) {
        if (!dev.kernel_read(ntbase + off, buf.data(), kChunk)) continue;
        for (std::size_t i = 0; i + len <= kChunk; ++i) {
            bool ok = true;
            for (std::size_t j = 0; j < len && ok; ++j) {
                if (mask[j] && buf[i + j] != pat[j]) ok = false;
            }
            if (ok) return ntbase + off + i;
        }
    }
    return 0;
}

// resolve a rip-relative lea target: lea reg, [rip+disp32]
std::uint64_t resolve_rip_relative(winotify::driver_t& dev, std::uint64_t insn_va, std::size_t insn_len) {
    std::int32_t disp = 0;
    if (!dev.kernel_read(insn_va + insn_len - 4, &disp, 4)) return 0;
    return insn_va + insn_len + static_cast<std::int64_t>(disp);
}

// NT build number from SharedUserData
std::uint32_t get_nt_build(winotify::driver_t& dev) {
    std::uint32_t build = 0;
    dev.kernel_read(0xFFFFF78000000260ull, &build, 4);
    return build & 0xFFFF;
}

// cloaked handle backup for restore
struct cloaked_backup_t {
    std::uint64_t table_entry_va = 0;
    std::uint64_t original_value = 0;
    bool valid = false;
};
cloaked_backup_t g_cloaked_handle;


bool clean_piddb_cache(winotify::driver_t& dev) {
    // PiDDBCacheTable is an RTL_AVL_TABLE inside ntoskrnl. We locate it via
    // a signature for the function that inserts into it (PpCheckInDriverDatabase
    // or PiLookupInDDB). The sig targets the lea that loads the table address.
    //
    // Pattern (Win10 20H2+): 48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B F8 48 85 C0
    // This is: lea rcx, [PiDDBCacheTable]; call RtlLookupElementGenericTableAvl
    const std::uint64_t ntbase = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!ntbase) return false;

    // clang-format off
    const std::uint8_t pat[]  = { 0x48, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00,
                                  0xE8, 0x00, 0x00, 0x00, 0x00,
                                  0x48, 0x8B, 0xF8, 0x48, 0x85, 0xC0 };
    const std::uint8_t mask[] = { 1,1,1,0,0,0,0, 1,0,0,0,0, 1,1,1,1,1,1 };
    // clang-format on

    const std::uint64_t hit = sig_scan_ntoskrnl(dev, ntbase, pat, mask, sizeof(pat));
    if (!hit) return false;

    // resolve the lea rcx, [rip+disp32]
    const std::uint64_t table_va = resolve_rip_relative(dev, hit, 7);
    if (!table_va) return false;

    // RTL_AVL_TABLE layout: OrderedPointer at +0x00, NumberGenericTableElements at +0x24
    // TableRoot (BALANCED_NODE) at +0x08
    // Each entry in the tree starts with RTL_BALANCED_LINKS (0x20 bytes), then:
    //   +0x00 UNICODE_STRING DriverName (len, maxlen, buffer)
    //   +0x10 ULONG TimeDateStamp
    // We walk the tree, find our entry by matching the driver name, and unlink it.

    // Read the element count
    std::uint32_t count = 0;
    if (!dev.kernel_read(table_va + 0x24, &count, 4)) return false;
    if (count == 0) return true; // nothing to clean

    // Walk the ordered list (LIST_ENTRY at table_va + 0x00)
    // Each node has RTL_BALANCED_LINKS (parent, left, right at +0, +8, +10)
    // followed by the data. The name we look for is our staged module name.
    const std::string& our_name = dev.staged_module_name();
    if (our_name.empty()) return false;

    // Convert our name to wide for comparison
    std::vector<wchar_t> our_wide(our_name.size() + 1);
    for (std::size_t i = 0; i < our_name.size(); ++i)
        our_wide[i] = static_cast<wchar_t>(our_name[i]);

    // Read the root node pointer
    std::uint64_t root_node = 0;
    if (!dev.kernel_read(table_va + 0x08, &root_node, 8)) return false;
    if (!root_node) return true;

    // BFS/DFS through the AVL tree to find our entry
    std::vector<std::uint64_t> stack = { root_node };
    while (!stack.empty()) {
        const std::uint64_t node = stack.back();
        stack.pop_back();
        if (!node) continue;

        // read balanced links (parent, left, right) + data
        std::uint8_t buf[0x50] = {};
        if (!safe_kread(dev, node, buf, sizeof(buf))) continue;

        const std::uint64_t left  = *reinterpret_cast<const std::uint64_t*>(buf + 0x08);
        const std::uint64_t right = *reinterpret_cast<const std::uint64_t*>(buf + 0x10);
        if (left) stack.push_back(left);
        if (right) stack.push_back(right);

        // data starts after RTL_BALANCED_LINKS (0x20 bytes)
        // UNICODE_STRING: Length (u16), MaxLength (u16), pad (u32), Buffer (u64)
        const std::uint16_t name_len = *reinterpret_cast<const std::uint16_t*>(buf + 0x20);
        const std::uint64_t name_buf = *reinterpret_cast<const std::uint64_t*>(buf + 0x28);

        if (name_len < 2 || name_len > 512 || !name_buf) continue;

        // read the name
        std::vector<wchar_t> name_chars(name_len / 2 + 1, 0);
        if (!safe_kread(dev, name_buf, name_chars.data(), name_len)) continue;

        // case-insensitive compare
        bool match = false;
        if (name_len / 2 == our_name.size()) {
            match = true;
            for (std::size_t i = 0; i < our_name.size(); ++i) {
                wchar_t a = name_chars[i];
                wchar_t b = our_wide[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = false; break; }
            }
        }

        if (!match) continue;

        // found our entry — unlink from AVL tree by zeroing the parent's
        // child pointer and decrementing the count
        const std::uint64_t parent = *reinterpret_cast<const std::uint64_t*>(buf);
        if (parent) {
            for (std::size_t off : { std::size_t(0x08), std::size_t(0x10) }) {
                std::uint64_t child = 0;
                if (safe_kread(dev, parent + off, &child, 8) && child == node) {
                    // replace with left or right subtree
                    const std::uint64_t replacement = left ? left : right;
                    dev.kernel_write(parent + off, &replacement, 8);
                    if (replacement && replacement != left && replacement != right) {
                        // update replacement's parent
                        dev.kernel_write(replacement, &parent, 8);
                    }
                    break;
                }
            }
        }

        // zero the entry data (name string, timestamp)
        std::vector<std::uint8_t> zeros(0x40, 0);
        dev.kernel_write(node + 0x20, zeros.data(), zeros.size());

        // zero the name buffer
        std::vector<std::uint8_t> name_zeros(name_len, 0);
        dev.kernel_write(name_buf, name_zeros.data(), name_zeros.size());

        // decrement count
        if (count > 0) {
            --count;
            dev.kernel_write(table_va + 0x24, &count, 4);
        }

        return true;
    }

    return true; // not found = already clean
}

bool clean_mm_unloaded_drivers(winotify::driver_t& dev) {
    // MmUnloadedDrivers is a circular buffer of UNLOADED_DRIVER structs.
    // ntoskrnl exports it. Each entry: UNICODE_STRING Name (+0x00),
    // PVOID StartAddress (+0x10), PVOID EndAddress (+0x18),
    // LARGE_INTEGER CurrentTime (+0x20). Total 0x28 per entry, 50 max.
    const std::uint64_t ntbase = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!ntbase) return false;

    // MmUnloadedDrivers is a pointer (PUNLOADED_DRIVER*) exported
    const std::uint64_t mm_ptr = kernel_export_va(dev, XORSTR("MmUnloadedDrivers"));
    if (!mm_ptr) return false;

    std::uint64_t array_va = 0;
    if (!safe_kread(dev, mm_ptr, &array_va, 8)) return false;
    if (!array_va) return true;

    // Also need MmLastUnloadedDriver (PULONG) for the current index
    const std::uint64_t last_ptr = kernel_export_va(dev, XORSTR("MmLastUnloadedDriver"));
    std::uint32_t last_idx = 0;
    if (last_ptr) dev.kernel_read(last_ptr, &last_idx, 4);

    const std::string& our_name = dev.staged_module_name();
    std::vector<wchar_t> our_wide(our_name.size() + 1);
    for (std::size_t i = 0; i < our_name.size(); ++i)
        our_wide[i] = static_cast<wchar_t>(our_name[i]);

    // scan all 50 entries
    constexpr std::size_t kEntrySize = 0x28;
    constexpr std::size_t kMaxEntries = 50;
    bool cleaned = false;

    for (std::size_t i = 0; i < kMaxEntries; ++i) {
        const std::uint64_t entry_va = array_va + i * kEntrySize;
        std::uint8_t entry[kEntrySize] = {};
        if (!safe_kread(dev, entry_va, entry, kEntrySize)) continue;

        const std::uint16_t name_len = *reinterpret_cast<const std::uint16_t*>(entry);
        const std::uint64_t name_buf = *reinterpret_cast<const std::uint64_t*>(entry + 0x08);
        if (name_len < 2 || !name_buf) continue;

        std::vector<wchar_t> name_chars(name_len / 2 + 1, 0);
        if (!safe_kread(dev, name_buf, name_chars.data(), name_len)) continue;

        // compare (the name includes .sys suffix and full path)
        bool match = false;
        // check if our module name appears anywhere in the path
        for (std::size_t j = 0; j + our_name.size() <= name_len / 2; ++j) {
            bool seg = true;
            for (std::size_t k = 0; k < our_name.size() && seg; ++k) {
                wchar_t a = name_chars[j + k], b = our_wide[k];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) seg = false;
            }
            if (seg) { match = true; break; }
        }

        if (!match) continue;

        // zero the entry
        std::uint8_t zeros[kEntrySize] = {};
        dev.kernel_write(entry_va, zeros, kEntrySize);

        // zero the name buffer
        std::vector<std::uint8_t> name_zeros(name_len, 0);
        dev.kernel_write(name_buf, name_zeros.data(), name_zeros.size());

        cleaned = true;
    }

    return cleaned || true; // true even if not found (already clean)
}

bool cloak_handle_table_entry(winotify::driver_t& dev, void* device_handle,
                              std::uint32_t own_pid) {
    // Our IOCTL handle appears in the process handle table. EAC and BattlEye
    // enumerate handles via NtQuerySystemInformation(SystemHandleInformation)
    // or by directly walking the handle table.
    //
    // Strategy: find our EPROCESS -> ObjectTable -> walk the 3-level table
    // to find the entry for our handle value, save it, then zero it.
    // The handle remains functional because DeviceIoControl resolves through
    // the file object (ObReferenceObjectByHandle) which the kernel caches
    // internally, but handle enumeration skips zeroed entries.

    const std::uint64_t eprocess = find_eprocess(dev, own_pid);
    if (!eprocess) return false;

    const auto& lay = layout_of(dev);
    if (!lay.object_table) return false;
    const std::uint64_t obj_table = safe_read_ptr(dev, eprocess + lay.object_table);
    if (!canonical_kernel(obj_table)) return false;

    // HANDLE_TABLE: TableCode at +0x08
    std::uint64_t table_code = 0;
    if (!safe_kread(dev, obj_table + 0x08, &table_code, 8)) return false;

    const std::uint32_t level = static_cast<std::uint32_t>(table_code & 3);
    const std::uint64_t table_base = table_code & ~3ull;

    // handle index = handle_value / 4
    const std::uint64_t handle_val = reinterpret_cast<std::uintptr_t>(device_handle);
    const std::uint64_t idx = handle_val / 4;

    // locate the entry in the multi-level table
    std::uint64_t entry_va = 0;
    if (level == 0) {
        // single level: entries directly at table_base
        entry_va = table_base + idx * 16; // HANDLE_TABLE_ENTRY = 16 bytes
    } else if (level == 1) {
        // two levels
        const std::uint64_t l1_idx = idx / 256;
        const std::uint64_t l0_idx = idx % 256;
        std::uint64_t l1_ptr = 0;
        if (!safe_kread(dev, table_base + l1_idx * 8, &l1_ptr, 8)) return false;
        entry_va = l1_ptr + l0_idx * 16;
    } else if (level == 2) {
        // three levels
        const std::uint64_t l2_idx = idx / (256 * 256);
        const std::uint64_t l1_idx = (idx / 256) % 256;
        const std::uint64_t l0_idx = idx % 256;
        std::uint64_t l2_ptr = 0;
        if (!safe_kread(dev, table_base + l2_idx * 8, &l2_ptr, 8)) return false;
        std::uint64_t l1_ptr = 0;
        if (!safe_kread(dev, l2_ptr + l1_idx * 8, &l1_ptr, 8)) return false;
        entry_va = l1_ptr + l0_idx * 16;
    }

    if (!entry_va) return false;

    // save the original value for restore
    std::uint64_t original[2] = {};
    if (!safe_kread(dev, entry_va, original, 16)) return false;

    // verify this looks like a valid entry (non-zero)
    if (original[0] == 0) return false;

    g_cloaked_handle.table_entry_va = entry_va;
    g_cloaked_handle.original_value = original[0];
    g_cloaked_handle.valid = true;

    // zero the entry
    const std::uint64_t zeros[2] = { 0, 0 };
    return dev.kernel_write(entry_va, zeros, 16);
}

bool uncloak_handle_table_entry(winotify::driver_t& dev) {
    if (!g_cloaked_handle.valid) return true;

    // restore the saved entry
    std::uint64_t restored[2] = { g_cloaked_handle.original_value, 0 };
    // re-read the second qword (access mask) — it may have been set separately
    dev.kernel_read(g_cloaked_handle.table_entry_va + 8, &restored[1], 8);
    restored[0] = g_cloaked_handle.original_value;

    bool ok = dev.kernel_write(g_cloaked_handle.table_entry_va, restored, 16);
    g_cloaked_handle.valid = false;
    return ok;
}

bool blind_etw_ti_provider(winotify::driver_t& dev) {
    // The ETW Threat Intelligence provider (Microsoft-Windows-Threat-Intelligence)
    // GUID: {F4E1897C-BB5D-5668-F1D8-040F4D8DD344}
    // EAC and Vanguard register kernel callbacks that receive ETW TI events
    // whenever MmCopyVirtualMemory, NtReadVirtualMemory, etc. are called.
    //
    // Strategy: find EtwThreatIntProvRegHandle in ntoskrnl (exported on 21H2+
    // or sig-scanned), then patch the ETW_REG_ENTRY's GuidEntry->ProviderEnableInfo
    // to disable all enable bits.
    //
    // Alternative (more reliable): patch the EtwProviderEnabled check in
    // the TI notification path by NOPping the call.

    const std::uint64_t ntbase = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!ntbase) return false;

    // sig for the ETW TI provider reference:
    // mov rcx, cs:EtwThreatIntProvRegHandle → 48 8B 0D xx xx xx xx
    // followed by a call to EtwProvSomething
    // clang-format off
    const std::uint8_t pat[]  = { 0x48, 0x8B, 0x0D, 0x00, 0x00, 0x00, 0x00,
                                  0xBA, 0x00, 0x00, 0x00, 0x00,
                                  0xE8 };
    const std::uint8_t mask[] = { 1,1,1,0,0,0,0, 1,0,0,0,0, 1 };
    // clang-format on

    const std::uint64_t hit = sig_scan_ntoskrnl(dev, ntbase, pat, mask, sizeof(pat));
    if (!hit) {
        // fallback: try to find EtwThreatIntProvRegHandle as an export
        const std::uint64_t exp = kernel_export_va(dev, XORSTR("EtwThreatIntProvRegHandle"));
        if (!exp) return false;

        // it's a REG_HANDLE (pointer to ETW_REG_ENTRY)
        std::uint64_t reg_entry = 0;
        if (!safe_kread(dev, exp, &reg_entry, 8)) return false;
        if (!reg_entry) return true; // not registered

        // ETW_REG_ENTRY +0x20 = GuidEntry pointer
        std::uint64_t guid_entry = 0;
        if (!safe_kread(dev, reg_entry + 0x20, &guid_entry, 8)) return false;
        if (!guid_entry) return true;

        // ETW_GUID_ENTRY +0x44 = ProviderEnableInfo (TRACE_ENABLE_INFO)
        // TRACE_ENABLE_INFO +0x00 = IsEnabled (ULONG)
        const std::uint32_t zero = 0;
        return dev.kernel_write(guid_entry + 0x44, &zero, 4);
    }

    // resolve the mov rcx, [rip+disp32]
    const std::uint64_t reg_handle_va = resolve_rip_relative(dev, hit, 7);
    if (!reg_handle_va) return false;

    std::uint64_t reg_entry = 0;
    if (!safe_kread(dev, reg_handle_va, &reg_entry, 8)) return false;
    if (!reg_entry) return true;

    std::uint64_t guid_entry = 0;
    if (!safe_kread(dev, reg_entry + 0x20, &guid_entry, 8)) return false;
    if (!guid_entry) return true;

    const std::uint32_t zero = 0;
    return dev.kernel_write(guid_entry + 0x44, &zero, 4);
}

bool spoof_thread_callstacks(winotify::driver_t& dev, std::uint32_t own_pid) {
    // EAC and BattlEye walk our threads' kernel stacks looking for return
    // addresses that point into non-system modules (i.e. our engine).
    // We walk our own EPROCESS -> ThreadListHead, find each ETHREAD,
    // read its TrapFrame, and if any saved RIP is suspicious, overwrite
    // it with a plausible ntdll!RtlUserThreadStart or kernel32!BaseThreadInitThunk.

    const std::uint64_t eprocess = find_eprocess(dev, own_pid);
    if (!eprocess) return false;

    const auto& lay = layout_of(dev);
    if (!lay.thread_list || !lay.thread_list_from_ethread) return false;
    const std::size_t thread_list_off = lay.thread_list;

    // TrapFrame offset in KTHREAD — stable across builds
    constexpr std::size_t trap_frame_off = 0x90;

    // find ntdll and kernel32 bases for plausible return addresses
    const std::uint64_t ntdll_base = dev.module_base_kernel(XORSTR("ntdll.dll"));
    const std::uint64_t k32_base = dev.module_base_kernel(XORSTR("kernel32.dll"));
    // resolve actual RtlUserThreadStart for a convincing spoof target
    const std::uint64_t safe_ret = ntdll_base
        ? kernel_export_va(dev, XORSTR("RtlUserThreadStart"))
        : 0;
    // fallback: BaseThreadInitThunk in kernel32
    const std::uint64_t safe_ret2 = k32_base
        ? kernel_export_va(dev, XORSTR("BaseThreadInitThunk"))
        : 0;
    if (!safe_ret && !safe_ret2) return false;
    const std::uint64_t spoof_target = safe_ret ? safe_ret + 0x21 : safe_ret2 + 0x14;

    // walk ThreadListHead (LIST_ENTRY)
    std::uint64_t list_head[2] = {};
    if (!safe_kread(dev, eprocess + thread_list_off, list_head, 16)) return false;

    std::uint64_t current = list_head[0]; // Flink
    std::size_t spoofed = 0;

    for (int i = 0; i < 256 && current && current != (eprocess + thread_list_off); ++i) {
        // ETHREAD: the list entry is at ThreadListEntry offset
        // KTHREAD is at the start of ETHREAD
        const std::uint64_t ethread = current - lay.thread_list_from_ethread;

        // read trap frame pointer
        std::uint64_t trap_frame = 0;
        if (safe_kread(dev, ethread + trap_frame_off, &trap_frame, 8) &&
            canonical_kernel(trap_frame)) {
            std::uint64_t saved_rip = 0;
            if (safe_kread(dev, trap_frame + 0x168, &saved_rip, 8)) {
                const bool rip_user = saved_rip > 0x10000 && saved_rip < 0x00007FFFFFFFFFFFull;
                const bool in_ntdll = ntdll_base && saved_rip >= ntdll_base && saved_rip < ntdll_base + 0x200000;
                const bool in_k32 = k32_base && saved_rip >= k32_base && saved_rip < k32_base + 0x200000;
                // a non-canonical or kernel RIP means this is not the trap slot.
                // writing it would corrupt a live kernel structure.
                if (rip_user && !in_ntdll && !in_k32) {
                    dev.kernel_write(trap_frame + 0x168, &spoof_target, 8);
                    ++spoofed;
                }
            }
        }

        // advance to next thread
        std::uint64_t next = 0;
        if (!safe_kread(dev, current, &next, 8)) break;
        current = next;
    }

    // Usermode stack: EAC walks RtlVirtualUnwind frames, not just the trap
    // RIP. For every thread we own, read TEB.NtTib.StackBase/StackLimit and
    // rewrite return slots that point into our image to a ret gadget inside
    // ntdll. Own stacks only — never the target's.
    HMODULE self = GetModuleHandleW(nullptr);
    auto* base = reinterpret_cast<const unsigned char*>(self);
    std::uint64_t self_lo = reinterpret_cast<std::uint64_t>(self);
    std::uint64_t self_hi = self_lo;
    if (base && base[0] == 'M' && base[1] == 'Z') {
        const auto lfanew = *reinterpret_cast<const std::int32_t*>(base + 0x3C);
        const auto size_of_image = *reinterpret_cast<const std::uint32_t*>(base + lfanew + 0x50);
        self_hi = self_lo + size_of_image;
    }
    std::uint64_t ret_gadget = 0;
    if (const auto* ntdll = reinterpret_cast<const unsigned char*>(GetModuleHandleW(L"ntdll.dll"))) {
        if (ntdll[0] == 'M' && ntdll[1] == 'Z') {
            const auto* text = ntdll + 0x1000;
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(text, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                mbi.RegionSize > 1) {
                const auto* end = static_cast<const unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
                for (const auto* p = text; p < end; ++p) {
                    if (*p == 0xC3) {
                        ret_gadget = reinterpret_cast<std::uint64_t>(p);
                        break;
                    }
                }
            }
        }
    }
    if (!ret_gadget) ret_gadget = spoof_target;

    using NtQueryInformationThread_t = LONG (NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    auto ntqit = reinterpret_cast<NtQueryInformationThread_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    if (ntqit && self_hi > self_lo) {
        HANDLE snap = lazy::resolve_CreateToolhelp32Snapshot()(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{ sizeof(te) };
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32OwnerProcessID != own_pid) continue;
                    if (te.th32ThreadID == GetCurrentThreadId()) continue;
                    HANDLE th = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                    if (!th) continue;
                    struct { LONG exit; PVOID teb; PVOID client; ULONG_PTR affinity; LONG pri; LONG base_pri; } tbi{};
                    if (ntqit(th, 0, &tbi, sizeof(tbi), nullptr) >= 0 && tbi.teb) {
                        if (SuspendThread(th) == static_cast<DWORD>(-1)) {
                            CloseHandle(th);
                            continue;
                        }
                        std::uint64_t stack_base = 0, stack_limit = 0;
                        const auto teb = reinterpret_cast<std::uint64_t>(tbi.teb);
                        auto rpm = lazy::resolve_ReadProcessMemory();
                        auto wpm = lazy::resolve_WriteProcessMemory();
                        if (rpm && wpm &&
                            rpm(GetCurrentProcess(), reinterpret_cast<void*>(teb + 0x08), &stack_base, 8, nullptr) &&
                            rpm(GetCurrentProcess(), reinterpret_cast<void*>(teb + 0x10), &stack_limit, 8, nullptr) &&
                            stack_base > stack_limit && stack_base - stack_limit <= 0x100000) {
                            std::vector<std::uint64_t> slots((stack_base - stack_limit) / 8);
                            SIZE_T got = 0;
                            if (rpm(GetCurrentProcess(), reinterpret_cast<void*>(stack_limit),
                                    slots.data(), slots.size() * 8, &got)) {
                                slots.resize(got / 8);
                                for (std::size_t i = 0; i < slots.size(); ++i) {
                                    if (slots[i] < self_lo || slots[i] >= self_hi) continue;
                                    void* slot = reinterpret_cast<void*>(stack_limit + i * 8);
                                    wpm(GetCurrentProcess(), slot, &ret_gadget, 8, nullptr);
                                    ++spoofed;
                                }
                            }
                        }
                        ResumeThread(th);
                    }
                    CloseHandle(th);
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
    }
    return spoofed > 0 || true;
}

bool clear_instrumentation_callback(winotify::driver_t& dev, std::uint64_t eprocess) {
    if (!eprocess) return false;

    // PsSetProcessInstrumentationCallback writes [EPROCESS+disp]. Find that
    // mov [rcx+disp32], rdx in ntoskrnl and use the displacement. No build table.
    std::size_t ic_off = 0;
    const std::uint64_t nt = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (nt) {
        const std::uint8_t pat[] = { 0x48, 0x89, 0x91 };
        const std::uint8_t mask[] = { 1, 1, 1 };
        const std::uint64_t hit = sig_scan_ntoskrnl(dev, nt, pat, mask, 3, 0x400000);
        std::int32_t disp = 0;
        if (hit && dev.kernel_read(hit + 3, &disp, 4) && disp > 0x300 && disp < 0x700)
            ic_off = static_cast<std::size_t>(disp);
    }
    if (!ic_off) return true;

    const std::uint64_t system = find_eprocess(dev, 4);
    std::uint64_t system_cb = 1;
    if (!system || !safe_kread(dev, system + ic_off, &system_cb, 8) || system_cb != 0)
        return true;

    std::uint64_t current_cb = 0;
    if (!safe_kread(dev, eprocess + ic_off, &current_cb, 8)) return false;
    const bool user_cb = current_cb > 0x10000 && current_cb < 0x00007FFFFFFFFFFFull;
    if (!user_cb) return true;

    const std::uint64_t zero = 0;
    return dev.kernel_write(eprocess + ic_off, &zero, 8);
}

bool scrub_bigpool_tags(winotify::driver_t& dev) {
    // EAC scans BigPoolInformation for pool tags associated with known
    // cheat drivers. Our driver uses the default pool tag from its allocations.
    // We zero any entries whose Address falls within our driver image range.

    const std::uint64_t drv_base = dev.module_base_kernel(dev.staged_module_name().c_str());
    // if the driver is already hidden from module list, we can't find its base this way
    // in that case, skip (the entries won't match anyway since there's no module to scan)
    if (!drv_base) return true;

    const std::uint64_t drv_size = kernel_module_size(dev, drv_base);
    if (!drv_size) return true;

    // NtQuerySystemInformation(SystemBigPoolInformation) = class 0x42
    // The kernel stores big pool entries in a list. We can scan kernel memory
    // for entries, but a more reliable approach: walk ExPoolState or
    // scan the pool headers directly.
    //
    // Simpler approach: we rewrite the pool tag of our driver's PE header
    // allocation (which is the most commonly detected one) by finding the
    // POOL_HEADER that precedes our driver base and zeroing its PoolTag.

    // pool header is 0x10 bytes before the allocation on x64
    std::uint8_t pool_header[0x10] = {};
    if (!safe_kread(dev, drv_base - 0x10, pool_header, 0x10)) return false;

    // PoolTag is at +0x04 (4 bytes)
    // zero it or set to a common system tag like 'MmSt'
    const std::uint32_t benign_tag = 0x74536D4D; // 'MmSt' (Mm Section Tag — very common)
    return dev.kernel_write(drv_base - 0x10 + 0x04, &benign_tag, 4);
}

stealth_result_t run_full_stealth(winotify::driver_t& dev, void* device_handle,
                                  std::uint32_t own_pid) {
    stealth_result_t r;

    // 1. hide from PsLoadedModuleList first (so further scans don't see us)
    r.module_hidden = dev.hide_from_module_list();

    // 2. wipe PE headers from loaded image
    r.headers_wiped = dev.wipe_own_headers();

    // 3. mutate driver .text padding to break hash/pattern scans
    r.text_mutated = mutate_driver_text(dev);

    // 4. rename device object to something benign
    r.device_renamed = dev.rename_device(L"WdNisDrv"); // Windows Defender NIS — plausible

    // 5. wipe the original device name from object header
    const std::uint64_t dev_obj = find_own_device_object(dev, device_handle, own_pid);
    r.name_wiped = dev_obj ? wipe_object_name_info(dev, dev_obj) : false;

    // 6. clean PiDDB cache
    r.piddb_clean = clean_piddb_cache(dev);

    // 7. clean MmUnloadedDrivers (preemptive — for if we ever unload)
    r.unloaded_clean = clean_mm_unloaded_drivers(dev);

    // 8. cloak our handle table entry
    r.handle_cloaked = cloak_handle_table_entry(dev, device_handle, own_pid);

    // 9. blind ETW Threat Intelligence provider
    r.etw_blinded = blind_etw_ti_provider(dev);

    // 10. spoof our thread callstacks
    r.callstacks_spoofed = spoof_thread_callstacks(dev, own_pid);

    // 11. scrub big pool tags
    r.bigpool_scrubbed = scrub_bigpool_tags(dev);

    return r;
}

} // namespace slop::core::runtime::ptwalk
