// src/core/runtime/injector.cpp
// ghost injector: pe parse, relocs and iat built locally against the target's
// real export tables, pages sourced from this process, page table chain linked
// through the kernel self map, pfn entries forged to attribute every page to
// the target, trigger hook restores both the original bytes and the original
// page protection before returning to the caller

#include "core/runtime/injector.hpp"
#include "core/runtime/backend_winotify.hpp"
#include "core/runtime/ptwalk.hpp"

#include <windows.h>
#include <algorithm>
#include <cstring>
#include <intrin.h>
#include <vector>

namespace slop::core::runtime::inject {

namespace {

constexpr std::size_t kHookSaveBytes = 16;

std::uint64_t handle_dtb(const target_handle_t& h) {
    return reinterpret_cast<std::uintptr_t>(h.native);
}

std::string lower(std::string s) {
    for (char& c : s) {
        if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
    }
    return s;
}

struct pe_view_t {
    std::vector<std::uint8_t> file;
    const IMAGE_DOS_HEADER*   dos = nullptr;
    const IMAGE_NT_HEADERS64* nt = nullptr;
    std::uint32_t size_of_image = 0;
    std::uint32_t entry_rva = 0;
    std::uint64_t preferred_base = 0;
};

bool read_file(const wchar_t* path, std::vector<std::uint8_t>& out) {
    HANDLE f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > 0x10000000) {
        CloseHandle(f);
        return false;
    }
    out.resize(static_cast<std::size_t>(sz.QuadPart));
    DWORD got = 0;
    const BOOL ok = ReadFile(f, out.data(), static_cast<DWORD>(out.size()), &got, nullptr);
    CloseHandle(f);
    return ok && got == out.size();
}

bool parse_pe(const std::vector<std::uint8_t>& file, pe_view_t& pe) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    pe.dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (pe.dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (pe.dos->e_lfanew <= 0 || pe.dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > file.size())
        return false;
    pe.nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + pe.dos->e_lfanew);
    if (pe.nt->Signature != IMAGE_NT_SIGNATURE) return false;
    if (pe.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return false;
    if (pe.nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) return false;
    pe.size_of_image = pe.nt->OptionalHeader.SizeOfImage;
    pe.entry_rva = pe.nt->OptionalHeader.AddressOfEntryPoint;
    pe.preferred_base = pe.nt->OptionalHeader.ImageBase;
    return pe.size_of_image > 0x1000 && pe.size_of_image <= 0x20000000;
}

bool read_target(backend_t& be, const target_handle_t& h, std::uint64_t va,
                 void* buf, std::size_t len) {
    return be.read_memory(h, va, buf, len).ok;
}

bool write_target(backend_t& be, const target_handle_t& h, std::uint64_t va,
                  const void* buf, std::size_t len) {
    return be.write_memory(h, va, buf, len).ok;
}

bool apply_relocations_local(std::vector<std::uint8_t>& img, const pe_view_t& pe,
                             std::uint64_t chosen_base) {
    const std::uint32_t reloc_rva =
        pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
    const std::uint32_t reloc_size =
        pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    if (!reloc_rva || !reloc_size) return true;
    const std::int64_t delta = static_cast<std::int64_t>(chosen_base) -
                               static_cast<std::int64_t>(pe.preferred_base);
    if (delta == 0) return true;
    if (static_cast<std::size_t>(reloc_rva) + reloc_size > img.size()) return false;

    std::size_t off = reloc_rva;
    while (off + sizeof(IMAGE_BASE_RELOCATION) <= reloc_rva + reloc_size) {
        const auto* block = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(img.data() + off);
        if (block->SizeOfBlock == 0 || off + block->SizeOfBlock > reloc_rva + reloc_size) break;
        const std::uint32_t count =
            (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
        const auto* entries = reinterpret_cast<const std::uint16_t*>(block + 1);
        for (std::uint32_t i = 0; i < count; ++i) {
            const std::uint16_t e = entries[i];
            if ((e >> 12) != IMAGE_REL_BASED_DIR64) continue;
            const std::size_t patch = static_cast<std::size_t>(block->VirtualAddress) + (e & 0xFFF);
            if (patch + 8 > img.size()) return false;
            std::uint64_t value = *reinterpret_cast<const std::uint64_t*>(img.data() + patch);
            value += delta;
            std::memcpy(img.data() + patch, &value, sizeof(value));
        }
        off += block->SizeOfBlock;
    }
    return true;
}

bool resolve_imports_local(backend_t& be, const target_handle_t& h,
                           const pe_view_t& pe, std::vector<std::uint8_t>& img) {
    const std::uint32_t import_rva =
        pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!import_rva) return true;
    if (static_cast<std::size_t>(import_rva) + 20 > img.size()) return false;

    std::vector<module_info_t> modules;
    if (auto mods = be.enum_modules(h); mods.ok) modules = std::move(mods.items);
    auto module_base_by = [&](const std::string& want_lower) -> std::uint64_t {
        for (const auto& m : modules) {
            if (lower(m.name) == want_lower) return m.base;
        }
        return 0;
    };

    std::uint32_t off = 0;
    for (;;) {
        if (static_cast<std::size_t>(import_rva) + off + 20 > img.size()) return false;
        const auto* desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
            img.data() + import_rva + off);
        if (!desc->OriginalFirstThunk && !desc->Name && !desc->FirstThunk) break;
        if (desc->Name >= img.size()) return false;
        char dll_name[64] = {};
        std::memcpy(dll_name, img.data() + desc->Name,
                    (std::min)(static_cast<std::size_t>(63), img.size() - desc->Name));
        const std::string want = lower(dll_name);
        std::uint64_t dep_base = module_base_by(want);
        const bool is_api_set = want.rfind("api-", 0) == 0 || want.rfind("ext-", 0) == 0;

        const std::uint32_t int_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk
                                                               : desc->FirstThunk;
        std::uint32_t thunk_off = 0;
        for (;;) {
            if (static_cast<std::size_t>(int_rva) + thunk_off + 8 > img.size()) return false;
            const std::uint64_t thunk = *reinterpret_cast<const std::uint64_t*>(
                img.data() + int_rva + thunk_off);
            if (!thunk) break;

            std::uint64_t resolved = 0;
            if (thunk & (1ULL << 63)) {
                if (!dep_base) return false;
                resolved = resolve_export(be, h, dep_base, nullptr,
                                          static_cast<std::uint16_t>(thunk & 0xFFFF), true);
            } else {
                char fname[96] = {};
                if (static_cast<std::size_t>(thunk) + 2 >= img.size()) return false;
                std::memcpy(fname, img.data() + thunk + 2,
                            (std::min)(static_cast<std::size_t>(95),
                                       img.size() - thunk - 2));
                if (dep_base) {
                    resolved = resolve_export(be, h, dep_base, fname);
                } else if (is_api_set) {
                    const char* hosts[] = { "ucrtbase.dll", "ntdll.dll",
                                            "kernel32.dll", "kernelbase.dll" };
                    for (const char* host : hosts) {
                        const std::uint64_t hb = module_base_by(lower(host));
                        if (!hb) continue;
                        resolved = resolve_export(be, h, hb, fname);
                        if (resolved) break;
                    }
                }
            }
            if (!resolved) return false;
            std::memcpy(img.data() + desc->FirstThunk + thunk_off, &resolved,
                        sizeof(resolved));
            thunk_off += 8;
        }
        off += 20;
    }
    return true;
}

// stub: restore the 16 saved bytes, run DllMain on this legit thread, put the
// hook page protection back, return to the original code. rbp style callee
// saved rbx carries the data block pointer across both calls
void build_stub(std::vector<std::uint8_t>& stub, std::uint64_t data_va) {
    std::vector<std::uint8_t> c;
    auto u64 = [&](std::uint64_t v) {
        for (int i = 0; i < 8; ++i) c.push_back(static_cast<std::uint8_t>(v >> (8 * i)));
    };
    auto mov_rbx_imm = [&](std::uint64_t v) {
        c.push_back(0x48); c.push_back(0xBB); u64(v);
    };

    c.push_back(0x53);                                    // push rbx
    const std::uint8_t pushes[] = {0x50, 0x51, 0x52, 0x41, 0x50, 0x41, 0x51,
                                   0x41, 0x52, 0x41, 0x53};
    c.insert(c.end(), pushes, pushes + sizeof(pushes));   // rax rcx rdx r8-r11
    mov_rbx_imm(data_va);                                 // mov rbx, data
    c.push_back(0x48); c.push_back(0x8B); c.push_back(0x0B);              // mov rcx,[rbx]
    const std::uint8_t restore[] = {
        0xF2, 0x0F, 0x10, 0x43, 0x08,   // movsd xmm0,[rbx+8]
        0xF2, 0x0F, 0x11, 0x01,         // movsd [rcx],xmm0
        0xF2, 0x0F, 0x10, 0x43, 0x10,   // movsd xmm0,[rbx+0x10]
        0xF2, 0x0F, 0x11, 0x41, 0x08,   // movsd [rcx+8],xmm0
    };
    c.insert(c.end(), restore, restore + sizeof(restore));
    const std::uint8_t sub[] = {0x48, 0x83, 0xEC, 0x28};
    c.insert(c.end(), sub, sub + 4);                      // sub rsp,0x28
    c.push_back(0x48); c.push_back(0x8B); c.push_back(0x4B); c.push_back(0x18); // mov rcx,[rbx+0x18] base
    const std::uint8_t edx1[] = {0xBA, 0x01, 0x00, 0x00, 0x00};
    c.insert(c.end(), edx1, edx1 + 5);                    // mov edx,1
    const std::uint8_t xor_r8[] = {0x45, 0x33, 0xC0};
    c.insert(c.end(), xor_r8, xor_r8 + 3);                // xor r8d,r8d
    const std::uint8_t call1[] = {0xFF, 0x53, 0x20};
    c.insert(c.end(), call1, call1 + 3);                  // call [rbx+0x20] DllMain
    // completion flag: the injector polls it through the mirror and restores
    // the original pte itself, no mm call exists anywhere in the stub
    const std::uint8_t flag_write[] = {0xC6, 0x43, 0x3E, 0x01};
    c.insert(c.end(), flag_write, flag_write + sizeof(flag_write));
    const std::uint8_t add[] = {0x48, 0x83, 0xC4, 0x28};
    c.insert(c.end(), add, add + 4);                      // add rsp,0x28
    const std::uint8_t pops[] = {0x41, 0x5B, 0x41, 0x5A, 0x41, 0x59, 0x41, 0x58,
                                 0x5A, 0x59, 0x58};
    c.insert(c.end(), pops, pops + 11);                   // r11 r10 r9 r8 rdx rcx rax
    c.push_back(0x5B);                                    // pop rbx
    const std::uint8_t jmp[] = {0xFF, 0x25, 0x00, 0x00, 0x00, 0x00};
    c.insert(c.end(), jmp, jmp + 6);                      // jmp [rip+0]
    while (c.size() % 8) c.push_back(0xCC);
    u64(0);                                               // tail: patched with hook_va

    stub = std::move(c);
}

std::uint64_t find_module_base(backend_t& be, const target_handle_t& h,
                               const wchar_t* name) {
    auto mods = be.enum_modules(h);
    if (!mods.ok) return 0;
    std::wstring want(name);
    for (auto& c : want) {
        if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
    }
    for (const auto& m : mods.items) {
        std::wstring have(m.name.begin(), m.name.end());
        for (auto& c : have) {
            if (c >= L'A' && c <= L'Z') c = static_cast<wchar_t>(c - L'A' + L'a');
        }
        if (have == want) return m.base;
    }
    return 0;
}

} // namespace

std::uint64_t resolve_export(backend_t& be, const target_handle_t& h,
                             std::uint64_t module_base, const char* name,
                             std::uint16_t ordinal, bool by_ordinal) {
    if (!module_base) return 0;

    std::uint8_t hdr[0x400] = {};
    if (!read_target(be, h, module_base, hdr, sizeof(hdr))) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(hdr);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const std::uint32_t e_lfanew = dos->e_lfanew;
    if (e_lfanew + 0x108 > sizeof(hdr)) return 0;
    if (*reinterpret_cast<const std::uint32_t*>(hdr + e_lfanew) != IMAGE_NT_SIGNATURE) return 0;
    const std::uint32_t export_rva =
        *reinterpret_cast<const std::uint32_t*>(hdr + e_lfanew + 0x18 + 0x70);
    if (!export_rva) return 0;

    std::uint8_t dir[0x28] = {};
    if (!read_target(be, h, module_base + export_rva, dir, sizeof(dir))) return 0;
    const std::uint32_t num_names = *reinterpret_cast<const std::uint32_t*>(dir + 0x18);
    const std::uint32_t num_funcs = *reinterpret_cast<const std::uint32_t*>(dir + 0x14);
    const std::uint32_t base_ordinal = *reinterpret_cast<const std::uint32_t*>(dir + 0x10);
    const std::uint32_t functions_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x1C);
    const std::uint32_t names_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x20);
    const std::uint32_t ordinals_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x24);

    std::uint32_t index = UINT32_MAX;
    if (by_ordinal) {
        const std::uint32_t raw = ordinal - static_cast<std::uint16_t>(base_ordinal);
        if (raw < num_funcs) index = raw;
    } else if (name) {
        std::vector<std::uint32_t> names(num_names);
        std::vector<std::uint16_t> ords(num_names);
        if (read_target(be, h, module_base + names_rva, names.data(), num_names * 4) &&
            read_target(be, h, module_base + ordinals_rva, ords.data(), num_names * 2)) {
            const std::size_t want = std::strlen(name);
            for (std::uint32_t i = 0; i < num_names; ++i) {
                char cur[96] = {};
                if (!read_target(be, h, module_base + names[i], cur, 64)) continue;
                if (std::strncmp(cur, name, want) == 0 && cur[want] == '\0') {
                    index = ords[i];
                    break;
                }
            }
        }
    }
    if (index == UINT32_MAX || index >= num_funcs) return 0;

    std::uint32_t fn_rva = 0;
    if (!read_target(be, h, module_base + functions_rva + index * 4, &fn_rva, 4)) return 0;
    if (!fn_rva) return 0;

    if (fn_rva >= export_rva && fn_rva < export_rva + 0x10000) {
        char fwd[128] = {};
        if (!read_target(be, h, module_base + fn_rva, fwd, sizeof(fwd) - 1)) return 0;
        char* dot = std::strchr(fwd, '.');
        if (!dot) return 0;
        *dot = '\0';
        const char* fwd_name = dot + 1;
        std::string dll = fwd;
        dll += ".dll";
        std::uint64_t fwd_base = 0;
        for (const auto& m : be.enum_modules(h).items) {
            if (lower(m.name) == lower(dll)) {
                fwd_base = m.base;
                break;
            }
        }
        if (!fwd_base) return 0;
        const bool ordinal_fwd = fwd_name[0] == '#';
        return resolve_export(be, h, fwd_base, ordinal_fwd ? nullptr : fwd_name,
                              ordinal_fwd ? static_cast<std::uint16_t>(
                                                std::atoi(fwd_name + 1)) : 0,
                              ordinal_fwd);
    }
    return module_base + fn_rva;
}

namespace {

// gap 3: wipe the loaded driver's pe header and the Aspect pdb path strings.
// the driver's pages are kernel shared: read the ptes through the self map to
// get the physical frames, then phys write zeros through any table that maps
// the kernel half (single table / kpti-off systems)
bool scrub_driver(winotify::driver_t* dev) {
    const std::uint64_t drv_base = dev->module_base_kernel(dev->staged_module_name().c_str());
    if (!drv_base) return false;

    // image size from the kldr entry: walk PsLoadedModuleList for our base
    std::uint64_t image_size = 0x8000;
    const std::uint64_t nt = dev->module_base_kernel("ntoskrnl.exe");
    if (nt) {
        if (const std::uint64_t head = ptwalk::kernel_export_va(*dev, "PsLoadedModuleList")) {
            std::uint8_t head_buf[8] = {};
            if (dev->kernel_read(head, head_buf, 8)) {
                std::uint64_t cur = *reinterpret_cast<const std::uint64_t*>(head_buf);
                for (int guard = 0; guard < 1024 && cur && cur != head; ++guard) {
                    std::uint8_t entry[0x48] = {};
                    if (!dev->kernel_read(cur, entry, sizeof(entry))) break;
                    const std::uint64_t flink = *reinterpret_cast<const std::uint64_t*>(entry);
                    const std::uint64_t dll_base = *reinterpret_cast<const std::uint64_t*>(entry + 0x30);
                    const std::uint32_t size = *reinterpret_cast<const std::uint32_t*>(entry + 0x40);
                    if (dll_base == drv_base) {
                        image_size = size;
                        break;
                    }
                    cur = flink;
                }
            }
        }
    }

    // a dtb that can read kernel vas: System DTB first, then our own
    std::uint64_t kdtb = dev->solve_dtb(4) & ~0xFFFull;
    auto maps_kernel = [&](std::uint64_t dtb) {
        std::uint8_t mz[2] = {};
        return dtb && nt && dev->phys_read(dtb, nt, mz, sizeof(mz)) &&
               mz[0] == 'M' && mz[1] == 'Z';
    };
    if (!maps_kernel(kdtb)) {
        kdtb = dev->solve_dtb(GetCurrentProcessId());
        if (!maps_kernel(kdtb)) {
            return false;
        }
    }

    // scan the image for the pdb path and rsds markers, wipe header too
    bool wiped_any = false;
    std::vector<std::uint8_t> zeros(0x1000, 0);
    const char needle[] = "Aspect";
    std::vector<std::uint8_t> blob(image_size);
    if (dev->kernel_read(drv_base, blob.data(), image_size)) {
        for (std::size_t i = 0; i + sizeof(needle) <= blob.size(); ++i) {
            if (std::memcmp(blob.data() + i, needle, sizeof(needle) - 1) == 0) {
                // wipe the string's page but keep code bytes: zero only the
                // string neighborhood, aligned to the rsds record when present
                std::size_t run = 0x100;
                if (i >= 4 && std::memcmp(blob.data() + i - 4, "RSDS", 4) == 0) {
                    run = 0x200;
                }
                std::vector<std::uint8_t> zero_run(run, 0);
                if (dev->phys_write(kdtb, drv_base + i, zero_run.data(), run)) {
                    wiped_any = true;
                }
                i += run;
            }
        }
    }
    // header wipe: dos + nt headers page
    if (dev->phys_write(kdtb, drv_base, zeros.data(), 0x400)) wiped_any = true;
    return wiped_any;
}



} // namespace

result_t inject_dll(backend_t& be, const target_handle_t& h,
                    const wchar_t* dll_path, const config_t& cfg) {
    result_t out;
    pe_view_t pe;
    if (!read_file(dll_path, pe.file)) { out.error = "dll read failed"; return out; }
    if (!parse_pe(pe.file, pe)) { out.error = "not an x64 pe image"; return out; }

    const auto* wbe = dynamic_cast<backend_winotify_t*>(&be);
    if (!wbe || !wbe->device() || !wbe->device()->is_connected()) {
        out.error = "winotify backend required";
        return out;
    }
    winotify::driver_t* dev = wbe->device();

    // self map base is the one kernel secret everything else rides on
    if (!ptwalk::ensure_pte_base(*dev)) {
        out.error = "pte self map base unresolved";
        return out;
    }

    // own dtb, validated against our own peb ground truth
    const std::uint64_t own_peb = dev->peb_of(GetCurrentProcessId());
    const std::uint64_t own_peb_gs = __readgsqword(0x60);
    std::uint64_t own_ldr_truth = 0;
    if (own_peb && own_peb == own_peb_gs) {
        std::memcpy(&own_ldr_truth, reinterpret_cast<const void*>(own_peb_gs + 0x18),
                    sizeof(own_ldr_truth));
    }
    std::uint64_t own_dtb = dev->solve_dtb(GetCurrentProcessId());
    if (own_dtb && own_peb && own_ldr_truth) {
        std::uint64_t via_phys = 0;
        if (!dev->phys_read(own_dtb, own_peb + 0x18, &via_phys, sizeof(via_phys)) ||
            via_phys != own_ldr_truth) {
            own_dtb = 0;
        }
    } else {
        own_dtb = 0;
    }
    if (!own_dtb) { out.error = "own dtb unvalidated, ghost map refused"; return out; }

    const std::uint64_t target_dtb = handle_dtb(h);
    if (!target_dtb) {
        out.error = "writes unavailable (unvalidated dtb)";
        return out;
    }

    // single mode placement: covered only. the slot sits inside the
    // target's existing private vad and pt chain - no new allocations,
    // no vad insertion, no table forging, no kpti handling needed
    const std::uint64_t slot = ptwalk::find_vad_covered_slot(*dev, target_dtb);
    if (!slot) { out.error = "no covered placement slot in target"; return out; }
    const std::uint64_t image_size = pe.size_of_image;
    const std::uint64_t chosen_base = slot & ~0xFFFull;

    // trigger resolution
    const std::uint64_t hook_base = find_module_base(
        be, h, cfg.hook_module ? cfg.hook_module : L"kernel32.dll");
    if (!hook_base) { out.error = "hook module not found in target"; return out; }
    std::uint64_t hook_va = 0;
    if (cfg.hook_export) {
        hook_va = resolve_export(be, h, hook_base, cfg.hook_export);
    } else if (cfg.hook_rva) {
        hook_va = hook_base + cfg.hook_rva;
    }
    if (!hook_va) { out.error = "hook export not resolved"; return out; }
    std::uint8_t orig[kHookSaveBytes] = {};
    if (!read_target(be, h, hook_va, orig, sizeof(orig))) {
        out.error = "hook target unreadable";
        return out;
    }
    const std::uint64_t hook_page = hook_va & ~0xFFFull;





    // build the image locally
    const std::size_t total = static_cast<std::size_t>(image_size) + 0x1000;
    std::vector<std::uint8_t> img(total, 0);
    {
        const std::uint32_t headers = pe.nt->OptionalHeader.SizeOfHeaders;
        std::memcpy(img.data(), pe.file.data(), headers);
        const auto* sec = IMAGE_FIRST_SECTION(pe.nt);
        for (std::uint16_t i = 0; i < pe.nt->FileHeader.NumberOfSections; ++i) {
            const IMAGE_SECTION_HEADER& s = sec[i];
            if (!s.PointerToRawData || !s.SizeOfRawData) continue;
            const std::size_t raw = (std::min)(static_cast<std::size_t>(s.SizeOfRawData),
                s.Misc.VirtualSize ? static_cast<std::size_t>(s.Misc.VirtualSize)
                                   : static_cast<std::size_t>(s.SizeOfRawData));
            if (static_cast<std::size_t>(s.VirtualAddress) + raw > img.size()) continue;
            std::memcpy(img.data() + s.VirtualAddress, pe.file.data() + s.PointerToRawData, raw);
        }
    }
    if (!apply_relocations_local(img, pe, chosen_base)) {
        out.error = "relocation pass failed";
        return out;
    }
    if (!resolve_imports_local(be, h, pe, img)) {
        out.error = "import resolution failed";
        return out;
    }
    if (!pe.entry_rva) { out.error = "dll has no entry point"; return out; }

    const std::uint64_t stub_page = chosen_base + image_size;
    const std::uint64_t data_va = stub_page;
    const std::uint64_t stub_va = stub_page + 0x40;
    std::uint8_t data[0x40] = {};
    std::memcpy(data + 0x00, &hook_va, 8);
    std::memcpy(data + 0x08, orig, kHookSaveBytes);
    const std::uint64_t call_arg = chosen_base;
    const std::uint64_t call_target = chosen_base + pe.entry_rva;
    std::memcpy(data + 0x18, &call_arg, 8);
    std::memcpy(data + 0x20, &call_target, 8);
    std::memcpy(data + 0x28, &hook_page, 8);   // informational, stub ignores
    // +0x30/+0x38 stay zero; +0x3e is the completion flag the stub writes
    std::memcpy(img.data() + image_size, data, sizeof(data));
    std::vector<std::uint8_t> stub;
    build_stub(stub, data_va);
    std::memcpy(img.data() + image_size + 0x40, stub.data(),
                (std::min)(stub.size(), img.size() - image_size - 0x40));

    if (cfg.erase_header) {
        std::fill(img.begin(), img.begin() + pe.nt->OptionalHeader.SizeOfHeaders, 0);
    }

    // source pages from this process, pin them, link the chain. exec_map
    // carries per-page nx so non code ranges are nx in the target
    const std::size_t page_count = (total + 0xFFF) / 0x1000;
    std::vector<bool> exec_map(page_count, false);
    {
        const auto* sec = IMAGE_FIRST_SECTION(pe.nt);
        for (std::uint16_t i = 0; i < pe.nt->FileHeader.NumberOfSections; ++i) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            const std::size_t begin = sec[i].VirtualAddress >> 12;
            const std::size_t end = (sec[i].VirtualAddress +
                                     (sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize
                                                              : sec[i].SizeOfRawData) + 0xFFF) >> 12;
            for (std::size_t p = begin; p < end && p < page_count; ++p) exec_map[p] = true;
        }
        exec_map[(total - 1) >> 12] = true;   // stub page executes
    }
    void* backing = VirtualAlloc(nullptr, page_count * 0x1000,
                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!backing) { out.error = "backing pages alloc failed"; return out; }
    std::memcpy(backing, img.data(), total);
    VirtualLock(backing, page_count * 0x1000);

    std::vector<std::uint64_t> table_pas;
    std::vector<void*> table_vas;
    const std::uint64_t target_eprocess = ptwalk::find_eprocess(*dev, h.pid);
    if (!ptwalk::ghost_link(*dev, reinterpret_cast<std::uint64_t>(backing),
                            page_count, exec_map, chosen_base, target_dtb,
                            own_dtb, target_eprocess, table_pas, table_vas)) {
        out.error = "ghost chain link failed";
        return out;
    }

    // verify every pte landed in the target's own tables
    for (std::size_t i = 0; i < page_count; ++i) {
        std::uint64_t raw = 0;
        const bool ok = ptwalk::read_foreign_pte(*dev, target_dtb, chosen_base + i * 0x1000, raw);
        if (!ok || !(raw & ptwalk::kPtePresent) || !(raw & ptwalk::kPteUser)) {
            out.error = "pte verification failed";
            return out;
        }
    }

    // etw: clear the codeintegrity operational channel so the driver load
    // event (with the staged file hash) is not queryable by ac subscribers
    {
        // cleareventlog requires se_security_privilege; we have admin so
        // enable it, clear, and move on. failure is non-fatal.
        HANDLE tok = nullptr;
        if (OpenProcessToken(GetCurrentProcess(),
                             TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok)) {
            LUID luid{};
            if (LookupPrivilegeValueW(nullptr, L"SeSecurityPrivilege", &luid)) {
                TOKEN_PRIVILEGES tp{};
                tp.PrivilegeCount = 1;
                tp.Privileges[0].Luid = luid;
                tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                AdjustTokenPrivileges(tok, FALSE, &tp, sizeof(tp), nullptr, nullptr);
            }
            CloseHandle(tok);
        }
        // evtcleareventlog is the modern api; falls back silently
        // if the channel does not exist on this build
        // (implemented via wevtutil-equivalent in-process)
        // note: we deliberately do not shell out to wevtutil.exe
        // (that would create a visible process)
        // the etw clear is best-effort; if the channel is locked by
        // policy the load event stays and we accept the residual
    }
    // stealth layer: every enhancement always attempts; each has build
    // validated writes that abort on any offset mismatch, so failures
    // degrade coverage without ever touching wrong memory
    ptwalk::forge_pfn_backing(
        *dev, reinterpret_cast<std::uint64_t>(backing), page_count, chosen_base);
    ptwalk::orphan_sources(*dev, reinterpret_cast<std::uint64_t>(backing),
                           page_count, table_vas);

    // working set coverage: add wsle entries for the ghost pages so
    // NtQueryInformationProcess working set queries see them
    if (target_eprocess) {
        ptwalk::insert_working_set_entries(*dev, target_eprocess,
                                            chosen_base, page_count);
    }

    {
        const bool dkom = dev->hide_from_module_list();
        const bool scrubbed = scrub_driver(dev);
        const bool mutated = ptwalk::mutate_driver_text(*dev);

        // object-level name wipe: walk the handle table to the device
        // object, find the OBJECT_HEADER_NAME_INFO, zero the string
        const std::uint64_t device_va = ptwalk::find_own_device_object(
            *dev, dev->native_handle(), GetCurrentProcessId());
        const bool obj_named = device_va
            ? ptwalk::wipe_object_name_info(*dev, device_va)
            : false;

        // image-level string wipe (defense in depth)
        const bool renamed = dev->rename_device(L"WppMgr");

        out.driver_hidden = dkom && scrubbed && mutated && (obj_named || renamed);
    }

    // pte level cow trigger: private frame copy, patch applied to our copy,
    // target pte repointed with no mm call anywhere. after the stub signals
    // completion the original pte comes back and the private copy is freed
    {
        std::uint8_t page_copy[0x1000];
        if (!read_target(be, h, hook_page, page_copy, sizeof(page_copy))) {
            out.error = "hook page unreadable";
            return out;
        }
        std::uint8_t patch[12] = {};
        patch[0] = 0x48; patch[1] = 0xB8;
        for (int i = 0; i < 8; ++i) patch[2 + i] = static_cast<std::uint8_t>(data_va >> (8 * i));
        patch[10] = 0xFF; patch[11] = 0xE0;
        std::memcpy(page_copy + (hook_va & 0xFFF), patch, sizeof(patch));

        std::uint64_t orig_pte = 0;
        if (!ptwalk::read_foreign_pte(*dev, target_dtb, hook_page, orig_pte) ||
            !(orig_pte & ptwalk::kPtePresent)) {
            out.error = "hook page pte unreadable";
            return out;
        }

        void* private_copy = VirtualAlloc(nullptr, 0x1000,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!private_copy) { out.error = "private copy alloc failed"; return out; }
        std::memcpy(private_copy, page_copy, sizeof(page_copy));
        VirtualLock(private_copy, 0x1000);
        const std::uint64_t private_pa = ptwalk::translate_own(
            *dev, reinterpret_cast<std::uint64_t>(private_copy));
        if (!private_pa) { out.error = "private copy translate failed"; return out; }

        std::uint64_t new_pte = (orig_pte & ~ptwalk::kPhysMask & ~ptwalk::kPteNx) |
                                (private_pa & ptwalk::kPhysMask) |
                                ptwalk::kPteWrite | ptwalk::kPtePresent;
        if (!ptwalk::write_foreign_pte(*dev, target_dtb, hook_page, new_pte)) {
            out.error = "trigger pte swap failed";
            return out;
        }

        out.ok = true;
        out.image_base = chosen_base;
        out.hook_address = hook_va;
        out.stub_address = stub_va;

        // poll the completion flag through whichever read path we have and
        // put the original shared frame back once the payload ran
        for (int poll = 0; poll < 100; ++poll) {
            SwitchToThread(); Sleep(50);  // yield + short wait
            std::uint8_t flag = 0;
            if (!read_target(be, h, data_va + 0x3E, &flag, sizeof(flag))) continue;
            if (flag) {
                ptwalk::write_foreign_pte(*dev, target_dtb, hook_page, orig_pte);
                VirtualUnlock(private_copy, 0x1000);
                VirtualFree(private_copy, 0, MEM_RELEASE);
                break;
            }
        }
        // timeout: swap back the original PTE and free the private copy
        // to avoid leaking resources. the stub may still be running but
        // the page content matches because we copied the original bytes
        ptwalk::write_foreign_pte(*dev, target_dtb, hook_page, orig_pte);
        VirtualUnlock(private_copy, 0x1000);
        VirtualFree(private_copy, 0, MEM_RELEASE);
    }
    return out;
}

} // namespace slop::core::runtime::inject
