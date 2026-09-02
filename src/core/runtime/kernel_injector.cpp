// src/core/runtime/kernel_injector.cpp

#include "core/runtime/kernel_injector.hpp"

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/kernel_service.hpp"
#include "core/runtime/voyager_comm.h"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <memory>
#include <string_view>

namespace slop::core::runtime::injector {

namespace {

// --- driver plumbing ------------------------------------------------------

voyager::device_t* active_dev(std::string* error) {
    auto* k = dynamic_cast<backend_kernel_t*>(&active());
    if (!k || !k->device()) {
        if (error) *error = "kernel driver not active (load slopdrvr first)";
        return nullptr;
    }
    return k->device();
}

// Bind the device to a target pid: switch the device's process context,
// resolve DTB if missing. Everything downstream (read_raw, write_raw,
// allocate_memory, call_function) rides on this.
bool bind_pid(voyager::device_t& dev, uint32_t pid, std::string* error) {
    if (pid == 0 || pid <= 4) {
        if (error) *error = "invalid pid";
        return false;
    }
    if (dev.get_process_id() != pid) {
        dev.set_process_id(pid);
    }
    if (dev.get_dtb() == 0) {
        const uint64_t dtb = dev.solve_dtb_for_pid(pid);
        if (dtb == 0) {
            if (error) *error = "dtb resolve failed for pid " + std::to_string(pid);
            return false;
        }
        dev.set_dtb(dtb);
    }
    return true;
}

// --- text helpers ---------------------------------------------------------

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool inameeq(const std::string& have, const std::string& want) {
    if (iequals(have, want)) return true;
    // let callers omit the .dll suffix
    if (iequals(have, want + ".dll")) return true;
    if (want.size() > 4) {
        const std::string tail = want.substr(want.size() - 4);
        if (iequals(tail, ".dll") && iequals(have, want.substr(0, want.size() - 4))) return true;
    }
    return false;
}

std::wstring utf8_to_wide(std::string_view s) {
    if (s.empty()) return {};
    const int wn = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                       static_cast<int>(s.size()), nullptr, 0);
    if (wn <= 0) return {};
    std::wstring out(static_cast<size_t>(wn), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), wn);
    return out;
}

std::string wide_to_utf8(const wchar_t* p, size_t n) {
    if (!p || !n) return {};
    const int un = WideCharToMultiByte(CP_UTF8, 0, p, static_cast<int>(n),
                                       nullptr, 0, nullptr, nullptr);
    if (un <= 0) return {};
    std::string out(static_cast<size_t>(un), '\0');
    WideCharToMultiByte(CP_UTF8, 0, p, static_cast<int>(n), out.data(), un,
                        nullptr, nullptr);
    return out;
}

// --- log helper -----------------------------------------------------------

void log(inject_result_t& r, std::string stage, std::string msg) {
    r.log.push_back({std::move(stage), std::move(msg)});
}

// --- target ldr walker ----------------------------------------------------

struct ldr_module_t {
    uint64_t    base = 0;
    uint32_t    size = 0;
    uint64_t    entry_point = 0;
    std::string name;
    std::string path;
};

std::string read_remote_utf16(voyager::device_t& dev, uint64_t addr,
                              uint16_t bytes) {
    if (!addr || !bytes) return {};
    const size_t chars = std::min<uint32_t>(bytes / 2u, 512u);
    if (!chars) return {};
    std::vector<wchar_t> raw(chars, L'\0');
    if (dev.read_raw(addr, raw.data(), chars * sizeof(wchar_t)) !=
        chars * sizeof(wchar_t))
        return {};
    return wide_to_utf8(raw.data(), chars);
}

// Walk InLoadOrderModuleList (PEB_LDR_DATA + 0x10). LDR_DATA_TABLE_ENTRY
// offsets on x64: DllBase=0x30, EntryPoint=0x38, SizeOfImage=0x40,
// FullDllName.Buffer=0x50, BaseDllName.Length=0x58, BaseDllName.Buffer=0x60.
// Same offsets driver.peb_modules uses.
std::vector<ldr_module_t> ldr_modules(voyager::device_t& dev,
                                      std::string* error = nullptr) {
    std::vector<ldr_module_t> out;
    voyager::device_t::peb_info peb{};
    if (!dev.read_peb(peb) || peb.ldr_address == 0) {
        if (error) *error = "read_peb failed (ldr null)";
        return out;
    }
    const uint64_t head = peb.ldr_address + 0x10;
    uint64_t cur = dev.read<uint64_t>(head);
    for (int iter = 0; iter < 1024 && cur && cur != head; ++iter) {
        const uint64_t entry = cur;
        ldr_module_t m;
        m.base = dev.read<uint64_t>(entry + 0x30);
        m.entry_point = dev.read<uint64_t>(entry + 0x38);
        m.size = dev.read<uint32_t>(entry + 0x40);
        const uint16_t base_len = dev.read<uint16_t>(entry + 0x58);
        const uint64_t base_buf = dev.read<uint64_t>(entry + 0x60);
        const uint16_t full_len = dev.read<uint16_t>(entry + 0x48);
        const uint64_t full_buf = dev.read<uint64_t>(entry + 0x50);
        m.name = read_remote_utf16(dev, base_buf, base_len);
        m.path = read_remote_utf16(dev, full_buf, full_len);
        const uint64_t next = dev.read<uint64_t>(cur);
        if (m.base) out.push_back(std::move(m));
        if (next == cur) break;
        cur = next;
    }
    return out;
}

std::optional<uint64_t> find_module_in_ldr(
    const std::vector<ldr_module_t>& mods, const std::string& want) {
    for (const auto& m : mods) {
        if (inameeq(m.name, want)) return m.base;
    }
    return std::nullopt;
}

// --- apiset schema (coarse but covers 99% of CRT/system imports) ---------
//
// A DLL importing from api-ms-win-crt-runtime-l1-1-0.dll actually resolves
// through ntdll's ApiSet namespace to a real backing DLL (usually
// ucrtbase/kernelbase). Rather than parse ApiSetSchema.dll or PEB+0x68
// (varies across Win10/11 builds), we short-circuit the prefixes that
// cover every apiset we hit in practice. If nothing matches, we return the
// original name and let LDR lookup fail loudly.
std::string apiset_backing_dll(std::string_view name) {
    auto low = std::string(name);
    for (auto& c : low) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    auto starts = [&](const char* p) {
        return low.rfind(p, 0) == 0;
    };
    if (starts("api-ms-win-crt-"))              return "ucrtbase.dll";
    if (starts("api-ms-win-core-"))             return "kernelbase.dll";
    if (starts("api-ms-win-eventing-"))         return "kernelbase.dll";
    if (starts("api-ms-win-security-"))         return "sechost.dll";
    if (starts("api-ms-win-service-"))          return "sechost.dll";
    if (starts("api-ms-win-devices-"))          return "kernelbase.dll";
    if (starts("api-ms-win-power-"))            return "kernelbase.dll";
    if (starts("api-ms-win-appmodel-"))         return "kernelbase.dll";
    if (starts("api-ms-win-shcore-"))           return "shcore.dll";
    if (starts("ext-ms-win-"))                  return "kernelbase.dll";
    return low; // unmapped - caller will fail if it's an apiset name
}

// --- forwarder-aware export resolver -------------------------------------
//
// Driver's resolve_export ioctl returns 0 for forwarded exports (their RVA
// points inside the export directory as a "OTHERDLL.Function" string, not a
// real function). We walk the export table ourselves via dev.read_raw so we
// see forwarders, then chase them across DLLs. Handles ordinal forwarders
// ("DLL.#123") and apiset forwarders too.
std::optional<uint64_t>
resolve_export_forwarded(voyager::device_t& dev,
                         const std::vector<ldr_module_t>& mods,
                         uint64_t module_base, const std::string& name,
                         int depth = 0) {
    if (depth > 6 || module_base == 0 || name.empty()) return std::nullopt;

    IMAGE_DOS_HEADER dos{};
    if (dev.read_raw(module_base, &dos, sizeof(dos)) != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) return std::nullopt;
    IMAGE_NT_HEADERS64 nt{};
    if (dev.read_raw(module_base + dos.e_lfanew, &nt, sizeof(nt)) != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) return std::nullopt;
    const auto& exp_dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (exp_dir.Size == 0 || exp_dir.VirtualAddress == 0) return std::nullopt;

    IMAGE_EXPORT_DIRECTORY exp{};
    if (dev.read_raw(module_base + exp_dir.VirtualAddress, &exp, sizeof(exp))
            != sizeof(exp)) return std::nullopt;

    const uint32_t n_names = exp.NumberOfNames;
    const uint32_t n_funcs = exp.NumberOfFunctions;
    if (!n_names || !n_funcs) return std::nullopt;

    // Read the three parallel tables in one go
    std::vector<uint32_t> names(n_names, 0);
    std::vector<uint16_t> ords(n_names, 0);
    std::vector<uint32_t> funcs(n_funcs, 0);
    if (dev.read_raw(module_base + exp.AddressOfNames,
                     names.data(), names.size() * 4)
            != names.size() * 4) return std::nullopt;
    if (dev.read_raw(module_base + exp.AddressOfNameOrdinals,
                     ords.data(), ords.size() * 2)
            != ords.size() * 2) return std::nullopt;
    if (dev.read_raw(module_base + exp.AddressOfFunctions,
                     funcs.data(), funcs.size() * 4)
            != funcs.size() * 4) return std::nullopt;

    // linear scan (export tables are already sorted for bsearch, but linear
    // is fine for the sizes we see and simpler)
    auto read_cstr = [&](uint64_t addr, size_t maxlen = 512) {
        std::string s;
        std::vector<char> buf(64, 0);
        size_t total = 0;
        while (total < maxlen) {
            const size_t chunk = std::min<size_t>(64, maxlen - total);
            const size_t got = dev.read_raw(addr + total, buf.data(), chunk);
            if (got == 0) break;
            for (size_t i = 0; i < got; ++i) {
                if (buf[i] == '\0') return s;
                s.push_back(buf[i]);
            }
            total += got;
            if (got < chunk) break;
        }
        return s;
    };

    uint32_t func_rva = 0;
    bool found = false;
    for (uint32_t i = 0; i < n_names; ++i) {
        const uint64_t name_va = module_base + names[i];
        const std::string exp_name = read_cstr(name_va, 512);
        if (exp_name == name) {
            const uint16_t o = ords[i];
            if (o < n_funcs) {
                func_rva = funcs[o];
                found = true;
            }
            break;
        }
    }
    if (!found || func_rva == 0) return std::nullopt;

    // forwarder detection: RVA points inside the export directory
    if (func_rva >= exp_dir.VirtualAddress &&
        func_rva < exp_dir.VirtualAddress + exp_dir.Size) {
        const std::string fwd =
            read_cstr(module_base + func_rva, 512);
        const size_t dot = fwd.find('.');
        if (dot == std::string::npos) return std::nullopt;
        const std::string fwd_dll_raw = fwd.substr(0, dot);
        const std::string fwd_fn = fwd.substr(dot + 1);
        // ordinal-forwarder: "DLL.#123" is not yet supported (rare)
        if (!fwd_fn.empty() && fwd_fn[0] == '#') return std::nullopt;

        const std::string fwd_dll = apiset_backing_dll(fwd_dll_raw + ".dll");
        auto fwd_base = find_module_in_ldr(mods, fwd_dll);
        if (!fwd_base) {
            // try the raw name too (kernel32.dll forwards to KERNELBASE
            // without .dll suffix -- apiset_backing_dll adds .dll; but if
            // the forwarder said something not-apiset, try both)
            fwd_base = find_module_in_ldr(mods, fwd_dll_raw + ".dll");
        }
        if (!fwd_base) return std::nullopt;
        return resolve_export_forwarded(dev, mods, *fwd_base, fwd_fn, depth + 1);
    }

    return module_base + func_rva;
}

// --- peb ldr unlink -------------------------------------------------------

// unlink an LDR_DATA_TABLE_ENTRY from all three lists (Load, Memory, Init)
// so hidden-module walks and toolhelp snapshots don't see the module.
bool ldr_unlink(voyager::device_t& dev, uint64_t module_base,
                std::string* error = nullptr) {
    voyager::device_t::peb_info peb{};
    if (!dev.read_peb(peb) || peb.ldr_address == 0) {
        if (error) *error = "read_peb failed";
        return false;
    }
    auto unlink_one = [&](uint64_t list_head, uint64_t entry_off_from_link) {
        uint64_t cur = dev.read<uint64_t>(list_head);
        for (int i = 0; i < 4096 && cur && cur != list_head; ++i) {
            const uint64_t link = cur;
            const uint64_t entry = link - entry_off_from_link;
            const uint64_t base = dev.read<uint64_t>(entry + 0x30);
            const uint64_t next = dev.read<uint64_t>(link);
            const uint64_t prev = dev.read<uint64_t>(link + 8);
            if (base == module_base) {
                // stitch: prev->Flink=next, next->Blink=prev, then null this
                dev.write<uint64_t>(prev, next);
                dev.write<uint64_t>(next + 8, prev);
                dev.write<uint64_t>(link, link);
                dev.write<uint64_t>(link + 8, link);
                return true;
            }
            if (next == cur) break;
            cur = next;
        }
        return false;
    };
    // InLoadOrderLinks at LDR_DATA_TABLE_ENTRY+0x00, list head at Ldr+0x10
    const bool a = unlink_one(peb.ldr_address + 0x10, 0x00);
    // InMemoryOrderLinks at +0x10, list head at Ldr+0x20
    const bool b = unlink_one(peb.ldr_address + 0x20, 0x10);
    // InInitializationOrderLinks at +0x20, list head at Ldr+0x30
    const bool c = unlink_one(peb.ldr_address + 0x30, 0x20);
    return a || b || c;
}

// --- pe parsing (host-side, on the DLL bytes) -----------------------------

struct pe_view_t {
    const uint8_t*                            data = nullptr;
    size_t                                    size = 0;
    const IMAGE_DOS_HEADER*                   dos = nullptr;
    const IMAGE_NT_HEADERS64*                 nt = nullptr;
    const IMAGE_SECTION_HEADER*               sections = nullptr;
    uint16_t                                  n_sections = 0;
    uint32_t                                  size_of_image = 0;
    uint32_t                                  size_of_headers = 0;
    uint64_t                                  preferred_base = 0;
    uint32_t                                  entry_rva = 0;
    uint16_t                                  machine = 0;
    uint16_t                                  characteristics = 0;
};

bool parse_pe64(const std::vector<uint8_t>& buf, pe_view_t& v,
                std::string* error) {
    v = {};
    if (buf.size() < sizeof(IMAGE_DOS_HEADER)) {
        if (error) *error = "buffer too small for DOS header";
        return false;
    }
    v.data = buf.data();
    v.size = buf.size();
    v.dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(v.data);
    if (v.dos->e_magic != IMAGE_DOS_SIGNATURE) {
        if (error) *error = "no MZ";
        return false;
    }
    const uint32_t nt_off = static_cast<uint32_t>(v.dos->e_lfanew);
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > buf.size()) {
        if (error) *error = "NT header truncated";
        return false;
    }
    v.nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(v.data + nt_off);
    if (v.nt->Signature != IMAGE_NT_SIGNATURE) {
        if (error) *error = "no PE\\0\\0";
        return false;
    }
    if (v.nt->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64) {
        if (error) *error = "not x64 (only AMD64 supported by kernel injector)";
        return false;
    }
    if (v.nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (error) *error = "OptionalHeader magic mismatch";
        return false;
    }
    v.machine         = v.nt->FileHeader.Machine;
    v.characteristics = v.nt->FileHeader.Characteristics;
    v.n_sections      = v.nt->FileHeader.NumberOfSections;
    v.size_of_image   = v.nt->OptionalHeader.SizeOfImage;
    v.size_of_headers = v.nt->OptionalHeader.SizeOfHeaders;
    v.preferred_base  = v.nt->OptionalHeader.ImageBase;
    v.entry_rva       = v.nt->OptionalHeader.AddressOfEntryPoint;
    const uint32_t sect_off =
        nt_off + FIELD_OFFSET(IMAGE_NT_HEADERS64, OptionalHeader) +
        v.nt->FileHeader.SizeOfOptionalHeader;
    if (sect_off + static_cast<size_t>(v.n_sections) * sizeof(IMAGE_SECTION_HEADER)
            > buf.size()) {
        if (error) *error = "section headers truncated";
        return false;
    }
    v.sections =
        reinterpret_cast<const IMAGE_SECTION_HEADER*>(v.data + sect_off);
    return true;
}

uint32_t section_rva_to_raw(const pe_view_t& pe, uint32_t rva) {
    if (rva < pe.size_of_headers) return rva;
    for (uint16_t i = 0; i < pe.n_sections; ++i) {
        const auto& s = pe.sections[i];
        const uint32_t vs =
            s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData;
        if (rva >= s.VirtualAddress && rva < s.VirtualAddress + vs) {
            const uint32_t off = rva - s.VirtualAddress;
            if (off >= s.SizeOfRawData) return 0;
            return s.PointerToRawData + off;
        }
    }
    return 0;
}

// section chars -> NtProtectVirtualMemory prot
uint32_t section_protect(uint32_t chars) {
    const bool r = (chars & IMAGE_SCN_MEM_READ) != 0;
    const bool w = (chars & IMAGE_SCN_MEM_WRITE) != 0;
    const bool x = (chars & IMAGE_SCN_MEM_EXECUTE) != 0;
    if (x && w) return PAGE_EXECUTE_READWRITE;
    if (x && r) return PAGE_EXECUTE_READ;
    if (x)      return PAGE_EXECUTE;
    if (w)      return PAGE_READWRITE;
    if (r)      return PAGE_READONLY;
    return PAGE_NOACCESS;
}

// --- writes larger than a page: chunk it ----------------------------------

bool write_target_chunked(voyager::device_t& dev, uint64_t va,
                          const void* src, size_t len,
                          std::string* error = nullptr) {
    const uint8_t* p = static_cast<const uint8_t*>(src);
    size_t off = 0;
    while (off < len) {
        const size_t chunk = std::min<size_t>(len - off, 0x1000);
        const size_t put = dev.write_raw(va + off, p + off, chunk);
        if (put != chunk) {
            if (error)
                *error = "write_target_chunked: short write at 0x" +
                         std::to_string(va + off) + " (" +
                         std::to_string(put) + "/" + std::to_string(chunk) +
                         ")";
            return false;
        }
        off += chunk;
    }
    return true;
}

bool zero_target(voyager::device_t& dev, uint64_t va, size_t len) {
    std::vector<uint8_t> zeros(std::min<size_t>(len, 0x1000), 0);
    size_t off = 0;
    while (off < len) {
        const size_t chunk = std::min<size_t>(len - off, zeros.size());
        if (dev.write_raw(va + off, zeros.data(), chunk) != chunk) return false;
        off += chunk;
    }
    return true;
}

// --- helpers exposed to consumers -----------------------------------------

std::optional<uint64_t> find_module_impl(voyager::device_t& dev, uint32_t pid,
                                         const std::string& name,
                                         std::string* error) {
    if (!bind_pid(dev, pid, error)) return std::nullopt;
    const auto mods = ldr_modules(dev, error);
    if (mods.empty()) return std::nullopt;
    return find_module_in_ldr(mods, name);
}

} // namespace

// =========================================================================
// public helpers
// =========================================================================

std::optional<uint64_t> find_module_base(uint32_t pid,
                                         const std::string& name,
                                         std::string* error) {
    auto* dev = active_dev(error);
    if (!dev) return std::nullopt;
    return find_module_impl(*dev, pid, name, error);
}

std::optional<uint64_t> resolve_export(uint32_t pid,
                                       const std::string& module_name,
                                       const std::string& export_name,
                                       std::string* error) {
    auto* dev = active_dev(error);
    if (!dev) return std::nullopt;
    const auto base = find_module_impl(*dev, pid, module_name, error);
    if (!base) {
        if (error && error->empty())
            *error = "module not loaded in target: " + module_name;
        return std::nullopt;
    }
    const uint64_t va = dev->resolve_export(*base, export_name.c_str());
    if (va == 0) {
        if (error) *error = "export not found: " + module_name + "!" + export_name;
        return std::nullopt;
    }
    return va;
}

// =========================================================================
// loadlibrary injection
// =========================================================================

inject_result_t inject_loadlibrary(uint32_t pid, const std::wstring& dll_path,
                                   const inject_options_t& opts) {
    inject_result_t r;
    r.mode = "loadlibrary";
    r.pid = pid;

    auto* dev = active_dev(&r.error);
    if (!dev) return r;

    if (!bind_pid(*dev, pid, &r.error)) return r;
    log(r, "bind", "pid=" + std::to_string(pid) +
                       " dtb=0x" + std::to_string(dev->get_dtb()));

    // 1. locate kernel32 in target -> LoadLibraryW
    const auto mods = ldr_modules(*dev, &r.error);
    if (mods.empty()) return r;
    auto k32 = find_module_in_ldr(mods, "kernel32.dll");
    if (!k32) {
        r.error = "kernel32.dll not loaded in target";
        return r;
    }
    log(r, "ldr", "kernel32.dll @ 0x" + std::to_string(*k32));

    const uint64_t load_lib = dev->resolve_export(*k32, "LoadLibraryW");
    if (!load_lib) {
        r.error = "resolve_export LoadLibraryW failed";
        return r;
    }
    log(r, "resolve", "LoadLibraryW @ 0x" + std::to_string(load_lib));

    // 2. alloc + write path in target
    const size_t path_bytes = (dll_path.size() + 1) * sizeof(wchar_t);
    const uint64_t path_buf = dev->allocate_memory(path_bytes);
    if (!path_buf) {
        r.error = "target allocate_memory failed for path buffer";
        return r;
    }
    log(r, "alloc", "path buf @ 0x" + std::to_string(path_buf) +
                        " (" + std::to_string(path_bytes) + " bytes)");
    if (!write_target_chunked(*dev, path_buf, dll_path.c_str(), path_bytes,
                              &r.error)) {
        dev->free_memory(path_buf);
        return r;
    }

    // 3. hijack a thread and call LoadLibraryW(path_buf)
    const uint64_t rc = dev->call_function(load_lib, path_buf);
    log(r, "call", "LoadLibraryW returned 0x" + std::to_string(rc));
    dev->free_memory(path_buf);

    if (rc == 0) {
        r.error = "LoadLibraryW returned NULL (module load failed in target)";
        return r;
    }

    r.module_base = rc;
    r.dllmain_return = rc;

    // 4. discover size + entry from the fresh LDR walk
    const auto post = ldr_modules(*dev);
    for (const auto& m : post) {
        if (m.base == rc) {
            r.module_size = m.size;
            r.entry_point = m.entry_point;
            break;
        }
    }

    // 5. optional PEB unlink
    if (opts.unlink_peb) {
        if (ldr_unlink(*dev, rc)) {
            r.peb_unlinked = true;
            log(r, "peb", "unlinked from all three LDR lists");
        } else {
            log(r, "peb", "unlink failed (module not found in LDR)");
        }
    }

    // 6. optional header erase
    if (opts.erase_pe_header) {
        // zero the first page (contains MZ, DOS stub, PE, optional header,
        // and the section headers)
        if (zero_target(*dev, rc, 0x1000)) {
            r.header_erased = true;
            log(r, "erase", "zeroed first 0x1000 of module");
        } else {
            log(r, "erase", "header zero failed");
        }
    }

    r.ok = true;
    return r;
}

// =========================================================================
// manual map
// =========================================================================

namespace {

// Ensure every DLL a manual-mapped image imports is loaded in the target.
// Apiset stubs (api-ms-win-*) get short-circuited to their real backing DLL
// which is always already loaded. Missing real deps get LoadLibrary'd via
// the same thread-hijack primitive.
bool ensure_dep_loaded(voyager::device_t& dev, uint32_t pid,
                       const std::string& dep_name_in, uint64_t& out_base,
                       std::string& real_name_out,
                       inject_result_t& r) {
    // apiset redirect
    const std::string mapped = apiset_backing_dll(dep_name_in);
    const std::string dep_name = mapped;
    real_name_out = dep_name;

    // fast path: already in LDR
    auto mods = ldr_modules(dev);
    if (auto b = find_module_in_ldr(mods, dep_name)) { out_base = *b; return true; }

    // apiset that didn't resolve -- LoadLibrary won't help either, apisets
    // aren't real files. bail loudly.
    if (dep_name.rfind("api-ms-", 0) == 0 || dep_name.rfind("ext-ms-", 0) == 0) {
        log(r, "dep",
            "apiset " + dep_name_in + " (backing " + dep_name +
                ") not loaded in target and cannot be LoadLibrary'd");
        return false;
    }

    log(r, "dep", "loading missing dep: " + dep_name);
    inject_options_t sub{};
    sub.erase_pe_header = false;
    sub.unlink_peb      = false;
    sub.call_timeout_ms = 8000;
    auto sub_r = inject_loadlibrary(pid, utf8_to_wide(dep_name), sub);
    if (!sub_r.ok) {
        log(r, "dep", "LoadLibrary(" + dep_name + ") failed: " + sub_r.error);
        return false;
    }
    out_base = sub_r.module_base;
    return true;
}

} // namespace

inject_result_t inject_manual_map(uint32_t pid,
                                  const std::vector<uint8_t>& dll_bytes,
                                  const inject_options_t& opts) {
    inject_result_t r;
    r.mode = "manual_map";
    r.pid = pid;

    auto* dev = active_dev(&r.error);
    if (!dev) return r;

    // 1. parse the pe on the host side
    pe_view_t pe{};
    if (!parse_pe64(dll_bytes, pe, &r.error)) return r;
    log(r, "parse", "sections=" + std::to_string(pe.n_sections) +
                        " size_of_image=0x" + std::to_string(pe.size_of_image) +
                        " preferred_base=0x" + std::to_string(pe.preferred_base));

    if (!bind_pid(*dev, pid, &r.error)) return r;
    log(r, "bind", "pid=" + std::to_string(pid));

    // 2. alloc size_of_image in target (RWX from the driver)
    const uint64_t base = dev->allocate_memory(pe.size_of_image);
    if (!base) {
        r.error = "target allocate_memory failed for image (size=" +
                  std::to_string(pe.size_of_image) + ")";
        return r;
    }
    r.module_base = base;
    r.module_size = pe.size_of_image;
    r.entry_point = base + pe.entry_rva;
    log(r, "alloc", "image @ 0x" + std::to_string(base) +
                        " size=0x" + std::to_string(pe.size_of_image));

    // 3. copy headers
    if (!write_target_chunked(*dev, base, pe.data, pe.size_of_headers,
                              &r.error)) {
        dev->free_memory(base);
        return r;
    }
    log(r, "hdrs", "wrote 0x" + std::to_string(pe.size_of_headers) +
                       " header bytes");

    // 4. copy sections
    for (uint16_t i = 0; i < pe.n_sections; ++i) {
        const auto& s = pe.sections[i];
        if (s.SizeOfRawData == 0) continue;
        if (static_cast<size_t>(s.PointerToRawData) + s.SizeOfRawData > pe.size) {
            r.error = "section raw range OOB";
            dev->free_memory(base);
            return r;
        }
        if (!write_target_chunked(*dev, base + s.VirtualAddress,
                                  pe.data + s.PointerToRawData,
                                  s.SizeOfRawData, &r.error)) {
            dev->free_memory(base);
            return r;
        }
    }
    log(r, "sect", "copied " + std::to_string(pe.n_sections) + " sections");

    // 5. apply base relocations
    const int64_t delta =
        static_cast<int64_t>(base) - static_cast<int64_t>(pe.preferred_base);
    if (delta != 0) {
        const auto& reloc_dir =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (reloc_dir.Size && reloc_dir.VirtualAddress) {
            // relocations live in the file image at the same RVA layout;
            // walk them from the source dll_bytes so we don't have to read
            // back from the target
            uint32_t off = 0;
            while (off < reloc_dir.Size) {
                const auto* blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(
                    pe.data + section_rva_to_raw(pe, reloc_dir.VirtualAddress + off));
                if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) ||
                    blk->SizeOfBlock > reloc_dir.Size - off) break;
                const uint32_t n_ent = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
                const auto* entries =
                    reinterpret_cast<const uint16_t*>(blk + 1);
                for (uint32_t i = 0; i < n_ent; ++i) {
                    const uint16_t type = entries[i] >> 12;
                    const uint16_t offs = entries[i] & 0x0FFF;
                    if (type == IMAGE_REL_BASED_DIR64) {
                        const uint64_t target = base + blk->VirtualAddress + offs;
                        uint64_t v = dev->read<uint64_t>(target);
                        v = static_cast<uint64_t>(static_cast<int64_t>(v) + delta);
                        dev->write<uint64_t>(target, v);
                        ++r.relocations_applied;
                    } else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                        // padding, skip
                    } else {
                        // unusual for x64 (HIGHLOW/HIGH/LOW never used)
                        log(r, "reloc", "unhandled reloc type " +
                                            std::to_string(type));
                    }
                }
                off += blk->SizeOfBlock;
            }
        }
    }
    log(r, "reloc", "delta=0x" + std::to_string(delta) +
                        " applied=" + std::to_string(r.relocations_applied));

    // 6. resolve imports
    const auto& imp_dir =
        pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.Size && imp_dir.VirtualAddress) {
        auto raw_at = [&](uint32_t rva) -> const uint8_t* {
            const uint32_t raw = section_rva_to_raw(pe, rva);
            if (raw == 0 || raw >= pe.size) return nullptr;
            return pe.data + raw;
        };
        const auto* desc =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(raw_at(imp_dir.VirtualAddress));
        if (!desc) {
            r.error = "import dir RVA does not resolve to raw";
            dev->free_memory(base);
            return r;
        }
        auto mods_now = ldr_modules(*dev);
        while (desc->Name) {
            const char* name_p =
                reinterpret_cast<const char*>(raw_at(desc->Name));
            if (!name_p) { r.error = "import DLL name RVA bad"; break; }
            const std::string dll_name_raw(name_p);

            uint64_t dep_base = 0;
            std::string dll_name;
            if (!ensure_dep_loaded(*dev, pid, dll_name_raw, dep_base,
                                   dll_name, r)) {
                r.imports_failed++;
                ++desc;
                continue;
            }
            // ldr may have grown if we LoadLibrary'd a real dep
            mods_now = ldr_modules(*dev);

            const uint32_t oft_rva = desc->OriginalFirstThunk
                                     ? desc->OriginalFirstThunk
                                     : desc->FirstThunk;
            const uint32_t ft_rva  = desc->FirstThunk;
            const auto* oft = reinterpret_cast<const uint64_t*>(raw_at(oft_rva));
            if (!oft) { r.imports_failed++; ++desc; continue; }

            for (uint32_t i = 0; oft[i]; ++i) {
                const uint64_t entry = oft[i];
                uint64_t api_va = 0;
                if (entry & IMAGE_ORDINAL_FLAG64) {
                    log(r, "import",
                        dll_name + " ordinal-only imports unsupported");
                    r.imports_failed++;
                    continue;
                }
                const auto* iben = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(
                    raw_at(static_cast<uint32_t>(entry)));
                if (!iben) { r.imports_failed++; continue; }
                const char* fn = reinterpret_cast<const char*>(iben->Name);
                // forwarder-aware resolver (host-side walk, chases across DLLs)
                auto ov = resolve_export_forwarded(*dev, mods_now, dep_base, fn);
                if (ov) api_va = *ov;
                // last-ditch fall back to the driver ioctl (fast path for
                // non-forwarded exports) in case something above tripped
                if (!api_va) api_va = dev->resolve_export(dep_base, fn);
                if (!api_va) {
                    log(r, "import",
                        "unresolved " + dll_name_raw + "!" + fn);
                    r.imports_failed++;
                    continue;
                }
                const uint64_t iat_slot = base + ft_rva + i * sizeof(uint64_t);
                dev->write<uint64_t>(iat_slot, api_va);
                r.imports_resolved++;
            }
            ++desc;
        }
    }
    log(r, "import", "resolved=" + std::to_string(r.imports_resolved) +
                        " failed=" + std::to_string(r.imports_failed));

    if (r.imports_failed > 0 && r.imports_resolved == 0) {
        r.error = "no imports resolved (DllMain would crash) -- aborting";
        dev->free_memory(base);
        return r;
    }

    // 7. protect sections (optional, on by default -- eliminates RWX
    //    fingerprint that ac memory-region scans flag)
    if (opts.protect_sections) {
        for (uint16_t i = 0; i < pe.n_sections; ++i) {
            const auto& s = pe.sections[i];
            const uint64_t addr = base + s.VirtualAddress;
            const uint64_t sz = s.Misc.VirtualSize
                                ? s.Misc.VirtualSize
                                : s.SizeOfRawData;
            if (!sz) continue;
            uint32_t old = 0;
            if (dev->protect_memory(addr, sz, section_protect(s.Characteristics),
                                    &old)) {
                r.sections_protected++;
            }
        }
        log(r, "protect",
            "re-protected " + std::to_string(r.sections_protected) +
                " sections per section chars");
    }

    // 8. TLS callbacks
    if (opts.call_tls_callbacks) {
        const auto& tls_dir =
            pe.nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tls_dir.Size && tls_dir.VirtualAddress) {
            // IMAGE_TLS_DIRECTORY64 is already relocated inside the mapped
            // image (relocs above patched AddressOfCallBacks), so read it
            // from the target.
            IMAGE_TLS_DIRECTORY64 tls{};
            dev->read_raw(base + tls_dir.VirtualAddress, &tls, sizeof(tls));
            uint64_t cb_ptr = tls.AddressOfCallBacks;
            for (int i = 0; i < 64 && cb_ptr; ++i) {
                const uint64_t cb = dev->read<uint64_t>(cb_ptr + i * 8);
                if (!cb) break;
                dev->call_function(cb, base, DLL_PROCESS_ATTACH, 0);
                log(r, "tls", "cb[" + std::to_string(i) + "] @ 0x" +
                                  std::to_string(cb) + " ran");
            }
        }
    }

    // 9. DllMain
    if (opts.call_dllmain && pe.entry_rva != 0) {
        const uint64_t dllmain = base + pe.entry_rva;
        const uint64_t ret =
            dev->call_function(dllmain, base, DLL_PROCESS_ATTACH, 1);
        r.dllmain_return = ret;
        log(r, "dllmain",
            "DllMain(0x" + std::to_string(base) + ", ATTACH, 1) -> 0x" +
                std::to_string(ret));
        if (ret == 0) {
            log(r, "dllmain",
                "returned FALSE -- module signalled load failure");
        }
    }

    // 10. header erase (mask MZ/DOS/NT/section table)
    if (opts.erase_pe_header) {
        if (zero_target(*dev, base, 0x1000)) {
            r.header_erased = true;
            log(r, "erase", "zeroed first 0x1000 of mapped image");
        }
    }

    r.ok = true;
    return r;
}

inject_result_t inject_manual_map_file(uint32_t pid,
                                       const std::string& dll_path,
                                       const inject_options_t& opts) {
    inject_result_t r;
    r.mode = "manual_map";
    r.pid = pid;

    std::ifstream f(dll_path, std::ios::binary | std::ios::ate);
    if (!f) {
        r.error = "cannot open dll file: " + dll_path;
        return r;
    }
    const std::streamsize n = f.tellg();
    if (n <= 0 || n > (64 * 1024 * 1024)) {
        r.error = "dll file empty or too large (>64 MiB)";
        return r;
    }
    f.seekg(0);
    std::vector<uint8_t> buf(static_cast<size_t>(n));
    if (!f.read(reinterpret_cast<char*>(buf.data()), n)) {
        r.error = "dll file read failed";
        return r;
    }
    return inject_manual_map(pid, buf, opts);
}

// =========================================================================
// unload
// =========================================================================

inject_result_t unload(uint32_t pid, uint64_t module_base, bool manual_mapped,
                       const inject_options_t& opts) {
    (void)opts;
    inject_result_t r;
    r.mode = manual_mapped ? "manual_map" : "loadlibrary";
    r.pid = pid;
    r.module_base = module_base;

    auto* dev = active_dev(&r.error);
    if (!dev) return r;
    if (!bind_pid(*dev, pid, &r.error)) return r;

    if (!manual_mapped) {
        // FreeLibrary in kernel32
        auto k32 = find_module_impl(*dev, pid, "kernel32.dll", &r.error);
        if (!k32) return r;
        const uint64_t fl = dev->resolve_export(*k32, "FreeLibrary");
        if (!fl) { r.error = "resolve FreeLibrary failed"; return r; }
        const uint64_t rc = dev->call_function(fl, module_base);
        log(r, "free", "FreeLibrary returned 0x" + std::to_string(rc));
        r.dllmain_return = rc;
        r.ok = (rc != 0);
        return r;
    }

    // manual-mapped: call DllMain(DLL_PROCESS_DETACH) then free
    // caller must know the entry point; probe the target headers if erased
    // we can only best-effort here. Skip DllMain if we can't find it.
    const uint64_t maybe_mz = dev->read<uint16_t>(module_base);
    if (maybe_mz == IMAGE_DOS_SIGNATURE) {
        const uint32_t e_lfanew = dev->read<uint32_t>(module_base + 0x3C);
        const uint32_t entry_rva =
            dev->read<uint32_t>(module_base + e_lfanew + 0x28);
        if (entry_rva) {
            const uint64_t entry = module_base + entry_rva;
            dev->call_function(entry, module_base, DLL_PROCESS_DETACH, 0);
            log(r, "detach",
                "DllMain(DETACH) at 0x" + std::to_string(entry));
        }
    } else {
        log(r, "detach", "header already erased, skipping DllMain(DETACH)");
    }

    if (dev->free_memory(module_base)) {
        r.ok = true;
        log(r, "free", "kernel-freed image");
    } else {
        r.error = "kernel free_memory failed";
    }
    return r;
}

} // namespace slop::core::runtime::injector
