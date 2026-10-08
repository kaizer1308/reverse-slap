// src/core/process/runtime_dump.cpp
// Full runtime deobfuscated dump implementation. Scylla-class import
// reconstruction + OEP detection + section rebuild, all through kernel
// phys reads.

#include "core/process/runtime_dump.hpp"
#include "core/process/module_dump.hpp"
#include "core/runtime/backend_registry.hpp"

#include <windows.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <set>
#include <unordered_map>

namespace slop::core::process {

using namespace slop::core::runtime;

namespace {

// ── export table reader ──────────────────────────────────────────────────
// read the export table of a loaded DLL to build the address→name map

struct dll_export_t {
    std::string name;
    uint16_t    ordinal = 0;
    uint64_t    va = 0;
};

std::vector<dll_export_t> read_dll_exports(
    session_t& session, uint64_t dll_base, uint32_t dll_size)
{
    std::vector<dll_export_t> exports;
    if (!dll_base || dll_size < 0x100) return exports;

    uint8_t hdr[0x400] = {};
    if (!session.read(dll_base, hdr, sizeof(hdr)).ok) return exports;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return exports;

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, hdr + 0x3C, 4);
    if (e_lfanew + 0x88 + 8 > sizeof(hdr)) return exports;

    uint32_t export_rva = 0, export_size = 0;
    std::memcpy(&export_rva, hdr + e_lfanew + 0x88, 4);
    std::memcpy(&export_size, hdr + e_lfanew + 0x8C, 4);
    if (!export_rva || !export_size || export_rva + export_size > dll_size)
        return exports;

    std::vector<uint8_t> edir(export_size);
    if (!session.read(dll_base + export_rva, edir.data(), export_size).ok)
        return exports;

    if (export_size < 40) return exports;
    uint32_t num_funcs = 0, num_names = 0;
    uint32_t addr_rva = 0, name_rva = 0, ordinal_rva = 0, ordinal_base = 0;
    std::memcpy(&num_funcs,    edir.data() + 20, 4);
    std::memcpy(&num_names,    edir.data() + 24, 4);
    std::memcpy(&addr_rva,     edir.data() + 28, 4);
    std::memcpy(&name_rva,     edir.data() + 32, 4);
    std::memcpy(&ordinal_rva,  edir.data() + 36, 4);
    std::memcpy(&ordinal_base, edir.data() + 16, 4);

    if (num_funcs > 65536 || num_names > 65536) return exports;

    // read the three arrays
    std::vector<uint32_t> addrs(num_funcs);
    std::vector<uint32_t> names(num_names);
    std::vector<uint16_t> ords(num_names);

    session.read(dll_base + addr_rva, addrs.data(), num_funcs * 4);
    session.read(dll_base + name_rva, names.data(), num_names * 4);
    session.read(dll_base + ordinal_rva, ords.data(), num_names * 2);

    // build name→ordinal map
    std::map<uint16_t, std::string> ord_to_name;
    for (uint32_t i = 0; i < num_names; ++i) {
        if (names[i] && names[i] < dll_size) {
            char name_buf[256] = {};
            session.read(dll_base + names[i], name_buf, sizeof(name_buf) - 1);
            ord_to_name[ords[i]] = name_buf;
        }
    }

    for (uint32_t i = 0; i < num_funcs; ++i) {
        if (!addrs[i]) continue;
        // skip forwarded exports (rva points inside the export dir)
        if (addrs[i] >= export_rva && addrs[i] < export_rva + export_size)
            continue;

        dll_export_t e;
        e.va = dll_base + addrs[i];
        e.ordinal = static_cast<uint16_t>(ordinal_base + i);
        auto it = ord_to_name.find(static_cast<uint16_t>(i));
        if (it != ord_to_name.end()) e.name = it->second;
        exports.push_back(std::move(e));
    }
    return exports;
}

// ── packer section names to strip ────────────────────────────────────────

bool is_packer_section(const char* name) {
    static const char* patterns[] = {
        ".vmp", ".vmpr", "VMP", ".the", ".tls0", "UPX", ".aspack",
        ".adata", ".nsp", ".perplex", ".enigma", ".mpress",
        ".petite", ".pack", ".pec", ".sforce", ".rsrc1",
        ".text0", ".code0", ".prot", ".obf", nullptr
    };
    for (int i = 0; patterns[i]; ++i) {
        if (std::strstr(name, patterns[i])) return true;
    }
    return false;
}

// ── file writer ──────────────────────────────────────────────────────────

bool write_file(const std::string& path, const std::vector<uint8_t>& data,
                std::string& error) {
    std::filesystem::create_directories(
        std::filesystem::path(path).parent_path());
    std::ofstream f(path, std::ios::binary);
    if (!f) { error = "cannot create output file"; return false; }
    f.write(reinterpret_cast<const char*>(data.data()),
            static_cast<std::streamsize>(data.size()));
    return true;
}

} // namespace

// ── import reconstruction ────────────────────────────────────────────────

std::vector<import_module_t> reconstruct_imports_from_iat(
    session_t& session, uint64_t module_base,
    const std::vector<uint8_t>& image)
{
    std::vector<import_module_t> result;
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return result;

    // build a global address→(dll,name) map from all loaded DLLs
    std::unordered_map<uint64_t, std::pair<std::string, std::string>> global_exports;
    std::unordered_map<uint64_t, uint16_t> global_ordinals;

    auto mods = active().enum_modules(session.handle());
    if (!mods.ok) return result;

    for (const auto& mod : mods.items) {
        if (mod.base == module_base) continue;  // skip self
        auto exports = read_dll_exports(session, mod.base, mod.size);
        for (const auto& e : exports) {
            global_exports[e.va] = { mod.name, e.name };
            global_ordinals[e.va] = e.ordinal;
        }
    }

    if (global_exports.empty()) return result;

    // parse the dumped image to find the IAT
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return result;

    const size_t nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > image.size()) return result;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return result;

    // scan ALL writable/readable sections for qwords that resolve to known
    // exports. this catches IATs even when the import directory is destroyed
    // (which is the whole point of packer import obfuscation).
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    std::map<std::string, import_module_t> by_dll;

    for (uint16_t si = 0; si < nt->FileHeader.NumberOfSections; ++si) {
        const uint32_t raw_off = sec[si].PointerToRawData;
        const uint32_t raw_sz = sec[si].SizeOfRawData;
        if (raw_off + raw_sz > image.size()) continue;

        for (uint32_t off = 0; off + 8 <= raw_sz; off += 8) {
            uint64_t val = 0;
            std::memcpy(&val, image.data() + raw_off + off, 8);

            auto it = global_exports.find(val);
            if (it == global_exports.end()) continue;

            const auto& [dll, func] = it->second;
            auto& mod = by_dll[dll];
            mod.dll_name = dll;

            reconstructed_import_t imp;
            imp.dll_name = dll;
            imp.func_name = func;
            imp.iat_rva = sec[si].VirtualAddress + off;
            imp.resolved_va = val;
            auto oit = global_ordinals.find(val);
            if (oit != global_ordinals.end()) imp.ordinal = oit->second;
            imp.by_ordinal = func.empty();
            mod.functions.push_back(std::move(imp));
        }
    }

    for (auto& [_, mod] : by_dll) {
        // deduplicate by IAT RVA
        std::set<uint64_t> seen;
        std::vector<reconstructed_import_t> unique;
        for (auto& f : mod.functions) {
            if (seen.insert(f.iat_rva).second)
                unique.push_back(std::move(f));
        }
        mod.functions = std::move(unique);
        result.push_back(std::move(mod));
    }
    return result;
}

// ── OEP detection ────────────────────────────────────────────────────────

uint64_t detect_original_entry(
    session_t& session, uint64_t module_base,
    const std::vector<uint8_t>& image, std::string* method_out)
{
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const uint32_t current_ep = nt->OptionalHeader.AddressOfEntryPoint;
    const auto* sec = IMAGE_FIRST_SECTION(nt);

    // method 1: if the current EP points into a known packer section,
    // scan the first code section for a common entry pattern
    char ep_sec_name[9] = {};
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (current_ep >= sec[i].VirtualAddress &&
            current_ep < sec[i].VirtualAddress + sec[i].Misc.VirtualSize) {
            std::memcpy(ep_sec_name, sec[i].Name, 8);
            break;
        }
    }

    bool ep_in_packer = is_packer_section(ep_sec_name);

    if (ep_in_packer) {
        // look for the first code section (.text or unnamed with exec flag)
        for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            if (!(sec[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) continue;
            char name[9] = {};
            std::memcpy(name, sec[i].Name, 8);
            if (is_packer_section(name)) continue;

            // read the first 64 bytes of this section from memory
            uint8_t code[64] = {};
            session.read(module_base + sec[i].VirtualAddress, code, sizeof(code));

            // look for common entry patterns:
            // sub rsp, XX (48 83 EC XX or 48 81 EC XX XX XX XX)
            // push rbp (55)
            // mov rbp, rsp (48 89 E5 or 48 8B EC)
            for (size_t j = 0; j < 48; ++j) {
                if (code[j] == 0x48 && code[j+1] == 0x83 && code[j+2] == 0xEC) {
                    if (method_out) *method_out = "sub rsp pattern in first code section";
                    return module_base + sec[i].VirtualAddress + j;
                }
                if (code[j] == 0x48 && code[j+1] == 0x81 && code[j+2] == 0xEC) {
                    if (method_out) *method_out = "sub rsp,imm32 pattern in first code section";
                    return module_base + sec[i].VirtualAddress + j;
                }
                if (code[j] == 0x55) {
                    // push rbp followed by mov rbp, rsp
                    if (j + 3 < 64 && code[j+1] == 0x48 &&
                        (code[j+2] == 0x89 || code[j+2] == 0x8B) &&
                        (code[j+3] == 0xE5 || code[j+3] == 0xEC)) {
                        if (method_out) *method_out = "push rbp; mov rbp,rsp pattern";
                        return module_base + sec[i].VirtualAddress + j;
                    }
                }
                if (code[j] == 0x40 && code[j+1] == 0x53) {
                    // push rbx (common msvc entry)
                    if (method_out) *method_out = "push rbx (MSVC entry pattern)";
                    return module_base + sec[i].VirtualAddress + j;
                }
            }

            // fallback: start of the first code section
            if (method_out) *method_out = "first code section start (fallback)";
            return module_base + sec[i].VirtualAddress;
        }
    }

    // method 2: the current EP may already be correct (unpacker already
    // restored it, or the binary isn't packed)
    if (method_out) *method_out = "current PE entry point (not in packer section)";
    return module_base + current_ep;
}

// ── import directory writer ──────────────────────────────────────────────

bool write_import_directory(
    std::vector<uint8_t>& image, uint64_t image_base,
    const std::vector<import_module_t>& imports)
{
    if (imports.empty() || image.size() < sizeof(IMAGE_DOS_HEADER))
        return false;

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    // build the new import directory at the end of the image.
    // layout: [import descriptors] [ILT entries] [hint/name entries] [dll names]
    const size_t old_size = image.size();
    const uint32_t new_section_rva =
        (nt->OptionalHeader.SizeOfImage + 0xFFF) & ~0xFFFu;

    // calculate sizes
    size_t desc_size = (imports.size() + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    size_t ilt_size = 0;
    for (const auto& mod : imports)
        ilt_size += (mod.functions.size() + 1) * 8;  // +1 for null terminator
    size_t hints_size = 0;
    for (const auto& mod : imports)
        for (const auto& f : mod.functions)
            hints_size += 2 + f.func_name.size() + 1 + ((f.func_name.size() + 3) & ~1u);
    size_t names_size = 0;
    for (const auto& mod : imports)
        names_size += mod.dll_name.size() + 1;

    const size_t total = desc_size + ilt_size + hints_size + names_size;
    const size_t aligned_total = (total + 0x1FFu) & ~0x1FFu;

    // extend the image
    image.resize(old_size + aligned_total, 0);

    // add a new section header for .idata2
    auto* sec = IMAGE_FIRST_SECTION(nt);
    uint16_t& num_sec = nt->FileHeader.NumberOfSections;
    if (num_sec >= 96) return false;  // sanity

    auto& new_sec = sec[num_sec];
    std::memcpy(new_sec.Name, ".idata2", 8);
    new_sec.Misc.VirtualSize = static_cast<uint32_t>(total);
    new_sec.VirtualAddress = new_section_rva;
    new_sec.SizeOfRawData = static_cast<uint32_t>(aligned_total);
    new_sec.PointerToRawData = static_cast<uint32_t>(old_size);
    new_sec.Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA;
    ++num_sec;

    // update SizeOfImage
    nt->OptionalHeader.SizeOfImage = new_section_rva +
        static_cast<uint32_t>((total + 0xFFFu) & ~0xFFFu);

    // write the directory
    uint8_t* base = image.data() + old_size;
    size_t pos = 0;

    // import descriptors
    size_t desc_pos = pos;
    pos += desc_size;

    // ILTs (one array per module)
    size_t ilt_pos = pos;
    pos += ilt_size;

    // hint/name entries
    size_t hint_pos = pos;

    // dll name strings
    size_t name_pos = pos + hints_size;

    // fill in everything
    size_t cur_ilt = ilt_pos;
    size_t cur_hint = hint_pos;
    size_t cur_name = name_pos;

    for (size_t mi = 0; mi < imports.size(); ++mi) {
        const auto& mod = imports[mi];

        IMAGE_IMPORT_DESCRIPTOR desc{};
        desc.OriginalFirstThunk = new_section_rva + static_cast<uint32_t>(cur_ilt);
        desc.Name = new_section_rva + static_cast<uint32_t>(cur_name);

        // find the FirstThunk (IAT) from the first function's iat_rva
        if (!mod.functions.empty())
            desc.FirstThunk = static_cast<uint32_t>(mod.functions[0].iat_rva);

        std::memcpy(base + desc_pos + mi * sizeof(desc), &desc, sizeof(desc));

        // write DLL name
        std::memcpy(base + cur_name, mod.dll_name.c_str(), mod.dll_name.size() + 1);
        cur_name += mod.dll_name.size() + 1;

        // write ILT entries + hint/name entries
        for (const auto& f : mod.functions) {
            uint64_t ilt_entry = 0;
            if (f.by_ordinal || f.func_name.empty()) {
                ilt_entry = 0x8000000000000000ull | f.ordinal;
            } else {
                ilt_entry = new_section_rva + static_cast<uint32_t>(cur_hint);
                // write hint/name
                uint16_t hint = f.ordinal;
                std::memcpy(base + cur_hint, &hint, 2);
                std::memcpy(base + cur_hint + 2, f.func_name.c_str(),
                            f.func_name.size() + 1);
                cur_hint += 2 + f.func_name.size() + 1;
                if (cur_hint & 1) ++cur_hint;  // align
            }
            std::memcpy(base + cur_ilt, &ilt_entry, 8);
            cur_ilt += 8;
        }
        // null terminator for ILT
        uint64_t zero = 0;
        std::memcpy(base + cur_ilt, &zero, 8);
        cur_ilt += 8;
    }

    // update the import data directory
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        new_section_rva + static_cast<uint32_t>(desc_pos);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        static_cast<uint32_t>(desc_size);

    return true;
}

// ── main dump function ───────────────────────────────────────────────────

runtime_dump_result_t dump_deobfuscated(
    session_t& session, uint64_t module_base, uint32_t module_size,
    const std::string& output_path, const runtime_dump_options_t& options)
{
    runtime_dump_result_t result;
    result.module_base = module_base;
    result.output_path = output_path;

    if (!module_base) {
        result.error = "module base is null";
        return result;
    }

    // step 1: read the PE header to get SizeOfImage if not provided
    uint8_t hdr[0x400] = {};
    if (!session.read(module_base, hdr, sizeof(hdr)).ok) {
        result.error = "cannot read PE header at module base";
        return result;
    }
    if (hdr[0] != 'M' || hdr[1] != 'Z') {
        result.error = "module base does not contain MZ signature";
        return result;
    }

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, hdr + 0x3C, 4);
    if (e_lfanew + sizeof(IMAGE_NT_HEADERS64) > sizeof(hdr)) {
        result.error = "NT header offset out of range";
        return result;
    }
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(hdr + e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        result.error = "invalid PE signature";
        return result;
    }

    if (module_size == 0) {
        module_size = nt->OptionalHeader.SizeOfImage;
    }
    result.module_size = module_size;

    if (module_size > 512 * 1024 * 1024) {
        result.error = "module size exceeds 512MB safety limit";
        return result;
    }

    // step 2: dump the entire virtual range
    std::vector<uint8_t> image(module_size, 0);
    const size_t chunk = options.chunk_size;
    size_t bytes_ok = 0;
    for (size_t off = 0; off < module_size; off += chunk) {
        const size_t read_sz = std::min(chunk, static_cast<size_t>(module_size) - off);
        if (session.read(module_base + off, image.data() + off, read_sz).ok)
            bytes_ok += read_sz;
    }
    if (bytes_ok < 0x1000) {
        result.error = "less than one page readable — module may be fully encrypted";
        return result;
    }

    // step 3: fix section table from actual memory layout
    auto* out_nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + e_lfanew);
    auto* sec = IMAGE_FIRST_SECTION(out_nt);
    uint16_t num_sec = out_nt->FileHeader.NumberOfSections;

    if (options.fix_sections) {
        for (uint16_t i = 0; i < num_sec; ++i) {
            // in a memory dump, data is at VirtualAddress.
            // for file layout: set PointerToRawData = VirtualAddress,
            // SizeOfRawData = VirtualSize (aligned to file alignment)
            sec[i].PointerToRawData = sec[i].VirtualAddress;
            uint32_t aligned_vsize = sec[i].Misc.VirtualSize;
            if (options.file_alignment && aligned_vsize) {
                aligned_vsize = (aligned_vsize + options.file_alignment - 1) &
                                ~(options.file_alignment - 1);
            }
            sec[i].SizeOfRawData = aligned_vsize;
            ++result.sections_rebuilt;
        }
    }

    // step 4: remove packer sections
    if (options.remove_packer_sections) {
        uint16_t kept = 0;
        for (uint16_t i = 0; i < num_sec; ++i) {
            char name[9] = {};
            std::memcpy(name, sec[i].Name, 8);
            if (is_packer_section(name)) {
                // zero the section data
                if (sec[i].PointerToRawData + sec[i].SizeOfRawData <= image.size()) {
                    std::memset(image.data() + sec[i].PointerToRawData, 0,
                                sec[i].SizeOfRawData);
                }
                ++result.packer_sections_removed;
                continue;
            }
            if (kept != i) sec[kept] = sec[i];
            ++kept;
        }
        out_nt->FileHeader.NumberOfSections = kept;
        num_sec = kept;
    }

    // step 5: detect OEP
    if (options.detect_oep) {
        std::string method;
        result.detected_oep = detect_original_entry(
            session, module_base, image, &method);
        if (result.detected_oep) {
            result.detected_oep_rva = static_cast<uint32_t>(
                result.detected_oep - module_base);
            result.oep_method = method;
            // patch the entry point
            out_nt->OptionalHeader.AddressOfEntryPoint = result.detected_oep_rva;
        }
    }

    // step 6: reconstruct imports
    if (options.reconstruct_imports) {
        result.imports = reconstruct_imports_from_iat(session, module_base, image);
        for (const auto& mod : result.imports) {
            result.total_imports += mod.functions.size();
            for (const auto& f : mod.functions) {
                if (!f.func_name.empty()) ++result.resolved_imports;
                else ++result.unresolved_imports;
            }
        }

        // write the new import directory into the image
        if (!result.imports.empty()) {
            write_import_directory(image, module_base, result.imports);
        }
    }

    // step 7: fix ImageBase to match the actual runtime base
    out_nt->OptionalHeader.ImageBase = module_base;

    // step 8: fix checksum
    if (options.fix_checksum) {
        result.checksum = fix_pe_checksum(image);
    }

    // step 9: write to disk
    if (!write_file(output_path, image, result.error)) {
        return result;
    }

    result.ok = true;
    result.bytes_written = image.size();
    return result;
}

} // namespace slop::core::process
