#include "core/process/module_dump.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/runtime/session.hpp"
#include "core/runtime/backend_registry.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <system_error>

namespace slop::core::process {

namespace {

constexpr size_t kMaxHeaderBytes = 4u * 1024u * 1024u;
constexpr size_t kMaxOutputBytes = 512u * 1024u * 1024u;
constexpr uint16_t kMaxSections = 256;

bool add_fits(size_t a, size_t b, size_t limit, size_t& sum) {
    if (a > limit || b > limit - a) return false;
    sum = a + b;
    return true;
}

bool read_exact(const module_read_fn_t& read, uintptr_t address, void* dst,
                size_t size, size_t chunk_size) {
    auto* out = static_cast<uint8_t*>(dst);
    size_t done = 0;
    const size_t chunk = std::max<size_t>(chunk_size, 4096);
    while (done < size) {
        const size_t take = std::min(chunk, size - done);
        const auto io = read(address + done, out + done, take);
        if (!io.ok || io.bytes != take) return false;
        done += take;
    }
    return true;
}

bool write_atomic(const std::string& output_path,
                  const std::vector<uint8_t>& data, std::string& error) {
    const std::filesystem::path final_path{output_path};
    if (final_path.empty()) {
        error = "output path is empty";
        return false;
    }

    const auto temporary = final_path.wstring() + L".slop-tmp-" +
        std::to_wstring(GetCurrentProcessId()) + L"-" +
        std::to_wstring(GetTickCount64());
    HANDLE file = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr,
                              CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY |
                              FILE_FLAG_WRITE_THROUGH, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        error = "failed to create temporary dump file (error " +
                std::to_string(GetLastError()) + ")";
        return false;
    }

    bool ok = true;
    size_t written_total = 0;
    while (written_total < data.size()) {
        const DWORD take = static_cast<DWORD>(std::min<size_t>(
            data.size() - written_total, 1u * 1024u * 1024u));
        DWORD written = 0;
        if (!WriteFile(file, data.data() + written_total, take, &written,
                       nullptr) || written != take) {
            ok = false;
            break;
        }
        written_total += written;
    }
    if (ok) ok = FlushFileBuffers(file) != FALSE;
    CloseHandle(file);

    if (ok) {
        ok = MoveFileExW(temporary.c_str(), final_path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (!ok) {
        const DWORD code = GetLastError();
        DeleteFileW(temporary.c_str());
        error = "failed to write dump file (error " + std::to_string(code) + ")";
    }
    return ok;
}

} // namespace

module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base, uint32_t module_size, const module_read_fn_t& read,
    std::vector<uint8_t>& output, const module_dump_options_t& options) {
    module_dump_result_t result;
    result.module_base = module_base;
    output.clear();

    if (module_base == 0 || module_size < sizeof(IMAGE_DOS_HEADER) || !read) {
        result.error = "invalid module range or reader";
        return result;
    }

    IMAGE_DOS_HEADER dos{};
    if (!read_exact(read, module_base, &dos, sizeof(dos), options.chunk_size)) {
        result.error = "failed to read DOS header";
        return result;
    }
    if (dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
        static_cast<size_t>(dos.e_lfanew) > kMaxHeaderBytes) {
        result.error = "module does not contain a valid DOS header";
        return result;
    }

    const size_t nt_offset = static_cast<size_t>(dos.e_lfanew);
    size_t coff_end = 0;
    if (!add_fits(nt_offset, sizeof(uint32_t) + sizeof(IMAGE_FILE_HEADER),
                  kMaxHeaderBytes, coff_end)) {
        result.error = "PE header offset is out of range";
        return result;
    }
    std::vector<uint8_t> prefix(coff_end);
    if (!read_exact(read, module_base, prefix.data(), prefix.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE header";
        return result;
    }
    uint32_t signature = 0;
    IMAGE_FILE_HEADER file_header{};
    std::memcpy(&signature, prefix.data() + nt_offset, sizeof(signature));
    std::memcpy(&file_header, prefix.data() + nt_offset + sizeof(signature),
                sizeof(file_header));
    if (signature != IMAGE_NT_SIGNATURE || file_header.NumberOfSections == 0 ||
        file_header.NumberOfSections > kMaxSections) {
        result.error = "module does not contain a valid PE header";
        return result;
    }
    if (file_header.SizeOfOptionalHeader < sizeof(uint16_t)) {
        result.error = "PE optional header is truncated";
        return result;
    }

    size_t optional_offset = coff_end;
    size_t section_table = 0;
    size_t section_table_end = 0;
    if (!add_fits(optional_offset, file_header.SizeOfOptionalHeader,
                  kMaxHeaderBytes, section_table) ||
        !add_fits(section_table,
                  static_cast<size_t>(file_header.NumberOfSections) *
                      sizeof(IMAGE_SECTION_HEADER),
                  kMaxHeaderBytes, section_table_end)) {
        result.error = "PE section table is out of range";
        return result;
    }

    std::vector<uint8_t> tables(section_table_end);
    if (!read_exact(read, module_base, tables.data(), tables.size(),
                    options.chunk_size)) {
        result.error = "failed to read PE section table";
        return result;
    }

    uint16_t optional_magic = 0;
    std::memcpy(&optional_magic, tables.data() + optional_offset,
                sizeof(optional_magic));
    uint32_t size_of_image = 0;
    uint32_t size_of_headers = 0;
    if (optional_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER64)) {
            result.error = "PE32+ optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER64 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
    } else if (optional_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        if (file_header.SizeOfOptionalHeader < sizeof(IMAGE_OPTIONAL_HEADER32)) {
            result.error = "PE32 optional header is truncated";
            return result;
        }
        IMAGE_OPTIONAL_HEADER32 optional{};
        std::memcpy(&optional, tables.data() + optional_offset, sizeof(optional));
        size_of_image = optional.SizeOfImage;
        size_of_headers = optional.SizeOfHeaders;
    } else {
        result.error = "unsupported PE optional-header magic";
        return result;
    }

    if (size_of_image == 0 || size_of_headers < section_table_end ||
        size_of_headers > kMaxHeaderBytes) {
        result.error = "PE image/header sizes are invalid";
        return result;
    }
    if (module_size < size_of_image) {
        result.warnings.push_back("enumerated module size is smaller than SizeOfImage");
    }

    std::vector<IMAGE_SECTION_HEADER> sections(file_header.NumberOfSections);
    std::memcpy(sections.data(), tables.data() + section_table,
                sections.size() * sizeof(IMAGE_SECTION_HEADER));

    size_t output_size = size_of_headers;
    for (const auto& section : sections) {
        size_t end = 0;
        if (!add_fits(section.PointerToRawData, section.SizeOfRawData,
                      kMaxOutputBytes, end)) {
            result.error = "PE section raw range is out of bounds";
            return result;
        }
        output_size = std::max(output_size, end);
    }
    if (output_size < 1024 || output_size > kMaxOutputBytes) {
        result.error = "reconstructed PE size is invalid";
        return result;
    }

    output.assign(output_size, 0);
    if (!read_exact(read, module_base, output.data(), size_of_headers,
                    options.chunk_size)) {
        result.error = "failed to read complete PE headers";
        output.clear();
        return result;
    }

    bool complete = true;
    for (const auto& section : sections) {
        if (section.SizeOfRawData == 0) continue;

        const uint64_t section_end = static_cast<uint64_t>(section.VirtualAddress) +
                                     section.SizeOfRawData;
        size_t readable = section.SizeOfRawData;
        if (section.VirtualAddress >= size_of_image) {
            readable = 0;
        } else if (section_end > size_of_image) {
            readable = size_of_image - section.VirtualAddress;
        }

        if (readable != 0 && !read_exact(
                read, module_base + section.VirtualAddress,
                output.data() + section.PointerToRawData, readable,
                options.chunk_size)) {
            if (options.strict_reads) {
                result.error = "failed to read section " +
                    std::string(reinterpret_cast<const char*>(section.Name),
                                strnlen(reinterpret_cast<const char*>(section.Name), 8));
                output.clear();
                return result;
            }
            std::fill_n(output.data() + section.PointerToRawData, readable, 0);
            complete = false;
        }
        if (readable < section.SizeOfRawData) {
            complete = false;
            result.warnings.push_back("section data extends beyond SizeOfImage and was zero-filled");
        }
    }

    // populate per-section info
    for (const auto& section : sections) {
        section_dump_info_t si;
        si.name.assign(reinterpret_cast<const char*>(section.Name),
                       strnlen(reinterpret_cast<const char*>(section.Name), 8));
        si.virtual_addr = section.VirtualAddress;
        si.virtual_size = section.Misc.VirtualSize;
        si.raw_offset = section.PointerToRawData;
        si.raw_size = section.SizeOfRawData;
        si.characteristics = section.Characteristics;
        si.bytes_read = section.SizeOfRawData;
        result.sections.push_back(si);
    }

    // fix checksum if requested
    if (options.fix_checksum && !output.empty()) {
        result.checksum = fix_pe_checksum(output);
    }

    const auto parsed = disasm::pe_parse(output.data(), output.size());
    if (!parsed.ok || parsed.sections.size() != sections.size()) {
        result.error = "reconstructed image failed PE validation";
        output.clear();
        return result;
    }

    result.ok = true;
    result.complete = complete;
    result.bytes_written = output.size();
    result.section_count = sections.size();
    return result;
}

module_dump_result_t dump_module_pe(
    runtime::session_t& session, const runtime::module_info_t& module,
    const std::string& output_path, const module_dump_options_t& options) {
    std::vector<uint8_t> image;
    auto result = reconstruct_mapped_pe(
        module.base, module.size,
        [&session](uintptr_t address, void* destination, size_t size) {
            return session.read(address, destination, size);
        },
        image, options);
    result.output_path = output_path;
    if (!result.ok) return result;

    // IAT rebuild: compare with the on-disk copy if available
    if (options.rebuild_imports) {
        // try to find the disk file: module path from the session
        // this is best-effort; if the file isn't accessible we skip
        result.imports_rebuilt = rebuild_iat(image, module.path);
    }

    // hook detection + unhooking against disk copy
    if (options.unhook_code && !module.path.empty()) {
        for (auto& si : result.sections) {
            if (!(si.characteristics & 0x20)) continue;  // code sections only
            auto diffs = detect_hooks(image, module.path,
                                       si.virtual_addr, si.raw_size);
            si.hook_count = diffs.size();
            si.hooked = !diffs.empty();
            result.hooks_detected += diffs.size();

            // restore disk bytes for hooked locations
            for (const auto& d : diffs) {
                if (d.rva < image.size()) {
                    image[d.rva] = d.disk_byte;
                    ++result.hooks_restored;
                }
            }
        }
    }

    // recalculate checksum after all modifications
    if (options.fix_checksum && !image.empty()) {
        result.checksum = fix_pe_checksum(image);
    }

    if (!write_atomic(output_path, image, result.error)) {
        result.ok = false;
        result.bytes_written = 0;
        return result;
    }
    result.bytes_written = image.size();
    return result;
}

std::vector<module_dump_result_t> dump_all_modules(
    runtime::session_t& session,
    const std::string& output_dir,
    const module_dump_options_t& options) {
    std::vector<module_dump_result_t> results;
    auto mods = runtime::active().enum_modules(session.handle());
    if (!mods.ok) return results;

    std::filesystem::create_directories(output_dir);
    for (const auto& mod : mods.items) {
        std::string safe_name = mod.name;
        for (char& c : safe_name) {
            if (c == '\\' || c == '/' || c == ':' || c == '*' ||
                c == '?' || c == '"' || c == '<' || c == '>' || c == '|')
                c = '_';
        }
        const std::string path = output_dir + "/" + safe_name;
        results.push_back(dump_module_pe(session, mod, path, options));
    }
    return results;
}

std::vector<hook_diff_t> detect_hooks(
    const std::vector<uint8_t>& memory_image,
    const std::string& disk_path,
    uint32_t section_rva, uint32_t section_size) {
    std::vector<hook_diff_t> diffs;
    if (disk_path.empty()) return diffs;

    // read the on-disk file
    std::ifstream disk(disk_path, std::ios::binary);
    if (!disk) return diffs;
    std::vector<uint8_t> disk_data(
        (std::istreambuf_iterator<char>(disk)),
         std::istreambuf_iterator<char>());

    if (disk_data.size() < sizeof(IMAGE_DOS_HEADER)) return diffs;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(disk_data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return diffs;

    const size_t nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > disk_data.size()) return diffs;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        disk_data.data() + nt_off);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return diffs;

    // find the section in the disk file that matches our rva
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        if (sec[i].VirtualAddress != section_rva) continue;

        const uint32_t disk_off = sec[i].PointerToRawData;
        const uint32_t disk_sz = sec[i].SizeOfRawData;
        const uint32_t cmp_sz = std::min({section_size, disk_sz,
            static_cast<uint32_t>(disk_data.size() - disk_off)});

        // the memory image has section data at PointerToRawData (file layout)
        // find where section_rva maps in the reconstructed image
        // since we reconstructed with file layout, it's at the section's raw offset
        // but we need to find our section's raw offset in the output
        uint32_t mem_off = section_rva;  // in memory layout, data is at VA
        // actually in the reconstructed image, data is at PointerToRawData
        // find it from the output PE headers
        if (memory_image.size() < sizeof(IMAGE_DOS_HEADER)) break;
        const auto* out_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(memory_image.data());
        const auto* out_nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            memory_image.data() + out_dos->e_lfanew);
        const auto* out_sec = IMAGE_FIRST_SECTION(out_nt);
        uint32_t out_off = 0;
        for (uint16_t j = 0; j < out_nt->FileHeader.NumberOfSections; ++j) {
            if (out_sec[j].VirtualAddress == section_rva) {
                out_off = out_sec[j].PointerToRawData;
                break;
            }
        }
        if (!out_off) break;

        for (uint32_t k = 0; k < cmp_sz; ++k) {
            if (out_off + k >= memory_image.size()) break;
            if (disk_off + k >= disk_data.size()) break;
            if (memory_image[out_off + k] != disk_data[disk_off + k]) {
                diffs.push_back({
                    out_off + k,
                    memory_image[out_off + k],
                    disk_data[disk_off + k]
                });
            }
        }
        break;
    }
    return diffs;
}

size_t rebuild_iat(std::vector<uint8_t>& image, const std::string& disk_path) {
    if (disk_path.empty() || image.size() < sizeof(IMAGE_DOS_HEADER))
        return 0;

    // read on-disk PE to get the original import directory
    std::ifstream disk(disk_path, std::ios::binary);
    if (!disk) return 0;
    std::vector<uint8_t> disk_data(
        (std::istreambuf_iterator<char>(disk)),
         std::istreambuf_iterator<char>());
    if (disk_data.size() < sizeof(IMAGE_DOS_HEADER)) return 0;

    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(disk_data.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        disk_data.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    // copy the import directory from the disk image into our reconstructed image
    // the IAT in memory contains resolved addresses; the disk IAT contains
    // hints/names. we want the disk version for static analysis.
    const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress == 0 || import_dir.Size == 0) return 0;

    // find the section containing the import directory in the disk file
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t sec_start = sec[i].VirtualAddress;
        uint32_t sec_end = sec_start + sec[i].Misc.VirtualSize;
        if (import_dir.VirtualAddress < sec_start ||
            import_dir.VirtualAddress >= sec_end) continue;

        // found: copy the entire section from disk to our image
        // (this restores the IAT to its unresolved state)
        uint32_t disk_off = sec[i].PointerToRawData;
        uint32_t disk_sz = sec[i].SizeOfRawData;

        // find the matching section in our output
        const auto* out_dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
        const auto* out_nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
            image.data() + out_dos->e_lfanew);
        const auto* out_sec = IMAGE_FIRST_SECTION(out_nt);
        for (uint16_t j = 0; j < out_nt->FileHeader.NumberOfSections; ++j) {
            if (out_sec[j].VirtualAddress != sec_start) continue;
            uint32_t out_off = out_sec[j].PointerToRawData;
            uint32_t copy_sz = std::min({disk_sz,
                static_cast<uint32_t>(disk_data.size() - disk_off),
                static_cast<uint32_t>(image.size() - out_off)});
            std::memcpy(image.data() + out_off,
                        disk_data.data() + disk_off, copy_sz);
            return copy_sz / sizeof(IMAGE_IMPORT_DESCRIPTOR);  // approximate count
        }
        break;
    }
    return 0;
}

uint32_t fix_pe_checksum(std::vector<uint8_t>& image) {
    if (image.size() < sizeof(IMAGE_DOS_HEADER)) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(image.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;

    const size_t nt_off = dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > image.size()) return 0;

    // checksum field offset: nt_off + 0x18 + 0x40 (OptionalHeader + 0x40)
    const size_t checksum_off = nt_off + 0x18 + 0x40;
    if (checksum_off + 4 > image.size()) return 0;

    // zero the checksum field first
    std::memset(image.data() + checksum_off, 0, 4);

    // compute: sum all uint16_t words with carry folding
    uint64_t sum = 0;
    const size_t word_count = image.size() / 2;
    const auto* words = reinterpret_cast<const uint16_t*>(image.data());
    for (size_t i = 0; i < word_count; ++i) {
        sum += words[i];
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    if (image.size() & 1) {
        sum += image.back();
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    sum = (sum & 0xFFFF) + (sum >> 16);  // final carry fold
    uint32_t checksum = static_cast<uint32_t>(sum) +
                        static_cast<uint32_t>(image.size());

    // write it back
    std::memcpy(image.data() + checksum_off, &checksum, 4);
    return checksum;
}

} // namespace slop::core::process
