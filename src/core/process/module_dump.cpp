#include "core/process/module_dump.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
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

    if (!write_atomic(output_path, image, result.error)) {
        result.ok = false;
        result.bytes_written = 0;
        return result;
    }
    return result;
}

} // namespace slop::core::process
