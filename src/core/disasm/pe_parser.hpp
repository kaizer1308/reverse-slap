#pragma once

// dependency free pe32+ parser over in memory file images

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::disasm {

struct pe_section_t {
    char     name[9]     = {};   // NUL-padded
    uint32_t rva         = 0;
    uint32_t virtual_size = 0;
    uint32_t raw_offset  = 0;
    uint32_t raw_size    = 0;
    uint32_t characteristics = 0;

    bool is_executable() const noexcept { return (characteristics & 0x20000000) != 0; } // IMAGE_SCN_MEM_EXECUTE
    bool contains_rva(uint32_t r) const noexcept {
        return r >= rva && r < rva + (virtual_size ? virtual_size : raw_size);
    }
};

struct pe_import_func_t {
    std::string name;
    uint16_t    ordinal = 0;
    bool        by_ordinal = false;
    uint32_t    iat_rva = 0;   // RVA of this function's IAT slot (PE32+)
};

struct pe_import_dll_t {
    std::string                   dll;
    std::vector<pe_import_func_t> functions;
};

struct pe_export_t {
    std::string name;
    uint32_t    rva     = 0;
    uint16_t    ordinal = 0;
    bool        forwarded = false;
    std::string forwarder;
};

struct pe_data_dir_t {
    uint32_t rva  = 0;
    uint32_t size = 0;
};

struct pe_image_t {
    bool     ok            = false;
    bool     pe32plus      = false;
    uint16_t machine       = 0;
    uint16_t subsystem     = 0;
    uint64_t image_base    = 0;
    uint32_t entry_rva     = 0;
    uint32_t size_of_image = 0;

    std::vector<pe_section_t> sections;
    std::vector<pe_import_dll_t> imports;
    std::vector<pe_export_t>     exports;

    pe_data_dir_t data_dirs[16] = {};

    std::optional<size_t> rva_to_offset(uint32_t rva) const;
    std::optional<size_t> va_to_offset(uint64_t va) const;   // uses image_base
    std::optional<uintptr_t> offset_to_va(size_t off) const;

    const pe_section_t* section_for_rva(uint32_t rva) const;
};

// Parse a file image. Returns ok=false (with everything zeroed) on failure
pe_image_t pe_parse(const uint8_t* data, size_t len);

} // namespace slop::core::disasm
