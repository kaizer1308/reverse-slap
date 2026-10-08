#pragma once

#include "core/runtime/backend.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace slop::core::runtime { class session_t; }

namespace slop::core::process {

using module_read_fn_t =
    std::function<runtime::io_result_t(uintptr_t, void*, size_t)>;

struct module_dump_options_t {
    size_t chunk_size = 64u * 1024u;
    bool strict_reads = true;

    // ── new options ──────────────────────────────────────────────────────
    bool rebuild_imports = true;       // reconstruct IAT from disk imports
    bool fix_section_alignment = true; // realign sections for static analysis
    bool fix_checksum = true;          // recalculate PE checksum
    bool unhook_code = true;           // compare .text with disk copy, restore
    bool strip_relocs = false;         // remove .reloc section (smaller file)
    bool zero_discardable = true;      // zero discardable sections
    uint32_t file_alignment = 0x200;   // output file alignment (0 = keep original)
};

struct section_dump_info_t {
    std::string name;
    uint32_t    virtual_addr = 0;
    uint32_t    virtual_size = 0;
    uint32_t    raw_offset = 0;
    uint32_t    raw_size = 0;
    uint32_t    characteristics = 0;
    size_t      bytes_read = 0;
    size_t      bytes_failed = 0;
    bool        hooked = false;        // differences detected vs disk
    size_t      hook_count = 0;        // number of byte differences
};

struct module_dump_result_t {
    bool ok = false;
    bool complete = false;
    std::string error;
    std::string output_path;
    uint64_t module_base = 0;
    size_t bytes_written = 0;
    size_t section_count = 0;
    std::vector<std::string> warnings;

    // ── new fields ──────────────────────────────────────────────────────
    std::vector<section_dump_info_t> sections;
    size_t imports_rebuilt = 0;        // count of import entries fixed
    size_t hooks_detected = 0;        // total byte diffs vs disk
    size_t hooks_restored = 0;        // bytes restored from disk
    uint32_t checksum = 0;            // recalculated checksum
};

// rebuild a file layout pe from a mapped image, separated so it tests
// without a live process
module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base,
    uint32_t module_size,
    const module_read_fn_t& read,
    std::vector<uint8_t>& output,
    const module_dump_options_t& options = {});

// dump one module through the active session, works with rpm and the
// driver alike
module_dump_result_t dump_module_pe(
    runtime::session_t& session,
    const runtime::module_info_t& module,
    const std::string& output_path,
    const module_dump_options_t& options = {});

// dump all loaded modules to a directory, returns per-module results
std::vector<module_dump_result_t> dump_all_modules(
    runtime::session_t& session,
    const std::string& output_dir,
    const module_dump_options_t& options = {});

// compare a dumped section against the on-disk original and report diffs
struct hook_diff_t {
    uint32_t rva;
    uint8_t  memory_byte;
    uint8_t  disk_byte;
};

std::vector<hook_diff_t> detect_hooks(
    const std::vector<uint8_t>& memory_image,
    const std::string& disk_path,
    uint32_t section_rva, uint32_t section_size);

// rebuild import address table from the on-disk import directory
size_t rebuild_iat(std::vector<uint8_t>& image, const std::string& disk_path);

// recalculate and write the PE checksum
uint32_t fix_pe_checksum(std::vector<uint8_t>& image);

} // namespace slop::core::process
