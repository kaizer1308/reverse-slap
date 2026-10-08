// src/core/process/runtime_dump.hpp
// Full runtime deobfuscated PE dump: captures the unpacked/decrypted state
// of a protected binary (VMProtect, Themida, custom packers) after it has
// finished initializing. Performs:
//   1. Full virtual-range memory dump via kernel phys reads
//   2. PE header reconstruction from memory layout
//   3. Import reconstruction by scanning the IAT for resolved addresses
//      and matching them against exports of all loaded DLLs (Scylla-class)
//   4. OEP detection via heuristics (TLS, entry stub analysis)
//   5. Section permission fixup from actual page protections
//   6. Relocation directory rebuild (optional)
// All reads go through the session (kernel phys path when winotify loaded).
// Zero handles in the target, zero API calls in target context.
#pragma once

#include "core/runtime/backend.hpp"
#include "core/runtime/session.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::process {

// ── import reconstruction ────────────────────────────────────────────────

struct reconstructed_import_t {
    std::string dll_name;
    std::string func_name;
    uint16_t    ordinal = 0;
    bool        by_ordinal = false;
    uint64_t    iat_rva = 0;       // RVA of the IAT slot in the dump
    uint64_t    resolved_va = 0;   // runtime address found in memory
};

struct import_module_t {
    std::string dll_name;
    std::vector<reconstructed_import_t> functions;
};

// ── runtime dump options ─────────────────────────────────────────────────

struct runtime_dump_options_t {
    bool    reconstruct_imports = true;    // scan IAT + match to DLL exports
    bool    detect_oep = true;             // find the real entry point
    bool    fix_sections = true;           // rebuild section table from pages
    bool    fix_checksum = true;
    bool    remove_packer_sections = true; // strip sections named .vmp, .the, etc.
    bool    realign_file = true;           // 0x200 file alignment for IDA
    size_t  chunk_size = 64u * 1024u;
    uint32_t file_alignment = 0x200;
};

// ── runtime dump result ──────────────────────────────────────────────────

struct runtime_dump_result_t {
    bool    ok = false;
    std::string error;
    std::string output_path;
    uint64_t module_base = 0;
    uint32_t module_size = 0;
    size_t   bytes_written = 0;

    // import reconstruction
    std::vector<import_module_t> imports;
    size_t total_imports = 0;
    size_t resolved_imports = 0;
    size_t unresolved_imports = 0;

    // OEP
    uint64_t detected_oep = 0;        // absolute VA
    uint32_t detected_oep_rva = 0;    // relative to module base
    std::string oep_method;            // how it was found

    // sections
    size_t sections_rebuilt = 0;
    size_t packer_sections_removed = 0;

    // summary
    std::vector<std::string> warnings;
    uint32_t checksum = 0;
};

// ── main API ─────────────────────────────────────────────────────────────

// dump a fully deobfuscated binary from runtime memory. the target module
// should have finished unpacking (past the packer's entry, into the real
// code). all reads go through the session's kernel phys path.
runtime_dump_result_t dump_deobfuscated(
    runtime::session_t& session,
    uint64_t module_base,
    uint32_t module_size,           // 0 = auto-detect from PE header
    const std::string& output_path,
    const runtime_dump_options_t& options = {});

// scan the resolved IAT and match against exports of all loaded DLLs.
// this is the core of import reconstruction (Scylla-equivalent).
std::vector<import_module_t> reconstruct_imports_from_iat(
    runtime::session_t& session,
    uint64_t module_base,
    const std::vector<uint8_t>& image);

// detect the original entry point by analyzing the module's code.
// returns 0 if detection fails.
uint64_t detect_original_entry(
    runtime::session_t& session,
    uint64_t module_base,
    const std::vector<uint8_t>& image,
    std::string* method_out = nullptr);

// write a new import directory into the PE image from reconstructed imports
bool write_import_directory(
    std::vector<uint8_t>& image,
    uint64_t image_base,
    const std::vector<import_module_t>& imports);

} // namespace slop::core::process
