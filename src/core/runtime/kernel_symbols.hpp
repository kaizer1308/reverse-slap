#pragma once

// src/core/runtime/kernel_symbols.hpp
// kernel symbols without a vendored pdb parser, read the debug directory
// through the bridge, pull the pdb from the microsoft server into a
// cache and resolve through dbghelp

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::runtime {

struct kernel_sym_t {
    uint64_t    address = 0;   // absolute VA at current ntoskrnl base
    std::string name;
};

namespace kernel_symbols {

struct load_state_t {
    bool     loaded = false;
    std::string pdb_path;
    std::string module_name;
    uint64_t ntos_base = 0;
    std::string guid_text;
    std::string error;
};

// Ensure the PDB is cached and loaded into dbghelp for the live base
load_state_t ensure_loaded();

// Resolve by symbol name ("NtCreateFile", "nt!NtCreateFile")
std::optional<kernel_sym_t> lookup(const std::string& name);

// Nearest known symbol below `address` plus offset
std::optional<kernel_sym_t> nearest(uint64_t address, int64_t* out_offset);

} // namespace kernel_symbols
} // namespace slop::core::runtime
