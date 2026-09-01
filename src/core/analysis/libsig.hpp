#pragma once

// byte signature library recognition, masked patterns over exec sections,
// sets are simple json entries with ?? wildcards

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"

namespace slop::core::analysis {

struct libsig_t {
    std::string name;
    std::string pattern;    // hex with ?? wildcards
    uint32_t    offset = 0; // anchor offset within the routine
};

struct libsig_hit_t {
    std::string sig_name;
    uint64_t    va = 0;
    std::optional<uint64_t> function_va;  // containing indexed function
};

std::vector<libsig_hit_t> libsig_scan(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    const disasm::function_index_t& fidx,
    const std::vector<libsig_t>& sigs);

// Parse a JSON signature set string ([[{"name","pattern","offset"},...]])
std::optional<std::vector<libsig_t>> parse_sig_set(const std::string& json_text,
                                                   std::string* error = nullptr);

} // namespace slop::core::analysis
