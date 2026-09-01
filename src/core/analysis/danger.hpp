#pragma once

// dangerous import callsite hunt, names matched against a risk table then
// callsites resolved through a caller supplied xref resolver

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"

namespace slop::core::analysis {

struct danger_hit_t {
    std::string              function;    // imported API name
    std::string              category;    // "execution" | "fs" | "copy" .
    uint64_t                 iat_va = 0;  // IAT slot VA in this image
    std::vector<uint64_t>    callsites;   // VAs referencing the slot
};

using xref_resolver_t =
    std::function<std::vector<uint64_t>(uint64_t target_va)>;

// base is the session va base for iat math, 0 means the preferred base
std::vector<danger_hit_t> danger_scan(
    const disasm::pe_image_t& pe,
    const xref_resolver_t& refs_to,
    uint64_t base = 0);

} // namespace slop::core::analysis
