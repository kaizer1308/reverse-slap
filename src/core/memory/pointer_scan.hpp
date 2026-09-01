#pragma once

// multi level backward pointer scan, one sweep per level, the frontier
// filters each aligned qword read, optional module backed roots only

#include <cstdint>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory {

struct pointer_scan_options_t {
    uintptr_t target     = 0;
    uint32_t  depth      = 3;        // clamped to infra::limits::max_pointer_depth
    int32_t   min_offset = -4096;
    int32_t   max_offset =  4096;
    uint32_t  alignment  = 4;        // qword holder alignment
    size_t    frontier_cap = 100'000; // per-level expansion guard
    bool      only_module_backed = false; // roots must live in MEM_IMAGE regions
};

struct pointer_chain_result_t {
    std::vector<uintptr_t> addresses;  // [root-most holder, ..., final holder]
    std::vector<int64_t>   offsets;    // offsets[i] applies to addresses[i]'s value

    size_t depth() const noexcept { return addresses.size(); }
};

struct pointer_scan_stats_t {
    uint64_t edges_explored = 0;
    bool     truncated      = false;
    bool     cancelled      = false;
};

std::vector<pointer_chain_result_t>
pointer_scan(reader_t& r,
             const std::vector<scan_region_t>& regions,
             const pointer_scan_options_t& opt,
             const slop::core::infra::cancel_token_t& tok,
             pointer_scan_stats_t* stats);

} // namespace slop::core::memory
