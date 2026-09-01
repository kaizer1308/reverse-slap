#pragma once

// src/core/process/handle_table.hpp
// Handle enumeration for attached target

#include <cstdint>
#include <memory>
#include <vector>

#include "core/runtime/backend.hpp"

namespace slop::core::process {

struct handle_table_t {
    std::vector<runtime::handle_info_t> items;
    int64_t sampled_ms = 0;
};

// Refresh handles for the active target. Returns job id (0 = rejected/no target)
uint64_t refresh_handles();

// Most recent immutable snapshot
std::shared_ptr<const handle_table_t> cached_handles();

} // namespace slop::core::process
