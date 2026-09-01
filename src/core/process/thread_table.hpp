#pragma once

// src/core/process/thread_table.hpp
// Thread enumeration for attached target

#include <cstdint>
#include <memory>
#include <vector>

#include "core/runtime/backend.hpp"

namespace slop::core::process {

struct thread_table_t {
    std::vector<runtime::thread_info_t> items;
    int64_t sampled_ms = 0;
};

// Refresh threads for the active target. Returns job id (0 = rejected/no target)
uint64_t refresh_threads();

// Most recent immutable snapshot
std::shared_ptr<const thread_table_t> cached_threads();

} // namespace slop::core::process
