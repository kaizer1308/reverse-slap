#pragma once

// src/core/process/process_list.hpp
// Snapshot of running processes. Job-based refresh, immutable cached result

#include <cstdint>
#include <memory>
#include <vector>

#include "core/runtime/backend.hpp"

namespace slop::core::process {

struct process_list_t {
    std::vector<runtime::process_info_t> items;
    int64_t  sampled_ms         = 0;
    bool     truncated          = false;
    bool     debug_privilege    = false;
    uint32_t inaccessible_count = 0;
};

// Submits a background job to refresh the process list
// Returns the job id (0 = rejected)
uint64_t refresh_processes(bool resolve_details = true);

// Returns the most recent immutable snapshot (may be nullptr before first refresh)
std::shared_ptr<const process_list_t> cached_processes();

} // namespace slop::core::process
