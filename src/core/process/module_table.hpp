#pragma once

// src/core/process/module_table.hpp
// Module enumeration and VA-to-module lookup for attached target

#include <cstdint>
#include <memory>
#include <vector>

#include "core/runtime/backend.hpp"

namespace slop::core::process {

struct module_table_t {
    std::vector<runtime::module_info_t> items;
    int64_t sampled_ms = 0;
};

// Refresh modules for the active target. Returns job id (0 = rejected/no target)
uint64_t refresh_modules();

// Most recent immutable snapshot
std::shared_ptr<const module_table_t> cached_modules();

// Resolve a virtual address to its owning module (nullptr if not found)
const runtime::module_info_t* va_to_module(uintptr_t va);

} // namespace slop::core::process
