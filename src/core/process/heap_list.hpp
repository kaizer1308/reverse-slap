#pragma once

// src/core/process/heap_list.hpp
// Target heap enumeration via Toolhelp snapshots (user-mode, no internals)

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::process {

struct heap_info_t {
    uint64_t    base = 0;
    uint32_t    size = 0;
    uint32_t    flags = 0;
    uint32_t    entries_used_hint = 0;
};

// Snapshot the target's heap list. Empty + error text on failure
std::vector<heap_info_t> list_heaps(uint32_t pid, std::string* error = nullptr);

// Walk allocation blocks of one heap (Heap32* is list-only; block walking
// uses the snapshot entry table)
struct heap_block_t {
    uint64_t address = 0;
    uint32_t size = 0;
    uint32_t flags = 0;
};
std::vector<heap_block_t> walk_heap_blocks(uint32_t pid, uint64_t heap_base,
                                           std::string* error = nullptr,
                                           size_t max_blocks = 4096);

} // namespace slop::core::process
