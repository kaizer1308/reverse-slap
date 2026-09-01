#pragma once

// src/target/region_zoo.hpp
// Allocations with various protection flags to exercise region shading and scan filters

#include <cstdint>

namespace slop_target {

struct region_zoo_t {
    void*    rw_block       = nullptr;   // PAGE_READWRITE, 1 MiB, filled pattern
    void*    noaccess_block = nullptr;   // PAGE_NOACCESS, 4 KiB
    void*    guard_block    = nullptr;   // PAGE_GUARD | PAGE_READWRITE, 4 KiB
    void*    exec_block     = nullptr;   // PAGE_EXECUTE_READ, 4 KiB
    void*    reserve_block  = nullptr;   // MEM_RESERVE only, 64 MiB
    void*    mapped_view    = nullptr;   // MapViewOfFile
    void*    mapped_handle  = nullptr;   // CreateFileMapping handle
    uint64_t rw_size        = 0;
};

extern region_zoo_t g_zoo;

void zoo_init();
void zoo_shutdown();

} // namespace slop_target
