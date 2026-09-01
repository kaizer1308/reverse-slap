#include "region_zoo.hpp"

#include <windows.h>
#include <cstdio>
#include <cstring>

namespace slop_target {

region_zoo_t g_zoo{};

void zoo_init() {
    constexpr size_t rw_size = 1u << 20; // 1 MiB

    // PAGE_READWRITE, filled with a known repeating pattern
    g_zoo.rw_block = VirtualAlloc(nullptr, rw_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (g_zoo.rw_block) {
        g_zoo.rw_size = rw_size;
        auto* p = static_cast<uint8_t*>(g_zoo.rw_block);
        for (size_t i = 0; i < rw_size; ++i) {
            p[i] = static_cast<uint8_t>(i & 0xFF);
        }
    }

    // PAGE_NOACCESS, scanner must skip this
    g_zoo.noaccess_block = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);

    // PAGE_GUARD, scanner must skip this
    g_zoo.guard_block = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (g_zoo.guard_block) {
        DWORD old_prot = 0;
        VirtualProtect(g_zoo.guard_block, 4096, PAGE_READWRITE | PAGE_GUARD, &old_prot);
    }

    // PAGE_EXECUTE_READ, tests executable region exclusion
    g_zoo.exec_block = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (g_zoo.exec_block) {
        // Fill with NOPs, then re-protect to EXECUTE_READ
        std::memset(g_zoo.exec_block, 0x90, 4096);
        DWORD old_prot = 0;
        VirtualProtect(g_zoo.exec_block, 4096, PAGE_EXECUTE_READ, &old_prot);
    }

    // MEM_RESERVE only (no commit), 64 MiB
    g_zoo.reserve_block = VirtualAlloc(nullptr, 64u << 20, MEM_RESERVE, PAGE_READWRITE);

    // Mapped file view
    HANDLE hMap = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0, 4096, nullptr);
    if (hMap) {
        g_zoo.mapped_handle = hMap;
        g_zoo.mapped_view = MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 4096);
        if (g_zoo.mapped_view) {
            std::memset(g_zoo.mapped_view, 0x42, 4096);
        }
    }

    std::printf("[zoo] rw=%p noaccess=%p guard=%p exec=%p reserve=%p mapped=%p\n",
        g_zoo.rw_block, g_zoo.noaccess_block, g_zoo.guard_block,
        g_zoo.exec_block, g_zoo.reserve_block, g_zoo.mapped_view);
}

void zoo_shutdown() {
    if (g_zoo.mapped_view)    UnmapViewOfFile(g_zoo.mapped_view);
    if (g_zoo.mapped_handle)  CloseHandle(g_zoo.mapped_handle);
    if (g_zoo.rw_block)       VirtualFree(g_zoo.rw_block, 0, MEM_RELEASE);
    if (g_zoo.noaccess_block) VirtualFree(g_zoo.noaccess_block, 0, MEM_RELEASE);
    if (g_zoo.guard_block)    VirtualFree(g_zoo.guard_block, 0, MEM_RELEASE);
    if (g_zoo.exec_block)     VirtualFree(g_zoo.exec_block, 0, MEM_RELEASE);
    if (g_zoo.reserve_block)  VirtualFree(g_zoo.reserve_block, 0, MEM_RELEASE);
    g_zoo = {};
}

} // namespace slop_target
