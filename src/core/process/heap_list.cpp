// src/core/process/heap_list.cpp

#include "core/process/heap_list.hpp"

#include <windows.h>
#include <tlhelp32.h>

namespace slop::core::process {

std::vector<heap_info_t> list_heaps(uint32_t pid, std::string* error) {
    std::vector<heap_info_t> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        if (error) *error = "snapshot failed";
        return out;
    }
    HEAPLIST32 hl{};
    hl.dwSize = sizeof(hl);
    if (Heap32ListFirst(snap, &hl)) {
        do {
            heap_info_t h;
            h.base  = hl.th32HeapID;
            h.flags = hl.dwFlags;
            // Per-heap size: sum of blocks is expensive; report the list
            // entry's committed range via the block walk lazily instead
            HEAPENTRY32 he{};
            he.dwSize = sizeof(he);
            uint64_t max_end = 0;
            if (Heap32First(&he, pid, hl.th32HeapID)) {
                do {
                    const uint64_t end =
                        static_cast<uint64_t>(he.dwAddress) +
                        he.dwBlockSize;
                    if (end > max_end) max_end = end;
                    ++h.entries_used_hint;
                } while (Heap32Next(&he) &&
                         h.entries_used_hint < 200000);
            }
            h.size = static_cast<uint32_t>(
                max_end > h.base ? max_end - h.base : 0);
            out.push_back(std::move(h));
        } while (Heap32ListNext(snap, &hl));
    }
    CloseHandle(snap);
    return out;
}

std::vector<heap_block_t> walk_heap_blocks(uint32_t pid, uint64_t heap_base,
                                           std::string* error,
                                           size_t max_blocks) {
    std::vector<heap_block_t> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPHEAPLIST, pid);
    if (snap == INVALID_HANDLE_VALUE) {
        if (error) *error = "snapshot failed";
        return out;
    }
    HEAPLIST32 hl{};
    hl.dwSize = sizeof(hl);
    if (Heap32ListFirst(snap, &hl)) {
        do {
            if (hl.th32HeapID != heap_base) continue;
            HEAPENTRY32 he{};
            he.dwSize = sizeof(he);
            if (Heap32First(&he, pid, hl.th32HeapID)) {
                do {
                    if (out.size() >= max_blocks) break;
                    heap_block_t b;
                    b.address = he.dwAddress;
                    b.size    = he.dwBlockSize;
                    b.flags   = he.dwFlags;
                    out.push_back(std::move(b));
                } while (Heap32Next(&he));
            }
            break;
        } while (Heap32ListNext(snap, &hl));
    }
    CloseHandle(snap);
    return out;
}

} // namespace slop::core::process
