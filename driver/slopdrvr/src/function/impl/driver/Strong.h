#pragma once
#pragma warning(push)
#pragma warning(disable: 4714)

#include <ntifs.h>
#include <intrin.h>
#include <imports/Defs.h>
#include <function/CoreSecurity.h>
#include <function/KernelLayout.h>

#define win_1803 17134
#define win_1809 17763
#define win_1903 18362
#define win_1909 18363
#define win_2004 19041
#define win_20H2 19569
#define win_21H1 20180
#define win_22H2 19045

__forceinline UINT64 pfn_mask()
{
    static volatile LONG g_pfn_mask_resolved = 0;
    static volatile UINT64 g_pfn_mask_value = 0x000FFFFFFFFFF000ULL;

    if (_InterlockedCompareExchange(&g_pfn_mask_resolved, 0, 0) == 2)
        return g_pfn_mask_value;

    LONG prev = _InterlockedCompareExchange(&g_pfn_mask_resolved, 1, 0);
    if (prev == 2)
        return g_pfn_mask_value;
    if (prev == 1) {
        while (_InterlockedCompareExchange(&g_pfn_mask_resolved, 0, 0) == 1)
            YieldProcessor();
        return g_pfn_mask_value;
    }

    ULONG build = slopdrvr_kernel_layout::build_number();
    if (build >= 22000)
        g_pfn_mask_value = 0x000FFFFFFFFFFF000ULL;
    else
        g_pfn_mask_value = 0x000FFFFFFFFFF000ULL;

    KeMemoryBarrier();
    _InterlockedExchange(&g_pfn_mask_resolved, 2);
    return g_pfn_mask_value;
}

#define PMASK pfn_mask()

namespace timing_guard {
    inline volatile ULONG g_timing_seed = 0x5A5A5A5Au;
    inline volatile ULONG64 g_timing_counter = 0;

    __forceinline ULONG next_timing_rand() {
        ULONG x = g_timing_seed;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        x ^= (ULONG)(__rdtsc() & 0xFFu);
        g_timing_seed = x;
        g_timing_counter++;
        return x;
    }

    __forceinline void add_jitter() {
        volatile ULONG spin = (next_timing_rand() & 0x7) + 1;
        while (spin--) {
            YieldProcessor();
        }
    }

    __forceinline void add_read_jitter() {
        if ((next_timing_rand() & 0xF) < 3) {
            add_jitter();
        }
    }

    __forceinline void heavy_jitter() {
        volatile ULONG count = (next_timing_rand() & 0x3) + 1;
        for (ULONG i = 0; i < count; i++) {
            add_jitter();
            KeMemoryBarrier();
        }
    }
}

namespace strong {

    __forceinline VOID* kmemcpy(void* dest, const void* src, size_t len) {
        char* d = (char*)dest;
        const char* s = (const char*)src;
        while (len--)
            *d++ = *s++;
        return dest;
    }

    __forceinline VOID* kmemset(void* dest, int val, size_t len) {
        unsigned char* d = (unsigned char*)dest;
        while (len--)
            *d++ = (unsigned char)val;
        return dest;
    }

    __forceinline ULONG get_windows_version() {
        RTL_OSVERSIONINFOW windows_version = { sizeof(RTL_OSVERSIONINFOW) };
        if (_RtlGetVersion && NT_SUCCESS(_RtlGetVersion(&windows_version))) {
            return windows_version.dwBuildNumber;
        }
        return 19045;
    }

    __forceinline NTSTATUS read_physical(ULONGLONG Address, PVOID buffer, SIZE_T size, SIZE_T* bytes_read) {
        if (!_MmCopyMemory || !buffer || size == 0) {
            if (bytes_read) *bytes_read = 0;
            return STATUS_INVALID_PARAMETER;
        }

        if (Address > 0x0000FFFFFFFFFFFFULL) {
            if (bytes_read) *bytes_read = 0;
            return STATUS_INVALID_ADDRESS;
        }

        timing_guard::add_read_jitter();

        MM_COPY_ADDRESS readable = { 0 };
        readable.PhysicalAddress.QuadPart = (LONGLONG)Address;

        SIZE_T copied = 0;
        NTSTATUS status = _MmCopyMemory(buffer, readable, size, MM_COPY_MEMORY_PHYSICAL, &copied);

        if (bytes_read) {
            *bytes_read = copied;
        }

        return status;
    }

    __forceinline NTSTATUS write_physical(PVOID Address, PVOID buffer, SIZE_T size, SIZE_T* bytes_written) {
        if (!Address || !buffer || size == 0) {
            if (bytes_written) *bytes_written = 0;
            return STATUS_INVALID_PARAMETER;
        }

        if (!_MmMapIoSpaceEx || !_MmUnmapIoSpace) {
            if (bytes_written) *bytes_written = 0;
            return STATUS_NOT_SUPPORTED;
        }

        if (size > 0x1000) {
            if (bytes_written) *bytes_written = 0;
            return STATUS_INVALID_BUFFER_SIZE;
        }

        timing_guard::add_jitter();

        PHYSICAL_ADDRESS writable = { 0 };
        writable.QuadPart = (LONGLONG)Address;

        if (writable.QuadPart > 0x0000FFFFFFFFFFFFLL || writable.QuadPart < 0x1000LL) {
            if (bytes_written) *bytes_written = 0;
            return STATUS_INVALID_ADDRESS;
        }

        PVOID mapped_memory = _MmMapIoSpaceEx(writable, size, PAGE_NOCACHE | PAGE_READWRITE);
        if (!mapped_memory) {
            if (bytes_written) *bytes_written = 0;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        __try {
            kmemcpy(mapped_memory, buffer, size);
            KeMemoryBarrier();

            if (bytes_written) *bytes_written = size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            _MmUnmapIoSpace(mapped_memory, size);
            if (bytes_written) *bytes_written = 0;
            return STATUS_ACCESS_VIOLATION;
        }

        _MmUnmapIoSpace(mapped_memory, size);

        return STATUS_SUCCESS;
    }

    __forceinline UINT64 translate_virtual_address(UINT64 directory_table_base, UINT64 virtual_address) {
        directory_table_base &= ~0xFFFull;

        directory_table_base &= PMASK;

        if (!directory_table_base) {
            return 0;
        }

        const UINT64 page_offset = virtual_address & 0xFFF;
        const UINT64 pte_index = (virtual_address >> 12) & 0x1FF;
        const UINT64 pde_index = (virtual_address >> 21) & 0x1FF;
        const UINT64 pdpte_index = (virtual_address >> 30) & 0x1FF;
        const UINT64 pml4e_index = (virtual_address >> 39) & 0x1FF;

        SIZE_T bytes_read = 0;

        UINT64 pml4e = 0;
        NTSTATUS status = read_physical(directory_table_base + (pml4e_index * 8), &pml4e, sizeof(pml4e), &bytes_read);
        if (!NT_SUCCESS(status) || bytes_read != sizeof(pml4e)) return 0;
        if (!(pml4e & 1)) return 0;


        UINT64 pdpte = 0;
        status = read_physical((pml4e & PMASK) + (pdpte_index * 8), &pdpte, sizeof(pdpte), &bytes_read);
        if (!NT_SUCCESS(status) || bytes_read != sizeof(pdpte)) return 0;

        if (pdpte & 1) {

            if (pdpte & 0x80) {
                return (pdpte & 0x000FFFFFC0000000ull) + (virtual_address & 0x3FFFFFFF);
            }
        } else if (!(pdpte & (1ull << 10)) && (pdpte & (1ull << 11))) {


        } else {
            return 0;
        }


        UINT64 pde = 0;
        status = read_physical((pdpte & PMASK) + (pde_index * 8), &pde, sizeof(pde), &bytes_read);
        if (!NT_SUCCESS(status) || bytes_read != sizeof(pde)) return 0;

        if (pde & 1) {

            if (pde & 0x80) {

                return (pde & 0x000FFFFFFFE00000ull) + (virtual_address & 0x1FFFFF);
            }
        } else if (!(pde & (1ull << 10)) && (pde & (1ull << 11))) {


        } else {
            return 0;
        }


        UINT64 pte = 0;
        status = read_physical((pde & PMASK) + (pte_index * 8), &pte, sizeof(pte), &bytes_read);
        if (!NT_SUCCESS(status) || bytes_read != sizeof(pte)) return 0;

        if (pte & 1) {

            const UINT64 physical_base = pte & PMASK;
            if (!physical_base) return 0;
            return physical_base + page_offset;
        }


        if (!(pte & (1ull << 10)) && (pte & (1ull << 11))) {
            const UINT64 physical_base = pte & PMASK;
            if (!physical_base) return 0;
            return physical_base + page_offset;
        }

        return 0;
    }
}

#pragma warning(pop)
