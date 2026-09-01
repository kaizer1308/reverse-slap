#pragma once
#include <ntifs.h>
#include "../../../imports/Defs.h"
#include "za.h"
#include "Strong.h"
#include "../../KernelLayout.h"

namespace pml4
{
    inline PVOID split_memory(PVOID SearchBase, SIZE_T SearchSize, const void* Pattern, SIZE_T PatternSize)
    {
        if (!SearchBase || !Pattern || SearchSize < PatternSize) {
            return nullptr;
        }

        const UCHAR* searchBase = static_cast<const UCHAR*>(SearchBase);
        const UCHAR* pattern = static_cast<const UCHAR*>(Pattern);

        for (SIZE_T i = 0; i <= SearchSize - PatternSize; ++i) {
            SIZE_T j = 0;
            for (; j < PatternSize; ++j) {
                if (searchBase[i + j] != pattern[j])
                    break;
            }

            if (j == PatternSize)
                return const_cast<UCHAR*>(&searchBase[i]);
        }

        return nullptr;
    }

    inline void* g_mmonp_MmPfnDatabase = nullptr;
    inline volatile LONG g_pfndb_initialized = 0;
    inline volatile LONG g_pfndb_summary_logged = 0;

    __forceinline UINT64 pteframe_mask()
    {
        static volatile LONG g_pteframe_mask_resolved = 0;
        static volatile UINT64 g_pteframe_mask_value = 0xFFFFFFFFFULL;

        if (_InterlockedCompareExchange(&g_pteframe_mask_resolved, 0, 0) == 2)
            return g_pteframe_mask_value;

        LONG prev = _InterlockedCompareExchange(&g_pteframe_mask_resolved, 1, 0);
        if (prev == 2)
            return g_pteframe_mask_value;
        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_pteframe_mask_resolved, 0, 0) == 1)
                YieldProcessor();
            return g_pteframe_mask_value;
        }

        ULONG build = slopdrvr_kernel_layout::build_number();
        if (build >= 22000)
            g_pteframe_mask_value = 0xFFFFFFFFFFULL;
        else
            g_pteframe_mask_value = 0xFFFFFFFFFULL;

        KeMemoryBarrier();
        _InterlockedExchange(&g_pteframe_mask_resolved, 2);
        return g_pteframe_mask_value;
    }

    inline NTSTATUS InitializeMmPfnDatabase()
    {
        if (_InterlockedCompareExchange(&g_pfndb_initialized, 1, 0) == 2) {
            return g_mmonp_MmPfnDatabase ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        LONG prev = _InterlockedCompareExchange(&g_pfndb_initialized, 1, 0);

        if (prev == 2) {
            return g_mmonp_MmPfnDatabase ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        if (prev == 1) {
            while (_InterlockedCompareExchange(&g_pfndb_initialized, 2, 2) != 2) {
                YieldProcessor();
            }
            KeMemoryBarrier();
            return g_mmonp_MmPfnDatabase ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        struct MmPfnDatabaseSearchPattern
        {
            const UCHAR* bytes;
            SIZE_T bytes_size;
            bool hard_coded;
        };

        MmPfnDatabaseSearchPattern patterns;

        static const UCHAR kPatternWin10x64[] = {
            0x48, 0x8B, 0xC1,
            0x48, 0xC1, 0xE8, 0x0C,
            0x48, 0x8D, 0x14, 0x40,
            0x48, 0x03, 0xD2,
            0x48, 0xB8,
        };

        patterns.bytes = kPatternWin10x64;
        patterns.bytes_size = sizeof(kPatternWin10x64);
        patterns.hard_coded = true;

        if (!_MmGetVirtualForPhysical) {
            _InterlockedExchange(&g_pfndb_initialized, 2);
            if (_InterlockedCompareExchange(&g_pfndb_summary_logged, 1, 0) == 0) {
                SD_KERNEL_PATTERN_LOG_PTR("MmPfnDatabase", "semantic_scan", "MmGetVirtualForPhysical.Win10x64", nullptr, FALSE,
                    "MmGetVirtualForPhysical export missing before pattern scan", "missing_MmGetVirtualForPhysical");
            }
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        const auto p_MmGetVirtualForPhysical = reinterpret_cast<UCHAR*>(_MmGetVirtualForPhysical);

        auto found = reinterpret_cast<UCHAR*>(split_memory(p_MmGetVirtualForPhysical, 0x30, patterns.bytes, patterns.bytes_size));
        if (!found) {
            _InterlockedExchange(&g_pfndb_initialized, 2);
            if (_InterlockedCompareExchange(&g_pfndb_summary_logged, 1, 0) == 0) {
                SD_KERNEL_PATTERN_LOG_PTR("MmPfnDatabase", "semantic_scan", "MmGetVirtualForPhysical.Win10x64", nullptr, FALSE,
                    "searched first 0x30 bytes of MmGetVirtualForPhysical for PFN database immediate", "pattern_not_found");
            }
            return STATUS_UNSUCCESSFUL;
        }

        UCHAR* pattern_match = found;
        found += patterns.bytes_size;

        void* pfn_db = nullptr;
        if (patterns.hard_coded) {
            pfn_db = *reinterpret_cast<void**>(found);
        }
        else {
            const auto mmpfn_address = *reinterpret_cast<ULONG_PTR*>(found);
            pfn_db = *reinterpret_cast<void**>(mmpfn_address);
        }

        pfn_db = PAGE_ALIGN(pfn_db);

        if (!pfn_db) {
            _InterlockedExchange(&g_pfndb_initialized, 2);
            if (_InterlockedCompareExchange(&g_pfndb_summary_logged, 1, 0) == 0) {
                SD_KERNEL_PATTERN_LOG_PTR("MmPfnDatabase", patterns.hard_coded ? "hardcoded_pattern" : "semantic_scan",
                    "MmGetVirtualForPhysical.Win10x64", nullptr, FALSE,
                    "pattern matched but decoded PFN database pointer was null after PAGE_ALIGN", "null_decoded_pointer");
            }
            return STATUS_UNSUCCESSFUL;
        }

        g_mmonp_MmPfnDatabase = pfn_db;
        KeMemoryBarrier();
        _InterlockedExchange(&g_pfndb_initialized, 2);
        if (_InterlockedCompareExchange(&g_pfndb_summary_logged, 1, 0) == 0) {
            SD_LOG("KVALIDATE build=%lu kind=pattern name=MmPfnDatabase source=%s pattern=MmGetVirtualForPhysical.Win10x64 value=%p validation=%s evidence=\"primitive=%p match=%p search=0x30 pattern_len=%llu hardcoded=%u aligned=%p\" fail_closed=none",
                sd_kernel_validation_build(),
                patterns.hard_coded ? "hardcoded_pattern" : "semantic_scan",
                pfn_db,
                sd_kernel_validation_state(TRUE),
                p_MmGetVirtualForPhysical,
                pattern_match,
                static_cast<unsigned long long>(patterns.bytes_size),
                patterns.hard_coded ? 1u : 0u,
                pfn_db);
        }

        return STATUS_SUCCESS;
    }

    inline uintptr_t dirbase_from_base_address(void* base)
    {
        if (!base) {
            return 0;
        }

        NTSTATUS init_status = InitializeMmPfnDatabase();
        if (!NT_SUCCESS(init_status) || !g_mmonp_MmPfnDatabase) {
            return 0;
        }

        virt_addr_t virt_base{};
        virt_base.value = base;

        SIZE_T read_size = 0;

        PPHYSICAL_MEMORY_RANGE ranges = _MmGetPhysicalMemoryRanges();
        if (!ranges) {
            return 0;
        }

        uintptr_t result = 0;

        const ULONGLONG MAX_TOTAL_PAGES = 0x400000;
        ULONGLONG total_pages_checked = 0;

        for (int i = 0; ; i++) {
            PPHYSICAL_MEMORY_RANGE elem = &ranges[i];

            if (!elem->BaseAddress.QuadPart || !elem->NumberOfBytes.QuadPart)
                break;

            uintptr_t current_phys_address = elem->BaseAddress.QuadPart;
            ULONGLONG page_count = elem->NumberOfBytes.QuadPart / 0x1000;

            for (ULONGLONG j = 0; j < page_count; j++, current_phys_address += 0x1000) {

                if (++total_pages_checked > MAX_TOTAL_PAGES) {
                    goto cleanup;
                }

                if ((total_pages_checked & 0xFF) == 0) {
                    YieldProcessor();
                }

                _MMPFN* pnfinfo = (_MMPFN*)((uintptr_t)g_mmonp_MmPfnDatabase + (current_phys_address >> 12) * sizeof(_MMPFN));

                if ((pnfinfo->u4.PteFrame & pteframe_mask()) != ((current_phys_address >> 12) & pteframe_mask())) {
                    continue;
                }

                MMPTE pml4e{};
                if (!NT_SUCCESS(strong::read_physical(current_phys_address + 8 * virt_base.pml4_index, &pml4e, 8, &read_size)) || read_size != 8)
                    continue;

                if (!pml4e.u.Hard.Valid)
                    continue;

                MMPTE pdpte{};
                if (!NT_SUCCESS(strong::read_physical((pml4e.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pdpt_index, &pdpte, 8, &read_size)) || read_size != 8)
                    continue;

                if (!pdpte.u.Hard.Valid)
                    continue;

                MMPTE pde{};
                if (!NT_SUCCESS(strong::read_physical((pdpte.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pd_index, &pde, 8, &read_size)) || read_size != 8)
                    continue;

                if (!pde.u.Hard.Valid)
                    continue;

                if (!(pde.u.Hard.LargePage)) {
                    MMPTE pte{};
                    if (!NT_SUCCESS(strong::read_physical((pde.u.Hard.PageFrameNumber << 12) + 8 * virt_base.pt_index, &pte, 8, &read_size)) || read_size != 8)
                        continue;

                    if (!pte.u.Hard.Valid)
                        continue;
                }

                result = current_phys_address;
                goto cleanup;
            }
        }

cleanup:
        ExFreePool(ranges);

        return result;
    }
}
