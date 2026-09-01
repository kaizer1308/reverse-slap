#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"

#define KPROCESS_DIRECTORYTABLEBASE_OFFSET 0x28

namespace dtb_guard {
    inline volatile ULONG g_dtb_entropy = 0xDEADBEEFu;

    __forceinline void timing_scatter() {
        ULONG x = g_dtb_entropy ^ (ULONG)(__rdtsc() & 0xFFFFFFFFu);
        x ^= x << 13;
        g_dtb_entropy = x;
        volatile ULONG spin = (x & 0x3) + 1;
        while (spin--) YieldProcessor();
    }

    __forceinline BOOLEAN is_valid_target_pid(UINT32 pid) {
        if (pid == 0) return FALSE;
        return TRUE;
    }

    __forceinline BOOLEAN is_valid_dtb(UINT64 dtb) {
        UINT64 pfn = (dtb >> 12) & 0xFFFFFFFFFULL;
        if (pfn == 0) return FALSE;
        if (pfn > 0x1000000) return FALSE;

        if ((dtb & 0x000FFFFFFFFFF000ULL) == 0) return FALSE;

        return TRUE;
    }
}

NTSTATUS functions::handle777d(p_dtb_solve request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!dtb_guard::is_valid_target_pid(request->pid)) {
        return STATUS_ACCESS_DENIED;
    }

    dtb_guard::timing_scatter();

    UINT64 cached_dtb = 0;
    if (LookupDTBCache(request->pid, &cached_dtb)) {
        // Pids get reused — validate the cache against the live EPROCESS
        // before serving, otherwise a recycled pid yields a dead process's
        // DTB (reads limp along on the fallback path, writes fail-closed).
        PEPROCESS live_process = nullptr;
        NTSTATUS lookup_status = _PsLookupProcessByProcessId
            ? _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &live_process)
            : STATUS_NOT_SUPPORTED;
        if (NT_SUCCESS(lookup_status) && live_process) {
            UINT64 live_dtb = 0;
            __try {
                live_dtb = *(UINT64*)((UCHAR*)live_process + KPROCESS_DIRECTORYTABLEBASE_OFFSET);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                live_dtb = 0;
            }
            if (_ObfDereferenceObject) _ObfDereferenceObject(live_process);

            if ((live_dtb & 0x000FFFFFFFFFF000ULL) == cached_dtb) {
                request->dtb = cached_dtb;
                dtb_guard::timing_scatter();
                return STATUS_SUCCESS;
            }
            SD_LOG("DTB_CACHE_STALE pid=%u cached=0x%llX live=0x%llX - invalidating",
                request->pid,
                static_cast<UINT64>(cached_dtb),
                static_cast<UINT64>(live_dtb & 0x000FFFFFFFFFF000ULL));
        }
        InvalidateDTBCache(request->pid);
    }
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    PEPROCESS process = nullptr;

    status = _PsLookupProcessByProcessId ? _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process) : STATUS_NOT_SUPPORTED;
    if (!NT_SUCCESS(status) || !process) {
        SD_LOG("DTB_RESOLVE_FAIL pid=%u status=0x%08X reason=PsLookupProcessByProcessId_failed", request->pid, static_cast<ULONG>(status));
        return status;
    }

    UINT64 dir_base = 0;

    __try {
        dir_base = *(UINT64*)((UCHAR*)process + KPROCESS_DIRECTORYTABLEBASE_OFFSET);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        SD_LOG("DTB_RESOLVE_FAIL pid=%u status=STATUS_ACCESS_VIOLATION reason=dir_base_read_exception offset=0x%llX", request->pid, static_cast<unsigned long long>(KPROCESS_DIRECTORYTABLEBASE_OFFSET));
        if (_ObfDereferenceObject) _ObfDereferenceObject(process);
        return STATUS_ACCESS_VIOLATION;
    }

    if (_ObfDereferenceObject) _ObfDereferenceObject(process);

    if (dir_base != 0 && dtb_guard::is_valid_dtb(dir_base)) {
        request->dtb = dir_base & 0x000FFFFFFFFFF000ULL;

        InsertDTBCache(request->pid, request->dtb);
        SD_LOG("DTB_RESOLVE_OK pid=%u dtb=0x%llX raw_dir_base=0x%llX", request->pid, static_cast<unsigned long long>(request->dtb), static_cast<unsigned long long>(dir_base));
        status = STATUS_SUCCESS;
    } else {
        request->dtb = 0;
        SD_LOG("DTB_RESOLVE_FAIL pid=%u status=STATUS_UNSUCCESSFUL reason=invalid_dtb raw_dir_base=0x%llX", request->pid, static_cast<unsigned long long>(dir_base));
        status = STATUS_UNSUCCESSFUL;
    }

    return status;
}
