#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

namespace device_names {

    inline wchar_t g_device_name[80] = L"\\Device\\slopdrvr";
    inline wchar_t g_symlink_name[80] = L"\\DosDevices\\Global\\slopdrvr";

    __forceinline BOOLEAN initialize_names() {
        return TRUE;
    }

    __forceinline const wchar_t* get_device_name() {
        return g_device_name;
    }

    __forceinline const wchar_t* get_symlink_name() {
        return g_symlink_name;
    }

}

namespace service_identity {

    // Full registry service path ("\Registry\Machine\...\Services\<name>")
    // captured at DriverEntry so a client can NtUnloadDriver the exact
    // randomized key the mapper created — no filename guessing, no
    // enumeration. 260 wide chars covers any realistic key length.
    inline wchar_t g_service_path[260] = L"";
    inline volatile LONG g_captured = 0;

    __forceinline void capture(PUNICODE_STRING registry_path) {
        if (!registry_path || !registry_path->Buffer ||
            registry_path->Length == 0 ||
            registry_path->Length >= sizeof(g_service_path)) {
            return;
        }
        ULONG i = 0;
        for (; i < registry_path->Length / sizeof(WCHAR); ++i) {
            g_service_path[i] = registry_path->Buffer[i];
        }
        g_service_path[i] = L'\0';
        _InterlockedExchange(&g_captured, 1);
    }

    __forceinline const wchar_t* get() {
        return g_service_path;
    }

    __forceinline BOOLEAN is_captured() {
        return _InterlockedCompareExchange(&g_captured, 0, 0) ? TRUE : FALSE;
    }

}

namespace caller_validation {

    // Registered-client tracking is REFERENCE COUNTED per open device
    // handle. The old single-slot registry let one handle's close wipe the
    // client status of every other live handle from the same pid: open A,
    // open B, close B, and A's subsequent IOCTLs lost the registered-client
    // bypass (the sandbox gate then denied a client that was still
    // attached). CREATE bumps the refcount, CLOSE drops it, the pid stays
    // registered while any handle remains.
    inline volatile HANDLE g_registered_client_pid = nullptr;
    inline volatile LONG g_client_handle_refs = 0;

    __forceinline BOOLEAN register_client() {
        HANDLE pid = PsGetCurrentProcessId();
        _InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), pid);
        const LONG refs = _InterlockedIncrement(&g_client_handle_refs);
        SD_LOG("CLIENT_REGISTER pid=%llu refs=%ld",
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)), refs);
        return TRUE;
    }

    __forceinline void unregister_client() {
        const LONG refs = _InterlockedDecrement(&g_client_handle_refs);
        if (refs <= 0) {
            _InterlockedExchange(&g_client_handle_refs, 0);
            HANDLE prev = reinterpret_cast<HANDLE>(_InterlockedExchangePointer(
                reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), nullptr));
            if (prev != nullptr) {
                SD_LOG("CLIENT_UNREGISTER pid=%llu refs=0",
                    static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(prev)));
            }
        } else {
            SD_LOG("CLIENT_CLOSE_KEEP pid=%llu refs=%ld",
                static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
                refs);
        }
    }

    __forceinline BOOLEAN is_registered_client(HANDLE pid) {
        return pid != nullptr && pid == g_registered_client_pid &&
               _InterlockedCompareExchange(&g_client_handle_refs, 0, 0) > 0;
    }
}
