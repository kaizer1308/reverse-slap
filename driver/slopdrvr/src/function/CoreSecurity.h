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

    inline volatile HANDLE g_registered_client_pid = nullptr;

    __forceinline BOOLEAN register_client() {
        HANDLE pid = PsGetCurrentProcessId();
        _InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), pid);
        SD_LOG("CLIENT_REGISTER pid=%llu",
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)));
        return TRUE;
    }

    __forceinline void unregister_client() {
        HANDLE prev = reinterpret_cast<HANDLE>(_InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), nullptr));
        if (prev != nullptr) {
            SD_LOG("CLIENT_UNREGISTER pid=%llu",
                static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(prev)));
        }
    }

    __forceinline BOOLEAN is_registered_client(HANDLE pid) {
        return pid != nullptr && pid == g_registered_client_pid;
    }
}
