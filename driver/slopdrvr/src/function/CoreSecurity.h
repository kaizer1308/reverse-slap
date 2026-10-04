#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "../stealth_config.h"

#ifndef YieldProcessor
#define YieldProcessor() _mm_pause()
#endif

#ifndef KeMemoryBarrier
#define KeMemoryBarrier() _ReadWriteBarrier()
#endif

namespace device_names {

    inline wchar_t g_device_name[80] = {};
    inline wchar_t g_symlink_name[80] = {};

    __forceinline BOOLEAN initialize_names() {
        const char* leaf = slop_stealth::kDeviceLeafHex;
        wchar_t* dev = g_device_name;
        wchar_t* sym = g_symlink_name;

        const wchar_t dev_prefix[] = L"\\Device\\";
        const wchar_t sym_prefix[] = L"\\DosDevices\\Global\\";
        for (const wchar_t* p = dev_prefix; *p; ++p) *dev++ = *p;
        for (const wchar_t* p = sym_prefix; *p; ++p) *sym++ = *p;
        for (int i = 0; i < 12 && leaf[i]; ++i) {
            *dev++ = static_cast<wchar_t>(leaf[i]);
            *sym++ = static_cast<wchar_t>(leaf[i]);
        }
        *dev = L'\0';
        *sym = L'\0';
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
    inline volatile LONG g_client_handle_refs = 0;
    inline volatile LONG g_authenticated = 0;
    inline volatile UINT64 g_boot_nonce = 0;
    inline volatile LONG g_nonce_init = 0;

    __forceinline UINT64 boot_nonce() {
        if (_InterlockedCompareExchange(&g_nonce_init, 0, 0) == 0) {
            LARGE_INTEGER perf = {};
            KeQuerySystemTime(&perf);
            UINT64 seed = static_cast<UINT64>(perf.QuadPart)
                ^ (static_cast<UINT64>(__rdtsc()) << 1)
                ^ static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId()));
            UINT64 nonce = slop_stealth::mix64(seed);
            if (nonce == 0) nonce = 0x9E3779B97F4A7C15ull;
            _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_boot_nonce),
                static_cast<LONG64>(nonce));
            _InterlockedExchange(&g_nonce_init, 1);
        }
        return g_boot_nonce;
    }

    __forceinline UINT64 expected_response(HANDLE pid) {
        return slop_stealth::auth_response(
            boot_nonce(),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)));
    }

    __forceinline BOOLEAN register_client() {
        HANDLE pid = PsGetCurrentProcessId();
        _InterlockedExchangePointer(
            reinterpret_cast<volatile PVOID*>(&g_registered_client_pid), pid);
        const LONG refs = _InterlockedIncrement(&g_client_handle_refs);
        _InterlockedExchange(&g_authenticated, 0);
        SD_LOG("CLIENT_REGISTER pid=%llu refs=%ld nonce=0x%llx",
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(pid)), refs,
            static_cast<unsigned long long>(boot_nonce()));
        return TRUE;
    }

    __forceinline void unregister_client() {
        const LONG refs = _InterlockedDecrement(&g_client_handle_refs);
        if (refs <= 0) {
            _InterlockedExchange(&g_client_handle_refs, 0);
            _InterlockedExchange(&g_authenticated, 0);
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

    __forceinline BOOLEAN is_authenticated() {
        return _InterlockedCompareExchange(&g_authenticated, 0, 0) != 0;
    }

    __forceinline BOOLEAN verify_response(HANDLE pid, UINT64 response) {
        if (pid == nullptr) return FALSE;
        if (response != expected_response(pid)) return FALSE;
        _InterlockedExchange(&g_authenticated, 1);
        return TRUE;
    }
}
