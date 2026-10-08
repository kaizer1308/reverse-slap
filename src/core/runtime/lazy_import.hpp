// src/core/runtime/lazy_import.hpp
// Runtime-resolved Win32 imports. Every API wrapped here disappears from
// the PE import table (IAT). Anti-cheats scan IAT for ReadProcessMemory,
// WriteProcessMemory, OpenProcess, CreateRemoteThread, VirtualAllocEx etc.
// By resolving at runtime via GetProcAddress (which itself is resolved from
// the PEB InLoadOrderModuleList → kernel32 export table), none of these
// names appear in our .idata section.
//
// Usage: lazy::ReadProcessMemory(hProcess, addr, buf, len, &read);
//   — identical signature to the Win32 API, resolved on first call.

#pragma once

#include <windows.h>
#include <cstdint>

namespace slop::core::runtime::lazy {

namespace detail {

// resolve a module handle from PEB without calling GetModuleHandle (which
// itself might be hooked). walks InLoadOrderModuleList.
inline HMODULE peb_module(const wchar_t* name) noexcept {
#if defined(_M_X64) || defined(__x86_64__)
    auto* peb = reinterpret_cast<const unsigned char*>(__readgsqword(0x60));
#else
    auto* peb = reinterpret_cast<const unsigned char*>(__readfsdword(0x30));
#endif
    auto* ldr = *reinterpret_cast<const unsigned char* const*>(peb + 0x18);
    auto* head = reinterpret_cast<const unsigned char*>(ldr + 0x10); // InLoadOrderModuleList
    auto* entry = *reinterpret_cast<const unsigned char* const*>(head);

    while (entry != head) {
        // LDR_DATA_TABLE_ENTRY: BaseDllName at +0x58 (x64), FullDllName at +0x48
        auto* base_name = *reinterpret_cast<const wchar_t* const*>(entry + 0x60);
        auto* dll_base = *reinterpret_cast<HMODULE const*>(entry + 0x30);

        if (base_name) {
            // case-insensitive compare
            bool match = true;
            for (int i = 0; name[i]; ++i) {
                wchar_t a = base_name[i], b = name[i];
                if (a >= L'A' && a <= L'Z') a += 32;
                if (b >= L'A' && b <= L'Z') b += 32;
                if (a != b) { match = false; break; }
            }
            if (match) return dll_base;
        }
        entry = *reinterpret_cast<const unsigned char* const*>(entry);
    }
    return nullptr;
}

// resolve an export by walking the PE export directory manually
inline void* manual_export(HMODULE mod, const char* name) noexcept {
    if (!mod || !name) return nullptr;
    auto* base = reinterpret_cast<const unsigned char*>(mod);
    auto e_lfanew = *reinterpret_cast<const int32_t*>(base + 0x3C);
    auto* nt = base + e_lfanew;
    // optional header: export dir RVA at +0x70 (x64) from NT headers
    auto export_rva = *reinterpret_cast<const uint32_t*>(nt + 0x18 + 0x70);
    if (!export_rva) return nullptr;

    auto* dir = base + export_rva;
    auto num_names = *reinterpret_cast<const uint32_t*>(dir + 0x18);
    auto names_rva = *reinterpret_cast<const uint32_t*>(dir + 0x20);
    auto ords_rva  = *reinterpret_cast<const uint32_t*>(dir + 0x24);
    auto funcs_rva = *reinterpret_cast<const uint32_t*>(dir + 0x1C);

    auto* names = reinterpret_cast<const uint32_t*>(base + names_rva);
    auto* ords  = reinterpret_cast<const uint16_t*>(base + ords_rva);
    auto* funcs = reinterpret_cast<const uint32_t*>(base + funcs_rva);

    for (uint32_t i = 0; i < num_names; ++i) {
        auto* fn_name = reinterpret_cast<const char*>(base + names[i]);
        // strcmp inline
        const char* a = fn_name;
        const char* b = name;
        while (*a && *a == *b) { ++a; ++b; }
        if (*a == *b) {
            return const_cast<unsigned char*>(base) + funcs[ords[i]];
        }
    }
    return nullptr;
}

template <typename Fn>
struct lazy_fn {
    Fn ptr = nullptr;
    const wchar_t* mod_name;
    const char* fn_name;

    Fn get() noexcept {
        if (!ptr) {
            HMODULE m = peb_module(mod_name);
            if (m) ptr = reinterpret_cast<Fn>(manual_export(m, fn_name));
        }
        return ptr;
    }
};

} // namespace detail

// macro to declare a lazy import
#define LAZY_IMPORT(mod, ret, name, ...) \
    inline ret name(__VA_ARGS__) {       \
        using fn_t = ret(WINAPI*)(__VA_ARGS__); \
        static detail::lazy_fn<fn_t> _lazy{nullptr, L ## mod, #name}; \
        auto f = _lazy.get();            \
        if (!f) return ret{};            \
        return f(__VA_ARGS__);           \
    }

// We can't use the macro directly because the parameter forwarding is complex.
// Instead, define each function explicitly with proper parameter names.

// ── kernel32.dll ──

using ReadProcessMemory_t = BOOL(WINAPI*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
using WriteProcessMemory_t = BOOL(WINAPI*)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
using VirtualAllocEx_t = LPVOID(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
using VirtualFreeEx_t = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD);
using VirtualProtectEx_t = BOOL(WINAPI*)(HANDLE, LPVOID, SIZE_T, DWORD, PDWORD);
using VirtualQueryEx_t = SIZE_T(WINAPI*)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
using OpenProcess_t = HANDLE(WINAPI*)(DWORD, BOOL, DWORD);
using CreateRemoteThread_t = HANDLE(WINAPI*)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                              LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
using CreateToolhelp32Snapshot_t = HANDLE(WINAPI*)(DWORD, DWORD);

// ── ntdll.dll ──

using NtReadVirtualMemory_t = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtWriteVirtualMemory_t = LONG(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
using NtQuerySystemInformation_t = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationProcess_t = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

#define LAZY_K32(type, name) \
    inline type resolve_##name() noexcept { \
        static detail::lazy_fn<type> _fn{nullptr, L"kernel32.dll", #name}; \
        return _fn.get(); \
    }

#define LAZY_NTDLL(type, name) \
    inline type resolve_##name() noexcept { \
        static detail::lazy_fn<type> _fn{nullptr, L"ntdll.dll", #name}; \
        return _fn.get(); \
    }

LAZY_K32(ReadProcessMemory_t, ReadProcessMemory)
LAZY_K32(WriteProcessMemory_t, WriteProcessMemory)
LAZY_K32(VirtualAllocEx_t, VirtualAllocEx)
LAZY_K32(VirtualFreeEx_t, VirtualFreeEx)
LAZY_K32(VirtualProtectEx_t, VirtualProtectEx)
LAZY_K32(VirtualQueryEx_t, VirtualQueryEx)
LAZY_K32(OpenProcess_t, OpenProcess)
LAZY_K32(CreateRemoteThread_t, CreateRemoteThread)
LAZY_K32(CreateToolhelp32Snapshot_t, CreateToolhelp32Snapshot)

LAZY_NTDLL(NtReadVirtualMemory_t, NtReadVirtualMemory)
LAZY_NTDLL(NtWriteVirtualMemory_t, NtWriteVirtualMemory)
LAZY_NTDLL(NtQuerySystemInformation_t, NtQuerySystemInformation)
LAZY_NTDLL(NtQueryInformationProcess_t, NtQueryInformationProcess)

#undef LAZY_K32
#undef LAZY_NTDLL

} // namespace slop::core::runtime::lazy
