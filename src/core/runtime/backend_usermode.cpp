// src/core/runtime/backend_usermode.cpp
// the plain win32 backend, openprocess and friends

#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/context.hpp"

#include <tlhelp32.h>

#include <psapi.h>

#include "core/infra/limits.hpp"

namespace slop::core::runtime {

namespace infra = slop::core::infra;

namespace {

constexpr DWORD kProcAccess = PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION |
                              PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                              PROCESS_SUSPEND_RESUME | PROCESS_CREATE_THREAD | SYNCHRONIZE;

// rpm handles cross page reads, bytes reports the partial count
io_result_t rpm(HANDLE h, uintptr_t addr, void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    SIZE_T got = 0;
    const BOOL ok = ReadProcessMemory(h, reinterpret_cast<LPCVOID>(addr), buf,
                                      static_cast<SIZE_T>(len), &got);
    r.bytes = static_cast<size_t>(got);
    r.ok    = ok != FALSE && got == len;
    if (!r.ok) r.error = GetLastError();
    return r;
}

io_result_t wpm(HANDLE h, uintptr_t addr, const void* buf, size_t len) {
    io_result_t r;
    if (len == 0) { r.ok = true; return r; }
    SIZE_T put = 0;
    const BOOL ok = WriteProcessMemory(h, reinterpret_cast<LPVOID>(addr), buf,
                                       static_cast<SIZE_T>(len), &put);
    r.bytes = static_cast<size_t>(put);
    r.ok    = ok != FALSE && put == len;
    if (!r.ok) r.error = GetLastError();
    return r;
}

arch_t detect_arch(HANDLE h) {
    BOOL wow64 = FALSE;
    if (IsWow64Process(h, &wow64))
        return wow64 ? arch_t::x86 : arch_t::x64;
    return arch_t::unknown;
}

elevation_t detect_elevation(uint32_t pid) {
    elevation_t e = elevation_t::unknown;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return e;
    HANDLE tok = nullptr;
    if (OpenProcessToken(h, TOKEN_QUERY, &tok)) {
        DWORD ret = 0;
        TOKEN_ELEVATION elev{};
        if (GetTokenInformation(tok, TokenElevation, &elev, sizeof(elev), &ret)) {
            // elevation flag only, the admin vs system split is overkill for now
            e = elev.TokenIsElevated ? elevation_t::elevated : elevation_t::standard;
        }
        CloseHandle(tok);
    }
    CloseHandle(h);
    return e;
}

std::string nt_path_to_dos(const std::string& path) {
    // toolhelp hands back device paths sometimes, map them best effort
    char drives[512]{};
    const DWORD len = GetLogicalDriveStringsA(sizeof(drives) - 1, drives);
    if (len == 0 || len >= sizeof(drives)) return path;

    std::string dos_path = path;
    for (size_t i = 0; i < len; i += 4) {
        const char letter = drives[i];
        if (!letter) break;

        char dev[64] = {};
        const std::string dos_prefix = std::string(1, letter) + ":";
        if (QueryDosDeviceA(dos_prefix.c_str(), dev, 63) == 0) continue;

        const size_t dlen = std::string(dev).size();
        if (_strnicmp(path.c_str(), dev, dlen) == 0 &&
            (path.size() > dlen && path[dlen] == '\\')) {
            dos_path = std::string(1, letter) + ":" + path.substr(dlen);
            break;
        }
    }
    return dos_path;
}

} // namespace

// identity

backend_kind_t backend_usermode_t::kind() const noexcept {
    return backend_kind_t::user_mode;
}

const char* backend_usermode_t::badge() const noexcept {
    return "user";
}

// attach and detach

target_handle_t backend_usermode_t::attach(uint32_t pid) {
    target_handle_t t;
    t.pid    = pid;
    t.native = OpenProcess(kProcAccess, FALSE, pid);
    if (!t.native) t.native = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    return t;
}

void backend_usermode_t::detach(target_handle_t& h) {
    if (h.native) CloseHandle(static_cast<HANDLE>(h.native));
    h.native = nullptr;
    h.pid    = 0;
}

// memory

io_result_t backend_usermode_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                            void* buf, size_t len) {
    if (!h.valid()) return { false, 0, ERROR_INVALID_HANDLE };
    return rpm(static_cast<HANDLE>(h.native), addr, buf, len);
}

io_result_t backend_usermode_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                             const void* buf, size_t len) {
    if (!h.valid()) return { false, 0, ERROR_INVALID_HANDLE };
    return wpm(static_cast<HANDLE>(h.native), addr, buf, len);
}

io_result_t backend_usermode_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                               size_t len, uint32_t new_prot, uint32_t* old_prot) {
    if (!h.valid()) return { false, 0, ERROR_INVALID_HANDLE };
    DWORD old = 0;
    const BOOL ok = VirtualProtectEx(static_cast<HANDLE>(h.native),
                                     reinterpret_cast<LPVOID>(addr),
                                     static_cast<SIZE_T>(len),
                                     static_cast<DWORD>(new_prot), &old);
    if (!ok) return { false, 0, GetLastError() };
    if (old_prot) *old_prot = old;
    return { true, len, 0 };
}

io_result_t backend_usermode_t::allocate_memory(const target_handle_t& h, uintptr_t addr,
                                                size_t len, uint32_t prot, uintptr_t* out_addr) {
    if (!h.valid()) return { false, 0, ERROR_INVALID_HANDLE };
    LPVOID p = VirtualAllocEx(static_cast<HANDLE>(h.native),
                              reinterpret_cast<LPVOID>(addr),
                              static_cast<SIZE_T>(len),
                              MEM_RESERVE | MEM_COMMIT, static_cast<DWORD>(prot));
    if (!p) return { false, 0, GetLastError() };
    if (out_addr) *out_addr = reinterpret_cast<uintptr_t>(p);
    return { true, len, 0 };
}

io_result_t backend_usermode_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    if (!h.valid()) return { false, 0, ERROR_INVALID_HANDLE };
    const BOOL ok = VirtualFreeEx(static_cast<HANDLE>(h.native),
                                  reinterpret_cast<LPVOID>(addr), 0, MEM_RELEASE);
    return ok ? io_result_t{ true, 0, 0 } : io_result_t{ false, 0, GetLastError() };
}

// enumeration

enum_result_t<process_info_t> backend_usermode_t::enum_processes() {
    enum_result_t<process_info_t> r;
    r.ok = true;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        r.ok    = false;
        r.error = GetLastError();
        return r;
    }

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            process_info_t pi;
            pi.pid        = pe.th32ProcessID;
            pi.parent_pid = pe.th32ParentProcessID;

            wchar_t exe[MAX_PATH]{};
            wcsncpy_s(exe, pe.szExeFile, _TRUNCATE);
            char narrow[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, exe, -1, narrow, MAX_PATH, nullptr, nullptr);
            pi.name = narrow;

            // arch and elevation probes are per pid syscalls, keep them cheap
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pi.pid);
            if (h) {
                pi.arch = detect_arch(h);
                // queryfullprocessimagename works without vm read and the handle is already open
                wchar_t image[MAX_PATH]{};
                DWORD image_len = MAX_PATH;
                if (QueryFullProcessImageNameW(h, 0, image, &image_len) && image_len > 0) {
                    char image_utf8[MAX_PATH * 2]{};
                    if (WideCharToMultiByte(CP_UTF8, 0, image, static_cast<int>(image_len),
                                            image_utf8, sizeof(image_utf8) - 1,
                                            nullptr, nullptr) > 0)
                        pi.path = image_utf8;
                }
                CloseHandle(h);
            }
            pi.elevation = detect_elevation(pi.pid);

            r.items.push_back(std::move(pi));
            if (r.items.size() >= infra::limits::max_handles_enumerated) {
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return r;
}

enum_result_t<module_info_t> backend_usermode_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> r;
    if (!h.valid()) { r.error = ERROR_INVALID_HANDLE; return r; }

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                           h.pid);
    if (snap == INVALID_HANDLE_VALUE) {
        r.error = GetLastError();
        return r;
    }

    MODULEENTRY32W me{};
    me.dwSize = sizeof(me);

    if (Module32FirstW(snap, &me)) {
        do {
            module_info_t mi;
            mi.base = reinterpret_cast<uintptr_t>(me.modBaseAddr);
            mi.size = me.modBaseSize;

            char name[MAX_PATH]{}, path[MAX_PATH * 2]{};
            WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, MAX_PATH, nullptr, nullptr);
            WideCharToMultiByte(CP_UTF8, 0, me.szExePath, -1, path, MAX_PATH * 2, nullptr, nullptr);
            mi.name = name;
            mi.path = nt_path_to_dos(path);

            r.items.push_back(std::move(mi));
        } while (Module32NextW(snap, &me));
        r.ok = true;
    } else {
        r.error = GetLastError();
    }

    CloseHandle(snap);
    return r;
}

enum_result_t<thread_info_t> backend_usermode_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> r;
    r.ok = true;

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        r.ok    = false;
        r.error = GetLastError();
        return r;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    if (Thread32First(snap, &te)) {
        do {
            if (pid != 0 && te.th32OwnerProcessID != pid) continue;
            thread_info_t ti;
            ti.tid      = te.th32ThreadID;
            ti.owner_pid = te.th32OwnerProcessID;
            r.items.push_back(ti);
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return r;
}

enum_result_t<region_info_t> backend_usermode_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> r;
    if (!h.valid()) { r.error = ERROR_INVALID_HANDLE; return r; }

    r.ok = true;
    MEMORY_BASIC_INFORMATION mbi{};
    LPCVOID cursor = nullptr;

    while (VirtualQueryEx(static_cast<HANDLE>(h.native), cursor, &mbi, sizeof(mbi))) {
        region_info_t ri;
        ri.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        ri.size    = mbi.RegionSize;
        ri.protect = mbi.Protect;
        ri.state   = mbi.State;
        ri.type    = mbi.Type;
        r.items.push_back(ri);

        if (r.items.size() >= infra::limits::max_regions_enumerated) break;

        cursor = static_cast<const BYTE*>(mbi.BaseAddress) + mbi.RegionSize;
    }
    return r;
}

enum_result_t<handle_info_t> backend_usermode_t::enum_handles(uint32_t /*pid*/) {
    // handle enumeration needs ntquerysysteminformation, left for the handle table pass
    enum_result_t<handle_info_t> r;
    r.ok    = true;
    r.error = 0;
    return r;
}

// ---------------------------------------------------------------------------
// Thread context
// ---------------------------------------------------------------------------

io_result_t backend_usermode_t::get_thread_context(uint32_t tid, thread_context_t& ctx) {
    HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!th) return { false, 0, GetLastError() };

    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    const BOOL ok = GetThreadContext(th, &c);
    CloseHandle(th);

    if (!ok) return { false, 0, GetLastError() };
    context_from_win(ctx, c);
    return { true, 0, 0 };
}

io_result_t backend_usermode_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    HANDLE th = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
    if (!th) return { false, 0, GetLastError() };

    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    context_to_win(c, ctx);
    const BOOL ok = SetThreadContext(th, &c);
    CloseHandle(th);

    return ok ? io_result_t{ true, 0, 0 } : io_result_t{ false, 0, GetLastError() };
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

arch_t backend_usermode_t::query_arch(const target_handle_t& h) {
    if (!h.valid()) return arch_t::unknown;
    return detect_arch(static_cast<HANDLE>(h.native));
}

elevation_t backend_usermode_t::query_elevation() {
    return detect_elevation(GetCurrentProcessId());
}

} // namespace slop::core::runtime
