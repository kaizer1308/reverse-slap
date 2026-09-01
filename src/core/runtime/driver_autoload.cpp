// src/core/runtime/driver_autoload.cpp

#include "core/runtime/driver_autoload.hpp"

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/voyager_comm.h"

#include <windows.h>
#include <winternl.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cwchar>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace slop::core::runtime::driver_autoload {

namespace {

bool file_exists(const std::string& p) {
    DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

std::string parent_dir(const std::string& dir) {
    const size_t slash = dir.find_last_of("\\/");
    if (slash == std::string::npos) return {};
    return dir.substr(0, slash);
}

std::string read_tail(const std::string& path, size_t max_bytes) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    f.seekg(0, std::ios::end);
    const std::streamoff size = static_cast<std::streamoff>(f.tellg());
    if (size <= 0) return {};
    const std::streamoff start =
        size > static_cast<std::streamoff>(max_bytes)
            ? size - static_cast<std::streamoff>(max_bytes)
            : 0;
    f.seekg(start);
    const auto span = static_cast<size_t>(size - start);
    std::string out(span, '\0');
    f.read(out.data(), static_cast<std::streamsize>(out.size()));
    const size_t first_nl = out.find('\n');
    if (first_nl != std::string::npos && first_nl + 1 < out.size())
        out = out.substr(first_nl + 1);
    return out;
}

// ntunloaddriver needs the privilege, enabled here on demand
long live_unload_service(const std::wstring& service_path) {
    using nt_unload_driver_fn = long (NTAPI*)(PUNICODE_STRING);
    static auto nt_unload_driver = reinterpret_cast<nt_unload_driver_fn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtUnloadDriver"));
    if (!nt_unload_driver) return -1;

    // Enable SeLoadDriverPrivilege (once per process)
    static const bool privilege_ready = [] {
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(),
                              TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tok))
            return false;
        LUID luid{};
        if (!LookupPrivilegeValueW(nullptr, L"SeLoadDriverPrivilege", &luid)) {
            CloseHandle(tok);
            return false;
        }
        TOKEN_PRIVILEGES tp{};
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        const BOOL ok = AdjustTokenPrivileges(tok, FALSE, &tp, 0, nullptr,
                                              nullptr);
        CloseHandle(tok);
        return ok && GetLastError() == ERROR_SUCCESS;
    }();
    if (!privilege_ready) return -2;

    UNICODE_STRING us{};
    us.Buffer = const_cast<PWSTR>(service_path.c_str());
    us.Length = static_cast<USHORT>(service_path.size() * sizeof(wchar_t));
    us.MaximumLength = us.Length;
    return nt_unload_driver(&us);
}

// delete the service key so the registry does not pile up
void delete_service_key(const std::wstring& service_path) {
    // translate to an hklm relative subkey for the recursive delete
    constexpr const wchar_t* kRegPrefix = L"\\Registry\\Machine\\";
    std::wstring subkey;
    if (service_path.rfind(kRegPrefix, 0) == 0) {
        subkey = service_path.substr(wcslen(kRegPrefix));
    } else if (service_path.rfind(L"\\Registry\\", 0) == 0) {
        return;   // unexpected registry root, do not guess
    } else {
        subkey = service_path;
    }
    HMODULE advapi = GetModuleHandleW(L"advapi32.dll");
    if (!advapi) return;
    using sh_delete_key_fn = LONG (WINAPI*)(HKEY, LPCWSTR);
    auto sh_delete_key = reinterpret_cast<sh_delete_key_fn>(
        GetProcAddress(advapi, "SHDeleteKeyW"));
    if (sh_delete_key)
        sh_delete_key(HKEY_LOCAL_MACHINE, subkey.c_str());
}

// a force killed session leaves the driver quiesced, ident is the one ioctl still honored so use it to recover
bool recover_quiesced_driver() {
    voyager::device_t dev;
    if (!dev.connect()) return false;

    voyager::device_t::driver_identity ident{};
    if (!dev.query_driver_identity(ident)) return false;
    if (!ident.unloading) return false;   // healthy driver, nothing to do

    const std::wstring ident_path = std::move(ident.service_path);
    // the handle must close before ntunloaddriver can finish
    dev.arm_shutdown();
    dev.disconnect();

    // candidate keys are the ident path plus anything pointing into our runtime dir
    std::vector<std::wstring> keys;
    if (!ident_path.empty()) keys.push_back(ident_path);

    HKEY services = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                      L"SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_ENUMERATE_SUB_KEYS | KEY_QUERY_VALUE,
                      &services) == ERROR_SUCCESS) {
        wchar_t name[256];
        for (DWORD i = 0;; ++i) {
            DWORD name_len = 256;
            const LONG rc = RegEnumKeyExW(services, i, name, &name_len,
                                          nullptr, nullptr, nullptr, nullptr);
            if (rc == ERROR_NO_MORE_ITEMS) break;
            if (rc != ERROR_SUCCESS) continue;
            HKEY sub = nullptr;
            if (RegOpenKeyExW(services, name, 0, KEY_QUERY_VALUE, &sub)
                    != ERROR_SUCCESS)
                continue;
            wchar_t image[1024]{};
            DWORD type = 0, size = sizeof(image) - sizeof(wchar_t);
            std::wstring key;
            if (RegQueryValueExW(sub, L"ImagePath", nullptr, &type,
                                 reinterpret_cast<LPBYTE>(image), &size)
                    == ERROR_SUCCESS) {
                const std::wstring img(image);
                // Mapper-loaded copies live under
                // %LOCALAPPDATA%\reverse-slop\DriverRuntime\<random>.sys
                if (img.find(L"reverse-slop\\DriverRuntime") !=
                        std::wstring::npos ||
                    img.find(L"reverse-slop/DriverRuntime") !=
                        std::wstring::npos) {
                    key = L"\\Registry\\Machine\\System\\CurrentControlSet"
                          L"\\Services\\" + std::wstring(name);
                }
            }
            RegCloseKey(sub);
            if (!key.empty()) keys.push_back(std::move(key));
        }
        RegCloseKey(services);
    }

    bool unloaded_any = false;
    for (const auto& key : keys) {
        const long status = live_unload_service(key);
        // 0 = unloaded now; C0000034 = no driver on that key (stale entry)
        if (status == 0 || status == 0xC0000034L) {
            delete_service_key(key);
            if (status == 0) unloaded_any = true;
        }
    }
    return unloaded_any;
}

} // namespace

artifact_paths_t find_artifacts(const std::string& exe_dir) {
    artifact_paths_t out;
    if (exe_dir.empty()) return out;

    std::vector<std::string> mapper_dirs = {exe_dir};
    std::vector<std::string> sys_dirs    = {exe_dir};

    // build tree layout is two levels up, the exe dir covers side by side packaging
    const std::string p1 = parent_dir(exe_dir);
    const std::string p2 = parent_dir(p1);
    for (const std::string& base : {p1, p2}) {
        if (base.empty() || base == exe_dir) continue;
        mapper_dirs.push_back(base + "\\mapper");
        sys_dirs.push_back(base + "\\driver");
        mapper_dirs.push_back(exe_dir + "\\mapper");
        sys_dirs.push_back(exe_dir + "\\driver");
    }

    for (const auto& d : mapper_dirs) {
        const std::string cand = d + "\\slop_mapper.exe";
        if (file_exists(cand)) { out.mapper_exe = cand; out.mapper_found = true; break; }
    }
    for (const auto& d : sys_dirs) {
        const std::string cand = d + "\\slopdrvr.sys";
        if (file_exists(cand)) { out.driver_sys = cand; out.sys_found = true; break; }
    }
    return out;
}

bool device_present() {
    HANDLE h = CreateFileA("\\\\.\\slopdrvr", 0,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, 0, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

load_report_t ensure_loaded_with(bool artifacts_available,
                                 const std::string& mapper_exe,
                                 const std::string& sys_path,
                                 const std::function<bool()>& probe,
                                 const spawn_fn& spawn) {
    load_report_t rep;
    if (probe()) {
        rep.was_loaded = true;
        rep.ok = true;
        return rep;
    }
    if (!artifacts_available) {
        rep.error = "slop_mapper.exe / slopdrvr.sys not found next to "
                    "reverse-slop.exe, driver stays unloaded";
        return rep;
    }

    rep.attempted = true;
    std::string tail;
    int code = spawn(mapper_exe, sys_path, &tail);
    if (code != 0) {
        rep.error = "mapper exit code " +
                    (code < 0 ? std::string("spawn-failure")
                              : std::to_string(code));
        rep.log_tail = tail;
        return rep;
    }
    if (!probe()) {
        rep.error = "device \\\\.\\slopdrvr still absent after mapper run "
                    "(old build may be resident until reverse-slop exits)";
        return rep;
    }
    rep.log_tail = tail;
    rep.ok = true;
    return rep;
}

load_report_t ensure_loaded(const std::string& exe_dir,
                            const std::function<bool()>& probe,
                            const spawn_fn& spawn) {
    const artifact_paths_t art = find_artifacts(exe_dir);
    return ensure_loaded_with(art.complete(), art.mapper_exe, art.driver_sys,
                              probe, spawn);
}

load_report_t ensure_loaded_real(const std::string& exe_dir) {
    return ensure_loaded(
        exe_dir,
        [] {
            if (!device_present()) return false;
            // force killed session, recover and let the mapper load fresh
            if (recover_quiesced_driver()) return false;
            return true;
        },
        [](const std::string& mapper_exe, const std::string& sys_path,
           std::string* log_tail) -> int {
            // Per-launch mapper log beside the mapper executable
            const size_t slash = mapper_exe.find_last_of("\\/");
            std::string log_path =
                slash == std::string::npos
                    ? "slop_mapper_last.log"
                    : mapper_exe.substr(0, slash) + "\\slop_mapper_last.log";

            SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
            HANDLE log_file =
                CreateFileA(log_path.c_str(), GENERIC_WRITE,
                            FILE_SHARE_READ, &sa, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, nullptr);
            SetEnvironmentVariableA("SLOP_MAPPER_LOG", log_path.c_str());

            const std::string cmd = "\"" + mapper_exe + "\" load \"" +
                                    sys_path + "\"";
            STARTUPINFOA si{};
            si.cb = sizeof(si);
            si.dwFlags = STARTF_USESTDHANDLES;
            si.hStdOutput = log_file ? log_file : GetStdHandle(STD_OUTPUT_HANDLE);
            si.hStdError  = si.hStdOutput;
            PROCESS_INFORMATION pi{};
            const BOOL created = CreateProcessA(
                nullptr, const_cast<char*>(cmd.c_str()), nullptr, nullptr,
                TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
            if (log_file) CloseHandle(log_file);
            if (!created) {
                if (log_tail)
                    *log_tail = "CreateProcess failed (error " +
                                std::to_string(GetLastError()) + ")";
                return -1;
            }
            const DWORD wait =
                WaitForSingleObject(pi.hProcess, 120000);
            DWORD exit_code = static_cast<DWORD>(-1);
            if (wait == WAIT_OBJECT_0)
                GetExitCodeProcess(pi.hProcess, &exit_code);
            else
                TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            if (log_tail) *log_tail = read_tail(log_path, 4096);
            return static_cast<int>(exit_code);
        });
}

// clean shutdown

unload_report_t request_unload_with(
    const std::function<bool()>& probe,
    const std::function<bool(std::wstring&)>& query_identity,
    const std::function<bool()>& arm_shutdown,
    const std::function<void()>& release_handles,
    const unload_service_fn& unload_service) {
    unload_report_t rep;
    if (!probe()) {
        // Nothing resident, clean by definition
        rep.ok = true;
        return rep;
    }
    rep.was_loaded = true;
    rep.attempted = true;

    std::wstring service_path;
    if (!query_identity(service_path) || service_path.empty()) {
        rep.error = "driver present but identity query failed, cannot "
                    "locate its service key (old build?); driver stays "
                    "loaded";
        return rep;
    }
    rep.service_path.resize(service_path.size() * 4, '\0');
    int written = WideCharToMultiByte(CP_UTF8, 0, service_path.c_str(),
                                      static_cast<int>(service_path.size()),
                                      rep.service_path.data(),
                                      static_cast<int>(rep.service_path.size()),
                                      nullptr, nullptr);
    rep.service_path.resize(written > 0 ? static_cast<size_t>(written) : 0);

    // Arm quiesce before touching handles: from here the driver refuses new
    // IOCTLs, so a straggler client cannot start work against the teardown
    if (!arm_shutdown()) {
        rep.error = "driver refused shutdown arm (old build?)";
        return rep;
    }
    release_handles();

    const long status = unload_service(service_path);
    if (status != 0) {
        rep.error = "NtUnloadDriver status 0x" +
                    [&] {
                        char buf[16] = "";
                        std::snprintf(buf, sizeof(buf), "%08lX",
                                      static_cast<unsigned long>(status));
                        return std::string(buf);
                    }();
        return rep;
    }
    rep.ok = true;
    return rep;
}

unload_report_t request_driver_unload() {
    // Identity query + shutdown arm go through the kernel backend's live
    // device when possible; otherwise a temporary connection is opened
    voyager::device_t temp_device;
    voyager::device_t* dev = nullptr;
    auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
    if (k && k->device() && k->device()->is_connected()) {
        dev = k->device();
    } else if (temp_device.connect()) {
        dev = &temp_device;
    }

    // Pre-quiesce hygiene: releasing the process context now frees the
    // remote-call shellcode page inside the target while the FM ioctl is
    // still legal, nothing the app allocated in another process outlives
    // this exit. (Identity + shutdown arms below never need the context.)
    if (dev && dev == (k ? k->device() : nullptr)) {
        dev->clear_process_context();
    }

    auto query_identity = [&](std::wstring& out) -> bool {
        if (!dev) return false;
        voyager::device_t::driver_identity ident{};
        if (!dev->query_driver_identity(ident)) return false;
        out = std::move(ident.service_path);
        return !out.empty();
    };
    auto arm_shutdown = [&]() -> bool {
        return dev && dev->arm_shutdown();
    };
    auto release_handles = [&]() {
        // Drop every handle the app holds on \\.\slopdrvr, NtUnloadDriver
        // only completes once the last file object on the device is gone
        if (k) {
            k->disconnect();
        }
        if (temp_device.is_connected()) {
            temp_device.disconnect();
        }
    };

    unload_report_t rep = request_unload_with(
        [] { return device_present(); }, query_identity, arm_shutdown,
        release_handles, live_unload_service);

    if (rep.ok && rep.was_loaded) {
        // Delete the (now-unloaded) service key by the captured path so
        // nothing accumulates in the registry across sessions
        std::wstring wide;
        wide.resize(rep.service_path.size());
        int n = MultiByteToWideChar(CP_UTF8, 0, rep.service_path.c_str(),
                                    static_cast<int>(rep.service_path.size()),
                                    wide.data(),
                                    static_cast<int>(wide.size()));
        wide.resize(n > 0 ? static_cast<size_t>(n) : 0);
        if (!wide.empty()) delete_service_key(wide);
    }
    return rep;
}

} // namespace slop::core::runtime::driver_autoload
