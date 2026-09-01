#include "core/runtime/privilege.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace slop::core::runtime::privilege {

namespace {

bool set_privilege(const wchar_t* name, bool enable) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return false;
    }

    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    if (!LookupPrivilegeValueW(nullptr, name, &tp.Privileges[0].Luid)) {
        CloseHandle(token);
        return false;
    }

    BOOL ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    DWORD err = GetLastError();
    CloseHandle(token);

    return ok && (err == ERROR_SUCCESS);
}

bool check_privilege(const wchar_t* name) {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return false;
    }

    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) {
        CloseHandle(token);
        return false;
    }

    PRIVILEGE_SET ps{};
    ps.PrivilegeCount = 1;
    ps.Privilege[0].Luid = luid;
    ps.Privilege[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL result = FALSE;
    PrivilegeCheck(token, &ps, &result);
    CloseHandle(token);

    return result != FALSE;
}

} // namespace

bool enable_debug() {
    return set_privilege(SE_DEBUG_NAME, true);
}

bool has_debug() {
    return check_privilege(SE_DEBUG_NAME);
}

} // namespace slop::core::runtime::privilege
