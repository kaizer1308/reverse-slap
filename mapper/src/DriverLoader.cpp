#include "Mapper.h"
#include <cstdarg>

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
static void DLDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int prefixLen = snprintf(buf, sizeof(buf), "[DriverLoader][%s] ", func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); FlushMapperLogFile(); }
}
#define DLLOG(fmt, ...) DLDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define DLLOG_STATUS(msg, st) DLDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

static ULONGLONG DLElapsedMs(ULONGLONG start) {
    ULONGLONG now = GetTickCount64();
    return now >= start ? now - start : 0;
}

static ULONG DLBuildNumber() {
    return *reinterpret_cast<volatile ULONG*>(static_cast<ULONG_PTR>(0x7FFE0260)) & 0xFFFFu;
}

static const char* DLFileTypeName(DWORD type) {
    switch (type) {
    case FILE_TYPE_DISK:
        return "disk";
    case FILE_TYPE_CHAR:
        return "char";
    case FILE_TYPE_PIPE:
        return "pipe";
    case FILE_TYPE_REMOTE:
        return "remote";
    default:
        return "unknown";
    }
}

static void DLProbeImagePath(PCWSTR phase, PCWSTR filePath) {
    const ULONGLONG start = GetTickCount64();
    if (!filePath || !filePath[0]) {
        DLLOG("image_probe phase=%ls path=(null) elapsed_ms=%llu", phase ? phase : L"(null)", DLElapsedMs(start));
        return;
    }

    DWORD attr = GetFileAttributesW(filePath);
    DWORD attrGle = GetLastError();
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    BOOL attrExOk = GetFileAttributesExW(filePath, GetFileExInfoStandard, &fad);
    DWORD attrExGle = GetLastError();
    HANDLE h = CreateFileW(filePath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    DWORD openGle = h == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS;
    LARGE_INTEGER size = {};
    DWORD type = FILE_TYPE_UNKNOWN;
    if (h != INVALID_HANDLE_VALUE) {
        GetFileSizeEx(h, &size);
        type = GetFileType(h);
        CloseHandle(h);
    }

    DLLOG("image_probe phase=%ls path=%ls attr=0x%08X attr_gle=%lu attr_ex=%u attr_ex_gle=%lu open=%u open_gle=%lu size=%lld type=%s elapsed_ms=%llu",
        phase ? phase : L"(null)",
        filePath,
        attr,
        attrGle,
        attrExOk ? 1u : 0u,
        attrExGle,
        h != INVALID_HANDLE_VALUE ? 1u : 0u,
        openGle,
        static_cast<long long>(size.QuadPart),
        DLFileTypeName(type),
        DLElapsedMs(start));
}

static NTSTATUS DLFlushServiceKey(PCWSTR servicePath, PCWSTR phase) {
    if (!servicePath || !servicePath[0] || !NtOpenKeyPtr) {
        return STATUS_INVALID_PARAMETER;
    }

    UNICODE_STRING keyName;
    RtlInitUnicodeString(&keyName, servicePath);
    OBJECT_ATTRIBUTES objAttr;
    InitializeObjectAttributes(&objAttr, &keyName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

    HANDLE hKey = nullptr;
    ACCESS_MASK access = KEY_READ;
    if (NtFlushKeyPtr) {
        access |= KEY_WRITE;
    }
    NTSTATUS status = NtOpenKeyPtr(&hKey, access, &objAttr);
    DLLOG("service_key_probe phase=%ls service=%ls open_status=0x%08X flush_available=%u",
        phase ? phase : L"(null)",
        servicePath,
        static_cast<DWORD>(status),
        NtFlushKeyPtr ? 1u : 0u);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    if (NtFlushKeyPtr) {
        NTSTATUS flushStatus = NtFlushKeyPtr(hKey);
        DLLOG("service_key_flush phase=%ls service=%ls status=0x%08X",
            phase ? phase : L"(null)",
            servicePath,
            static_cast<DWORD>(flushStatus));
        if (!NT_SUCCESS(flushStatus)) {
            status = flushStatus;
        }
    }

    NtClose(hKey);
    return status;
}

static NTSTATUS WriteKernelLogPathValue(PCWSTR servicePath) {
    constexpr PCWSTR kUnifiedKernelLogPath = L"\\??\\C:\\Users\\Public\\Desktop\\slop_kernel.log";
    WCHAR inheritedKernelLogPath[512] = {};
    DWORD inheritedLen = GetEnvironmentVariableW(L"SLOP_KERNEL_LOG_PATH", inheritedKernelLogPath, _countof(inheritedKernelLogPath));
    if (inheritedLen > 0 && inheritedLen < _countof(inheritedKernelLogPath) && wcscmp(inheritedKernelLogPath, kUnifiedKernelLogPath) != 0) {
        DLLOG("SLOP_KERNEL_LOG_PATH ignored inherited=%ls unified=%ls", inheritedKernelLogPath, kUnifiedKernelLogPath);
    } else if (inheritedLen >= _countof(inheritedKernelLogPath)) {
        DLLOG("SLOP_KERNEL_LOG_PATH ignored too long len=%lu unified=%ls", static_cast<unsigned long>(inheritedLen), kUnifiedKernelLogPath);
    }
    NTSTATUS status = RtlWriteRegistryValuePtr(0, servicePath, L"SlopKernelLogPath", REG_SZ, const_cast<PWSTR>(kUnifiedKernelLogPath),
        static_cast<ULONG>((wcslen(kUnifiedKernelLogPath) + 1) * sizeof(WCHAR)));
    DLLOG("SlopKernelLogPath: %ls", kUnifiedKernelLogPath);
    DLLOG_STATUS("RtlWriteRegistryValue (SlopKernelLogPath)", status);
    return status;
}

namespace DriverLoader {

    NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath) {
        DLLOG("Creating service for: %ls", filePath);
        const WCHAR prefix[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        SIZE_T prefixLen = wcslen(prefix);

        wmemcpy(servicePath, prefix, prefixLen);

        PCWSTR filePtr = filePath;
        PCWSTR lastSlash = filePath;

        while (*filePtr) {
            if (*filePtr == L'\\') {
                lastSlash = filePtr + 1;
            }
            filePtr++;
        }

        SIZE_T pathLen = prefixLen;
        PCWSTR namePtr = lastSlash;
        while (*namePtr && *namePtr != L'.' && pathLen < 126) {
            servicePath[pathLen] = *namePtr;
            pathLen++;
            namePtr++;
        }
        servicePath[pathLen] = L'\0';

        NTSTATUS status = RtlCreateRegistryKeyPtr(0, servicePath);
        DLLOG("Service path: %ls", servicePath);
        DLLOG_STATUS("RtlCreateRegistryKey", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        WCHAR ntPath[512] = {0};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, _countof(ntPath), filePath);

        SIZE_T ntPathLen = wcslen(ntPath);

        status = RtlWriteRegistryValuePtr(0, servicePath, L"ImagePath", REG_SZ, ntPath,
            static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));
        DLLOG("ImagePath: %ls", ntPath);
        DLLOG_STATUS("RtlWriteRegistryValue (ImagePath)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        status = WriteKernelLogPathValue(servicePath);
        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD typeValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD, &typeValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Type)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD startValue = 3;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Start", REG_DWORD, &startValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Start)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DWORD errorControlValue = 1;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"ErrorControl", REG_DWORD, &errorControlValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (ErrorControl)", status);

        if (!NT_SUCCESS(status)) {
            return status;
        }

        DLLOG("Service created successfully");
        DLFlushServiceKey(servicePath, L"create_driver_service");
        return STATUS_SUCCESS;
    }

    NTSTATUS CreateMinifilterService(PWSTR servicePath, PCWSTR filePath,
                                     PCWSTR instanceName, PCWSTR altitude) {
        DLLOG("Creating minifilter service for: %ls (altitude=%ls)", filePath, altitude);
        const WCHAR prefix[] = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
        SIZE_T prefixLen = wcslen(prefix);

        wmemcpy(servicePath, prefix, prefixLen);

        PCWSTR filePtr = filePath;
        PCWSTR lastSlash = filePath;
        while (*filePtr) {
            if (*filePtr == L'\\') lastSlash = filePtr + 1;
            filePtr++;
        }

        SIZE_T pathLen = prefixLen;
        PCWSTR namePtr = lastSlash;
        while (*namePtr && *namePtr != L'.' && pathLen < 126) {
            servicePath[pathLen] = *namePtr;
            pathLen++;
            namePtr++;
        }
        servicePath[pathLen] = L'\0';

        NTSTATUS status = RtlCreateRegistryKeyPtr(0, servicePath);
        DLLOG("Service path: %ls", servicePath);
        DLLOG_STATUS("RtlCreateRegistryKey (service)", status);
        if (!NT_SUCCESS(status)) return status;

        WCHAR ntPath[512] = {0};
        wcscpy_s(ntPath, L"\\??\\");
        wcscat_s(ntPath, _countof(ntPath), filePath);
        SIZE_T ntPathLen = wcslen(ntPath);

        status = RtlWriteRegistryValuePtr(0, servicePath, L"ImagePath", REG_SZ, ntPath,
            static_cast<ULONG>((ntPathLen + 1) * sizeof(WCHAR)));
        DLLOG_STATUS("RtlWriteRegistryValue (ImagePath)", status);
        if (!NT_SUCCESS(status)) return status;

        status = WriteKernelLogPathValue(servicePath);
        if (!NT_SUCCESS(status)) return status;

        DWORD typeValue = 2;
        status = RtlWriteRegistryValuePtr(0, servicePath, L"Type", REG_DWORD,
            &typeValue, sizeof(DWORD));
        DLLOG_STATUS("RtlWriteRegistryValue (Type=2 FILE_SYSTEM_DRIVER)", status);
        if (!NT_SUCCESS(status)) return status;

        DWORD startValue = 3;
        RtlWriteRegistryValuePtr(0, servicePath, L"Start", REG_DWORD,
            &startValue, sizeof(DWORD));

        DWORD errorControlValue = 1;
        RtlWriteRegistryValuePtr(0, servicePath, L"ErrorControl", REG_DWORD,
            &errorControlValue, sizeof(DWORD));

        static const WCHAR groupName[] = L"FSFilter Activity Monitor";
        RtlWriteRegistryValuePtr(0, servicePath, L"Group", REG_SZ,
            const_cast<PWSTR>(groupName),
            static_cast<ULONG>((wcslen(groupName) + 1) * sizeof(WCHAR)));

        static const WCHAR dependOn[] = L"FltMgr\0";
        RtlWriteRegistryValuePtr(0, servicePath, L"DependOnService", REG_MULTI_SZ,
            const_cast<PWSTR>(dependOn),
            static_cast<ULONG>((_countof(dependOn) + 1) * sizeof(WCHAR)));

        WCHAR instancesPath[256] = {0};
        wcscpy_s(instancesPath, servicePath);
        wcscat_s(instancesPath, L"\\Instances");

        status = RtlCreateRegistryKeyPtr(0, instancesPath);
        DLLOG_STATUS("RtlCreateRegistryKey (Instances)", status);
        if (!NT_SUCCESS(status)) return status;

        RtlWriteRegistryValuePtr(0, instancesPath, L"DefaultInstance", REG_SZ,
            const_cast<PWSTR>(instanceName),
            static_cast<ULONG>((wcslen(instanceName) + 1) * sizeof(WCHAR)));

        WCHAR instanceKey[320] = {0};
        wcscpy_s(instanceKey, instancesPath);
        wcscat_s(instanceKey, L"\\");
        wcscat_s(instanceKey, _countof(instanceKey), instanceName);

        status = RtlCreateRegistryKeyPtr(0, instanceKey);
        DLLOG_STATUS("RtlCreateRegistryKey (Instance)", status);
        if (!NT_SUCCESS(status)) return status;

        RtlWriteRegistryValuePtr(0, instanceKey, L"Altitude", REG_SZ,
            const_cast<PWSTR>(altitude),
            static_cast<ULONG>((wcslen(altitude) + 1) * sizeof(WCHAR)));

        DWORD instanceFlags = 0;
        RtlWriteRegistryValuePtr(0, instanceKey, L"Flags", REG_DWORD,
            &instanceFlags, sizeof(DWORD));

        DLLOG("Minifilter service created successfully");
        DLFlushServiceKey(servicePath, L"create_minifilter_service");
        return STATUS_SUCCESS;
    }

    NTSTATUS LoadDriver(PCWSTR servicePath, PCWSTR imagePath) {
        const ULONGLONG start = GetTickCount64();
        DLLOG("Loading driver: %ls", servicePath);
        DLLOG("LoadDriver enter service=%ls service_len=%llu pid=%lu tid=%lu build=%lu ntload=%p",
            servicePath ? servicePath : L"(null)",
            servicePath ? static_cast<unsigned long long>(wcslen(servicePath)) : 0ULL,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            DLBuildNumber(),
            NtLoadDriverPtr);
        DLFlushServiceKey(servicePath, L"pre_load");
        DLProbeImagePath(L"pre_load", imagePath);
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);
        DLLOG("LoadDriver unicode length=%u max=%u buffer=%p elapsed_ms=%llu",
            usServicePath.Length,
            usServicePath.MaximumLength,
            usServicePath.Buffer,
            DLElapsedMs(start));

        NTSTATUS status = NtLoadDriverPtr(&usServicePath);
        DLLOG_STATUS("NtLoadDriver", status);
        if (status == static_cast<NTSTATUS>(0xC0000034L)) {
            DLLOG("NtLoadDriver object_name_not_found retry_prepare service=%ls image=%ls elapsed_ms=%llu",
                servicePath ? servicePath : L"(null)",
                imagePath ? imagePath : L"(null)",
                DLElapsedMs(start));
            DLFlushServiceKey(servicePath, L"retry_object_name_not_found");
            DLProbeImagePath(L"retry_object_name_not_found", imagePath);
            Sleep(50);
            status = NtLoadDriverPtr(&usServicePath);
            DLLOG_STATUS("NtLoadDriver retry", status);
        }
        DLLOG("LoadDriver exit service=%ls status=0x%08X elapsed_ms=%llu pid=%lu tid=%lu",
            servicePath ? servicePath : L"(null)",
            (DWORD)status,
            DLElapsedMs(start),
            GetCurrentProcessId(),
            GetCurrentThreadId());
        if (!NT_SUCCESS(status)) {
            DLLOG("NtLoadDriver FAILED for '%ls', NTSTATUS=0x%08X", servicePath, (DWORD)status);
        }

        return status;
    }

    NTSTATUS UnloadDriver(PCWSTR servicePath) {
        const ULONGLONG start = GetTickCount64();
        DLLOG("Unloading driver: %ls", servicePath);
        DLLOG("UnloadDriver enter service=%ls service_len=%llu pid=%lu tid=%lu build=%lu ntunload=%p",
            servicePath ? servicePath : L"(null)",
            servicePath ? static_cast<unsigned long long>(wcslen(servicePath)) : 0ULL,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            DLBuildNumber(),
            NtUnloadDriverPtr);
        UNICODE_STRING usServicePath;
        RtlInitUnicodeString(&usServicePath, servicePath);
        DLLOG("UnloadDriver unicode length=%u max=%u buffer=%p elapsed_ms=%llu",
            usServicePath.Length,
            usServicePath.MaximumLength,
            usServicePath.Buffer,
            DLElapsedMs(start));

        NTSTATUS status = NtUnloadDriverPtr(&usServicePath);
        DLLOG_STATUS("NtUnloadDriver", status);
        DLLOG("UnloadDriver exit service=%ls status=0x%08X elapsed_ms=%llu pid=%lu tid=%lu",
            servicePath ? servicePath : L"(null)",
            (DWORD)status,
            DLElapsedMs(start),
            GetCurrentProcessId(),
            GetCurrentThreadId());

        return status;
    }

}
