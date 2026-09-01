#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <winternl.h>
#include <Psapi.h>
#include <cstdint>
#include <string>
#include <random>
#include <intrin.h>

#pragma comment(lib, "ntdll.lib")

void FlushMapperLogFile();

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS          ((NTSTATUS)0x00000000L)
#endif
#ifndef STATUS_UNSUCCESSFUL
#define STATUS_UNSUCCESSFUL     ((NTSTATUS)0xC0000001L)
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND        ((NTSTATUS)0xC0000225L)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif
#ifndef STATUS_INVALID_HANDLE
#define STATUS_INVALID_HANDLE   ((NTSTATUS)0xC0000008L)
#endif
#ifndef STATUS_ACCESS_DENIED
#define STATUS_ACCESS_DENIED    ((NTSTATUS)0xC0000022L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_OBJECT_PATH_NOT_FOUND
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003AL)
#endif
#ifndef STATUS_IMAGE_ALREADY_LOADED
#define STATUS_IMAGE_ALREADY_LOADED ((NTSTATUS)0xC000010EL)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_PRIVILEGE_NOT_HELD
#define STATUS_PRIVILEGE_NOT_HELD ((NTSTATUS)0xC0000061L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef CTL_CODE
#define CTL_CODE(DeviceType, Function, Method, Access) (((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif
#ifndef METHOD_BUFFERED
#define METHOD_BUFFERED 0
#endif
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS 0
#endif

typedef LARGE_INTEGER PHYSICAL_ADDRESS, *PPHYSICAL_ADDRESS;

#define WINIO_DEVICE_NAME L"\\Device\\GLCKIo"
#define WINIO_SYMLINK_NAME L"\\DosDevices\\GLCKIo"
#define WINIO_DEVICE_TYPE 0x8010
#define IOCTL_WINIO_MAPPHYSTOLIN CTL_CODE(WINIO_DEVICE_TYPE, 0x810, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINIO_UNMAPPHYSADDR CTL_CODE(WINIO_DEVICE_TYPE, 0x811, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINIO_READPORT CTL_CODE(WINIO_DEVICE_TYPE, 0x814, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_WINIO_WRITEPORT CTL_CODE(WINIO_DEVICE_TYPE, 0x815, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define SE_LOAD_DRIVER_PRIVILEGE 10
#define IA32_LSTAR_MSR        0xC0000082


namespace AntiDetect {
    inline void TimingJitter() {
        static std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<int> dist(50, 500);
        volatile int dummy = 0;
        for (int i = 0; i < dist(rng); i++) {
            dummy += i;
            _mm_pause();
        }
    }

    inline std::wstring GenerateRandomServiceName() {
        static const wchar_t charset[] = L"abcdefghijklmnopqrstuvwxyz0123456789";
        std::mt19937 rng(static_cast<unsigned int>(__rdtsc()));
        std::uniform_int_distribution<int> dist(0, sizeof(charset) / sizeof(wchar_t) - 2);
        std::wstring name;
        int len = 8 + (rng() % 8);
        for (int i = 0; i < len; i++) {
            name += charset[dist(rng)];
        }
        return name;
    }

    inline bool IsBeingDebugged() {
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        if (debugged) return true;
        if (IsDebuggerPresent()) return true;
        typedef NTSTATUS(NTAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
        pNtQIP NtQIP = (pNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
        if (NtQIP) {
            ULONG_PTR debugPort = 0;
            NTSTATUS st = NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr);
            if (st >= 0 && debugPort != 0) return true;
            ULONG debugFlags = 0;
            st = NtQIP(GetCurrentProcess(), 0x1F, &debugFlags, sizeof(debugFlags), nullptr);
            if (st >= 0 && debugFlags == 0) return true;
        }
        return false;
    }

    inline void MemoryBarrier() {
        _mm_mfence();
        _mm_lfence();
    }
}

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

#pragma pack(push, 1)

typedef struct _WINIO_PHYS_MEM {
    LARGE_INTEGER Size;
    LARGE_INTEGER PhysicalAddress;
    HANDLE SectionHandle;
    PVOID MappedAddress;
    PVOID SectionObject;
} WINIO_PHYS_MEM, *PWINIO_PHYS_MEM;

typedef struct _WINIO_PHYS_UNMAP {
    LARGE_INTEGER Size;
    LARGE_INTEGER PhysicalAddress;
    HANDLE SectionHandle;
    PVOID MappedAddress;
    PVOID SectionObject;
} WINIO_PHYS_UNMAP, *PWINIO_PHYS_UNMAP;

typedef struct _WINIO_PORT_OP {
    USHORT Port;
    ULONG Value;
    UCHAR Size;
} WINIO_PORT_OP, *PWINIO_PORT_OP;

#pragma pack(pop)

typedef NTSTATUS(NTAPI* pNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* pNtLoadDriver)(
    PUNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* pNtUnloadDriver)(
    PUNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* pRtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN WasEnabled
    );

typedef NTSTATUS(NTAPI* pRtlGetFullPathName_UEx)(
    PCWSTR FileName,
    ULONG BufferLength,
    PWSTR Buffer,
    PWSTR* FilePart,
    PULONG InputPathType
    );

typedef NTSTATUS(NTAPI* pRtlCreateRegistryKey)(
    ULONG RelativeTo,
    PWSTR Path
    );

typedef NTSTATUS(NTAPI* pRtlWriteRegistryValue)(
    ULONG RelativeTo,
    PCWSTR Path,
    PCWSTR ValueName,
    ULONG ValueType,
    PVOID ValueData,
    ULONG ValueLength
    );

typedef NTSTATUS(NTAPI* pNtDeviceIoControlFile)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode,
    PVOID InputBuffer,
    ULONG InputBufferLength,
    PVOID OutputBuffer,
    ULONG OutputBufferLength
    );

typedef NTSTATUS(NTAPI* pNtDeleteKey)(
    HANDLE KeyHandle
    );

typedef NTSTATUS(NTAPI* pNtOpenKey)(
    PHANDLE KeyHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes
    );

typedef NTSTATUS(NTAPI* pNtFlushKey)(
    HANDLE KeyHandle
    );

typedef NTSTATUS(NTAPI* pNtCreateFile)(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
    );

typedef NTSTATUS(NTAPI* pNtSetInformationFile)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
    );

extern pNtQuerySystemInformation NtQuerySystemInformationPtr;
extern pNtLoadDriver NtLoadDriverPtr;
extern pNtUnloadDriver NtUnloadDriverPtr;
extern pRtlAdjustPrivilege RtlAdjustPrivilegePtr;
extern pRtlGetFullPathName_UEx RtlGetFullPathName_UExPtr;
extern pRtlCreateRegistryKey RtlCreateRegistryKeyPtr;
extern pRtlWriteRegistryValue RtlWriteRegistryValuePtr;
extern pNtDeviceIoControlFile NtDeviceIoControlFilePtr;
extern pNtDeleteKey NtDeleteKeyPtr;
extern pNtOpenKey NtOpenKeyPtr;
extern pNtFlushKey NtFlushKeyPtr;
extern pNtCreateFile NtCreateFilePtr;
extern pNtSetInformationFile NtSetInformationFilePtr;

extern WCHAR g_LoaderServicePath[128];
extern WCHAR g_DriverServicePath[128];

extern unsigned char* g_P2CDriverData;
extern size_t g_P2CDriverSize;

extern PVOID g_OriginalCiCallback;
extern PVOID g_CiCallbackAddress;
extern bool g_CiCallbackPatched;

extern bool g_KernelSigningVerified;
extern DWORD g_PatchedFlags;
extern PVOID g_DriverLoadAddress;
extern WCHAR g_DonorCopyPath[520];
extern WCHAR g_DonorSignerName[256];

extern WCHAR g_ShadowFsServicePath[128];

namespace Utils {
    std::wstring GenerateRandomName(size_t length);
    BOOL InitializeNtFunctions();
    NTSTATUS AdjustPrivilege(ULONG privilege, BOOLEAN enable);
    NTSTATUS GetFullPath(PCWSTR fileName, PWSTR buffer, ULONG bufferLength);
    BOOL SecureDeleteFile(PCWSTR filePath);
    BOOL PosixDeleteFile(PCWSTR filePath);
    BOOL ForceDeleteOrRename(PCWSTR filePath);
    BOOL HideLoadedImagePath(PCWSTR filePath);
    std::wstring GetTempFilePath(PCWSTR extension);
    std::wstring GetSiblingTempFilePath(PCWSTR basePath, PCWSTR extension);
}

namespace DriverLoader {
    NTSTATUS CreateDriverService(PWSTR servicePath, PCWSTR filePath);
    NTSTATUS CreateMinifilterService(PWSTR servicePath, PCWSTR filePath,
                                     PCWSTR instanceName, PCWSTR altitude);
    NTSTATUS LoadDriver(PCWSTR servicePath, PCWSTR imagePath = nullptr);
    NTSTATUS UnloadDriver(PCWSTR servicePath);
}

namespace KernelUtils {
    PVOID GetKernelModuleBase(const char* moduleName);
    PVOID GetKernelProcAddress(PVOID moduleBase, const char* procName);
    BOOL GetCiValidateImageHeaderEntry(PVOID* outCiEntry, PVOID* outZwFlush);
    BOOL PatchDriverSigningFlags(HANDLE device, PCWSTR driverFileName);
    BOOL PatchDriverSigningFlagsByBase(HANDLE device, PVOID driverBase, ULONG driverImageSize, PCSTR label, BOOL updateDriverLoadAddress);
    PVOID GetDriverBaseByName(PCWSTR driverFileName, PULONG outImageSize);
}

namespace VulnDriver {
    NTSTATUS OpenDevice(PHANDLE deviceHandle);
    NTSTATUS MapPhysicalMemory(HANDLE device, ULONGLONG physAddr, ULONG size, PVOID* mappedAddr);
    NTSTATUS UnmapPhysicalMemory(HANDLE device, PVOID mappedAddr);
    NTSTATUS ReadPhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID buffer, SIZE_T size);
    NTSTATUS WritePhysicalMemory(HANDLE device, ULONGLONG physAddr, PVOID data, SIZE_T size);
    NTSTATUS ExchangePhysicalPointer(HANDLE device, ULONGLONG physAddr, PVOID newValue, PVOID* oldValue);
    NTSTATUS ReadKernelMemory(HANDLE device, PVOID address, PVOID buffer, SIZE_T size);
    NTSTATUS WriteKernelMemory(HANDLE device, PVOID address, PVOID data, SIZE_T size);
    NTSTATUS ReadMsr(HANDLE device, ULONG msrIndex, PULONGLONG value);
    NTSTATUS WriteMsr(HANDLE device, ULONG msrIndex, ULONGLONG value);
    ULONGLONG VirtualToPhysical(HANDLE device, PVOID virtualAddress);
    VOID CloseDevice(HANDLE deviceHandle);
    VOID ResetCR3Cache();
}

namespace MapperCore {
    NTSTATUS TriggerExploit(PCWSTR targetDriverFileName,
                            PCWSTR shadowFsDriverFileName = nullptr, PCWSTR targetDriverFullPath = nullptr,
                            PCWSTR shadowFsDriverFullPath = nullptr,
                            PCWSTR loaderDriverFullPath = nullptr);
    NTSTATUS WindLoadDriver(PCWSTR loaderPath, PCWSTR driverPath,
                            PCWSTR shadowFsPath = nullptr);
    NTSTATUS RestoreCiCallback(HANDLE device);
    NTSTATUS CleanupArtifacts();
}

namespace SignedMemory {
    BOOL TransplantCertificateToDriver(LPCWSTR targetDriverPath);
    BOOL SelfSignDriver(LPCWSTR targetDriverPath);
}
