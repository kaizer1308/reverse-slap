#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"

namespace vad_impl {

    typedef NTSTATUS(NTAPI* pfn_ZwQueryVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        ULONG MemoryInformationClass,
        PVOID MemoryInformation,
        SIZE_T MemoryInformationLength,
        PSIZE_T ReturnLength);

    inline pfn_ZwQueryVirtualMemory g_ZwQueryVirtualMemory = nullptr;
    inline volatile LONG g_resolved = 0;

    __forceinline void resolve() {
        if (_InterlockedCompareExchange(&g_resolved, 0, 0) != 0) return;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, L"ZwQueryVirtualMemory");
        g_ZwQueryVirtualMemory = reinterpret_cast<pfn_ZwQueryVirtualMemory>(
            MmGetSystemRoutineAddress(&name));
        _InterlockedExchange(&g_resolved, 1);
    }

    struct MEMORY_BASIC_INFORMATION_K {
        PVOID BaseAddress;
        PVOID AllocationBase;
        ULONG AllocationProtect;
        USHORT PartitionId;
        USHORT Reserved;
        SIZE_T RegionSize;
        ULONG State;
        ULONG Protect;
        ULONG Type;
    };

    struct UNICODE_STRING_K {
        USHORT Length;
        USHORT MaximumLength;
        PWCH Buffer;
    };

    constexpr ULONG MemoryBasicInformation = 0;
    constexpr ULONG MemoryMappedFilenameInformation = 2;
    constexpr ULONG MEM_MAPPED_K = 0x40000;
    constexpr ULONG MEM_IMAGE_K = 0x1000000;
}

NTSTATUS functions::handle_vad_walk(p_vad_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    UINT32 pid = request->pid;
    request->entry_count = 0;
    request->total_count = 0;

    vad_impl::resolve();
    if (!vad_impl::g_ZwQueryVirtualMemory) return STATUS_NOT_SUPPORTED;
    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess || !_KeUnstackDetachProcess)
        return STATUS_NOT_SUPPORTED;

    PEPROCESS process = nullptr;
    NTSTATUS st = _PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &process);
    if (!NT_SUCCESS(st) || !process) return st;

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    ULONG written = 0;
    ULONG total = 0;
    UINT64 addr = 0;

    __try {
        while (addr < 0x7FFFFFFFFFFF) {
            vad_impl::MEMORY_BASIC_INFORMATION_K mbi = {};
            SIZE_T ret_len = 0;
            st = vad_impl::g_ZwQueryVirtualMemory(
                reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)),
                reinterpret_cast<PVOID>(addr),
                vad_impl::MemoryBasicInformation,
                &mbi, sizeof(mbi), &ret_len);

            if (!NT_SUCCESS(st)) break;
            if (mbi.RegionSize == 0) break;

            if (mbi.State != 0x10000) {
                ++total;
                if (written < MAX_VAD_ENTRIES) {
                    auto& out = request->entries[written];
                    out.base = reinterpret_cast<UINT64>(mbi.BaseAddress);
                    out.size = mbi.RegionSize;
                    out.allocation_base = reinterpret_cast<UINT64>(mbi.AllocationBase);
                    out.state = mbi.State;
                    out.protect = mbi.Protect;
                    out.type = mbi.Type;
                    out.allocation_protect = mbi.AllocationProtect;
                    out.mapped_name[0] = L'\0';

                    if (mbi.Type == vad_impl::MEM_MAPPED_K || mbi.Type == vad_impl::MEM_IMAGE_K) {
                        UCHAR name_buf[520] = {};
                        SIZE_T name_len = 0;
                        NTSTATUS name_st = vad_impl::g_ZwQueryVirtualMemory(
                            reinterpret_cast<HANDLE>(static_cast<LONG_PTR>(-1)),
                            reinterpret_cast<PVOID>(addr),
                            vad_impl::MemoryMappedFilenameInformation,
                            name_buf, sizeof(name_buf), &name_len);
                        if (NT_SUCCESS(name_st)) {
                            auto* us = reinterpret_cast<vad_impl::UNICODE_STRING_K*>(name_buf);
                            if (us->Buffer && us->Length > 0) {
                                USHORT chars = us->Length / sizeof(WCHAR);
                                if (chars > 127) chars = 127;
                                for (USHORT c = 0; c < chars; ++c)
                                    out.mapped_name[c] = us->Buffer[c];
                                out.mapped_name[chars] = L'\0';
                            }
                        }
                    }
                    ++written;
                }
            }

            UINT64 next = reinterpret_cast<UINT64>(mbi.BaseAddress) + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    request->entry_count = written;
    request->total_count = total;
    return STATUS_SUCCESS;
}
