#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"

namespace handle_enum_impl {

    struct SYSTEM_HANDLE_INFORMATION_EX_HEADER {
        ULONG_PTR NumberOfHandles;
        ULONG_PTR Reserved;
    };

    struct SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
        PVOID Object;
        ULONG_PTR UniqueProcessId;
        ULONG_PTR HandleValue;
        ULONG GrantedAccess;
        USHORT CreatorBackTraceIndex;
        USHORT ObjectTypeIndex;
        ULONG HandleAttributes;
        ULONG Reserved;
    };

    constexpr ULONG SystemExtendedHandleInformation = 0x40;
}

NTSTATUS functions::handle_handle_table_enum(p_handle_table_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    UINT32 target_pid = request->pid;
    request->entry_count = 0;
    request->total_count = 0;

    ULONG buf_size = 0x100000;
    PVOID buf = nullptr;
    NTSTATUS st;

    for (int attempt = 0; attempt < 8; ++attempt) {
        buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, buf_size, 'ldnH');
        if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

        st = ZwQuerySystemInformation(
            static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(handle_enum_impl::SystemExtendedHandleInformation),
            buf, buf_size, nullptr);

        if (NT_SUCCESS(st)) break;

        ExFreePoolWithTag(buf, 'ldnH');
        buf = nullptr;

        if (st != STATUS_INFO_LENGTH_MISMATCH) return st;
        buf_size *= 2;
        if (buf_size > 0x4000000) return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    auto* header = static_cast<handle_enum_impl::SYSTEM_HANDLE_INFORMATION_EX_HEADER*>(buf);
    auto* entries = reinterpret_cast<handle_enum_impl::SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX*>(
        static_cast<UCHAR*>(buf) + sizeof(handle_enum_impl::SYSTEM_HANDLE_INFORMATION_EX_HEADER));

    ULONG total_for_pid = 0;
    ULONG written = 0;

    __try {
        for (ULONG_PTR i = 0; i < header->NumberOfHandles; ++i) {
            if (static_cast<UINT32>(entries[i].UniqueProcessId) != target_pid) continue;
            ++total_for_pid;
            if (written >= MAX_HANDLE_ENTRIES) continue;

            request->entries[written].handle_value = static_cast<UINT64>(entries[i].HandleValue);
            request->entries[written].object_address = reinterpret_cast<UINT64>(entries[i].Object);
            request->entries[written].granted_access = entries[i].GrantedAccess;
            request->entries[written].object_type_index = entries[i].ObjectTypeIndex;
            request->entries[written].padding = 0;
            ++written;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    request->entry_count = written;
    request->total_count = total_for_pid;
    ExFreePoolWithTag(buf, 'ldnH');
    return STATUS_SUCCESS;
}
