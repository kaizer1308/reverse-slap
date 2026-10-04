#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"

NTSTATUS functions::handle_kmod_enum(p_kmod_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->entry_count = 0;
    request->total_count = 0;

    ULONG needed = 0;
    ZwQuerySystemInformation(SystemModuleInformationInternal, nullptr, 0, &needed);
    if (needed == 0) needed = 0x10000;
    needed += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;

    PRTL_PROCESS_MODULES buf = static_cast<PRTL_PROCESS_MODULES>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, needed, 'domK'));
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;

    NTSTATUS st = ZwQuerySystemInformation(SystemModuleInformationInternal, buf, needed, &needed);
    if (!NT_SUCCESS(st)) {
        ExFreePoolWithTag(buf, 'domK');
        return st;
    }

    ULONG count = buf->NumberOfModules;
    request->total_count = count;

    ULONG written = 0;
    __try {
        for (ULONG i = 0; i < count && written < MAX_KMOD_ENTRIES; ++i) {
            const auto& mod = buf->Modules[i];
            request->entries[written].base = reinterpret_cast<UINT64>(mod.ImageBase);
            request->entries[written].size = mod.ImageSize;
            request->entries[written].load_order = mod.LoadOrderIndex;
            request->entries[written].flags = mod.Flags;

            const char* name = reinterpret_cast<const char*>(mod.FullPathName) + mod.OffsetToFileName;
            ULONG j = 0;
            while (name[j] && j < 63) {
                request->entries[written].name[j] = name[j];
                ++j;
            }
            request->entries[written].name[j] = '\0';
            ++written;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    request->entry_count = written;
    ExFreePoolWithTag(buf, 'domK');
    return STATUS_SUCCESS;
}
