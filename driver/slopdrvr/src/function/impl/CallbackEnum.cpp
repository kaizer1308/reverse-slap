#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"

namespace stealth_impl {

    struct ex_callback_routine_block_t {
        UINT64 rundown_protect;
        UINT64 function;
        UINT64 context;
    };
    static_assert(sizeof(ex_callback_routine_block_t) == 24, "ex_callback_routine_block_t must be 24 bytes");

    constexpr ULONG kProcessNotifyMax = 64;
    constexpr ULONG kThreadNotifyMax  = 64;
    constexpr ULONG kImageNotifyMax   = 64;

    constexpr UINT32 kKindProcess = 1;
    constexpr UINT32 kKindThread  = 2;
    constexpr UINT32 kKindImage   = 3;
    constexpr UINT32 kKindObject  = 4;

    __forceinline BOOLEAN is_kernel_ptr(UINT64 v) {
        return v >= 0xFFFF800000000000ULL;
    }

    __forceinline UINT64 resolve_array_via_lea(const wchar_t* routine_name) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return 0;
        UNICODE_STRING name;
        RtlInitUnicodeString(&name, routine_name);
        PVOID fn = MmGetSystemRoutineAddress(&name);
        if (!fn) return 0;

        UINT64 base = reinterpret_cast<UINT64>(fn);
        __try {
            for (ULONG i = 0; i < 0x80; ++i) {
                UINT8* p = reinterpret_cast<UINT8*>(base + i);
                if (p[0] == 0x48 && p[1] == 0x8D) {
                    UINT8 modrm = p[2];
                    if ((modrm & 0xC7) == 0x05) {
                        INT32 disp = *reinterpret_cast<INT32*>(p + 3);
                        UINT64 target = base + i + 7 + disp;
                        if (is_kernel_ptr(target)) return target;
                    }
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
        return 0;
    }

    __forceinline ULONG enum_flat_array(UINT64 array_base, ULONG max_entries,
                                        CALLBACK_ENTRY* out, ULONG out_cap, UINT32 kind) {
        if (!array_base || !out || out_cap == 0) return 0;
        ULONG written = 0;
        __try {
            for (ULONG i = 0; i < max_entries && written < out_cap; ++i) {
                auto* block = reinterpret_cast<ex_callback_routine_block_t*>(array_base + i * sizeof(ex_callback_routine_block_t));
                UINT64 fn = block->function;
                if (fn == 0) continue;
                if (!is_kernel_ptr(fn)) continue;
                out[written].callback_address = fn;
                out[written].module_base = 0;
                out[written].kind = kind;
                out[written].index = i;
                out[written].active = 1;
                out[written].padding = 0;
                ++written;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
        return written;
    }

    inline volatile LONG g_arrays_resolved = 0;
    inline UINT64 g_process_array = 0;
    inline UINT64 g_thread_array = 0;
    inline UINT64 g_image_array = 0;

    __forceinline void resolve_arrays() {
        if (_InterlockedCompareExchange(&g_arrays_resolved, 0, 0) != 0) return;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
        g_process_array = resolve_array_via_lea(L"PsSetCreateProcessNotifyRoutineEx");
        g_thread_array  = resolve_array_via_lea(L"PsSetCreateThreadNotifyRoutine");
        g_image_array   = resolve_array_via_lea(L"PsSetLoadImageNotifyRoutine");
        _InterlockedExchange(&g_arrays_resolved, 1);
    }

    __forceinline UINT64 array_for_kind(UINT32 kind) {
        resolve_arrays();
        switch (kind) {
        case kKindProcess: return g_process_array;
        case kKindThread:  return g_thread_array;
        case kKindImage:   return g_image_array;
        default: return 0;
        }
    }

    __forceinline ULONG max_for_kind(UINT32 kind) {
        switch (kind) {
        case kKindProcess: return kProcessNotifyMax;
        case kKindThread:  return kThreadNotifyMax;
        case kKindImage:   return kImageNotifyMax;
        default: return 0;
        }
    }
}

NTSTATUS functions::handle_callback_enum(p_callback_enum request) {
    if (!request) return STATUS_INVALID_PARAMETER;
    request->entry_count = 0;
    request->total_count = 0;

    UINT32 kind = request->kind;
    if (kind == stealth_impl::kKindObject) {
        return STATUS_SUCCESS;
    }

    UINT64 array = stealth_impl::array_for_kind(kind);
    ULONG max_entries = stealth_impl::max_for_kind(kind);
    if (!array || max_entries == 0) return STATUS_NOT_FOUND;

    request->entry_count = stealth_impl::enum_flat_array(
        array, max_entries, request->entries, MAX_CALLBACK_ENTRIES, kind);
    request->total_count = request->entry_count;
    return STATUS_SUCCESS;
}
