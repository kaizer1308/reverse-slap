#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include <stddef.h>
#include <intrin.h>

#pragma intrinsic(_mm_mfence)

#ifdef SLOP_NET_DEBUG
#define RC_DBG(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[SLOP-RC] " fmt "\n", ##__VA_ARGS__); } while(0)
#define RC_ERR(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[SLOP-RC][ERR] " fmt "\n", ##__VA_ARGS__); } while(0)
#else
#define RC_DBG(fmt, ...) ((void)0)
#define RC_ERR(fmt, ...) ((void)0)
#endif

namespace call_guard {
    __forceinline BOOLEAN is_valid_user_range(UINT64 addr) {
        return (addr > 0x10000ULL && addr < 0x00007FFFFFFFFFFFULL);
    }

    __forceinline BOOLEAN is_valid_code_ptr(UINT64 addr) {
        if (!is_valid_user_range(addr)) return FALSE;
        return TRUE;
    }

    __forceinline BOOLEAN is_valid_dtb(UINT64 dtb) {
        if (dtb == 0) return FALSE;
        UINT64 clean_dtb = dtb & ~0xFFFULL;
        UINT64 pfn = (clean_dtb >> 12) & 0xFFFFFFFFFULL;
        return (pfn != 0);
    }
}

#pragma pack(push, 1)
typedef struct _CALL_CONTEXT {
    UINT64 target_func;
    UINT64 spoof_gadget;
    UINT64 param1;
    UINT64 param2;
    UINT64 param3;
    UINT64 param4;
    UINT64 ret_value;
    UINT64 saved_rsp;
    UINT64 original_rip;
    UINT64 rbx_backup;
    volatile UINT64 exec_done;
    UINT64 trampoline_addr;
    UINT64 stack_backup[8];
    UINT64 xmm_backup[12];
    UINT64 reserved[8];
} CALL_CONTEXT, *PCALL_CONTEXT;
#pragma pack(pop)

static_assert(sizeof(CALL_CONTEXT) == 320, "CALL_CONTEXT must be 320 bytes");
static_assert(offsetof(CALL_CONTEXT, ret_value) == 0x30, "ret_value must be at offset 0x30");
static_assert(offsetof(CALL_CONTEXT, original_rip) == 0x40, "original_rip must be at offset 0x40");
static_assert(offsetof(CALL_CONTEXT, exec_done) == 0x50, "exec_done must be at offset 0x50");
static_assert(offsetof(CALL_CONTEXT, trampoline_addr) == 0x58, "trampoline_addr must be at offset 0x58");

static __forceinline UINT64 rc_diag_mix(UINT64 value, UINT64 input) {
    value ^= input + 0x9E3779B97F4A7C15ULL + (value << 6) + (value >> 2);
    return value;
}

static __forceinline UINT64 rc_diag_fingerprint_remote(p_remote_call request) {
    if (!request)
        return 0;
    UINT64 value = 0xA1DA778100000001ULL;
    value = rc_diag_mix(value, request->dtb);
    value = rc_diag_mix(value, request->target_function);
    value = rc_diag_mix(value, request->shellcode_address);
    value = rc_diag_mix(value, request->spoof_return);
    value = rc_diag_mix(value, request->arg1);
    value = rc_diag_mix(value, request->arg2);
    value = rc_diag_mix(value, request->arg3);
    value = rc_diag_mix(value, request->arg4);
    value = rc_diag_mix(value, request->original_rip);
    return value;
}

static __forceinline UINT64 rc_diag_fingerprint_result(p_call_result request) {
    if (!request)
        return 0;
    UINT64 value = 0xA1DA778200000001ULL;
    value = rc_diag_mix(value, request->dtb);
    value = rc_diag_mix(value, request->result_address);
    value = rc_diag_mix(value, request->result);
    value = rc_diag_mix(value, request->completed);
    return value;
}

static __forceinline UINT64 rc_diag_elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
    LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
    if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
        return 0;
    return static_cast<UINT64>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<UINT64>(freq.QuadPart));
}

namespace poly_engine {
    inline volatile ULONG g_poly_seed = 0xCAFEBABEu;

    __forceinline ULONG poly_rand() {
        ULONG x = g_poly_seed ^ (ULONG)(__rdtsc() & 0xFFFFFFFFu);
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        g_poly_seed = x;
        return x;
    }

    __forceinline SIZE_T emit_junk(PUINT8 buf, SIZE_T max_junk) {
        SIZE_T count = (poly_rand() % (max_junk + 1));
        for (SIZE_T j = 0; j < count; j++) {
            ULONG r = poly_rand() % 8;
            switch (r) {
                case 0: buf[j] = 0x90; break;
                case 1: buf[j] = 0x66; if (j + 1 < count) buf[++j] = 0x90; break;
                case 2: buf[j] = 0x0F; if (j + 1 < count) { buf[++j] = 0x1F; if (j + 1 < count) buf[++j] = 0x00; } break;
                case 3: buf[j] = 0x87; buf[j] |= 0xC0; break;
                case 4: buf[j] = 0x48; if (j + 1 < count) buf[++j] = 0x87; if (j + 1 < count) buf[++j] = 0xC0; break;
                default: buf[j] = 0x90; break;
            }
        }
        return count;
    }
}

namespace shellcode_builder {

    __forceinline SIZE_T build_spoofed_call_v2(PUINT8 buf, UINT64 ctx_addr, UINT64 spoof_gadget, UINT64 epilogue_addr) {
        UNREFERENCED_PARAMETER(spoof_gadget);
        UNREFERENCED_PARAMETER(epilogue_addr);
        SIZE_T i = 0;

        i += poly_engine::emit_junk(&buf[i], 3);

        buf[i++] = 0x50;
        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x60; buf[i++] = 0x60;
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0x40; buf[i++] = 0x60; buf[i++] = 0x08;
        buf[i++] = 0x58;

        buf[i++] = 0x9C;

        buf[i++] = 0x50;
        buf[i++] = 0x51;
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;

        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;


        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0xA6; buf[i++] = 0x00; buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;

        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x20;
        i += 4;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x06;

        buf[i++] = 0xFF; buf[i++] = 0xD0;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;

        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;


        buf[i++] = 0xF3; buf[i++] = 0x90;

        buf[i++] = 0xEB; buf[i++] = 0xFC;

        return i;
    }

    __forceinline SIZE_T build_jmp_rbx_spoofed(PUINT8 buf, UINT64 ctx_addr, UINT64 jmp_rbx_gadget, UINT64 epilogue_addr) {
        SIZE_T i = 0;

        buf[i++] = 0x50;
        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x60; buf[i++] = 0x60;
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0x40; buf[i++] = 0x60; buf[i++] = 0x08;
        buf[i++] = 0x58;

        buf[i++] = 0x9C;

        buf[i++] = 0x50;
        buf[i++] = 0x51;
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;

        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;


        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0xA6; buf[i++] = 0x00; buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;

        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x20;
        i += 4;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x58;
        buf[i++] = 0x50;

        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = epilogue_addr;
        i += 8;
        buf[i++] = 0x50;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x1E;

        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = jmp_rbx_gadget;
        i += 8;

        buf[i++] = 0xFF; buf[i++] = 0xE0;

        return i;
    }

    __forceinline SIZE_T build_epilogue_v2(PUINT8 buf, UINT64 ctx_addr) {
        SIZE_T i = 0;

        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xC4; buf[i++] = 0x10;

        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;

        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;


        buf[i++] = 0xF3; buf[i++] = 0x90;

        buf[i++] = 0xEB; buf[i++] = 0xFC;

        return i;
    }

    __forceinline SIZE_T build_direct_call(PUINT8 buf, UINT64 ctx_addr, UINT64 epilogue_addr) {
        UNREFERENCED_PARAMETER(epilogue_addr);
        SIZE_T i = 0;

        buf[i++] = 0x50;
        buf[i++] = 0x48; buf[i++] = 0xB8;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;
        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x60; buf[i++] = 0x60;
        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0x40; buf[i++] = 0x60; buf[i++] = 0x08;
        buf[i++] = 0x58;

        buf[i++] = 0x9C;

        buf[i++] = 0x50;
        buf[i++] = 0x51;
        buf[i++] = 0x52;
        buf[i++] = 0x53;
        buf[i++] = 0x55;
        buf[i++] = 0x56;
        buf[i++] = 0x57;
        buf[i++] = 0x41; buf[i++] = 0x50;
        buf[i++] = 0x41; buf[i++] = 0x51;
        buf[i++] = 0x41; buf[i++] = 0x52;
        buf[i++] = 0x41; buf[i++] = 0x53;
        buf[i++] = 0x41; buf[i++] = 0x54;
        buf[i++] = 0x41; buf[i++] = 0x55;
        buf[i++] = 0x41; buf[i++] = 0x56;
        buf[i++] = 0x41; buf[i++] = 0x57;

        buf[i++] = 0x48; buf[i++] = 0xBE;
        *(UINT64*)&buf[i] = ctx_addr;
        i += 8;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x5E; buf[i++] = 0x48;


        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0xA6; buf[i++] = 0x00; buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x83; buf[i++] = 0xE4; buf[i++] = 0xF0;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC; buf[i++] = 0x80; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x66; buf[i++] = 0x38;

        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x04; buf[i++] = 0x24;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x4C; buf[i++] = 0x24; buf[i++] = 0x10;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x54; buf[i++] = 0x24; buf[i++] = 0x20;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x5C; buf[i++] = 0x24; buf[i++] = 0x30;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x64; buf[i++] = 0x24; buf[i++] = 0x40;
        buf[i++] = 0x0F; buf[i++] = 0x29; buf[i++] = 0x6C; buf[i++] = 0x24; buf[i++] = 0x50;

        buf[i++] = 0x48; buf[i++] = 0x81; buf[i++] = 0xEC;
        *(UINT32*)&buf[i] = 0x20;
        i += 4;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x10;
        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x56; buf[i++] = 0x18;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x46; buf[i++] = 0x20;
        buf[i++] = 0x4C; buf[i++] = 0x8B; buf[i++] = 0x4E; buf[i++] = 0x28;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x06;

        buf[i++] = 0xFF; buf[i++] = 0xD0;

        buf[i++] = 0x48; buf[i++] = 0x89; buf[i++] = 0x46; buf[i++] = 0x30;

        buf[i++] = 0x48; buf[i++] = 0x8B; buf[i++] = 0x5E; buf[i++] = 0x48;

        buf[i++] = 0x48; buf[i++] = 0xC7; buf[i++] = 0x46; buf[i++] = 0x50;
        buf[i++] = 0x01; buf[i++] = 0x00; buf[i++] = 0x00; buf[i++] = 0x00;

        buf[i++] = 0x0F; buf[i++] = 0xAE; buf[i++] = 0xF0;


        buf[i++] = 0xF3; buf[i++] = 0x90;

        buf[i++] = 0xEB; buf[i++] = 0xFC;

        return i;
    }
}

NTSTATUS functions::handle7781(p_remote_call request) {
    if (!request) {
        RC_ERR("handle7781: null request");
        SD_LOG("RC7781_REJECT phase=null_request status=0x%08lx pid=%llu tid=%llu irql=%lu",
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
            static_cast<ULONG>(KeGetCurrentIrql()));
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER rc_freq{};
    LARGE_INTEGER rc_start = KeQueryPerformanceCounter(&rc_freq);
    const UINT64 rc_fp = rc_diag_fingerprint_remote(request);
    SD_LOG("RC7781_ENTRY fp=0x%llx pid=%llu tid=%llu irql=%lu dtb=0x%llx target=0x%llx shellcode=0x%llx spoof=0x%llx original_rip=0x%llx args=0x%llx,0x%llx,0x%llx,0x%llx",
        rc_fp,
        static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
        static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
        static_cast<ULONG>(KeGetCurrentIrql()),
        request->dtb,
        request->target_function,
        request->shellcode_address,
        request->spoof_return,
        request->original_rip,
        request->arg1,
        request->arg2,
        request->arg3,
        request->arg4);

    RC_DBG("handle7781: target_func=0x%llX shellcode_addr=0x%llX dtb=0x%llX spoof=0x%llX",
        request->target_function, request->shellcode_address, request->dtb, request->spoof_return);
    RC_DBG("handle7781: args: 0x%llX, 0x%llX, 0x%llX, 0x%llX",
        request->arg1, request->arg2, request->arg3, request->arg4);
    RC_DBG("handle7781: original_rip=0x%llX", request->original_rip);

    if (!call_guard::is_valid_code_ptr(request->target_function)) {
        RC_ERR("handle7781: invalid target_function 0x%llX", request->target_function);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=target_function status=0x%08lx target=0x%llx elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_INVALID_ADDRESS),
            request->target_function,
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_INVALID_ADDRESS;
    }

    if (!call_guard::is_valid_dtb(request->dtb)) {
        RC_ERR("handle7781: invalid dtb 0x%llX", request->dtb);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=dtb status=0x%08lx dtb=0x%llx elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            request->dtb,
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (request->shellcode_address == 0) {
        RC_ERR("handle7781: shellcode_address is 0");
        SD_LOG("RC7781_REJECT fp=0x%llx phase=shellcode_zero status=0x%08lx elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (!call_guard::is_valid_user_range(request->shellcode_address)) {
        RC_ERR("handle7781: shellcode_address 0x%llX out of user range", request->shellcode_address);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=shellcode_range status=0x%08lx shellcode=0x%llx elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_INVALID_ADDRESS),
            request->shellcode_address,
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 dtb_clean = request->dtb & ~0xFFFULL;
    UINT64 base_addr = request->shellcode_address;
    UINT64 context_addr = base_addr;
    UINT64 code_addr = base_addr + 0x200;
    UINT64 epilogue_addr = base_addr + 0x600;

    CALL_CONTEXT ctx = { 0 };
    ctx.target_func = request->target_function;
    ctx.spoof_gadget = request->spoof_return;
    ctx.param1 = request->arg1;
    ctx.param2 = request->arg2;
    ctx.param3 = request->arg3;
    ctx.param4 = request->arg4;
    ctx.ret_value = 0;
    ctx.saved_rsp = 0;
    ctx.original_rip = request->original_rip;
    ctx.rbx_backup = 0;
    ctx.exec_done = 0;
    ctx.trampoline_addr = epilogue_addr;
    for (int k = 0; k < 8; k++) ctx.stack_backup[k] = 0;
    for (int k = 0; k < 12; k++) ctx.xmm_backup[k] = 0;
    for (int k = 0; k < 8; k++) ctx.reserved[k] = 0;

    UINT8 shellcode[768];
    SIZE_T sc_size = 0;

    if (request->spoof_return != 0 && call_guard::is_valid_code_ptr(request->spoof_return)) {
        RC_DBG("handle7781: using JMP RBX spoofed call, gadget=0x%llX", request->spoof_return);
        sc_size = shellcode_builder::build_jmp_rbx_spoofed(shellcode, context_addr, request->spoof_return, epilogue_addr);
    } else {
        RC_DBG("handle7781: using direct call");
        sc_size = shellcode_builder::build_direct_call(shellcode, context_addr, epilogue_addr);
    }

    if (sc_size == 0 || sc_size > sizeof(shellcode)) {
        RC_ERR("handle7781: shellcode build failed, sc_size=%llu", (UINT64)sc_size);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=shellcode_build status=0x%08lx sc_size=%llu max=%llu elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_UNSUCCESSFUL),
            static_cast<UINT64>(sc_size),
            static_cast<UINT64>(sizeof(shellcode)),
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_UNSUCCESSFUL;
    }

    RC_DBG("handle7781: shellcode built, size=%llu bytes", (UINT64)sc_size);

    UINT8 epilogue[256];
    SIZE_T ep_size = shellcode_builder::build_epilogue_v2(epilogue, context_addr);

    if (ep_size == 0 || ep_size > sizeof(epilogue)) {
        RC_ERR("handle7781: epilogue build failed, ep_size=%llu", (UINT64)ep_size);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=epilogue_build status=0x%08lx ep_size=%llu max=%llu elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_UNSUCCESSFUL),
            static_cast<UINT64>(ep_size),
            static_cast<UINT64>(sizeof(epilogue)),
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_UNSUCCESSFUL;
    }

    RC_DBG("handle7781: epilogue built, size=%llu bytes", (UINT64)ep_size);
    RC_DBG("handle7781: layout base=0x%llX ctx=0x%llX code=0x%llX epi=0x%llX",
        base_addr, context_addr, code_addr, epilogue_addr);
    SD_LOG("RC7781_LAYOUT fp=0x%llx dtb_clean=0x%llx base=0x%llx ctx=0x%llx code=0x%llx epi=0x%llx sc_size=%llu ep_size=%llu spoof_valid=%u elapsed_us=%llu",
        rc_fp,
        dtb_clean,
        base_addr,
        context_addr,
        code_addr,
        epilogue_addr,
        static_cast<UINT64>(sc_size),
        static_cast<UINT64>(ep_size),
        (request->spoof_return != 0 && call_guard::is_valid_code_ptr(request->spoof_return)) ? 1u : 0u,
        rc_diag_elapsed_us(rc_start, rc_freq));

    SIZE_T bytes_written = 0;
    NTSTATUS status = STATUS_UNSUCCESSFUL;

    UINT64 phys_ctx = strong::translate_virtual_address(dtb_clean, context_addr);
    if (!phys_ctx) {
        RC_ERR("handle7781: translate context_addr 0x%llX failed", context_addr);
        SD_LOG("RC7781_REJECT fp=0x%llx phase=translate_context status=0x%08lx ctx=0x%llx elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(STATUS_INVALID_ADDRESS),
            context_addr,
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_INVALID_ADDRESS;
    }

    SD_LOG("RC7781_WRITE_CONTEXT_BEGIN fp=0x%llx ctx=0x%llx phys=0x%llx bytes=%llu elapsed_us=%llu",
        rc_fp,
        context_addr,
        phys_ctx,
        static_cast<UINT64>(sizeof(ctx)),
        rc_diag_elapsed_us(rc_start, rc_freq));
    status = strong::write_physical((PVOID)phys_ctx, &ctx, sizeof(ctx), &bytes_written);
    if (!NT_SUCCESS(status) || bytes_written != sizeof(ctx)) {
        RC_ERR("handle7781: write context failed st=0x%08X written=%llu/%llu",
            status, (UINT64)bytes_written, (UINT64)sizeof(ctx));
        SD_LOG("RC7781_REJECT fp=0x%llx phase=write_context status=0x%08lx ctx=0x%llx phys=0x%llx written=%llu expected=%llu elapsed_us=%llu",
            rc_fp,
            static_cast<ULONG>(status),
            context_addr,
            phys_ctx,
            static_cast<UINT64>(bytes_written),
            static_cast<UINT64>(sizeof(ctx)),
            rc_diag_elapsed_us(rc_start, rc_freq));
        return STATUS_UNSUCCESSFUL;
    }

    RC_DBG("handle7781: context written to phys=0x%llX (%llu bytes)", phys_ctx, (UINT64)bytes_written);
    SD_LOG("RC7781_WRITE_CONTEXT_DONE fp=0x%llx ctx=0x%llx phys=0x%llx written=%llu elapsed_us=%llu",
        rc_fp,
        context_addr,
        phys_ctx,
        static_cast<UINT64>(bytes_written),
        rc_diag_elapsed_us(rc_start, rc_freq));

    SIZE_T remaining = sc_size;
    SIZE_T offset = 0;

    while (remaining > 0) {
        UINT64 current_va = code_addr + offset;
        UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, current_va);

        if (!physical_addr) {
            RC_ERR("handle7781: translate shellcode VA 0x%llX failed at offset=%llu", current_va, (UINT64)offset);
            SD_LOG("RC7781_REJECT fp=0x%llx phase=translate_shellcode status=0x%08lx va=0x%llx offset=%llu remaining=%llu elapsed_us=%llu",
                rc_fp,
                static_cast<ULONG>(STATUS_INVALID_ADDRESS),
                current_va,
                static_cast<UINT64>(offset),
                static_cast<UINT64>(remaining),
                rc_diag_elapsed_us(rc_start, rc_freq));
            return STATUS_INVALID_ADDRESS;
        }

        SIZE_T page_offset = physical_addr & 0xFFF;
        SIZE_T bytes_in_page = 0x1000 - page_offset;
        SIZE_T write_size = (bytes_in_page < remaining) ? bytes_in_page : remaining;

        SIZE_T written = 0;
        status = strong::write_physical(
            (PVOID)physical_addr,
            &shellcode[offset],
            write_size,
            &written
        );

        if (!NT_SUCCESS(status)) {
            RC_ERR("handle7781: write shellcode failed st=0x%08X at VA=0x%llX phys=0x%llX", status, current_va, physical_addr);
            SD_LOG("RC7781_REJECT fp=0x%llx phase=write_shellcode status=0x%08lx va=0x%llx phys=0x%llx offset=%llu write_size=%llu written=%llu elapsed_us=%llu",
                rc_fp,
                static_cast<ULONG>(status),
                current_va,
                physical_addr,
                static_cast<UINT64>(offset),
                static_cast<UINT64>(write_size),
                static_cast<UINT64>(written),
                rc_diag_elapsed_us(rc_start, rc_freq));
            return status;
        }

        remaining -= written;
        offset += written;
    }

    RC_DBG("handle7781: shellcode written to code_addr=0x%llX (%llu bytes)", code_addr, (UINT64)sc_size);
    SD_LOG("RC7781_WRITE_SHELLCODE_DONE fp=0x%llx code=0x%llx bytes=%llu elapsed_us=%llu",
        rc_fp,
        code_addr,
        static_cast<UINT64>(sc_size),
        rc_diag_elapsed_us(rc_start, rc_freq));

    remaining = ep_size;
    offset = 0;

    while (remaining > 0) {
        UINT64 current_va = epilogue_addr + offset;
        UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, current_va);

        if (!physical_addr) {
            RC_ERR("handle7781: translate epilogue VA 0x%llX failed at offset=%llu", current_va, (UINT64)offset);
            SD_LOG("RC7781_REJECT fp=0x%llx phase=translate_epilogue status=0x%08lx va=0x%llx offset=%llu remaining=%llu elapsed_us=%llu",
                rc_fp,
                static_cast<ULONG>(STATUS_INVALID_ADDRESS),
                current_va,
                static_cast<UINT64>(offset),
                static_cast<UINT64>(remaining),
                rc_diag_elapsed_us(rc_start, rc_freq));
            return STATUS_INVALID_ADDRESS;
        }

        SIZE_T page_offset = physical_addr & 0xFFF;
        SIZE_T bytes_in_page = 0x1000 - page_offset;
        SIZE_T write_size = (bytes_in_page < remaining) ? bytes_in_page : remaining;

        SIZE_T written = 0;
        status = strong::write_physical(
            (PVOID)physical_addr,
            &epilogue[offset],
            write_size,
            &written
        );

        if (!NT_SUCCESS(status)) {
            RC_ERR("handle7781: write epilogue failed st=0x%08X at VA=0x%llX phys=0x%llX", status, current_va, physical_addr);
            SD_LOG("RC7781_REJECT fp=0x%llx phase=write_epilogue status=0x%08lx va=0x%llx phys=0x%llx offset=%llu write_size=%llu written=%llu elapsed_us=%llu",
                rc_fp,
                static_cast<ULONG>(status),
                current_va,
                physical_addr,
                static_cast<UINT64>(offset),
                static_cast<UINT64>(write_size),
                static_cast<UINT64>(written),
                rc_diag_elapsed_us(rc_start, rc_freq));
            return status;
        }

        remaining -= written;
        offset += written;
    }

    RC_DBG("handle7781: epilogue written to epilogue_addr=0x%llX (%llu bytes)", epilogue_addr, (UINT64)ep_size);
    SD_LOG("RC7781_WRITE_EPILOGUE_DONE fp=0x%llx epilogue=0x%llx bytes=%llu elapsed_us=%llu",
        rc_fp,
        epilogue_addr,
        static_cast<UINT64>(ep_size),
        rc_diag_elapsed_us(rc_start, rc_freq));

    KeMemoryBarrier();
    _mm_mfence();


    {
        UINT64 verify_phys = strong::translate_virtual_address(dtb_clean, code_addr);
        if (verify_phys) {
            UINT8 verify_buf[16] = { 0 };
            SIZE_T verify_read = 0;
            NTSTATUS vst = strong::read_physical(verify_phys, verify_buf, sizeof(verify_buf), &verify_read);
            if (NT_SUCCESS(vst) && verify_read >= 16) {
                RC_DBG("handle7781: verify code[0..15]: %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                    verify_buf[0], verify_buf[1], verify_buf[2], verify_buf[3],
                    verify_buf[4], verify_buf[5], verify_buf[6], verify_buf[7],
                    verify_buf[8], verify_buf[9], verify_buf[10], verify_buf[11],
                    verify_buf[12], verify_buf[13], verify_buf[14], verify_buf[15]);
                RC_DBG("handle7781: expected[0..15]:  %02X %02X %02X %02X %02X %02X %02X %02X  %02X %02X %02X %02X %02X %02X %02X %02X",
                    shellcode[0], shellcode[1], shellcode[2], shellcode[3],
                    shellcode[4], shellcode[5], shellcode[6], shellcode[7],
                    shellcode[8], shellcode[9], shellcode[10], shellcode[11],
                    shellcode[12], shellcode[13], shellcode[14], shellcode[15]);
            } else {
                RC_ERR("handle7781: verify read-back failed st=0x%08X read=%llu", vst, (UINT64)verify_read);
            }
        } else {
            RC_ERR("handle7781: verify translate code_addr 0x%llX failed", code_addr);
        }
    }

    request->shellcode_address = code_addr;
    request->result = 0;
    request->completed = 0;

    RC_DBG("handle7781: SUCCESS -- entry=0x%llX ctx=0x%llX epi=0x%llX target=0x%llX",
        code_addr, context_addr, epilogue_addr, request->target_function);
    SD_LOG("RC7781_SUCCESS fp=0x%llx entry=0x%llx ctx=0x%llx epilogue=0x%llx target=0x%llx result=0x%llx completed=%llu elapsed_us=%llu",
        rc_fp,
        code_addr,
        context_addr,
        epilogue_addr,
        request->target_function,
        request->result,
        request->completed,
        rc_diag_elapsed_us(rc_start, rc_freq));

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle7782(p_call_result request) {
    if (!request) {
        RC_ERR("handle7782: null request");
        SD_LOG("RC7782_REJECT phase=null_request status=0x%08lx pid=%llu tid=%llu irql=%lu",
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
            static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
            static_cast<ULONG>(KeGetCurrentIrql()));
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER cr_freq{};
    LARGE_INTEGER cr_start = KeQueryPerformanceCounter(&cr_freq);
    const UINT64 cr_fp = rc_diag_fingerprint_result(request);
    SD_LOG("RC7782_ENTRY fp=0x%llx pid=%llu tid=%llu irql=%lu dtb=0x%llx result_addr=0x%llx completed_in=%llu result_in=0x%llx",
        cr_fp,
        static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
        static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
        static_cast<ULONG>(KeGetCurrentIrql()),
        request->dtb,
        request->result_address,
        request->completed,
        request->result);

    if (!call_guard::is_valid_dtb(request->dtb)) {
        RC_ERR("handle7782: invalid dtb 0x%llX", request->dtb);
        SD_LOG("RC7782_REJECT fp=0x%llx phase=dtb status=0x%08lx dtb=0x%llx elapsed_us=%llu",
            cr_fp,
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            request->dtb,
            rc_diag_elapsed_us(cr_start, cr_freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (request->result_address == 0) {
        RC_ERR("handle7782: result_address is 0");
        SD_LOG("RC7782_REJECT fp=0x%llx phase=result_zero status=0x%08lx elapsed_us=%llu",
            cr_fp,
            static_cast<ULONG>(STATUS_INVALID_PARAMETER),
            rc_diag_elapsed_us(cr_start, cr_freq));
        return STATUS_INVALID_PARAMETER;
    }

    if (!call_guard::is_valid_user_range(request->result_address)) {
        RC_ERR("handle7782: result_address 0x%llX out of user range", request->result_address);
        SD_LOG("RC7782_REJECT fp=0x%llx phase=result_range status=0x%08lx result_addr=0x%llx elapsed_us=%llu",
            cr_fp,
            static_cast<ULONG>(STATUS_INVALID_ADDRESS),
            request->result_address,
            rc_diag_elapsed_us(cr_start, cr_freq));
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 dtb_clean = request->dtb & ~0xFFFULL;
    UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, request->result_address);

    if (!physical_addr) {
        RC_ERR("handle7782: translate result_address 0x%llX failed", request->result_address);
        SD_LOG("RC7782_REJECT fp=0x%llx phase=translate_result status=0x%08lx result_addr=0x%llx elapsed_us=%llu",
            cr_fp,
            static_cast<ULONG>(STATUS_INVALID_ADDRESS),
            request->result_address,
            rc_diag_elapsed_us(cr_start, cr_freq));
        return STATUS_INVALID_ADDRESS;
    }

    CALL_CONTEXT ctx = { 0 };
    SIZE_T bytes_read = 0;

    KeMemoryBarrier();

    NTSTATUS status = strong::read_physical(
        physical_addr,
        &ctx,
        sizeof(ctx),
        &bytes_read
    );

    if (!NT_SUCCESS(status) || bytes_read != sizeof(ctx)) {
        RC_ERR("handle7782: read_physical failed st=0x%08X read=%llu/%llu",
            status, (UINT64)bytes_read, (UINT64)sizeof(ctx));
        SD_LOG("RC7782_REJECT fp=0x%llx phase=read_context status=0x%08lx result_addr=0x%llx phys=0x%llx read=%llu expected=%llu elapsed_us=%llu",
            cr_fp,
            static_cast<ULONG>(status),
            request->result_address,
            physical_addr,
            static_cast<UINT64>(bytes_read),
            static_cast<UINT64>(sizeof(ctx)),
            rc_diag_elapsed_us(cr_start, cr_freq));
        return STATUS_UNSUCCESSFUL;
    }

    KeMemoryBarrier();

    volatile UINT64 done_flag = ctx.exec_done;
    request->completed = 0;
    request->result = 0;

    if (done_flag != 0) {
        request->result = ctx.ret_value;
        request->completed = 1;
        RC_DBG("handle7782: DONE exec_done=0x%llX ret_value=0x%llX", (UINT64)done_flag, ctx.ret_value);
    } else {

    }

    SD_LOG("RC7782_DONE fp=0x%llx result_addr=0x%llx phys=0x%llx read=%llu exec_done=0x%llx completed=%llu result=0x%llx saved_rsp=0x%llx original_rip=0x%llx elapsed_us=%llu",
        cr_fp,
        request->result_address,
        physical_addr,
        static_cast<UINT64>(bytes_read),
        static_cast<UINT64>(done_flag),
        request->completed,
        request->result,
        ctx.saved_rsp,
        ctx.original_rip,
        rc_diag_elapsed_us(cr_start, cr_freq));

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle7782_legacy(p_call_result request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!call_guard::is_valid_dtb(request->dtb)) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->result_address == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (!call_guard::is_valid_user_range(request->result_address)) {
        return STATUS_INVALID_ADDRESS;
    }

    UINT64 dtb_clean = request->dtb & ~0xFFFULL;
    UINT64 physical_addr = strong::translate_virtual_address(dtb_clean, request->result_address);

    if (!physical_addr) {
        return STATUS_INVALID_ADDRESS;
    }

    CALL_CONTEXT ctx = { 0 };
    SIZE_T bytes_read = 0;

    KeMemoryBarrier();

    NTSTATUS status = strong::read_physical(
        physical_addr,
        &ctx,
        sizeof(ctx),
        &bytes_read
    );

    if (!NT_SUCCESS(status) || bytes_read != sizeof(ctx)) {
        return STATUS_UNSUCCESSFUL;
    }

    KeMemoryBarrier();

    request->result = (ctx.exec_done != 0) ? ctx.ret_value : 0;
    return STATUS_SUCCESS;
}

namespace alloc_internal {
    inline volatile UINT64 g_alloc_key = 0x5A5A5A5A5A5A5A5AULL;

    __forceinline void timing_noise() {
        volatile ULONG spin = (__rdtsc() & 0x7) + 1;
        while (spin--) {
            YieldProcessor();
        }
    }
}

NTSTATUS functions::handle7783(p_alloc_mem request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (request->pid == 0 || request->pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->size == 0 || request->size > 0x1000000) {
        return STATUS_INVALID_BUFFER_SIZE;
    }


    if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ZwAllocateVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    alloc_internal::timing_noise();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);

    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    alloc_internal::timing_noise();

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    PVOID base_addr = nullptr;
    SIZE_T region_size = (request->size + 0xFFF) & ~0xFFFULL;

    status = _ZwAllocateVirtualMemory(
        (HANDLE)-1,
        &base_addr,
        0,
        &region_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );

    if (NT_SUCCESS(status) && base_addr) {
        __try {
            volatile UCHAR* p = (volatile UCHAR*)base_addr;
            for (SIZE_T off = 0; off < region_size; off += 0x1000) {
                p[off] = 0;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    if (NT_SUCCESS(status) && base_addr) {
        request->allocated_address = (UINT64)base_addr;
        request->actual_size = region_size;
    } else {
        request->allocated_address = 0;
        request->actual_size = 0;
    }

    SD_LOG("ALLOC_MEM_DONE pid=%u requested_size=0x%llx region_size=0x%llx base=0x%llx status=0x%08X caller_pid=%llu caller_tid=%llu",
        request->pid,
        (unsigned long long)request->size,
        (unsigned long long)region_size,
        (unsigned long long)(UINT_PTR)base_addr,
        (unsigned int)status,
        (unsigned long long)(ULONG_PTR)PsGetCurrentProcessId(),
        (unsigned long long)(ULONG_PTR)PsGetCurrentThreadId());

    return status;
}

NTSTATUS functions::handle7784(p_free_mem request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (request->pid == 0 || request->pid <= 4) {
        return STATUS_INVALID_PARAMETER;
    }

    if (request->address == 0) {
        return STATUS_INVALID_PARAMETER;
    }


    if (!call_guard::is_valid_user_range(request->address)) {
        return STATUS_INVALID_ADDRESS;
    }

    if (!_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ZwFreeVirtualMemory) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    alloc_internal::timing_noise();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);

    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    PVOID base_addr = (PVOID)request->address;
    SIZE_T region_size = 0;

    status = _ZwFreeVirtualMemory(
        (HANDLE)-1,
        &base_addr,
        &region_size,
        MEM_RELEASE
    );


    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}
