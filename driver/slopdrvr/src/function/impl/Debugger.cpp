#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../KernelLayout.h"
#include "../Struct.h"

extern "C" NTSTATUS NTAPI ZwQueryInformationProcess(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

typedef struct _SYSTEM_PROCESS_INFORMATION_LOCAL {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    UCHAR Reserved1[48];
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    PVOID Reserved2;
    ULONG HandleCount;
    ULONG SessionId;
    PVOID Reserved3;
    SIZE_T PeakVirtualSize;
    SIZE_T VirtualSize;
    ULONG Reserved4;
    SIZE_T PeakWorkingSetSize;
    SIZE_T WorkingSetSize;
    PVOID Reserved5;
    SIZE_T QuotaPagedPoolUsage;
    PVOID Reserved6;
    SIZE_T QuotaNonPagedPoolUsage;
    SIZE_T PagefileUsage;
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION_LOCAL, *PSYSTEM_PROCESS_INFORMATION_LOCAL;

typedef struct _SYSTEM_THREAD_INFORMATION_LOCAL {
    LARGE_INTEGER Reserved1[3];
    ULONG Reserved2;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG Reserved3;
    ULONG ThreadState;
    ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION_LOCAL, *PSYSTEM_THREAD_INFORMATION_LOCAL;

typedef struct _THREAD_BASIC_INFORMATION_LOCAL {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    KPRIORITY Priority;
    KPRIORITY BasePriority;
} THREAD_BASIC_INFORMATION_LOCAL, *PTHREAD_BASIC_INFORMATION_LOCAL;

static_assert(sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL) == 256, "Unexpected SYSTEM_PROCESS_INFORMATION_LOCAL size");
static_assert(sizeof(SYSTEM_THREAD_INFORMATION_LOCAL) == 80, "Unexpected SYSTEM_THREAD_INFORMATION_LOCAL size");

static constexpr ACCESS_MASK kThreadQueryInformationAccess = 0x0040;

namespace sysinfo_guard {
    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL kSystemProcessInformationClass =
        static_cast<SYSTEM_INFORMATION_CLASS_INTERNAL>(5);
    constexpr ULONG kThreadInfoTag = 'hTwW';
}

namespace tctx_diag {
    constexpr ULONG kContextBaseFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS;
    constexpr ULONG kContextDebugFlags = kContextBaseFlags | CONTEXT_DEBUG_REGISTERS;
    constexpr UINT64 kDebugRegisterMask =
        (1ULL << 18) | (1ULL << 19) | (1ULL << 20) |
        (1ULL << 21) | (1ULL << 22) | (1ULL << 23);

    struct os_version_snapshot_t {
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        ULONG major = 0;
        ULONG minor = 0;
        ULONG build = 0;
    };

    struct thread_snapshot_t {
        NTSTATUS status = STATUS_NOT_FOUND;
        BOOLEAN found = FALSE;
        ULONG scanned_processes = 0;
        ULONG scanned_threads = 0;
        ULONG process_thread_count = 0;
        ULONG thread_state = 0xFFFFFFFFu;
        ULONG wait_reason = 0xFFFFFFFFu;
        PVOID start_address = nullptr;
        KPRIORITY priority = 0;
        LONG base_priority = 0;
        HANDLE client_pid = nullptr;
        HANDLE client_tid = nullptr;
    };

    __forceinline BOOLEAN core_registers_present(const CONTEXT& ctx) {
        return ctx.Rip != 0 && ctx.Rsp != 0;
    }

    __forceinline BOOLEAN is_user_canonical(UINT64 value) {
        return value != 0 && value <= 0x00007FFFFFFFFFFFULL;
    }

    __forceinline BOOLEAN is_kernel_canonical(UINT64 value) {
        return value >= 0xFFFF800000000000ULL;
    }

    __forceinline const char* address_class(UINT64 value) {
        if (value == 0) {
            return "zero";
        }
        if (is_user_canonical(value)) {
            return "user";
        }
        if (is_kernel_canonical(value)) {
            return "kernel";
        }
        return "noncanonical";
    }

    __forceinline BOOLEAN user_context_sane(UINT64 rip, UINT64 rsp, UINT64 rflags) {
        return rflags != 0 && is_user_canonical(rip) && is_user_canonical(rsp);
    }

    __forceinline BOOLEAN user_context_sane(const CONTEXT& ctx) {
        return user_context_sane(ctx.Rip, ctx.Rsp, ctx.EFlags);
    }

    __forceinline BOOLEAN user_context_sane(const thread_ctx& ctx) {
        return user_context_sane(ctx.rip, ctx.rsp, ctx.rflags);
    }

    __forceinline BOOLEAN debug_registers_requested(UINT64 mask) {
        return (mask & kDebugRegisterMask) != 0;
    }

    __forceinline const char* ntstatus_text(NTSTATUS status) {
        switch (status) {
        case STATUS_SUCCESS: return "STATUS_SUCCESS";
        case STATUS_UNSUCCESSFUL: return "STATUS_UNSUCCESSFUL";
        case STATUS_PENDING: return "STATUS_PENDING";
        case STATUS_INVALID_PARAMETER: return "STATUS_INVALID_PARAMETER";
        case STATUS_INVALID_HANDLE: return "STATUS_INVALID_HANDLE";
        case STATUS_INVALID_CID: return "STATUS_INVALID_CID";
        case STATUS_INVALID_DEVICE_STATE: return "STATUS_INVALID_DEVICE_STATE";
        case STATUS_PROCEDURE_NOT_FOUND: return "STATUS_PROCEDURE_NOT_FOUND";
        case STATUS_NOT_FOUND: return "STATUS_NOT_FOUND";
        case STATUS_ACCESS_DENIED: return "STATUS_ACCESS_DENIED";
        case STATUS_ACCESS_VIOLATION: return "STATUS_ACCESS_VIOLATION";
        case STATUS_INVALID_ADDRESS: return "STATUS_INVALID_ADDRESS";
        case STATUS_INFO_LENGTH_MISMATCH: return "STATUS_INFO_LENGTH_MISMATCH";
        case STATUS_INSUFFICIENT_RESOURCES: return "STATUS_INSUFFICIENT_RESOURCES";
        case STATUS_THREAD_IS_TERMINATING: return "STATUS_THREAD_IS_TERMINATING";
        default: return "STATUS_OTHER";
        }
    }

    __forceinline ULONG ntstatus_win32_fallback(NTSTATUS status) {
        switch (status) {
        case STATUS_SUCCESS: return 0;
        case STATUS_PENDING: return 997;
        case STATUS_UNSUCCESSFUL: return 31;
        case STATUS_NOT_SUPPORTED: return 50;
        case STATUS_INSUFFICIENT_RESOURCES: return 8;
        case STATUS_INVALID_PARAMETER: return 87;
        case STATUS_NOT_FOUND: return 1168;
        case STATUS_OBJECT_NAME_NOT_FOUND: return 2;
        case STATUS_OBJECT_NAME_COLLISION: return 183;
        case STATUS_ACCESS_DENIED: return 5;
        case STATUS_BUFFER_TOO_SMALL: return 122;
        case STATUS_INFO_LENGTH_MISMATCH: return 24;
        case STATUS_INVALID_HANDLE: return 6;
        case STATUS_INVALID_ADDRESS: return 487;
        case STATUS_PROCEDURE_NOT_FOUND: return 127;
        case STATUS_NO_MEMORY: return 8;
        case STATUS_TIMEOUT: return 1460;
        case STATUS_CANCELLED: return 1223;
        default: return (ULONG)status;
        }
    }

    __forceinline ULONG ntstatus_win32(NTSTATUS status) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return ntstatus_win32_fallback(status);
        }
        return RtlNtStatusToDosError(status);
    }

    __forceinline ULONGLONG elapsed_ms(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart) {
            return 0;
        }
        return static_cast<ULONGLONG>(((now.QuadPart - start.QuadPart) * 1000) / freq.QuadPart);
    }

    os_version_snapshot_t query_os_version() {
        os_version_snapshot_t out;
        if (!_RtlGetVersion) {
            return out;
        }
        RTL_OSVERSIONINFOW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        out.status = _RtlGetVersion(&version);
        if (NT_SUCCESS(out.status)) {
            out.major = version.dwMajorVersion;
            out.minor = version.dwMinorVersion;
            out.build = version.dwBuildNumber;
        }
        return out;
    }

    thread_snapshot_t query_thread_snapshot(UINT32 pid, UINT32 tid) {
        thread_snapshot_t out;
        if (pid == 0 || tid == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) {
            out.status = STATUS_INVALID_PARAMETER;
            return out;
        }

        ULONG required_length = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            sysinfo_guard::kSystemProcessInformationClass,
            nullptr,
            0,
            &required_length);
        if (status != STATUS_INFO_LENGTH_MISMATCH || required_length < sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL)) {
            out.status = NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
            return out;
        }

        ULONG buffer_length = required_length + 0x4000;
        PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
        if (!buffer) {
            out.status = STATUS_INSUFFICIENT_RESOURCES;
            return out;
        }

        for (int attempt = 0; attempt < 3; ++attempt) {
            status = ZwQuerySystemInformation(
                sysinfo_guard::kSystemProcessInformationClass,
                buffer,
                buffer_length,
                &required_length);
            if (status != STATUS_INFO_LENGTH_MISMATCH) {
                break;
            }

            ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
            buffer_length = required_length + 0x4000;
            buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
            if (!buffer) {
                out.status = STATUS_INSUFFICIENT_RESOURCES;
                return out;
            }
        }

        if (!NT_SUCCESS(status)) {
            out.status = status;
            ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
            return out;
        }

        PUCHAR cursor = static_cast<PUCHAR>(buffer);
        while (TRUE) {
            auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_LOCAL>(cursor);
            out.scanned_processes++;
            if ((UINT32)(ULONG_PTR)info->UniqueProcessId == pid) {
                out.process_thread_count = info->NumberOfThreads;
                auto threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION_LOCAL>(cursor + sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL));
                for (ULONG index = 0; index < info->NumberOfThreads; ++index) {
                    out.scanned_threads++;
                    if ((UINT32)(ULONG_PTR)threads[index].ClientId.UniqueThread != tid) {
                        continue;
                    }
                    out.found = TRUE;
                    out.status = STATUS_SUCCESS;
                    out.thread_state = threads[index].ThreadState;
                    out.wait_reason = threads[index].WaitReason;
                    out.start_address = threads[index].StartAddress;
                    out.priority = threads[index].Priority;
                    out.base_priority = threads[index].BasePriority;
                    out.client_pid = threads[index].ClientId.UniqueProcess;
                    out.client_tid = threads[index].ClientId.UniqueThread;
                    break;
                }
                break;
            }

            if (info->NextEntryOffset == 0) {
                break;
            }
            cursor += info->NextEntryOffset;
        }

        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        return out;
    }

    __forceinline NTSTATUS attach_process(PEPROCESS process, PKAPC_STATE apc_state, PBOOLEAN attached) {
        *attached = FALSE;
        if (!process || !_KeStackAttachProcess || !_KeUnstackDetachProcess || process == PsGetCurrentProcess()) {
            return STATUS_SUCCESS;
        }
        NTSTATUS status = STATUS_SUCCESS;
        __try {
            _KeStackAttachProcess(process, apc_state);
            *attached = TRUE;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
            *attached = FALSE;
        }
        return status;
    }

    __forceinline void detach_process(PKAPC_STATE apc_state, BOOLEAN attached) {
        if (!attached || !_KeUnstackDetachProcess) {
            return;
        }
        __try {
            _KeUnstackDetachProcess(apc_state);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    __forceinline NTSTATUS call_ps_get(PEPROCESS process, PETHREAD thread, PCONTEXT ctx, BOOLEAN attach, NTSTATUS* attach_status, PBOOLEAN attached) {
        KAPC_STATE apc_state = {};
        *attach_status = attach ? attach_process(process, &apc_state, attached) : STATUS_SUCCESS;
        if (!NT_SUCCESS(*attach_status)) {
            return *attach_status;
        }
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        __try {
            status = _PsGetContextThread(thread, ctx, KernelMode);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        detach_process(&apc_state, *attached);
        return status;
    }

    __forceinline NTSTATUS call_ps_set(PEPROCESS process, PETHREAD thread, PCONTEXT ctx, BOOLEAN attach, NTSTATUS* attach_status, PBOOLEAN attached) {
        KAPC_STATE apc_state = {};
        *attach_status = attach ? attach_process(process, &apc_state, attached) : STATUS_SUCCESS;
        if (!NT_SUCCESS(*attach_status)) {
            return *attach_status;
        }
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        __try {
            status = _PsSetContextThread(thread, ctx, KernelMode);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
        }
        detach_process(&apc_state, *attached);
        return status;
    }

    __forceinline void log_context(const char* prefix, const char* phase, const char* source, ULONG attempt, NTSTATUS status, NTSTATUS attach_status, BOOLEAN attached, const CONTEXT& ctx, const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        SD_LOG("TCTX %s phase=%s source=%s attempt=%u status=0x%08X status_text=%s attach_status=0x%08X attach_status_text=%s attached=%u flags=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rbp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX core_valid=%u user_sane=%u elapsed_ms=%llu",
            prefix,
            phase,
            source,
            attempt,
            (ULONG)status,
            ntstatus_text(status),
            (ULONG)attach_status,
            ntstatus_text(attach_status),
            attached ? 1u : 0u,
            ctx.ContextFlags,
            (unsigned long long)ctx.Rip,
            address_class(ctx.Rip),
            (unsigned long long)ctx.Rsp,
            address_class(ctx.Rsp),
            (unsigned long long)ctx.Rbp,
            (unsigned long long)ctx.EFlags,
            (unsigned long long)ctx.Dr0,
            (unsigned long long)ctx.Dr1,
            (unsigned long long)ctx.Dr2,
            (unsigned long long)ctx.Dr3,
            (unsigned long long)ctx.Dr6,
            (unsigned long long)ctx.Dr7,
            core_registers_present(ctx) ? 1u : 0u,
            user_context_sane(ctx) ? 1u : 0u,
            elapsed_ms(start, freq));
    }
}


namespace dbg_guard {
    inline volatile ULONG g_dbg_entropy = 0xABCD1234u;

    __forceinline void timing_scatter() {
        ULONG x = g_dbg_entropy ^ (ULONG)(__rdtsc() & 0xFFFFu);
        x ^= x << 13;
        g_dbg_entropy = x;
        volatile ULONG spin = (x & 0x3) + 1;
        while (spin--) YieldProcessor();
    }

    __forceinline ULONGLONG elapsed_ms(const LARGE_INTEGER& start, const LARGE_INTEGER& freq) {
        LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
        if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart) {
            return 0;
        }
        return static_cast<ULONGLONG>(((now.QuadPart - start.QuadPart) * 1000) / freq.QuadPart);
    }

    __forceinline void short_context_retry_delay() {
        LARGE_INTEGER delay;
        delay.QuadPart = -10000;
        KeDelayExecutionThread(KernelMode, FALSE, &delay);
    }
}


namespace trapframe_ctx {

    constexpr ULONG DR7_USER_MASK            = 0xFFFF0355;
    constexpr UINT64 DR7_GLOBAL_ENABLE_BITS  = 0xAAULL;

    __forceinline UINT64 sanitize_user_dr7(UINT64 dr7) {
        return (dr7 & DR7_USER_MASK) & ~DR7_GLOBAL_ENABLE_BITS;
    }

    __forceinline void copy_context_to_request(const CONTEXT& ctx, p_thread_ctx request) {
        request->rax = ctx.Rax;
        request->rbx = ctx.Rbx;
        request->rcx = ctx.Rcx;
        request->rdx = ctx.Rdx;
        request->rsi = ctx.Rsi;
        request->rdi = ctx.Rdi;
        request->rbp = ctx.Rbp;
        request->rsp = ctx.Rsp;
        request->r8  = ctx.R8;
        request->r9  = ctx.R9;
        request->r10 = ctx.R10;
        request->r11 = ctx.R11;
        request->r12 = ctx.R12;
        request->r13 = ctx.R13;
        request->r14 = ctx.R14;
        request->r15 = ctx.R15;
        request->rip = ctx.Rip;
        request->rflags = ctx.EFlags;
        request->cs  = ctx.SegCs;
        request->ss  = ctx.SegSs;
        request->dr0 = ctx.Dr0;
        request->dr1 = ctx.Dr1;
        request->dr2 = ctx.Dr2;
        request->dr3 = ctx.Dr3;
        request->dr6 = ctx.Dr6;
        request->dr7 = ctx.Dr7;
    }

    __forceinline void apply_request_to_context(p_thread_ctx request, PCONTEXT ctx) {
        UINT64 mask = request->register_mask;
        if (mask & (1ULL << 0))  ctx->Rax    = request->rax;
        if (mask & (1ULL << 1))  ctx->Rbx    = request->rbx;
        if (mask & (1ULL << 2))  ctx->Rcx    = request->rcx;
        if (mask & (1ULL << 3))  ctx->Rdx    = request->rdx;
        if (mask & (1ULL << 4))  ctx->Rsi    = request->rsi;
        if (mask & (1ULL << 5))  ctx->Rdi    = request->rdi;
        if (mask & (1ULL << 6))  ctx->Rbp    = request->rbp;
        if (mask & (1ULL << 7))  ctx->Rsp    = request->rsp;
        if (mask & (1ULL << 8))  ctx->R8     = request->r8;
        if (mask & (1ULL << 9))  ctx->R9     = request->r9;
        if (mask & (1ULL << 10)) ctx->R10    = request->r10;
        if (mask & (1ULL << 11)) ctx->R11    = request->r11;
        if (mask & (1ULL << 12)) ctx->R12    = request->r12;
        if (mask & (1ULL << 13)) ctx->R13    = request->r13;
        if (mask & (1ULL << 14)) ctx->R14    = request->r14;
        if (mask & (1ULL << 15)) ctx->R15    = request->r15;
        if (mask & (1ULL << 16)) ctx->Rip    = request->rip;
        if (mask & (1ULL << 17)) ctx->EFlags = (ULONG)request->rflags;
        if (mask & (1ULL << 18)) ctx->Dr0    = request->dr0;
        if (mask & (1ULL << 19)) ctx->Dr1    = request->dr1;
        if (mask & (1ULL << 20)) ctx->Dr2    = request->dr2;
        if (mask & (1ULL << 21)) ctx->Dr3    = request->dr3;
        if (mask & (1ULL << 22)) ctx->Dr6    = request->dr6;
        if (mask & (1ULL << 23)) ctx->Dr7    = sanitize_user_dr7(request->dr7);
    }

    struct native_context_attempt_t {
        const char* source;
        ULONG flags;
        BOOLEAN ps_path;
        BOOLEAN attach;
    };

    NTSTATUS read_native_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, PCONTEXT ctx, p_thread_ctx request, const char* phase, BOOLEAN private_user_only) {
        if (!process || !thread || !ctx || !request) {
            return STATUS_INVALID_PARAMETER;
        }

        LARGE_INTEGER phase_freq = {};
        LARGE_INTEGER phase_start = KeQueryPerformanceCounter(&phase_freq);
        KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
        NTSTATUS ps_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS nt_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        const char* selected_source = "none";
        ULONG selected_flags = 0;
        BOOLEAN selected_attached = FALSE;
        BOOLEAN zero_context_seen = FALSE;
        BOOLEAN invalid_user_context_seen = FALSE;
        tctx_diag::thread_snapshot_t read_thread_before = tctx_diag::query_thread_snapshot(request->pid, request->tid);
        ULONG import_missing_count = 0;
        ULONG handle_missing_count = 0;
        ULONG call_failure_count = 0;
        ULONG attach_failure_count = 0;
        ULONG zero_context_count = 0;
        ULONG invalid_user_context_count = 0;
        NTSTATUS last_failure_status = STATUS_SUCCESS;
        NTSTATUS last_attach_status = STATUS_SUCCESS;
        const char* last_failure_source = "none";
        const char* first_zero_context_source = "none";
        const char* first_invalid_user_context_source = "none";
        native_context_attempt_t attempts[] = {
            { "ps_kernel_debug", tctx_diag::kContextDebugFlags, TRUE, FALSE },
            { "ps_attach_debug", tctx_diag::kContextDebugFlags, TRUE, TRUE },
            { "ps_kernel_base", tctx_diag::kContextBaseFlags, TRUE, FALSE },
            { "ps_attach_base", tctx_diag::kContextBaseFlags, TRUE, TRUE },
            { "nt_handle_debug", tctx_diag::kContextDebugFlags, FALSE, FALSE },
            { "nt_handle_base", tctx_diag::kContextBaseFlags, FALSE, FALSE },
            { "ps_kernel_legacy", CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, TRUE, FALSE },
            { "ps_attach_legacy", CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS, TRUE, TRUE }
        };
        ULONG attempt_index = 0;
        const BOOLEAN private_user_read_available = ssdt_resolver::resolve_user_context();

        SD_LOG("TCTX %s read_begin pid=%u tid=%u previous_mode=%u requestor_mode=%u private_user_only=%u private_user_read_available=%u thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu process_thread_count=%lu scanned_processes=%lu scanned_threads=%lu ps_get=%p user_get=%p internal_direct=%p zw_get=%p nt_get=%p handle=%p attach_available=%u ps_get_absent=%u nt_get_resolver_absent=%u handle_absent=%u",
            phase,
            request->pid,
            request->tid,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            private_user_only ? 1u : 0u,
            private_user_read_available ? 1u : 0u,
            read_thread_before.found ? 1u : 0u,
            (ULONG)read_thread_before.status,
            tctx_diag::ntstatus_text(read_thread_before.status),
            read_thread_before.thread_state,
            read_thread_before.wait_reason,
            read_thread_before.process_thread_count,
            read_thread_before.scanned_processes,
            read_thread_before.scanned_threads,
            _PsGetContextThread,
            ssdt_resolver::g_PsGetUserContextThread,
            ssdt_resolver::g_PspGetContextThreadInternal,
            _ZwGetContextThread,
            ssdt_resolver::g_NtGetContextThread,
            thread_handle,
            (_KeStackAttachProcess && _KeUnstackDetachProcess) ? 1u : 0u,
            _PsGetContextThread ? 0u : 1u,
            (_ZwGetContextThread || ssdt_resolver::g_NtGetContextThread) ? 0u : 1u,
            thread_handle ? 0u : 1u);

        if (private_user_read_available) {
            for (ULONG retry = 0; retry < 4; ++retry) {
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = tctx_diag::kContextDebugFlags;
                status = ssdt_resolver::call_PsGetUserContextThread(thread, ctx);
                tctx_diag::log_context("read_attempt", phase, "ps_private_user_debug", attempt_index++, status, STATUS_SUCCESS, FALSE, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status) && tctx_diag::user_context_sane(*ctx)) {
                    SD_LOG("TCTX %s read_selected source=ps_private_user_debug status=0x%08X flags=0x%08X attached=0 rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=1 elapsed_ms=%llu",
                        phase,
                        (ULONG)status,
                        ctx->ContextFlags,
                        (unsigned long long)ctx->Rip,
                        tctx_diag::address_class(ctx->Rip),
                        (unsigned long long)ctx->Rsp,
                        tctx_diag::address_class(ctx->Rsp),
                        (unsigned long long)ctx->EFlags,
                        dbg_guard::elapsed_ms(phase_start, phase_freq));
                    return status;
                }
                if (NT_SUCCESS(status)) {
                    if (!tctx_diag::core_registers_present(*ctx)) {
                        zero_context_seen = TRUE;
                        ++zero_context_count;
                        if (zero_context_count == 1) {
                            first_zero_context_source = "ps_private_user_debug";
                        }
                        last_failure_status = STATUS_UNSUCCESSFUL;
                        status = STATUS_UNSUCCESSFUL;
                    } else {
                        invalid_user_context_seen = TRUE;
                        ++invalid_user_context_count;
                        if (invalid_user_context_count == 1) {
                            first_invalid_user_context_source = "ps_private_user_debug";
                        }
                        last_failure_status = STATUS_INVALID_ADDRESS;
                        status = STATUS_INVALID_ADDRESS;
                    }
                    last_attach_status = STATUS_SUCCESS;
                    last_failure_source = "ps_private_user_debug";
                } else {
                    ++call_failure_count;
                    last_failure_status = status;
                    last_attach_status = STATUS_SUCCESS;
                    last_failure_source = "ps_private_user_debug";
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }

            for (ULONG retry = 0; retry < 3; ++retry) {
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = tctx_diag::kContextBaseFlags;
                status = ssdt_resolver::call_PsGetUserContextThread(thread, ctx);
                tctx_diag::log_context("read_attempt", phase, "ps_private_user_base", attempt_index++, status, STATUS_SUCCESS, FALSE, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status) && tctx_diag::user_context_sane(*ctx)) {
                    SD_LOG("TCTX %s read_selected source=ps_private_user_base status=0x%08X flags=0x%08X attached=0 rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=1 elapsed_ms=%llu",
                        phase,
                        (ULONG)status,
                        ctx->ContextFlags,
                        (unsigned long long)ctx->Rip,
                        tctx_diag::address_class(ctx->Rip),
                        (unsigned long long)ctx->Rsp,
                        tctx_diag::address_class(ctx->Rsp),
                        (unsigned long long)ctx->EFlags,
                        dbg_guard::elapsed_ms(phase_start, phase_freq));
                    return status;
                }
                if (NT_SUCCESS(status)) {
                    if (!tctx_diag::core_registers_present(*ctx)) {
                        zero_context_seen = TRUE;
                        ++zero_context_count;
                        if (zero_context_count == 1) {
                            first_zero_context_source = "ps_private_user_base";
                        }
                        last_failure_status = STATUS_UNSUCCESSFUL;
                        status = STATUS_UNSUCCESSFUL;
                    } else {
                        invalid_user_context_seen = TRUE;
                        ++invalid_user_context_count;
                        if (invalid_user_context_count == 1) {
                            first_invalid_user_context_source = "ps_private_user_base";
                        }
                        last_failure_status = STATUS_INVALID_ADDRESS;
                        status = STATUS_INVALID_ADDRESS;
                    }
                    last_attach_status = STATUS_SUCCESS;
                    last_failure_source = "ps_private_user_base";
                } else {
                    ++call_failure_count;
                    last_failure_status = status;
                    last_attach_status = STATUS_SUCCESS;
                    last_failure_source = "ps_private_user_base";
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
        } else {
            ++import_missing_count;
            last_failure_status = STATUS_PROCEDURE_NOT_FOUND;
            last_attach_status = STATUS_PROCEDURE_NOT_FOUND;
            last_failure_source = "ps_private_user_unresolved";
            SD_LOG("TCTX %s read_private_user_unavailable pid=%u tid=%u user_get=%p state=%ld elapsed_ms=%llu",
                phase,
                request->pid,
                request->tid,
                ssdt_resolver::g_PsGetUserContextThread,
                _InterlockedCompareExchange(&ssdt_resolver::g_user_ctx_resolved, 0, 0),
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }

        if (private_user_only) {
            SD_LOG("TCTX %s read_private_only_fail_closed pid=%u tid=%u status=0x%08X status_text=%s private_user_read_available=%u attempt_count=%lu last_source=%s last_status=0x%08X last_status_text=%s zero_context_seen=%u invalid_user_context_seen=%u previous_mode=%u requestor_mode=%u elapsed_ms=%llu",
                phase,
                request->pid,
                request->tid,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                private_user_read_available ? 1u : 0u,
                attempt_index,
                last_failure_source,
                (ULONG)last_failure_status,
                tctx_diag::ntstatus_text(last_failure_status),
                zero_context_seen ? 1u : 0u,
                invalid_user_context_seen ? 1u : 0u,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
            return private_user_read_available ? status : STATUS_PROCEDURE_NOT_FOUND;
        }

        for (ULONG route = 0; route < sizeof(attempts) / sizeof(attempts[0]); ++route) {
            const native_context_attempt_t& current = attempts[route];
            if (current.ps_path && !_PsGetContextThread) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                ps_status = status;
                ++import_missing_count;
                last_failure_status = status;
                last_attach_status = STATUS_PROCEDURE_NOT_FOUND;
                last_failure_source = current.source;
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                tctx_diag::log_context("read_missing", phase, current.source, attempt_index++, status, STATUS_PROCEDURE_NOT_FOUND, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }
            if (!current.ps_path && !thread_handle) {
                status = STATUS_INVALID_HANDLE;
                nt_status = status;
                ++handle_missing_count;
                last_failure_status = status;
                last_attach_status = STATUS_INVALID_HANDLE;
                last_failure_source = current.source;
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                tctx_diag::log_context("read_skipped", phase, current.source, attempt_index++, status, STATUS_INVALID_HANDLE, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }

            for (ULONG retry = 0; retry < 4; ++retry) {
                strong::kmemset(ctx, 0, sizeof(*ctx));
                ctx->ContextFlags = current.flags;
                NTSTATUS attach_status = STATUS_SUCCESS;
                BOOLEAN attached = FALSE;
                __try {
                    if (current.ps_path) {
                        status = tctx_diag::call_ps_get(process, thread, ctx, current.attach, &attach_status, &attached);
                        ps_status = status;
                    } else {
                        status = ssdt_resolver::call_NtGetContextThread(thread_handle, ctx);
                        nt_status = status;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = (NTSTATUS)GetExceptionCode();
                    if (current.ps_path) {
                        ps_status = status;
                    } else {
                        nt_status = status;
                    }
                }
                tctx_diag::log_context("read_attempt", phase, current.source, attempt_index++, status, attach_status, attached, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status) && tctx_diag::user_context_sane(*ctx)) {
                    selected_source = current.source;
                    selected_flags = ctx->ContextFlags;
                    selected_attached = attached;
                    SD_LOG("TCTX %s read_selected source=%s status=0x%08X flags=0x%08X attached=%u rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=1 elapsed_ms=%llu",
                        phase,
                        selected_source,
                        (ULONG)status,
                        selected_flags,
                        selected_attached ? 1u : 0u,
                        (unsigned long long)ctx->Rip,
                        tctx_diag::address_class(ctx->Rip),
                        (unsigned long long)ctx->Rsp,
                        tctx_diag::address_class(ctx->Rsp),
                        (unsigned long long)ctx->EFlags,
                        dbg_guard::elapsed_ms(phase_start, phase_freq));
                    return status;
                }
                if (NT_SUCCESS(status)) {
                    if (!tctx_diag::core_registers_present(*ctx)) {
                        zero_context_seen = TRUE;
                        ++zero_context_count;
                        if (zero_context_count == 1) {
                            first_zero_context_source = current.source;
                        }
                        last_failure_status = STATUS_UNSUCCESSFUL;
                        status = STATUS_UNSUCCESSFUL;
                    } else {
                        invalid_user_context_seen = TRUE;
                        ++invalid_user_context_count;
                        if (invalid_user_context_count == 1) {
                            first_invalid_user_context_source = current.source;
                        }
                        last_failure_status = STATUS_INVALID_ADDRESS;
                        status = STATUS_INVALID_ADDRESS;
                    }
                    last_attach_status = attach_status;
                    last_failure_source = current.source;
                } else {
                    ++call_failure_count;
                    if (!NT_SUCCESS(attach_status)) {
                        ++attach_failure_count;
                    }
                    last_failure_status = status;
                    last_attach_status = attach_status;
                    last_failure_source = current.source;
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
        }

        if (invalid_user_context_seen) {
            status = STATUS_INVALID_ADDRESS;
        } else if (zero_context_seen) {
            status = STATUS_UNSUCCESSFUL;
        }
        const UINT32 unsupported_state = (!NT_SUCCESS(status) &&
            !_PsGetContextThread && !_ZwGetContextThread && !ssdt_resolver::g_NtGetContextThread) ? 1u : 0u;
        const UINT32 zero_context = (NT_SUCCESS(status) && (ctx->Rip == 0 || ctx->Rsp == 0)) ? 1u : 0u;
        tctx_diag::thread_snapshot_t read_thread_after = tctx_diag::query_thread_snapshot(request->pid, request->tid);
        if (!NT_SUCCESS(status) || zero_context) {
            SD_LOG("TCTX %s read_failure_summary pid=%u tid=%u status=0x%08X status_text=%s attempts=%u import_missing=%lu handle_missing=%lu call_failures=%lu attach_failures=%lu zero_context_failures=%lu invalid_user_context_failures=%lu first_zero_source=%s first_invalid_user_source=%s last_source=%s last_status=0x%08X last_status_text=%s last_attach_status=0x%08X last_attach_status_text=%s ps_get_absent=%u nt_get_resolver_absent=%u handle_absent=%u thread_before_found=%u thread_before_state=%lu thread_before_wait_reason=%lu thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu rip_class=%s rsp_class=%s elapsed_ms=%llu",
                phase,
                request->pid,
                request->tid,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                attempt_index,
                import_missing_count,
                handle_missing_count,
                call_failure_count,
                attach_failure_count,
                zero_context_count,
                invalid_user_context_count,
                first_zero_context_source,
                first_invalid_user_context_source,
                last_failure_source,
                (ULONG)last_failure_status,
                tctx_diag::ntstatus_text(last_failure_status),
                (ULONG)last_attach_status,
                tctx_diag::ntstatus_text(last_attach_status),
                _PsGetContextThread ? 0u : 1u,
                (_ZwGetContextThread || ssdt_resolver::g_NtGetContextThread) ? 0u : 1u,
                thread_handle ? 0u : 1u,
                read_thread_before.found ? 1u : 0u,
                read_thread_before.thread_state,
                read_thread_before.wait_reason,
                read_thread_after.found ? 1u : 0u,
                (ULONG)read_thread_after.status,
                tctx_diag::ntstatus_text(read_thread_after.status),
                read_thread_after.thread_state,
                read_thread_after.wait_reason,
                tctx_diag::address_class(ctx->Rip),
                tctx_diag::address_class(ctx->Rsp),
                dbg_guard::elapsed_ms(phase_start, phase_freq));
            SD_LOG("TCTX %s read_fail_detail pid=%u tid=%u status=0x%08X status_text=%s ps_status=0x%08X ps_status_text=%s nt_status=0x%08X nt_status_text=%s previous_mode=%u requestor_mode=%u handle=%p unsupported_state=%u zero_context=%u zero_seen=%u invalid_user_context=%u rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX elapsed_ms=%llu",
                phase,
                request->pid,
                request->tid,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                (ULONG)ps_status,
                tctx_diag::ntstatus_text(ps_status),
                (ULONG)nt_status,
                tctx_diag::ntstatus_text(nt_status),
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                thread_handle,
                unsupported_state,
                zero_context,
                zero_context_seen ? 1u : 0u,
                invalid_user_context_seen ? 1u : 0u,
                (unsigned long long)ctx->Rip,
                tctx_diag::address_class(ctx->Rip),
                (unsigned long long)ctx->Rsp,
                tctx_diag::address_class(ctx->Rsp),
                (unsigned long long)ctx->EFlags,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }
        SD_LOG("TCTX %s read_exit status=0x%08X status_text=%s selected_source=%s selected_flags=0x%08X selected_attached=%u flags=0x%08X thread_after_found=%u thread_after_state=%lu thread_after_wait_reason=%lu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            phase,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            selected_source,
            selected_flags,
            selected_attached ? 1u : 0u,
            ctx->ContextFlags,
            read_thread_after.found ? 1u : 0u,
            read_thread_after.thread_state,
            read_thread_after.wait_reason,
            (unsigned long long)ctx->Rip,
            tctx_diag::address_class(ctx->Rip),
            (unsigned long long)ctx->Rsp,
            tctx_diag::address_class(ctx->Rsp),
            (unsigned long long)ctx->EFlags,
            tctx_diag::user_context_sane(*ctx) ? 1u : 0u,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            dbg_guard::elapsed_ms(phase_start, phase_freq));
        return status;
    }

    NTSTATUS write_native_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, PCONTEXT ctx, p_thread_ctx request, BOOLEAN private_user_only) {
        if (!process || !thread || !ctx || !request) {
            return STATUS_INVALID_PARAMETER;
        }

        LARGE_INTEGER phase_freq = {};
        LARGE_INTEGER phase_start = KeQueryPerformanceCounter(&phase_freq);
        KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
        const BOOLEAN needs_debug = tctx_diag::debug_registers_requested(request->register_mask);
        const ULONG write_flags = needs_debug ? tctx_diag::kContextDebugFlags : tctx_diag::kContextBaseFlags;
        native_context_attempt_t attempts[] = {
            { "ps_kernel_write", write_flags, TRUE, FALSE },
            { "ps_attach_write", write_flags, TRUE, TRUE },
            { "nt_handle_write", write_flags, FALSE, FALSE }
        };
        ctx->ContextFlags = write_flags;
        SD_LOG("TCTX set write_begin pid=%u tid=%u mask=0x%llX flags=0x%08X needs_debug=%u rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX previous_mode=%u requestor_mode=%u ps_set=%p zw_set=%p nt_set=%p handle=%p",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            ctx->ContextFlags,
            needs_debug ? 1u : 0u,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            _PsSetContextThread,
            _ZwSetContextThread,
            ssdt_resolver::g_NtSetContextThread,
            thread_handle);

        NTSTATUS status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS ps_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS nt_status = STATUS_PROCEDURE_NOT_FOUND;
        const char* selected_source = "none";
        ULONG selected_flags = 0;
        BOOLEAN selected_attached = FALSE;
        ULONG attempt_index = 0;
        const BOOLEAN private_user_write_available = ssdt_resolver::resolve_user_set_context();
        BOOLEAN private_write_attempted = FALSE;

        SD_LOG("TCTX set write_route_gate pid=%u tid=%u mask=0x%llX private_user_only=%u private_user_write_available=%u internal_direct=%p ps_set=%p state=%ld previous_mode=%u requestor_mode=%u ctx_thread_handle=%p elapsed_ms=%llu",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            private_user_only ? 1u : 0u,
            private_user_write_available ? 1u : 0u,
            ssdt_resolver::g_PspSetContextThreadInternal,
            _PsSetContextThread,
            _InterlockedCompareExchange(&ssdt_resolver::g_user_set_ctx_resolved, 0, 0),
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            thread_handle,
            dbg_guard::elapsed_ms(phase_start, phase_freq));

        // Debug-register writes skip the private-user shortcut when the real
        // routes are available: call_PsSetUserContextThread pokes the saved
        // context without arming the scheduler's debug-active state
        // (KTHREAD DebugActive), so DR0-DR7 set that way never reload onto
        // the CPU — the write "succeeds", reads back, and the breakpoint
        // never fires (a silent lie to the client). Prefer the real
        // PsSetContextThread routes; on hardened systems where they are all
        // denied the set fails loudly instead of pretending.
        const BOOLEAN private_route_allowed =
            private_user_write_available && !needs_debug;

        if (private_route_allowed) {
            private_write_attempted = TRUE;
            for (ULONG retry = 0; retry < 3; ++retry) {
                ctx->ContextFlags = write_flags;
                status = ssdt_resolver::call_PsSetUserContextThread(thread, ctx);
                ps_status = status;
                tctx_diag::log_context("write_attempt", "set", "ps_private_user_write", attempt_index++, status, STATUS_SUCCESS, FALSE, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status)) {
                    selected_source = "ps_private_user_write";
                    selected_flags = write_flags;
                    selected_attached = FALSE;
                    break;
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
            if (NT_SUCCESS(status)) {
                SD_LOG("TCTX set write_selected source=ps_private_user_write status=0x%08X flags=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
                    (ULONG)status,
                    ctx->ContextFlags,
                    (unsigned long long)ctx->Rip,
                    (unsigned long long)ctx->Rsp,
                    (unsigned long long)ctx->EFlags,
                    (unsigned long long)ctx->Dr0,
                    (unsigned long long)ctx->Dr1,
                    (unsigned long long)ctx->Dr2,
                    (unsigned long long)ctx->Dr3,
                    (unsigned long long)ctx->Dr6,
                    (unsigned long long)ctx->Dr7,
                    dbg_guard::elapsed_ms(phase_start, phase_freq));
                SD_LOG("TCTX set write_exit status=0x%08X selected_source=%s selected_flags=0x%08X selected_attached=%u flags=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
                    (ULONG)status,
                    selected_source,
                    selected_flags,
                    selected_attached ? 1u : 0u,
                    ctx->ContextFlags,
                    (unsigned long long)ctx->Rip,
                    (unsigned long long)ctx->Rsp,
                    (unsigned long long)ctx->EFlags,
                    (unsigned long long)ctx->Dr0,
                    (unsigned long long)ctx->Dr1,
                    (unsigned long long)ctx->Dr2,
                    (unsigned long long)ctx->Dr3,
                    (unsigned long long)ctx->Dr6,
                    (unsigned long long)ctx->Dr7,
                    dbg_guard::elapsed_ms(phase_start, phase_freq));
                return status;
            }
        } else {
            SD_LOG("TCTX set write_private_user_skipped pid=%u tid=%u private_available=%u needs_debug=%u ps_set=%p internal_direct=%p state=%ld elapsed_ms=%llu",
                request->pid,
                request->tid,
                private_user_write_available ? 1u : 0u,
                needs_debug ? 1u : 0u,
                _PsSetContextThread,
                ssdt_resolver::g_PspSetContextThreadInternal,
                _InterlockedCompareExchange(&ssdt_resolver::g_user_set_ctx_resolved, 0, 0),
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }

        if (private_user_only) {
            SD_LOG("TCTX set write_private_only_result pid=%u tid=%u status=0x%08X status_text=%s private_user_write_available=%u private_write_attempted=%u attempts=%lu ps_status=0x%08X ps_status_text=%s selected_source=%s rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX previous_mode=%u requestor_mode=%u elapsed_ms=%llu",
                request->pid,
                request->tid,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                private_user_write_available ? 1u : 0u,
                private_write_attempted ? 1u : 0u,
                attempt_index,
                (ULONG)ps_status,
                tctx_diag::ntstatus_text(ps_status),
                selected_source,
                (unsigned long long)ctx->Rip,
                (unsigned long long)ctx->Rsp,
                (unsigned long long)ctx->EFlags,
                (unsigned long long)ctx->Dr0,
                (unsigned long long)ctx->Dr1,
                (unsigned long long)ctx->Dr2,
                (unsigned long long)ctx->Dr3,
                (unsigned long long)ctx->Dr6,
                (unsigned long long)ctx->Dr7,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
            return private_user_write_available ? status : STATUS_PROCEDURE_NOT_FOUND;
        }

        for (ULONG route = 0; route < sizeof(attempts) / sizeof(attempts[0]); ++route) {
            const native_context_attempt_t& current = attempts[route];
            if (current.ps_path && !_PsSetContextThread) {
                status = STATUS_PROCEDURE_NOT_FOUND;
                ps_status = status;
                tctx_diag::log_context("write_missing", "set", current.source, attempt_index++, status, STATUS_PROCEDURE_NOT_FOUND, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }
            if (!current.ps_path && !thread_handle) {
                status = STATUS_INVALID_HANDLE;
                nt_status = status;
                tctx_diag::log_context("write_skipped", "set", current.source, attempt_index++, status, STATUS_INVALID_HANDLE, FALSE, *ctx, phase_start, phase_freq);
                continue;
            }

            for (ULONG retry = 0; retry < 3; ++retry) {
                ctx->ContextFlags = current.flags;
                NTSTATUS attach_status = STATUS_SUCCESS;
                BOOLEAN attached = FALSE;
                __try {
                    if (current.ps_path) {
                        status = tctx_diag::call_ps_set(process, thread, ctx, current.attach, &attach_status, &attached);
                        ps_status = status;
                    } else {
                        status = ssdt_resolver::call_NtSetContextThread(thread_handle, ctx);
                        nt_status = status;
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = (NTSTATUS)GetExceptionCode();
                    if (current.ps_path) {
                        ps_status = status;
                    } else {
                        nt_status = status;
                    }
                }
                tctx_diag::log_context("write_attempt", "set", current.source, attempt_index++, status, attach_status, attached, *ctx, phase_start, phase_freq);
                if (NT_SUCCESS(status)) {
                    selected_source = current.source;
                    selected_flags = current.flags;
                    selected_attached = attached;
                    break;
                }
                if (status != STATUS_UNSUCCESSFUL && status != STATUS_PENDING) {
                    break;
                }
                dbg_guard::short_context_retry_delay();
            }
            if (NT_SUCCESS(status)) {
                break;
            }
        }

        if (!NT_SUCCESS(status)) {
            const UINT32 unsupported_state = (!_PsSetContextThread && !_ZwSetContextThread && !ssdt_resolver::g_NtSetContextThread) ? 1u : 0u;
            SD_LOG("TCTX set write_fail_detail pid=%u tid=%u status=0x%08X ps_status=0x%08X nt_status=0x%08X previous_mode=%u requestor_mode=%u handle=%p unsupported_state=%u elapsed_ms=%llu",
                request->pid,
                request->tid,
                (ULONG)status,
                (ULONG)ps_status,
                (ULONG)nt_status,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                thread_handle,
                unsupported_state,
                dbg_guard::elapsed_ms(phase_start, phase_freq));
        }
        SD_LOG("TCTX set write_exit status=0x%08X selected_source=%s selected_flags=0x%08X selected_attached=%u flags=0x%08X rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            (ULONG)status,
            selected_source,
            selected_flags,
            selected_attached ? 1u : 0u,
            ctx->ContextFlags,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7,
            dbg_guard::elapsed_ms(phase_start, phase_freq));
        return status;
    }

    NTSTATUS get_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, p_thread_ctx request, PCONTEXT ctx) {
        NTSTATUS status = read_native_context(process, thread, thread_handle, ctx, request, "get", FALSE);
        if (NT_SUCCESS(status)) {
            copy_context_to_request(*ctx, request);
        }
        return status;
    }

    NTSTATUS set_context(PEPROCESS process, PETHREAD thread, HANDLE thread_handle, p_thread_ctx request, PCONTEXT ctx, BOOLEAN private_user_only) {
        const BOOLEAN needs_debug = tctx_diag::debug_registers_requested(request->register_mask);
        NTSTATUS status = read_native_context(process, thread, thread_handle, ctx, request, "set_base", private_user_only);
        if (!NT_SUCCESS(status)) {
            SD_LOG("TCTX set base_read_failed status=0x%08X pid=%u tid=%u mask=0x%llX private_user_only=%u",
                (ULONG)status,
                request ? request->pid : 0,
                request ? request->tid : 0,
                request ? (unsigned long long)request->register_mask : 0ULL,
                private_user_only ? 1u : 0u);
            return status;
        }
        if (needs_debug && ((ctx->ContextFlags & CONTEXT_DEBUG_REGISTERS) == 0)) {
            SD_LOG("TCTX set base_read_rejected_no_debug pid=%u tid=%u mask=0x%llX flags=0x%08X private_user_only=%u",
                request->pid,
                request->tid,
                (unsigned long long)request->register_mask,
                ctx->ContextFlags,
                private_user_only ? 1u : 0u);
            return STATUS_INVALID_DEVICE_STATE;
        }

        apply_request_to_context(request, ctx);
        ctx->ContextFlags = needs_debug ? tctx_diag::kContextDebugFlags : tctx_diag::kContextBaseFlags;
        SD_LOG("TCTX set applied pid=%u tid=%u mask=0x%llX flags=0x%08X needs_debug=%u private_user_only=%u rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            ctx->ContextFlags,
            needs_debug ? 1u : 0u,
            private_user_only ? 1u : 0u,
            (unsigned long long)ctx->Rip,
            (unsigned long long)ctx->Rsp,
            (unsigned long long)ctx->EFlags,
            (unsigned long long)ctx->Dr0,
            (unsigned long long)ctx->Dr1,
            (unsigned long long)ctx->Dr2,
            (unsigned long long)ctx->Dr3,
            (unsigned long long)ctx->Dr6,
            (unsigned long long)ctx->Dr7);
        return write_native_context(process, thread, thread_handle, ctx, request, private_user_only);
    }
}


namespace tctx_system_route {
    constexpr ULONG kWorkerTag = 'xTcT';
    constexpr LONGLONG kWorkerWait100ns = -50000000LL;

    struct worker_t {
        KEVENT done;
        PEPROCESS process;
        PETHREAD thread;
        POBJECT_TYPE thread_type;
        thread_ctx input;
        thread_ctx output;
        CONTEXT ctx;
        NTSTATUS status;
        NTSTATUS open_status;
        NTSTATUS suspend_status;
        NTSTATUS context_status;
        NTSTATUS resume_status;
        NTSTATUS resume_fallback_status;
        NTSTATUS close_status;
        ULONG suspend_prev_count;
        ULONG resume_prev_count;
        KPROCESSOR_MODE caller_mode;
        KPROCESSOR_MODE worker_mode;
        BOOLEAN suspended;
        BOOLEAN suspended_via_ps;
        BOOLEAN result_valid;
        BOOLEAN close_attempted;
        UINT32 pid;
        UINT32 tid;
        LARGE_INTEGER start;
        LARGE_INTEGER freq;
        HANDLE thread_handle;
        const char* reason;
        volatile LONG refs;
    };

    __forceinline void release_work(worker_t* work) {
        if (work && InterlockedDecrement(&work->refs) == 0) {
            ExFreePoolWithTag(work, kWorkerTag);
        }
    }

    __forceinline NTSTATUS resume_worker_thread(worker_t* work) {
        if (!work || !work->suspended) {
            return STATUS_SUCCESS;
        }

        ULONG prev_count = 0;
        NTSTATUS primary = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS fallback = STATUS_PROCEDURE_NOT_FOUND;

        if (work->suspended_via_ps && _PsResumeThread) {
            __try {
                primary = _PsResumeThread(work->thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                primary = (NTSTATUS)GetExceptionCode();
            }
        } else if (work->thread_handle) {
            __try {
                primary = ssdt_resolver::call_NtResumeThread(work->thread_handle, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                primary = (NTSTATUS)GetExceptionCode();
            }
        }

        work->resume_prev_count = prev_count;
        work->resume_status = primary;
        SD_LOG("TCTX system_worker_resume_primary route=system_thread reason=%s pid=%u tid=%u status=0x%08X status_text=%s win32=%lu prev=%lu via_ps=%u handle=%p ps_resume=%p zw_resume=%p nt_resume=%p elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            (ULONG)primary,
            tctx_diag::ntstatus_text(primary),
            tctx_diag::ntstatus_win32(primary),
            prev_count,
            work->suspended_via_ps ? 1u : 0u,
            work->thread_handle,
            _PsResumeThread,
            _ZwResumeThread,
            ssdt_resolver::g_NtResumeThread,
            tctx_diag::elapsed_ms(work->start, work->freq));

        if (!NT_SUCCESS(primary)) {
            prev_count = 0;
            if (work->suspended_via_ps && work->thread_handle) {
                __try {
                    fallback = ssdt_resolver::call_NtResumeThread(work->thread_handle, &prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    fallback = (NTSTATUS)GetExceptionCode();
                }
            } else if (_PsResumeThread) {
                __try {
                    fallback = _PsResumeThread(work->thread, &prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    fallback = (NTSTATUS)GetExceptionCode();
                }
            }
            work->resume_fallback_status = fallback;
            if (NT_SUCCESS(fallback)) {
                work->resume_prev_count = prev_count;
            }
            SD_LOG("TCTX system_worker_resume_fallback route=system_thread reason=%s pid=%u tid=%u status=0x%08X status_text=%s win32=%lu prev=%lu via_ps=%u handle=%p ps_resume=%p zw_resume=%p nt_resume=%p elapsed_ms=%llu",
                work->reason,
                work->pid,
                work->tid,
                (ULONG)fallback,
                tctx_diag::ntstatus_text(fallback),
                tctx_diag::ntstatus_win32(fallback),
                prev_count,
                work->suspended_via_ps ? 1u : 0u,
                work->thread_handle,
                _PsResumeThread,
                _ZwResumeThread,
                ssdt_resolver::g_NtResumeThread,
                tctx_diag::elapsed_ms(work->start, work->freq));
        }

        NTSTATUS effective = NT_SUCCESS(primary) ? primary : fallback;
        if (NT_SUCCESS(effective)) {
            work->suspended = FALSE;
        }
        return effective;
    }

    VOID NTAPI worker_entry(PVOID parameter) {
        worker_t* work = static_cast<worker_t*>(parameter);
        if (!work) {
            if (_PsTerminateSystemThread) {
                _PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            }
            return;
        }

        work->worker_mode = ExGetPreviousMode();
        tctx_diag::thread_snapshot_t before = tctx_diag::query_thread_snapshot(work->pid, work->tid);
        SD_LOG("TCTX system_worker_entry route=system_thread reason=%s pid=%u tid=%u set=%u mask=0x%llX caller_previous_mode=%u worker_previous_mode=%u current_pid=%p current_tid=%p process=%p thread=%p thread_type=%p thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            work->input.should_set,
            (unsigned long long)work->input.register_mask,
            (ULONG)work->caller_mode,
            (ULONG)work->worker_mode,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            work->process,
            work->thread,
            work->thread_type,
            before.found ? 1u : 0u,
            (ULONG)before.status,
            tctx_diag::ntstatus_text(before.status),
            before.thread_state,
            before.wait_reason,
            tctx_diag::elapsed_ms(work->start, work->freq));

        ACCESS_MASK desired_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | SYNCHRONIZE;
        if (work->input.should_set != 0) {
            desired_access |= THREAD_SET_CONTEXT;
        }

        __try {
            work->open_status = _ObOpenObjectByPointer(
                work->thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                desired_access,
                work->thread_type,
                KernelMode,
                &work->thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            work->open_status = (NTSTATUS)GetExceptionCode();
            work->thread_handle = nullptr;
        }

        SD_LOG("TCTX system_worker_open route=system_thread reason=%s pid=%u tid=%u desired=0x%08X status=0x%08X status_text=%s win32=%lu handle=%p thread_type=%p elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            (ULONG)desired_access,
            (ULONG)work->open_status,
            tctx_diag::ntstatus_text(work->open_status),
            tctx_diag::ntstatus_win32(work->open_status),
            work->thread_handle,
            work->thread_type,
            tctx_diag::elapsed_ms(work->start, work->freq));

        NTSTATUS status = work->open_status;
        if (NT_SUCCESS(status) && work->thread_handle) {
            if (_PsSuspendThread && (_PsResumeThread || _ZwResumeThread || ssdt_resolver::g_NtResumeThread)) {
                __try {
                    work->suspend_status = _PsSuspendThread(work->thread, &work->suspend_prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    work->suspend_status = (NTSTATUS)GetExceptionCode();
                }
                SD_LOG("TCTX system_worker_suspend_ps route=system_thread reason=%s pid=%u tid=%u status=0x%08X status_text=%s win32=%lu prev=%lu ps_suspend=%p ps_resume=%p elapsed_ms=%llu",
                    work->reason,
                    work->pid,
                    work->tid,
                    (ULONG)work->suspend_status,
                    tctx_diag::ntstatus_text(work->suspend_status),
                    tctx_diag::ntstatus_win32(work->suspend_status),
                    work->suspend_prev_count,
                    _PsSuspendThread,
                    _PsResumeThread,
                    tctx_diag::elapsed_ms(work->start, work->freq));
                if (NT_SUCCESS(work->suspend_status)) {
                    work->suspended = TRUE;
                    work->suspended_via_ps = TRUE;
                }
            }

            if (!work->suspended) {
                work->suspend_prev_count = 0;
                __try {
                    work->suspend_status = ssdt_resolver::call_NtSuspendThread(work->thread_handle, &work->suspend_prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    work->suspend_status = (NTSTATUS)GetExceptionCode();
                }
                SD_LOG("TCTX system_worker_suspend_nt route=system_thread reason=%s pid=%u tid=%u status=0x%08X status_text=%s win32=%lu prev=%lu handle=%p zw_suspend=%p nt_suspend=%p worker_previous_mode=%u elapsed_ms=%llu",
                    work->reason,
                    work->pid,
                    work->tid,
                    (ULONG)work->suspend_status,
                    tctx_diag::ntstatus_text(work->suspend_status),
                    tctx_diag::ntstatus_win32(work->suspend_status),
                    work->suspend_prev_count,
                    work->thread_handle,
                    _ZwSuspendThread,
                    ssdt_resolver::g_NtSuspendThread,
                    (ULONG)work->worker_mode,
                    tctx_diag::elapsed_ms(work->start, work->freq));
                if (NT_SUCCESS(work->suspend_status)) {
                    work->suspended = TRUE;
                    work->suspended_via_ps = FALSE;
                }
            }

            tctx_diag::thread_snapshot_t after_suspend = tctx_diag::query_thread_snapshot(work->pid, work->tid);
            SD_LOG("TCTX system_worker_suspend_summary route=system_thread reason=%s pid=%u tid=%u suspended=%u via_ps=%u status=0x%08X status_text=%s win32=%lu prev=%lu thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu elapsed_ms=%llu",
                work->reason,
                work->pid,
                work->tid,
                work->suspended ? 1u : 0u,
                work->suspended_via_ps ? 1u : 0u,
                (ULONG)work->suspend_status,
                tctx_diag::ntstatus_text(work->suspend_status),
                tctx_diag::ntstatus_win32(work->suspend_status),
                work->suspend_prev_count,
                after_suspend.found ? 1u : 0u,
                (ULONG)after_suspend.status,
                tctx_diag::ntstatus_text(after_suspend.status),
                after_suspend.thread_state,
                after_suspend.wait_reason,
                tctx_diag::elapsed_ms(work->start, work->freq));

            if (work->suspended) {
                strong::kmemcpy(&work->output, &work->input, sizeof(work->output));
                strong::kmemset(&work->ctx, 0, sizeof(work->ctx));
                if (work->input.should_set == 0) {
                    work->context_status = trapframe_ctx::get_context(work->process, work->thread, work->thread_handle, &work->output, &work->ctx);
                    work->result_valid = NT_SUCCESS(work->context_status) && tctx_diag::user_context_sane(work->output);
                    if (NT_SUCCESS(work->context_status) && !work->result_valid) {
                        work->context_status = tctx_diag::core_registers_present(work->ctx) ? STATUS_INVALID_ADDRESS : STATUS_UNSUCCESSFUL;
                    }
                } else {
                    work->context_status = trapframe_ctx::set_context(work->process, work->thread, work->thread_handle, &work->output, &work->ctx, FALSE);
                    work->result_valid = NT_SUCCESS(work->context_status);
                }

                SD_LOG("TCTX system_worker_context route=system_thread reason=%s pid=%u tid=%u set=%u status=0x%08X status_text=%s win32=%lu valid=%u flags=0x%08X rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
                    work->reason,
                    work->pid,
                    work->tid,
                    work->input.should_set,
                    (ULONG)work->context_status,
                    tctx_diag::ntstatus_text(work->context_status),
                    tctx_diag::ntstatus_win32(work->context_status),
                    work->result_valid ? 1u : 0u,
                    work->ctx.ContextFlags,
                    (unsigned long long)work->output.rip,
                    tctx_diag::address_class(work->output.rip),
                    (unsigned long long)work->output.rsp,
                    tctx_diag::address_class(work->output.rsp),
                    (unsigned long long)work->output.rflags,
                    tctx_diag::user_context_sane(work->output) ? 1u : 0u,
                    (unsigned long long)work->output.dr0,
                    (unsigned long long)work->output.dr1,
                    (unsigned long long)work->output.dr2,
                    (unsigned long long)work->output.dr3,
                    (unsigned long long)work->output.dr6,
                    (unsigned long long)work->output.dr7,
                    tctx_diag::elapsed_ms(work->start, work->freq));
                status = work->context_status;
            } else {
                status = NT_SUCCESS(work->suspend_status) ? STATUS_INVALID_DEVICE_STATE : work->suspend_status;
            }
        }

        NTSTATUS resume_effective = resume_worker_thread(work);
        if (!NT_SUCCESS(resume_effective)) {
            status = resume_effective;
        }

        if (work->thread_handle) {
            work->close_attempted = TRUE;
            __try {
                work->close_status = _ZwClose(work->thread_handle);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                work->close_status = (NTSTATUS)GetExceptionCode();
            }
            SD_LOG("TCTX system_worker_close route=system_thread reason=%s pid=%u tid=%u handle=%p status=0x%08X status_text=%s win32=%lu elapsed_ms=%llu",
                work->reason,
                work->pid,
                work->tid,
                work->thread_handle,
                (ULONG)work->close_status,
                tctx_diag::ntstatus_text(work->close_status),
                tctx_diag::ntstatus_win32(work->close_status),
                tctx_diag::elapsed_ms(work->start, work->freq));
            work->thread_handle = nullptr;
        }

        work->status = status;
        tctx_diag::thread_snapshot_t after = tctx_diag::query_thread_snapshot(work->pid, work->tid);
        SD_LOG("TCTX system_worker_exit route=system_thread reason=%s pid=%u tid=%u set=%u status=0x%08X status_text=%s win32=%lu open_status=0x%08X suspend_status=0x%08X context_status=0x%08X resume_status=0x%08X resume_fallback_status=0x%08X close_status=0x%08X suspended_after=%u valid=%u thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            work->input.should_set,
            (ULONG)work->status,
            tctx_diag::ntstatus_text(work->status),
            tctx_diag::ntstatus_win32(work->status),
            (ULONG)work->open_status,
            (ULONG)work->suspend_status,
            (ULONG)work->context_status,
            (ULONG)work->resume_status,
            (ULONG)work->resume_fallback_status,
            (ULONG)work->close_status,
            work->suspended ? 1u : 0u,
            work->result_valid ? 1u : 0u,
            after.found ? 1u : 0u,
            (ULONG)after.status,
            tctx_diag::ntstatus_text(after.status),
            after.thread_state,
            after.wait_reason,
            (unsigned long long)work->output.rip,
            tctx_diag::address_class(work->output.rip),
            (unsigned long long)work->output.rsp,
            tctx_diag::address_class(work->output.rsp),
            (unsigned long long)work->output.rflags,
            tctx_diag::user_context_sane(work->output) ? 1u : 0u,
            (unsigned long long)work->output.dr0,
            (unsigned long long)work->output.dr1,
            (unsigned long long)work->output.dr2,
            (unsigned long long)work->output.dr3,
            (unsigned long long)work->output.dr6,
            (unsigned long long)work->output.dr7,
            tctx_diag::elapsed_ms(work->start, work->freq));

        KeSetEvent(&work->done, IO_NO_INCREMENT, FALSE);
        release_work(work);
        if (_PsTerminateSystemThread) {
            _PsTerminateSystemThread(STATUS_SUCCESS);
        }
    }

    NTSTATUS run(PEPROCESS process,
                 PETHREAD thread,
                 POBJECT_TYPE thread_type,
                 p_thread_ctx request,
                 KPROCESSOR_MODE caller_mode,
                 const char* reason,
                 const LARGE_INTEGER& parent_start,
                 const LARGE_INTEGER& parent_freq) {
        if (!process || !thread || !thread_type || !request) {
            return STATUS_INVALID_PARAMETER;
        }

        if (!_PsCreateSystemThread || !_PsTerminateSystemThread || !_ObOpenObjectByPointer || !_ZwClose) {
            SD_LOG("TCTX system_route_unavailable route=system_thread reason=%s pid=%u tid=%u create=%p terminate=%p ob_open=%p zw_close=%p thread_type=%p elapsed_ms=%llu",
                reason ? reason : "none",
                request->pid,
                request->tid,
                _PsCreateSystemThread,
                _PsTerminateSystemThread,
                _ObOpenObjectByPointer,
                _ZwClose,
                thread_type,
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        const LONG suspend_state_before = _InterlockedCompareExchange(&ssdt_resolver::g_funcs_resolved, 0, 0);
        const LONG context_state_before = _InterlockedCompareExchange(&ssdt_resolver::g_ctx_funcs_resolved, 0, 0);
        BOOLEAN suspend_prime_attempted = FALSE;
        BOOLEAN context_prime_attempted = FALSE;
        BOOLEAN suspend_prime_resolved = (ssdt_resolver::g_NtSuspendThread != nullptr && ssdt_resolver::g_NtResumeThread != nullptr) ? TRUE : FALSE;
        BOOLEAN context_prime_resolved = (ssdt_resolver::g_NtGetContextThread != nullptr && ssdt_resolver::g_NtSetContextThread != nullptr) ? TRUE : FALSE;

        if (!_ZwSuspendThread &&
            (!ssdt_resolver::g_NtSuspendThread || !ssdt_resolver::g_NtResumeThread)) {
            suspend_prime_attempted = TRUE;
            ssdt_resolver::find_ssdt();
            suspend_prime_resolved = ssdt_resolver::resolve_suspend_resume();
        }

        if ((!_ZwGetContextThread || !_ZwSetContextThread) &&
            (!ssdt_resolver::g_NtGetContextThread || !ssdt_resolver::g_NtSetContextThread)) {
            context_prime_attempted = TRUE;
            ssdt_resolver::find_ssdt();
            context_prime_resolved = ssdt_resolver::resolve_thread_context();
        }

        SD_LOG("TCTX system_route_prime route=pre_worker reason=%s pid=%u tid=%u set=%u caller_previous_mode=%u current_pid=%p current_tid=%p suspend_attempted=%u suspend_resolved=%u suspend_state_before=%ld suspend_state_after=%ld context_attempted=%u context_resolved=%u context_state_before=%ld context_state_after=%ld ssdt=%p service_table=%p limit=%lu ps_suspend=%p ps_resume=%p zw_suspend=%p zw_resume=%p nt_suspend=%p nt_resume=%p ps_get=%p ps_set=%p zw_get=%p zw_set=%p nt_get=%p nt_set=%p elapsed_ms=%llu",
            reason ? reason : "none",
            request->pid,
            request->tid,
            request->should_set,
            (ULONG)caller_mode,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            suspend_prime_attempted ? 1u : 0u,
            suspend_prime_resolved ? 1u : 0u,
            suspend_state_before,
            _InterlockedCompareExchange(&ssdt_resolver::g_funcs_resolved, 0, 0),
            context_prime_attempted ? 1u : 0u,
            context_prime_resolved ? 1u : 0u,
            context_state_before,
            _InterlockedCompareExchange(&ssdt_resolver::g_ctx_funcs_resolved, 0, 0),
            ssdt_resolver::g_ssdt,
            ssdt_resolver::g_ssdt ? ssdt_resolver::g_ssdt->ServiceTable : nullptr,
            ssdt_resolver::g_ssdt ? ssdt_resolver::g_ssdt->ServiceLimit : 0,
            _PsSuspendThread,
            _PsResumeThread,
            _ZwSuspendThread,
            _ZwResumeThread,
            ssdt_resolver::g_NtSuspendThread,
            ssdt_resolver::g_NtResumeThread,
            _PsGetContextThread,
            _PsSetContextThread,
            _ZwGetContextThread,
            _ZwSetContextThread,
            ssdt_resolver::g_NtGetContextThread,
            ssdt_resolver::g_NtSetContextThread,
            tctx_diag::elapsed_ms(parent_start, parent_freq));

        worker_t* work = static_cast<worker_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(worker_t), kWorkerTag));
        if (!work) {
            SD_LOG("TCTX system_route_alloc_failed route=system_thread reason=%s pid=%u tid=%u bytes=%llu elapsed_ms=%llu",
                reason ? reason : "none",
                request->pid,
                request->tid,
                (unsigned long long)sizeof(worker_t),
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        strong::kmemset(work, 0, sizeof(*work));
        KeInitializeEvent(&work->done, NotificationEvent, FALSE);
        work->status = STATUS_UNSUCCESSFUL;
        work->open_status = STATUS_NOT_FOUND;
        work->suspend_status = STATUS_NOT_FOUND;
        work->context_status = STATUS_NOT_FOUND;
        work->resume_status = STATUS_NOT_FOUND;
        work->resume_fallback_status = STATUS_NOT_FOUND;
        work->close_status = STATUS_NOT_FOUND;
        work->process = process;
        work->thread = thread;
        work->thread_type = thread_type;
        work->caller_mode = caller_mode;
        work->pid = request->pid;
        work->tid = request->tid;
        work->reason = reason ? reason : "none";
        work->start = KeQueryPerformanceCounter(&work->freq);
        work->refs = 2;
        strong::kmemcpy(&work->input, request, sizeof(work->input));
        strong::kmemcpy(&work->output, request, sizeof(work->output));

        HANDLE worker_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
        NTSTATUS create_status = _PsCreateSystemThread(
            &worker_handle,
            THREAD_ALL_ACCESS,
            &oa,
            nullptr,
            nullptr,
            worker_entry,
            work);

        SD_LOG("TCTX system_route_create route=system_thread reason=%s pid=%u tid=%u set=%u status=0x%08X status_text=%s win32=%lu worker_handle=%p process=%p thread=%p caller_previous_mode=%u elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            work->input.should_set,
            (ULONG)create_status,
            tctx_diag::ntstatus_text(create_status),
            tctx_diag::ntstatus_win32(create_status),
            worker_handle,
            process,
            thread,
            (ULONG)caller_mode,
            tctx_diag::elapsed_ms(parent_start, parent_freq));

        if (!NT_SUCCESS(create_status)) {
            ExFreePoolWithTag(work, kWorkerTag);
            return create_status;
        }

        LARGE_INTEGER timeout;
        timeout.QuadPart = kWorkerWait100ns;
        NTSTATUS wait_status = KeWaitForSingleObject(&work->done, Executive, KernelMode, FALSE, &timeout);
        NTSTATUS final_wait_status = wait_status;
        if (wait_status != STATUS_SUCCESS) {
            SD_LOG("TCTX system_route_wait_bounded route=system_thread reason=%s pid=%u tid=%u wait_status=0x%08X wait_status_text=%s win32=%lu timeout_100ns=%lld worker_handle=%p elapsed_ms=%llu",
                work->reason,
                work->pid,
                work->tid,
                (ULONG)wait_status,
                tctx_diag::ntstatus_text(wait_status),
                tctx_diag::ntstatus_win32(wait_status),
                (long long)kWorkerWait100ns,
                worker_handle,
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            if (worker_handle) {
                NTSTATUS close_worker_status = _ZwClose(worker_handle);
                SD_LOG("TCTX system_route_worker_handle_close route=system_thread reason=%s pid=%u tid=%u handle=%p status=0x%08X status_text=%s win32=%lu after_timeout=1 elapsed_ms=%llu",
                    work->reason,
                    work->pid,
                    work->tid,
                    worker_handle,
                    (ULONG)close_worker_status,
                    tctx_diag::ntstatus_text(close_worker_status),
                    tctx_diag::ntstatus_win32(close_worker_status),
                    tctx_diag::elapsed_ms(parent_start, parent_freq));
            }
            release_work(work);
            return STATUS_IO_TIMEOUT;
        }

        if (worker_handle) {
            NTSTATUS close_worker_status = _ZwClose(worker_handle);
            SD_LOG("TCTX system_route_worker_handle_close route=system_thread reason=%s pid=%u tid=%u handle=%p status=0x%08X status_text=%s win32=%lu elapsed_ms=%llu",
                work->reason,
                work->pid,
                work->tid,
                worker_handle,
                (ULONG)close_worker_status,
                tctx_diag::ntstatus_text(close_worker_status),
                tctx_diag::ntstatus_win32(close_worker_status),
                tctx_diag::elapsed_ms(parent_start, parent_freq));
        }

        NTSTATUS status = work->status;
        const BOOLEAN copy_result = NT_SUCCESS(status) && request->should_set == 0 && work->result_valid;
        if (copy_result) {
            strong::kmemcpy(request, &work->output, sizeof(*request));
        } else if (NT_SUCCESS(status) && request->should_set == 0) {
            status = STATUS_UNSUCCESSFUL;
        }

        SD_LOG("TCTX system_route_exit route=system_thread reason=%s pid=%u tid=%u set=%u status=0x%08X status_text=%s win32=%lu create_status=0x%08X wait_status=0x%08X final_wait_status=0x%08X worker_status=0x%08X open_status=0x%08X suspend_status=0x%08X context_status=0x%08X resume_status=0x%08X resume_fallback_status=0x%08X valid=%u copied=%u rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
            work->reason,
            work->pid,
            work->tid,
            work->input.should_set,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            tctx_diag::ntstatus_win32(status),
            (ULONG)create_status,
            (ULONG)wait_status,
            (ULONG)final_wait_status,
            (ULONG)work->status,
            (ULONG)work->open_status,
            (ULONG)work->suspend_status,
            (ULONG)work->context_status,
            (ULONG)work->resume_status,
            (ULONG)work->resume_fallback_status,
            work->result_valid ? 1u : 0u,
            copy_result ? 1u : 0u,
            (unsigned long long)work->output.rip,
            tctx_diag::address_class(work->output.rip),
            (unsigned long long)work->output.rsp,
            tctx_diag::address_class(work->output.rsp),
            (unsigned long long)work->output.rflags,
            tctx_diag::user_context_sane(work->output) ? 1u : 0u,
            (unsigned long long)work->output.dr0,
            (unsigned long long)work->output.dr1,
            (unsigned long long)work->output.dr2,
            (unsigned long long)work->output.dr3,
            (unsigned long long)work->output.dr6,
            (unsigned long long)work->output.dr7,
            tctx_diag::elapsed_ms(parent_start, parent_freq));

        release_work(work);
        return status;
    }
}


NTSTATUS functions::handle_thread_ctx(p_thread_ctx request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        SD_LOG("TCTX reject invalid_request request=%p", request);
        return STATUS_INVALID_PARAMETER;
    }

    LARGE_INTEGER tctx_freq = {};
    LARGE_INTEGER tctx_start = KeQueryPerformanceCounter(&tctx_freq);
    KPROCESSOR_MODE previous_mode = ExGetPreviousMode();
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SD_LOG("TCTX reject bad_irql pid=%u tid=%u set=%u irql=%u previous_mode=%u requestor_mode=%u",
            request->pid,
            request->tid,
            request->should_set,
            (ULONG)KeGetCurrentIrql(),
            (ULONG)previous_mode,
            (ULONG)previous_mode);
        return STATUS_INVALID_DEVICE_STATE;
    }

    POBJECT_TYPE thread_type = (PsThreadType && *PsThreadType) ? *PsThreadType : nullptr;
    tctx_diag::os_version_snapshot_t os_version = tctx_diag::query_os_version();
    tctx_diag::thread_snapshot_t thread_before = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    SD_LOG("TCTX entry pid=%u tid=%u set=%u mask=0x%llX irql=%u previous_mode=%u requestor_mode=%u current_pid=%p current_tid=%p os_status=0x%08X os_status_text=%s os=%lu.%lu.%lu thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu start=%p client_pid=%p client_tid=%p process_thread_count=%lu scanned_processes=%lu scanned_threads=%lu ps_get=%p ps_set=%p zw_get=%p zw_set=%p ps_suspend=%p ps_resume=%p zw_suspend=%p zw_resume=%p ob_open=%p zw_close=%p thread_type_ptr=%p thread_type=%p stack_attach=%p stack_detach=%p",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        (ULONG)KeGetCurrentIrql(),
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        PsGetCurrentProcessId(),
        PsGetCurrentThreadId(),
        (ULONG)os_version.status,
        tctx_diag::ntstatus_text(os_version.status),
        os_version.major,
        os_version.minor,
        os_version.build,
        thread_before.found ? 1u : 0u,
        (ULONG)thread_before.status,
        tctx_diag::ntstatus_text(thread_before.status),
        thread_before.thread_state,
        thread_before.wait_reason,
        thread_before.start_address,
        thread_before.client_pid,
        thread_before.client_tid,
        thread_before.process_thread_count,
        thread_before.scanned_processes,
        thread_before.scanned_threads,
        _PsGetContextThread,
        _PsSetContextThread,
        _ZwGetContextThread,
        _ZwSetContextThread,
        _PsSuspendThread,
        _PsResumeThread,
        _ZwSuspendThread,
        _ZwResumeThread,
        _ObOpenObjectByPointer,
        _ZwClose,
        PsThreadType,
        thread_type,
        _KeStackAttachProcess,
        _KeUnstackDetachProcess);
    SD_LOG("TCTX request_fields pid=%u tid=%u set=%u mask=0x%llX rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX rsi=0x%llX rdi=0x%llX rbp=0x%llX rsp=0x%llX r8=0x%llX r9=0x%llX r10=0x%llX r11=0x%llX r12=0x%llX r13=0x%llX r14=0x%llX r15=0x%llX rip=0x%llX rflags=0x%llX cs=0x%llX ss=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX previous_mode=%u requestor_mode=%u",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        (unsigned long long)request->rax,
        (unsigned long long)request->rbx,
        (unsigned long long)request->rcx,
        (unsigned long long)request->rdx,
        (unsigned long long)request->rsi,
        (unsigned long long)request->rdi,
        (unsigned long long)request->rbp,
        (unsigned long long)request->rsp,
        (unsigned long long)request->r8,
        (unsigned long long)request->r9,
        (unsigned long long)request->r10,
        (unsigned long long)request->r11,
        (unsigned long long)request->r12,
        (unsigned long long)request->r13,
        (unsigned long long)request->r14,
        (unsigned long long)request->r15,
        (unsigned long long)request->rip,
        (unsigned long long)request->rflags,
        (unsigned long long)request->cs,
        (unsigned long long)request->ss,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        (ULONG)previous_mode,
        (ULONG)previous_mode);

    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_ObfDereferenceObject) {
        SD_LOG("TCTX reject missing_lookup pid=%u tid=%u lookup_process=%p lookup_thread=%p deref=%p",
            request->pid,
            request->tid,
            _PsLookupProcessByProcessId,
            _PsLookupThreadByThreadId,
            _ObfDereferenceObject);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    SD_LOG("TCTX lookup_process pid=%u status=0x%08X status_text=%s process=%p",
        request->pid,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    SD_LOG("TCTX lookup_thread tid=%u status=0x%08X status_text=%s thread=%p",
        request->tid,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        thread);
    if (!NT_SUCCESS(status) || !thread) {
        _ObfDereferenceObject(process);
        return status;
    }


    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            SD_LOG("TCTX reject process_mismatch pid=%u tid=%u process=%p thread_process=%p",
                request->pid,
                request->tid,
                process,
                thread_process);
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            return STATUS_INVALID_CID;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        SD_LOG("TCTX reject process_check_exception pid=%u tid=%u code=0x%08X",
            request->pid,
            request->tid,
            (ULONG)GetExceptionCode());
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    dbg_guard::timing_scatter();

    const BOOLEAN private_get_context_available = ssdt_resolver::resolve_user_context();
    const BOOLEAN private_set_context_available = request->should_set != 0 ? ssdt_resolver::resolve_user_set_context() : FALSE;
    const BOOLEAN debug_register_set =
        request->should_set != 0 &&
        tctx_diag::debug_registers_requested(request->register_mask);
    const BOOLEAN private_set_context_fast_path =
        request->should_set != 0 &&
        private_get_context_available &&
        private_set_context_available;
    const BOOLEAN private_set_without_suspend =
        private_set_context_fast_path &&
        previous_mode != KernelMode &&
        !debug_register_set;
    const BOOLEAN private_context_fast_path =
        request->should_set != 0 ?
        private_set_context_fast_path :
        private_get_context_available;
    const BOOLEAN ps_suspend_available = (_PsSuspendThread && (_PsResumeThread || _ZwResumeThread || ssdt_resolver::g_NtResumeThread)) ? TRUE : FALSE;
    const BOOLEAN nt_suspend_available = (_ZwSuspendThread || ssdt_resolver::g_NtSuspendThread) ? TRUE : FALSE;
    SD_LOG("TCTX route_decision phase=pre_suspend pid=%u tid=%u set=%u mask=0x%llX debug_register_set=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX previous_mode=%u requestor_mode=%u private_get_available=%u private_set_available=%u private_set_without_suspend=%u private_context_fast_path=%u ps_suspend_available=%u nt_suspend_available=%u ctx_thread_suspended=0 private_write_route_attempted=0 private_write_status=0x%08X private_write_status_text=%s elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        debug_register_set ? 1u : 0u,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        private_get_context_available ? 1u : 0u,
        private_set_context_available ? 1u : 0u,
        private_set_without_suspend ? 1u : 0u,
        private_context_fast_path ? 1u : 0u,
        ps_suspend_available ? 1u : 0u,
        nt_suspend_available ? 1u : 0u,
        (ULONG)STATUS_NOT_FOUND,
        tctx_diag::ntstatus_text(STATUS_NOT_FOUND),
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));
    if (previous_mode != KernelMode && (!private_context_fast_path || debug_register_set)) {
        NTSTATUS system_status = tctx_system_route::run(
            process,
            thread,
            thread_type,
            request,
            previous_mode,
            debug_register_set ? "debug_register_set_requires_suspend" : "user_previous_mode",
            tctx_start,
            tctx_freq);
        if (NT_SUCCESS(system_status)) {
            tctx_diag::thread_snapshot_t thread_after_system = tctx_diag::query_thread_snapshot(request->pid, request->tid);
            SD_LOG("TCTX exit route=system_thread pid=%u tid=%u set=%u debug_register_set=%u status=0x%08X status_text=%s win32=%lu previous_mode=%u requestor_mode=%u thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_set,
                debug_register_set ? 1u : 0u,
                (ULONG)system_status,
                tctx_diag::ntstatus_text(system_status),
                tctx_diag::ntstatus_win32(system_status),
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                thread_after_system.found ? 1u : 0u,
                (ULONG)thread_after_system.status,
                tctx_diag::ntstatus_text(thread_after_system.status),
                thread_after_system.thread_state,
                thread_after_system.wait_reason,
                (unsigned long long)request->rip,
                tctx_diag::address_class(request->rip),
                (unsigned long long)request->rsp,
                tctx_diag::address_class(request->rsp),
                (unsigned long long)request->rflags,
                tctx_diag::user_context_sane(*request) ? 1u : 0u,
                (unsigned long long)request->dr0,
                (unsigned long long)request->dr1,
                (unsigned long long)request->dr2,
                (unsigned long long)request->dr3,
                (unsigned long long)request->dr6,
                (unsigned long long)request->dr7,
                dbg_guard::elapsed_ms(tctx_start, tctx_freq));
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            return system_status;
        }
        SD_LOG("TCTX system_route_continue route=inline_direct pid=%u tid=%u set=%u debug_register_set=%u system_status=0x%08X system_status_text=%s win32=%lu previous_mode=%u requestor_mode=%u elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_set,
            debug_register_set ? 1u : 0u,
            (ULONG)system_status,
            tctx_diag::ntstatus_text(system_status),
            tctx_diag::ntstatus_win32(system_status),
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            dbg_guard::elapsed_ms(tctx_start, tctx_freq));
    }
    else if (previous_mode != KernelMode) {
        SD_LOG("TCTX system_route_bypass route=inline_private pid=%u tid=%u set=%u private_context_fast_path=%u private_get_available=%u private_set_available=%u private_set_without_suspend=%u previous_mode=%u requestor_mode=%u elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_set,
            private_context_fast_path ? 1u : 0u,
            private_get_context_available ? 1u : 0u,
            private_set_context_available ? 1u : 0u,
            private_set_without_suspend ? 1u : 0u,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            dbg_guard::elapsed_ms(tctx_start, tctx_freq));
    }


    HANDLE ctx_thread_handle = nullptr;
    BOOLEAN ctx_thread_suspended = FALSE;
    NTSTATUS open_status = STATUS_PROCEDURE_NOT_FOUND;
    NTSTATUS suspend_status = STATUS_PROCEDURE_NOT_FOUND;
    ULONG suspend_prev_count = 0;
    BOOLEAN tried_ps_suspend = FALSE;
    BOOLEAN ctx_thread_suspended_via_ps = FALSE;
    BOOLEAN suspend_ps_exception_seen = FALSE;
    NTSTATUS suspend_ps_exception_code = STATUS_SUCCESS;
    BOOLEAN suspend_nt_exception_seen = FALSE;
    NTSTATUS suspend_nt_exception_code = STATUS_SUCCESS;
    BOOLEAN suspend_nt_user_previous_mode_skipped = FALSE;
    const char* open_strategy = "not_attempted";
    const char* suspend_strategy = "none";
    const char* suspend_constraint = "none";

    if (private_set_without_suspend) {
        open_status = STATUS_SUCCESS;
        suspend_status = STATUS_SUCCESS;
        open_strategy = "private_internal_direct";
        suspend_strategy = "private_internal_no_suspend";
        suspend_constraint = "validated_private_context_route";
        SD_LOG("TCTX suspend_bypass_private_set pid=%u tid=%u mask=0x%llX previous_mode=%u requestor_mode=%u private_get_available=%u private_set_available=%u ps_suspend_available=%u nt_suspend_available=%u ctx_thread_suspended=0 private_write_route_attempted=0 private_write_status=0x%08X private_write_status_text=%s elapsed_ms=%llu",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            private_get_context_available ? 1u : 0u,
            private_set_context_available ? 1u : 0u,
            ps_suspend_available ? 1u : 0u,
            nt_suspend_available ? 1u : 0u,
            (ULONG)STATUS_NOT_FOUND,
            tctx_diag::ntstatus_text(STATUS_NOT_FOUND),
            dbg_guard::elapsed_ms(tctx_start, tctx_freq));
    } else if (_ObOpenObjectByPointer && _ZwClose && thread_type) {
        open_strategy = "obopen_thread_object";
        ACCESS_MASK desired_access = THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT;
        if (request->should_set != 0) {
            desired_access |= THREAD_SET_CONTEXT;
        }

        __try {
            open_status = _ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                desired_access,
                thread_type,
                KernelMode,
                &ctx_thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            open_status = (NTSTATUS)GetExceptionCode();
            ctx_thread_handle = nullptr;
        }

        SD_LOG("TCTX open_handle pid=%u tid=%u desired=0x%08X status=0x%08X status_text=%s handle=%p thread_type=%p",
            request->pid,
            request->tid,
            (ULONG)desired_access,
            (ULONG)open_status,
            tctx_diag::ntstatus_text(open_status),
            ctx_thread_handle,
            thread_type);

        if (NT_SUCCESS(open_status) && ctx_thread_handle) {
            if (_PsSuspendThread && (_PsResumeThread || _ZwResumeThread)) {
                tried_ps_suspend = TRUE;
                __try {
                    suspend_status = _PsSuspendThread(thread, &suspend_prev_count);
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    suspend_status = (NTSTATUS)GetExceptionCode();
                    suspend_ps_exception_seen = TRUE;
                    suspend_ps_exception_code = suspend_status;
                }
                SD_LOG("TCTX suspend_ps_with_handle pid=%u tid=%u status=0x%08X status_text=%s prev=%lu ps_suspend=%p handle=%p",
                    request->pid,
                    request->tid,
                    (ULONG)suspend_status,
                    tctx_diag::ntstatus_text(suspend_status),
                    suspend_prev_count,
                    _PsSuspendThread,
                    ctx_thread_handle);
                if (NT_SUCCESS(suspend_status)) {
                    ctx_thread_suspended = TRUE;
                    ctx_thread_suspended_via_ps = TRUE;
                    suspend_strategy = "ps_with_handle";
                }
            }
            if (!ctx_thread_suspended) {
                suspend_prev_count = 0;
                if (!_ZwSuspendThread && previous_mode != KernelMode) {
                    suspend_status = STATUS_INVALID_DEVICE_STATE;
                    suspend_nt_user_previous_mode_skipped = TRUE;
                    suspend_constraint = "direct_nt_suspend_skipped_user_previous_mode";
                    SD_LOG("TCTX suspend_nt_with_handle_skipped pid=%u tid=%u status=0x%08X status_text=%s previous_mode=%u requestor_mode=%u zw_suspend=%p nt_suspend=%p handle=%p reason=direct_nt_kernel_pointer_requires_kernel_previous_mode",
                        request->pid,
                        request->tid,
                        (ULONG)suspend_status,
                        tctx_diag::ntstatus_text(suspend_status),
                        (ULONG)previous_mode,
                        (ULONG)previous_mode,
                        _ZwSuspendThread,
                        ssdt_resolver::g_NtSuspendThread,
                        ctx_thread_handle);
                } else {
                    __try {
                        suspend_status = ssdt_resolver::call_NtSuspendThread(ctx_thread_handle, &suspend_prev_count);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        suspend_status = (NTSTATUS)GetExceptionCode();
                        suspend_nt_exception_seen = TRUE;
                        suspend_nt_exception_code = suspend_status;
                    }
                }
                SD_LOG("TCTX suspend_nt_with_handle pid=%u tid=%u status=0x%08X status_text=%s prev=%lu zw_suspend=%p nt_suspend=%p handle=%p",
                    request->pid,
                    request->tid,
                    (ULONG)suspend_status,
                    tctx_diag::ntstatus_text(suspend_status),
                    suspend_prev_count,
                    _ZwSuspendThread,
                    ssdt_resolver::g_NtSuspendThread,
                    ctx_thread_handle);
                if (NT_SUCCESS(suspend_status)) {
                    ctx_thread_suspended = TRUE;
                    ctx_thread_suspended_via_ps = FALSE;
                    suspend_strategy = "nt_with_handle";
                }
            }

            SD_LOG("TCTX suspend_with_handle pid=%u tid=%u status=0x%08X status_text=%s prev=%lu ps_suspend=%p zw_suspend=%p handle=%p via_ps=%u",
                request->pid,
                request->tid,
                (ULONG)suspend_status,
                tctx_diag::ntstatus_text(suspend_status),
                suspend_prev_count,
                _PsSuspendThread,
                _ZwSuspendThread,
                ctx_thread_handle,
                ctx_thread_suspended_via_ps ? 1u : 0u);
        }
    } else {
        SD_LOG("TCTX open_skipped pid=%u tid=%u ob_open=%p zw_close=%p thread_type_ptr=%p thread_type=%p",
            request->pid,
            request->tid,
            _ObOpenObjectByPointer,
            _ZwClose,
            PsThreadType,
            thread_type);
        open_strategy = "missing_open_primitives";
    }

    if (!private_set_without_suspend && !ctx_thread_suspended && !tried_ps_suspend && _PsSuspendThread && _PsResumeThread) {
        suspend_prev_count = 0;
        tried_ps_suspend = TRUE;
        __try {
            suspend_status = _PsSuspendThread(thread, &suspend_prev_count);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            suspend_status = (NTSTATUS)GetExceptionCode();
            suspend_ps_exception_seen = TRUE;
            suspend_ps_exception_code = suspend_status;
        }
        SD_LOG("TCTX suspend_ps_direct pid=%u tid=%u status=0x%08X status_text=%s prev=%lu ps_suspend=%p",
            request->pid,
            request->tid,
            (ULONG)suspend_status,
            tctx_diag::ntstatus_text(suspend_status),
            suspend_prev_count,
            _PsSuspendThread);
        if (NT_SUCCESS(suspend_status)) {
            ctx_thread_suspended = TRUE;
            ctx_thread_suspended_via_ps = TRUE;
            suspend_strategy = "ps_direct";
        }
    }

    const UINT32 open_import_absent = (!private_set_without_suspend && (!_ObOpenObjectByPointer || !_ZwClose || !thread_type)) ? 1u : 0u;
    const UINT32 suspend_import_absent = (!private_set_without_suspend && !_PsSuspendThread && !_ZwSuspendThread && !ssdt_resolver::g_NtSuspendThread && !suspend_nt_user_previous_mode_skipped) ? 1u : 0u;
    const UINT32 suspend_call_failed = (!private_set_without_suspend && !ctx_thread_suspended && !suspend_import_absent &&
        (tried_ps_suspend || ctx_thread_handle != nullptr || suspend_nt_user_previous_mode_skipped)) ? 1u : 0u;
    tctx_diag::thread_snapshot_t thread_after_suspend = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    SD_LOG("TCTX suspend_summary pid=%u tid=%u set=%u mask=0x%llX private_set_without_suspend=%u private_get_available=%u private_set_available=%u open_strategy=%s suspend_strategy=%s suspend_constraint=%s suspended=%u via_ps=%u tried_ps_suspend=%u open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s open_import_absent=%u suspend_import_absent=%u suspend_call_failed=%u nt_user_previous_mode_skipped=%u ps_exception=%u ps_exception_code=0x%08X nt_exception=%u nt_exception_code=0x%08X handle=%p thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        private_set_without_suspend ? 1u : 0u,
        private_get_context_available ? 1u : 0u,
        private_set_context_available ? 1u : 0u,
        open_strategy,
        suspend_strategy,
        suspend_constraint,
        ctx_thread_suspended ? 1u : 0u,
        ctx_thread_suspended_via_ps ? 1u : 0u,
        tried_ps_suspend ? 1u : 0u,
        (ULONG)open_status,
        tctx_diag::ntstatus_text(open_status),
        (ULONG)suspend_status,
        tctx_diag::ntstatus_text(suspend_status),
        open_import_absent,
        suspend_import_absent,
        suspend_call_failed,
        suspend_nt_user_previous_mode_skipped ? 1u : 0u,
        suspend_ps_exception_seen ? 1u : 0u,
        (ULONG)suspend_ps_exception_code,
        suspend_nt_exception_seen ? 1u : 0u,
        (ULONG)suspend_nt_exception_code,
        ctx_thread_handle,
        thread_after_suspend.found ? 1u : 0u,
        (ULONG)thread_after_suspend.status,
        tctx_diag::ntstatus_text(thread_after_suspend.status),
        thread_after_suspend.thread_state,
        thread_after_suspend.wait_reason,
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));

    if (!ctx_thread_suspended && request->should_set != 0 && !private_set_without_suspend) {
        SD_LOG("TCTX reject suspend_failed pid=%u tid=%u open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s handle=%p ps_suspend=%p zw_suspend=%p suspend_import_absent=%u suspend_call_failed=%u nt_user_previous_mode_skipped=%u suspend_constraint=%s private_get_available=%u private_set_available=%u",
            request->pid,
            request->tid,
            (ULONG)open_status,
            tctx_diag::ntstatus_text(open_status),
            (ULONG)suspend_status,
            tctx_diag::ntstatus_text(suspend_status),
            ctx_thread_handle,
            _PsSuspendThread,
            _ZwSuspendThread,
            suspend_import_absent,
            suspend_call_failed,
            suspend_nt_user_previous_mode_skipped ? 1u : 0u,
            suspend_constraint,
            private_get_context_available ? 1u : 0u,
            private_set_context_available ? 1u : 0u);
        if (ctx_thread_handle) {
            _ZwClose(ctx_thread_handle);
        }
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!ctx_thread_suspended && private_set_without_suspend) {
        SD_LOG("TCTX set_private_without_suspend pid=%u tid=%u mask=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX private_get_available=%u private_set_available=%u open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s private_write_route_attempted=0 private_write_status=0x%08X private_write_status_text=%s elapsed_ms=%llu",
            request->pid,
            request->tid,
            (unsigned long long)request->register_mask,
            (unsigned long long)request->dr0,
            (unsigned long long)request->dr1,
            (unsigned long long)request->dr2,
            (unsigned long long)request->dr3,
            (unsigned long long)request->dr6,
            (unsigned long long)request->dr7,
            private_get_context_available ? 1u : 0u,
            private_set_context_available ? 1u : 0u,
            (ULONG)open_status,
            tctx_diag::ntstatus_text(open_status),
            (ULONG)suspend_status,
            tctx_diag::ntstatus_text(suspend_status),
            (ULONG)STATUS_NOT_FOUND,
            tctx_diag::ntstatus_text(STATUS_NOT_FOUND),
            dbg_guard::elapsed_ms(tctx_start, tctx_freq));
    } else if (!ctx_thread_suspended) {
        SD_LOG("TCTX read_without_suspend pid=%u tid=%u open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s handle=%p ps_get=%p zw_get=%p suspend_import_absent=%u suspend_call_failed=%u nt_user_previous_mode_skipped=%u suspend_constraint=%s",
            request->pid,
            request->tid,
            (ULONG)open_status,
            tctx_diag::ntstatus_text(open_status),
            (ULONG)suspend_status,
            tctx_diag::ntstatus_text(suspend_status),
            ctx_thread_handle,
            _PsGetContextThread,
            _ZwGetContextThread,
            suspend_import_absent,
            suspend_call_failed,
            suspend_nt_user_previous_mode_skipped ? 1u : 0u,
            suspend_constraint);
    } else {
        for (ULONG settle = 0; settle < 4; ++settle) {
            dbg_guard::short_context_retry_delay();
            tctx_diag::thread_snapshot_t settle_snapshot = tctx_diag::query_thread_snapshot(request->pid, request->tid);
            SD_LOG("TCTX suspend_settle pid=%u tid=%u index=%lu strategy=%s found=%u status=0x%08X status_text=%s state=%lu wait_reason=%lu elapsed_ms=%llu",
                request->pid,
                request->tid,
                settle,
                suspend_strategy,
                settle_snapshot.found ? 1u : 0u,
                (ULONG)settle_snapshot.status,
                tctx_diag::ntstatus_text(settle_snapshot.status),
                settle_snapshot.thread_state,
                settle_snapshot.wait_reason,
                dbg_guard::elapsed_ms(tctx_start, tctx_freq));
        }
    }

    CONTEXT ctx;
    strong::kmemset(&ctx, 0, sizeof(ctx));

    ULONGLONG context_start_ms = dbg_guard::elapsed_ms(tctx_start, tctx_freq);
    SD_LOG("TCTX context_begin pid=%u tid=%u set=%u mask=0x%llX private_set_without_suspend=%u private_get_available=%u private_set_available=%u handle=%p open_strategy=%s suspend_strategy=%s suspend_constraint=%s suspended=%u via_ps=%u open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s previous_mode=%u requestor_mode=%u attach_available=%u open_import_absent=%u suspend_import_absent=%u suspend_call_failed=%u nt_user_previous_mode_skipped=%u elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        (unsigned long long)request->register_mask,
        private_set_without_suspend ? 1u : 0u,
        private_get_context_available ? 1u : 0u,
        private_set_context_available ? 1u : 0u,
        ctx_thread_handle,
        open_strategy,
        suspend_strategy,
        suspend_constraint,
        ctx_thread_suspended ? 1u : 0u,
        ctx_thread_suspended_via_ps ? 1u : 0u,
        (ULONG)open_status,
        tctx_diag::ntstatus_text(open_status),
        (ULONG)suspend_status,
        tctx_diag::ntstatus_text(suspend_status),
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        (_KeStackAttachProcess && _KeUnstackDetachProcess) ? 1u : 0u,
        open_import_absent,
        suspend_import_absent,
        suspend_call_failed,
        suspend_nt_user_previous_mode_skipped ? 1u : 0u,
        context_start_ms);

    if (request->should_set == 0) {
        status = trapframe_ctx::get_context(process, thread, ctx_thread_handle, request, &ctx);
    }
    else {
        status = trapframe_ctx::set_context(process, thread, ctx_thread_handle, request, &ctx, private_set_without_suspend);
    }

    SD_LOG("TCTX context_end pid=%u tid=%u set=%u private_set_without_suspend=%u status=0x%08X status_text=%s rip=0x%llX rsp=0x%llX rflags=0x%llX dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX flags=0x%08X elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        private_set_without_suspend ? 1u : 0u,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        (unsigned long long)request->rip,
        (unsigned long long)request->rsp,
        (unsigned long long)request->rflags,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        ctx.ContextFlags,
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));

    if (NT_SUCCESS(status) && request->should_set == 0 && !tctx_diag::user_context_sane(*request)) {
        const BOOLEAN core_present = request->rip != 0 && request->rsp != 0;
        SD_LOG("TCTX reject invalid_user_context pid=%u tid=%u status_after=0x%08X reason=%s rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=0 dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX flags=0x%08X previous_mode=%u requestor_mode=%u",
            request->pid,
            request->tid,
            core_present ? (ULONG)STATUS_INVALID_ADDRESS : (ULONG)STATUS_UNSUCCESSFUL,
            core_present ? "kernel_or_noncanonical_context" : "zero_context",
            (unsigned long long)request->rip,
            tctx_diag::address_class(request->rip),
            (unsigned long long)request->rsp,
            tctx_diag::address_class(request->rsp),
            (unsigned long long)request->rflags,
            (unsigned long long)request->dr0,
            (unsigned long long)request->dr1,
            (unsigned long long)request->dr2,
            (unsigned long long)request->dr3,
            (unsigned long long)request->dr6,
            (unsigned long long)request->dr7,
            ctx.ContextFlags,
            (ULONG)previous_mode,
            (ULONG)previous_mode);
        status = core_present ? STATUS_INVALID_ADDRESS : STATUS_UNSUCCESSFUL;
    }

    if (ctx_thread_suspended && ctx_thread_handle) {
        ULONG prev_count = 0;
        NTSTATUS resume_status = STATUS_PROCEDURE_NOT_FOUND;

        if (ctx_thread_suspended_via_ps && _PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        } else if (_ZwResumeThread || ssdt_resolver::g_NtResumeThread || ctx_thread_handle) {
            __try {
                resume_status = ssdt_resolver::call_NtResumeThread(ctx_thread_handle, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        } else if (_PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        }

        SD_LOG("TCTX resume_with_handle pid=%u tid=%u status=0x%08X status_text=%s prev=%lu ps_resume=%p zw_resume=%p handle=%p via_ps=%u final_before=0x%08X final_before_text=%s",
            request->pid,
            request->tid,
            (ULONG)resume_status,
            tctx_diag::ntstatus_text(resume_status),
            prev_count,
            _PsResumeThread,
            ssdt_resolver::g_NtResumeThread ? ssdt_resolver::g_NtResumeThread : _ZwResumeThread,
            ctx_thread_handle,
            ctx_thread_suspended_via_ps ? 1u : 0u,
            (ULONG)status,
            tctx_diag::ntstatus_text(status));
        if (NT_SUCCESS(status) && !NT_SUCCESS(resume_status)) {
            status = resume_status;
        }
    } else if (ctx_thread_suspended) {
        ULONG prev_count = 0;
        NTSTATUS resume_status = STATUS_PROCEDURE_NOT_FOUND;
        if (_PsResumeThread) {
            __try {
                resume_status = _PsResumeThread(thread, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                resume_status = (NTSTATUS)GetExceptionCode();
            }
        }
        SD_LOG("TCTX resume_ps_direct pid=%u tid=%u status=0x%08X status_text=%s prev=%lu ps_resume=%p final_before=0x%08X final_before_text=%s",
            request->pid,
            request->tid,
            (ULONG)resume_status,
            tctx_diag::ntstatus_text(resume_status),
            prev_count,
            _PsResumeThread,
            (ULONG)status,
            tctx_diag::ntstatus_text(status));
        if (NT_SUCCESS(status) && !NT_SUCCESS(resume_status)) {
            status = resume_status;
        }
    }
    if (ctx_thread_handle) {
        _ZwClose(ctx_thread_handle);
    }

    tctx_diag::thread_snapshot_t thread_after = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    SD_LOG("TCTX exit pid=%u tid=%u set=%u private_set_without_suspend=%u private_get_available=%u private_set_available=%u status=0x%08X status_text=%s open_status=0x%08X open_status_text=%s suspend_status=0x%08X suspend_status_text=%s open_strategy=%s suspend_strategy=%s suspend_constraint=%s suspended=%u via_ps=%u open_import_absent=%u suspend_import_absent=%u suspend_call_failed=%u nt_user_previous_mode_skipped=%u ps_exception=%u ps_exception_code=0x%08X nt_exception=%u nt_exception_code=0x%08X previous_mode=%u requestor_mode=%u thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu rip=0x%llX rip_class=%s rsp=0x%llX rsp_class=%s rflags=0x%llX user_sane=%u dr0=0x%llX dr1=0x%llX dr2=0x%llX dr3=0x%llX dr6=0x%llX dr7=0x%llX elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_set,
        private_set_without_suspend ? 1u : 0u,
        private_get_context_available ? 1u : 0u,
        private_set_context_available ? 1u : 0u,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        (ULONG)open_status,
        tctx_diag::ntstatus_text(open_status),
        (ULONG)suspend_status,
        tctx_diag::ntstatus_text(suspend_status),
        open_strategy,
        suspend_strategy,
        suspend_constraint,
        ctx_thread_suspended ? 1u : 0u,
        ctx_thread_suspended_via_ps ? 1u : 0u,
        open_import_absent,
        suspend_import_absent,
        suspend_call_failed,
        suspend_nt_user_previous_mode_skipped ? 1u : 0u,
        suspend_ps_exception_seen ? 1u : 0u,
        (ULONG)suspend_ps_exception_code,
        suspend_nt_exception_seen ? 1u : 0u,
        (ULONG)suspend_nt_exception_code,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        thread_after.found ? 1u : 0u,
        (ULONG)thread_after.status,
        tctx_diag::ntstatus_text(thread_after.status),
        thread_after.thread_state,
        thread_after.wait_reason,
        (unsigned long long)request->rip,
        tctx_diag::address_class(request->rip),
        (unsigned long long)request->rsp,
        tctx_diag::address_class(request->rsp),
        (unsigned long long)request->rflags,
        tctx_diag::user_context_sane(*request) ? 1u : 0u,
        (unsigned long long)request->dr0,
        (unsigned long long)request->dr1,
        (unsigned long long)request->dr2,
        (unsigned long long)request->dr3,
        (unsigned long long)request->dr6,
        (unsigned long long)request->dr7,
        dbg_guard::elapsed_ms(tctx_start, tctx_freq));

    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    return status;
}


namespace tsr_system_route {
    constexpr ULONG kWorkerTag = 'rTsT';
    constexpr LONGLONG kWorkerWait100ns = -10000000LL;

    struct worker_t {
        KEVENT done;
        PETHREAD thread;
        POBJECT_TYPE thread_type;
        UINT32 pid;
        UINT32 tid;
        UINT32 should_resume;
        ULONG previous_count;
        NTSTATUS status;
        NTSTATUS open_status;
        NTSTATUS call_status;
        NTSTATUS close_status;
        KPROCESSOR_MODE caller_mode;
        KPROCESSOR_MODE worker_mode;
        HANDLE thread_handle;
        LARGE_INTEGER start;
        LARGE_INTEGER freq;
        volatile LONG refs;
    };

    __forceinline void release_work(worker_t* work) {
        if (work && InterlockedDecrement(&work->refs) == 0) {
            ExFreePoolWithTag(work, kWorkerTag);
        }
    }

    VOID NTAPI worker_entry(PVOID parameter) {
        worker_t* work = static_cast<worker_t*>(parameter);
        if (!work) {
            if (_PsTerminateSystemThread) {
                _PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
            }
            return;
        }

        work->worker_mode = ExGetPreviousMode();
        tctx_diag::thread_snapshot_t before = tctx_diag::query_thread_snapshot(work->pid, work->tid);
        SD_LOG("TSR system_worker_entry pid=%u tid=%u resume=%u caller_previous_mode=%u worker_previous_mode=%u current_pid=%p current_tid=%p thread=%p thread_type=%p thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu elapsed_ms=%llu",
            work->pid,
            work->tid,
            work->should_resume,
            (ULONG)work->caller_mode,
            (ULONG)work->worker_mode,
            PsGetCurrentProcessId(),
            PsGetCurrentThreadId(),
            work->thread,
            work->thread_type,
            before.found ? 1u : 0u,
            (ULONG)before.status,
            tctx_diag::ntstatus_text(before.status),
            before.thread_state,
            before.wait_reason,
            tctx_diag::elapsed_ms(work->start, work->freq));

        __try {
            work->open_status = _ObOpenObjectByPointer(
                work->thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SUSPEND_RESUME,
                work->thread_type,
                KernelMode,
                &work->thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            work->open_status = (NTSTATUS)GetExceptionCode();
            work->thread_handle = nullptr;
        }

        SD_LOG("TSR system_worker_open pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu handle=%p thread_type=%p elapsed_ms=%llu",
            work->pid,
            work->tid,
            work->should_resume,
            (ULONG)work->open_status,
            tctx_diag::ntstatus_text(work->open_status),
            tctx_diag::ntstatus_win32(work->open_status),
            work->thread_handle,
            work->thread_type,
            tctx_diag::elapsed_ms(work->start, work->freq));

        if (NT_SUCCESS(work->open_status) && work->thread_handle) {
            ULONG prev_count = 0;
            __try {
                work->call_status = work->should_resume == 0
                    ? ssdt_resolver::call_NtSuspendThread(work->thread_handle, &prev_count)
                    : ssdt_resolver::call_NtResumeThread(work->thread_handle, &prev_count);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                work->call_status = (NTSTATUS)GetExceptionCode();
            }
            work->previous_count = prev_count;
            SD_LOG("TSR system_worker_call pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu prev=%lu worker_previous_mode=%u zw_suspend=%p zw_resume=%p nt_suspend=%p nt_resume=%p elapsed_ms=%llu",
                work->pid,
                work->tid,
                work->should_resume,
                (ULONG)work->call_status,
                tctx_diag::ntstatus_text(work->call_status),
                tctx_diag::ntstatus_win32(work->call_status),
                work->previous_count,
                (ULONG)work->worker_mode,
                _ZwSuspendThread,
                _ZwResumeThread,
                ssdt_resolver::g_NtSuspendThread,
                ssdt_resolver::g_NtResumeThread,
                tctx_diag::elapsed_ms(work->start, work->freq));

            __try {
                work->close_status = _ZwClose(work->thread_handle);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                work->close_status = (NTSTATUS)GetExceptionCode();
            }
            work->thread_handle = nullptr;
        } else {
            work->call_status = work->open_status;
        }

        work->status = NT_SUCCESS(work->open_status) ? work->call_status : work->open_status;
        tctx_diag::thread_snapshot_t after = tctx_diag::query_thread_snapshot(work->pid, work->tid);
        SD_LOG("TSR system_worker_exit pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu open_status=0x%08X call_status=0x%08X close_status=0x%08X prev=%lu thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu elapsed_ms=%llu",
            work->pid,
            work->tid,
            work->should_resume,
            (ULONG)work->status,
            tctx_diag::ntstatus_text(work->status),
            tctx_diag::ntstatus_win32(work->status),
            (ULONG)work->open_status,
            (ULONG)work->call_status,
            (ULONG)work->close_status,
            work->previous_count,
            after.found ? 1u : 0u,
            (ULONG)after.status,
            tctx_diag::ntstatus_text(after.status),
            after.thread_state,
            after.wait_reason,
            tctx_diag::elapsed_ms(work->start, work->freq));

        if (_ObfDereferenceObject) {
            _ObfDereferenceObject(work->thread);
        }
        KeSetEvent(&work->done, IO_NO_INCREMENT, FALSE);
        release_work(work);
        if (_PsTerminateSystemThread) {
            _PsTerminateSystemThread(STATUS_SUCCESS);
        }
    }

    NTSTATUS run(PETHREAD thread,
                 POBJECT_TYPE thread_type,
                 p_suspend_resume_thread request,
                 KPROCESSOR_MODE caller_mode,
                 const LARGE_INTEGER& parent_start,
                 const LARGE_INTEGER& parent_freq) {
        if (!thread || !thread_type || !request) {
            return STATUS_INVALID_PARAMETER;
        }
        if (!_PsCreateSystemThread || !_PsTerminateSystemThread || !_ObOpenObjectByPointer || !_ZwClose || !_ObReferenceObjectSafe || !_ObfDereferenceObject) {
            SD_LOG("TSR system_route_unavailable pid=%u tid=%u resume=%u create=%p terminate=%p ob_open=%p zw_close=%p ob_ref_safe=%p deref=%p thread_type=%p elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_resume,
                _PsCreateSystemThread,
                _PsTerminateSystemThread,
                _ObOpenObjectByPointer,
                _ZwClose,
                _ObReferenceObjectSafe,
                _ObfDereferenceObject,
                thread_type,
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            return STATUS_PROCEDURE_NOT_FOUND;
        }
        if (!_ObReferenceObjectSafe(thread)) {
            SD_LOG("TSR system_route_ref_failed pid=%u tid=%u resume=%u thread=%p elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_resume,
                thread,
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            return STATUS_THREAD_IS_TERMINATING;
        }

        worker_t* work = static_cast<worker_t*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(worker_t), kWorkerTag));
        if (!work) {
            _ObfDereferenceObject(thread);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        strong::kmemset(work, 0, sizeof(*work));
        KeInitializeEvent(&work->done, NotificationEvent, FALSE);
        work->thread = thread;
        work->thread_type = thread_type;
        work->pid = request->pid;
        work->tid = request->tid;
        work->should_resume = request->should_resume;
        work->status = STATUS_UNSUCCESSFUL;
        work->open_status = STATUS_NOT_FOUND;
        work->call_status = STATUS_NOT_FOUND;
        work->close_status = STATUS_NOT_FOUND;
        work->caller_mode = caller_mode;
        work->start = KeQueryPerformanceCounter(&work->freq);
        work->refs = 2;

        HANDLE worker_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
        NTSTATUS create_status = _PsCreateSystemThread(
            &worker_handle,
            THREAD_ALL_ACCESS,
            &oa,
            nullptr,
            nullptr,
            worker_entry,
            work);

        SD_LOG("TSR system_route_create pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu worker_handle=%p caller_previous_mode=%u elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)create_status,
            tctx_diag::ntstatus_text(create_status),
            tctx_diag::ntstatus_win32(create_status),
            worker_handle,
            (ULONG)caller_mode,
            tctx_diag::elapsed_ms(parent_start, parent_freq));

        if (!NT_SUCCESS(create_status)) {
            _ObfDereferenceObject(thread);
            ExFreePoolWithTag(work, kWorkerTag);
            return create_status;
        }

        LARGE_INTEGER timeout;
        timeout.QuadPart = kWorkerWait100ns;
        NTSTATUS wait_status = KeWaitForSingleObject(&work->done, Executive, KernelMode, FALSE, &timeout);
        if (wait_status != STATUS_SUCCESS) {
            SD_LOG("TSR system_route_wait_bounded pid=%u tid=%u resume=%u wait_status=0x%08X wait_status_text=%s win32=%lu timeout_100ns=%lld worker_handle=%p elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_resume,
                (ULONG)wait_status,
                tctx_diag::ntstatus_text(wait_status),
                tctx_diag::ntstatus_win32(wait_status),
                (long long)kWorkerWait100ns,
                worker_handle,
                tctx_diag::elapsed_ms(parent_start, parent_freq));
            if (worker_handle) {
                NTSTATUS close_worker_status = _ZwClose(worker_handle);
                SD_LOG("TSR system_route_worker_handle_close pid=%u tid=%u resume=%u handle=%p status=0x%08X status_text=%s win32=%lu after_timeout=1 elapsed_ms=%llu",
                    request->pid,
                    request->tid,
                    request->should_resume,
                    worker_handle,
                    (ULONG)close_worker_status,
                    tctx_diag::ntstatus_text(close_worker_status),
                    tctx_diag::ntstatus_win32(close_worker_status),
                    tctx_diag::elapsed_ms(parent_start, parent_freq));
            }
            release_work(work);
            return STATUS_IO_TIMEOUT;
        }

        if (worker_handle) {
            NTSTATUS close_worker_status = _ZwClose(worker_handle);
            SD_LOG("TSR system_route_worker_handle_close pid=%u tid=%u resume=%u handle=%p status=0x%08X status_text=%s win32=%lu elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_resume,
                worker_handle,
                (ULONG)close_worker_status,
                tctx_diag::ntstatus_text(close_worker_status),
                tctx_diag::ntstatus_win32(close_worker_status),
                tctx_diag::elapsed_ms(parent_start, parent_freq));
        }

        NTSTATUS status = work->status;
        request->previous_count = work->previous_count;
        SD_LOG("TSR system_route_exit pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu prev=%lu open_status=0x%08X call_status=0x%08X close_status=0x%08X elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            tctx_diag::ntstatus_win32(status),
            request->previous_count,
            (ULONG)work->open_status,
            (ULONG)work->call_status,
            (ULONG)work->close_status,
            tctx_diag::elapsed_ms(parent_start, parent_freq));
        release_work(work);
        return status;
    }
}

NTSTATUS functions::handle_thread_enum(p_thread_enum request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!_PsLookupProcessByProcessId || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    dbg_guard::timing_scatter();

    ULONG required_length = 0;
    status = ZwQuerySystemInformation(
        sysinfo_guard::kSystemProcessInformationClass,
        nullptr,
        0,
        &required_length);

    if (status != STATUS_INFO_LENGTH_MISMATCH || required_length < sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL)) {
        _ObfDereferenceObject(process);
        return NT_SUCCESS(status) ? STATUS_UNSUCCESSFUL : status;
    }

    ULONG buffer_length = required_length + 0x4000;
    PVOID buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
    if (!buffer) {
        _ObfDereferenceObject(process);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    for (int attempt = 0; attempt < 3; ++attempt) {
        status = ZwQuerySystemInformation(
            sysinfo_guard::kSystemProcessInformationClass,
            buffer,
            buffer_length,
            &required_length);

        if (status != STATUS_INFO_LENGTH_MISMATCH) {
            break;
        }

        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        buffer_length = required_length + 0x4000;
        buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, buffer_length, sysinfo_guard::kThreadInfoTag);
        if (!buffer) {
            _ObfDereferenceObject(process);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);
        _ObfDereferenceObject(process);
        return status;
    }

    UINT32 count = 0;
    BOOLEAN process_found = FALSE;
    PUCHAR cursor = (PUCHAR)buffer;

    while (TRUE) {
        auto info = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION_LOCAL>(cursor);
        if ((UINT32)(ULONG_PTR)info->UniqueProcessId == request->pid) {
            process_found = TRUE;
            auto threads = reinterpret_cast<PSYSTEM_THREAD_INFORMATION_LOCAL>(cursor + sizeof(SYSTEM_PROCESS_INFORMATION_LOCAL));

            for (ULONG index = 0; index < info->NumberOfThreads && count < MAX_ENUM_THREADS; ++index) {
                request->entries[count].tid = (UINT32)(ULONG_PTR)threads[index].ClientId.UniqueThread;
                request->entries[count].state = threads[index].ThreadState;
                request->entries[count].rip = (UINT64)threads[index].StartAddress;
                count++;
            }
            break;
        }

        if (info->NextEntryOffset == 0) {
            break;
        }

        cursor += info->NextEntryOffset;
    }

    ExFreePoolWithTag(buffer, sysinfo_guard::kThreadInfoTag);

    _ObfDereferenceObject(process);
    request->thread_count = count;

    if (!process_found) {
        return STATUS_NOT_FOUND;
    }

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_suspend_resume_thread(p_suspend_resume_thread request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        SD_LOG("TSR reject invalid_request request=%p pid=%u tid=%u resume=%u",
            request,
            request ? request->pid : 0,
            request ? request->tid : 0,
            request ? request->should_resume : 0);
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SD_LOG("TSR reject bad_irql pid=%u tid=%u resume=%u irql=%u",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    LARGE_INTEGER tsr_freq = {};
    LARGE_INTEGER tsr_start = KeQueryPerformanceCounter(&tsr_freq);
    POBJECT_TYPE thread_type = (PsThreadType && *PsThreadType) ? *PsThreadType : nullptr;
    BOOLEAN use_ps = (_PsSuspendThread != nullptr && _PsResumeThread != nullptr);
    BOOLEAN use_handle = (_ObOpenObjectByPointer != nullptr && _ZwClose != nullptr && thread_type != nullptr);
    KPROCESSOR_MODE previous_mode = ExGetPreviousMode();

    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId || !_ObfDereferenceObject || (!use_ps && !use_handle)) {
        SD_LOG("TSR reject missing_import pid=%u tid=%u resume=%u lookup_process=%p lookup_thread=%p deref=%p use_ps=%u use_handle=%u ps_suspend=%p ps_resume=%p ob_open=%p zw_close=%p thread_type=%p",
            request->pid,
            request->tid,
            request->should_resume,
            _PsLookupProcessByProcessId,
            _PsLookupThreadByThreadId,
            _ObfDereferenceObject,
            use_ps ? 1u : 0u,
            use_handle ? 1u : 0u,
            _PsSuspendThread,
            _PsResumeThread,
            _ObOpenObjectByPointer,
            _ZwClose,
            thread_type);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        SD_LOG("TSR lookup_process pid=%u tid=%u resume=%u status=0x%08X status_text=%s elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            dbg_guard::elapsed_ms(tsr_start, tsr_freq));
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId(
        (HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        SD_LOG("TSR lookup_thread pid=%u tid=%u resume=%u status=0x%08X status_text=%s elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            dbg_guard::elapsed_ms(tsr_start, tsr_freq));
        _ObfDereferenceObject(process);
        return status;
    }

    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            SD_LOG("TSR reject process_mismatch pid=%u tid=%u resume=%u process=%p thread_process=%p elapsed_ms=%llu",
                request->pid,
                request->tid,
                request->should_resume,
                process,
                thread_process,
                dbg_guard::elapsed_ms(tsr_start, tsr_freq));
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            return STATUS_INVALID_CID;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
        SD_LOG("TSR reject process_check_exception pid=%u tid=%u resume=%u status=0x%08X status_text=%s elapsed_ms=%llu",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            dbg_guard::elapsed_ms(tsr_start, tsr_freq));
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        return STATUS_INVALID_CID;
    }

    tctx_diag::thread_snapshot_t before = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    SD_LOG("TSR entry pid=%u tid=%u resume=%u previous_mode=%u requestor_mode=%u use_ps=%u use_handle=%u ps_suspend=%p ps_resume=%p zw_suspend=%p zw_resume=%p nt_suspend=%p nt_resume=%p ob_open=%p zw_close=%p thread_type=%p thread_found=%u thread_status=0x%08X thread_status_text=%s thread_state=%lu wait_reason=%lu elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_resume,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        use_ps ? 1u : 0u,
        use_handle ? 1u : 0u,
        _PsSuspendThread,
        _PsResumeThread,
        _ZwSuspendThread,
        _ZwResumeThread,
        ssdt_resolver::g_NtSuspendThread,
        ssdt_resolver::g_NtResumeThread,
        _ObOpenObjectByPointer,
        _ZwClose,
        thread_type,
        before.found ? 1u : 0u,
        (ULONG)before.status,
        tctx_diag::ntstatus_text(before.status),
        before.thread_state,
        before.wait_reason,
        dbg_guard::elapsed_ms(tsr_start, tsr_freq));

    ULONG prev_count = 0;

    if (use_ps) {
        BOOLEAN ps_exception_seen = FALSE;
        NTSTATUS ps_exception_code = STATUS_SUCCESS;
        __try {
            if (request->should_resume == 0) {
                status = _PsSuspendThread(thread, &prev_count);
            }
            else {
                status = _PsResumeThread(thread, &prev_count);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
            ps_exception_seen = TRUE;
            ps_exception_code = status;
        }
        SD_LOG("TSR ps pid=%u tid=%u resume=%u status=0x%08X status_text=%s prev=%lu previous_mode=%u requestor_mode=%u exception=%u exception_code=0x%08X",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            tctx_diag::ntstatus_text(status),
            prev_count,
            (ULONG)previous_mode,
            (ULONG)previous_mode,
            ps_exception_seen ? 1u : 0u,
            (ULONG)ps_exception_code);
    }
    if ((!use_ps || !NT_SUCCESS(status)) && use_handle) {

        HANDLE thread_handle = nullptr;
        prev_count = 0;
        __try {
            status = _ObOpenObjectByPointer(
                thread,
                OBJ_KERNEL_HANDLE,
                nullptr,
                THREAD_SUSPEND_RESUME,
                thread_type,
                KernelMode,
                &thread_handle);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            status = (NTSTATUS)GetExceptionCode();
            thread_handle = nullptr;
        }
        SD_LOG("TSR open pid=%u tid=%u resume=%u status=0x%08X handle=%p thread_type=%p",
            request->pid,
            request->tid,
            request->should_resume,
            (ULONG)status,
            thread_handle,
            thread_type);

        if (NT_SUCCESS(status) && thread_handle) {
            prev_count = 0;
            BOOLEAN nt_exception_seen = FALSE;
            NTSTATUS nt_exception_code = STATUS_SUCCESS;
            BOOLEAN direct_nt_skipped = FALSE;
            const BOOLEAN ssdt_ready_for_operation =
                (request->should_resume == 0)
                    ? (ssdt_resolver::g_NtSuspendThread != nullptr || ssdt_resolver::resolve_suspend_resume())
                    : (ssdt_resolver::g_NtResumeThread != nullptr || ssdt_resolver::resolve_suspend_resume());
            const BOOLEAN missing_kernel_resume_path =
                (request->should_resume == 0)
                    ? (_ZwSuspendThread == nullptr && !ssdt_ready_for_operation)
                    : (_ZwResumeThread == nullptr && !ssdt_ready_for_operation);
            const BOOLEAN raw_ssdt_requires_kernel_previous_mode =
                (request->should_resume == 0)
                    ? (_ZwSuspendThread == nullptr && ssdt_ready_for_operation && previous_mode != KernelMode)
                    : (_ZwResumeThread == nullptr && ssdt_ready_for_operation && previous_mode != KernelMode);
            if (raw_ssdt_requires_kernel_previous_mode) {
                direct_nt_skipped = TRUE;
                status = tsr_system_route::run(thread, thread_type, request, previous_mode, tsr_start, tsr_freq);
                prev_count = request->previous_count;
            } else if (missing_kernel_resume_path && previous_mode != KernelMode) {
                direct_nt_skipped = TRUE;
                status = STATUS_INVALID_DEVICE_STATE;
            } else {
                __try {
                    if (request->should_resume == 0) {
                        status = ssdt_resolver::call_NtSuspendThread(thread_handle, &prev_count);
                    }
                    else {
                        status = ssdt_resolver::call_NtResumeThread(thread_handle, &prev_count);
                    }
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    status = (NTSTATUS)GetExceptionCode();
                    nt_exception_seen = TRUE;
                    nt_exception_code = status;
                }
            }
            SD_LOG("TSR nt pid=%u tid=%u resume=%u status=0x%08X status_text=%s prev=%lu zw_suspend=%p zw_resume=%p nt_suspend=%p nt_resume=%p previous_mode=%u requestor_mode=%u direct_nt_skipped=%u raw_ssdt_system_route=%u exception=%u exception_code=0x%08X",
                request->pid,
                request->tid,
                request->should_resume,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                prev_count,
                _ZwSuspendThread,
                _ZwResumeThread,
                ssdt_resolver::g_NtSuspendThread,
                ssdt_resolver::g_NtResumeThread,
                (ULONG)previous_mode,
                (ULONG)previous_mode,
                direct_nt_skipped ? 1u : 0u,
                raw_ssdt_requires_kernel_previous_mode ? 1u : 0u,
                nt_exception_seen ? 1u : 0u,
                (ULONG)nt_exception_code);
            _ZwClose(thread_handle);
        }
        else {
            SD_LOG("TSR open_failed pid=%u tid=%u resume=%u status=0x%08X status_text=%s use_ps=%u use_handle=%u previous_mode=%u requestor_mode=%u",
                request->pid,
                request->tid,
                request->should_resume,
                (ULONG)status,
                tctx_diag::ntstatus_text(status),
                use_ps ? 1u : 0u,
                use_handle ? 1u : 0u,
                (ULONG)previous_mode,
                (ULONG)previous_mode);
        }
    }

    request->previous_count = prev_count;
    tctx_diag::thread_snapshot_t after = tctx_diag::query_thread_snapshot(request->pid, request->tid);
    SD_LOG("TSR exit pid=%u tid=%u resume=%u status=0x%08X status_text=%s win32=%lu prev=%lu previous_mode=%u requestor_mode=%u thread_after_found=%u thread_after_status=0x%08X thread_after_status_text=%s thread_after_state=%lu thread_after_wait_reason=%lu elapsed_ms=%llu",
        request->pid,
        request->tid,
        request->should_resume,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        tctx_diag::ntstatus_win32(status),
        request->previous_count,
        (ULONG)previous_mode,
        (ULONG)previous_mode,
        after.found ? 1u : 0u,
        (ULONG)after.status,
        tctx_diag::ntstatus_text(after.status),
        after.thread_state,
        after.wait_reason,
        dbg_guard::elapsed_ms(tsr_start, tsr_freq));
    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_thread_query_information(p_thread_query_information request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (request->info_class != 0) {
        request->status = (UINT32)STATUS_NOT_SUPPORTED;
        return STATUS_NOT_SUPPORTED;
    }
    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_ObfDereferenceObject || !_ObOpenObjectByPointer || !_ZwClose ||
        !_ZwQueryInformationThread) {
        request->status = (UINT32)STATUS_PROCEDURE_NOT_FOUND;
        SD_LOG("TQIF reject missing_import pid=%u tid=%u lookup_process=%p lookup_thread=%p deref=%p ob_open=%p zw_close=%p zw_query_thread=%p",
            request->pid,
            request->tid,
            _PsLookupProcessByProcessId,
            _PsLookupThreadByThreadId,
            _ObfDereferenceObject,
            _ObOpenObjectByPointer,
            _ZwClose,
            _ZwQueryInformationThread);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        request->status = (UINT32)status;
        SD_LOG("TQIF lookup_process pid=%u tid=%u status=0x%08X status_text=%s",
            request->pid, request->tid, (ULONG)status, tctx_diag::ntstatus_text(status));
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        _ObfDereferenceObject(process);
        request->status = (UINT32)status;
        SD_LOG("TQIF lookup_thread pid=%u tid=%u status=0x%08X status_text=%s",
            request->pid, request->tid, (ULONG)status, tctx_diag::ntstatus_text(status));
        return status;
    }

    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            request->status = (UINT32)STATUS_INVALID_CID;
            SD_LOG("TQIF reject process_mismatch pid=%u tid=%u process=%p thread_process=%p",
                request->pid, request->tid, process, thread_process);
            return STATUS_INVALID_CID;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        request->status = (UINT32)status;
        SD_LOG("TQIF reject process_check_exception pid=%u tid=%u status=0x%08X",
            request->pid, request->tid, (ULONG)status);
        return status;
    }

    POBJECT_TYPE thread_type = PsThreadType ? *PsThreadType : nullptr;
    HANDLE thread_handle = nullptr;
    status = _ObOpenObjectByPointer(
        thread,
        OBJ_KERNEL_HANDLE,
        nullptr,
        kThreadQueryInformationAccess,
        thread_type,
        KernelMode,
        &thread_handle);
    if (NT_SUCCESS(status) && thread_handle) {
        THREAD_BASIC_INFORMATION_LOCAL tbi{};
        ULONG returned = 0;
        status = _ZwQueryInformationThread(
            thread_handle,
            0,
            &tbi,
            sizeof(tbi),
            &returned);
        request->return_length = returned;
        if (NT_SUCCESS(status)) {
            request->exit_status = static_cast<INT64>(tbi.ExitStatus);
            request->teb_base = (UINT64)(ULONG_PTR)tbi.TebBaseAddress;
            request->client_process = (UINT64)(ULONG_PTR)tbi.ClientId.UniqueProcess;
            request->client_thread = (UINT64)(ULONG_PTR)tbi.ClientId.UniqueThread;
            request->affinity_mask = (UINT64)tbi.AffinityMask;
            request->priority = (INT32)tbi.Priority;
            request->base_priority = (INT32)tbi.BasePriority;
        }
        _ZwClose(thread_handle);
    }
    request->status = (UINT32)status;
    SD_LOG("TQIF exit pid=%u tid=%u status=0x%08X status_text=%s teb=0x%llX client_pid=0x%llX client_tid=0x%llX return=%u",
        request->pid,
        request->tid,
        (ULONG)status,
        tctx_diag::ntstatus_text(status),
        (unsigned long long)request->teb_base,
        (unsigned long long)request->client_process,
        (unsigned long long)request->client_thread,
        request->return_length);
    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);
    return status;
}


NTSTATUS functions::handle_terminate_thread(p_terminate_thread_request request) {
    if (!request || request->pid == 0 || request->tid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (request->tid == HandleToULong(PsGetCurrentThreadId())) {
        request->status = (UINT32)STATUS_INVALID_PARAMETER;
        return STATUS_INVALID_PARAMETER;
    }
    if (!_PsLookupProcessByProcessId || !_PsLookupThreadByThreadId ||
        !_ObfDereferenceObject || !_ObOpenObjectByPointer || !_ZwClose ||
        !_ZwTerminateThread) {
        request->status = (UINT32)STATUS_PROCEDURE_NOT_FOUND;
        SD_LOG("TTERM reject missing_import pid=%u tid=%u lookup_process=%p lookup_thread=%p deref=%p ob_open=%p zw_close=%p zw_term=%p",
            request->pid,
            request->tid,
            _PsLookupProcessByProcessId,
            _PsLookupThreadByThreadId,
            _ObfDereferenceObject,
            _ObOpenObjectByPointer,
            _ZwClose,
            _ZwTerminateThread);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        request->status = (UINT32)status;
        return status;
    }

    PETHREAD thread = nullptr;
    status = _PsLookupThreadByThreadId((HANDLE)(ULONG_PTR)request->tid, &thread);
    if (!NT_SUCCESS(status) || !thread) {
        _ObfDereferenceObject(process);
        request->status = (UINT32)status;
        return status;
    }

    __try {
        PEPROCESS thread_process = IoThreadToProcess(thread);
        if (thread_process != process) {
            _ObfDereferenceObject(thread);
            _ObfDereferenceObject(process);
            request->status = (UINT32)STATUS_INVALID_CID;
            SD_LOG("TTERM reject process_mismatch pid=%u tid=%u process=%p thread_process=%p",
                request->pid, request->tid, process, thread_process);
            return STATUS_INVALID_CID;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        status = (NTSTATUS)GetExceptionCode();
        _ObfDereferenceObject(thread);
        _ObfDereferenceObject(process);
        request->status = (UINT32)status;
        return status;
    }

    POBJECT_TYPE thread_type = PsThreadType ? *PsThreadType : nullptr;
    HANDLE thread_handle = nullptr;
    status = _ObOpenObjectByPointer(
        thread,
        OBJ_KERNEL_HANDLE,
        nullptr,
        THREAD_TERMINATE,
        thread_type,
        KernelMode,
        &thread_handle);
    if (NT_SUCCESS(status) && thread_handle) {
        status = _ZwTerminateThread(thread_handle, (NTSTATUS)request->exit_status);
        _ZwClose(thread_handle);
    }
    request->status = (UINT32)status;
    SD_LOG("TTERM exit pid=%u tid=%u exit=0x%08X status=0x%08X status_text=%s",
        request->pid,
        request->tid,
        request->exit_status,
        (ULONG)status,
        tctx_diag::ntstatus_text(status));
    _ObfDereferenceObject(thread);
    _ObfDereferenceObject(process);
    return status;
}


NTSTATUS functions::handle_close_process_handle(p_close_handle_request request) {
    if (!request || request->pid == 0 || request->handle_value == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }
    if (!_ZwOpenProcess || !_ZwClose) {
        request->status = (UINT32)STATUS_PROCEDURE_NOT_FOUND;
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    HANDLE owner_handle = nullptr;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, nullptr, OBJ_KERNEL_HANDLE, nullptr, nullptr);
    CLIENT_ID cid{};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)request->pid;
    cid.UniqueThread = nullptr;
    NTSTATUS status = _ZwOpenProcess(&owner_handle, PROCESS_DUP_HANDLE, &oa, &cid);
    if (NT_SUCCESS(status) && owner_handle) {
        HANDLE dup = nullptr;
        status = ZwDuplicateObject(
            owner_handle,
            (HANDLE)(ULONG_PTR)request->handle_value,
            NtCurrentProcess(),
            &dup,
            0,
            OBJ_KERNEL_HANDLE,
            DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE);
        if (dup) {
            _ZwClose(dup);
        }
        _ZwClose(owner_handle);
    }
    request->status = (UINT32)status;
    SD_LOG("HCLS exit pid=%u handle=0x%llX status=0x%08X status_text=%s",
        request->pid,
        (unsigned long long)request->handle_value,
        (ULONG)status,
        tctx_diag::ntstatus_text(status));
    return status;
}


NTSTATUS functions::handle_query_memory(p_query_memory request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    MEMORY_BASIC_INFORMATION mbi;
    strong::kmemset(&mbi, 0, sizeof(mbi));
    SIZE_T returned_length = 0;

    status = _ZwQueryVirtualMemory(
        (HANDLE)-1,
        (PVOID)request->address,
        MemoryBasicInformation,
        &mbi,
        sizeof(mbi),
        &returned_length);

    if (NT_SUCCESS(status)) {
        request->region_base    = (UINT64)mbi.BaseAddress;
        request->region_size    = (UINT64)mbi.RegionSize;
        request->state          = mbi.State;
        request->protect        = mbi.Protect;
        request->type           = mbi.Type;
        request->allocation_base = (UINT64)mbi.AllocationBase;
        request->allocation_protect = mbi.AllocationProtect;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_protect_memory(p_protect_memory request) {
    if (!request) {
        SD_LOG("memory::protect_memory: REJECT request=null");
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        SD_LOG("memory::protect_memory: REJECT irql=%lu", KeGetCurrentIrql());
        return STATUS_INVALID_DEVICE_STATE;
    }

    SD_LOG("memory::protect_memory: handle ENTER pid=%lu addr=0x%016llX size=0x%llX new=0x%08X",
        (ULONG)request->pid,
        (unsigned long long)request->address,
        (unsigned long long)request->size,
        (ULONG)request->new_protect);

    if (request->pid == 0 || request->size == 0) {
        SD_LOG("memory::protect_memory: REJECT pid_or_size_zero pid=%lu size=0x%llX",
            (ULONG)request->pid, (unsigned long long)request->size);
        return STATUS_INVALID_PARAMETER;
    }

    if (request->address == 0) {
        SD_LOG("memory::protect_memory: REJECT addr_zero");
        return STATUS_INVALID_PARAMETER;
    }

    const UINT64 kUserAddressMax = 0x00007FFFFFFFFFFFULL;
    if (request->address >= kUserAddressMax) {
        SD_LOG("memory::protect_memory: REJECT addr_kernel_range addr=0x%016llX",
            (unsigned long long)request->address);
        return STATUS_INVALID_ADDRESS;
    }

    if (request->size > 0x00000000FFFFFFFFULL) {
        SD_LOG("memory::protect_memory: REJECT size_too_large size=0x%llX",
            (unsigned long long)request->size);
        return STATUS_INVALID_PARAMETER;
    }

    if ((request->address + request->size) < request->address ||
        (request->address + request->size) >= kUserAddressMax) {
        SD_LOG("memory::protect_memory: REJECT range_overflow addr=0x%016llX size=0x%llX",
            (unsigned long long)request->address,
            (unsigned long long)request->size);
        return STATUS_INVALID_ADDRESS;
    }

    const ULONG kAllowedProtect =
        PAGE_NOACCESS | PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
        PAGE_EXECUTE_WRITECOPY | PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE;
    if ((request->new_protect & ~kAllowedProtect) != 0 || request->new_protect == 0) {
        SD_LOG("memory::protect_memory: REJECT bad_protect_flags new=0x%08X mask=0x%08X",
            (ULONG)request->new_protect, (ULONG)kAllowedProtect);
        return STATUS_INVALID_PAGE_PROTECTION;
    }

    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwProtectVirtualMemory || !_ObfDereferenceObject) {
        SD_LOG("memory::protect_memory: REJECT procedures_missing PsLookup=%p KeStack=%p KeUnstack=%p ZwProtect=%p ObfDeref=%p",
            _PsLookupProcessByProcessId, _KeStackAttachProcess,
            _KeUnstackDetachProcess, _ZwProtectVirtualMemory, _ObfDereferenceObject);
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        SD_LOG("memory::protect_memory: PsLookupProcessByProcessId FAIL pid=%lu status=0x%08X process=%p",
            (ULONG)request->pid, (ULONG)status, process);
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    PVOID base_addr = (PVOID)request->address;
    SIZE_T region_size = (SIZE_T)request->size;
    ULONG old_protect = 0;

    __try {
        status = _ZwProtectVirtualMemory(
            (HANDLE)-1,
            &base_addr,
            &region_size,
            request->new_protect,
            &old_protect);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        SD_LOG("memory::protect_memory: EXCEPTION pid=%lu addr=0x%016llX code=0x%08X",
            (ULONG)request->pid,
            (unsigned long long)request->address,
            (ULONG)status);
    }

    SD_LOG("memory::protect_memory: ZwProtectVirtualMemory RESULT pid=%lu in_addr=0x%016llX out_addr=0x%016llX in_size=0x%llX out_size=0x%llX new=0x%08X old=0x%08X status=0x%08X",
        (ULONG)request->pid,
        (unsigned long long)request->address,
        (unsigned long long)(ULONG_PTR)base_addr,
        (unsigned long long)request->size,
        (unsigned long long)region_size,
        (ULONG)request->new_protect,
        (ULONG)old_protect,
        (ULONG)status);

    if (NT_SUCCESS(status)) {
        request->old_protect = old_protect;
    }
    else {
        request->old_protect = 0;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return status;
}


NTSTATUS functions::handle_enum_regions(p_enum_regions request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!_PsLookupProcessByProcessId || !_KeStackAttachProcess ||
        !_KeUnstackDetachProcess || !_ZwQueryVirtualMemory || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);

    UINT32 count = 0;
    UINT64 addr = request->start_address;
    UINT64 max_addr = 0x00007FFFFFFFFFFFULL;
    if (request->max_address != 0 && request->max_address < max_addr) {
        max_addr = request->max_address;
    }

    while (addr < max_addr && count < MAX_ENUM_REGIONS) {
        MEMORY_BASIC_INFORMATION mbi;
        strong::kmemset(&mbi, 0, sizeof(mbi));
        SIZE_T returned = 0;

        status = _ZwQueryVirtualMemory(
            (HANDLE)-1,
            (PVOID)addr,
            MemoryBasicInformation,
            &mbi,
            sizeof(mbi),
            &returned);

        if (!NT_SUCCESS(status) || mbi.RegionSize == 0) {
            break;
        }


        if (mbi.State == MEM_COMMIT || request->include_all) {
            request->entries[count].base    = (UINT64)mbi.BaseAddress;
            request->entries[count].size    = (UINT64)mbi.RegionSize;
            request->entries[count].state   = mbi.State;
            request->entries[count].protect = mbi.Protect;
            request->entries[count].type    = mbi.Type;
            count++;
        }

        UINT64 next = (UINT64)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    request->region_count = count;

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_read_peb(p_read_peb request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    PVOID peb = (PVOID)_PsGetProcessPeb(process);
    if (!peb) {
        _ObfDereferenceObject(process);
        return STATUS_NOT_FOUND;
    }

    request->peb_address = (UINT64)peb;


    KAPC_STATE apc_state;
    _KeStackAttachProcess(process, &apc_state);


    __try {
        UCHAR* peb_base = (UCHAR*)peb;
        request->image_base      = *(UINT64*)(peb_base + 0x10);
        request->being_debugged  = *(UCHAR*)(peb_base + 0x02);
        request->nt_global_flag  = *(UINT32*)(peb_base + 0xBC);
        request->ldr_address     = *(UINT64*)(peb_base + 0x18);
        request->process_heap    = *(UINT64*)(peb_base + 0x30);
        request->number_of_heaps = *(UINT32*)(peb_base + 0xE8);
        request->max_heaps       = *(UINT32*)(peb_base + 0xEC);
        request->process_heaps   = *(UINT64*)(peb_base + 0xF0);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        _KeUnstackDetachProcess(&apc_state);
        _ObfDereferenceObject(process);
        return STATUS_ACCESS_VIOLATION;
    }

    _KeUnstackDetachProcess(&apc_state);
    _ObfDereferenceObject(process);

    return STATUS_SUCCESS;
}


NTSTATUS functions::handle_spoof_debug_flags(p_spoof_debug request) {
    if (!request || request->pid == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;
    }

    if (!_PsLookupProcessByProcessId || !_PsGetProcessPeb ||
        !_KeStackAttachProcess || !_KeUnstackDetachProcess || !_ObfDereferenceObject) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    dbg_guard::timing_scatter();

    PEPROCESS process = nullptr;
    NTSTATUS status = _PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)request->pid, &process);
    if (!NT_SUCCESS(status) || !process) {
        return status;
    }

    UINT32 cleared = 0;


    PVOID peb = (PVOID)_PsGetProcessPeb(process);
    if (peb) {
        KAPC_STATE apc_state;
        _KeStackAttachProcess(process, &apc_state);

        __try {
            UCHAR* peb_base = (UCHAR*)peb;
            if (*(UCHAR*)(peb_base + 0x02) != 0) {
                *(UCHAR*)(peb_base + 0x02) = 0;
                cleared |= 2;
            }
            if (*(UINT32*)(peb_base + 0xBC) != 0) {

                *(UINT32*)(peb_base + 0xBC) &= ~(0x70u);
                cleared |= 4;
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {

        }

        _KeUnstackDetachProcess(&apc_state);
    }

    _ObfDereferenceObject(process);

    request->result_flags = cleared;

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_get_module_export(p_module_export request) {
    if (!request || request->module_base == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->dtb == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    dbg_guard::timing_scatter();

    UINT64 dtb = request->dtb;
    UINT64 base = request->module_base;


    UINT8 dos_hdr[64];
    SIZE_T bytes_read = 0;
    UINT64 phys = strong::translate_virtual_address(dtb, base);
    if (!phys) return STATUS_INVALID_ADDRESS;

    NTSTATUS status = strong::read_physical(phys, dos_hdr, 64, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 64) return STATUS_UNSUCCESSFUL;
    if (*(UINT16*)dos_hdr != 0x5A4D) return STATUS_INVALID_IMAGE_FORMAT;

    UINT32 pe_off = *(UINT32*)(dos_hdr + 0x3C);
    if (pe_off > 0x1000) return STATUS_INVALID_IMAGE_FORMAT;


    UINT8 pe_hdr[0x200];
    phys = strong::translate_virtual_address(dtb, base + pe_off);
    if (!phys) return STATUS_INVALID_ADDRESS;
    status = strong::read_physical(phys, pe_hdr, 0x200, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 0x100) return STATUS_UNSUCCESSFUL;
    if (*(UINT32*)pe_hdr != 0x00004550) return STATUS_INVALID_IMAGE_FORMAT;

    UINT16 opt_magic = *(UINT16*)(pe_hdr + 0x18);
    UINT32 export_rva = 0;
    if (opt_magic == 0x020B) {
        export_rva = *(UINT32*)(pe_hdr + 0x18 + 0x70);
    }
    else if (opt_magic == 0x010B) {
        export_rva = *(UINT32*)(pe_hdr + 0x18 + 0x60);
    }

    if (export_rva == 0) return STATUS_NOT_FOUND;


    UINT8 exp_dir[40];
    phys = strong::translate_virtual_address(dtb, base + export_rva);
    if (!phys) return STATUS_INVALID_ADDRESS;
    status = strong::read_physical(phys, exp_dir, 40, &bytes_read);
    if (!NT_SUCCESS(status) || bytes_read < 40) return STATUS_UNSUCCESSFUL;

    UINT32 num_names         = *(UINT32*)(exp_dir + 24);
    UINT32 addr_of_funcs_rva = *(UINT32*)(exp_dir + 28);
    UINT32 addr_of_names_rva = *(UINT32*)(exp_dir + 32);
    UINT32 addr_of_ords_rva  = *(UINT32*)(exp_dir + 36);
    UINT32 ordinal_base      = *(UINT32*)(exp_dir + 16);


    char target_name[128];
    strong::kmemset(target_name, 0, sizeof(target_name));
    for (int i = 0; i < 127 && request->export_name[i]; i++) {
        target_name[i] = request->export_name[i];
    }


    for (UINT32 i = 0; i < num_names && i < 8192; i++) {

        UINT32 name_rva = 0;
        phys = strong::translate_virtual_address(dtb, base + addr_of_names_rva + i * 4);
        if (!phys) continue;
        strong::read_physical(phys, &name_rva, 4, &bytes_read);
        if (name_rva == 0) continue;


        char exp_name[128];
        strong::kmemset(exp_name, 0, sizeof(exp_name));
        phys = strong::translate_virtual_address(dtb, base + name_rva);
        if (!phys) continue;
        strong::read_physical(phys, exp_name, 127, &bytes_read);
        exp_name[127] = 0;


        bool match = true;
        for (int c = 0; c < 127; c++) {
            if (target_name[c] == 0 && exp_name[c] == 0) break;
            if (target_name[c] != exp_name[c]) { match = false; break; }
        }

        if (match) {

            UINT16 ordinal = 0;
            phys = strong::translate_virtual_address(dtb, base + addr_of_ords_rva + i * 2);
            if (!phys) return STATUS_UNSUCCESSFUL;
            strong::read_physical(phys, &ordinal, 2, &bytes_read);


            UINT32 func_rva = 0;
            phys = strong::translate_virtual_address(dtb, base + addr_of_funcs_rva + ordinal * 4);
            if (!phys) return STATUS_UNSUCCESSFUL;
            strong::read_physical(phys, &func_rva, 4, &bytes_read);

            request->resolved_address = base + func_rva;
            request->ordinal = ordinal_base + ordinal;
            return STATUS_SUCCESS;
        }
    }

    request->resolved_address = 0;
    return STATUS_NOT_FOUND;
}


NTSTATUS functions::handle_virt_to_phys(p_virt_to_phys request) {
    if (!request || request->dtb == 0 || request->virtual_address == 0) {
        return STATUS_INVALID_PARAMETER;
    }

    UINT64 physical = strong::translate_virtual_address(request->dtb, request->virtual_address);
    request->physical_address = physical;

    return (physical != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}

NTSTATUS functions::handle_query_ssdt(p_ssdt_query request) {
    if (!request) {
        return STATUS_INVALID_PARAMETER;
    }

    request->lstar = 0;
    request->descriptor_address = 0;
    request->service_table = 0;
    request->counter_table = 0;
    request->argument_table = 0;
    request->service_limit = 0;
    request->flags = 0;

    __try {
        request->lstar = __readmsr(0xC0000082);
        if (request->lstar >= 0xFFFF800000000000ULL) {
            request->flags |= 0x2u;
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        request->lstar = ssdt_resolver::g_lstar;
    }

    if (!ssdt_resolver::find_ssdt() || !ssdt_resolver::g_ssdt) {
        return STATUS_NOT_FOUND;
    }

    ssdt_resolver::PKSERVICE_TABLE_DESCRIPTOR ssdt = ssdt_resolver::g_ssdt;

    __try {
        request->descriptor_address = reinterpret_cast<UINT64>(ssdt);
        request->service_table = reinterpret_cast<UINT64>(ssdt->ServiceTable);
        request->counter_table = reinterpret_cast<UINT64>(ssdt->CounterTable);
        request->argument_table = reinterpret_cast<UINT64>(ssdt->ArgumentTable);
        request->service_limit = static_cast<UINT32>(ssdt->ServiceLimit);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        request->descriptor_address = 0;
        request->service_table = 0;
        request->counter_table = 0;
        request->argument_table = 0;
        request->service_limit = 0;
        return STATUS_UNSUCCESSFUL;
    }

    if (request->lstar == 0) {
        request->lstar = ssdt_resolver::g_lstar;
    }

    if (request->descriptor_address < 0xFFFF800000000000ULL ||
        request->service_table < 0xFFFF800000000000ULL ||
        request->service_limit == 0 ||
        request->service_limit > 0x2000) {
        return STATUS_INVALID_ADDRESS;
    }

    if (!_MmIsAddressValid || !_MmIsAddressValid(reinterpret_cast<PVOID>(request->descriptor_address)) ||
        !_MmIsAddressValid(reinterpret_cast<PVOID>(request->service_table))) {
        return STATUS_INVALID_ADDRESS;
    }

    request->flags |= 0x1u;
    if (request->descriptor_address != 0 && request->service_table != 0) {
        request->flags |= 0x4u;
    }

    return STATUS_SUCCESS;
}


