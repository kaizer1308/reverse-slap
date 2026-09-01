#pragma once
#include <ntifs.h>
#include <intrin.h>
#include "../imports/Defs.h"
#include "CoreSecurity.h"

namespace debug_events {

    static constexpr ULONG EVENT_TYPE_INVALID         = 0;
    static constexpr ULONG EVENT_TYPE_IMAGE_LOADED    = 1;
    static constexpr ULONG EVENT_TYPE_PROCESS_CREATED = 2;
    static constexpr ULONG EVENT_TYPE_PROCESS_EXITED  = 3;

    static constexpr ULONG EVENT_FLAG_KERNEL_IMAGE = 0x00000001u;
    static constexpr ULONG EVENT_FLAG_SYSTEM_MODE  = 0x00000002u;

    static constexpr ULONG IMAGE_PATH_MAX_CHARS = 260;

#pragma pack(push, 8)
    typedef struct _DEBUG_EVENT_T {
        UINT32  event_type;
        UINT32  process_id;
        UINT32  thread_id;
        UINT32  flags;
        UINT64  timestamp;
        UINT64  image_base;
        UINT64  image_size;
        WCHAR   image_path[IMAGE_PATH_MAX_CHARS];
    } DEBUG_EVENT_T, *PDEBUG_EVENT_T;
#pragma pack(pop)

    static_assert(sizeof(DEBUG_EVENT_T) == 560, "DEBUG_EVENT_T size must be 560 bytes for ABI parity");

#pragma pack(push, 8)
    typedef struct _DRAIN_DEBUG_EVENTS_REQUEST_T {
        UINT32  session_key;
        UINT32  max_events;
        UINT32  returned_count;
        UINT32  dropped_since_last_drain;
        UINT64  total_dropped;
        UINT64  total_published;
        DEBUG_EVENT_T events[64];
    } DRAIN_DEBUG_EVENTS_REQUEST_T, *PDRAIN_DEBUG_EVENTS_REQUEST_T;
#pragma pack(pop)

    static_assert(sizeof(DRAIN_DEBUG_EVENTS_REQUEST_T) ==
        (4u + 4u + 4u + 4u + 8u + 8u + 64u * sizeof(DEBUG_EVENT_T)),
        "DRAIN_DEBUG_EVENTS_REQUEST_T size mismatch");

    static constexpr ULONG RING_CAPACITY = 1024;
    static_assert((RING_CAPACITY & (RING_CAPACITY - 1)) == 0, "RING_CAPACITY must be power-of-two");
    static constexpr ULONG RING_MASK = RING_CAPACITY - 1;

    inline DEBUG_EVENT_T*           g_ring = nullptr;
    inline volatile LONG64          g_write_index = 0;
    inline volatile LONG64          g_read_index = 0;
    inline volatile LONG            g_dropped_in_window = 0;
    inline volatile LONG64          g_total_dropped = 0;
    inline volatile LONG64          g_total_published = 0;
    inline volatile LONG            g_initialized = 0;
    inline volatile LONG            g_image_callback_registered = 0;
    inline volatile LONG            g_process_callback_registered = 0;
    inline FAST_MUTEX               g_buffer_lock = {};

    static constexpr ULONG TAG_DBEV = 'vEdW';

    __forceinline LARGE_INTEGER now_qpc() {
        LARGE_INTEGER lt = {};
        KeQuerySystemTime(&lt);
        return lt;
    }

    __forceinline BOOLEAN filter_targets_client(HANDLE pid) {
        HANDLE client_pid = caller_validation::g_registered_client_pid;
        if (!client_pid) return FALSE;
        return (pid == client_pid) ? TRUE : FALSE;
    }

    __forceinline void publish_event(const DEBUG_EVENT_T& evt) {
        if (!g_ring || _InterlockedCompareExchange(&g_initialized, 0, 0) == 0)
            return;

        ExAcquireFastMutex(&g_buffer_lock);

        LONG64 write_idx = g_write_index;
        LONG64 read_idx = g_read_index;
        LONG64 used_signed = write_idx - read_idx;
        if (used_signed < 0) used_signed = 0;

        if (used_signed >= static_cast<LONG64>(RING_CAPACITY)) {
            g_read_index = read_idx + 1;
            _InterlockedIncrement(&g_dropped_in_window);
            _InterlockedIncrement64(&g_total_dropped);
        }

        ULONG slot = static_cast<ULONG>(static_cast<ULONG64>(write_idx) & RING_MASK);
        RtlCopyMemory(&g_ring[slot], &evt, sizeof(DEBUG_EVENT_T));
        g_write_index = write_idx + 1;
        _InterlockedIncrement64(&g_total_published);

        ExReleaseFastMutex(&g_buffer_lock);
    }

    __forceinline ULONG drain_into(PDEBUG_EVENT_T out_buffer, ULONG max_events,
                                   PULONG out_dropped_since_last,
                                   PULONG64 out_total_dropped,
                                   PULONG64 out_total_published) {
        if (!g_ring || !out_buffer || max_events == 0) {
            if (out_dropped_since_last) *out_dropped_since_last = 0;
            if (out_total_dropped) *out_total_dropped = 0;
            if (out_total_published) *out_total_published = 0;
            return 0;
        }

        ExAcquireFastMutex(&g_buffer_lock);

        LONG64 write_idx = g_write_index;
        LONG64 read_idx = g_read_index;
        LONG64 available = write_idx - read_idx;
        if (available < 0) available = 0;

        ULONG to_copy = (available > static_cast<LONG64>(max_events))
            ? max_events
            : static_cast<ULONG>(available);

        for (ULONG i = 0; i < to_copy; ++i) {
            ULONG slot = static_cast<ULONG>(
                static_cast<ULONG64>(read_idx + static_cast<LONG64>(i)) & RING_MASK);
            RtlCopyMemory(&out_buffer[i], &g_ring[slot], sizeof(DEBUG_EVENT_T));
        }

        g_read_index = read_idx + static_cast<LONG64>(to_copy);

        LONG dropped = _InterlockedExchange(&g_dropped_in_window, 0);
        if (out_dropped_since_last) *out_dropped_since_last = static_cast<ULONG>(dropped);
        if (out_total_dropped) *out_total_dropped = static_cast<ULONG64>(g_total_dropped);
        if (out_total_published) *out_total_published = static_cast<ULONG64>(g_total_published);

        ExReleaseFastMutex(&g_buffer_lock);

        return to_copy;
    }

    inline VOID NTAPI load_image_callback(
        PUNICODE_STRING FullImageName,
        HANDLE ProcessId,
        PIMAGE_INFO ImageInfo)
    {
        if (_InterlockedCompareExchange(&g_initialized, 0, 0) == 0)
            return;

        if (!filter_targets_client(ProcessId))
            return;

        DEBUG_EVENT_T evt = {};
        evt.event_type = EVENT_TYPE_IMAGE_LOADED;
        evt.process_id = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(ProcessId));
        evt.thread_id = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId()));
        evt.timestamp = static_cast<UINT64>(now_qpc().QuadPart);

        if (ImageInfo) {
            evt.image_base = reinterpret_cast<UINT64>(ImageInfo->ImageBase);
            evt.image_size = static_cast<UINT64>(ImageInfo->ImageSize);
            if (ImageInfo->SystemModeImage)
                evt.flags |= EVENT_FLAG_SYSTEM_MODE;
            if (ImageInfo->ImageMappedToAllPids == 0 && ImageInfo->SystemModeImage)
                evt.flags |= EVENT_FLAG_KERNEL_IMAGE;
        }

        if (FullImageName && FullImageName->Buffer && FullImageName->Length > 0) {
            ULONG src_chars = FullImageName->Length / sizeof(WCHAR);
            if (src_chars >= IMAGE_PATH_MAX_CHARS)
                src_chars = IMAGE_PATH_MAX_CHARS - 1;
            __try {
                RtlCopyMemory(evt.image_path, FullImageName->Buffer, src_chars * sizeof(WCHAR));
                evt.image_path[src_chars] = L'\0';
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                evt.image_path[0] = L'\0';
            }
        }

        publish_event(evt);
    }

    inline VOID NTAPI process_notify_callback(
        PEPROCESS Process,
        HANDLE ProcessId,
        PPS_CREATE_NOTIFY_INFO CreateInfo)
    {
        UNREFERENCED_PARAMETER(Process);

        if (_InterlockedCompareExchange(&g_initialized, 0, 0) == 0)
            return;

        HANDLE client_pid = caller_validation::g_registered_client_pid;

        if (!CreateInfo) {
            if (!client_pid)
                return;

            UINT32 dying = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(ProcessId));
            UINT32 client = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(client_pid));
            if (dying == 0 || dying != client)
                return;

            DEBUG_EVENT_T evt = {};
            evt.event_type = EVENT_TYPE_PROCESS_EXITED;
            evt.process_id = dying;
            evt.thread_id = 0;
            evt.timestamp = static_cast<UINT64>(now_qpc().QuadPart);
            evt.image_path[0] = L'\0';
            publish_event(evt);
            return;
        }

        if (!client_pid)
            return;

        HANDLE parent_pid = CreateInfo->ParentProcessId;
        if (parent_pid != client_pid)
            return;

        DEBUG_EVENT_T evt = {};
        evt.event_type = EVENT_TYPE_PROCESS_CREATED;
        evt.process_id = static_cast<UINT32>(reinterpret_cast<ULONG_PTR>(ProcessId));
        evt.thread_id = 0;
        evt.timestamp = static_cast<UINT64>(now_qpc().QuadPart);

        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer &&
            CreateInfo->ImageFileName->Length > 0) {
            ULONG src_chars = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
            if (src_chars >= IMAGE_PATH_MAX_CHARS)
                src_chars = IMAGE_PATH_MAX_CHARS - 1;
            __try {
                RtlCopyMemory(evt.image_path, CreateInfo->ImageFileName->Buffer,
                              src_chars * sizeof(WCHAR));
                evt.image_path[src_chars] = L'\0';
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                evt.image_path[0] = L'\0';
            }
        } else {
            evt.image_path[0] = L'\0';
        }

        publish_event(evt);
    }

    inline NTSTATUS initialize() {
        if (_InterlockedCompareExchange(&g_initialized, 0, 0) != 0)
            return STATUS_ALREADY_REGISTERED;

        if (!_PsSetLoadImageNotifyRoutine || !_PsSetCreateProcessNotifyRoutineEx) {
            SD_LOG("debug_events::initialize: required Ps* routines not resolved (load=%p create_ex=%p)",
                _PsSetLoadImageNotifyRoutine, _PsSetCreateProcessNotifyRoutineEx);
            return STATUS_NOT_SUPPORTED;
        }

        SIZE_T bytes = static_cast<SIZE_T>(RING_CAPACITY) * sizeof(DEBUG_EVENT_T);
        g_ring = static_cast<DEBUG_EVENT_T*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes, TAG_DBEV));
        if (!g_ring) {
            SD_LOG("debug_events::initialize: ring allocation FAILED bytes=%llu", (ULONG64)bytes);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        RtlZeroMemory(g_ring, bytes);
        ExInitializeFastMutex(&g_buffer_lock);
        _InterlockedExchange64(&g_write_index, 0);
        _InterlockedExchange64(&g_read_index, 0);
        _InterlockedExchange(&g_dropped_in_window, 0);
        _InterlockedExchange64(&g_total_dropped, 0);
        _InterlockedExchange64(&g_total_published, 0);

        _InterlockedExchange(&g_initialized, 1);

        NTSTATUS img_st = _PsSetLoadImageNotifyRoutine(load_image_callback);
        if (NT_SUCCESS(img_st)) {
            _InterlockedExchange(&g_image_callback_registered, 1);
            SD_LOG("debug_events::initialize: PsSetLoadImageNotifyRoutine OK");
        } else {
            SD_LOG("debug_events::initialize: PsSetLoadImageNotifyRoutine FAILED 0x%08lx", img_st);
        }

        NTSTATUS proc_st = _PsSetCreateProcessNotifyRoutineEx(process_notify_callback, FALSE);
        if (NT_SUCCESS(proc_st)) {
            _InterlockedExchange(&g_process_callback_registered, 1);
            SD_LOG("debug_events::initialize: PsSetCreateProcessNotifyRoutineEx OK");
        } else {
            SD_LOG("debug_events::initialize: PsSetCreateProcessNotifyRoutineEx FAILED 0x%08lx", proc_st);
        }

        if (!NT_SUCCESS(img_st) && !NT_SUCCESS(proc_st)) {
            _InterlockedExchange(&g_initialized, 0);
            ExFreePoolWithTag(g_ring, TAG_DBEV);
            g_ring = nullptr;
            return img_st;
        }

        return STATUS_SUCCESS;
    }

    inline void cleanup() {
        if (_InterlockedCompareExchange(&g_initialized, 0, 1) != 1)
            return;

        if (_InterlockedCompareExchange(&g_image_callback_registered, 0, 1) == 1) {
            if (_PsRemoveLoadImageNotifyRoutine)
                _PsRemoveLoadImageNotifyRoutine(load_image_callback);
        }

        if (_InterlockedCompareExchange(&g_process_callback_registered, 0, 1) == 1) {
            if (_PsSetCreateProcessNotifyRoutineEx)
                _PsSetCreateProcessNotifyRoutineEx(process_notify_callback, TRUE);
        }

        ExAcquireFastMutex(&g_buffer_lock);
        if (g_ring) {
            ExFreePoolWithTag(g_ring, TAG_DBEV);
            g_ring = nullptr;
        }
        ExReleaseFastMutex(&g_buffer_lock);
    }
}
