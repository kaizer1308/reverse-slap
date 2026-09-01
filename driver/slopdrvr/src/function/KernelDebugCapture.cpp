#include "KernelDebugCapture.h"

#include <ntifs.h>
#include <ntstrsafe.h>

namespace dbg_capture {

    static constexpr ULONG kRingSize = 0x100000;
    static constexpr ULONG kMaxMessageLen = 768;
    static constexpr ULONG kFlushIntervalMs = 200;
    static constexpr ULONG kMaxIdleFlushIntervalMs = 5000;
    static constexpr ULONG kPoolTag = 'gbDA';

    static UCHAR* g_ring = nullptr;
    static UCHAR* g_flush_buffer = nullptr;
    static volatile ULONG g_write_pos = 0;
    static volatile ULONG g_read_pos = 0;
    static volatile LONG g_initialized = 0;
    static volatile LONG g_stop = 0;
    static KSPIN_LOCK g_lock;
    static KEVENT g_wake_event;
    static PETHREAD g_drain_thread = nullptr;
    static volatile UINT64 g_drain_thread_tid = 0;
    static volatile LONG g_ring_drop_events = 0;
    static volatile LONG g_ring_drop_bytes = 0;
    static volatile LONG g_flush_lost_events = 0;
    static volatile LONG g_flush_lost_bytes = 0;
    static volatile LONG g_immediate_failures = 0;
    static volatile LONG g_immediate_last_status = STATUS_SUCCESS;

    static const wchar_t* const kDefaultLogPath = L"\\??\\C:\\Users\\Public\\Desktop\\slop_kernel.log";
    static WCHAR g_log_path_buffer[512] = {};
    static UNICODE_STRING g_log_path = {};
    static volatile LONG g_log_path_configured = 0;

    // --- verbosity + size cap ------------------------------------------------
    static volatile LONG g_log_level = 1;   // kLogCritical by default

    // Hard byte cap for slop_kernel.log. When the file crosses it, the
    // flush path rewrites the file keeping only the newest half — the log
    // becomes a bounded rotating tail instead of an append-forever firehose.
    static constexpr UINT64 kDefaultLogCapBytes = 64ull * 1024 * 1024;  // 64 MB
    static volatile LONG64 g_log_cap_bytes = static_cast<LONG64>(kDefaultLogCapBytes);

    ULONG current_log_level() {
        return static_cast<ULONG>(_InterlockedCompareExchange(&g_log_level, 0, 0));
    }

    BOOLEAN should_log(ULONG level) {
        return static_cast<LONG>(level) <=
               _InterlockedCompareExchange(&g_log_level, 0, 0);
    }

    void set_log_level(ULONG level) {
        if (level > 4) return;
        _InterlockedExchange(&g_log_level, static_cast<LONG>(level));
        write_immediate_formatted("[SD] dbg_capture::set_log_level level=%lu\n", level);
    }

    void set_log_cap_mb(ULONG mb) {
        if (mb < 1 || mb > 512) return;
        _InterlockedExchange64(&g_log_cap_bytes,
            static_cast<LONG64>(mb) * 1024 * 1024);
        write_immediate_formatted("[SD] dbg_capture::set_log_cap_mb cap_mb=%lu\n", mb);
    }

    ULONG current_log_cap_mb() {
        const LONG64 cap = _InterlockedCompareExchange64(&g_log_cap_bytes, 0, 0);
        return cap > 0 ? static_cast<ULONG>(cap / (1024 * 1024)) : 0;
    }

    static BOOLEAN starts_with_path_prefix(const WCHAR* text, ULONG chars, const WCHAR* prefix)
    {
        if (!text || !prefix) return FALSE;
        ULONG i = 0;
        while (prefix[i] != L'\0') {
            if (i >= chars || text[i] != prefix[i]) return FALSE;
            ++i;
        }
        return TRUE;
    }

    static BOOLEAN has_supported_log_path_prefix(const WCHAR* text, ULONG chars)
    {
        return starts_with_path_prefix(text, chars, L"\\??\\") ||
               starts_with_path_prefix(text, chars, L"\\Device\\");
    }

    static UNICODE_STRING current_log_path()
    {
        if (g_log_path.Buffer && g_log_path.Length > 0)
            return g_log_path;
        UNICODE_STRING path;
        RtlInitUnicodeString(&path, kDefaultLogPath);
        return path;
    }

    static BOOLEAN read_dword_value(HANDLE key, PCWSTR name, ULONG* out_value)
    {
        if (!key || !name || !out_value)
            return FALSE;

        UNICODE_STRING value_name;
        RtlInitUnicodeString(&value_name, name);

        struct storage_t
        {
            KEY_VALUE_PARTIAL_INFORMATION info;
            UCHAR bytes[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)];
        } storage = {};

        ULONG bytes_returned = 0;
        NTSTATUS st = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
            storage.bytes, sizeof(storage.bytes), &bytes_returned);
        if (!NT_SUCCESS(st))
            return FALSE;

        PKEY_VALUE_PARTIAL_INFORMATION info =
            reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(storage.bytes);
        if (info->Type != REG_DWORD || info->DataLength < sizeof(ULONG))
            return FALSE;

        RtlCopyMemory(out_value, info->Data, sizeof(ULONG));
        return TRUE;
    }

    void configure_log_path(PUNICODE_STRING registry_path)
    {
        if (_InterlockedCompareExchange(&g_log_path_configured, 1, 0) != 0)
            return;

        RtlInitUnicodeString(&g_log_path, kDefaultLogPath);
        if (!registry_path || !registry_path->Buffer || registry_path->Length == 0)
            return;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL)
            return;

        HANDLE key = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, registry_path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
        NTSTATUS st = ZwOpenKey(&key, KEY_QUERY_VALUE, &oa);
        if (!NT_SUCCESS(st) || !key)
            return;

        // --- log path (REG_SZ) ------------------------------------------------
        {
            UNICODE_STRING value_name;
            RtlInitUnicodeString(&value_name, L"SlopKernelLogPath");

            union query_storage_t
            {
                KEY_VALUE_PARTIAL_INFORMATION info;
                UCHAR bytes[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(g_log_path_buffer)];
            } storage = {};

            ULONG bytes_returned = 0;
            st = ZwQueryValueKey(key, &value_name, KeyValuePartialInformation,
                storage.bytes, sizeof(storage.bytes), &bytes_returned);
            if (NT_SUCCESS(st)) {
                PKEY_VALUE_PARTIAL_INFORMATION info =
                    reinterpret_cast<PKEY_VALUE_PARTIAL_INFORMATION>(storage.bytes);
                if ((info->Type == REG_SZ || info->Type == REG_EXPAND_SZ) &&
                    info->DataLength >= sizeof(WCHAR) &&
                    info->DataLength < sizeof(g_log_path_buffer)) {
                    const WCHAR* src = reinterpret_cast<const WCHAR*>(info->Data);
                    ULONG chars = info->DataLength / sizeof(WCHAR);
                    while (chars > 0 && src[chars - 1] == L'\0')
                        --chars;
                    if (chars != 0 && chars < RTL_NUMBER_OF(g_log_path_buffer) &&
                        has_supported_log_path_prefix(src, chars)) {
                        RtlCopyMemory(g_log_path_buffer, src, chars * sizeof(WCHAR));
                        g_log_path_buffer[chars] = L'\0';
                        RtlInitUnicodeString(&g_log_path, g_log_path_buffer);
                    }
                }
            }
        }

        // --- verbosity + size cap (REG_DWORD), both optional ------------------
        {
            ULONG value = 0;
            if (read_dword_value(key, L"SlopKernelLogLevel", &value) && value <= 4) {
                _InterlockedExchange(&g_log_level, static_cast<LONG>(value));
            }
            if (read_dword_value(key, L"SlopKernelLogCapMB", &value) && value >= 1 && value <= 512) {
                _InterlockedExchange64(&g_log_cap_bytes,
                    static_cast<LONG64>(value) * 1024 * 1024);
            }
        }

        ZwClose(key);
    }

    static BOOLEAN is_hex_digit_char(char c)
    {
        return (c >= '0' && c <= '9') ||
               (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    }

    static BOOLEAN token_matches(const char* text, const char* token)
    {
        while (*token) {
            if (*text++ != *token++) return FALSE;
        }
        return TRUE;
    }

    static SIZE_T token_length(const char* token)
    {
        SIZE_T len = 0;
        while (token[len]) ++len;
        return len;
    }

    static void redact_labeled_hex_values(char* text)
    {
        static const char* const labels[] = {
            "session_key=0x", "session=0x", "g_session=0x",
            "magic=0x", "expected=0x", "received=0x",
            "existing=0x", "new=0x", "hb_key=0x",
            "key=0x", "proof=0x", "nonce=0x",
            "token=0x", "challenge=0x", "response=0x",
            "raw_cmd=0x", "raw_param=0x", "enc_cmd=0x", "enc_param=0x"
        };

        for (char* p = text; p && *p; ++p) {
            for (ULONG i = 0; i < RTL_NUMBER_OF(labels); ++i) {
                if (!token_matches(p, labels[i])) continue;
                char* v = p + token_length(labels[i]);
                while (*v && is_hex_digit_char(*v)) {
                    *v++ = 'x';
                }
                break;
            }
        }
    }

    static void redact_long_hex_runs(char* text)
    {
        char* p = text;
        while (p && *p) {
            char* start = p;
            ULONG hex_count = 0;
            while (*p && (is_hex_digit_char(*p) || *p == '`')) {
                if (is_hex_digit_char(*p)) ++hex_count;
                ++p;
            }
            if (hex_count >= 12) {
                for (char* q = start; q < p; ++q) {
                    if (is_hex_digit_char(*q)) *q = 'x';
                }
            }
            if (p == start) ++p;
        }
    }

    static void scrub_message(char* text)
    {
        if (!text) return;
        redact_labeled_hex_values(text);
        redact_long_hex_runs(text);
    }

    static void copy_into_ring_locked(const char* data, ULONG len)
    {
        ULONG wpos = g_write_pos;
        ULONG rpos = g_read_pos;
        ULONG used = wpos - rpos;
        if (used > kRingSize) {
            g_read_pos = wpos - kRingSize;
            rpos = g_read_pos;
            used = kRingSize;
        }

        ULONG free_bytes = kRingSize - used;
        if (free_bytes < len) {
            ULONG to_drop = len - free_bytes;
            g_read_pos = rpos + to_drop;
            _InterlockedIncrement(&g_ring_drop_events);
            _InterlockedExchangeAdd(&g_ring_drop_bytes, static_cast<LONG>(to_drop));
        }

        ULONG offset = wpos % kRingSize;
        ULONG first_chunk = kRingSize - offset;
        if (first_chunk > len) first_chunk = len;
        RtlCopyMemory(g_ring + offset, data, first_chunk);
        if (first_chunk < len) {
            RtlCopyMemory(g_ring, data + first_chunk, len - first_chunk);
        }
        g_write_pos = wpos + len;
    }

    static void push_raw(const char* data, ULONG len)
    {
        if (g_drain_thread && PsGetCurrentThread() == g_drain_thread) return;
        if (!g_ring || len == 0) return;
        if (len > kMaxMessageLen) len = kMaxMessageLen;

        char ts[40];
        size_t ts_len = 0;
        LARGE_INTEGER sys_time, local_time;
        TIME_FIELDS tf = {};
        KeQuerySystemTime(&sys_time);
        ExSystemTimeToLocalTime(&sys_time, &local_time);
        RtlTimeToTimeFields(&local_time, &tf);
        NTSTATUS sf = RtlStringCbPrintfA(ts, sizeof(ts),
            "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            (ULONG)tf.Year, (ULONG)tf.Month, (ULONG)tf.Day,
            (ULONG)tf.Hour, (ULONG)tf.Minute, (ULONG)tf.Second,
            (ULONG)tf.Milliseconds);
        if (!NT_SUCCESS(sf) || !NT_SUCCESS(RtlStringCbLengthA(ts, sizeof(ts), &ts_len))) {
            ts_len = 0;
        }

        KIRQL old_irql;
        KeAcquireSpinLock(&g_lock, &old_irql);
        if (ts_len > 0) copy_into_ring_locked(ts, (ULONG)ts_len);
        copy_into_ring_locked(data, len);
        KeReleaseSpinLock(&g_lock, old_irql);

        KeSetEvent(&g_wake_event, 0, FALSE);
    }

    void write_formatted(const char* fmt, ...)
    {
        if (!_InterlockedCompareExchange(&g_initialized, 0, 0)) return;

        char buf[kMaxMessageLen];
        va_list ap;
        va_start(ap, fmt);
        NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (!NT_SUCCESS(s) && s != STATUS_BUFFER_OVERFLOW) return;

        size_t out_len = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) return;
        scrub_message(buf);
        push_raw(buf, static_cast<ULONG>(out_len));
    }

    void write_formatted_level(ULONG level, const char* fmt, ...)
    {
        // Level gate lives here so every SD_LOG_* macro call site compiles to
        // a compare + (almost always) a return, keeping hot paths cheap.
        if (!should_log(level)) return;
        if (!_InterlockedCompareExchange(&g_initialized, 0, 0)) return;

        char buf[kMaxMessageLen];
        va_list ap;
        va_start(ap, fmt);
        NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (!NT_SUCCESS(s) && s != STATUS_BUFFER_OVERFLOW) return;

        size_t out_len = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) return;
        scrub_message(buf);
        push_raw(buf, static_cast<ULONG>(out_len));
    }

    struct flush_result_t
    {
        ULONG bytes;
        NTSTATUS create_status;
        NTSTATUS write_status;
        ULONG elapsed_us;
        ULONG ring_drop_events;
        ULONG ring_drop_bytes;
        ULONG flush_lost_events;
        ULONG flush_lost_bytes;
        ULONG immediate_failures;
        NTSTATUS immediate_last_status;
    };

    static ULONG elapsed_us(LARGE_INTEGER start, LARGE_INTEGER end, LARGE_INTEGER freq)
    {
        if (freq.QuadPart <= 0 || end.QuadPart < start.QuadPart) return 0;
        ULONGLONG delta = static_cast<ULONGLONG>(end.QuadPart - start.QuadPart);
        return static_cast<ULONG>((delta * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
    }

    static BOOLEAN should_log_empty(UINT64 empty_count)
    {
        UNREFERENCED_PARAMETER(empty_count);
        return FALSE;
    }

    static BOOLEAN should_log_flush(const flush_result_t& flush, UINT64 flush_count)
    {
        UNREFERENCED_PARAMETER(flush_count);
        if (!NT_SUCCESS(flush.create_status) || !NT_SUCCESS(flush.write_status)) return TRUE;
        if (flush.elapsed_us >= 5000) return TRUE;
        if (flush.ring_drop_events != 0 || flush.ring_drop_bytes != 0) return TRUE;
        if (flush.flush_lost_events != 0 || flush.flush_lost_bytes != 0) return TRUE;
        if (flush.immediate_failures != 0 || !NT_SUCCESS(flush.immediate_last_status)) return TRUE;
        return FALSE;
    }

    static const char* wait_reason(NTSTATUS status, BOOLEAN stopping)
    {
        if (stopping) return "stop";
        if (status == STATUS_SUCCESS) return "event";
        if (status == STATUS_TIMEOUT) return "timeout";
        return "status";
    }

    // Rewrite the log keeping only the newest `keep_bytes` of the current
    // file. Runs on the drain thread at PASSIVE_LEVEL; a failure simply
    // leaves the file as-is (the append below still lands, worst case the
    // cap is exceeded by one flush).
    static void truncate_log_tail(const UNICODE_STRING& path, UINT64 keep_bytes)
    {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, const_cast<PUNICODE_STRING>(&path),
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
        if (!NT_SUCCESS(st) || !hFile)
            return;

        // Current size (opening with FILE_OPEN above guarantees it exists).
        FILE_STANDARD_INFORMATION info = {};
        st = ZwQueryInformationFile(hFile, &iosb, &info, sizeof(info),
            FileStandardInformation);
        if (!NT_SUCCESS(st)) {
            ZwClose(hFile);
            return;
        }
        const UINT64 file_size = info.EndOfFile.QuadPart > 0
            ? static_cast<UINT64>(info.EndOfFile.QuadPart) : 0;
        if (file_size <= keep_bytes) {
            ZwClose(hFile);
            return;   // nothing to trim yet
        }

        // Read the newest keep_bytes into a scratch buffer (bounded: callers
        // pass half the cap, so this allocation is cap/2 — 32 MB at the
        // default 64 MB cap; paged pool, this is pure file-I/O scratch).
        const ULONG read_len = static_cast<ULONG>(keep_bytes);
        UCHAR* scratch = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_PAGED, read_len, kPoolTag));
        if (!scratch) {
            ZwClose(hFile);
            return;
        }

        LARGE_INTEGER read_offset;
        read_offset.QuadPart =
            static_cast<LONGLONG>(file_size - keep_bytes);
        st = ZwReadFile(hFile, NULL, NULL, NULL, &iosb,
            scratch, read_len, &read_offset, NULL);
        const ULONG got = NT_SUCCESS(st) && iosb.Information <= read_len
            ? static_cast<ULONG>(iosb.Information) : 0;
        if (got == 0) {
            ExFreePoolWithTag(scratch, kPoolTag);
            ZwClose(hFile);
            return;
        }

        // Skip a partial leading line so the trimmed log starts clean.
        ULONG start = 0;
        while (start < got && scratch[start] != '\n')
            ++start;
        if (start < got) ++start;   // past the newline

        // Rewrite: position 0, newest tail, then truncate.
        LARGE_INTEGER write_offset;
        write_offset.QuadPart = 0;
        st = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
            scratch + start, got - start, &write_offset, NULL);
        if (NT_SUCCESS(st)) {
            FILE_END_OF_FILE_INFORMATION eof{};
            eof.EndOfFile.QuadPart =
                static_cast<LONGLONG>(got - start);
            NTSTATUS trunc = ZwSetInformationFile(hFile, &iosb, &eof,
                sizeof(eof), FileEndOfFileInformation);
            write_immediate_formatted("[SD] dbg_capture::flush_to_file log_capped file_size=%llu keep_bytes=%llu trunc_status=0x%08lx\n",
                static_cast<unsigned long long>(file_size),
                static_cast<unsigned long long>(got - start),
                static_cast<ULONG>(trunc));
        }
        ExFreePoolWithTag(scratch, kPoolTag);
        ZwClose(hFile);
    }

    // Query the current on-disk size of the log (0 on any failure — a
    // missing file starts fresh, which is what we want).
    static UINT64 query_log_size(const UNICODE_STRING& path)
    {
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, const_cast<PUNICODE_STRING>(&path),
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
        if (!NT_SUCCESS(st) || !hFile)
            return 0;

        FILE_STANDARD_INFORMATION info = {};
        st = ZwQueryInformationFile(hFile, &iosb, &info, sizeof(info),
            FileStandardInformation);
        ZwClose(hFile);
        if (!NT_SUCCESS(st))
            return 0;
        return info.EndOfFile.QuadPart > 0
            ? static_cast<UINT64>(info.EndOfFile.QuadPart)
            : 0;
    }

    static flush_result_t flush_to_file()
    {
        flush_result_t result = {};
        result.create_status = STATUS_SUCCESS;
        result.write_status = STATUS_SUCCESS;
        if (!g_ring || !g_flush_buffer) return result;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return result;

        LARGE_INTEGER freq;
        LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);

        ULONG snapshot_len = 0;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_lock, &old_irql);
        ULONG wpos = g_write_pos;
        ULONG rpos = g_read_pos;
        ULONG used = wpos - rpos;
        if (used == 0) {
            KeReleaseSpinLock(&g_lock, old_irql);
            return result;
        }
        if (used > kRingSize) {
            rpos = wpos - kRingSize;
            used = kRingSize;
        }
        ULONG offset = rpos % kRingSize;
        ULONG first_chunk = kRingSize - offset;
        if (first_chunk > used) first_chunk = used;
        RtlCopyMemory(g_flush_buffer, g_ring + offset, first_chunk);
        if (first_chunk < used) {
            RtlCopyMemory(g_flush_buffer + first_chunk, g_ring, used - first_chunk);
        }
        g_read_pos = rpos + used;
        snapshot_len = used;
        KeReleaseSpinLock(&g_lock, old_irql);
        result.bytes = snapshot_len;

        UNICODE_STRING path = current_log_path();

        // --- size cap: the log is a bounded rotating tail --------------------
        // Once the file crosses the cap, truncate it to the newest half.
        // This kills the append-forever growth that once ballooned the
        // kernel log to gigabytes under per-packet tracing.
        const UINT64 cap_bytes = static_cast<UINT64>(
            _InterlockedCompareExchange64(&g_log_cap_bytes, 0, 0));
        const UINT64 file_size = query_log_size(path);
        if (cap_bytes > 0 && file_size + snapshot_len > cap_bytes) {
            // Trim the on-disk file to the newest half; the append below
            // then adds this flush's bytes at the end of the trimmed file.
            truncate_log_tail(path, cap_bytes / 2);
        }

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_APPEND_DATA | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);
        result.create_status = st;

        if (NT_SUCCESS(st) && hFile) {
            LARGE_INTEGER offset_li;
            offset_li.HighPart = -1;
            offset_li.LowPart = FILE_WRITE_TO_END_OF_FILE;
            result.write_status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                g_flush_buffer, snapshot_len, &offset_li, NULL);
            ZwClose(hFile);
        } else if (NT_SUCCESS(st)) {
            result.write_status = STATUS_INVALID_HANDLE;
        }
        if (snapshot_len != 0 && (!NT_SUCCESS(result.create_status) || !NT_SUCCESS(result.write_status))) {
            _InterlockedIncrement(&g_flush_lost_events);
            _InterlockedExchangeAdd(&g_flush_lost_bytes, static_cast<LONG>(snapshot_len));
        }
        LARGE_INTEGER end = KeQueryPerformanceCounter(nullptr);
        result.elapsed_us = elapsed_us(start, end, freq);
        result.ring_drop_events = static_cast<ULONG>(_InterlockedExchange(&g_ring_drop_events, 0));
        result.ring_drop_bytes = static_cast<ULONG>(_InterlockedExchange(&g_ring_drop_bytes, 0));
        result.flush_lost_events = static_cast<ULONG>(_InterlockedExchange(&g_flush_lost_events, 0));
        result.flush_lost_bytes = static_cast<ULONG>(_InterlockedExchange(&g_flush_lost_bytes, 0));
        result.immediate_failures = static_cast<ULONG>(_InterlockedExchange(&g_immediate_failures, 0));
        result.immediate_last_status = result.immediate_failures != 0
            ? static_cast<NTSTATUS>(_InterlockedExchange(&g_immediate_last_status, STATUS_SUCCESS))
            : STATUS_SUCCESS;
        return result;
    }

    static void write_immediate_raw(const char* data, ULONG len)
    {
        if (!data || len == 0 || KeGetCurrentIrql() != PASSIVE_LEVEL) return;

        char ts[40];
        size_t ts_len = 0;
        LARGE_INTEGER sys_time, local_time;
        TIME_FIELDS tf = {};
        KeQuerySystemTime(&sys_time);
        ExSystemTimeToLocalTime(&sys_time, &local_time);
        RtlTimeToTimeFields(&local_time, &tf);
        NTSTATUS ts_status = RtlStringCbPrintfA(ts, sizeof(ts),
            "[%04u-%02u-%02u %02u:%02u:%02u.%03u] ",
            (ULONG)tf.Year, (ULONG)tf.Month, (ULONG)tf.Day,
            (ULONG)tf.Hour, (ULONG)tf.Minute, (ULONG)tf.Second,
            (ULONG)tf.Milliseconds);
        if (!NT_SUCCESS(ts_status) || !NT_SUCCESS(RtlStringCbLengthA(ts, sizeof(ts), &ts_len))) {
            ts_len = 0;
        }

        UNICODE_STRING path = current_log_path();

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, &path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

        HANDLE hFile = nullptr;
        IO_STATUS_BLOCK iosb = {};
        NTSTATUS st = ZwCreateFile(
            &hFile,
            FILE_APPEND_DATA | SYNCHRONIZE,
            &oa,
            &iosb,
            NULL,
            FILE_ATTRIBUTE_NORMAL,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_OPEN_IF,
            FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT,
            NULL, 0);

        NTSTATUS write_status = STATUS_SUCCESS;
        if (NT_SUCCESS(st) && hFile) {
            LARGE_INTEGER offset_li;
            offset_li.HighPart = -1;
            offset_li.LowPart = FILE_WRITE_TO_END_OF_FILE;
            if (ts_len > 0) {
                write_status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                    ts, static_cast<ULONG>(ts_len), &offset_li, NULL);
            }
            if (NT_SUCCESS(write_status)) {
                write_status = ZwWriteFile(hFile, NULL, NULL, NULL, &iosb,
                    const_cast<char*>(data), len, &offset_li, NULL);
            }
            ZwClose(hFile);
        } else if (NT_SUCCESS(st)) {
            write_status = STATUS_INVALID_HANDLE;
        } else {
            write_status = st;
        }
        if (!NT_SUCCESS(st) || !NT_SUCCESS(write_status)) {
            _InterlockedExchange(&g_immediate_last_status, static_cast<LONG>(!NT_SUCCESS(st) ? st : write_status));
            _InterlockedIncrement(&g_immediate_failures);
        }
    }

    void write_immediate_formatted(const char* fmt, ...)
    {
        if (!fmt) return;

        char buf[kMaxMessageLen];
        va_list ap;
        va_start(ap, fmt);
        NTSTATUS s = RtlStringCbVPrintfA(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        if (!NT_SUCCESS(s) && s != STATUS_BUFFER_OVERFLOW) return;

        size_t out_len = 0;
        if (!NT_SUCCESS(RtlStringCbLengthA(buf, sizeof(buf), &out_len))) return;
        scrub_message(buf);
        write_immediate_raw(buf, static_cast<ULONG>(out_len));
    }

    static VOID NTAPI drain_thread_routine(PVOID context)
    {
        UNREFERENCED_PARAMETER(context);

        UINT64 tid = reinterpret_cast<UINT64>(PsGetCurrentThreadId());
        _InterlockedExchange64(reinterpret_cast<volatile LONG64*>(&g_drain_thread_tid),
            static_cast<LONG64>(tid));
        ULONG wait_ms = kFlushIntervalMs;
        UINT64 empty_count = 0;
        UINT64 total_bytes = 0;
        UINT64 total_flush_us = 0;
        UINT64 flush_count = 0;
        UINT64 suppressed_flush_count = 0;
        UINT64 suppressed_flush_bytes = 0;
        UINT64 suppressed_flush_us = 0;

        write_immediate_formatted("[SD] dbg_capture::drain_thread_start tid=%llu wait_ms=%lu max_wait_ms=%lu\n",
            static_cast<unsigned long long>(tid),
            wait_ms,
            kMaxIdleFlushIntervalMs);

        for (;;) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(static_cast<LONGLONG>(wait_ms) * 10000LL);
            NTSTATUS wait_status = KeWaitForSingleObject(&g_wake_event, Executive, KernelMode, FALSE, &timeout);
            BOOLEAN stopping = _InterlockedCompareExchange(&g_stop, 0, 0) ? TRUE : FALSE;
            if (stopping) break;

            flush_result_t flush = flush_to_file();
            if (flush.bytes != 0) {
                total_bytes += flush.bytes;
                total_flush_us += flush.elapsed_us;
                ++flush_count;
                empty_count = 0;
                wait_ms = kFlushIntervalMs;
                if (should_log_flush(flush, flush_count)) {
                    write_immediate_formatted("[SD] dbg_capture::drain_thread_flush tid=%llu wait_status=0x%08lx wake=%s bytes=%lu total_bytes=%llu flush_us=%lu total_flush_us=%llu flush_count=%llu suppressed_flushes=%llu suppressed_bytes=%llu suppressed_flush_us=%llu create=0x%08lx write=0x%08lx ring_drop_events=%lu ring_drop_bytes=%lu flush_lost_events=%lu flush_lost_bytes=%lu immediate_failures=%lu immediate_last=0x%08lx next_wait_ms=%lu\n",
                        static_cast<unsigned long long>(tid),
                        static_cast<ULONG>(wait_status),
                        wait_reason(wait_status, FALSE),
                        flush.bytes,
                        static_cast<unsigned long long>(total_bytes),
                        flush.elapsed_us,
                        static_cast<unsigned long long>(total_flush_us),
                        static_cast<unsigned long long>(flush_count),
                        static_cast<unsigned long long>(suppressed_flush_count),
                        static_cast<unsigned long long>(suppressed_flush_bytes),
                        static_cast<unsigned long long>(suppressed_flush_us),
                        static_cast<ULONG>(flush.create_status),
                        static_cast<ULONG>(flush.write_status),
                        flush.ring_drop_events,
                        flush.ring_drop_bytes,
                        flush.flush_lost_events,
                        flush.flush_lost_bytes,
                        flush.immediate_failures,
                        static_cast<ULONG>(flush.immediate_last_status),
                        wait_ms);
                    suppressed_flush_count = 0;
                    suppressed_flush_bytes = 0;
                    suppressed_flush_us = 0;
                } else {
                    ++suppressed_flush_count;
                    suppressed_flush_bytes += flush.bytes;
                    suppressed_flush_us += flush.elapsed_us;
                }
            } else {
                ++empty_count;
                ULONG previous_wait = wait_ms;
                if (wait_ms < kMaxIdleFlushIntervalMs) {
                    wait_ms *= 2;
                    if (wait_ms > kMaxIdleFlushIntervalMs)
                        wait_ms = kMaxIdleFlushIntervalMs;
                }
                if (should_log_empty(empty_count)) {
                    write_immediate_formatted("[SD] dbg_capture::drain_thread_idle tid=%llu wait_status=0x%08lx wake=%s empty_count=%llu wait_ms=%lu next_wait_ms=%lu total_bytes=%llu total_flush_us=%llu flush_count=%llu\n",
                        static_cast<unsigned long long>(tid),
                        static_cast<ULONG>(wait_status),
                        wait_reason(wait_status, FALSE),
                        static_cast<unsigned long long>(empty_count),
                        previous_wait,
                        wait_ms,
                        static_cast<unsigned long long>(total_bytes),
                        static_cast<unsigned long long>(total_flush_us),
                        static_cast<unsigned long long>(flush_count));
                }
            }
        }

        flush_result_t final_flush = flush_to_file();
        total_bytes += final_flush.bytes;
        total_flush_us += final_flush.elapsed_us;
        if (final_flush.bytes != 0)
            ++flush_count;
        write_immediate_formatted("[SD] dbg_capture::drain_thread_exit tid=%llu final_bytes=%lu total_bytes=%llu empty_count=%llu total_flush_us=%llu flush_count=%llu suppressed_flushes=%llu suppressed_bytes=%llu suppressed_flush_us=%llu create=0x%08lx write=0x%08lx ring_drop_events=%lu ring_drop_bytes=%lu flush_lost_events=%lu flush_lost_bytes=%lu immediate_failures=%lu immediate_last=0x%08lx\n",
            static_cast<unsigned long long>(tid),
            final_flush.bytes,
            static_cast<unsigned long long>(total_bytes),
            static_cast<unsigned long long>(empty_count),
            static_cast<unsigned long long>(total_flush_us),
            static_cast<unsigned long long>(flush_count),
            static_cast<unsigned long long>(suppressed_flush_count),
            static_cast<unsigned long long>(suppressed_flush_bytes),
            static_cast<unsigned long long>(suppressed_flush_us),
            static_cast<ULONG>(final_flush.create_status),
            static_cast<ULONG>(final_flush.write_status),
            final_flush.ring_drop_events,
            final_flush.ring_drop_bytes,
            final_flush.flush_lost_events,
            final_flush.flush_lost_bytes,
            final_flush.immediate_failures,
            static_cast<ULONG>(final_flush.immediate_last_status));
        PsTerminateSystemThread(STATUS_SUCCESS);
    }

    NTSTATUS initialize()
    {
        if (_InterlockedCompareExchange(&g_initialized, 0, 0)) return STATUS_SUCCESS;

        write_immediate_formatted("[SD] dbg_capture::initialize_enter irql=%lu pid=%llu tid=%llu ring=%p flush=%p\n",
            static_cast<ULONG>(KeGetCurrentIrql()),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentProcessId())),
            static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(PsGetCurrentThreadId())),
            g_ring,
            g_flush_buffer);

        g_ring = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kRingSize, kPoolTag));
        if (!g_ring) {
            write_immediate_formatted("[SD] dbg_capture::initialize_alloc_failed target=ring bytes=%lu status=0x%08lx\n",
                kRingSize,
                static_cast<ULONG>(STATUS_INSUFFICIENT_RESOURCES));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        g_flush_buffer = static_cast<UCHAR*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, kRingSize, kPoolTag));
        if (!g_flush_buffer) {
            ExFreePoolWithTag(g_ring, kPoolTag);
            g_ring = nullptr;
            write_immediate_formatted("[SD] dbg_capture::initialize_alloc_failed target=flush bytes=%lu status=0x%08lx\n",
                kRingSize,
                static_cast<ULONG>(STATUS_INSUFFICIENT_RESOURCES));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        KeInitializeSpinLock(&g_lock);
        KeInitializeEvent(&g_wake_event, SynchronizationEvent, FALSE);
        g_write_pos = 0;
        g_read_pos = 0;
        g_stop = 0;

        _InterlockedExchange(&g_initialized, 1);

        HANDLE thread_handle = nullptr;
        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
        NTSTATUS st = PsCreateSystemThread(
            &thread_handle,
            THREAD_ALL_ACCESS,
            &oa,
            NULL,
            NULL,
            drain_thread_routine,
            NULL);
        if (!NT_SUCCESS(st)) {
            ExFreePoolWithTag(g_ring, kPoolTag);
            g_ring = nullptr;
            ExFreePoolWithTag(g_flush_buffer, kPoolTag);
            g_flush_buffer = nullptr;
            _InterlockedExchange(&g_initialized, 0);
            write_immediate_formatted("[SD] dbg_capture::initialize_thread_failed status=0x%08lx ring=%p flush=%p\n",
                static_cast<ULONG>(st),
                g_ring,
                g_flush_buffer);
            return st;
        }

        NTSTATUS ref_status = ObReferenceObjectByHandle(
            thread_handle,
            THREAD_ALL_ACCESS,
            NULL,
            KernelMode,
            reinterpret_cast<PVOID*>(&g_drain_thread),
            NULL);
        ZwClose(thread_handle);

        write_immediate_formatted("[SD] dbg_capture::initialize_exit status=0x%08lx ref_status=0x%08lx ring=%p flush=%p thread=%p initialized=%ld\n",
            static_cast<ULONG>(st),
            static_cast<ULONG>(ref_status),
            g_ring,
            g_flush_buffer,
            g_drain_thread,
            _InterlockedCompareExchange(&g_initialized, 0, 0));

        return STATUS_SUCCESS;
    }

    void shutdown()
    {
        // Stop + join the drain thread, flush what is left, free the rings.
        // Only ever called from DriverUnload (single-threaded teardown).
        if (_InterlockedCompareExchange(&g_initialized, 0, 0) == 0)
            return;

        _InterlockedExchange(&g_stop, 1);
        KeSetEvent(&g_wake_event, 0, FALSE);

        PETHREAD thread = g_drain_thread;
        g_drain_thread = nullptr;
        if (thread) {
            LARGE_INTEGER timeout;
            timeout.QuadPart = -(5LL * 10000000LL);   // 5 s bound
            NTSTATUS wait_status = KeWaitForSingleObject(
                thread, Executive, KernelMode, FALSE, &timeout);
            write_immediate_formatted("[SD] dbg_capture::shutdown thread_join status=0x%08lx\n",
                static_cast<ULONG>(wait_status));
            ObDereferenceObject(thread);
        }

        // The thread is gone — no lock needed to free the buffers now.
        if (g_ring) {
            ExFreePoolWithTag(g_ring, kPoolTag);
            g_ring = nullptr;
        }
        if (g_flush_buffer) {
            ExFreePoolWithTag(g_flush_buffer, kPoolTag);
            g_flush_buffer = nullptr;
        }
        g_write_pos = 0;
        g_read_pos = 0;
        _InterlockedExchange(&g_initialized, 0);
        write_immediate_formatted("[SD] dbg_capture::shutdown complete\n");
    }
}
