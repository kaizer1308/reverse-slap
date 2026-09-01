#pragma once

#include <ntifs.h>

namespace dbg_capture {

    // Log verbosity, mirror of the registry value SlopKernelLogLevel:
    //   0 = errors only       1 = + critical lifecycle (default)
    //   2 = + per-IOCTL       3 = + per-packet WFP paths
    //   4 = everything
    // The per-packet WFP classify logs are what once grew slop_kernel.log
    // to gigabytes — level 1 (default) keeps them off.
    enum log_level_t : ULONG {
        kLogError    = 0,
        kLogCritical = 1,
        kLogIoctl    = 2,
        kLogPacket   = 3,
        kLogTrace    = 4,
    };

    // Current level (registry-configured; defaults to kLogCritical).
    ULONG current_log_level();

    // True when a message of `level` should be emitted.
    BOOLEAN should_log(ULONG level);

    // Live reconfiguration (LOGCTL ioctl). Both clamp their input and
    // announce the change in the log itself.
    void set_log_level(ULONG level);       // 0..4
    void set_log_cap_mb(ULONG mb);         // 1..512
    ULONG current_log_cap_mb();

    void configure_log_path(PUNICODE_STRING registry_path);

    NTSTATUS initialize();

    // Stop + join the drain thread, flush the ring, free the buffers.
    // Called from DriverUnload only.
    void shutdown();

    void write_formatted(const char* fmt, ...);

    // Level-filtered variant used by the SD_LOG_* macros.
    void write_formatted_level(ULONG level, const char* fmt, ...);

    void write_immediate_formatted(const char* fmt, ...);
}
