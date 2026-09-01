// src/live/probe_kernel.cpp
// tiny driver probe, connect attach read, exit 0 means the path is healthy

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>

#include "core/runtime/voyager_comm.h"

#include <cstdio>
#include <cstdint>

static uint32_t find_pid(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{ sizeof(pe) };
    uint32_t pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            char narrow[MAX_PATH];
            WideCharToMultiByte(CP_ACP, 0, pe.szExeFile, -1, narrow, sizeof(narrow), nullptr, nullptr);
            if (_stricmp(narrow, name) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

int main(int argc, char** argv) {
    const char* targetName = argc > 1 ? argv[1] : "SlopTarget.exe";

    // rip-sample mode: poll every thread's RIP through the driver, print
    // samples that fall OUTSIDE ntdll waits (i.e. user/kernel32 code paths)
    if (argc > 2 && std::strcmp(argv[1], "--rip-sample") == 0) {
        voyager::device_t dev;
        if (!dev.connect()) { std::printf("FAIL connect\n"); return 1; }
        const uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 0));
        dev.set_process_id(pid);
        const uint64_t dtb = dev.solve_dtb_for_pid(pid);
        if (dtb) dev.set_dtb(dtb);

        for (int round = 0; round < 200; ++round) {
            auto threads = dev.enumerate_threads();
            for (const auto& t : threads) {
                voyager::device_t::thread_context ctx{};
                if (!dev.get_thread_context(t.tid, ctx)) continue;
                // ntdll on this boot sits around 0x7FFDD9590000; skip waits there
                if (ctx.rip >= 0x7FFDD9000000ULL && ctx.rip < 0x7FFDD9800000ULL) continue;
                std::printf("[s] tid=%u rip=0x%llX\n", t.tid,
                            static_cast<unsigned long long>(ctx.rip));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(7));
        }
        dev.disconnect();
        return 0;
    }

    // hwbp-test mode: set DR0 via driver on all threads, read back, report
    if (argc > 3 && std::strcmp(argv[1], "--hwbp-test") == 0) {
        voyager::device_t dev;
        if (!dev.connect()) { std::printf("FAIL connect\n"); return 1; }
        const uint32_t pid = static_cast<uint32_t>(std::strtoul(argv[2], nullptr, 0));
        const uint64_t addr = std::strtoull(argv[3], nullptr, 0);
        dev.set_process_id(pid);
        const uint64_t dtb = dev.solve_dtb_for_pid(pid);
        if (dtb) dev.set_dtb(dtb);
        std::printf("[t] attached pid=%u dtb=0x%llX\n", pid,
                    static_cast<unsigned long long>(dev.get_dtb()));

        auto threads = dev.enumerate_threads();
        for (const auto& t : threads) {
            const bool ok = dev.set_hardware_breakpoint(t.tid, 0, addr, 0, 0);
            voyager::device_t::thread_context ctx{};
            const bool got = dev.get_thread_context(t.tid, ctx);
            std::printf("[t] tid=%u set=%d ctx=%d rip=0x%llX dr0=0x%llX dr7=0x%llX\n",
                        t.tid, ok ? 1 : 0, got ? 1 : 0,
                        static_cast<unsigned long long>(ctx.rip),
                        static_cast<unsigned long long>(ctx.dr0 ? ctx.dr0 : 0),
                        static_cast<unsigned long long>(ctx.dr7));
        }
        dev.disconnect();
        return 0;
    }

    voyager::device_t dev;

    std::printf("[01] connecting to \\\\.\\slopdrvr ...\n");
    if (!dev.connect()) {
        std::printf("     FAIL connect gle=%lu\n", GetLastError());
        return 1;
    }
    std::printf("[02] connected\n");

    const uint32_t pid = find_pid(targetName);
    if (!pid) {
        std::printf("     FAIL target '%s' not running\n", targetName);
        return 2;
    }
    std::printf("[03] target %s pid=%u\n", targetName, pid);

    dev.clear_process_context();
    dev.set_process_id(pid);
    std::printf("[04] process_id set, solving DTB ...\n");
    const uint64_t dtb = dev.solve_dtb_for_pid(pid);
    if (dtb) dev.set_dtb(dtb);
    std::printf("[05] solve_dtb_for_pid -> 0x%llX (cached 0x%llX)\n",
                static_cast<unsigned long long>(dtb),
                static_cast<unsigned long long>(dev.get_dtb()));
    if (!dtb || !dev.get_dtb()) {
        std::printf("     FAIL dtb resolve\n");
        return 3;
    }

    const uint64_t base = dev.find_image();
    std::printf("[06] base_address -> 0x%llX\n", static_cast<unsigned long long>(base));

    uint8_t buf[16] = {};
    const size_t got = dev.read_raw(base, buf, sizeof(buf));
    std::printf("[07] read_raw @base -> %zu bytes: ", got);
    for (uint8_t b : buf) std::printf("%02X", b);
    std::printf("\n");
    if (got != sizeof(buf)) {
        std::printf("     FAIL short read gle=%lu\n", GetLastError());
        return 4;
    }

    auto threads = dev.enumerate_threads();
    std::printf("[08] enumerate_threads -> %zu entries\n", threads.size());

    voyager::device_t::thread_context ctx{};
    bool ctxOk = false;
    for (const auto& t : threads) {
        if (dev.get_thread_context(t.tid, ctx)) { ctxOk = true; break; }
    }
    std::printf("[09] get_thread_context -> %s rip=0x%llX\n",
                ctxOk ? "OK" : "FAIL",
                static_cast<unsigned long long>(ctx.rip));

    dev.clear_process_context();
    dev.disconnect();
    std::printf("[10] disconnected cleanly\n");
    std::printf("=== PROBE PASS ===\n");
    return 0;
}
