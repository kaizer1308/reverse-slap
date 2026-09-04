// src/target/main.cpp
// the test target, known values and pointer chains to scan for

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "known_values.hpp"
#include "pointer_chain.hpp"
#include "aob_fixtures.hpp"
#include "region_zoo.hpp"
#include "mutator.hpp"
#include "report.hpp"

using namespace slop_target;

namespace {

std::atomic<bool> g_running{true};
std::atomic<bool> g_auto_tick{false};
std::atomic<int>  g_tick_hz{1};

// Crash diagnostics: the injector test suite hijacks threads in this
// process, and when something goes wrong the access violation kills the
// fixture with no trace. This filter writes the exception record and
// register state to %TEMP% so the failing instruction is identifiable.
LONG WINAPI crash_dump_filter(EXCEPTION_POINTERS* ep) {
    char path[MAX_PATH] = {};
    if (GetTempPathA(MAX_PATH, path) == 0) return EXCEPTION_CONTINUE_SEARCH;
    char tail[64] = {};
    std::snprintf(tail, sizeof(tail), "sloptarget_crash_%u.txt",
                  GetCurrentProcessId());
    std::strcat(path, tail);
    FILE* f = nullptr;
    if (fopen_s(&f, path, "w") == 0 && f) {
        const EXCEPTION_RECORD& xr = *ep->ExceptionRecord;
        std::fprintf(f, "code=0x%08lX addr=0x%llX flags=0x%lX\n",
                     xr.ExceptionCode,
                     (unsigned long long)(uintptr_t)xr.ExceptionAddress,
                     xr.ExceptionFlags);
        for (unsigned i = 0; i < xr.NumberParameters && i < 15; ++i)
            std::fprintf(f, "info[%u]=0x%llX\n", i,
                         (unsigned long long)xr.ExceptionInformation[i]);
        if (ep->ContextRecord) {
            const CONTEXT& c = *ep->ContextRecord;
            std::fprintf(f,
                "rip=0x%llX rsp=0x%llX rbp=0x%llX\n"
                "rax=0x%llX rbx=0x%llX rcx=0x%llX rdx=0x%llX\n"
                "rsi=0x%llX rdi=0x%llX r8=0x%llX r9=0x%llX\n"
                "r10=0x%llX r11=0x%llX r12=0x%llX r13=0x%llX\n"
                "r14=0x%llX r15=0x%llX\n"
                "tid=%lu\n",
                (unsigned long long)c.Rip, (unsigned long long)c.Rsp,
                (unsigned long long)c.Rbp,
                (unsigned long long)c.Rax, (unsigned long long)c.Rbx,
                (unsigned long long)c.Rcx, (unsigned long long)c.Rdx,
                (unsigned long long)c.Rsi, (unsigned long long)c.Rdi,
                (unsigned long long)c.R8, (unsigned long long)c.R9,
                (unsigned long long)c.R10, (unsigned long long)c.R11,
                (unsigned long long)c.R12, (unsigned long long)c.R13,
                (unsigned long long)c.R14, (unsigned long long)c.R15,
                GetCurrentThreadId());
        }
        std::fclose(f);
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

void ticker_thread() {
    while (g_running.load(std::memory_order_relaxed)) {
        if (g_auto_tick.load(std::memory_order_relaxed)) {
            values_tick();
        }
        const int hz = g_tick_hz.load(std::memory_order_relaxed);
        const int ms = (hz > 0) ? (1000 / hz) : 1000;
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }
}

void process_command(const char* line) {
    if (!line || line[0] == '\0') return;

    char cmd[64]{}, arg1[64]{}, arg2[128]{};
    std::sscanf(line, "%63s %63s %127[^\n]", cmd, arg1, arg2);

    if (std::strcmp(cmd, "quit") == 0 || std::strcmp(cmd, "exit") == 0) {
        g_running.store(false);
    }
    else if (std::strcmp(cmd, "tick") == 0) {
        values_tick();
        std::printf("[tick] health=%d score=%d speed=%.3f\n",
            static_cast<int>(g_values.health),
            static_cast<int>(g_values.score),
            static_cast<float>(g_values.speed));
    }
    else if (std::strcmp(cmd, "auto") == 0) {
        int hz = (arg1[0] != '\0') ? std::atoi(arg1) : 1;
        if (hz < 1) hz = 1;
        if (hz > 100) hz = 100;
        g_tick_hz.store(hz);
        g_auto_tick.store(true);
        std::printf("[auto] ticking at %d Hz\n", hz);
    }
    else if (std::strcmp(cmd, "stop") == 0) {
        g_auto_tick.store(false);
        std::printf("[auto] stopped\n");
    }
    else if (std::strcmp(cmd, "set") == 0) {
        values_set(arg1, arg2);
    }
    else if (std::strcmp(cmd, "inc") == 0) {
        values_inc(arg1);
    }
    else if (std::strcmp(cmd, "dec") == 0) {
        values_dec(arg1);
    }
    else if (std::strcmp(cmd, "mutate") == 0) {
        mutator_mutate();
        std::printf("[mutate] one pass complete\n");
    }
    else if (std::strcmp(cmd, "realloc") == 0) {
        chain_realloc();
    }
    else if (std::strcmp(cmd, "report") == 0) {
        report_print();
        report_json();
    }
    else if (std::strcmp(cmd, "regions") == 0) {
        std::printf("rw=%p noaccess=%p guard=%p exec=%p reserve=%p mapped=%p\n",
            g_zoo.rw_block, g_zoo.noaccess_block, g_zoo.guard_block,
            g_zoo.exec_block, g_zoo.reserve_block, g_zoo.mapped_view);
    }
    else {
        std::printf("[?] unknown command: %s\n", cmd);
    }
}

} // namespace

int main(int argc, char* argv[]) {
    SetUnhandledExceptionFilter(crash_dump_filter);
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("SlopTarget v0.1 - reverse-slop test target\n");
    std::printf("PID: %u\n\n", GetCurrentProcessId());

    // Initialize subsystems
    values_init();
    chain_init();
    zoo_init();
    mutator_init();

    // Force AOB fixtures to be linked (prevent dead-code elimination)
    volatile int32_t aob_touch = aob_unique_fn() + aob_twin_a() + aob_twin_b();
    (void)aob_touch;

    // Print + write address report
    report_print();
    report_json();

    // Parse CLI flags
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--auto") == 0) {
            int hz = 1;
            if (i + 1 < argc) { hz = std::atoi(argv[++i]); }
            if (hz < 1) hz = 1;
            g_tick_hz.store(hz);
            g_auto_tick.store(true);
            std::printf("[auto] ticking at %d Hz\n", hz);
        }
    }

    // Start ticker thread
    std::thread ticker(ticker_thread);

    // Command loop
    std::printf("commands: tick, auto <hz>, stop, set <name> <val>, inc <name>, "
                "dec <name>, mutate, realloc, report, regions, quit\n> ");

    char line[256];
    while (g_running.load(std::memory_order_relaxed)) {
        if (!std::fgets(line, sizeof(line), stdin)) break;
        // Strip trailing newline
        size_t len = std::strlen(line);
        if (len > 0 && line[len - 1] == '\n') line[len - 1] = '\0';
        process_command(line);
        if (g_running.load(std::memory_order_relaxed))
            std::printf("> ");
    }

    // Shutdown
    g_running.store(false);
    if (ticker.joinable()) ticker.join();
    chain_shutdown();
    zoo_shutdown();
    delete g_heap_values;

    std::printf("SlopTarget exiting.\n");
    return 0;
}
