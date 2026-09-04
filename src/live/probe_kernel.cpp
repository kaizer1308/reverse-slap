// src/live/probe_kernel.cpp
// tiny driver probe, connect attach read, exit 0 means the path is healthy

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "core/runtime/voyager_comm.h"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/kernel_injector.hpp"
#include "core/infra/diag.hpp"

#include <chrono>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <thread>

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

static uint32_t spawn_cmd(HANDLE* kept = nullptr) {
    // Prefer the SlopTarget fixture (self-waking ticker thread); cmd.exe's
    // only quiet thread sits in a console read that never completes.
    char self[MAX_PATH] = {};
    if (GetModuleFileNameA(nullptr, self, MAX_PATH)) {
        char* slash = strrchr(self, '\\');
        if (slash) {
            *slash = '\0';
            char target[MAX_PATH] = {};
            _snprintf_s(target, MAX_PATH, _TRUNCATE,
                        "%s\\..\\src\\app\\SlopTarget.exe", self);
            STARTUPINFOA si{};
            si.cb = sizeof(si);
            PROCESS_INFORMATION pi{};
            char mutable_cmd[MAX_PATH] = {};
            strncpy_s(mutable_cmd, MAX_PATH, target, _TRUNCATE);
            if (CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                               CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hThread);
                Sleep(750);
                if (kept) {
                    *kept = pi.hProcess;
                } else {
                    CloseHandle(pi.hProcess);
                }
                return pi.dwProcessId;
            }
        }
    }
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[MAX_PATH] = {};
    GetSystemDirectoryA(cmd, MAX_PATH - 16);
    strcat_s(cmd, MAX_PATH, "\\cmd.exe");
    char* mutable_cmd = cmd;
    if (!CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        return 0;
    CloseHandle(pi.hThread);
    Sleep(750);
    if (kept) {
        *kept = pi.hProcess;
    } else {
        CloseHandle(pi.hProcess);
    }
    return pi.dwProcessId;
}

static void kill_pid(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        WaitForSingleObject(h, 5000);
        CloseHandle(h);
    }
}

// isolate the hijack mechanics: suspend each victim thread, write its own
// context back (no RIP change, no shellcode), resume, and see if the victim
// survives. Splits "suspend/set/resume on a console-blocked thread is
// inherently fatal" from "the hijack RIP/shellcode is the killer".
static int suspend_test(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { std::printf("FAIL snapshot\n"); return 1; }
    THREADENTRY32 te{ sizeof(te) };
    int cycled = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != pid) continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                       THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!th) continue;
            DWORD prev = 0;
            const DWORD sus = SuspendThread(th);
            if (sus != (DWORD)-1 && sus == 0) {
                prev = sus;
                CONTEXT ctx{ .ContextFlags = CONTEXT_FULL };
                if (GetThreadContext(th, &ctx)) {
                    std::printf("[s] tid=%u rip=0x%llX rsp=0x%llX -> set back\n",
                                te.th32ThreadID,
                                (unsigned long long)ctx.Rip,
                                (unsigned long long)ctx.Rsp);
                    SetThreadContext(th, &ctx); // identical context
                    ++cycled;
                }
                ResumeThread(th);
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    std::printf("[s] cycled %d threads with suspend/set-same/resume\n", cycled);
    Sleep(3000);
    HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD ec = 0;
    const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
    if (alive) CloseHandle(alive);
    std::printf("[s] after cycle: alive=%d exit_code=%lu\n", live ? 1 : 0, ec);
    return live ? 0 : 1;
}

// bisect the hijack: set RIP to a bare `jmp $-2` spin gadget inside the
// victim's own ntdll (optionally with the real hijack's RSP shift) and see
// whether the victim survives. Isolates "RIP change kills" from "RSP
// shift kills" from "shellcode content kills".
static int spin_test(uint32_t pid, bool shift_rsp, int thread_index) {
    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("     FAIL kernel backend not activatable\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) {
        std::printf("     FAIL no kernel device\n");
        reg::set_backend_preference(saved);
        return 1;
    }
    dev->set_process_id(pid);
    const std::uint64_t dtb = dev->solve_dtb_for_pid(pid);
    if (!dtb) { std::printf("     FAIL dtb\n"); reg::set_backend_preference(saved); return 1; }
    dev->set_dtb(dtb);

    const auto ntdll = slop::core::runtime::injector::find_module_base(pid, "ntdll.dll");
    if (!ntdll) { std::printf("     FAIL ntdll base\n"); reg::set_backend_preference(saved); return 1; }
    std::printf("[p] ntdll @ 0x%llX\n", (unsigned long long)*ntdll);

    // scan ntdll code for `EB FE` (jmp $-2)
    std::uint64_t gadget = 0;
    std::vector<std::uint8_t> buf(0x10000);
    for (std::uint64_t off = 0x1000; off < 0x180000 && !gadget; off += 0x10000 - 2) {
        const std::size_t got = dev->read_raw(*ntdll + off, buf.data(), buf.size());
        if (got != buf.size()) break;
        for (std::size_t i = 0; i + 1 < buf.size(); ++i) {
            if (buf[i] == 0xEB && buf[i + 1] == 0xFE) {
                gadget = *ntdll + off + i;
                break;
            }
        }
    }
    if (!gadget) { std::printf("     FAIL no EB FE gadget in ntdll\n"); reg::set_backend_preference(saved); return 1; }
    std::printf("[p] spin gadget @ 0x%llX (rsp_shift=%d)\n",
                (unsigned long long)gadget, shift_rsp ? 1 : 0);

    // pick the Nth victim thread in creation order (0 = main)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { std::printf("FAIL snapshot\n"); reg::set_backend_preference(saved); return 1; }
    THREADENTRY32 te{ sizeof(te) };
    DWORD tid = 0;
    int seen = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (seen == thread_index) { tid = te.th32ThreadID; break; }
                ++seen;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!tid) { std::printf("     FAIL no thread\n"); reg::set_backend_preference(saved); return 1; }

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                               THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                           FALSE, tid);
    if (!th) { std::printf("     FAIL open tid=%u gle=%lu\n", tid, GetLastError()); reg::set_backend_preference(saved); return 1; }
    SuspendThread(th);
    CONTEXT ctx{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &ctx);
    std::printf("[p] hijack tid=%u rip=0x%llX -> 0x%llX rsp=0x%llX",
                tid, (unsigned long long)ctx.Rip,
                (unsigned long long)gadget, (unsigned long long)ctx.Rsp);
    ctx.Rip = gadget;
    if (shift_rsp) {
        ctx.Rsp = ((ctx.Rsp - 0x108) & ~0xFULL) + 0x8;
    }
    std::printf(" rsp'=0x%llX\n", (unsigned long long)ctx.Rsp);
    SetThreadContext(th, &ctx);
    ResumeThread(th);
    CloseHandle(th);

    Sleep(3000);
    HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD ec = 0;
    const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
    if (alive) CloseHandle(alive);
    std::printf("[p] after spin-hijack: alive=%d exit_code=%lu\n", live ? 1 : 0, ec);
    reg::set_backend_preference(saved);
    return live ? 0 : 1;
}

// spawn SlopTarget as a debugged child so its access violation surfaces as
// a debug event: exception code, faulting address, thread, and full context
// at the moment of the crash.
static int call_test_debug() {
    char self[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, self, MAX_PATH)) return 1;
    char* slash = strrchr(self, '\\');
    if (!slash) return 1;
    *slash = '\0';
    char target[MAX_PATH] = {};
    _snprintf_s(target, MAX_PATH, _TRUNCATE, "%s\\..\\src\\app\\SlopTarget.exe", self);
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char mutable_cmd[MAX_PATH] = {};
    strncpy_s(mutable_cmd, MAX_PATH, target, _TRUNCATE);
    if (!CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                        DEBUG_ONLY_THIS_PROCESS | CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) {
        std::printf("[g] FAIL spawn gle=%lu\n", GetLastError());
        return 1;
    }
    const uint32_t pid = pi.dwProcessId;
    std::printf("[g] debugged victim pid=%u\n", pid);

    // pump until the initial loader breakpoint so the victim actually runs
    bool saw_first_bp = false;
    for (int spins = 0; spins < 100 && !saw_first_bp; ++spins) {
        DEBUG_EVENT de{};
        if (!WaitForDebugEvent(&de, 200)) continue;
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
            de.u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT) {
            saw_first_bp = true;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    if (!saw_first_bp) std::printf("[g] warn: no initial breakpoint seen\n");
    Sleep(1500); // let it print its report and reach the fgets loop

    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    int rc = 1;
    if (reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        auto gcpid = slop::core::runtime::injector::resolve_export(
            pid, "kernel32.dll", "GetCurrentProcessId");
        if (gcpid) {
            const ULONGLONG t0 = GetTickCount64();
            auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
            const std::uint64_t r = k && k->device()
                ? k->device()->call_function(*gcpid) : 0;
            std::printf("[g] call -> 0x%llX (%llu ms) expected pid=%u\n",
                        (unsigned long long)r,
                        (unsigned long long)(GetTickCount64() - t0), pid);
            rc = (r == pid) ? 0 : 1;
        } else {
            std::printf("[g] FAIL resolve\n");
        }
    }
    reg::set_backend_preference(saved);

    // pump debug events: report any exception with full context
    for (int spins = 0; spins < 60; ++spins) {
        DEBUG_EVENT de{};
        if (!WaitForDebugEvent(&de, 100)) {
            // nothing pending; bail when the victim is gone
            DWORD ec = 0;
            if (!GetExitCodeProcess(pi.hProcess, &ec) || ec != STILL_ACTIVE) {
                break;
            }
            continue;
        }
        DWORD cont = DBG_CONTINUE;
        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            const EXCEPTION_RECORD& xr = de.u.Exception.ExceptionRecord;
            if (xr.ExceptionCode == STATUS_BREAKPOINT && !saw_first_bp) {
                saw_first_bp = true; // initial ntdll breakpoint, ignore
            } else {
                std::printf("[g] EXCEPTION tid=%lu code=0x%lX addr=0x%llX "
                            "first_chance=%d\n",
                            de.dwThreadId, xr.ExceptionCode,
                            (unsigned long long)(uintptr_t)xr.ExceptionAddress,
                            de.u.Exception.dwFirstChance ? 1 : 0);
                if (xr.ExceptionInformation[0]) {
                    std::printf("[g]   %s access at 0x%llX\n",
                                xr.ExceptionInformation[0] == 0 ? "read" :
                                xr.ExceptionInformation[0] == 1 ? "write" :
                                "exec",
                                (unsigned long long)xr.ExceptionInformation[1]);
                }
                CONTEXT ctx{ .ContextFlags = CONTEXT_FULL };
                HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                       FALSE, de.dwThreadId);
                if (th) {
                    if (GetThreadContext(th, &ctx)) {
                        std::printf("[g]   ctx rip=0x%llX rsp=0x%llX rcx=0x%llX "
                                    "rax=0x%llX rsi=0x%llX\n",
                                    (unsigned long long)ctx.Rip,
                                    (unsigned long long)ctx.Rsp,
                                    (unsigned long long)ctx.Rcx,
                                    (unsigned long long)ctx.Rax,
                                    (unsigned long long)ctx.Rsi);
                    }
                    CloseHandle(th);
                }
                cont = DBG_EXCEPTION_NOT_HANDLED; // let it die
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            std::printf("[g] victim exited code=0x%lX\n",
                        de.u.ExitProcess.dwExitCode);
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, cont);
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return rc;
}

// full-primitive replication minus the RC ioctl: allocate via the driver,
// write ctx + shellcode through the physical path ourselves, hijack the
// ticker, and read the result back. Then bisect: `gadget` mode plants only
// EB FE at the code offset, `full` mode plants the exact build_direct_call
// shellcode the driver emits.
// stage-wise emission: 1=prologue rax/ctx, 2=+pushes, 3=+rsi/rbx/rsp backup,
// 4=+stack switch, 5=+xmm saves, 6=full call. Every truncation ends in a
// bare spin so the thread never runs off the end.
static size_t emit_direct_call(uint8_t* buf, uint64_t ctx_addr, int stages) {
    size_t i = 0;
    auto put = [&](const uint8_t* p, size_t n) { memcpy(buf + i, p, n); i += n; };
    auto spin = [&]() { buf[i++] = 0xEB; buf[i++] = 0xFE; };
    uint8_t b1[1] = { 0x50 }; put(b1, 1);                                  // push rax
    uint8_t b2[2] = { 0x48, 0xB8 }; put(b2, 2);                            // movabs rax, ctx
    memcpy(buf + i, &ctx_addr, 8); i += 8;
    uint8_t b3[4] = { 0x48, 0x89, 0x60, 0x60 }; put(b3, 4);                // mov [rax+0x60], rsi
    uint8_t b4[5] = { 0x48, 0x83, 0x40, 0x60, 0x08 }; put(b4, 5);          // add qword [rax+0x60], 8
    uint8_t b5[1] = { 0x58 }; put(b5, 1);                                  // pop rax
    uint8_t b6[1] = { 0x9C }; put(b6, 1);                                  // pushfq
    if (stages < 2) { spin(); return i; }
    uint8_t b7[23] = { 0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57,
                       0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41, 0x53,
                       0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57 };
    put(b7, 23);                                                            // push rax..r15
    if (stages < 3) { spin(); return i; }
    uint8_t b8[2] = { 0x48, 0xBE }; put(b8, 2);                            // movabs rsi, ctx
    memcpy(buf + i, &ctx_addr, 8); i += 8;
    uint8_t b9[4] = { 0x48, 0x89, 0x5E, 0x48 }; put(b9, 4);                // mov [rsi+0x48], rbx
    uint8_t b10[7] = { 0x48, 0x89, 0xA6, 0x00, 0x01, 0x00, 0x00 }; put(b10, 7); // mov [rsi+0x100], rsp
    if (stages < 4) { spin(); return i; }
    uint8_t b11[4] = { 0x48, 0x83, 0xE4, 0xF0 }; put(b11, 4);              // and rsp, ~0xF
    uint8_t b12[7] = { 0x48, 0x81, 0xEC, 0x80, 0x00, 0x00, 0x00 }; put(b12, 7); // sub rsp, 0x80
    uint8_t b13[4] = { 0x48, 0x89, 0x66, 0x38 }; put(b13, 4);              // mov [rsi+0x38], rsp
    if (stages < 5) { spin(); return i; }
    if (stages == 8) {
        // stage-5 variant: exactly ONE movups store, then spin
        static const uint8_t one_sse[5] = { 0x0F, 0x11, 0x04, 0x24 };  // movups [rsp], xmm0
        put(one_sse, 4);
        spin();
        return i;
    }
    if (stages == 9) {
        // stage-5 variant: SSE read from the ctx page, no stack write
        static const uint8_t sse_read[4] = { 0x0F, 0x10, 0x06 };       // movups xmm0, [rsi]
        put(sse_read, 3);
        spin();
        return i;
    }
    if (stages == 7) {
        // stage-5 variant: same 0x60 bytes of stack scratch, plain qword
        // stores instead of SSE -- isolates "stack write kills" from "SSE
        // instruction kills"
        static const uint8_t plain[59] = {
            0x48, 0x89, 0x04, 0x24,             // mov [rsp], rax
            0x48, 0x89, 0x4C, 0x24, 0x08,       // mov [rsp+8], rcx
            0x48, 0x89, 0x54, 0x24, 0x10,       // mov [rsp+0x10], rdx
            0x48, 0x89, 0x5C, 0x24, 0x18,       // mov [rsp+0x18], rbx
            0x48, 0x89, 0x6C, 0x24, 0x20,       // mov [rsp+0x20], rbp
            0x48, 0x89, 0x74, 0x24, 0x28,       // mov [rsp+0x28], rsi
            0x48, 0x89, 0x7C, 0x24, 0x30,       // mov [rsp+0x30], rdi
            0x4C, 0x89, 0x44, 0x24, 0x38,       // mov [rsp+0x38], r8
            0x4C, 0x89, 0x4C, 0x24, 0x40,       // mov [rsp+0x40], r9
            0x4C, 0x89, 0x54, 0x24, 0x48,       // mov [rsp+0x48], r10
            0x4C, 0x89, 0x5C, 0x24, 0x50,       // mov [rsp+0x50], r11
            0x4C, 0x89, 0x64, 0x24, 0x58,       // mov [rsp+0x58], r12
        };
        put(plain, sizeof(plain));
        spin();
        return i;
    }
    uint8_t b14[29] = { 0x0F, 0x11, 0x04, 0x24,
                        0x0F, 0x11, 0x4C, 0x24, 0x10,
                        0x0F, 0x11, 0x54, 0x24, 0x20,
                        0x0F, 0x11, 0x5C, 0x24, 0x30,
                        0x0F, 0x11, 0x64, 0x24, 0x40,
                        0x0F, 0x11, 0x6C, 0x24, 0x50 };
    put(b14, 29);                                                           // movups x6
    if (stages < 6) { spin(); return i; }
    uint8_t b15[7] = { 0x48, 0x81, 0xEC, 0x20, 0x00, 0x00, 0x00 }; put(b15, 7); // sub rsp, 0x20
    uint8_t b16[19] = { 0x48, 0x8B, 0x4E, 0x10,
                        0x48, 0x8B, 0x56, 0x18,
                        0x4C, 0x8B, 0x46, 0x20,
                        0x4C, 0x8B, 0x4E, 0x28,
                        0x48, 0x8B, 0x06 };
    put(b16, 19);                                                           // args + target
    uint8_t b17[2] = { 0xFF, 0xD0 }; put(b17, 2);                           // call rax
    uint8_t b18[4] = { 0x48, 0x89, 0x46, 0x30 }; put(b18, 4);               // mov [rsi+0x30], rax
    uint8_t b19[4] = { 0x48, 0x8B, 0x5E, 0x48 }; put(b19, 4);               // mov rbx, [rsi+0x48]
    uint8_t b20[8] = { 0x48, 0xC7, 0x46, 0x50, 0x01, 0x00, 0x00, 0x00 }; put(b20, 8); // exec_done=1
    uint8_t b21[3] = { 0x0F, 0xAE, 0xF0 }; put(b21, 3);                     // mfence
    uint8_t b22[2] = { 0xF3, 0x90 }; put(b22, 2);                           // pause
    uint8_t b23[2] = { 0xEB, 0xFC }; put(b23, 2);                           // jmp $-2
    return i;
}

static int shell_test(uint32_t pid, int stages, int thread_index = 1) {
    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("     FAIL kernel backend\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) { reg::set_backend_preference(saved); return 1; }
    dev->set_process_id(pid);
    const std::uint64_t dtb = dev->solve_dtb_for_pid(pid);
    if (!dtb) { std::printf("     FAIL dtb\n"); reg::set_backend_preference(saved); return 1; }
    dev->set_dtb(dtb);

    auto gcpid = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "GetCurrentProcessId");
    if (!gcpid) { std::printf("     FAIL resolve\n"); reg::set_backend_preference(saved); return 1; }

    const std::uint64_t base = dev->allocate_memory(0x2000);
    if (!base) { std::printf("     FAIL alloc\n"); reg::set_backend_preference(saved); return 1; }
    std::printf("[h] alloc @ 0x%llX ( GetCurrentProcessId @ 0x%llX )\n",
                (unsigned long long)base, (unsigned long long)*gcpid);

    // ctx: target_func at +0, params at +0x10.., mirrors CALL_CONTEXT
    struct ctx_t {
        std::uint64_t target_func, spoof_gadget, param1, param2, param3, param4;
        std::uint64_t ret_value, saved_rsp, original_rip, rbx_backup, exec_done;
        std::uint64_t trampoline, stack_backup[8];
    };
    ctx_t ctx{};
    ctx.target_func = *gcpid;
    ctx.trampoline  = base + 0x600;
    if (dev->write_raw(base, &ctx, sizeof(ctx)) != sizeof(ctx)) {
        std::printf("     FAIL ctx write\n");
        dev->free_memory(base);
        reg::set_backend_preference(saved);
        return 1;
    }

    uint8_t code[256] = {};
    size_t code_len = 2;
    code[0] = 0xEB; code[1] = 0xFE;               // stage 0: bare spin
    if (stages > 0) {
        code_len = emit_direct_call(code, base, stages);
    }
    if (dev->write_raw(base + 0x200, code, code_len) != code_len) {
        std::printf("     FAIL code write\n");
        dev->free_memory(base);
        reg::set_backend_preference(saved);
        return 1;
    }
    std::printf("[h] wrote %zu code bytes @ 0x%llX (stages=%d)\n",
                code_len, (unsigned long long)(base + 0x200), stages);

    // hijack the ticker (thread index 1)
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { std::printf("FAIL snapshot\n"); dev->free_memory(base); reg::set_backend_preference(saved); return 1; }
    THREADENTRY32 te{ sizeof(te) };
    DWORD tid = 0;
    int seen = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                if (seen == thread_index) { tid = te.th32ThreadID; break; }
                ++seen;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!tid) { std::printf("     FAIL pick ticker\n"); dev->free_memory(base); reg::set_backend_preference(saved); return 1; }

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                               THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                           FALSE, tid);
    if (!th) { std::printf("     FAIL open tid\n"); dev->free_memory(base); reg::set_backend_preference(saved); return 1; }
    SuspendThread(th);
    CONTEXT hctx{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &hctx);
    const std::uint64_t orig_rip = hctx.Rip;
    const std::uint64_t orig_rsp = hctx.Rsp;
    hctx.Rip = base + 0x200;
    hctx.Rsp = ((hctx.Rsp - 0x108) & ~0xFULL) + 0x8;
    SetThreadContext(th, &hctx);
    ResumeThread(th);
    CloseHandle(th);
    std::printf("[h] hijacked ticker tid=%u rip 0x%llX -> 0x%llX rsp 0x%llX -> 0x%llX\n",
                tid, (unsigned long long)orig_rip,
                (unsigned long long)hctx.Rip,
                (unsigned long long)orig_rsp, (unsigned long long)hctx.Rsp);

    // poll exec_done / ret_value through the physical path
    std::uint64_t done = 0, ret = 0, srsp = 0;
    for (int i = 0; i < 40; ++i) {
        done = dev->read<std::uint64_t>(base + 0x50);
        ret = dev->read<std::uint64_t>(base + 0x30);
        srsp = dev->read<std::uint64_t>(base + 0x38);
        if (done) break;
        Sleep(100);
    }
    const std::uint64_t rsi_backup = dev->read<std::uint64_t>(base + 0x60);
    const std::uint64_t rbx_backup = dev->read<std::uint64_t>(base + 0x48);
    const std::uint64_t rsp_backup = dev->read<std::uint64_t>(base + 0x100);
    std::printf("[h] exec_done=0x%llX ret=0x%llX saved_rsp=0x%llX "
                "rsi_bak=0x%llX rbx_bak=0x%llX rsp_bak=0x%llX (expected pid=%u)\n",
                (unsigned long long)done, (unsigned long long)ret,
                (unsigned long long)srsp,
                (unsigned long long)rsi_backup,
                (unsigned long long)rbx_backup,
                (unsigned long long)rsp_backup, pid);

    HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD ec = 0;
    const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
    if (alive) CloseHandle(alive);
    std::printf("[h] victim alive=%d exit_code=%lu\n", live ? 1 : 0, ec);

    // restore the ticker so the victim stays clean
    if (live && done) {
        HANDLE th2 = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                                    THREAD_SET_CONTEXT,
                                FALSE, tid);
        if (th2) {
            SuspendThread(th2);
            CONTEXT rctx{ .ContextFlags = CONTEXT_FULL };
            GetThreadContext(th2, &rctx);
            rctx.Rip = orig_rip;
            rctx.Rsp = orig_rsp;
            SetThreadContext(th2, &rctx);
            ResumeThread(th2);
            CloseHandle(th2);
            std::printf("[h] ticker restored\n");
        }
    }
    dev->free_memory(base);
    reg::set_backend_preference(saved);
    return (live && done && ret == pid) ? 0 : 1;
}

// dormant-hijack + restore of the console-reading main thread: mirrors the
// real call flow's attempt 1 (hijack, poll until timeout, restore original
// context). Tests whether the restore breaks the pending console read.
static int restore_test(uint32_t pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { std::printf("FAIL snapshot\n"); return 1; }
    THREADENTRY32 te{ sizeof(te) };
    DWORD tid = 0;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) { tid = te.th32ThreadID; break; }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (!tid) { std::printf("     FAIL no main thread\n"); return 1; }

    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                               THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                           FALSE, tid);
    if (!th) { std::printf("     FAIL open tid=%u gle=%lu\n", tid, GetLastError()); return 1; }

    SuspendThread(th);
    CONTEXT orig{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &orig);
    std::printf("[r] main thread tid=%u rip=0x%llX rsp=0x%llX\n", tid,
                (unsigned long long)orig.Rip, (unsigned long long)orig.Rsp);

    // dormant hijack: point it at a spin gadget in ntdll with the real
    // flow's RSP shift. The thread is blocked in a console read so this
    // never executes -- it sits in the saved context like the real attempt.
    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved_pref = reg::current_preference();
    std::uint64_t gadget = 0;
    if (reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
        voyager::device_t* dev = k ? k->device() : nullptr;
        if (dev) {
            dev->set_process_id(pid);
            const std::uint64_t dtb = dev->solve_dtb_for_pid(pid);
            if (dtb) {
                dev->set_dtb(dtb);
                const auto ntdll = slop::core::runtime::injector::find_module_base(
                    pid, "ntdll.dll");
                if (ntdll) {
                    std::vector<std::uint8_t> buf(0x10000);
                    for (std::uint64_t off = 0x1000; off < 0x180000 && !gadget;
                         off += 0x10000 - 2) {
                        if (dev->read_raw(*ntdll + off, buf.data(), buf.size()) != buf.size()) break;
                        for (std::size_t i = 0; i + 1 < buf.size(); ++i) {
                            if (buf[i] == 0xEB && buf[i + 1] == 0xFE) {
                                gadget = *ntdll + off + i;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    reg::set_backend_preference(saved_pref);
    if (!gadget) { std::printf("     FAIL no gadget\n"); CloseHandle(th); return 1; }

    CONTEXT hijacked = orig;
    hijacked.Rip = gadget;
    hijacked.Rsp = ((hijacked.Rsp - 0x108) & ~0xFULL) + 0x8;
    SetThreadContext(th, &hijacked);
    ResumeThread(th);
    std::printf("[r] dormant hijack set (rip=0x%llX rsp=0x%llX), waiting 2.5s\n",
                (unsigned long long)hijacked.Rip,
                (unsigned long long)hijacked.Rsp);
    Sleep(2500);

    // restore, exactly like the attempt-timeout path
    SuspendThread(th);
    CONTEXT cur{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &cur);
    std::printf("[r] before restore: rip=0x%llX rsp=0x%llX\n",
                (unsigned long long)cur.Rip, (unsigned long long)cur.Rsp);
    SetThreadContext(th, &orig);
    ResumeThread(th);
    CloseHandle(th);
    std::printf("[r] restored original context\n");

    for (int i = 0; i < 10; ++i) {
        Sleep(500);
        HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        DWORD ec = 0;
        const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
        if (alive) CloseHandle(alive);
        if (!live) {
            std::printf("[r] victim DIED %d ms after restore, exit=%lu\n",
                        (i + 1) * 500, ec);
            return 1;
        }
    }
    std::printf("[r] victim alive 5s after restore\n");
    return 0;
}

// run the REAL call_function against a cmd.exe victim (no self-waking
// threads, hijack stays dormant, process survives), then dump the ctx +
// shellcode bytes the driver planted so they can be checked against the
// expected emission.
static int rc_dump_test() {
    namespace reg = slop::core::runtime;
    // cmd.exe, not SlopTarget: we need a victim whose threads never wake
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[MAX_PATH] = {};
    GetSystemDirectoryA(cmd, MAX_PATH - 16);
    strcat_s(cmd, MAX_PATH, "\\cmd.exe");
    char* mutable_cmd = cmd;
    if (!CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        std::printf("[x] FAIL spawn cmd\n");
        return 1;
    }
    CloseHandle(pi.hThread);
    const uint32_t pid = pi.dwProcessId;
    Sleep(750);
    std::printf("[x] cmd pid=%u\n", pid);

    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("[x] FAIL backend\n");
        CloseHandle(pi.hProcess);
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) { reg::set_backend_preference(saved); CloseHandle(pi.hProcess); return 1; }

    auto gcpid = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "GetCurrentProcessId");
    if (!gcpid) { std::printf("[x] FAIL resolve\n"); reg::set_backend_preference(saved); CloseHandle(pi.hProcess); return 1; }

    const std::uint64_t r = dev->call_function(*gcpid);
    std::printf("[x] call -> 0x%llX (expected 0, dormant victim)\n",
                (unsigned long long)r);

    const std::uint64_t base = dev->get_shellcode_address_diag();
    std::printf("[x] shellcode base=0x%llX\n", (unsigned long long)base);
    if (base) {
        std::vector<std::uint8_t> mem(0x800);
        const std::size_t got = dev->read_raw(base, mem.data(), mem.size());
        std::printf("[x] read %zu bytes\n", got);
        for (std::size_t off = 0; off < got; off += 16) {
            std::printf("[x] +0x%03zX:", off);
            for (std::size_t j = 0; j < 16 && off + j < got; ++j)
                std::printf(" %02X", mem[off + j]);
            std::printf("\n");
        }
    }

    // verify the victim is still alive after all that
    DWORD ec = 0;
    GetExitCodeProcess(pi.hProcess, &ec);
    std::printf("[x] victim alive=%d exit=%lu\n",
                ec == STILL_ACTIVE ? 1 : 0, ec);
    reg::set_backend_preference(saved);
    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 3000);
    CloseHandle(pi.hProcess);
    return 0;
}

// exact real-flow sequence: plant ctx+shellcode, dormant-hijack the console
// main thread for one attempt window, restore, then hijack the ticker and
// let it run the call. Mirrors call_function's attempt 1 + attempt 2.
static int seq_test(uint32_t pid) {
    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("     FAIL backend\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) { reg::set_backend_preference(saved); return 1; }
    dev->set_process_id(pid);
    const std::uint64_t dtb = dev->solve_dtb_for_pid(pid);
    if (!dtb) { std::printf("     FAIL dtb\n"); reg::set_backend_preference(saved); return 1; }
    dev->set_dtb(dtb);

    auto gcpid = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "GetCurrentProcessId");
    if (!gcpid) { std::printf("     FAIL resolve\n"); reg::set_backend_preference(saved); return 1; }

    const std::uint64_t base = dev->allocate_memory(0x2000);
    if (!base) { std::printf("     FAIL alloc\n"); reg::set_backend_preference(saved); return 1; }

    struct ctx_t {
        std::uint64_t target_func, spoof_gadget, param1, param2, param3, param4;
        std::uint64_t ret_value, saved_rsp, original_rip, rbx_backup, exec_done;
        std::uint64_t trampoline, stack_backup[8];
    };
    ctx_t ctx{};
    ctx.target_func = *gcpid;
    ctx.trampoline  = base + 0x600;
    dev->write_raw(base, &ctx, sizeof(ctx));
    uint8_t code[256] = {};
    const size_t code_len = emit_direct_call(code, base, 6);
    dev->write_raw(base + 0x200, code, code_len);
    std::printf("[q] planted %zu-byte shellcode @ 0x%llX\n",
                code_len, (unsigned long long)(base + 0x200));

    // thread inventory in creation order
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) { std::printf("FAIL snapshot\n"); reg::set_backend_preference(saved); return 1; }
    THREADENTRY32 te{ sizeof(te) };
    std::vector<DWORD> tids;
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    if (tids.size() < 2) { std::printf("     FAIL need 2 threads\n"); reg::set_backend_preference(saved); return 1; }

    // ---- attempt 1: dormant hijack of the main thread ----
    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                               THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                           FALSE, tids[0]);
    SuspendThread(th);
    CONTEXT o1{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &o1);
    CONTEXT h1 = o1;
    h1.Rip = base + 0x200;
    h1.Rsp = ((h1.Rsp - 0x108) & ~0xFULL) + 0x8;
    SetThreadContext(th, &h1);
    ResumeThread(th);
    CloseHandle(th);
    std::printf("[q] attempt1: dormant hijack of main tid=%u, waiting 2.5s\n", tids[0]);
    Sleep(2500);
    th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_SET_CONTEXT, FALSE, tids[0]);
    SuspendThread(th);
    SetThreadContext(th, &o1);
    ResumeThread(th);
    CloseHandle(th);
    std::printf("[q] attempt1: restored main\n");

    // ---- attempt 2: hijack the ticker, let it run ----
    th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                        THREAD_SET_CONTEXT | THREAD_QUERY_INFORMATION,
                    FALSE, tids[1]);
    SuspendThread(th);
    CONTEXT o2{ .ContextFlags = CONTEXT_FULL };
    GetThreadContext(th, &o2);
    CONTEXT h2 = o2;
    h2.Rip = base + 0x200;
    h2.Rsp = ((h2.Rsp - 0x108) & ~0xFULL) + 0x8;
    SetThreadContext(th, &h2);
    ResumeThread(th);
    CloseHandle(th);
    std::printf("[q] attempt2: hijacked ticker tid=%u rip=0x%llX rsp=0x%llX\n",
                tids[1], (unsigned long long)h2.Rip, (unsigned long long)h2.Rsp);

    std::uint64_t done = 0, ret = 0;
    for (int i = 0; i < 40; ++i) {
        done = dev->read<std::uint64_t>(base + 0x50);
        ret = dev->read<std::uint64_t>(base + 0x30);
        if (done) break;
        Sleep(100);
    }
    std::printf("[q] exec_done=0x%llX ret=0x%llX (expected pid=%u)\n",
                (unsigned long long)done, (unsigned long long)ret, pid);

    if (done) {
        th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                            THREAD_SET_CONTEXT,
                        FALSE, tids[1]);
        SuspendThread(th);
        CONTEXT cur{ .ContextFlags = CONTEXT_FULL };
        GetThreadContext(th, &cur);
        cur.Rip = o2.Rip;
        cur.Rsp = o2.Rsp;
        SetThreadContext(th, &cur);
        ResumeThread(th);
        CloseHandle(th);
        std::printf("[q] ticker restored\n");
    }

    HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD ec = 0;
    const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
    if (alive) CloseHandle(alive);
    std::printf("[q] victim alive=%d exit=%lu\n", live ? 1 : 0, ec);
    dev->free_memory(base);
    reg::set_backend_preference(saved);
    return (live && done && ret == pid) ? 0 : 1;
}

// LoadLibraryW through the remote-call primitive: write the path into the
// target, call it, then check whether the module actually landed in the
// target's LDR and whether the fixture DllMain's marker file appeared --
// distinguishes "call ran, return capture broken" from "call genuinely
// failed inside the target".
static int loadlib_test() {
    char self[MAX_PATH] = {};
    if (!GetModuleFileNameA(nullptr, self, MAX_PATH)) return 1;
    char* slash = strrchr(self, '\\');
    if (!slash) return 1;
    *slash = '\0';
    char src[MAX_PATH] = {};
    _snprintf_s(src, MAX_PATH, _TRUNCATE, "%s\\..\\tests\\slop_inject_fixture.dll", self);
    char temp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp);
    char staged[MAX_PATH] = {};
    _snprintf_s(staged, MAX_PATH, _TRUNCATE, "%sslop_probe_fixture.dll", temp);
    if (!CopyFileA(src, staged, FALSE)) {
        std::printf("[l] FAIL stage fixture gle=%lu\n", GetLastError());
        return 1;
    }

    HANDLE proc = nullptr;
    const uint32_t pid = spawn_cmd(&proc);
    if (!pid) { std::printf("[l] FAIL spawn\n"); return 1; }
    std::printf("[l] victim pid=%u staged=%s\n", pid, staged);

    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("[l] FAIL backend\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;

    // clear any stale marker
    char mpath[MAX_PATH] = {};
    _snprintf_s(mpath, MAX_PATH, _TRUNCATE, "%sslop_inject_marker_%u.bin", temp, pid);
    DeleteFileA(mpath);

    int rc = 1;
    const auto llw = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "LoadLibraryW");
    if (!llw) {
        std::printf("[l] FAIL resolve LoadLibraryW\n");
    } else {
        const std::wstring wpath(staged, staged + strlen(staged));
        const size_t bytes = (wpath.size() + 1) * sizeof(wchar_t);
        const std::uint64_t buf = dev->allocate_memory(bytes);
        std::printf("[l] path buf @ 0x%llX (%zu bytes)\n",
                    (unsigned long long)buf, bytes);
        if (dev->write_raw(buf, wpath.c_str(), bytes) == bytes) {
            const ULONGLONG t0 = GetTickCount64();
            const std::uint64_t r = dev->call_function(*llw, buf);
            std::printf("[l] LoadLibraryW -> 0x%llX (%llu ms)\n",
                        (unsigned long long)r,
                        (unsigned long long)(GetTickCount64() - t0));

            // did the module land in the LDR?
            const auto base = slop::core::runtime::injector::find_module_base(
                pid, "slop_probe_fixture.dll");
            std::printf("[l] module in LDR: %s\n",
                        base ? "YES" : "NO");

            // did DllMain run (marker file)?
            HANDLE mf = CreateFileA(mpath, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
            if (mf != INVALID_HANDLE_VALUE) {
                std::printf("[l] DllMain marker: PRESENT\n");
                CloseHandle(mf);
            } else {
                std::printf("[l] DllMain marker: absent\n");
            }
            rc = (r != 0 && base) ? 0 : 1;
        } else {
            std::printf("[l] FAIL write path\n");
        }
    }
    reg::set_backend_preference(saved);
    if (proc) CloseHandle(proc);
    kill_pid(pid);
    DeleteFileA(staged);
    DeleteFileA(mpath);
    return rc;
}

// replicate the injector's exact loadlibrary flow, then harvest every
// thread's LastErrorValue from the victim's TEBs through the driver --
// names the actual LoadLibraryW failure inside the target.
static int loadlib_err_test() {
    char temp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp);
    char src[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, src, MAX_PATH);
    char* slash = strrchr(src, '\\');
    if (slash) {
        *slash = '\0';
        strcat_s(src, MAX_PATH, "\\..\\tests\\slop_inject_fixture.dll");
    }
    char staged[MAX_PATH] = {};
    _snprintf_s(staged, MAX_PATH, _TRUNCATE, "%sslop_inject_fixture_%u.dll",
                temp, GetCurrentProcessId());
    if (!CopyFileA(src, staged, FALSE)) {
        std::printf("[e] FAIL stage gle=%lu\n", GetLastError());
        return 1;
    }

    HANDLE proc = nullptr;
    const uint32_t pid = spawn_cmd(&proc);
    if (!pid) { std::printf("[e] FAIL spawn\n"); return 1; }
    std::printf("[e] victim pid=%u staged=%s\n", pid, staged);

    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("[e] FAIL backend\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;

    char mpath[MAX_PATH] = {};
    _snprintf_s(mpath, MAX_PATH, _TRUNCATE, "%sslop_inject_marker_%u.bin", temp, pid);
    DeleteFileA(mpath);

    int rc = 1;
    const auto llw = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "LoadLibraryW");
    if (!llw) {
        std::printf("[e] FAIL resolve\n");
    } else {
        const std::wstring wpath(staged, staged + strlen(staged));
        const size_t bytes = (wpath.size() + 1) * sizeof(wchar_t);
        const std::uint64_t buf = dev->allocate_memory(bytes);
        if (dev->write_raw(buf, wpath.c_str(), bytes) == bytes) {
            const ULONGLONG t0 = GetTickCount64();
            const std::uint64_t r = dev->call_function(*llw, buf);
            std::printf("[e] LoadLibraryW -> 0x%llX (%llu ms)\n",
                        (unsigned long long)r,
                        (unsigned long long)(GetTickCount64() - t0));

            const auto base = slop::core::runtime::injector::find_module_base(
                pid, "slop_inject_fixture.dll");
            std::printf("[e] module in LDR: %s\n", base ? "YES" : "NO");
            HANDLE mf = CreateFileA(mpath, GENERIC_READ, FILE_SHARE_READ,
                                    nullptr, OPEN_EXISTING, 0, nullptr);
            std::printf("[e] DllMain marker: %s\n",
                        mf != INVALID_HANDLE_VALUE ? "PRESENT" : "absent");
            if (mf != INVALID_HANDLE_VALUE) CloseHandle(mf);
            rc = (r != 0 && base) ? 0 : 1;
        } else {
            std::printf("[e] FAIL write path\n");
        }
    }
    reg::set_backend_preference(saved);
    if (proc) CloseHandle(proc);
    kill_pid(pid);
    DeleteFileA(staged);
    DeleteFileA(mpath);
    return rc;
}

// remote-call primitive check: GetCurrentProcessId in the target must come
// back as the target pid, GetTickCount as a plausible tick. Optionally
// raises the driver log level so RC7781/RC7782 land in slop_kernel.log.
static int call_test(uint32_t pid, int log_level, bool do_call,
                     HANDLE proc_handle = nullptr) {
    namespace reg = slop::core::runtime;
    reg::registry_init();
    const reg::backend_pref_t saved = reg::current_preference();
    if (!reg::set_backend_preference(reg::backend_pref_t::force_kernel)) {
        std::printf("     FAIL kernel backend not activatable\n");
        return 1;
    }
    auto* k = dynamic_cast<reg::backend_kernel_t*>(&reg::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) {
        std::printf("     FAIL no kernel device\n");
        reg::set_backend_preference(saved);
        return 1;
    }

    if (log_level > 0) {
        voyager::device_t::log_config cfg{};
        cfg.level = static_cast<std::uint32_t>(log_level);
        cfg.cap_mb = 64;
        const bool applied = dev->log_config_op(cfg, true);
        std::printf("[c] log level -> %u applied=%d\n", cfg.level, applied ? 1 : 0);
    }

    if (!do_call) {
        // control: no call at all, just sit here for 5s
        Sleep(5000);
        HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        DWORD ec = 0;
        const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
        if (alive) CloseHandle(alive);
        std::printf("[c] control (no call): alive=%d exit_code=%lu\n", live ? 1 : 0, ec);
        reg::set_backend_preference(saved);
        return live ? 0 : 1;
    }

    const ULONGLONG t0 = GetTickCount64();

    auto gcpid = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "GetCurrentProcessId");
    if (!gcpid) {
        std::printf("     FAIL resolve GetCurrentProcessId\n");
        reg::set_backend_preference(saved);
        return 1;
    }
    std::printf("[c] kernel32!GetCurrentProcessId @ 0x%llX\n",
                static_cast<unsigned long long>(*gcpid));

    auto gtick = slop::core::runtime::injector::resolve_export(
        pid, "kernel32.dll", "GetTickCount");

    const std::uint64_t r_pid = dev->call_function(*gcpid);
    const ULONGLONG dt1 = GetTickCount64() - t0;
    std::printf("[c] call GetCurrentProcessId -> 0x%llX (%llu ms) expected pid=%u %s\n",
                static_cast<unsigned long long>(r_pid),
                static_cast<unsigned long long>(dt1), pid,
                r_pid == pid ? "MATCH" : "MISMATCH");

    // dump the remote-call diag ring: selected threads, hijack rips, poll
    // outcomes -- the play-by-play of what call_function actually did
    {
        auto snap = slop::core::infra::diag::snapshot();
        std::printf("[c] --- diag ring (%zu entries) ---\n",
                    snap.entries.size());
        for (const auto& e : snap.entries) {
            if (e.tag != "comm") continue;
            if (e.message.rfind("remote_call_um_poll_ioctl", 0) == 0) continue;
            if (e.message.rfind("remote_call_um_poll_progress", 0) == 0) continue;
            std::printf("[c] %s\n", e.message.c_str());
        }
    }

    // post-mortem: is the target still alive and are its pages still
    // readable through the physical path? distinguishes "call crashed the
    // process" from "CR-poll path is broken"
    if (proc_handle) {
        WaitForSingleObject(proc_handle, 2000);
        DWORD ec2 = 0;
        GetExitCodeProcess(proc_handle, &ec2);
        std::printf("[d] exit code via kept handle: 0x%lX (%lu)\n", ec2, ec2);
    }
    {
        HANDLE alive = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        DWORD ec = 0;
        const bool live = alive && GetExitCodeProcess(alive, &ec) && ec == STILL_ACTIVE;
        if (alive) CloseHandle(alive);
        std::printf("[d] target alive=%d exit_code=%lu\n", live ? 1 : 0, ec);

        const auto k32b = slop::core::runtime::injector::find_module_base(
            pid, "kernel32.dll");
        if (k32b) {
            std::uint8_t mz[2] = {};
            const std::size_t got = dev->read_raw(*k32b, mz, sizeof(mz));
            std::printf("[d] post-call kernel32 MZ read: got=%zu %02X%02X\n",
                        got, mz[0], mz[1]);
        } else {
            std::printf("[d] post-call kernel32 LDR walk FAILED\n");
        }
    }

    std::uint64_t r_tick = 0;
    if (gtick) {
        const ULONGLONG t1 = GetTickCount64();
        r_tick = dev->call_function(*gtick);
        const ULONGLONG dt2 = GetTickCount64() - t1;
        std::printf("[c] call GetTickCount -> 0x%llX (%llu ms) %s\n",
                    static_cast<unsigned long long>(r_tick),
                    static_cast<unsigned long long>(dt2),
                    (r_tick != 0 && r_tick < 0xFFFFFFFFull) ? "PLAUSIBLE" : "BAD");
    }

    if (log_level > 0) {
        voyager::device_t::log_config cfg{};
        cfg.level = 1;
        dev->log_config_op(cfg, true);
    }

    const bool ok = r_pid == pid && r_tick != 0;
    reg::set_backend_preference(saved);
    std::printf("%s\n", ok ? "=== CALL TEST PASS ===" : "=== CALL TEST FAIL ===");
    return ok ? 0 : 1;
}

int main(int argc, char** argv) {
    setvbuf(stdout, nullptr, _IONBF, 0);
    const char* targetName = argc > 1 ? argv[1] : "SlopTarget.exe";

    // shellcode-in-driver-page test: our own physical writes + hijack
    // exact attempt-1 + attempt-2 sequence replication:
    //   probe_kernel --seq-test
    if (argc >= 2 && std::strcmp(argv[1], "--seq-test") == 0) {
        const uint32_t pid = spawn_cmd();
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        std::printf("[q] spawned pid=%u\n", pid);
        const int rc = seq_test(pid);
        kill_pid(pid);
        return rc;
    }

    // injector-flow replication with the test's exact staging name:
    //   probe_kernel --loadlib-err
    if (argc >= 2 && std::strcmp(argv[1], "--loadlib-err") == 0) {
        return loadlib_err_test();
    }

    // LoadLibraryW through the primitive against a fresh victim:
    //   probe_kernel --loadlib-test
    if (argc >= 2 && std::strcmp(argv[1], "--loadlib-test") == 0) {
        return loadlib_test();
    }

    // dump the driver-planted shellcode from a dormant cmd.exe victim:
    //   probe_kernel --rc-dump
    if (argc >= 2 && std::strcmp(argv[1], "--rc-dump") == 0) {
        return rc_dump_test();
    }

    // dormant-hijack + restore of the console main thread:
    //   probe_kernel --restore-test
    if (argc >= 2 && std::strcmp(argv[1], "--restore-test") == 0) {
        const uint32_t pid = spawn_cmd();
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        std::printf("[r] spawned pid=%u\n", pid);
        const int rc = restore_test(pid);
        kill_pid(pid);
        return rc;
    }

    //   probe_kernel --shell-test <stages 0-6>
    if (argc >= 2 && std::strcmp(argv[1], "--shell-test") == 0) {
        const int stages = (argc > 2) ? std::atoi(argv[2]) : 0;
        const uint32_t pid = spawn_cmd();
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        std::printf("[h] spawned pid=%u\n", pid);
        const int tidx = (argc > 3) ? std::atoi(argv[3]) : 1;
        const int rc = shell_test(pid, stages, tidx);
        kill_pid(pid);
        return rc;
    }

    // debugged-victim call test: captures the crash as a debug event
    //   probe_kernel --call-test-debug
    if (argc >= 2 && std::strcmp(argv[1], "--call-test-debug") == 0) {
        return call_test_debug();
    }

    // spin-gadget hijack bisection on a fresh victim:
    //   probe_kernel --spin-test [shift-rsp] [thread-index]
    if (argc >= 2 && std::strcmp(argv[1], "--spin-test") == 0) {
        const bool shift = (argc > 2 && std::strcmp(argv[2], "shift-rsp") == 0);
        const int tidx = (argc > 3) ? std::atoi(argv[3]) : 0;
        const uint32_t pid = spawn_cmd();
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        std::printf("[p] spawned pid=%u thread_index=%d\n", pid, tidx);
        const int rc = spin_test(pid, shift, tidx);
        kill_pid(pid);
        return rc;
    }

    // suspend/set-same/resume isolation on a fresh victim:
    //   probe_kernel --sus-test
    if (argc >= 2 && std::strcmp(argv[1], "--sus-test") == 0) {
        const uint32_t pid = spawn_cmd();
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        std::printf("[s] spawned pid=%u\n", pid);
        const int rc = suspend_test(pid);
        kill_pid(pid);
        return rc;
    }

    // remote-call primitive check on a fresh sacrificial victim:
    //   probe_kernel --call-test [driver-log-level] [--no-call]
    if (argc >= 2 && std::strcmp(argv[1], "--call-test") == 0) {
        voyager::device_t dev;
        if (!dev.connect()) { std::printf("FAIL connect\n"); return 1; }
        dev.disconnect();
        int argi = 2;
        int lvl = 0;
        if (argi < argc && argv[argi][0] >= '0' && argv[argi][0] <= '9') {
            lvl = std::atoi(argv[argi++]);
        }
        bool do_call = true;
        if (argi < argc && std::strcmp(argv[argi], "--no-call") == 0) {
            do_call = false;
            ++argi;
        }
        HANDLE proc = nullptr;
        const uint32_t pid = spawn_cmd(&proc);
        if (!pid) { std::printf("FAIL spawn victim\n"); return 1; }
        char victim[MAX_PATH] = {};
        {
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (h) {
                GetModuleFileNameExA(h, nullptr, victim, MAX_PATH);
                CloseHandle(h);
            }
        }
        std::printf("[c] spawned pid=%u victim=%s\n", pid,
                    victim[0] ? victim : "?");
        const int rc = call_test(pid, lvl, do_call, proc);
        if (proc) CloseHandle(proc);
        kill_pid(pid);
        return rc;
    }


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
