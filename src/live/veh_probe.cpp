// VEH injection probe: replicates debugger_t::kattach standalone
// standalone copy of the debugger veh attach for poking at the injection
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>

#include "core/runtime/voyager_comm.h"

// page layout (mirror of veh_stub.hpp)
constexpr uint64_t kGlobalsOff  = 0x0400;   // +0x00 sleep_fn, +0x08 veh_handle
constexpr uint64_t kSlotsOff    = 0x0480;
constexpr uint64_t kSlotStride  = 0x0540;
constexpr int      kSlotCount   = 4;
constexpr uint64_t kContextOff  = 0x40;
constexpr uint64_t kContextSize = 0x4D0;
constexpr uint64_t kCmdOff      = 0x510;
constexpr uint64_t kCaptureOff  = 0x03E0;
constexpr uint64_t kStackTop    = 0x1F08;

extern const uint8_t kVehStub[400];

// generated stub (same bytes as the app's veh_stub.hpp)
#include "veh_stub_bytes.inc"

int main(int argc, char** argv) {
    if (argc < 2) { printf("usage: veh_probe.exe <pid>\n"); return 1; }
    const uint32_t pid = static_cast<uint32_t>(strtoul(argv[1], nullptr, 0));

    voyager::device_t dev;
    if (!dev.connect()) { printf("FAIL connect\n"); return 1; }
    dev.set_process_id(pid);
    const uint64_t dtb = dev.solve_dtb_for_pid(pid);
    if (!dtb) { printf("FAIL dtb solve\n"); return 1; }
    dev.set_dtb(dtb);
    printf("[1] dev ready pid=%u dtb=%llx\n", pid, (unsigned long long)dtb);

    const uint64_t page = dev.allocate_memory(0x2000);
    if (!page) { printf("FAIL alloc\n"); return 1; }
    printf("[2] page = %llx\n", (unsigned long long)page);

    std::vector<uint8_t> zeros(0x2000, 0);
    if (dev.write_raw(page, zeros.data(), zeros.size()) != 0x2000) { printf("FAIL zero\n"); return 1; }
    if (dev.write_raw(page, kVehStub, sizeof(kVehStub)) != sizeof(kVehStub)) { printf("FAIL stub write\n"); return 1; }
    printf("[3] stub written (%zu bytes)\n", sizeof(kVehStub));

    // verify stub bytes read back
    uint8_t check[8] = {};
    dev.read_raw(page, check, 8);
    printf("[4] stub readback: %02x %02x %02x %02x %02x %02x %02x %02x\n",
           check[0], check[1], check[2], check[3], check[4], check[5], check[6], check[7]);

    // module walk for ntdll + kernel32
    uint64_t ntdll = 0, kernel32 = 0;
    {
        voyager::device_t::peb_info peb{};
        if (!dev.read_peb(peb) || !peb.ldr_address) { printf("FAIL read_peb\n"); return 1; }
        uint64_t cur = 0;
        if (dev.read_raw(peb.ldr_address + 0x10, &cur, 8) != 8) { printf("FAIL ldr\n"); return 1; }
        int iter = 0;
        while (cur && cur != peb.ldr_address + 0x10 && iter++ < 1024) {
            const uint64_t base = dev.read<uint64_t>(cur + 0x30);
            // BaseDllName: length (bytes) @+0x58, buffer @+0x60
            const uint16_t nlen = dev.read<uint16_t>(cur + 0x58) / 2;
            char name[64] = {};
            if (nlen && nlen < 60) {
                std::vector<uint8_t> raw(size_t(nlen) * 2, 0);
                const uint64_t nbuf = dev.read<uint64_t>(cur + 0x60);
                if (nbuf && dev.read_raw(nbuf, raw.data(), raw.size()) == raw.size()) {
                    WideCharToMultiByte(CP_UTF8, 0, (LPCWCH)raw.data(), nlen,
                                        name, sizeof(name), nullptr, nullptr);
                }
            }
            printf("    module: %s @ %llx\n", name, (unsigned long long)base);
            if (_stricmp(name, "ntdll.dll") == 0) ntdll = base;
            if (_stricmp(name, "kernel32.dll") == 0) kernel32 = base;
            const uint64_t next = dev.read<uint64_t>(cur);
            if (next == cur) break;
            cur = next;
        }
    }
    if (!ntdll || !kernel32) { printf("FAIL modules ntdll=%llx kernel32=%llx\n",
                                      (unsigned long long)ntdll, (unsigned long long)kernel32); return 1; }

    const uint64_t p_sleep  = dev.resolve_export(kernel32, "Sleep");
    const uint64_t p_add    = dev.resolve_export(ntdll, "RtlAddVectoredExceptionHandler");
    const uint64_t p_remove = dev.resolve_export(ntdll, "RtlRemoveVectoredExceptionHandler");
    printf("[5] sleep=%llx add=%llx remove=%llx\n",
           (unsigned long long)p_sleep, (unsigned long long)p_add, (unsigned long long)p_remove);
    if (!p_sleep || !p_add || !p_remove) { printf("FAIL exports\n"); return 1; }

    if (dev.write_raw(page + kGlobalsOff, &p_sleep, 8) != 8) { printf("FAIL sleep write\n"); return 1; }

    // capture stub
    const uint64_t capture = page + kCaptureOff;
    {
        const int32_t disp = static_cast<int32_t>(kGlobalsOff + 8 - (kCaptureOff + 7));
        const uint8_t cap_code[] = {0x48, 0x89, 0x05,
                                    (uint8_t)(disp & 0xFF), (uint8_t)((disp >> 8) & 0xFF),
                                    (uint8_t)((disp >> 16) & 0xFF), (uint8_t)((disp >> 24) & 0xFF),
                                    0xEB, 0xFE};
        dev.write_raw(capture, cap_code, sizeof(cap_code));
        dev.write_raw(page + kStackTop, &capture, 8);
    }

    // hijack: try each thread
    constexpr uint64_t kGprMask = (1ull << 18) - 1;
    uint64_t handle = 0;
    uint32_t used_tid = 0;
    for (const auto& t : dev.enumerate_threads()) {
        const uint32_t tid = t.tid;
        if (!tid) continue;
        printf("[6] trying tid=%u (rip=%llx)\n", tid, (unsigned long long)t.rip);
        if (!dev.suspend_thread(tid)) { printf("    suspend failed\n"); continue; }
        voyager::device_t::thread_context orig{};
        if (!dev.get_thread_context(tid, orig)) { printf("    getctx failed\n"); dev.resume_thread(tid); continue; }
        printf("    orig rip=%llx rsp=%llx\n", (unsigned long long)orig.rip, (unsigned long long)orig.rsp);
        voyager::device_t::thread_context call_ctx = orig;
        call_ctx.rip = p_add;
        call_ctx.rcx = 1;
        call_ctx.rdx = page;
        call_ctx.rsp = page + kStackTop;
        if (!dev.set_thread_context(tid, call_ctx, kGprMask)) { printf("    setctx failed\n"); dev.resume_thread(tid); continue; }
        dev.resume_thread(tid);
        PostThreadMessageW(tid, 0, 0, 0);
        for (int i = 0; i < 2400 && handle == 0; ++i) {  // 12 s
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            dev.read_raw(page + kGlobalsOff + 8, &handle, 8);
        }
        dev.suspend_thread(tid);
        dev.set_thread_context(tid, orig, kGprMask);
        dev.resume_thread(tid);
        if (handle) { used_tid = tid; break; }
    }

    printf("[7] veh handle = %llx (tid %u)\n", (unsigned long long)handle, used_tid);
    if (!handle) { printf("FAIL hijack\n"); dev.free_memory(page); return 1; }

    // park test: wait for the target to fault (its own int3 or Sleep-driven)
    // Re-solve the dtb after the hijack: discriminates a stale device-side
    // dtb from broken driver state
    {
        const uint64_t dtb2 = dev.solve_dtb_for_pid(pid);
        printf("[7b] re-solve dtb: %llx (was %llx)\n", (unsigned long long)dtb2, (unsigned long long)dtb);
        if (dtb2) dev.set_dtb(dtb2);
        uint32_t mz0 = 0;
        const size_t g = dev.read_raw(ntdll, &mz0, 4);
        printf("[7c] mz after re-solve: %08x(%zu)\n", mz0, g);
        fflush(stdout);
    }
    printf("[8] polling slots for 15 s...\n");
    for (int s = 0; s < 15; ++s) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        uint32_t mz = 0;
        const size_t mz_got = dev.read_raw(ntdll, &mz, 4);
        uint8_t all_states[kSlotCount] = {};
        for (int i = 0; i < kSlotCount; ++i) {
            const uint64_t slot = page + kSlotsOff + i * kSlotStride;
            uint8_t hdr[0x40] = {};
            dev.read_raw(slot, hdr, 0x40);
            all_states[i] = hdr[0];
            if (hdr[0] == 1) {
                uint64_t tid2 = 0, code = 0, addr = 0;
                memcpy(&tid2, hdr + 0x10, 8);
                memcpy(&code, hdr + 0x18, 8);
                memcpy(&addr, hdr + 0x20, 8);
                printf("    HIT slot %d: tid=%llu code=%llx addr=%llx\n",
                       i, (unsigned long long)tid2, (unsigned long long)code,
                       (unsigned long long)addr);
                // release with continue
                const uint64_t cmd = 1;
                dev.write_raw(slot + kCmdOff, &cmd, 8);
            }
        }
        printf("    poll %2d: mz=%08x(%zu) states=%u,%u,%u,%u\n", s, mz, mz_got,
               all_states[0], all_states[1], all_states[2], all_states[3]);
        fflush(stdout);
    }

    // detach: remove VEH + free page
    {
        const int32_t disp = static_cast<int32_t>(kGlobalsOff + 8 - (kCaptureOff + 7));
        const uint8_t cap_code[] = {0x48, 0x89, 0x05,
                                    (uint8_t)(disp & 0xFF), (uint8_t)((disp >> 8) & 0xFF),
                                    (uint8_t)((disp >> 16) & 0xFF), (uint8_t)((disp >> 24) & 0xFF),
                                    0xEB, 0xFE};
        uint64_t zero = 0;
        dev.write_raw(page + kGlobalsOff + 8, &zero, 8);
        dev.write_raw(capture, cap_code, sizeof(cap_code));
        dev.write_raw(page + kStackTop, &capture, 8);
        for (const auto& t : dev.enumerate_threads()) {
            if (!t.tid) continue;
            if (!dev.suspend_thread(t.tid)) continue;
            voyager::device_t::thread_context orig{};
            if (!dev.get_thread_context(t.tid, orig)) { dev.resume_thread(t.tid); continue; }
            voyager::device_t::thread_context call_ctx = orig;
            call_ctx.rip = p_remove;
            call_ctx.rcx = handle;
            call_ctx.rsp = page + kStackTop;
            if (dev.set_thread_context(t.tid, call_ctx, kGprMask)) {
                dev.resume_thread(t.tid);
                uint64_t done = 0;
                for (int i = 0; i < 100 && done == 0; ++i) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(5));
                    dev.read_raw(page + kGlobalsOff + 8, &done, 8);
                }
                dev.suspend_thread(t.tid);
                dev.set_thread_context(t.tid, orig, kGprMask);
                dev.resume_thread(t.tid);
                if (done) { printf("[9] VEH removed (result %llx)\n", (unsigned long long)done); break; }
            } else {
                dev.resume_thread(t.tid);
            }
        }
    }
    dev.free_memory(page);
    printf("[10] done\n");
    return 0;
}
