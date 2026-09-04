// src/tests/test_driver.cpp
// Live slopdrvr kernel-driver test suite. Runs the real IOCTL surface
// against the loaded driver (mapper-loaded or service-loaded, both speak
// \\.\slopdrvr). Every test degrades to a printed skip when the driver is
// absent so CI without test-signing stays green; with the driver resident
// this exercises the paths the kernel AC workflows ride on: connect,
// identity, log control, DTB solve, physical R/W, alloc/free, thread
// control, PEB/SSDT/V2P queries, sandbox gating, debug-event drain, and
// the network enumeration surface.

#include "harness.hpp"

#include "core/runtime/voyager_comm.h"
#include "core/runtime/kernel_service.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwctype>
#include <functional>
#include <string>
#include <thread>
#include <vector>

namespace {

using voyager::device_t;
namespace kernel_svc = slop::core::runtime::kernel_svc;

// One shared device for the ordering-sensitive lifecycle tests, refreshed
// lazily. Tests that mutate connection state build their own device_t.
device_t& shared_device() {
    static device_t dev;
    return dev;
}

bool driver_loaded() {
    return shared_device().connect();
}

// Find the test target or any stable sacrificial process (our own spawn).
uint32_t spawn_helper() {
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[MAX_PATH] = {};
    GetSystemDirectoryA(cmd, MAX_PATH - 64);
    std::strcat(cmd, "\\cmd.exe");
    char* mutable_cmd = cmd;
    if (!CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        return 0;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return pi.dwProcessId;
}

void kill_helper(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        WaitForSingleObject(h, 5000);
        CloseHandle(h);
    }
}

std::vector<uint32_t> process_threads(uint32_t pid) {
    std::vector<uint32_t> tids;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return tids;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid)
                tids.push_back(te.th32ThreadID);
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return tids;
}

} // namespace

// ---------------------------------------------------------------------------
// Connection + identity + lifecycle
// ---------------------------------------------------------------------------

TEST_CASE(driver_connect_reports_stable_state) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    REQUIRE(dev.is_connected());
    // Second connect is idempotent, keeps the handle
    REQUIRE(dev.connect());
    REQUIRE(dev.is_connected());
    REQUIRE(dev.get_last_connect_error() == 0);
}

TEST_CASE(driver_ident_reports_version_and_service_path) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    device_t::driver_identity ident{};
    if (!dev.query_driver_identity(ident)) {
        // Mapper/exploit loads carry no registry identity: the call must
        // FAIL cleanly, never return fake success with a garbage path
        // (the old 260-NUL clamp bug)
        std::printf("  no service identity (mapped load) - clean failure\n");
        return;
    }
    REQUIRE_EQ(ident.driver_version, 1u);
    REQUIRE_FALSE(ident.unloading);
    // A captured identity must be a printable registry path with no
    // embedded NULs
    std::string narrow;
    narrow.reserve(ident.service_path.size());
    for (wchar_t c : ident.service_path) {
        REQUIRE_NE(c, L'\0');
        narrow.push_back(static_cast<char>(c));
    }
    REQUIRE_FALSE(narrow.empty());
    std::string lower = narrow;
    for (auto& c : lower)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    REQUIRE(lower.rfind("\\registry\\", 0) == 0);
    std::printf("  service path: %s\n", narrow.c_str());
}

TEST_CASE(driver_logctl_query_and_roundtrip) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();

    // Pure query (magic 0)
    device_t::log_config cfg{};
    REQUIRE(dev.log_config_op(cfg, false));
    const uint32_t original_level = cfg.level;
    std::printf("  log level=%u cap=%u MB\n", cfg.level, cfg.cap_mb);

    // Apply an in-range level, read back, then restore. Cap 0 keeps current.
    device_t::log_config set{};
    set.level = (original_level == 2) ? 3u : 2u;
    set.cap_mb = 0;
    REQUIRE(dev.log_config_op(set, true));
    REQUIRE_EQ(set.level, ((original_level == 2) ? 3u : 2u));
    // And the query path agrees with the applied state
    device_t::log_config verify{};
    REQUIRE(dev.log_config_op(verify, false));
    REQUIRE_EQ(verify.level, set.level);

    // Out-of-range level (5) is rejected without state change
    device_t::log_config bad{};
    bad.level = 5;
    bad.cap_mb = 0;
    REQUIRE_FALSE(dev.log_config_op(bad, true));

    // Restore original level
    device_t::log_config restore{};
    restore.level = original_level;
    restore.cap_mb = 0;
    REQUIRE(dev.log_config_op(restore, true));
}

TEST_CASE(driver_send_ioctl_rejects_null_buffer_and_disconnected) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // Null buffer / zero size are client-side rejects: ERROR_INVALID_PARAMETER.
    // The GLE is checked through the device's own telemetry because the
    // telemetry logging itself may touch Win32 and clobber thread-local GLE.
    device_t& dev = shared_device();
    uint32_t br = 0;
    REQUIRE_FALSE(dev.send_ioctl_raw(ioctl_codes::IDENT(), nullptr, 0, br));
    REQUIRE_EQ(dev.get_last_raw_ioctl_telemetry().gle,
               static_cast<std::uint32_t>(ERROR_INVALID_PARAMETER));

    // A never-connected device rejects with ERROR_INVALID_HANDLE. It must
    // not attempt any IRP_MJ_CREATE/CREATE-close churn on the live device —
    // a connect+disconnect here used to unregister the client pid and wedge
    // every later ioctl once a sandbox entry existed (driver refcount fix)
    device_t never_connected;
    REQUIRE_FALSE(never_connected.is_connected());
    voyager::detail::ident_request probe{};
    REQUIRE_FALSE(never_connected.send_ioctl_raw(ioctl_codes::IDENT(), &probe,
                                                 sizeof(probe), br));
    REQUIRE_EQ(never_connected.get_last_raw_ioctl_telemetry().gle,
               static_cast<std::uint32_t>(ERROR_INVALID_HANDLE));
}

TEST_CASE(driver_unknown_ioctl_returns_invalid_device_request) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    uint32_t br = 0;
    // Valid shape, code nothing dispatches (offset 0x7F7 far past LOGCTL)
    const DWORD bogus = 0x00220000u | ((0x800u + 0x7F7u) << 2);
    voyager::detail::ident_request probe{};
    REQUIRE_FALSE(dev.send_ioctl_raw(bogus, &probe, sizeof(probe), br));
}

// ---------------------------------------------------------------------------
// DTB solve + physical memory
// ---------------------------------------------------------------------------

TEST_CASE(driver_solves_self_dtb_and_kernel_dtb) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    const uint32_t self_pid = GetCurrentProcessId();

    const uint64_t dtb = dev.solve_dtb_for_pid(self_pid);
    REQUIRE(dtb != 0);
    REQUIRE_EQ(dtb & 0xFFF, 0u);   // CR3 is page aligned

    // Bogus PID must not solve
    REQUIRE_EQ(dev.solve_dtb_for_pid(0), 0u);
    REQUIRE_EQ(dev.solve_dtb_for_pid(0xFFFFFFF0u), 0u);

    // System process DTB (pid 4)
    const uint64_t kdtb = dev.solve_dtb_for_pid(4);
    REQUIRE(kdtb != 0);
    REQUIRE_EQ(kdtb & 0xFFF, 0u);
    REQUIRE_NE(kdtb, dtb);
}

TEST_CASE(driver_read_write_own_process_memory_via_physical_path) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    const uint32_t self_pid = GetCurrentProcessId();

    // Sentinel buffer the driver must be able to see through our DTB
    static uint64_t sentinel = 0x1122334455667788ull;
    sentinel = 0x1122334455667788ull;

    dev.set_process_id(self_pid);
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    uint64_t via_driver = 0;
    REQUIRE_EQ(dev.read_raw(reinterpret_cast<uint64_t>(&sentinel),
                            &via_driver, sizeof(via_driver)),
               sizeof(via_driver));
    REQUIRE_EQ(via_driver, 0x1122334455667788ull);

    // Write it back through the physical path, verify locally
    const uint64_t replacement = 0xAABBCCDDEEFF0011ull;
    REQUIRE_EQ(dev.write_raw(reinterpret_cast<uint64_t>(&sentinel),
                             &replacement, sizeof(replacement)),
               sizeof(replacement));
    REQUIRE_EQ(sentinel, 0xAABBCCDDEEFF0011ull);

    // Unmapped-VA read contract: the driver ZERO-FILLS unmapped reads and
    // reports the full byte count (Memory.cpp read path), writes to
    // unmapped VA are fail-closed instead. Probe an address inside a
    // genuinely MEM_FREE region and require the zero-fill shape.
    MEMORY_BASIC_INFORMATION mbi{};
    uint64_t probe_va = 0;
    for (uint64_t scan = 0x10000000000ull; scan < 0x700000000000ull;
         scan += 0x1000000000ull) {
        if (VirtualQuery(reinterpret_cast<void*>(scan), &mbi, sizeof(mbi)) &&
            mbi.State == MEM_FREE && mbi.RegionSize >= 0x200000) {
            probe_va = scan + 0x1000;
            break;
        }
    }
    REQUIRE(probe_va != 0);
    uint8_t scratch[16] = {};
    REQUIRE_EQ(dev.read_raw(probe_va, scratch, sizeof(scratch)),
               sizeof(scratch));
    for (uint8_t b : scratch)
        REQUIRE_EQ(b, 0u);
}

TEST_CASE(driver_read_crosses_page_boundary) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    const uint32_t self_pid = GetCurrentProcessId();
    dev.set_process_id(self_pid);
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    // Commit two pages and straddle the boundary
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uint8_t* pages = static_cast<uint8_t*>(VirtualAlloc(
        nullptr, si.dwPageSize * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    REQUIRE(pages != nullptr);
    uint8_t* second = pages + si.dwPageSize;
    for (int i = 0; i < 8; ++i) {
        second[i] = static_cast<uint8_t>(0xC0 + i);
        pages[si.dwPageSize - 8 + i] = static_cast<uint8_t>(0x80 + i);
    }

    uint8_t out[16] = {};
    const uint64_t straddle = reinterpret_cast<uint64_t>(second) - 8;
    REQUIRE_EQ(dev.read_raw(straddle, out, sizeof(out)), sizeof(out));
    for (int i = 0; i < 8; ++i) {
        REQUIRE_EQ(out[i], static_cast<uint8_t>(0x80 + i));
        REQUIRE_EQ(out[8 + i], static_cast<uint8_t>(0xC0 + i));
    }
    VirtualFree(pages, 0, MEM_RELEASE);
}

TEST_CASE(driver_read_size_guards) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    dev.set_process_id(GetCurrentProcessId());
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    // >256MB is rejected client side before any IOCTL
    uint8_t scratch[8] = {};
    REQUIRE_EQ(dev.read_raw(reinterpret_cast<uint64_t>(scratch),
                            scratch, 0x10000001ull), 0u);
    REQUIRE_EQ(dev.write_raw(reinterpret_cast<uint64_t>(scratch),
                             scratch, 0x10000001ull), 0u);
    // Zero size is a reject, not a stall
    REQUIRE_EQ(dev.read_raw(reinterpret_cast<uint64_t>(scratch), scratch, 0), 0u);
}

TEST_CASE(driver_allocates_and_frees_memory) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    dev.set_process_id(GetCurrentProcessId());
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    const uint64_t addr = dev.allocate_memory(0x1000);
    REQUIRE(addr != 0);
    REQUIRE_EQ(addr & 0xFFF, 0u);

    // The allocation is writable through the physical path
    uint64_t marker = 0x5A5A5A5A5A5A5A5Aull;
    REQUIRE_EQ(dev.write_raw(addr, &marker, sizeof(marker)), sizeof(marker));
    uint64_t back = 0;
    REQUIRE_EQ(dev.read_raw(addr, &back, sizeof(back)), sizeof(back));
    REQUIRE_EQ(back, marker);

    REQUIRE(dev.free_memory(addr));
    // Freeing an already-freed (or plainly bogus) address fails cleanly
    REQUIRE_FALSE(dev.free_memory(addr));
    REQUIRE_FALSE(dev.free_memory(0x1));
}

// ---------------------------------------------------------------------------
// Thread surface
// ---------------------------------------------------------------------------

TEST_CASE(driver_enumerates_suspends_resumes_thread) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const uint32_t helper = spawn_helper();
    REQUIRE(helper != 0);
    struct kill_t {
        uint32_t pid;
        ~kill_t() { kill_helper(pid); }
    } kill{helper};

    device_t& dev = shared_device();
    dev.set_process_id(helper);

    const auto tids_before = process_threads(helper);
    REQUIRE_FALSE(tids_before.empty());

    const auto infos = dev.enumerate_threads();
    REQUIRE_FALSE(infos.empty());
    size_t matched = 0;
    for (const auto& t : infos) {
        REQUIRE(t.tid != 0);
        for (uint32_t tid : tids_before)
            if (tid == t.tid) ++matched;
    }
    REQUIRE_EQ(matched, tids_before.size());

    const uint32_t tid = tids_before.front();
    uint32_t prev = 0;
    REQUIRE(dev.suspend_thread(tid, &prev));
    // Suspended thread reports rip in the kernel wait region; the contract
    // is only that a context comes back sane enough to round-trip
    device_t::thread_context ctx{};
    REQUIRE(dev.get_thread_context(tid, ctx));
    REQUIRE(ctx.rip != 0);
    uint32_t prev2 = 0;
    REQUIRE(dev.resume_thread(tid, &prev2));
    REQUIRE(prev2 != 0);   // was suspended, count back to nonzero

    // Bogus TIDs must fail, not hang
    REQUIRE_FALSE(dev.suspend_thread(0));
    REQUIRE_FALSE(dev.resume_thread(0xFFFFFFF0u));

    dev.clear_process_context();
}

TEST_CASE(driver_thread_query_information_shapes) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const uint32_t helper = spawn_helper();
    REQUIRE(helper != 0);
    struct kill_t {
        uint32_t pid;
        ~kill_t() { kill_helper(pid); }
    } kill{helper};

    device_t& dev = shared_device();
    dev.set_process_id(helper);
    const auto tids = process_threads(helper);
    REQUIRE_FALSE(tids.empty());

    voyager::detail::thread_query_information_request info{};
    REQUIRE(dev.query_thread_basic_information(tids.front(), info));
    REQUIRE_EQ(info.tid, tids.front());
    // A live cmd.exe thread has a TEB on x64
    REQUIRE(info.teb_base != 0);

    REQUIRE_FALSE(dev.query_thread_basic_information(0, info));
    REQUIRE_FALSE(dev.query_thread_basic_information(0xF0000000u, info));

    dev.clear_process_context();
}

// ---------------------------------------------------------------------------
// Query surface: PEB / SSDT / V2P / memory regions
// ---------------------------------------------------------------------------

TEST_CASE(driver_reads_own_peb) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t dev;
    REQUIRE(dev.connect());
    dev.set_process_id(GetCurrentProcessId());

    device_t::peb_info info{};
    REQUIRE(dev.read_peb(info));
    // Image base must match what the loader tells us locally
    HMODULE self = GetModuleHandleW(nullptr);
    REQUIRE_EQ(info.image_base, reinterpret_cast<uint64_t>(self));
    REQUIRE(info.peb_address != 0);
    REQUIRE(info.ldr_address != 0);
    REQUIRE(info.process_heap != 0);

    dev.clear_process_context();
}

TEST_CASE(driver_queries_ssdt) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // Raw SSDT ioctl path (no backend registry dependency): table base,
    // limit, and decodable handler entries. The kernel AC workflows lean
    // on this map.
    device_t& dev = shared_device();
    dev.solve_kernel_dtb();
    REQUIRE(dev.get_kernel_dtb() != 0);
    device_t::ssdt_info info{};
    REQUIRE(dev.query_ssdt(info));
    REQUIRE(info.service_table != 0);
    REQUIRE(info.lstar != 0);
    REQUIRE_GT(info.service_limit, 0x100u);
    REQUIRE_LT(info.service_limit, 0x1000u);

    // Decode entries through the kernel read path: handler = base + entry>>4
    const uint32_t limit = info.service_limit < 512 ? info.service_limit : 512;
    std::vector<uint8_t> raw(static_cast<size_t>(limit) * 4);
    REQUIRE_EQ(dev.read_kernel_raw(info.service_table, raw.data(), raw.size()),
               raw.size());
    size_t valid_handlers = 0;
    for (uint32_t i = 0; i < limit; ++i) {
        uint32_t entry = 0;
        std::memcpy(&entry, raw.data() + i * 4, 4);
        const uint64_t handler = info.service_table + (entry >> 4);
        if (handler >= info.service_table &&
            handler < info.service_table + 0x2000000ull) {
            ++valid_handlers;
        }
    }
    // Every entry must land inside ntoskrnl's canonical span
    REQUIRE_EQ(valid_handlers, static_cast<size_t>(limit));
    std::printf("  ssdt: table=0x%llX limit=%u lstar=0x%llX\n",
                (unsigned long long)info.service_table, info.service_limit,
                (unsigned long long)info.lstar);
}

TEST_CASE(driver_virtual_to_physical_roundtrip) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    dev.set_process_id(GetCurrentProcessId());
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    static uint64_t probe = 0x4142434445464748ull;
    const uint64_t va = reinterpret_cast<uint64_t>(&probe);
    const uint64_t pa = dev.virtual_to_physical(va);
    REQUIRE(pa != 0);
    REQUIRE_EQ(pa & 0xFFF, va & 0xFFF);   // page offset preserved

    // Null VA is a client reject
    REQUIRE_EQ(dev.virtual_to_physical(0), 0u);

    dev.clear_process_context();
}

TEST_CASE(driver_query_memory_and_enumerate_regions) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    dev.set_process_id(GetCurrentProcessId());

    // Query a committed RW page we own
    uint8_t page[4096]{};
    device_t::memory_region_info info{};
    REQUIRE(dev.query_memory(reinterpret_cast<uint64_t>(page), info));
    REQUIRE(info.state != 0);   // MEM_COMMIT
    REQUIRE(info.size > 0);
    REQUIRE(info.base <= reinterpret_cast<uint64_t>(page));

    // Region enumeration returns our page inside the span it reports
    const auto regions = dev.enumerate_memory_regions();
    bool found = false;
    for (const auto& r : regions) {
        if (r.base <= reinterpret_cast<uint64_t>(page) &&
            r.base + r.size > reinterpret_cast<uint64_t>(page)) {
            found = true;
            break;
        }
    }
    REQUIRE(found);
    std::printf("  regions: %zu\n", regions.size());

    dev.clear_process_context();
}

TEST_CASE(driver_spoof_debug_flags_self) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t dev;
    REQUIRE(dev.connect());
    dev.set_process_id(GetCurrentProcessId());
    uint32_t flags = 0;
    REQUIRE(dev.spoof_debug_flags(&flags));
    dev.clear_process_context();
}

// ---------------------------------------------------------------------------
// Sandbox gating (malware-safe) + debug events + network surface
// ---------------------------------------------------------------------------

TEST_CASE(driver_sandbox_protect_unprotect_lifecycle) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    const uint32_t self_pid = GetCurrentProcessId();

    // Regression for the client-refcount bug: open a second device handle
    // and close it — the shared handle must keep registered-client status.
    // Under the old single-slot registry this close unregistered the pid
    // and every later IOCTL from the process was denied once a sandbox
    // entry existed.
    {
        device_t extra;
        REQUIRE(extra.connect());
        extra.disconnect();
    }

    // Protect + unprotect a sacrificial victim process. Never sandbox the
    // test process itself with blocking flags before cleanup is proven:
    // a sandboxed BLOCK_KERNEL_HANDLE pid loses the device open path.
    const uint32_t victim = spawn_helper();
    REQUIRE(victim != 0);
    struct kill_t {
        uint32_t pid;
        ~kill_t() { kill_helper(pid); }
    } kill{victim};

    uint64_t denials = 0;
    REQUIRE(dev.protect_sandbox_pid(victim, 0, &denials));
    uint64_t denials_after = 0;
    REQUIRE(dev.unprotect_sandbox_pid(victim, &denials_after));

    // Re-protect then verify a fresh client can still talk while the entry
    // exists (the fresh open is a NEW registered client — the gate must
    // pass it), then unprotect through it.
    REQUIRE(dev.protect_sandbox_pid(victim, 0, &denials));
    {
        device_t fresh;
        REQUIRE(fresh.connect());
        REQUIRE(fresh.solve_dtb_for_pid(GetCurrentProcessId()) != 0);
        uint64_t d = 0;
        REQUIRE(fresh.unprotect_sandbox_pid(victim, &d));
    }

    // Self-protect is allowed for the registered client (driver logs a
    // NOTE and takes it); the no-wedge contract: it must be reversible
    // through the still-open registered handle.
    if (dev.protect_sandbox_pid(self_pid, 0, &denials)) {
        uint64_t d = 0;
        REQUIRE(dev.unprotect_sandbox_pid(self_pid, &d));
    } else {
        std::printf("  self-protect refused by policy (ok)\n");
    }

    // pid=0 is rejected. High never-allocated PIDs are ACCEPTED by design
    // (pre-protecting a pid before spawn), and MUST be reversible so the
    // sandbox table can never wedge.
    REQUIRE_FALSE(dev.protect_sandbox_pid(0, 0, &denials));
    REQUIRE(dev.protect_sandbox_pid(0xFFFFFFF0u, 0, &denials));
    REQUIRE(dev.unprotect_sandbox_pid(0xFFFFFFF0u, &denials));
    // Unprotecting something never protected is a clean not-found
    REQUIRE_FALSE(dev.unprotect_sandbox_pid(0xFFFFFFF1u, &denials));
}

TEST_CASE(driver_net_log_register_rejects_bad_pid) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    // pid=0 rejected; high never-allocated pid is accepted by design and
    // cleanly reversible (register then unregister)
    REQUIRE_FALSE(dev.net_log_register_pid(0, true));
    REQUIRE_FALSE(dev.net_log_register_pid(0, false));
    if (dev.net_log_register_pid(0xFFFFFFF0u, true)) {
        REQUIRE(dev.net_log_register_pid(0xFFFFFFF0u, false));
    } else {
        std::printf("  net-log register for unused pid refused (ok)\n");
    }
}

TEST_CASE(driver_drains_debug_events_shape) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    std::vector<device_t::debug_event_record> events;
    device_t::debug_event_drain_stats stats{};
    // A clean drain on a quiet system returns success with zero or more
    // well-formed events; malformed records are the failure mode
    REQUIRE(dev.drain_debug_events(events, 8, &stats));
    for (const auto& e : events) {
        REQUIRE(e.process_id != 0);
        REQUIRE(e.type != device_t::debug_event_type_e::invalid);
        REQUIRE(e.timestamp != 0);
    }
    std::printf("  drained %zu events (total published %llu)\n",
                events.size(),
                (unsigned long long)stats.total_published);
}

TEST_CASE(driver_network_enumeration_surface) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();

    // Connection enumeration: shape-check, any count is valid
    const auto conns = dev.enumerate_connections();
    for (const auto& c : conns) {
        REQUIRE(c.address_family == 2 || c.address_family == 23);
        REQUIRE(c.local_port <= 0xFFFFu);
        REQUIRE(c.remote_port <= 0xFFFFu);
    }
    std::printf("  connections: %zu\n", conns.size());

    // Interface enumeration: a real machine has at least the loopback
    const auto ifaces = dev.enumerate_interfaces();
    REQUIRE_FALSE(ifaces.empty());
    for (const auto& i : ifaces) {
        REQUIRE(i.mtu >= 576 || i.mtu == 0);   // minimal IPv4 MTU or unknown
    }
    std::printf("  interfaces: %zu\n", ifaces.size());

    // Stats + filter rule lifecycle: add, list, remove, clear — every step
    // must round-trip or fail cleanly; a rule that lands must be countable
    device_t::network_stats stats{};
    REQUIRE(dev.get_network_stats(stats));
    const uint32_t rules_before = stats.active_filter_rules;

    uint32_t rule_id = 0;
    if (dev.add_filter_rule(1 /*block*/, 2 /*both*/, 6 /*tcp*/, 0, 0,
                            nullptr, nullptr, &rule_id)) {
        REQUIRE(rule_id != 0);
        REQUIRE(dev.get_network_stats(stats));
        REQUIRE_EQ(stats.active_filter_rules, rules_before + 1);
        REQUIRE(dev.remove_filter_rule(rule_id));
        REQUIRE(dev.get_network_stats(stats));
        REQUIRE_EQ(stats.active_filter_rules, rules_before);
    } else {
        std::printf("  filter add refused (stats-consistent path)\n");
    }
    REQUIRE(dev.clear_filter_rules());
}

TEST_CASE(driver_dns_spoof_rule_lifecycle) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    device_t& dev = shared_device();
    // Add / list / remove round-trip with a clearly fake domain
    uint32_t rule_id = 0;
    if (dev.dns_spoof_op(0 /*add*/, 0, "slop-test-invalid.invalid",
                         nullptr, 2, 60, &rule_id)) {
        REQUIRE(rule_id != 0);
        bool listed = false;
        for (const auto& r : dev.list_dns_spoof_rules()) {
            if (r.rule_id == rule_id) {
                listed = true;
                REQUIRE_EQ(r.domain, std::string("slop-test-invalid.invalid"));
                REQUIRE_EQ(r.active, 1u);
            }
        }
        REQUIRE(listed);
        REQUIRE(dev.dns_spoof_op(1 /*remove*/, rule_id));
        for (const auto& r : dev.list_dns_spoof_rules())
            REQUIRE_NE(r.rule_id, rule_id);
    } else {
        std::printf("  dns spoof add refused (ok)\n");
    }
}

// ---------------------------------------------------------------------------
// kernel_svc domain layer over the driver
// ---------------------------------------------------------------------------

namespace {

// Force the kernel backend for kernel_svc paths and restore whatever
// preference was active before — the registry is process-global and other
// suites assume user-mode defaults
bool with_kernel_backend(const std::function<void()>& body) {
    using slop::core::runtime::registry_init;
    using slop::core::runtime::set_backend_preference;
    using slop::core::runtime::current_preference;
    using slop::core::runtime::backend_pref_t;
    registry_init();
    const backend_pref_t saved = current_preference();
    const bool kernel = set_backend_preference(backend_pref_t::force_kernel);
    if (kernel) body();
    set_backend_preference(saved);
    return kernel;
}

} // namespace

TEST_CASE(kernel_svc_module_enumeration_when_driver_live) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const bool ran = with_kernel_backend([] {
        std::string err;
        const auto mods = kernel_svc::enumerate_modules(&err);
        REQUIRE(err.empty());
        REQUIRE_FALSE(mods.empty());
        bool saw_ntoskrnl = false;
        for (const auto& m : mods) {
            REQUIRE(m.base != 0);
            if (m.name == "ntoskrnl.exe") saw_ntoskrnl = true;
        }
        REQUIRE(saw_ntoskrnl);
        std::printf("  kernel modules: %zu\n", mods.size());
    });
    if (!ran) std::printf("  [skip] kernel backend not activatable\n");
}

TEST_CASE(kernel_svc_read_kernel_nt_header) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const bool ran = with_kernel_backend([] {
        std::string err;
        const auto mods = kernel_svc::enumerate_modules(&err);
        REQUIRE_FALSE(mods.empty());
        // ntoskrnl's base must read back an MZ header through the physical path
        const uint64_t nt_base = [&] {
            for (const auto& m : mods)
                if (m.name == "ntoskrnl.exe") return m.base;
            return 0ull;
        }();
        REQUIRE(nt_base != 0);

        std::vector<uint8_t> hdr;
        const std::string rerr = kernel_svc::kernel_read(nt_base, 2, &hdr);
        REQUIRE(rerr.empty());
        REQUIRE_EQ(hdr.size(), 2u);
        REQUIRE_EQ(hdr[0], 'M');
        REQUIRE_EQ(hdr[1], 'Z');
    });
    if (!ran) std::printf("  [skip] kernel backend not activatable\n");
}

TEST_CASE(kernel_svc_dump_module_rejects_bad_inputs) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const bool ran = with_kernel_backend([] {
        // Zero base/size and oversized spans are rejected before any read.
        // Size guard fires before the MZ check, so a giant span on a real
        // base is also refused without touching memory
        REQUIRE_FALSE(kernel_svc::dump_module(0, 0x1000, "x.sys").empty());
        REQUIRE_FALSE(kernel_svc::dump_module(0x1000, 0, "x.sys").empty());
        REQUIRE_FALSE(kernel_svc::dump_module(0xFFFFF78000000000ull,
                                              0x7FFFFFFFull, "x.sys").empty());
    });
    if (!ran) std::printf("  [skip] kernel backend not activatable\n");
}

TEST_CASE(kernel_svc_kernel_search_finds_nt_signature) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const bool ran = with_kernel_backend([] {
        std::string err;
        const auto mods = kernel_svc::enumerate_modules(&err);
        const uint64_t nt_base = [&] {
            for (const auto& m : mods)
                if (m.name == "ntoskrnl.exe") return m.base;
            return 0ull;
        }();
        REQUIRE(nt_base != 0);

        // 'MZ' at the exact base, max window, one hit expected
        const auto hits = kernel_svc::kernel_search(nt_base, nt_base + 0x1000,
                                                    {'M', 'Z'}, 4);
        REQUIRE_FALSE(hits.empty());
        REQUIRE_EQ(hits.front(), nt_base);

        // Inverted range is rejected empty
        REQUIRE(kernel_svc::kernel_search(nt_base + 0x1000, nt_base,
                                          {'M', 'Z'}, 4).empty());
    });
    if (!ran) std::printf("  [skip] kernel backend not activatable\n");
}

TEST_CASE(kernel_svc_read_peb_over_driver) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // The RPEB ioctl path driven directly: attach a private device to self
    device_t dev;
    REQUIRE(dev.connect());
    dev.set_process_id(GetCurrentProcessId());
    device_t::peb_info info{};
    REQUIRE(dev.read_peb(info));
    REQUIRE_EQ(info.image_base,
               reinterpret_cast<uint64_t>(GetModuleHandleW(nullptr)));
    dev.clear_process_context();
}

TEST_CASE(driver_resolve_export_ntdll) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // MEX export resolution through the driver, cross-checked against the
    // local module map
    device_t dev;
    REQUIRE(dev.connect());
    dev.set_process_id(GetCurrentProcessId());
    dev.solve_dtb();
    REQUIRE(dev.get_dtb() != 0);

    const uint64_t ntdll = reinterpret_cast<uint64_t>(GetModuleHandleW(L"ntdll.dll"));
    const auto local = reinterpret_cast<uint64_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtClose"));
    REQUIRE(local != 0);
    REQUIRE_EQ(dev.resolve_export(ntdll, "NtClose"), local);

    // Bogus export names resolve to nothing, no crash
    REQUIRE_EQ(dev.resolve_export(ntdll, "SlopNoSuchExport"), 0u);
    REQUIRE_EQ(dev.resolve_export(0, "NtClose"), 0u);
    REQUIRE_EQ(dev.resolve_export(ntdll, ""), 0u);

    dev.clear_process_context();
}

// ---------------------------------------------------------------------------
// Concurrency: parallel IOCTLs from many threads
// ---------------------------------------------------------------------------

TEST_CASE(driver_parallel_ioctl_stress) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // AC workflows fire concurrent reads while polling; the dispatcher's
    // g_active_ioctls guard plus the DTB cache lock must survive overlap
    constexpr int kThreads = 4;
    constexpr int kIters = 50;
    std::atomic<int> failures{0};
    std::atomic<int> solved{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&] {
            device_t dev;
            if (!dev.connect()) {
                failures.fetch_add(1);
                return;
            }
            for (int i = 0; i < kIters; ++i) {
                const uint64_t dtb = dev.solve_dtb_for_pid(GetCurrentProcessId());
                if (dtb == 0) {
                    failures.fetch_add(1);
                } else {
                    solved.fetch_add(1);
                    if ((dtb & 0xFFF) != 0) failures.fetch_add(1);
                }
                // Liveness probe through a second code path: stats query
                // must keep succeeding under overlap (IDENT is not a probe
                // for mapped loads — no registry identity to report)
                device_t::network_stats stats{};
                if (!dev.get_network_stats(stats)) failures.fetch_add(1);
            }
        });
    }
    for (auto& w : workers) w.join();
    REQUIRE_EQ(failures.load(), 0);
    REQUIRE_EQ(solved.load(), kThreads * kIters);
}

TEST_CASE(driver_reconnect_cycle) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    // AC sessions churn handles; 8 connect/solve/disconnect cycles must not
    // wedge the registered-client tracking in Pilot
    for (int i = 0; i < 8; ++i) {
        device_t dev;
        REQUIRE(dev.connect());
        REQUIRE(dev.solve_dtb_for_pid(GetCurrentProcessId()) != 0);
        device_t::network_stats stats{};
        REQUIRE(dev.get_network_stats(stats));
        dev.disconnect();
        REQUIRE_FALSE(dev.is_connected());
    }
    // The shared device still works after all that churn
    REQUIRE(shared_device().connect());
}
