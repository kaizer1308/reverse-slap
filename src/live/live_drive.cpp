// src/live/live_drive.cpp
// end to end run against a spawned target, exit 0 means the whole flow works

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include "core/infra/limits.hpp"
#include "core/infra/work_queue.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/read_util.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/scan_bridge.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace {

using json = nlohmann::json;
using slop::core::memory::scan_config_t;
using slop::core::memory::scan_type_t;
using slop::core::memory::value_width_t;

int g_step = 0;

void ok(const std::string& what, const std::string& detail = {}) {
    std::printf("[%02d] PASS  %-34s %s\n", ++g_step, what.c_str(), detail.c_str());
}

void die(const std::string& what, const std::string& detail = {}) {
    std::printf("[%02d] FAIL  %-34s %s\n", ++g_step, what.c_str(), detail.c_str());
    std::exit(1);
}

// Target process plumbing

struct target_t {
    HANDLE proc = nullptr;
    HANDLE stdin_w = nullptr;
    HANDLE stdout_r = nullptr;
    PROCESS_INFORMATION pi{};
    uint32_t pid = 0;
    json report;
};

std::string read_until_marker(HANDLE r) {
    std::string out;
    char buf[512];
    DWORD n = 0;
    const std::string marker = "commands:";
    while (out.find(marker) == std::string::npos) {
        if (!ReadFile(r, buf, sizeof(buf) - 1, &n, nullptr) || n == 0) break;
        buf[n] = '\0';
        out += buf;
        if (out.size() > 1 << 20) break;
    }
    return out;
}

void send_command(target_t& t, const std::string& cmd) {
    DWORD written = 0;
    WriteFile(t.stdin_w, (cmd + "\n").c_str(),
              static_cast<DWORD>(cmd.size() + 1), &written, nullptr);
    FlushFileBuffers(t.stdin_w);
    Sleep(120);   // let the command loop chew
}

std::string drain(HANDLE r) {
    std::string out;
    char buf[1024];
    DWORD n = 0;
    while (PeekNamedPipe(r, nullptr, 0, nullptr, &n, nullptr) && n > 0) {
        if (!ReadFile(r, buf, sizeof(buf) - 1, &n, nullptr) || n == 0) break;
        buf[n] = '\0';
        out += buf;
        if (out.size() > 1 << 20) break;
    }
    return out;
}

bool spawn_target(target_t& t) {
    SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };

    HANDLE in_r = nullptr, out_w = nullptr;
    CreatePipe(&in_r, &t.stdin_w, &sa, 0);
    CreatePipe(&t.stdout_r, &out_w, &sa, 0);
    SetHandleInformation(t.stdin_w, HANDLE_FLAG_INHERIT, 0);
    SetHandleInformation(t.stdout_r, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA si{};
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = in_r;
    si.hStdOutput = out_w;
    si.hStdError = out_w;

    char exe[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exe, MAX_PATH);
    // Expect sibling: build/live/slop_live.exe -> build/src/app/SlopTarget.exe
    std::string path(exe);
    const size_t pos = path.find_last_of("\\/");
    path = path.substr(0, pos) + "\\..\\src\\app\\SlopTarget.exe";

    char cmd[MAX_PATH * 2]{};
    std::snprintf(cmd, sizeof(cmd), "\"%s\"", path.c_str());   // no auto-tick: deterministic

    if (!CreateProcessA(nullptr, cmd, nullptr, nullptr, TRUE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &t.pi)) {
        return false;
    }
    t.proc = t.pi.hProcess;
    CloseHandle(in_r);
    CloseHandle(out_w);

    read_until_marker(t.stdout_r);   // banner + report + prompt

    // Locate the freshest report json
    char temp[MAX_PATH]{};
    GetTempPathA(MAX_PATH, temp);
    WIN32_FIND_DATAA fd{};
    std::string newest;
    FILETIME ft{};
    HANDLE ff = FindFirstFileA((std::string(temp) + "sloptarget-*.json").c_str(), &fd);
    if (ff != INVALID_HANDLE_VALUE) {
        do {
            if (newest.empty() ||
                CompareFileTime(&fd.ftLastWriteTime, &ft) > 0) {
                ft = fd.ftLastWriteTime;
                newest = std::string(temp) + fd.cFileName;
            }
        } while (FindNextFileA(ff, &fd));
        FindClose(ff);
    }
    if (newest.empty()) return false;

    std::ifstream f(newest);
    f >> t.report;

    t.pid = t.report["pid"].get<uint32_t>();
    return t.pid != 0;
}

// Backend helpers

slop::core::runtime::target_handle_t g_handle;

class live_reader_t final : public slop::core::memory::reader_t {
public:
    explicit live_reader_t(slop::core::runtime::backend_t& b) : b_(b) {}
    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto io = b_.read_memory(g_handle, addr, dst, len);
        return io.ok && io.bytes == len;
    }
private:
    slop::core::runtime::backend_t& b_;
};

live_reader_t backend_reader() { return live_reader_t(slop::core::runtime::active()); }

slop::core::infra::cancel_token_t cancel_none() { return {}; }

std::string& aob_err_scrub() { static std::string e; e.clear(); return e; }

} // namespace

int main() {
    setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== reverse-slop LIVE DRIVE ===\n\n");

    target_t tgt;
    if (!spawn_target(tgt))
        die("spawn SlopTarget", "build it first");
    ok("spawned SlopTarget", "pid " + std::to_string(tgt.pid));

    // Registry + attach
    slop::core::runtime::registry_init();
    slop::core::infra::pool::start();

    auto& backend = slop::core::runtime::active();
    g_handle = backend.attach(tgt.pid);
    if (!g_handle.valid()) die("backend attach");
    ok("attached", std::string("badge=") + backend.badge());

    // Exact scan: read CURRENT health straight from target memory
    const uintptr_t health_addr = tgt.report["values"]["health"].get<uintptr_t>();

    int32_t cur_hp = 0;
    if (!backend.read_memory(g_handle, health_addr, &cur_hp, 4).ok)
        die("read current health");
    ok("read current health", std::to_string(cur_hp));

    // Region set from the backend (driver ER path under the kernel badge)
    auto regions = slop::core::runtime::target_scan_regions(g_handle);
    if (regions.empty()) die("region enumeration");

    scan_config_t cfg;
    cfg.type  = scan_type_t::exact_value;
    cfg.width = value_width_t::i32;
    cfg.value1 = static_cast<double>(cur_hp);
    cfg.fast = slop::core::memory::fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    slop::core::memory::memscan_t engine;
    std::string scan_err;
    auto reader = backend_reader();
    const auto tok = cancel_none();
    engine.first_scan(reader, std::move(regions), cfg, tok, &scan_err);
    if (!scan_err.empty()) die("first scan", scan_err);

    const auto& hits = engine.results();
    ok("exact scan i32=" + std::to_string(cur_hp),
       std::to_string(engine.stats().regions_scanned) + " regions, " +
       std::to_string(hits.size()) + " raw hits");

    const bool found_health = std::any_of(hits.begin(), hits.end(),
        [&](const slop::core::memory::scan_result_t& h) {
            return h.address == health_addr;
        });
    if (!found_health) die("health address in first-scan results",
                           std::to_string(hits.size()) + " candidates");
    ok("health located", "addr " + std::to_string(health_addr));

    // Mutate from TARGET side, then rescan increased
    send_command(tgt, "inc health");
    send_command(tgt, "inc health");
    send_command(tgt, "inc health");          // 1000 -> 1003

    scan_config_t ncfg = cfg;
    ncfg.type = scan_type_t::increased;
    const size_t before = hits.size();
    engine.next_scan(reader, ncfg, tok, &scan_err);
    if (!scan_err.empty()) die("rescan increased", scan_err);
    const auto& increased = engine.results();

    const bool narrowed = increased.size() < before;
    const bool still_found = std::any_of(increased.begin(), increased.end(),
        [&](const slop::core::memory::scan_result_t& h) {
            return h.address == health_addr;
        });
    if (!narrowed || !still_found)
        die("rescan increased narrows", std::to_string(increased.size()));
    ok("rescan increased", std::to_string(before) + " -> " +
                           std::to_string(increased.size()));

    // WRITE through backend: set health 9999
    const int32_t new_hp = 9999;
    auto io = backend.write_memory(g_handle, health_addr, &new_hp, 4);
    if (!io.ok) die("backend write");
    ok("wrote health=9999");

    // Prove the TARGET saw our write: make it decrement its own copy,
    // then read back through the backend. 9999 -> 9998
    send_command(tgt, "dec health");
    int32_t after_dec = 0;
    for (int i = 0; i < 30; ++i) {
        Sleep(100);
        if (!backend.read_memory(g_handle, health_addr, &after_dec, 4).ok)
            die("readback after dec");
        if (after_dec == new_hp - 1) break;
    }
    if (after_dec != new_hp - 1)
        die("target confirms our write", "expected " +
            std::to_string(new_hp - 1) + ", saw " + std::to_string(after_dec));
    ok("target confirms health=9999", "it decremented to " + std::to_string(after_dec));
    ok("target confirms health=9999", "(read back from its own .data)");

    // AOB scan for the magic fixture
    const uintptr_t magic_addr = tgt.report["values"]["magic_bytes"].get<uintptr_t>();
    auto pat = slop::core::memory::aob_compile(
        "DE AD BE EF CA FE BA BE",
        aob_err_scrub());
    if (!pat) die("aob compile");

    // Scan committed regions from the backend. No early-exit: the pattern
    // may appear in .text immediates AND in .data as the fixture array
    auto aob_regions = slop::core::runtime::target_scan_regions(g_handle);
    slop::core::memory::aob_scan_options_t aopt;
    auto aob_hits = slop::core::memory::aob_scan(
        reader, aob_regions, *pat, aopt, tok, nullptr);

    const bool aob_ok = std::any_of(aob_hits.begin(), aob_hits.end(),
        [&](uintptr_t a) { return a == magic_addr; });
    if (!aob_ok) die("aob scan finds magic_bytes",
                     std::to_string(aob_hits.size()) + " hits");
    ok("aob scan finds magic_bytes", std::to_string(aob_hits.size()) + " hit(s)");

    // Pointer chain walk: world -> ... -> hp
    const uint64_t world = tgt.report["chain"]["g_world_ptr"].get<uint64_t>();
    const uint64_t hp_expect = tgt.report["chain"]["hp"].get<uint64_t>();
    auto offs = tgt.report["chain"]["offsets"].get<std::vector<int64_t>>();

    uint64_t cur = world;
    bool walk_ok = true;
    for (size_t i = 0; i < offs.size() && walk_ok; ++i) {
        uint64_t next = 0;
        walk_ok = backend.read_memory(g_handle, cur, &next, 8).ok;
        if (!walk_ok) break;
        cur = next + static_cast<uint64_t>(offs[i]);
    }
    if (!walk_ok || cur != hp_expect) die("pointer chain walk");
    ok("pointer chain walk", "world -> hp @ " + std::to_string(hp_expect));

    // Cleanup
    backend.detach(g_handle);
    send_command(tgt, "quit");
    WaitForSingleObject(tgt.proc, 2000);

    std::printf("\n=== LIVE DRIVE: ALL GREEN (%d steps) ===\n", g_step);
    return 0;
}
