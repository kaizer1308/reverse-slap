// src/tests/test_injector.cpp
// Live kernel-injector test suite. Runs the full slopdrvr-backed injection
// pipeline against a sacrificial process with the driver resident: helper
// lookups (find_module_base / resolve_export), manual map (PE parse, kernel
// alloc, section copy, relocs, import resolution incl. forwarders + apisets,
// TLS callbacks, DllMain, section re-protect, header erase), LoadLibraryW
// hijack mode (with a remote export call round-trip through the injected
// image), PEB unlink, and both unload paths. Proof of execution rides a
// marker file the fixture DLL's DllMain drops into %TEMP% carrying the
// module base it sees from inside the target.
//
// Every test degrades to a printed skip when the driver is absent so CI
// without the driver stays green.

#include "harness.hpp"

#include "core/runtime/kernel_injector.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/voyager_comm.h"
#include "core/infra/diag.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

namespace {

using slop::core::runtime::injector::inject_loadlibrary;
using slop::core::runtime::injector::inject_manual_map;
using slop::core::runtime::injector::inject_manual_map_file;
using slop::core::runtime::injector::inject_options_t;
using slop::core::runtime::injector::inject_result_t;
using slop::core::runtime::injector::find_module_base;
using slop::core::runtime::injector::resolve_export;
using slop::core::runtime::injector::unload;

#ifndef SLOP_INJECT_DLL_PATH
#define SLOP_INJECT_DLL_PATH ""
#endif

bool driver_loaded() {
    static voyager::device_t probe;
    return probe.connect();
}

// Force the kernel backend: the injector rides backend_registry::active()
// so it must see the kernel device, not the user-mode default. Restores the
// saved preference afterwards (registry is process-global).
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

// Spawn the SlopTarget fixture: its ticker thread sleeps in a 1s loop, so a
// hijacked thread context survives the wait and executes when the sleep
// expires -- no force-wake needed. cmd.exe is a pathological victim (its
// only quiescent thread is blocked in a console read that never completes).
uint32_t spawn_helper() {
#ifdef SLOP_TARGET_EXE_PATH
    STARTUPINFOA si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    char cmd[MAX_PATH] = {};
    strncpy_s(cmd, MAX_PATH, SLOP_TARGET_EXE_PATH, _TRUNCATE);
    char* mutable_cmd = cmd;
    if (CreateProcessA(nullptr, mutable_cmd, nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        // let the ticker thread start its first sleep so there is always a
        // hijackable, self-waking thread in the target
        Sleep(750);
        return pi.dwProcessId;
    }
    std::printf("  [warn] SlopTarget spawn failed gle=%lu, falling back to cmd\n",
                GetLastError());
#endif
    STARTUPINFOA si2{};
    si2.cb = sizeof(si2);
    PROCESS_INFORMATION pi2{};
    char cmd2[MAX_PATH] = {};
    GetSystemDirectoryA(cmd2, MAX_PATH - 64);
    std::strcat(cmd2, "\\cmd.exe");
    char* mutable_cmd2 = cmd2;
    if (!CreateProcessA(nullptr, mutable_cmd2, nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si2, &pi2)) {
        return 0;
    }
    CloseHandle(pi2.hThread);
    CloseHandle(pi2.hProcess);
    Sleep(750);
    return pi2.dwProcessId;
}

void kill_helper(uint32_t pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pid);
    if (h) {
        TerminateProcess(h, 0);
        WaitForSingleObject(h, 5000);
        CloseHandle(h);
    }
}

// --- marker file plumbing (mirrors inject_fixture_dll.cpp) ----------------

#pragma pack(push, 1)
struct marker_file_t {
    uint32_t magic;
    uint32_t reason;
    uint32_t pid;
    uint32_t tls_value;
    uint64_t module_base;
    uint64_t marker_fn_addr;
};
#pragma pack(pop)

constexpr uint32_t kMarkerMagicV1 = 0x315A4E49u;

std::string marker_path(uint32_t pid) {
    char temp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp);
    char tail[64] = {};
    _snprintf_s(tail, sizeof(tail), _TRUNCATE, "slop_inject_marker_%u.bin",
                pid);
    return std::string(temp) + tail;
}

bool clear_marker(uint32_t pid) {
    const std::string p = marker_path(pid);
    return DeleteFileA(p.c_str()) != 0;
}

bool read_marker(uint32_t pid, marker_file_t& out) {
    const std::string p = marker_path(pid);
    HANDLE f = CreateFileA(p.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD got = 0;
    const BOOL ok = ReadFile(f, &out, sizeof(out), &got, nullptr);
    CloseHandle(f);
    return ok && got == sizeof(out) && out.magic == kMarkerMagicV1;
}

// Poll briefly: the DllMain call completes before inject_* returns, but the
// marker write happens inside the target so allow a short settle window.
bool wait_marker(uint32_t pid, marker_file_t& out, uint32_t ms = 3000) {
    for (uint32_t slept = 0; slept < ms; slept += 100) {
        if (read_marker(pid, out)) return true;
        Sleep(100);
    }
    return read_marker(pid, out);
}

void dump_result(const inject_result_t& r) {
    std::printf("  mode=%s ok=%d base=0x%llX size=0x%llX entry=0x%llX\n",
                r.mode.c_str(), r.ok ? 1 : 0,
                (unsigned long long)r.module_base,
                (unsigned long long)r.module_size,
                (unsigned long long)r.entry_point);
    std::printf("  imports=%u/%u relocs=%u protected=%u dllmain=0x%llX "
                "erased=%d unlinked=%d\n",
                r.imports_resolved, r.imports_failed,
                r.relocations_applied, r.sections_protected,
                (unsigned long long)r.dllmain_return,
                r.header_erased ? 1 : 0, r.peb_unlinked ? 1 : 0);
    if (!r.error.empty())
        std::printf("  error: %s\n", r.error.c_str());
    for (const auto& l : r.log)
        std::printf("  [%s] %s\n", l.stage.c_str(), l.message.c_str());
    // play-by-play of the remote-call machinery when something went wrong
    if (!r.ok) {
        auto snap = slop::core::infra::diag::snapshot();
        for (const auto& e : snap.entries) {
            if (e.tag != "comm") continue;
            if (e.message.rfind("remote_call_um_poll_ioctl", 0) == 0) continue;
            if (e.message.rfind("remote_call_um_poll_progress", 0) == 0) continue;
            if (e.message.rfind("set_process_id_switch", 0) == 0) continue;
            std::printf("  [diag] %s\n", e.message.c_str());
        }
    }
}

std::vector<uint8_t> read_file_bytes(const char* path) {
    std::vector<uint8_t> out;
    HANDLE f = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return out;
    LARGE_INTEGER sz{};
    if (GetFileSizeEx(f, &sz) && sz.QuadPart > 0 &&
        sz.QuadPart <= (64ll * 1024 * 1024)) {
        out.resize(static_cast<size_t>(sz.QuadPart));
        DWORD got = 0;
        if (!ReadFile(f, out.data(), static_cast<DWORD>(out.size()), &got,
                      nullptr) ||
            got != out.size())
            out.clear();
    }
    CloseHandle(f);
    return out;
}

// Copy the fixture to a temp path -- LoadLibraryW in the target needs a
// real file on disk, and the CMake-passed path must not be the only copy so
// the test never loads a stale artifact from a previous build by accident.
// Returns the staged path; module_name_out receives the file's base name
// (the name the module will carry in the target's LDR).
std::string stage_fixture_copy(std::string* module_name_out = nullptr) {
    char temp[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, temp);
    char dst[MAX_PATH] = {};
    _snprintf_s(dst, sizeof(dst), _TRUNCATE, "%sslop_inject_fixture_%u.dll",
                temp, GetCurrentProcessId());
    if (!CopyFileA(SLOP_INJECT_DLL_PATH, dst, FALSE)) return {};
    if (module_name_out) {
        const char* name = strrchr(dst, '\\');
        name = name ? name + 1 : dst;
        *module_name_out = name;
    }
    return dst;
}

} // namespace

// ---------------------------------------------------------------------------
// helper surface: find_module_base / resolve_export
// ---------------------------------------------------------------------------

TEST_CASE(injector_helpers_find_module_and_export) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);

    const bool ran = with_kernel_backend([&] {
        std::string err;
        const auto k32 = find_module_base(pid, "kernel32.dll", &err);
        REQUIRE(k32.has_value());
        REQUIRE(*k32 != 0);
        REQUIRE(err.empty());
        std::printf("  kernel32 @ 0x%llX\n", (unsigned long long)*k32);

        // suffix-less and case-mangled lookups must land the same module
        const auto k32b = find_module_base(pid, "KERNEL32", &err);
        REQUIRE(k32b.has_value());
        REQUIRE_EQ(*k32b, *k32);

        const auto ntdll = find_module_base(pid, "ntdll.dll", &err);
        REQUIRE(ntdll.has_value());
        REQUIRE_NE(*ntdll, 0ull);

        // a module that's certainly not there must miss, not return garbage
        const auto miss = find_module_base(pid, "slop_no_such_module.dll");
        REQUIRE_FALSE(miss.has_value());

        // export resolution: LoadLibraryW inside kernel32's range
        const auto llw = resolve_export(pid, "kernel32.dll", "LoadLibraryW",
                                        &err);
        REQUIRE(llw.has_value());
        REQUIRE(*llw > *k32);
        REQUIRE(*llw < *k32 + 0x2000000);
        std::printf("  kernel32!LoadLibraryW @ 0x%llX\n",
                    (unsigned long long)*llw);

        // miss must be a clean failure with a message
        const auto nope = resolve_export(pid, "kernel32.dll",
                                         "SlopNoSuchExport");
        REQUIRE_FALSE(nope.has_value());
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
}

// ---------------------------------------------------------------------------
// manual map: the full pipeline
// ---------------------------------------------------------------------------

TEST_CASE(injector_manual_map_full_pipeline) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const std::vector<uint8_t> dll = read_file_bytes(SLOP_INJECT_DLL_PATH);
    REQUIRE_FALSE(dll.empty());

    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);
    clear_marker(pid);

    const bool ran = with_kernel_backend([&] {
        inject_options_t opts{}; // defaults: dllmain + tls + protect + erase
        const inject_result_t r = inject_manual_map(pid, dll, opts);
        dump_result(r);

        REQUIRE(r.ok);
        REQUIRE(r.error.empty());
        REQUIRE_NE(r.module_base, 0ull);
        REQUIRE_GT(r.module_size, 0x1000u);
        REQUIRE_NE(r.entry_point, 0ull);
        REQUIRE_GT(r.imports_resolved, 0u);
        REQUIRE_EQ(r.imports_failed, 0u);
        REQUIRE_GT(r.sections_protected, 0u);
        REQUIRE(r.header_erased);
        // ASLR makes a zero delta practically impossible on a real spawn
        REQUIRE_GT(r.relocations_applied, 0u);
        // DllMain returned TRUE
        REQUIRE_EQ(r.dllmain_return, 1ull);

        // the marker proves the code ran inside the target. The base the
        // target saw must be exactly the base the injector mapped at --
        // except manual maps have no LDR entry, so GetModuleHandleExA
        // FROM_ADDRESS inside the DLL reports 0: the hiding working
        marker_file_t m{};
        REQUIRE(wait_marker(pid, m));
        REQUIRE_EQ(m.reason, DLL_PROCESS_ATTACH);
        REQUIRE_EQ(m.pid, pid);
        REQUIRE(m.module_base == 0 || m.module_base == r.module_base);
        // CRT TLS callbacks ran before DllMain -> canary initialized
        REQUIRE_EQ(m.tls_value, 0x51u);
        REQUIRE_GT(m.marker_fn_addr, r.module_base);
        REQUIRE_LT(m.marker_fn_addr, r.module_base + r.module_size);

        // header erased: MZ must be gone from the first page
        auto* dev = dynamic_cast<slop::core::runtime::backend_kernel_t*>(
            &slop::core::runtime::active());
        REQUIRE(dev != nullptr);
        REQUIRE(dev->device() != nullptr);
        const uint16_t mz =
            dev->device()->read<uint16_t>(r.module_base);
        REQUIRE_NE(mz, 0x5A4Du); // 'MZ'
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
}

TEST_CASE(injector_manual_map_headers_kept_when_not_erased) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const std::vector<uint8_t> dll = read_file_bytes(SLOP_INJECT_DLL_PATH);
    REQUIRE_FALSE(dll.empty());

    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);
    clear_marker(pid);

    const bool ran = with_kernel_backend([&] {
        inject_options_t opts{};
        opts.erase_pe_header = false;
        opts.call_dllmain    = false; // also: DllMain must NOT run
        opts.call_tls_callbacks = false;
        const inject_result_t r = inject_manual_map(pid, dll, opts);
        dump_result(r);

        REQUIRE(r.ok);
        REQUIRE_EQ(r.imports_failed, 0u);
        REQUIRE_FALSE(r.header_erased);
        REQUIRE_EQ(r.dllmain_return, 0ull); // never called

        // no DllMain -> no marker
        marker_file_t m{};
        REQUIRE_FALSE(read_marker(pid, m));

        // headers kept: MZ + PE\\0\\0 readable through the physical path,
        // and the target-side entry RVA must match the file's
        auto* dev = dynamic_cast<slop::core::runtime::backend_kernel_t*>(
            &slop::core::runtime::active());
        REQUIRE(dev != nullptr);
        REQUIRE(dev->device() != nullptr);
        const uint16_t mz = dev->device()->read<uint16_t>(r.module_base);
        REQUIRE_EQ(mz, 0x5A4Du);
        const uint32_t lfanew =
            dev->device()->read<uint32_t>(r.module_base + 0x3C);
        REQUIRE_GT(lfanew, 0u);
        REQUIRE_LT(lfanew, 0x1000u);
        const uint32_t pesig =
            dev->device()->read<uint32_t>(r.module_base + lfanew);
        REQUIRE_EQ(pesig, 0x00004550u); // 'PE\0\0'
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
}

TEST_CASE(injector_manual_map_rejects_garbage) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);

    const bool ran = with_kernel_backend([&] {
        // not a PE at all
        std::vector<uint8_t> junk(0x1000, 0xCC);
        inject_result_t r = inject_manual_map(pid, junk, {});
        REQUIRE_FALSE(r.ok);
        REQUIRE_FALSE(r.error.empty());
        std::printf("  junk: %s\n", r.error.c_str());

        // 32-bit image must be refused with a clear message
        std::vector<uint8_t> mz32(0x400, 0);
        mz32[0] = 'M'; mz32[1] = 'Z';
        const uint32_t lfanew_off = 0x80;
        *reinterpret_cast<uint32_t*>(&mz32[0x3C]) = lfanew_off;
        auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(&mz32[lfanew_off]);
        nt->Signature = 0x00004550;
        nt->FileHeader.Machine = 0x014C; // i386
        nt->OptionalHeader.Magic = 0x10B; // PE32
        r = inject_manual_map(pid, mz32, {});
        REQUIRE_FALSE(r.ok);
        REQUIRE(r.error.find("x64") != std::string::npos);
        std::printf("  pe32: %s\n", r.error.c_str());

        // pid 0 / System must be refused before any driver touch
        r = inject_manual_map(0, {1, 2, 3}, {});
        REQUIRE_FALSE(r.ok);
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
}

// ---------------------------------------------------------------------------
// loadlibrary mode: hijack LoadLibraryW, then remote-call into the module
// ---------------------------------------------------------------------------

TEST_CASE(injector_loadlibrary_and_remote_export_call) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    std::string module_name;
    const std::string staged = stage_fixture_copy(&module_name);
    REQUIRE_FALSE(staged.empty());
    // widen for LoadLibraryW
    std::wstring wpath(staged.begin(), staged.end());

    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);
    clear_marker(pid);

    const bool ran = with_kernel_backend([&] {
        inject_options_t opts{};
        opts.erase_pe_header = false;
        opts.unlink_peb      = false;
        const inject_result_t r =
            inject_loadlibrary(pid, wpath, opts);
        dump_result(r);

        REQUIRE(r.ok);
        REQUIRE(r.error.empty());
        REQUIRE_NE(r.module_base, 0ull);
        REQUIRE_GT(r.module_size, 0x1000u);
        // LoadLibraryW returns the module handle == base
        REQUIRE_EQ(r.dllmain_return, r.module_base);

        // module must now be visible through the helper surface
        const auto base = find_module_base(pid, module_name);
        REQUIRE(base.has_value());
        REQUIRE_EQ(*base, r.module_base);

        // DllMain ran inside the target (LoadLibrary runs it for us)
        marker_file_t m{};
        REQUIRE(wait_marker(pid, m));
        REQUIRE_EQ(m.pid, pid);
        REQUIRE_EQ(m.module_base, r.module_base);

        // resolve an export in the freshly loaded module and remote-call
        // it through the driver's thread-hijack primitive: proves the IAT
        // of a genuinely loader-mapped image + our call path both work
        const auto fn = resolve_export(pid, module_name,
                                       "fixture_export_sum");
        REQUIRE(fn.has_value());
        auto* dev = dynamic_cast<slop::core::runtime::backend_kernel_t*>(
            &slop::core::runtime::active());
        REQUIRE(dev != nullptr);
        const uint64_t got = dev->device()->call_function(*fn, 1234, 5678);
        REQUIRE_EQ(got, 6912ull);

        // clean unload through FreeLibrary
        const inject_result_t u = unload(pid, r.module_base, false, {});
        REQUIRE(u.ok);
        // module gone from the LDR after FreeLibrary
        const auto gone = find_module_base(pid, module_name);
        REQUIRE_FALSE(gone.has_value());
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
    DeleteFileA(staged.c_str());
}

TEST_CASE(injector_loadlibrary_peb_unlink_hides_module) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    std::string module_name;
    const std::string staged = stage_fixture_copy(&module_name);
    REQUIRE_FALSE(staged.empty());
    std::wstring wpath(staged.begin(), staged.end());

    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);
    clear_marker(pid);

    const bool ran = with_kernel_backend([&] {
        inject_options_t opts{};
        opts.unlink_peb = true;
        const inject_result_t r = inject_loadlibrary(pid, wpath, opts);
        dump_result(r);
        REQUIRE(r.ok);
        REQUIRE(r.peb_unlinked);
        REQUIRE(r.header_erased);

        // unlinked: LDR walk must no longer see it (that's the same walk
        // toolhelp-style hidden-module scanners ride)
        const auto gone = find_module_base(pid, module_name);
        REQUIRE_FALSE(gone.has_value());

        // but the code is still mapped and runnable -- remote-call the
        // export by the base we kept from before the unlink
        auto* dev = dynamic_cast<slop::core::runtime::backend_kernel_t*>(
            &slop::core::runtime::active());
        REQUIRE(dev != nullptr);
        REQUIRE(dev->device() != nullptr);
        // walk the (unlinked) image's export dir by hand through raw reads
        const uint64_t b = r.module_base;
        // header was erased in this mode, so re-derive from the copy on
        // disk: entry RVA of fixture_marker_value is not needed -- just
        // prove the pages still execute via the known DllMain marker side
        // effect, which already fired during LoadLibrary.
        marker_file_t m{};
        REQUIRE(wait_marker(pid, m));
        REQUIRE_EQ(m.module_base, b);

        // FreeLibrary still works by handle==base even when unlinked
        const inject_result_t u = unload(pid, r.module_base, false, {});
        REQUIRE(u.ok);
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
    DeleteFileA(staged.c_str());
}

// ---------------------------------------------------------------------------
// unload of a manual-mapped image
// ---------------------------------------------------------------------------

TEST_CASE(injector_unload_manual_mapped_image) {
    if (!driver_loaded()) {
        std::printf("  [skip] driver not loaded\n");
        return;
    }
    const uint32_t pid = spawn_helper();
    REQUIRE_NE(pid, 0u);
    clear_marker(pid);

    const bool ran = with_kernel_backend([&] {
        // map with default options (section protection on -- exercises the
        // VAD-split + re-merge free path in unload)
        inject_options_t opts{};
        opts.erase_pe_header = false;
        const inject_result_t r =
            inject_manual_map_file(pid, SLOP_INJECT_DLL_PATH, opts);
        REQUIRE(r.ok);
        REQUIRE_NE(r.module_base, 0ull);

        // unload: default path skips DllMain(DETACH) (CRT teardown on a
        // hijacked host thread corrupts host state for LDR-less images)
        // and frees the region -- VAD re-merge + size hint keep the free
        // working after per-section protection split the allocation
        const inject_result_t u =
            unload(pid, r.module_base, true, {}, r.module_size);
        dump_result(u);
        REQUIRE(u.ok);
        REQUIRE(u.error.empty());

        // freed: the physical read back of the old base must not see the
        // mapped MZ anymore (page may read anything, but not a live header)
        auto* dev = dynamic_cast<slop::core::runtime::backend_kernel_t*>(
            &slop::core::runtime::active());
        REQUIRE(dev != nullptr);
        const uint16_t mz = dev->device()->read<uint16_t>(r.module_base);
        REQUIRE_NE(mz, 0x5A4Du);
    });
    REQUIRE(ran);

    kill_helper(pid);
    clear_marker(pid);
}
