#pragma once

// src/core/runtime/kernel_injector.hpp
// kernel-assisted dll injection over slopdrvr, keeps the user-mode side away
// from the target so kernel anticheats can't catch us on obregistercallbacks
// or the create-thread notify routes. every touch on the target rides ioctls:
// ZwAllocateVirtualMemory from kernel context, dtb physical writes, and a
// thread hijack that spoofs the return address.
//
// two modes:
//   loadlibrary  -> resolve LoadLibraryW in kernel32, thread-hijack it. still
//                   trips PsSetLoadImageNotifyRoutine (LoadImage callback), but
//                   the callstack from AC's view is a legit thread in the target
//   manual_map   -> full pe map (headers, sections, relocs, imports, tls,
//                   DllMain), no ldr, no LoadImage notify. optionally erase
//                   the pe header and re-protect sections for scan evasion
//
// helpers (find_module, resolve_export) also useful on their own from the
// inject mcp tool for target introspection

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::runtime::injector {

struct inject_options_t {
    // manual_map + loadlibrary: zero out MZ/DOS/NT after DllMain runs so
    // anticheat header scans don't catch the mapped image
    bool erase_pe_header = true;
    // manual_map: apply IMAGE_SECTION_HEADER->Characteristics via
    // NtProtectVirtualMemory so scans looking for RWX regions don't flag us
    bool protect_sections = true;
    // manual_map: run DllMain with DLL_PROCESS_ATTACH after imports resolve
    bool call_dllmain = true;
    // manual_map: run TLS callbacks (rare on non-CRT dlls; safe default on)
    bool call_tls_callbacks = true;
    // loadlibrary: unlink the module from PEB Ldr lists after LoadLibrary
    // returns, so hidden-module walks and CreateToolhelp module snapshots
    // don't see it
    bool unlink_peb = false;
    // unload of a manual-mapped image: call DllMain(DLL_PROCESS_DETACH)
    // before freeing. OFF by default -- the static CRT's detach path runs
    // per-thread teardown (_freeptd, FLS callbacks) on whichever host
    // thread the hijack landed on, and for an image with no LDR entry that
    // corrupts the host's CRT state nondeterministically. The memory free
    // alone is always safe.
    bool call_dllmain_detach = false;
    // total budget for the thread-hijack call primitive (per call)
    uint32_t call_timeout_ms = 8000;
};

struct inject_log_line_t {
    std::string stage;
    std::string message;
};

struct inject_result_t {
    bool                          ok = false;
    std::string                   error;
    std::string                   mode;                 // "loadlibrary" | "manual_map" | "helper"
    uint32_t                      pid = 0;
    uint64_t                      module_base = 0;
    uint64_t                      module_size = 0;
    uint64_t                      entry_point = 0;
    uint64_t                      dllmain_return = 0;   // LoadLibrary return, or DllMain return
    uint32_t                      imports_resolved = 0;
    uint32_t                      imports_failed = 0;
    uint32_t                      relocations_applied = 0;
    uint32_t                      sections_protected = 0;
    bool                          header_erased = false;
    bool                          peb_unlinked = false;
    std::vector<inject_log_line_t> log;
};

// Enumerate target PEB LDR, return base of module matching `name` (case
// insensitive, dot-suffix optional). Nullopt on miss or when driver is down.
std::optional<uint64_t> find_module_base(uint32_t pid, const std::string& name,
                                         std::string* error = nullptr);

// Resolve an export in the target by module name + export name. Combines
// find_module_base + driver resolve_export.
std::optional<uint64_t> resolve_export(uint32_t pid,
                                       const std::string& module_name,
                                       const std::string& export_name,
                                       std::string* error = nullptr);

// LoadLibraryW via kernel-side alloc + dtb write + thread hijack of a
// resident thread in the target. Returns the loaded module's base.
inject_result_t inject_loadlibrary(uint32_t pid, const std::wstring& dll_path,
                                   const inject_options_t& opts = {});

// Manual map: parses `dll_bytes` as PE64, maps into target via kernel alloc
// + dtb writes, applies relocs, resolves imports through the target's
// existing loaded modules (LoadLibrary'ing missing deps), optionally runs
// TLS callbacks and DllMain, then optionally re-protects sections and
// erases the PE header.
inject_result_t inject_manual_map(uint32_t pid,
                                  const std::vector<uint8_t>& dll_bytes,
                                  const inject_options_t& opts = {});

inject_result_t inject_manual_map_file(uint32_t pid,
                                       const std::string& dll_path,
                                       const inject_options_t& opts = {});

// Best-effort unload of a mapped DLL. For loadlibrary mode this resolves
// FreeLibrary in kernel32 and calls it. For manual-map bases we just call
// DllMain(base, DLL_PROCESS_DETACH, 1) then kernel-free. size_hint, when
// nonzero, is the mapped SizeOfImage from the inject result -- it lets the
// VAD re-merge (needed for the one-shot MEM_RELEASE after per-section
// protection split the allocation) work even when the target's header page
// has been trimmed out of the working set and the physical read fails.
inject_result_t unload(uint32_t pid, uint64_t module_base,
                       bool manual_mapped,
                       const inject_options_t& opts = {},
                       uint64_t size_hint = 0);

} // namespace slop::core::runtime::injector
