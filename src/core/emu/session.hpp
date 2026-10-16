#pragma once

// one shot x64 emulation over unicorn, map regions, seed registers, run
// with budget timeout and stop address, collect trace and taint,
// callers materialize the bytes so this stays source agnostic

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "core/emu/taint.hpp"
#include "core/infra/cancel.hpp"

namespace slop::core::emu {

inline constexpr size_t kPageSize = 0x1000;

// Demand paging: asked for a 4 KiB page the code touches that nothing mapped.
// Fill out[kPageSize] and return true to map it and retry the access, false
// to let it fault. Runs on the emulation thread, off every tool lock
using page_source_t = std::function<bool(uint64_t page, uint8_t* out)>;

struct emu_mem_region_t {
    uint64_t             addr = 0;
    std::vector<uint8_t> bytes;
};

struct import_slot_t {
    uint64_t    slot = 0;      // IAT slot va, patched to point at a stub
    std::string name;          // "dll!func" or "dll!#ordinal"
    bool        has_ret = false;   // ret replaces api_ret for this import
    uint64_t    ret = 0;
};

// stub page holds one RET per import
inline constexpr size_t kMaxImports = 16384;

struct run_request_t {
    std::vector<uint8_t> code;                 // required, non-empty
    uint64_t code_base       = 0x400000;
    bool     entry_absolute  = false;          // false: entry is offset into code
    uint64_t entry           = 0;

    uint64_t stack_base      = 0x002FF000;
    size_t   stack_size      = 0x100000;
    bool     sp_set          = false;          // override initial RSP
    uint64_t sp              = 0;

    std::map<std::string, uint64_t> regs;      // "rax".."r15", "rip", "rflags", "fs_base", "gs_base"
    std::vector<emu_mem_region_t>   maps;      // extra data mappings

    // Pages nothing mapped come from here on first touch, so calls, jumps
    // and loads outside the code slice keep running. The pages the code
    // slice only partly covers are completed from it too
    page_source_t page_in;
    size_t        page_in_max = 4096;          // demand pages per run (16 MiB)

    // IAT slots redirected to stubs: a call through one is logged in
    // api_calls and returns api_ret in rax instead of faulting
    std::vector<import_slot_t> imports;        // <= kMaxImports
    uint64_t api_ret = 0;

    // A zeroed TEB/PEB is mapped at gs base (self, PEB, stack bounds, ids)
    // unless regs sets gs_base or the pages are taken; this fills
    // PEB.ImageBaseAddress
    uint64_t image_base = 0;

    // Memory read back after the run. Pages the run never touched come
    // from page_in, so a dump of an untouched global still has its bytes
    struct dump_range_t { uint64_t addr = 0; size_t len = 0; };
    std::vector<dump_range_t> dumps;

    uint64_t until_addr        = 0;            // stop-before address (0 = none)
    uint64_t max_instructions  = 100000;
    uint32_t timeout_ms        = 5000;         // clamped to kMaxTimeoutMs
    infra::cancel_token_t cancel;              // polled per instruction, stops with "cancelled"

    bool     trace             = false;
    size_t   trace_max         = 4096;

    // Taint: mark input ranges inside any mapped region before running
    struct taint_source_t { uint64_t addr = 0; size_t len = 0; };
    std::vector<taint_source_t> taint_sources;
    // Output window reported through output_tainted
    uint64_t watch_addr = 0;
    size_t   watch_len  = 0;
};

struct run_result_t {
    bool        ok = false;
    std::string error;
    std::string stopped_reason;   // return|until|count|timeout|cancelled|invalid_mem_*|invalid_insn|cpu_exception

    uint64_t instructions = 0;
    std::map<std::string, uint64_t> regs;

    struct trace_entry_t { uint64_t ip = 0; std::string text; };
    std::vector<trace_entry_t> trace;

    // value holds the stored bytes for len <= 8, 0 for wider stores
    struct write_entry_t { uint64_t ip = 0; uint64_t addr = 0; size_t len = 0; uint64_t value = 0; };
    std::vector<write_entry_t> writes;     // capped at 2048 entries
    size_t total_writes = 0;

    // ip is the call (or jmp) through the slot, ret the address it returns to
    struct api_call_t {
        uint64_t    ip = 0;
        uint64_t    ret = 0;
        std::string name;
        uint64_t    args[4] = {};          // rcx, rdx, r8, r9 at entry
    };
    std::vector<api_call_t> api_calls;     // capped at 1024 entries
    size_t total_api_calls = 0;

    size_t paged_in          = 0;          // demand pages mapped from page_in
    bool   page_in_exhausted = false;      // a fault was left standing at page_in_max
    bool   teb_mapped        = false;

    std::vector<emu_mem_region_t> memory;  // one per dump, cut at the first unreadable page

    struct fault_t { uint64_t ip = 0; uint64_t addr = 0; std::string access; };
    std::optional<fault_t> fault;

    // Taint results (empty when no sources were marked)
    std::vector<taint_range_t> taint_ranges;
    std::vector<taint_event_t> taint_events;
    bool output_tainted = false;
};

// Budget ceiling for one run. MCP clients commonly abort requests at 60 s,
// so a run plus result serialization has to finish well inside that window.
inline constexpr uint32_t kMaxTimeoutMs = 30000;

run_result_t emulate_run(const run_request_t& req);

} // namespace slop::core::emu
