#pragma once

// one shot x64 emulation over unicorn, map regions, seed registers, run
// with budget timeout and stop address, collect trace and taint,
// callers materialize the bytes so this stays source agnostic

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "core/emu/taint.hpp"

namespace slop::core::emu {

struct emu_mem_region_t {
    uint64_t             addr = 0;
    std::vector<uint8_t> bytes;
};

struct run_request_t {
    std::vector<uint8_t> code;                 // required, non-empty
    uint64_t code_base       = 0x400000;
    bool     entry_absolute  = false;          // false: entry is offset into code
    uint64_t entry           = 0;

    uint64_t stack_base      = 0x002FF000;
    size_t   stack_size      = 0x100000;
    bool     sp_set          = false;          // override initial RSP
    uint64_t sp              = 0;

    std::map<std::string, uint64_t> regs;      // "rax".."r15", "rip", "rflags"
    std::vector<emu_mem_region_t>   maps;      // extra data mappings

    uint64_t until_addr        = 0;            // stop-before address (0 = none)
    uint64_t max_instructions  = 100000;
    uint32_t timeout_ms        = 5000;

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
    std::string stopped_reason;   // return|until|count|timeout|invalid_mem|invalid_insn|cpu_exception

    uint64_t instructions = 0;
    std::map<std::string, uint64_t> regs;

    struct trace_entry_t { uint64_t ip = 0; std::string text; };
    std::vector<trace_entry_t> trace;

    struct write_entry_t { uint64_t ip = 0; uint64_t addr = 0; size_t len = 0; };
    std::vector<write_entry_t> writes;     // capped at 2048 entries
    size_t total_writes = 0;

    struct fault_t { uint64_t ip = 0; uint64_t addr = 0; std::string access; };
    std::optional<fault_t> fault;

    // Taint results (empty when no sources were marked)
    std::vector<taint_range_t> taint_ranges;
    std::vector<taint_event_t> taint_events;
    bool output_tainted = false;
};

run_result_t emulate_run(const run_request_t& req);

} // namespace slop::core::emu
