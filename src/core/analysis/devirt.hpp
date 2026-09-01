#pragma once

// the devirt pipeline over the loaded image, find the vm entry, classify
// handlers, trace it under unicorn, lift to il and render pseudocode

#include <cstdint>
#include <string>
#include <vector>

#include "core/analysis/xray.hpp"

namespace slop::core::analysis::devirt {

// identify

struct identify_result_t {
    bool        ok = false;
    std::string error;
    bool        likely_vm = false;
    int         confidence_pct = 0;
    uint64_t    fn_va = 0;
    uint64_t    dispatcher = 0;        // first indirect-jump site
    uint64_t    handler_table = 0;     // best table-base candidate
    uint32_t    table_entry_size = 0;  // probed 8 / 4 / 0 unknown
    size_t      indirect_jumps = 0;
    size_t      cmp_chain_len = 0;
};

identify_result_t identify(const xray::image_ref_t& img, uint64_t fn_va);

// handler classification

struct handler_t {
    uint32_t    opcode = 0;            // table slot index
    uint64_t    va = 0;
    std::string classification;        // vm_push .. vm_complex
    size_t      instruction_count = 0;
    std::vector<std::string> insns;    // decoded text (capped)
};

struct classify_result_t {
    bool        ok = false;
    std::string error;
    uint64_t    handler_table = 0;
    uint32_t    entry_size = 0;
    std::vector<handler_t> handlers;
    size_t      valid_entries = 0;
};

classify_result_t classify_handlers(const xray::image_ref_t& img,
                                    uint64_t handler_table,
                                    uint32_t entry_size = 0,   // 0 = probe 8 then 4
                                    size_t max_handlers = 256);

const char* classify_handler_insns(const std::vector<disasm::insn_t>& insns);

// bytecode trace

struct trace_result_t {
    bool        ok = false;
    std::string error;
    std::string note;
    size_t      runs = 0;
    size_t      dispatcher_hits = 0;
    std::vector<uint32_t> bytecode;        // opcode slot sequence in execution order
    std::vector<uint64_t> handler_order;   // matching handler VAs
    std::string stopped_reason;
};

trace_result_t trace_bytecode(const xray::image_ref_t& img,
                              uint64_t entry_va, uint64_t dispatcher,
                              const std::vector<uint64_t>& handler_vas,
                              size_t max_ops = 512);

// lifting

struct lift_line_t {
    uint32_t    opcode = 0;
    uint64_t    handler_va = 0;
    std::string il;
};

struct lift_result_t {
    bool ok = false;
    std::string error;
    std::vector<lift_line_t> lines;
    size_t covered = 0;                 // ops mapped to a classification
};

lift_result_t lift(const trace_result_t& trace, const classify_result_t& cls);

std::string pseudocode(const lift_result_t& lifted);

} // namespace slop::core::analysis::devirt
