#pragma once

// mutating deobfuscation over the loaded session, nops, predicates, anti
// debug, xor and strings, every edit lands in the patch journal

#include <cstdint>
#include <string>
#include <vector>

#include "core/disasm/binary_state.hpp"

namespace slop::core::analysis::imgpatch {

struct patch_hit_t {
    uint64_t    va = 0;
    std::string action;                  // nop_fill|xor_eax|resolve_jmp|.
    std::string detail;
};

struct op_result_t {
    bool        ok = false;
    std::string error;
    std::vector<patch_hit_t> patches;    // what changed (or would change)
    bool     dry_run = false;
    uint64_t bytes_changed = 0;
    // Extras per op:
    uint64_t detected_key  = 0;
    double   key_confidence = 0.0;
    size_t   strings_found = 0;
};

// NOP out junk: nop sleds longer than threshold plus (aggressive) dead-code
// heads inside the function
op_result_t nop_junk(disasm::binary_state::binary_t& bin,
                     uint64_t fn_va, bool aggressive, size_t nop_threshold);

// Rewrite always/never-taken opaque predicate branches into unconditional
// jumps / nops. dry_run previews without touching bytes
op_result_t resolve_opaque_predicates(disasm::binary_state::binary_t& bin,
                                      uint64_t fn_va, bool dry_run);

// Neutralize anti-debug calls/traps/timing inside a function range
struct anti_debug_opts_t {
    bool patch_api_calls = true;
    bool patch_int_traps = true;
    bool patch_timing    = true;
};
op_result_t patch_anti_debug(disasm::binary_state::binary_t& bin,
                             uint64_t fn_va, const anti_debug_opts_t& opts,
                             bool dry_run);

// xor decrypt in place, auto tries every single byte key and scores
// common opcodes over the first 256 bytes
op_result_t unpack_xor(disasm::binary_state::binary_t& bin,
                       uint64_t va, size_t size, const std::string& method,
                       const std::string& key_hex);

// Recover stack strings / xor-encoded strings referenced by a function
op_result_t decode_strings(disasm::binary_state::binary_t& bin,
                           uint64_t fn_va);

// Raw byte write through the journal (revertible)
op_result_t write_bytes(disasm::binary_state::binary_t& bin,
                        uint64_t va, const std::vector<uint8_t>& bytes);

// Revert the whole patch journal (restores original bytes)
op_result_t revert_all(disasm::binary_state::binary_t& bin);

// the full pass, scores before and after, dry run previews everything
struct full_pass_result_t {
    bool        ok = false;
    std::string error;
    bool     dry_run = false;
    int      pre_score = 0, post_score = 0;
    size_t   strings_found = 0;
    uint64_t bytes_changed = 0;
    struct step_t { std::string name; bool success; std::string note; };
    std::vector<step_t> steps;
};

// Local obfuscation scorer (same weights as xray::detect_obfuscation)
int obfuscation_score(disasm::binary_state::binary_t& bin, uint64_t fn_va);

full_pass_result_t full_pass(disasm::binary_state::binary_t& bin,
                             uint64_t fn_va, bool dry_run);

// re decode after a patch so every byte is instructions again
struct rebuild_result_t {
    bool        ok = false;
    std::string error;
    size_t   instruction_count = 0;
    std::vector<std::pair<uint64_t, std::string>> insns;   // capped sample
};

rebuild_result_t rebuild(disasm::binary_state::binary_t& bin, uint64_t fn_va);

} // namespace slop::core::analysis::imgpatch
