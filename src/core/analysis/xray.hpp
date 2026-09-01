#pragma once

// the static analysis battery, cfg, complexity, obfuscation patterns,
// string recon, hooks, syscalls, api hashes, entropy, page classes,
// gadgets and crypto, pure bytes in structs out

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"

namespace slop::core::analysis::xray {

struct image_ref_t {
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    uint64_t                    base = 0;              // VA base of the session
    disasm::engine_t*           eng  = nullptr;
    const disasm::function_index_t* fns = nullptr;    // optional (hooks/gadgets)
};

// shared decode helpers

// function extent containing a va from the index, 0 when not indexed,
// bounds per function analysis so a linear decode cant run through rets
uint64_t function_bound(const image_ref_t& img, uint64_t va);

// Linear-decode up to `max` instructions from va. `end_va` (when non-zero)
// is a hard stop: decoding never crosses it
std::vector<disasm::insn_t> decode_range(const image_ref_t& img,
                                         uint64_t va, size_t max,
                                         uint64_t end_va = 0);

// CFG

struct block_t {
    uint64_t start = 0, end = 0;         // end exclusive
    size_t   instructions = 0;
    std::vector<uint64_t> successors;
};

struct cfg_result_t {
    bool ok = false;
    std::string error;
    std::vector<block_t> blocks;
    size_t   edge_count = 0;
    size_t   back_edges = 0;
    uint64_t cyclomatic = 0;
    bool     truncated  = false;
};

cfg_result_t build_cfg(const image_ref_t& img, uint64_t fn_va,
                       size_t max_blocks = 200);

// complexity

struct complexity_result_t {
    size_t instruction_count = 0;
    size_t basic_block_count = 0;
    size_t edge_count        = 0;
    uint64_t cyclomatic      = 0;
    size_t call_count = 0, branch_count = 0, return_count = 0;
    size_t arithmetic_ops = 0, memory_accesses = 0, string_operations = 0;
    size_t unique_operators = 0, unique_operands = 0;
    const char* rating = "";             // simple..extremely_complex
};

complexity_result_t function_complexity(const image_ref_t& img, uint64_t fn_va);

// obfuscation

struct pattern_hit_t {
    std::string type;                    // nop_sled|opaque_predicate|indirect_jump|
                                         // push_ret|dead_head
    uint64_t    address = 0;
    std::string detail;
};

struct obfuscation_result_t {
    std::vector<pattern_hit_t> patterns;
    size_t opaque_predicates = 0, dead_heads = 0, junk_sequences = 0;
    size_t indirect_jumps = 0, push_ret = 0;
    int    score_pct      = 0;
};

obfuscation_result_t detect_obfuscation(const image_ref_t& img, uint64_t fn_va);

// string decryption recon

struct string_cand_t {
    std::string type;                    // stack_string|xor_pattern
    uint64_t    address = 0;
    std::string reconstructed;           // stack strings only
    uint64_t    xor_key = 0;             // xor patterns only
    size_t      length  = 0;
};

std::vector<string_cand_t> string_decrypt_recon(const image_ref_t& img,
                                                uint64_t fn_va);

// indirect calls

struct indirect_call_t {
    uint64_t    address = 0;
    std::string text;
    std::string classification;          // vtable_call|function_pointer|register_call
    std::string base_register;           // vtable calls
    int64_t     offset = 0;              // vtable calls
    uint64_t    target = 0;              // resolved function pointers when possible
};

std::vector<indirect_call_t> indirect_calls(const image_ref_t& img,
                                            uint64_t fn_va);

// anti-analysis

struct detection_t {
    std::string type;                    // debug_api|vm_api|cpuid|rdtsc|int_trap|
                                         // vm_backdoor_port
    uint64_t    address = 0;
    std::string detail;
};

struct anti_analysis_result_t {
    std::vector<detection_t> detections;
    size_t anti_debug = 0, anti_vm = 0, timing_checks = 0, traps = 0;
    int    score_pct  = 0;
};

anti_analysis_result_t detect_anti_analysis(const image_ref_t& img,
                                            uint64_t fn_va);

// inline hooks

struct hook_hit_t {
    uint64_t    address = 0;
    std::string name;
    std::string hook_type;               // jmp_rel32|jmp_indirect_rip|mov_rax_jmp_rax|
                                         // push_ret|int3_prologue
    uint64_t    target = 0;
    std::string prologue_hex;
};

std::vector<hook_hit_t> detect_hooks(const image_ref_t& img,
                                     size_t max_functions = 500);

// direct syscalls

struct syscall_hit_t {
    uint64_t address = 0;
    uint32_t ssn     = 0;
    std::string pattern;                 // mov_r10_rcx|mov_eax_syscall|int_2e
};

std::vector<syscall_hit_t> detect_syscalls(const image_ref_t& img,
                                           uint64_t va, size_t size);

// API hashing

// Hash one API name (optionally "DLL!API" composite) with the named scheme
// Returns 0 for unknown algorithm names
uint32_t hash_api(std::string_view name, std::string_view algo,
                  bool include_dll_name);

struct api_hash_hit_t {
    uint64_t    hash = 0;
    std::string api, dll;
};

// Dictionary attack: hash every import (and dll!import composite) and report
// which queried hashes hit
std::vector<api_hash_hit_t> resolve_api_hashes(const image_ref_t& img,
                                               const std::vector<uint64_t>& hashes,
                                               const std::string& algo);

// entropy

double shannon_entropy(const uint8_t* data, size_t len);

struct window_entropy_t {
    uint64_t    offset = 0;              // relative to scan start
    double      entropy = 0;
    const char* verdict = "";
};

struct entropy_result_t {
    double overall = 0, min_window = 0, max_window = 0;
    std::vector<window_entropy_t> windows;
    const char* verdict = "";
    bool truncated = false;
};

entropy_result_t entropy_scan(const image_ref_t& img, uint64_t va,
                              size_t size, size_t window = 256);

// page classification

struct page_class_t {
    uint64_t    address = 0;
    size_t      size    = 0;
    const char* klass   = "";
    double entropy = 0, insn_ratio = 0, zero_ratio = 0, string_ratio = 0;
};

std::vector<page_class_t> classify_pages(const image_ref_t& img,
                                         uint64_t va, size_t size,
                                         size_t page_size = 4096);

// control-flow flattening

struct cff_state_block_t {
    uint64_t start = 0, end = 0;
    bool     has_next = false;
    int64_t  next_state = 0;
    uint64_t assign_addr = 0;
};

struct cff_result_t {
    bool   flattened = false;
    size_t block_count = 0;
    uint64_t dispatcher = 0;
    size_t   dispatcher_backedges = 0;
    bool     has_state_var = false;
    std::string state_var_desc;          // "reg:eax" or "mem:[...]"
    std::vector<cff_state_block_t> state_blocks;
};

cff_result_t detect_cff(const image_ref_t& img, uint64_t fn_va);

// ROP gadgets

struct gadget_t {
    uint64_t    address = 0;             // VA of the gadget's first instruction
    std::string text;                    // "ret" / "pop rcx ; ret" .
};

std::vector<gadget_t> rop_gadgets(const image_ref_t& img,
                                  size_t limit = 200,
                                  size_t max_gadget_len = 5);

// crypto constant hunt (ranged)

struct crypto_hit_t {
    uint64_t    va = 0;
    std::string algorithm, constant_name;
    uint64_t    value = 0;
    const char* source = "";             // immediate | data
};

std::vector<crypto_hit_t> crypto_range_bytes(uint64_t base_va,
                                             const uint8_t* data, size_t len,
                                             const disasm::engine_t* eng,
                                             size_t limit);

std::vector<crypto_hit_t> crypto_range(const image_ref_t& img,
                                       uint64_t va, size_t size, size_t limit);

} // namespace slop::core::analysis::xray
