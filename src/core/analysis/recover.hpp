#pragma once

// unicorn backed recovery, cff dispatcher maps, opaque predicate proofs
// over seeded runs, invariants from registers that never move

#include <cstdint>
#include <string>
#include <vector>

#include "core/analysis/xray.hpp"

namespace slop::core::analysis::recover {

// flattening recovery

struct state_edge_t {
    int64_t  state  = 0;                 // dispatcher comparison value / table index
    uint64_t target = 0;                 // real basic-block entered for this state
};

struct recovery_result_t {
    bool        ok = false;
    std::string error;
    bool        flattened = false;
    uint64_t    fn_va = 0;
    uint64_t    dispatcher = 0;
    std::string mode;                    // cmp_chain | jump_table | none
    std::vector<state_edge_t> dispatch_map;
    size_t      blocks = 0;
    size_t      fake_edges = 0;          // static back-edges into the dispatcher
    size_t      real_edges_recovered = 0;
    // Emulation corroboration
    bool   corroborated = false;         // dispatcher reached during sampled runs
    size_t runs = 0;
    size_t dispatcher_entries_observed = 0;
    std::string note;
};

recovery_result_t recover_flattened(const xray::image_ref_t& img,
                                    uint64_t fn_va, size_t runs = 4);

// opaque predicate proof

struct predicate_proof_t {
    uint64_t    jcc_va = 0;
    std::string text;
    bool        static_idiom = false;    // xor r,r / test r,r immediately prior
    int         taken_runs = 0;          // runs where the branch was observed taken
    int         seen_runs = 0;           // runs where the branch executed at all
    int         total_runs = 0;
    bool        proven_always_taken = false;
    bool        proven_never_taken = false;
};

std::vector<predicate_proof_t> prove_predicates(const xray::image_ref_t& img,
                                                uint64_t fn_va, size_t runs = 4);

// invariant observation

struct invariant_t {
    std::string reg;
    uint64_t    value = 0;
};

struct invariant_result_t {
    bool        ok = false;
    std::string error;
    size_t      instructions_executed = 0;
    std::string stopped_reason;
    std::vector<invariant_t> invariants;
};

invariant_result_t observe_invariants(const xray::image_ref_t& img,
                                      uint64_t fn_va, size_t runs = 4);

// IAT audit (post-unpack import healing report)

// Scan a data range for pointer-sized IAT slots: each qword landing in an
// executable section is checked against the parsed import table. Named
// slots confirm existing imports; valid-but-unnamed slots are healing
// candidates (their targets decode as code/thunks but carry no name)
struct iat_slot_t {
    uint64_t    slot_va = 0;
    uint64_t    target = 0;
    std::string name;                 // empty when unresolved
};

struct iat_audit_result_t {
    bool        ok = false;
    std::string error;
    size_t      slots_scanned = 0;
    size_t      named = 0;
    size_t      unnamed_valid = 0;
    size_t      invalid = 0;
    std::vector<iat_slot_t> unnamed;   // capped sample of healing candidates
};

iat_audit_result_t iat_audit(const xray::image_ref_t& img,
                             uint64_t scan_va = 0,          // 0 = all non-exec data sections
                             size_t scan_size = 1u << 20);

} // namespace slop::core::analysis::recover
