// src/core/disasm/hyperion_session.hpp
// the bridge between the vendored hyperion engine and our disasm stack
// analysis runs on its own thread and ready() only flips when its done so
// db reads after that never race a write, decompile is serialized because
// the pipeline objects are not re-entrant

#pragma once

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "core/disasm/engine.hpp"

#include "core/analysis/analyzer.h"
#include "core/decompiler/decompiler.h"
#include "core/loader/pe_loader.h"
#include "threading/worker_pool.h"

namespace slop::core::disasm::hyperion_session {

struct session_t {
    session_t();
    ~session_t();

    session_t(const session_t&)            = delete;
    session_t& operator=(const session_t&) = delete;

    // lifecycle

    // parse and analyze async on a private thread, base_override rebases the image
    bool start(const uint8_t* bytes, size_t len, uint64_t base_override);
    // Synchronous variant (tests / small images): runs on the caller thread
    bool start_sync(const uint8_t* bytes, size_t len, uint64_t base_override);
    // Re-run analysis from an in-memory (possibly patched) copy of the image
    void reanalyze(const std::vector<uint8_t>& patched_bytes);

    // cooperative cancel, flags the analyzer and waits for the worker to land
    void stop();

    // analysis landed but had to stop short of the whole image, see
    // analysis_insn_budget()
    bool        truncated() const;

    bool        ready() const { return ready_.load(std::memory_order_acquire); }
    // True while the background worker is running a pipeline (between
    // start()/reanalyze() and ready()/stop()/failure)
    bool        running() const;
    float       progress() const;
    std::string error() const;   // last analysis failure, "" when healthy

    // analysis results (only meaningful when ready())

    const hype::AnalysisDB&  db() const;       // analyzer_->db()
    hype::AnalysisDB&        db_mut();         // annotation merges (persist.hype_load)
    const hype::RTTIParser&  rtti() const;     // analyzer_->rtti_parser()
    const hype::PEImage&     image() const { return img_; }
    const hype::SignatureMatcher& signatures() const;

    // Containing function (any block spans va), or exact-entry lookup
    // function_at uses an interval index built once when analysis completes
    const hype::Function* function_at(uint64_t va) const;
    const hype::Function* function_entry(uint64_t va) const;

    // Decompile the function containing `va` to pseudo-C lines. Results are
    // cached per function entry and invalidated by reanalysis or renames
    bool decompile(uint64_t va, std::vector<hype::PseudoLine>& out,
                   std::string& err);

    // User renames to apply onto the AnalysisDB once analysis lands (names
    // the analyzer derives would otherwise clobber mid-analysis renames)
    void queue_names(const std::unordered_map<uint64_t, std::string>& names);

    // hyperion decode through the slop insn abi, lossless for everything
    // consumers read, operand flags are heuristic
    static insn_t convert(const hype::Insn& in);

    // One-shot decode of a raw buffer through the hyperion engine (x64)
    static bool decode(uint64_t va, const uint8_t* buf, size_t len,
                       insn_t& out);
    // Decode `count` instructions starting at va with 1-byte resync on bad
    // bytes (same contract as the old engine-based MCP path)
    static std::vector<insn_t> decode_range(uint64_t va, const uint8_t* buf,
                                             size_t len, size_t count);

private:
    void run_pipeline();          // caller: worker_ or start_sync
    void join_worker();
    bool begin(const uint8_t* bytes, size_t len, uint64_t base_override);
    void set_error(std::string msg);   // err_mu_-guarded
    void build_interval_index();       // after analysis completes
    void invalidate_decomp_cache();

    hype::WorkerPool pool_{4};    // analyzer-internal parallel sweeps
    hype::PEImage    img_;
    uint64_t         base_override_ = 0;
    std::unique_ptr<hype::Analyzer> analyzer_;

    // Immutable after ready_: sorted [start, end) block ranges → function
    struct BlockRange { uint64_t start; uint64_t end; const hype::Function* func; };
    std::vector<BlockRange> block_ranges_;

    // Decompile cache, keyed by function entry. Valid until reanalyze/queue_names
    std::unordered_map<uint64_t, std::vector<hype::PseudoLine>> decomp_cache_;
    std::atomic<uint64_t> decomp_cache_gen_{0};

    std::thread        worker_;
    mutable std::mutex start_mu_;   // serializes start/reanalyze/stop/dtor
    mutable std::mutex err_mu_;     // err_ is read cross-thread
    std::mutex         decomp_mu_;  // Decompiler pipeline not re-entrant
    std::mutex         pending_mu_; // pending_names_ (queue_names vs worker)
    std::unordered_map<uint64_t, std::string> pending_names_;
    std::atomic<bool>  ready_{false};
    std::atomic<bool>  running_{false};
    std::string        err_;        // written before ready_ flip / on failure
};

// Shared decode engine (thread-guarded; hyperion's Zydis decoder carries no
// cross-call state, but the C++ wrapper is cheap to lock)
hype::Disassembler& shared_decoder();

// How many instructions a single analysis may put in the database. The DB
// holds one record per instruction plus another per basic block, so a few
// hundred megabytes of code would need tens of gigabytes; past the budget the
// run stops descending and reports truncated() instead of thrashing.
//
// Derived from available RAM, floor 250K, ceiling 2M. SLOP_HYPERION_INSN_BUDGET
// overrides it (0 disables the cap entirely)
size_t analysis_insn_budget();

} // namespace slop::core::disasm::hyperion_session
