#pragma once
#include "core/loader/pe_loader.h"
#include "core/disasm/disassembler.h"
#include "core/disasm/capstone_disasm.h"
#include "analysis_db.h"
#include "signatures.h"
#include "rtti.h"
#include "threading/worker_pool.h"
#include "threading/task_scheduler.h"
#include <atomic>
#include <unordered_set>

namespace hype {

class Analyzer {
public:
    Analyzer(PEImage& img, WorkerPool& pool);

    void run();
    void apply_signatures();
    float progress() const { return progress_.load(); }

    // Instruction ceiling for the descent phases, 0 for unlimited. An image
    // whose code section runs to hundreds of megabytes decodes to tens of
    // millions of instructions, and the DB keeps one record per instruction
    // plus another per basic block, so an unbounded run on such an image
    // exhausts memory long before it finishes. With a budget the run lands on
    // a smaller but coherent DB and says so through budget_reached()
    void set_insn_budget(size_t max_insns) { insn_budget_ = max_insns; }
    size_t insn_budget() const { return insn_budget_; }
    bool budget_reached() const { return budget_hit_.load(std::memory_order_relaxed); }

    // Cooperative cancellation: set from any thread; run() checks between
    // phases (and inside the big walks) and bails out leaving the DB
    // partially built. A cancelled run never reports ready.
    void request_cancel() {
        cancel_.store(true, std::memory_order_relaxed);
        cancel_shared_->store(true, std::memory_order_relaxed);
    }
    bool was_cancelled() const { return cancelled_.load(std::memory_order_relaxed); }

    AnalysisDB& db() { return db_; }
    const AnalysisDB& db() const { return db_; }
    SignatureMatcher& sig_matcher() { return sigmatch_; }
    const SignatureMatcher& sig_matcher() const { return sigmatch_; }
    RTTIParser& rtti_parser() { return rtti_; }
    const RTTIParser& rtti_parser() const { return rtti_; }

private:
    void linear_sweep();
    void merge_tentative();
    void recursive_descent();
    void detect_functions();
    void detect_thunks();
    // `only`, when set, restricts the pass to those function entries. The
    // fixed point uses it so later rounds touch just the functions whose CFG
    // actually changed instead of rebuilding the whole image every round
    void build_cfgs(const std::unordered_set<va_t>* only = nullptr);
    void discover_cfg_fixed_point();
    void remove_junk_code();
    void detect_switches(const std::unordered_set<va_t>* only = nullptr);
    void build_xrefs();
    void find_strings();
    void find_string_refs();
    void detect_vtables();
    void detect_globals();
    void apply_names();
    void detect_noreturn();
    void detect_tail_calls();
    void detect_calling_conventions();
    void detect_main();
    void propagate_dataflow(const std::unordered_set<va_t>* only = nullptr);
    void detect_loops();
    void recover_structs();
    void populate_data_sections();
    void propagate_interproc_types();

    void descend(va_t addr, std::unordered_set<va_t>& visited);
    bool over_budget();   // latches budget_hit_ the first time it trips
    const u8* va_to_ptr(va_t addr, size_t* max_len = nullptr);
    bool is_iat_addr(va_t addr) const;
    bool is_code_addr(va_t addr) const;
    bool in_section(va_t addr, const char* name) const;
    const Segment* section_for(va_t addr) const;

    // Address -> segment in log(segments) instead of a linear walk. The walk
    // showed up everywhere: once per decoded instruction in descend, once per
    // pointer slot across every data section in the vtable and data sweeps
    struct SegmentSpan {
        va_t           va;
        va_t           end;      // va + virtual size
        const Segment* seg;
        bool           executable;
    };
    void build_segment_index();
    const SegmentSpan* span_for(va_t addr) const;
    std::vector<SegmentSpan> segment_index_;   // sorted by va, non-overlapping

    bool use_capstone() const {
        return img_.arch != Arch::X86 && img_.arch != Arch::X64;
    }
    bool decode_insn(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_insn_range(va_t start, const u8* data, size_t len);

    PEImage&           img_;
    Disassembler       disasm_;
    CapstoneDisasm     cap_disasm_;
    AnalysisDB         db_;
    WorkerPool&        pool_;
    TaskScheduler      sched_;
    SignatureMatcher   sigmatch_;
    RTTIParser         rtti_;
    std::atomic<float> progress_{0.f};
    std::atomic<bool>  cancel_{false};
    std::atomic<bool>  cancelled_{false};
    size_t             insn_budget_ = 0;
    std::atomic<bool>  budget_hit_{false};
    // Shared with sweep workers so decode_range can probe cancellation.
    std::shared_ptr<std::atomic<bool>> cancel_shared_{std::make_shared<std::atomic<bool>>(false)};
    std::unordered_map<va_t, Insn> tentative_;
    std::unordered_map<va_t, std::vector<va_t>> recovered_edges_;
    // functions that gained an edge or a resolved target in the last round
    std::unordered_set<va_t> cfg_dirty_;
};

}
