#pragma once

// byte granular taint over emulated memory plus a register taint set,
// pure module with no unicorn headers, session.cpp drives the
// propagation through boundary, analyze and the note calls

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace slop::core::emu {

struct taint_range_t {
    uint64_t addr = 0;
    size_t   len  = 0;
};

struct taint_event_t {
    uint64_t    ip = 0;
    std::string insn;
    std::string kind;      // "mem" | "reg"
    std::string target;    // human-readable destination
};

class taint_tracker_t {
public:
    void reset();

    // Memory shadow (byte-granular, page-backed)
    void     mark_memory(uint64_t addr, size_t len);
    void     clear_memory(uint64_t addr, size_t len);
    bool     memory_any(uint64_t addr, size_t len) const;
    // dst[i] takes src[i]'s taint, overlap safe (memmove semantics)
    void     copy_memory(uint64_t dst, uint64_t src, size_t len);

    // Register taint keyed by canonical register id
    // (see taint_canonical_reg below; 0 = not trackable)
    void     set_reg(uint64_t canonical, bool tainted);
    bool     reg(uint64_t canonical) const;

    // propagation driver

    // Call before decoding each new instruction (pre-exec)
    void boundary();

    // How one written register takes its taint when the instruction retires
    enum class dest_mode_t : uint8_t {
        flow,       // sources: tainted source registers or a tainted load
        weak,       // flow, on top of what it held (partial or conditional write)
        mem,        // a tainted load only (xchg reg,mem)
        mem_weak,   // mem, on top of what it held
        set,        // fixed at decode time (xchg reg,reg)
        clear,      // constant result (zeroing idioms)
    };
    // How the instruction's stores take their taint
    enum class store_mode_t : uint8_t {
        flow,       // tainted source registers or a tainted load
        regs,       // tainted source registers only (xchg mem,reg)
        never,      // the stored value is not data (call's return address)
    };

    // Decode-time inputs for the CURRENT instruction (pre-exec)
    struct insn_sources_t {
        bool src_regs_tainted = false;   // any data source register tainted
        bool reads_memory     = false;   // any source operand is memory
        store_mode_t store    = store_mode_t::flow;
        struct deferred_dest_t {
            uint32_t    canonical = 0;
            dest_mode_t mode      = dest_mode_t::flow;
            bool        value     = false;    // dest_mode_t::set
            std::string name;                 // register name for event reporting
        };
        std::vector<deferred_dest_t> dests;
    };
    void analyze(uint64_t ip, const std::string& text, const insn_sources_t& src);

    // Execution-time observations (mid-instruction)
    bool note_mem_read(uint64_t addr, size_t len);    // true if any byte tainted
    bool note_mem_write(uint64_t addr, size_t len);   // true if store is tainted

    // Report helpers
    static constexpr size_t kMaxEvents = 512;
    void record_event(const taint_event_t& e);
    std::vector<taint_range_t> tainted_ranges(size_t max_ranges = 1024) const;
    const std::vector<taint_event_t>& events() const { return events_; }

private:
    static constexpr size_t kPageBits  = 4096;
    static constexpr size_t kPageBytes = kPageBits / 8;

    bool byte(uint64_t addr) const;

    std::map<uint64_t, std::vector<uint8_t>> pages_;   // page -> bitmap
    std::map<uint64_t, bool> reg_taint_;
    bool read_flag_       = false;
    bool src_regs_tainted_ = false;
    insn_sources_t cur_{};
    uint64_t cur_ip_   = 0;
    std::string cur_text_;
    std::vector<taint_event_t> events_;
};

// Map a ZydisRegister value onto its canonical id: the 64-bit register for
// GPRs, RFLAGS for the flags, ZMMn for XMMn/YMMn/ZMMn.
// Returns 0 for everything else (x87/MMX, segment, debug, control, mask, IP)
uint32_t taint_canonical_reg(uint32_t zydis_register);

// "rax", "rflags", "xmm3"; "?" for an id taint_canonical_reg never returns
std::string taint_reg_name(uint32_t canonical);

} // namespace slop::core::emu
