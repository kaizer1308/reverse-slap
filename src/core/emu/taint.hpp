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
    bool     memory_any(uint64_t addr, size_t len) const;

    // Register taint keyed by canonical GP register id
    // (see taint_canonical_reg below; 0 = not trackable)
    void     set_reg(uint64_t canonical, bool tainted);
    bool     reg(uint64_t canonical) const;

    // propagation driver

    // Call before decoding each new instruction (pre-exec)
    void boundary();

    // Decode-time inputs for the CURRENT instruction (pre-exec)
    struct insn_sources_t {
        bool src_regs_tainted = false;   // any explicit/implicit GP source reg tainted
        bool reads_memory     = false;   // any source operand is memory
        struct deferred_dest_t {
            uint32_t    canonical = 0;
            bool        zeroing   = false;   // xor/sub r,r idiom -> forced untainted
            std::string name;                 // operand text for event reporting
        };
        std::vector<deferred_dest_t> dests;
    };
    void analyze(uint64_t ip, const std::string& text, const insn_sources_t& src);

    // Execution-time observations (mid-instruction)
    bool note_mem_read(uint64_t addr, size_t len);    // true if any byte tainted
    bool note_mem_write(uint64_t addr, size_t len);   // true if store is tainted

    // Report helpers
    void record_event(const taint_event_t& e);
    std::vector<taint_range_t> tainted_ranges(size_t max_ranges = 1024) const;
    const std::vector<taint_event_t>& events() const { return events_; }

private:
    static constexpr size_t kPageBits  = 4096;
    static constexpr size_t kPageBytes = kPageBits / 8;

    std::map<uint64_t, std::vector<uint8_t>> pages_;   // page -> bitmap
    std::map<uint64_t, bool> reg_taint_;
    bool read_flag_       = false;
    bool src_regs_tainted_ = false;
    insn_sources_t cur_{};
    uint64_t cur_ip_   = 0;
    std::string cur_text_;
    std::vector<taint_event_t> events_;
};

// Map a ZydisRegister value onto its canonical 64-bit GP register id
// Returns 0 for non-GP registers (SIMD, segment, debug, control...)
uint32_t taint_canonical_reg(uint32_t zydis_register);

} // namespace slop::core::emu
