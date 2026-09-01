// src/core/emu/taint.cpp

#include "core/emu/taint.hpp"

#include <Zydis/Zydis.h>

namespace slop::core::emu {

void taint_tracker_t::reset() {
    pages_.clear();
    reg_taint_.clear();
    read_flag_ = false;
    src_regs_tainted_ = false;
    cur_ = {};
    cur_ip_ = 0;
    cur_text_.clear();
    events_.clear();
}

void taint_tracker_t::mark_memory(uint64_t addr, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = addr + i;
        auto& bm = pages_[a / kPageBits];
        if (bm.empty()) bm.resize(kPageBytes, 0);
        const size_t bit = static_cast<size_t>(a % kPageBits);
        bm[bit >> 3] |= static_cast<uint8_t>(1u << (bit & 7));
    }
}

bool taint_tracker_t::memory_any(uint64_t addr, size_t len) const {
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = addr + i;
        const auto it = pages_.find(a / kPageBits);
        if (it == pages_.end()) continue;
        const size_t bit = static_cast<size_t>(a % kPageBits);
        if (it->second[bit >> 3] & (1u << (bit & 7))) return true;
    }
    return false;
}

void taint_tracker_t::set_reg(uint64_t canonical, bool tainted) {
    if (!canonical) return;
    reg_taint_[canonical] = tainted;
}

bool taint_tracker_t::reg(uint64_t canonical) const {
    if (!canonical) return false;
    const auto it = reg_taint_.find(canonical);
    return it != reg_taint_.end() && it->second;
}

void taint_tracker_t::boundary() {
    // Resolve the previous instruction's deferred destinations now that its
    // execution (and therefore its memory reads) are complete
    if (!cur_.dests.empty()) {
        const bool dest_taint =
            src_regs_tainted_ || (cur_.reads_memory && read_flag_);
        for (const auto& d : cur_.dests) {
            const bool value = d.zeroing ? false : dest_taint;
            const bool prev  = reg(d.canonical);
            set_reg(d.canonical, value);
            if (value && !prev && !d.name.empty()) {
                events_.push_back({cur_ip_, cur_text_, "reg", d.name});
                if (events_.size() >= 512) return;   // event cap
            }
        }
    }
    read_flag_ = false;
}

void taint_tracker_t::analyze(uint64_t ip, const std::string& text,
                              const insn_sources_t& src) {
    cur_ip_   = ip;
    cur_text_ = text;
    cur_ = src;
    src_regs_tainted_ = src.src_regs_tainted;
}

bool taint_tracker_t::note_mem_read(uint64_t addr, size_t len) {
    if (memory_any(addr, len)) {
        read_flag_ = true;
        return true;
    }
    return false;
}

bool taint_tracker_t::note_mem_write(uint64_t /*addr*/, size_t /*len*/) {
    // A store is tainted when the instruction consumed tainted memory or any
    // of its source registers carried taint into the stored value
    return read_flag_ || src_regs_tainted_;
}

void taint_tracker_t::record_event(const taint_event_t& e) {
    if (events_.size() < 512) events_.push_back(e);
}

std::vector<taint_range_t> taint_tracker_t::tainted_ranges(size_t max_ranges) const {
    std::vector<taint_range_t> out;
    uint64_t run_start = 0;
    bool     in_run    = false;
    for (const auto& [page_base, bm] : pages_) {
        for (size_t bit = 0; bit < kPageBits; ++bit) {
            const bool t = (bm[bit >> 3] & (1u << (bit & 7))) != 0;
            const uint64_t addr = page_base * kPageBits + bit;
            if (t && !in_run) { run_start = addr; in_run = true; }
            else if (!t && in_run) {
                if (out.size() >= max_ranges) return out;
                out.push_back({run_start, static_cast<size_t>(addr - run_start)});
                in_run = false;
            }
        }
    }
    if (in_run && out.size() < max_ranges)
        out.push_back({run_start, static_cast<size_t>(kPageBits)});
    return out;
}

uint32_t taint_canonical_reg(uint32_t r) {
    switch (static_cast<ZydisRegister>(r)) {
    case ZYDIS_REGISTER_AL: case ZYDIS_REGISTER_AH:
    case ZYDIS_REGISTER_AX: case ZYDIS_REGISTER_EAX:
    case ZYDIS_REGISTER_RAX:   return ZYDIS_REGISTER_RAX;
    case ZYDIS_REGISTER_CL: case ZYDIS_REGISTER_CH:
    case ZYDIS_REGISTER_CX: case ZYDIS_REGISTER_ECX:
    case ZYDIS_REGISTER_RCX:   return ZYDIS_REGISTER_RCX;
    case ZYDIS_REGISTER_DL: case ZYDIS_REGISTER_DH:
    case ZYDIS_REGISTER_DX: case ZYDIS_REGISTER_EDX:
    case ZYDIS_REGISTER_RDX:   return ZYDIS_REGISTER_RDX;
    case ZYDIS_REGISTER_BL: case ZYDIS_REGISTER_BH:
    case ZYDIS_REGISTER_BX: case ZYDIS_REGISTER_EBX:
    case ZYDIS_REGISTER_RBX:   return ZYDIS_REGISTER_RBX;
    case ZYDIS_REGISTER_SPL: case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_ESP: case ZYDIS_REGISTER_RSP:
                               return ZYDIS_REGISTER_RSP;
    case ZYDIS_REGISTER_BPL: case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_EBP: case ZYDIS_REGISTER_RBP:
                               return ZYDIS_REGISTER_RBP;
    case ZYDIS_REGISTER_SIL: case ZYDIS_REGISTER_SI:
    case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_RSI:
                               return ZYDIS_REGISTER_RSI;
    case ZYDIS_REGISTER_DIL: case ZYDIS_REGISTER_DI:
    case ZYDIS_REGISTER_EDI: case ZYDIS_REGISTER_RDI:
                               return ZYDIS_REGISTER_RDI;
    default: break;
    }
    // R8B..R15B, R8W..R15W and R8D..R15D are contiguous 8-entry blocks
    // immediately before R8..R15 in the Zydis register enum
    if (r >= ZYDIS_REGISTER_R8B && r <= ZYDIS_REGISTER_R15D) {
        static constexpr uint32_t kMap64[8] = {
            ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9,  ZYDIS_REGISTER_R10,
            ZYDIS_REGISTER_R11, ZYDIS_REGISTER_R12, ZYDIS_REGISTER_R13,
            ZYDIS_REGISTER_R14, ZYDIS_REGISTER_R15,
        };
        return kMap64[(r - ZYDIS_REGISTER_R8B) % 8];
    }
    if (r >= ZYDIS_REGISTER_R8 && r <= ZYDIS_REGISTER_R15)
        return r;
    if (r == ZYDIS_REGISTER_EFLAGS || r == ZYDIS_REGISTER_RFLAGS)
        return ZYDIS_REGISTER_RFLAGS;
    return 0;
}

} // namespace slop::core::emu
