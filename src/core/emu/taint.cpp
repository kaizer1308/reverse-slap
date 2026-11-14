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

void taint_tracker_t::clear_memory(uint64_t addr, size_t len) {
    if (pages_.empty()) return;
    for (size_t i = 0; i < len; ++i) {
        const uint64_t a = addr + i;
        const auto it = pages_.find(a / kPageBits);
        if (it == pages_.end()) {
            // nothing on this page, skip to the next one
            const uint64_t left = kPageBits - (a % kPageBits);
            if (left > len - i) break;
            i += static_cast<size_t>(left) - 1;
            continue;
        }
        const size_t bit = static_cast<size_t>(a % kPageBits);
        it->second[bit >> 3] &= static_cast<uint8_t>(~(1u << (bit & 7)));
    }
}

bool taint_tracker_t::byte(uint64_t addr) const {
    const auto it = pages_.find(addr / kPageBits);
    if (it == pages_.end()) return false;
    const size_t bit = static_cast<size_t>(addr % kPageBits);
    return (it->second[bit >> 3] & (1u << (bit & 7))) != 0;
}

bool taint_tracker_t::memory_any(uint64_t addr, size_t len) const {
    if (pages_.empty()) return false;
    for (size_t i = 0; i < len; ++i)
        if (byte(addr + i)) return true;
    return false;
}

void taint_tracker_t::copy_memory(uint64_t dst, uint64_t src, size_t len) {
    if (dst == src || len == 0) return;
    if (pages_.empty()) return;   // nothing tainted anywhere, nothing to move
    auto put = [this](uint64_t a, bool t) {
        if (t) mark_memory(a, 1);
        else   clear_memory(a, 1);
    };
    if (dst < src || dst - src >= len) {
        for (size_t i = 0; i < len; ++i) put(dst + i, byte(src + i));
    } else {
        for (size_t i = len; i-- > 0;) put(dst + i, byte(src + i));
    }
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
    const bool loaded = cur_.reads_memory && read_flag_;
    for (const auto& d : cur_.dests) {
        const bool prev = reg(d.canonical);
        bool value = false;
        switch (d.mode) {
        case dest_mode_t::flow:     value = src_regs_tainted_ || loaded;         break;
        case dest_mode_t::weak:     value = prev || src_regs_tainted_ || loaded; break;
        case dest_mode_t::mem:      value = loaded;                              break;
        case dest_mode_t::mem_weak: value = prev || loaded;                      break;
        case dest_mode_t::set:      value = d.value;                             break;
        case dest_mode_t::clear:    value = false;                               break;
        }
        set_reg(d.canonical, value);
        if (value && !prev && !d.name.empty())
            record_event({cur_ip_, cur_text_, "reg", d.name});
    }
    // each instruction is resolved once: a boundary with no analyze in
    // between (untraceable bytes, an import stub) must not replay it
    cur_ = {};
    src_regs_tainted_ = false;
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
    switch (cur_.store) {
    case store_mode_t::never: return false;
    case store_mode_t::regs:  return src_regs_tainted_;
    case store_mode_t::flow:  break;
    }
    // A store is tainted when the instruction consumed tainted memory or any
    // of its source registers carried taint into the stored value
    return read_flag_ || src_regs_tainted_;
}

void taint_tracker_t::record_event(const taint_event_t& e) {
    if (events_.size() < kMaxEvents) events_.push_back(e);
}

std::vector<taint_range_t> taint_tracker_t::tainted_ranges(size_t max_ranges) const {
    std::vector<taint_range_t> out;
    uint64_t run_start = 0, run_end = 0;   // [run_start, run_end)
    bool     in_run    = false;
    auto close = [&] {
        if (in_run && out.size() < max_ranges)
            out.push_back({run_start, static_cast<size_t>(run_end - run_start)});
        in_run = false;
    };
    for (const auto& [page, bm] : pages_) {
        const uint64_t page_base = page * kPageBits;
        // a run only carries over from the page right before this one
        if (in_run && run_end != page_base) close();
        for (size_t bit = 0; bit < kPageBits; ++bit) {
            if ((bit & 7) == 0 && bm[bit >> 3] == 0) {   // whole byte clear
                close();
                bit += 7;
                continue;
            }
            const bool t = (bm[bit >> 3] & (1u << (bit & 7))) != 0;
            const uint64_t addr = page_base + bit;
            if (t) {
                if (!in_run) { run_start = addr; in_run = true; }
                run_end = addr + 1;
            } else {
                close();
            }
        }
        if (out.size() >= max_ranges) return out;
    }
    close();
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
    if (r == ZYDIS_REGISTER_FLAGS || r == ZYDIS_REGISTER_EFLAGS ||
        r == ZYDIS_REGISTER_RFLAGS)
        return ZYDIS_REGISTER_RFLAGS;
    // XMMn, YMMn and ZMMn are views of one register
    if (r >= ZYDIS_REGISTER_XMM0 && r <= ZYDIS_REGISTER_XMM31)
        return ZYDIS_REGISTER_ZMM0 + (r - ZYDIS_REGISTER_XMM0);
    if (r >= ZYDIS_REGISTER_YMM0 && r <= ZYDIS_REGISTER_YMM31)
        return ZYDIS_REGISTER_ZMM0 + (r - ZYDIS_REGISTER_YMM0);
    if (r >= ZYDIS_REGISTER_ZMM0 && r <= ZYDIS_REGISTER_ZMM31)
        return r;
    return 0;
}

std::string taint_reg_name(uint32_t canonical) {
    switch (canonical) {
    case ZYDIS_REGISTER_RAX: return "rax";
    case ZYDIS_REGISTER_RCX: return "rcx";
    case ZYDIS_REGISTER_RDX: return "rdx";
    case ZYDIS_REGISTER_RBX: return "rbx";
    case ZYDIS_REGISTER_RSP: return "rsp";
    case ZYDIS_REGISTER_RBP: return "rbp";
    case ZYDIS_REGISTER_RSI: return "rsi";
    case ZYDIS_REGISTER_RDI: return "rdi";
    case ZYDIS_REGISTER_RFLAGS: return "rflags";
    default: break;
    }
    if (canonical >= ZYDIS_REGISTER_R8 && canonical <= ZYDIS_REGISTER_R15)
        return "r" + std::to_string(8 + (canonical - ZYDIS_REGISTER_R8));
    if (canonical >= ZYDIS_REGISTER_ZMM0 && canonical <= ZYDIS_REGISTER_ZMM31)
        return "xmm" + std::to_string(canonical - ZYDIS_REGISTER_ZMM0);
    return "?";
}

} // namespace slop::core::emu
