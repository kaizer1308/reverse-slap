// src/core/emu/insn.cpp

#include "core/emu/insn.hpp"

namespace slop::core::emu {

namespace {

using dest_mode_t  = taint_tracker_t::dest_mode_t;
using store_mode_t = taint_tracker_t::store_mode_t;

bool is_vector_reg(ZydisRegister r) {
    const ZydisRegisterClass cls = ZydisRegisterGetClass(r);
    return cls == ZYDIS_REGCLASS_XMM || cls == ZYDIS_REGCLASS_YMM ||
           cls == ZYDIS_REGCLASS_ZMM;
}

// Instructions whose result is the same whatever the register held
bool is_zeroing_idiom(const ZydisDecodedInstruction& zin, const ZydisDecodedOperand* ops) {
    switch (zin.mnemonic) {
    case ZYDIS_MNEMONIC_XOR:   case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_PXOR:  case ZYDIS_MNEMONIC_XORPS:  case ZYDIS_MNEMONIC_XORPD:
    case ZYDIS_MNEMONIC_VPXOR: case ZYDIS_MNEMONIC_VXORPS: case ZYDIS_MNEMONIC_VXORPD:
    case ZYDIS_MNEMONIC_PSUBB: case ZYDIS_MNEMONIC_PSUBW:
    case ZYDIS_MNEMONIC_PSUBD: case ZYDIS_MNEMONIC_PSUBQ:
    case ZYDIS_MNEMONIC_PCMPEQB: case ZYDIS_MNEMONIC_PCMPEQW:
    case ZYDIS_MNEMONIC_PCMPEQD: case ZYDIS_MNEMONIC_PCMPEQQ:
        break;
    default:
        return false;
    }
    const uint8_t n = zin.operand_count_visible;
    if (n < 2 || n > 3) return false;
    // the two sources: both operands, or the last two of a VEX form
    const auto& a = ops[n - 2];
    const auto& b = ops[n - 1];
    return a.type == ZYDIS_OPERAND_TYPE_REGISTER && b.type == ZYDIS_OPERAND_TYPE_REGISTER &&
           a.reg.value == b.reg.value;
}

} // namespace

// F2/F3 on movs, cmps, stos, lods, scas, ins, outs: the code hook fires once
// per iteration of these
bool is_rep_string(const uint8_t* bytes, size_t n) {
    bool rep = false;
    for (size_t i = 0; i < n; ++i) {
        const uint8_t b = bytes[i];
        if (b == 0xF2 || b == 0xF3) { rep = true; continue; }
        if (b == 0xF0 || b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 ||
            b == 0x64 || b == 0x65 || b == 0x66 || b == 0x67 || (b & 0xF0) == 0x40)
            continue;                                   // other prefixes, REX
        return rep && ((b >= 0xA4 && b <= 0xA7) || (b >= 0xAA && b <= 0xAF) ||
                       (b >= 0x6C && b <= 0x6F));
    }
    return false;
}

// Unicorn's x86 core predates AVX. It rejects 256-bit forms, but it runs a
// VEX.128 instruction as its legacy SSE twin: the first source register
// (vvvv) is ignored and the destination is used in its place, so
// `vpxor xmm0, xmm1, xmm2` computes xmm0 ^ xmm2. That only matches when the
// two are the same register. Opmask instructions decode as unrelated legacy
// opcodes (kmovw is setb). BMI's VEX forms on general registers are right
bool vex_miscomputed(const ZydisDecodedInstruction& zin, const ZydisDecodedOperand* ops) {
    if (zin.encoding != ZYDIS_INSTRUCTION_ENCODING_VEX) return false;
    if (zin.mnemonic == ZYDIS_MNEMONIC_VZEROALL) return true;   // runs as emms
    const ZydisDecodedOperand* nds = nullptr;
    bool vector = false;
    for (uint8_t i = 0; i < zin.operand_count_visible; ++i) {
        const auto& op = ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            if (ZydisRegisterGetClass(op.reg.value) == ZYDIS_REGCLASS_MASK) return true;
            vector = vector || is_vector_reg(op.reg.value);
        }
        if (op.encoding == ZYDIS_OPERAND_ENCODING_IS4) return true;   // implicit xmm0 in SSE
        if (op.encoding == ZYDIS_OPERAND_ENCODING_NDSNDD) nds = &op;
    }
    if (!vector || !nds) return false;      // BMI, or a two-operand form
    if (zin.raw.vex.L) return false;        // 256-bit raises #UD, nothing silent
    if (zin.operand_count_visible < 2) return true;
    // dst, vvvv, src normally; vvvv, src, imm for the shift-by-immediate group
    const auto& twin = nds == &ops[0] ? ops[1] : ops[0];
    return !(twin.type == ZYDIS_OPERAND_TYPE_REGISTER && twin.reg.value == nds->reg.value);
}

// Sort one instruction's operands into taint sources and destinations.
// Registers that only do bookkeeping are left out: the stack pointer of a
// push/pop/call/ret and the pointers and count of a string instruction are
// never data, and treating them as such taints everything that follows
taint_tracker_t::insn_sources_t taint_sources(const taint_tracker_t& t,
                                              const ZydisDecodedInstruction& zin,
                                              const ZydisDecodedOperand* ops) {
    taint_tracker_t::insn_sources_t src;
    const bool string_op = zin.meta.category == ZYDIS_CATEGORY_STRINGOP ||
                           zin.meta.category == ZYDIS_CATEGORY_IOSTRINGOP;

    auto add_dest = [&src](uint32_t canon, dest_mode_t mode, bool value = false) {
        // the flags change on nearly every instruction, they are tracked
        // but not worth an event each
        src.dests.push_back({canon, mode, value,
                             canon == ZYDIS_REGISTER_RFLAGS ? std::string()
                                                            : taint_reg_name(canon)});
    };

    if (zin.mnemonic == ZYDIS_MNEMONIC_XCHG && zin.operand_count_visible == 2) {
        const auto& a = ops[0];
        const auto& b = ops[1];
        const bool narrow = a.size < 32;   // the rest of the register keeps its taint
        if (a.type == ZYDIS_OPERAND_TYPE_REGISTER && b.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const uint32_t ca = taint_canonical_reg(a.reg.value);
            const uint32_t cb = taint_canonical_reg(b.reg.value);
            if (ca && cb && ca != cb) {
                const bool ta = t.reg(ca), tb = t.reg(cb);
                add_dest(ca, dest_mode_t::set, narrow ? ta || tb : tb);
                add_dest(cb, dest_mode_t::set, narrow ? ta || tb : ta);
            }
            return src;
        }
        // register <-> memory: each side takes only what the other held
        const auto& r = a.type == ZYDIS_OPERAND_TYPE_REGISTER ? a : b;
        if (r.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const uint32_t cr = taint_canonical_reg(r.reg.value);
            src.reads_memory     = true;
            src.src_regs_tainted = t.reg(cr);
            src.store            = store_mode_t::regs;
            if (cr) add_dest(cr, narrow ? dest_mode_t::mem_weak : dest_mode_t::mem);
            return src;
        }
    }

    for (uint8_t i = 0; i < zin.operand_count; ++i) {
        // Full operand list: includes implicit GPRs (div/mul rax:rdx, the
        // flags) so coarse register taint stays faithful
        const auto& op = ops[i];
        const bool hidden = op.visibility == ZYDIS_OPERAND_VISIBILITY_HIDDEN;
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER) {
            const uint32_t canon = taint_canonical_reg(op.reg.value);
            if (!canon) continue;
            if (hidden && canon == ZYDIS_REGISTER_RSP) continue;
            if (hidden && string_op &&
                (canon == ZYDIS_REGISTER_RSI || canon == ZYDIS_REGISTER_RDI ||
                 canon == ZYDIS_REGISTER_RCX))
                continue;
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                src.src_regs_tainted |= t.reg(canon);
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) {
                // a conditional write may keep the old value, and an 8/16-bit
                // one keeps the rest of the register
                const bool keeps_old =
                    !(op.actions & ZYDIS_OPERAND_ACTION_WRITE) ||
                    (op.size < 32 && canon != ZYDIS_REGISTER_RFLAGS);
                add_dest(canon, keeps_old ? dest_mode_t::weak : dest_mode_t::flow);
            }
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.mem.type == ZYDIS_MEMOP_TYPE_AGEN) {
                // lea computes with its base and index, they are data here
                src.src_regs_tainted |= t.reg(taint_canonical_reg(op.mem.base)) ||
                                        t.reg(taint_canonical_reg(op.mem.index));
            } else if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) {
                src.reads_memory = true;
            }
        }
    }

    if (zin.mnemonic == ZYDIS_MNEMONIC_CALL) {
        src.store = store_mode_t::never;   // the pushed return address
    } else if (zin.mnemonic == ZYDIS_MNEMONIC_LEAVE) {
        // rbp comes off the stack, the frame pointer it held is not a source
        for (auto& d : src.dests) d.mode = dest_mode_t::mem;
    } else if (is_zeroing_idiom(zin, ops)) {
        // a partial write (xor al,al) still keeps the rest of the register
        src.src_regs_tainted = false;
        for (auto& d : src.dests)
            if (d.mode == dest_mode_t::flow) d.mode = dest_mode_t::clear;
    }
    return src;
}

} // namespace slop::core::emu
