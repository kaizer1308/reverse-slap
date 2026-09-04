#include "lifter.h"
#include "core/disasm/disassembler.h"
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <algorithm>

namespace hype {

[[maybe_unused]] static constexpr int REG_RAX = 0, REG_RCX = 1, REG_RDX = 2, REG_RBX = 3;
[[maybe_unused]] static constexpr int REG_RSP = 4, REG_RBP = 5, REG_RSI = 6, REG_RDI = 7;
[[maybe_unused]] static constexpr int REG_R8 = 8, REG_R9 = 9, REG_R10 = 10, REG_R11 = 11;
[[maybe_unused]] static constexpr int REG_R12 = 12, REG_R13 = 13, REG_R14 = 14, REG_R15 = 15;
static constexpr int REG_ZF = 100, REG_CF = 101, REG_SF = 102, REG_OF = 103;

static const struct { u16 zreg; const char* name; int id; int size; } kRegTable[] = {
    {ZYDIS_REGISTER_RAX,"rax",0,8},{ZYDIS_REGISTER_EAX,"eax",0,4},{ZYDIS_REGISTER_AX,"ax",0,2},{ZYDIS_REGISTER_AL,"al",0,1},
    {ZYDIS_REGISTER_RCX,"rcx",1,8},{ZYDIS_REGISTER_ECX,"ecx",1,4},{ZYDIS_REGISTER_CX,"cx",1,2},{ZYDIS_REGISTER_CL,"cl",1,1},
    {ZYDIS_REGISTER_RDX,"rdx",2,8},{ZYDIS_REGISTER_EDX,"edx",2,4},{ZYDIS_REGISTER_DX,"dx",2,2},{ZYDIS_REGISTER_DL,"dl",2,1},
    {ZYDIS_REGISTER_RBX,"rbx",3,8},{ZYDIS_REGISTER_EBX,"ebx",3,4},{ZYDIS_REGISTER_BX,"bx",3,2},{ZYDIS_REGISTER_BL,"bl",3,1},
    {ZYDIS_REGISTER_RSP,"rsp",4,8},{ZYDIS_REGISTER_ESP,"esp",4,4},
    {ZYDIS_REGISTER_RBP,"rbp",5,8},{ZYDIS_REGISTER_EBP,"ebp",5,4},
    {ZYDIS_REGISTER_RSI,"rsi",6,8},{ZYDIS_REGISTER_ESI,"esi",6,4},{ZYDIS_REGISTER_SIL,"sil",6,1},
    {ZYDIS_REGISTER_RDI,"rdi",7,8},{ZYDIS_REGISTER_EDI,"edi",7,4},{ZYDIS_REGISTER_DIL,"dil",7,1},
    {ZYDIS_REGISTER_R8,"r8",8,8},{ZYDIS_REGISTER_R8D,"r8d",8,4},{ZYDIS_REGISTER_R8W,"r8w",8,2},{ZYDIS_REGISTER_R8B,"r8b",8,1},
    {ZYDIS_REGISTER_R9,"r9",9,8},{ZYDIS_REGISTER_R9D,"r9d",9,4},{ZYDIS_REGISTER_R9W,"r9w",9,2},{ZYDIS_REGISTER_R9B,"r9b",9,1},
    {ZYDIS_REGISTER_R10,"r10",10,8},{ZYDIS_REGISTER_R10D,"r10d",10,4},
    {ZYDIS_REGISTER_R11,"r11",11,8},{ZYDIS_REGISTER_R11D,"r11d",11,4},
    {ZYDIS_REGISTER_R12,"r12",12,8},{ZYDIS_REGISTER_R12D,"r12d",12,4},
    {ZYDIS_REGISTER_R13,"r13",13,8},{ZYDIS_REGISTER_R13D,"r13d",13,4},
    {ZYDIS_REGISTER_R14,"r14",14,8},{ZYDIS_REGISTER_R14D,"r14d",14,4},
    {ZYDIS_REGISTER_R15,"r15",15,8},{ZYDIS_REGISTER_R15D,"r15d",15,4},
};

Varnode Lifter::reg_vn(u16 zreg, u16 bits) {
    for (auto& r : kRegTable)
        if (r.zreg == zreg) return vn_reg(r.id, r.name, r.size);
    int id = 50 + (zreg % 50);
    return vn_reg(id, "unk", bits / 8);
}

Varnode Lifter::alloc_temp(int sz) {
    return vn_temp(next_temp_++, sz);
}

void Lifter::emit(PcodeBlock& b, PcodeOp op, Varnode out, std::vector<Varnode> in, va_t a) {
    PcodeInsn p;
    p.op = op;
    p.output = out;
    p.inputs = std::move(in);
    p.addr = a ? a : cur_addr_;
    p.seq = cur_seq_++;
    b.ops.push_back(std::move(p));
}


Varnode Lifter::effective_address(const Operand& op, PcodeBlock& out, int access_size) {
    // Frame-relative accesses with no index become stack varnodes so the
    // emitter can declare locals instead of printing raw rbp/rsp arithmetic.
    if ((op.mem.base == ZYDIS_REGISTER_RBP || op.mem.base == ZYDIS_REGISTER_EBP ||
         op.mem.base == ZYDIS_REGISTER_RSP || op.mem.base == ZYDIS_REGISTER_ESP) &&
        (!op.mem.index || op.mem.index == ZYDIS_REGISTER_NONE)) {
        const int sz = access_size > 0 ? access_size / 8 : 8;
        Varnode var = vn_stack(op.mem.base == ZYDIS_REGISTER_RBP || op.mem.base == ZYDIS_REGISTER_EBP
                                   ? REG_RBP : REG_RSP,
                               op.mem.disp, sz < 1 ? 1 : sz);
        stack_vars_.push_back(var);
        return var;
    }

    if (op.val && (op.mem.base == ZYDIS_REGISTER_RIP || op.mem.base == ZYDIS_REGISTER_EIP))
        return vn_const(op.val);

    Varnode address = vn_const(0);
    bool has_address = false;
    if (op.mem.base && op.mem.base != ZYDIS_REGISTER_NONE) {
        address = reg_vn(op.mem.base, 64);
        has_address = true;
    }
    if (op.mem.index && op.mem.index != ZYDIS_REGISTER_NONE) {
        Varnode index = reg_vn(op.mem.index, 64);
        if (op.mem.scale > 1) {
            Varnode scaled = alloc_temp();
            emit(out, PcodeOp::INT_MULT, scaled, {index, vn_const(op.mem.scale)});
            index = scaled;
        }
        if (has_address) {
            Varnode sum = alloc_temp();
            emit(out, PcodeOp::ADD, sum, {address, index});
            address = sum;
        } else {
            address = index;
        }
        has_address = true;
    }
    if (op.mem.disp != 0) {
        Varnode displacement = vn_const(static_cast<u64>(op.mem.disp));
        if (has_address) {
            Varnode sum = alloc_temp();
            emit(out, PcodeOp::ADD, sum, {address, displacement});
            address = sum;
        } else {
            address = displacement;
        }
        has_address = true;
    }
    return has_address ? address : vn_const(op.val);
}

Varnode Lifter::operand_read(const Insn& insn, int idx, const AnalysisDB& /*db*/, PcodeBlock& out) {
    if (idx >= insn.op_count) return vn_const(0);
    auto& op = insn.ops[idx];
    switch (op.type) {
    case OpType::Reg:
        return reg_vn(op.reg, op.size);
    case OpType::Imm:
        return vn_const(op.val, op.size / 8 ? op.size / 8 : 8);
    case OpType::Mem: {
        Varnode addr = effective_address(op, out, op.size);
        int sz = op.size / 8;
        if (sz < 1) sz = 8;
        Varnode result = alloc_temp(sz);
        emit(out, PcodeOp::LOAD, result, {addr});
        return result;
    }
    default:
        return vn_const(0);
    }
}

void Lifter::operand_write(const Insn& insn, int idx, Varnode val, PcodeBlock& out) {
    if (idx >= insn.op_count) return;
    auto& op = insn.ops[idx];
    if (op.type == OpType::Reg) {
        Varnode dst = reg_vn(op.reg, op.size);

        // x64 sub-register writes must also update the full register:
        // 32-bit writes zero-extend; 8/16-bit writes preserve the upper bits.
        if (arch_ == Arch::X64 && op.size > 0 && op.size < 64 && dst.id >= 0 && dst.id < 16) {
            static const char* kFullNames[16] = {
                "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
                "r8","r9","r10","r11","r12","r13","r14","r15"
            };
            Varnode full = vn_reg(dst.id, kFullNames[dst.id], 8);
            if (op.size == 32) {
                emit(out, PcodeOp::COPY, dst, {val});
                Varnode extended = alloc_temp(8);
                emit(out, PcodeOp::INT_ZEXT, extended, {val});
                emit(out, PcodeOp::COPY, full, {extended});
            } else {
                // Read the full register BEFORE the sub-register write so the
                // preserved upper bits are the pre-write value; the full-register
                // COPY comes last so later reads observe the combined value.
                Varnode upper = alloc_temp(8 - val.size);
                emit(out, PcodeOp::SUBPIECE, upper, {full, vn_const(val.size, 8)});
                emit(out, PcodeOp::COPY, dst, {val});
                Varnode combined = alloc_temp(8);
                emit(out, PcodeOp::PIECE, combined, {upper, val});
                emit(out, PcodeOp::COPY, full, {combined});
            }
        } else {
            emit(out, PcodeOp::COPY, dst, {val});
        }
    } else if (op.type == OpType::Mem) {
        emit(out, PcodeOp::STORE, {}, {effective_address(op, out, op.size), val});
    }
}

void Lifter::emit_flags(const Insn& /*insn*/, Varnode lhs, Varnode rhs, PcodeBlock& out, bool is_test) {
    Varnode zf = vn_reg(REG_ZF, "ZF", 1);
    Varnode cf = vn_reg(REG_CF, "CF", 1);
    Varnode sf = vn_reg(REG_SF, "SF", 1);
    Varnode of_v = vn_reg(REG_OF, "OF", 1);

    if (is_test) {
        Varnode tmp = alloc_temp(lhs.size);
        emit(out, PcodeOp::AND, tmp, {lhs, rhs});
        emit(out, PcodeOp::INT_EQUAL, zf, {tmp, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_SLESS, sf, {tmp, vn_const(0, lhs.size)});
        emit(out, PcodeOp::COPY, cf, {vn_const(0, 1)});
        emit(out, PcodeOp::COPY, of_v, {vn_const(0, 1)});
    } else {
        Varnode diff = alloc_temp(lhs.size);
        emit(out, PcodeOp::SUB, diff, {lhs, rhs});
        emit(out, PcodeOp::INT_EQUAL, zf, {diff, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_SLESS, sf, {diff, vn_const(0, lhs.size)});
        emit(out, PcodeOp::INT_LESS, cf, {lhs, rhs});
        // OF = sign(lhs) != sign(rhs) && sign(result) != sign(lhs), expressed
        // without a sign-extract op: (lhs^rhs) & (lhs^diff) has the sign bit
        // set exactly when signed overflow occurred.
        Varnode x1 = alloc_temp(lhs.size);
        emit(out, PcodeOp::XOR, x1, {lhs, rhs});
        Varnode x2 = alloc_temp(lhs.size);
        emit(out, PcodeOp::XOR, x2, {lhs, diff});
        Varnode both = alloc_temp(lhs.size);
        emit(out, PcodeOp::AND, both, {x1, x2});
        emit(out, PcodeOp::INT_SLESS, of_v, {both, vn_const(0, lhs.size)});
    }
}

// Condition code extracted from the mnemonic tail ("j" and "set" share it).
enum class CondKind {
    ZF, NZF, CF, NCF, LT, GE, LE, GT, BE, A, SF, NSF, OF, NOF, UNKNOWN
};

// Condition code from the Zydis mnemonic id. Analysis builds skip operand
// text (and the mnemonic string is only the enum name), so the lifter must
// not depend on the formatted string. Zydis canonicalizes each condition to
// one spelling (JZ, JB, ...), so no alias handling is needed. Parity
// (jp/jnp) and cxz/loop forms have no flag model and stay UNKNOWN, matching
// the old string parser.
static CondKind cond_kind_from_id(u16 mnemonic_id) {
    switch (static_cast<ZydisMnemonic>(mnemonic_id)) {
    case ZYDIS_MNEMONIC_JZ: case ZYDIS_MNEMONIC_SETZ:
        return CondKind::ZF;
    case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_SETNZ:
        return CondKind::NZF;
    case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_SETB:
        return CondKind::CF;
    case ZYDIS_MNEMONIC_JNB: case ZYDIS_MNEMONIC_SETNB:
        return CondKind::NCF;
    case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_SETL:
        return CondKind::LT;
    case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_SETNL:
        return CondKind::GE;
    case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_SETLE:
        return CondKind::LE;
    case ZYDIS_MNEMONIC_JNLE: case ZYDIS_MNEMONIC_SETNLE:
        return CondKind::GT;
    case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_SETBE:
        return CondKind::BE;
    case ZYDIS_MNEMONIC_JNBE: case ZYDIS_MNEMONIC_SETNBE:
        return CondKind::A;
    case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_SETS:
        return CondKind::SF;
    case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_SETNS:
        return CondKind::NSF;
    case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_SETO:
        return CondKind::OF;
    case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_SETNO:
        return CondKind::NOF;
    default:
        return CondKind::UNKNOWN;
    }
}

static CondKind cond_kind(const char* mn) {
    const char* c = mn;
    if ((c[0] == 'j' || c[0] == 'J') ||
        (c[0] == 's' && c[1] == 'e' && c[2] == 't'))
        c += (c[0] == 's') ? 3 : 1;
    else
        return CondKind::UNKNOWN;

    std::string_view s(c);
    if (s == "e" || s == "z")  return CondKind::ZF;
    if (s == "ne" || s == "nz") return CondKind::NZF;
    if (s == "b" || s == "c" || s == "nae") return CondKind::CF;
    if (s == "ae" || s == "nb" || s == "nc") return CondKind::NCF;
    if (s == "l" || s == "nge")  return CondKind::LT;
    if (s == "ge" || s == "nl")  return CondKind::GE;
    if (s == "le" || s == "ng")  return CondKind::LE;
    if (s == "g" || s == "nle")  return CondKind::GT;
    if (s == "be" || s == "na")  return CondKind::BE;
    if (s == "a" || s == "nbe")  return CondKind::A;
    if (s == "s")  return CondKind::SF;
    if (s == "ns") return CondKind::NSF;
    if (s == "o")  return CondKind::OF;
    if (s == "no") return CondKind::NOF;
    return CondKind::UNKNOWN;
}

// Builds the branch/taken value for a jcc/setcc from the flag varnodes.
// LT/GE/LE/GT use SF/OF per x86 semantics: a < b signed <=> SF != OF.
Varnode Lifter::emit_condition(const Insn& insn, PcodeBlock& out) {
    auto zf = vn_reg(REG_ZF, "ZF", 1);
    auto cf = vn_reg(REG_CF, "CF", 1);
    auto sf = vn_reg(REG_SF, "SF", 1);
    auto of = vn_reg(REG_OF, "OF", 1);

    const auto not_v = [&](const Varnode& v) {
        Varnode t = alloc_temp(1);
        emit(out, PcodeOp::BOOL_NOT, t, {v});
        return t;
    };
    const auto or_v = [&](const Varnode& a, const Varnode& b) {
        Varnode t = alloc_temp(1);
        emit(out, PcodeOp::BOOL_OR, t, {a, b});
        return t;
    };
    const auto neq_v = [&](const Varnode& a, const Varnode& b) {
        Varnode t = alloc_temp(1);
        emit(out, PcodeOp::INT_NEQUAL, t, {a, b});
        return t;
    };
    const auto eq_v = [&](const Varnode& a, const Varnode& b) {
        Varnode t = alloc_temp(1);
        emit(out, PcodeOp::INT_EQUAL, t, {a, b});
        return t;
    };

    switch (insn.mnemonic_id ? cond_kind_from_id(insn.mnemonic_id)
                             : cond_kind(insn.mnemonic)) {
    case CondKind::ZF:  return zf;
    case CondKind::NZF: return not_v(zf);
    case CondKind::CF:  return cf;
    case CondKind::NCF: return not_v(cf);
    case CondKind::LT:  return neq_v(sf, of);
    case CondKind::GE:  return eq_v(sf, of);
    case CondKind::LE:  return or_v(zf, neq_v(sf, of));
    case CondKind::GT:  return not_v(or_v(zf, neq_v(sf, of)));
    case CondKind::BE:  return or_v(cf, zf);
    case CondKind::A:   return not_v(or_v(cf, zf));
    case CondKind::SF:  return sf;
    case CondKind::NSF: return not_v(sf);
    case CondKind::OF:  return of;
    case CondKind::NOF: return not_v(of);
    case CondKind::UNKNOWN:
    default:
        // Parity and exotic conditions: flags not tracked. ZF is the least
        // surprising fallback and keeps the branch visible.
        return not_v(zf);
    }
}

void Lifter::lift_insn(const Insn& insn, const AnalysisDB& db, PcodeBlock& out) {
    cur_addr_ = insn.addr;
    cur_seq_ = 0;

    auto rsp = vn_reg(REG_RSP, "rsp", 8);

    switch (insn.type) {
    case InsnType::Mov: {
        Varnode src = operand_read(insn, 1, db, out);
        operand_write(insn, 0, src, out);
        break;
    }
    case InsnType::Lea: {
        auto& dst_op = insn.ops[0];
        auto& src_op = insn.ops[1];
        if (dst_op.type == OpType::Reg && src_op.type == OpType::Mem) {
            if (src_op.val != 0 && src_op.mem.base != ZYDIS_REGISTER_NONE &&
                (src_op.mem.base == ZYDIS_REGISTER_RIP || src_op.mem.base == ZYDIS_REGISTER_EIP)) {
                emit(out, PcodeOp::COPY, reg_vn(dst_op.reg, dst_op.size), {vn_const(src_op.val)});
                break;
            }
            Varnode addr = vn_const(0);
            bool has = false;
            if (src_op.mem.base && src_op.mem.base != ZYDIS_REGISTER_NONE) {
                addr = reg_vn(src_op.mem.base, 64);
                has = true;
            }
            if (src_op.mem.index && src_op.mem.index != ZYDIS_REGISTER_NONE) {
                Varnode idx_r = reg_vn(src_op.mem.index, 64);
                if (src_op.mem.scale > 1) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::INT_MULT, t, {idx_r, vn_const(src_op.mem.scale)});
                    idx_r = t;
                }
                if (has) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::ADD, t, {addr, idx_r});
                    addr = t;
                } else { addr = idx_r; }
                has = true;
            }
            if (src_op.mem.disp != 0) {
                Varnode d = vn_const(static_cast<u64>(src_op.mem.disp));
                if (has) {
                    Varnode t = alloc_temp();
                    emit(out, PcodeOp::ADD, t, {addr, d});
                    addr = t;
                } else { addr = d; }
            }
            emit(out, PcodeOp::COPY, reg_vn(dst_op.reg, dst_op.size), {addr});
        }
        break;
    }
    case InsnType::Add: case InsnType::Sub:
    case InsnType::And: case InsnType::Or: case InsnType::Xor:
    case InsnType::Shl: case InsnType::Shr: case InsnType::Sar:
    case InsnType::Rol: case InsnType::Ror: {
        auto& dst_op = insn.ops[0];
        Varnode lhs = operand_read(insn, 0, db, out);
        Varnode rhs = operand_read(insn, 1, db, out);

        if (insn.type == InsnType::Xor && insn.op_count >= 2 &&
            insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Reg &&
            insn.ops[0].reg == insn.ops[1].reg) {
            operand_write(insn, 0, vn_const(0, dst_op.size / 8), out);
            break;
        }

        PcodeOp pop = PcodeOp::ADD;
        switch (insn.type) {
        case InsnType::Add: pop = PcodeOp::ADD; break;
        case InsnType::Sub: pop = PcodeOp::SUB; break;
        case InsnType::And: pop = PcodeOp::AND; break;
        case InsnType::Or:  pop = PcodeOp::OR;  break;
        case InsnType::Xor: pop = PcodeOp::XOR; break;
        case InsnType::Shl: pop = PcodeOp::SHIFT_LEFT; break;
        case InsnType::Shr: pop = PcodeOp::SHIFT_RIGHT; break;
        case InsnType::Sar: pop = PcodeOp::SHIFT_ARIGHT; break;
        case InsnType::Rol: pop = PcodeOp::ROTATE_LEFT; break;
        case InsnType::Ror: pop = PcodeOp::ROTATE_RIGHT; break;
        default: break;
        }
        Varnode result = alloc_temp(lhs.size);
        emit(out, pop, result, {lhs, rhs});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Inc: case InsnType::Dec: {
        Varnode val = operand_read(insn, 0, db, out);
        Varnode result = alloc_temp(val.size);
        emit(out, insn.type == InsnType::Inc ? PcodeOp::ADD : PcodeOp::SUB,
             result, {val, vn_const(1, val.size)});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Mul: case InsnType::Imul: {
        Varnode result = alloc_temp();
        if (insn.op_count == 1) {
            auto rax_v = vn_reg(REG_RAX, "rax", 8);
            Varnode src = operand_read(insn, 0, db, out);
            emit(out, PcodeOp::INT_MULT, result, {rax_v, src});
            emit(out, PcodeOp::COPY, rax_v, {result});
        } else if (insn.op_count == 2) {
            Varnode lhs = operand_read(insn, 0, db, out);
            Varnode rhs = operand_read(insn, 1, db, out);
            emit(out, PcodeOp::INT_MULT, result, {lhs, rhs});
            operand_write(insn, 0, result, out);
        } else if (insn.op_count == 3) {
            Varnode lhs = operand_read(insn, 1, db, out);
            Varnode rhs = operand_read(insn, 2, db, out);
            emit(out, PcodeOp::INT_MULT, result, {lhs, rhs});
            operand_write(insn, 0, result, out);
        }
        break;
    }
    case InsnType::Div: case InsnType::Idiv: {
        auto rax_v = vn_reg(REG_RAX, "rax", 8);
        Varnode src = operand_read(insn, 0, db, out);
        Varnode result = alloc_temp();
        emit(out, insn.type == InsnType::Idiv ? PcodeOp::INT_SDIV : PcodeOp::INT_DIV,
             result, {rax_v, src});
        emit(out, PcodeOp::COPY, rax_v, {result});
        break;
    }
    case InsnType::Movsx: case InsnType::Movzx: {
        Varnode src = operand_read(insn, 1, db, out);
        Varnode result = alloc_temp(insn.ops[0].size / 8);
        emit(out, insn.type == InsnType::Movsx ? PcodeOp::INT_SEXT : PcodeOp::INT_ZEXT,
             result, {src});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Not: {
        Varnode src = operand_read(insn, 0, db, out);
        Varnode result = alloc_temp(src.size);
        emit(out, PcodeOp::INT_NEGATE, result, {src});
        operand_write(insn, 0, result, out);
        break;
    }
    case InsnType::Push: {
        Varnode src = operand_read(insn, 0, db, out);
        const int slot = db.arch == Arch::X86 ? 4 : 8;
        Varnode new_sp = alloc_temp(slot);
        emit(out, PcodeOp::SUB, new_sp, {rsp, vn_const(slot)});
        emit(out, PcodeOp::COPY, rsp, {new_sp});
        emit(out, PcodeOp::STORE, {}, {rsp, src});
        break;
    }
    case InsnType::Pop: {
        const int slot = db.arch == Arch::X86 ? 4 : 8;
        Varnode loaded = alloc_temp(slot);
        emit(out, PcodeOp::LOAD, loaded, {rsp});
        operand_write(insn, 0, loaded, out);
        Varnode new_sp = alloc_temp(slot);
        emit(out, PcodeOp::ADD, new_sp, {rsp, vn_const(slot)});
        emit(out, PcodeOp::COPY, rsp, {new_sp});
        break;
    }
    case InsnType::Cmp: case InsnType::Test: {
        Varnode lhs = operand_read(insn, 0, db, out);
        Varnode rhs = operand_read(insn, 1, db, out);
        emit_flags(insn, lhs, rhs, out, insn.type == InsnType::Test);
        break;
    }
    case InsnType::Setcc: {
        Varnode result = emit_condition(insn, out);
        Varnode final = alloc_temp(1);
        emit(out, PcodeOp::INT_ZEXT, final, {result});
        operand_write(insn, 0, final, out);
        break;
    }
    case InsnType::Jcc: {
        Varnode cond_val = emit_condition(insn, out);
        va_t target = insn.branch_target();
        emit(out, PcodeOp::CBRANCH, {}, {vn_const(target), cond_val});
        break;
    }
    case InsnType::Jmp:
        emit(out, PcodeOp::BRANCH, {}, {vn_const(insn.branch_target())});
        break;
    case InsnType::Call: {
        va_t target = insn.branch_target();
        std::string name;
        if (target) {
            auto nit = db.names.find(target);
            if (nit != db.names.end())
                name = nit->second;
            else if (db.image_base && target >= db.image_base)
                name = fmt::format("sub_{:X}", target - db.image_base);
            else
                name = fmt::format("sub_{:X}", target);
        } else {
            name = fmt::format("indirect_{:X}", insn.addr);
        }
        Varnode rax_v = vn_reg(REG_RAX, "rax", 8);
        Varnode fn_addr = vn_const(target);
        fn_addr.name = std::move(name);
        if (db.arch == Arch::X86) {
            // cdecl/stdcall: arguments travel on the stack, no register args.
            emit(out, PcodeOp::CALL, rax_v, {fn_addr});
        } else {
            emit(out, PcodeOp::CALL, rax_v, {fn_addr,
                vn_reg(REG_RCX, "rcx"), vn_reg(REG_RDX, "rdx"),
                vn_reg(REG_R8, "r8"), vn_reg(REG_R9, "r9")});
        }
        break;
    }
    case InsnType::Ret: {
        out.has_return = true;
        emit(out, PcodeOp::RETURN, {}, {vn_reg(REG_RAX, "rax")});
        break;
    }
    case InsnType::Nop:
        break;
    default: {
        // Unsupported instruction: keep it visible and side-effecting rather
        // than silently deleting semantics (SIMD, atomics, string ops, CMOV).
        // Operand text is skipped in analysis builds, so re-render it here;
        // this runs once per unlifted instruction in a decompiled function.
        Varnode intrinsic;
        intrinsic.kind = VarnodeKind::Temp;
        intrinsic.id = next_temp_++;
        intrinsic.size = 8;
        intrinsic.name = fmt::format("__asm {{ {} }}", Disassembler::format_text(insn, db.arch));
        Varnode result = alloc_temp(8);
        emit(out, PcodeOp::INTRINSIC, result, {intrinsic});
        break;
    }
    }
}

void Lifter::lift_block(const BasicBlock& bb, const AnalysisDB& db, PcodeBlock& out) {
    out.addr = bb.start;
    for (auto& insn : bb.insns)
        lift_insn(insn, db, out);
}

PcodeFunc Lifter::lift(const Function& func, const AnalysisDB& db) {
    next_temp_ = 256;
    arch_ = db.arch;
    stack_vars_.clear();

    PcodeFunc pf;
    pf.entry = func.entry;
    if (!func.name.empty())
        pf.name = func.name;
    else if (db.image_base && func.entry >= db.image_base)
        pf.name = fmt::format("sub_{:X}", func.entry - db.image_base);
    else
        pf.name = fmt::format("sub_{:X}", func.entry);

    std::vector<va_t> order;
    for (auto& [addr, _] : func.blocks)
        order.push_back(addr);
    std::sort(order.begin(), order.end());

    for (int i = 0; i < (int)order.size(); ++i)
        addr_to_block_[order[i]] = i;

    for (int i = 0; i < (int)order.size(); ++i) {
        auto it = func.blocks.find(order[i]);
        if (it == func.blocks.end()) continue;
        PcodeBlock blk;
        blk.id = i;
        lift_block(it->second, db, blk);

        for (va_t s : it->second.succs) {
            auto sit = addr_to_block_.find(s);
            if (sit != addr_to_block_.end())
                blk.succs.push_back(sit->second);
        }
        pf.blocks.push_back(std::move(blk));
    }

    // build preds
    for (int i = 0; i < (int)pf.blocks.size(); ++i) {
        for (int s : pf.blocks[i].succs)
            if (s >= 0 && s < (int)pf.blocks.size())
                pf.blocks[s].preds.push_back(i);
    }

    pf.next_temp = next_temp_;
    pf.locals = stack_vars_;
    pf.params = {
        vn_reg(REG_RCX, "rcx"), vn_reg(REG_RDX, "rdx"),
        vn_reg(REG_R8, "r8"), vn_reg(REG_R9, "r9")
    };

    addr_to_block_.clear();
    return pf;
}

}
