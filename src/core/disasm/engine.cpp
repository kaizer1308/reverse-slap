// src/core/disasm/engine.cpp

#include "core/disasm/engine.hpp"

#include <algorithm>
#include <cstring>

namespace slop::core::disasm {

engine_t::engine_t() = default;

bool engine_t::init(bool x64) {
    if (initialized_ && x64_ == x64) return true;
    if (ZYAN_FAILED(ZydisDecoderInit(&decoder_,
                                     x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
                                     x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32)))
        return false;
    if (ZYAN_FAILED(ZydisFormatterInit(&formatter_, ZYDIS_FORMATTER_STYLE_INTEL)))
        return false;
    ZydisFormatterSetProperty(&formatter_, ZYDIS_FORMATTER_PROP_UPPERCASE_MNEMONIC,
                              ZYAN_TRUE);
    initialized_ = true;
    x64_ = x64;
    return true;
}

std::optional<insn_t> engine_t::decode(uint64_t va, const uint8_t* buf,
                                       size_t len) const {
    if (!initialized_ || buf == nullptr || len == 0) return std::nullopt;

    ZydisDecodedInstruction instr{};
    // Full (not _VISIBLE) array: DecodeInitial/DecodeFull write every slot,
    // including hidden operands, sizing by VISIBLE overruns the stack
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT]{};
    const ZyanStatus st = ZydisDecoderDecodeFull(&decoder_, buf, len, &instr, ops);
    if (!ZYAN_SUCCESS(st)) return std::nullopt;

    insn_t out;
    out.va     = va;
    out.length = static_cast<uint8_t>(instr.length);
    std::memcpy(out.bytes, buf, instr.length);
    out.mnemonic = instr.mnemonic;

    char text[256]{};
    if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter_, &instr, ops,
                                                     instr.operand_count_visible,
                                                     text, sizeof(text), va, ZYAN_NULL)))
        out.text = text;

    // Compact operand summary for analysis passes
    const uint8_t vis =
        static_cast<uint8_t>(std::min<size_t>(instr.operand_count_visible,
                                              ZYDIS_MAX_OPERAND_COUNT_VISIBLE));
    for (uint8_t i = 0; i < vis; ++i) {
        const auto& op = ops[i];
        operand_t&  o  = out.ops[out.op_count++];
        o.read  = op.actions & ZYDIS_OPERAND_ACTION_READ;
        o.write = op.actions & ZYDIS_OPERAND_ACTION_WRITE;
        switch (op.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            o.cls = op_class_t::reg;
            o.reg = op.reg.value;
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            o.cls       = op_class_t::mem;
            o.mem_base  = op.mem.base;
            o.mem_index = op.mem.index;
            o.scale     = static_cast<uint8_t>(op.mem.scale);
            o.disp      = op.mem.disp.value;
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            o.cls = op_class_t::imm;
            o.imm = op.imm.is_signed
                        ? static_cast<uint64_t>(op.imm.value.s)
                        : op.imm.value.u;
            break;
        default:
            break;
        }
    }

    switch (instr.mnemonic) {
    case ZYDIS_MNEMONIC_CALL: out.flow = flow_t::call; break;
    case ZYDIS_MNEMONIC_JMP:  out.flow = flow_t::jmp;  break;
    case ZYDIS_MNEMONIC_RET:  out.flow = flow_t::ret;  break;
    default:
        if (instr.meta.category == ZYDIS_CATEGORY_COND_BR)
            out.flow = flow_t::jcc;
        break;
    }

    if (out.flow != flow_t::none && out.flow != flow_t::ret) {
        // Branch target: first operand
        for (size_t i = 0; i < instr.operand_count_visible; ++i) {
            uint64_t abs = 0;
            if (ZydisCalcAbsoluteAddress(&instr, &ops[i], va, &abs) == ZYAN_STATUS_SUCCESS) {
                out.has_rel_target = true;
                out.rel_target     = abs;
                break;
            }
        }
    }

    // Rip-relative data reference (first memory operand with RIP base)
    for (size_t i = 0; i < instr.operand_count_visible; ++i) {
        const auto& op = ops[i];
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
        if (op.mem.base != ZYDIS_REGISTER_RIP) continue;
        uint64_t abs = 0;
        if (ZydisCalcAbsoluteAddress(&instr, &op, va, &abs) == ZYAN_STATUS_SUCCESS) {
            out.has_rip_rel    = true;
            out.rip_rel_target = abs;
        }
        break;
    }

    return out;
}

} // namespace slop::core::disasm
