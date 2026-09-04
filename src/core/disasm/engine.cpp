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
                                       size_t len, bool want_text) const {
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

    if (want_text) {
        char text[256]{};
        if (ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&formatter_, &instr, ops,
                                                         instr.operand_count_visible,
                                                         text, sizeof(text), va, ZYAN_NULL)))
            out.text = text;
    }

    // Compact operand summary for analysis passes
    const uint8_t vis =
        static_cast<uint8_t>(std::min<size_t>(instr.operand_count_visible,
                                              ZYDIS_MAX_OPERAND_COUNT_VISIBLE));
    for (uint8_t i = 0; i < vis; ++i) {
        const auto& op = ops[i];
        operand_t&  o  = out.ops[out.op_count++];
        o.read  = (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
        o.write = (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
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

    switch (instr.meta.category) {
    case ZYDIS_CATEGORY_CALL:      out.flow = flow_t::call; break;
    case ZYDIS_CATEGORY_UNCOND_BR: out.flow = flow_t::jmp;  break;
    case ZYDIS_CATEGORY_COND_BR:   out.flow = flow_t::jcc;  break;
    case ZYDIS_CATEGORY_RET:       out.flow = flow_t::ret;  break;
    default: break;
    }

    if (out.flow != flow_t::none && out.flow != flow_t::ret) {
        // A memory operand resolves the pointer slot, not the branch
        // destination. Only relative immediates are statically direct targets.
        for (size_t i = 0; i < instr.operand_count_visible; ++i) {
            if (ops[i].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !ops[i].imm.is_relative)
                continue;
            uint64_t abs = 0;
            if (ZydisCalcAbsoluteAddress(&instr, &ops[i], va, &abs) == ZYAN_STATUS_SUCCESS) {
                out.has_rel_target = true;
                out.rel_target     = x64_ ? abs : static_cast<uint32_t>(abs);
                break;
            }
        }
    }

    // Address-size override selects EIP-relative addressing even in x64.
    for (size_t i = 0; i < instr.operand_count_visible; ++i) {
        const auto& op = ops[i];
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY) continue;
        if (op.mem.base != ZYDIS_REGISTER_RIP && op.mem.base != ZYDIS_REGISTER_EIP) continue;
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
