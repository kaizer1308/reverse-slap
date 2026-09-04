#include "disassembler.h"
#include <Zydis/Zydis.h>
#include <fmt/format.h>
#include <algorithm>
#include <cstring>

namespace hype {

struct Disassembler::Impl {
    ZydisDecoder    decoder;
    ZydisFormatter  formatter;
};

Disassembler::Disassembler() : impl_(std::make_unique<Impl>()) {
    ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&impl_->formatter, ZYDIS_FORMATTER_STYLE_INTEL);
}

Disassembler::~Disassembler() = default;

void Disassembler::set_arch(Arch arch) {
    if (arch == Arch::X86)
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    else
        ZydisDecoderInit(&impl_->decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
}

static InsnType classify(const ZydisDecodedInstruction& insn) {
    const auto m = insn.mnemonic;
    if (insn.meta.category == ZYDIS_CATEGORY_COND_BR)
        return InsnType::Jcc;
    if (insn.meta.category == ZYDIS_CATEGORY_SETCC)
        return InsnType::Setcc;

    switch (m) {
    case ZYDIS_MNEMONIC_NOP:  return InsnType::Nop;
    case ZYDIS_MNEMONIC_MOV:     return InsnType::Mov;
    case ZYDIS_MNEMONIC_MOVZX:   return InsnType::Movzx;
    case ZYDIS_MNEMONIC_MOVSX:
    case ZYDIS_MNEMONIC_MOVSXD:  return InsnType::Movsx;
    case ZYDIS_MNEMONIC_PUSH:   return InsnType::Push;
    case ZYDIS_MNEMONIC_POP:    return InsnType::Pop;
    case ZYDIS_MNEMONIC_CALL:   return InsnType::Call;
    case ZYDIS_MNEMONIC_RET:    return InsnType::Ret;
    case ZYDIS_MNEMONIC_JMP:    return InsnType::Jmp;
    case ZYDIS_MNEMONIC_CMP:    return InsnType::Cmp;
    case ZYDIS_MNEMONIC_TEST:   return InsnType::Test;
    case ZYDIS_MNEMONIC_ADD:    return InsnType::Add;
    case ZYDIS_MNEMONIC_SUB:    return InsnType::Sub;
    case ZYDIS_MNEMONIC_MUL:    return InsnType::Mul;
    case ZYDIS_MNEMONIC_IMUL:   return InsnType::Imul;
    case ZYDIS_MNEMONIC_DIV:    return InsnType::Div;
    case ZYDIS_MNEMONIC_IDIV:   return InsnType::Idiv;
    case ZYDIS_MNEMONIC_INC:    return InsnType::Inc;
    case ZYDIS_MNEMONIC_DEC:    return InsnType::Dec;
    case ZYDIS_MNEMONIC_AND:    return InsnType::And;
    case ZYDIS_MNEMONIC_OR:     return InsnType::Or;
    case ZYDIS_MNEMONIC_XOR:    return InsnType::Xor;
    case ZYDIS_MNEMONIC_NOT:    return InsnType::Not;
    case ZYDIS_MNEMONIC_SHL:    return InsnType::Shl;
    case ZYDIS_MNEMONIC_SHR:    return InsnType::Shr;
    case ZYDIS_MNEMONIC_SAR:    return InsnType::Sar;
    case ZYDIS_MNEMONIC_ROL:    return InsnType::Rol;
    case ZYDIS_MNEMONIC_ROR:    return InsnType::Ror;
    case ZYDIS_MNEMONIC_LEA:    return InsnType::Lea;
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT3:   return InsnType::Int;
    case ZYDIS_MNEMONIC_SYSCALL: return InsnType::Syscall;
    default:                    return InsnType::Other;
    }
}

bool Disassembler::decode(va_t addr, const u8* data, size_t len, Insn& out,
                          bool want_text) {
    ZydisDecodedInstruction zi;
    ZydisDecodedOperand     zo[ZYDIS_MAX_OPERAND_COUNT];

    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&impl_->decoder, data, len, &zi, zo)))
        return false;

    out.addr = addr;
    out.len = static_cast<u8>(zi.length);
    out.mnemonic_id = static_cast<u16>(zi.mnemonic);
    out.type = classify(zi);
    std::memcpy(out.bytes, data, zi.length);

    if (!want_text) {
        // No formatter: the canonical enum name is enough for every analysis
        // consumer (branch/operand classification keys off mnemonic_id and
        // InsnType, never the string). Display paths re-render on demand.
        const char* mn = ZydisMnemonicGetString(zi.mnemonic);
        if (mn) out.set_mnemonic(mn);
        else out.mnemonic[0] = '\0';
        out.op_str[0] = '\0';
    } else {
        char buf[256];
        ZydisFormatterFormatInstruction(&impl_->formatter, &zi, zo,
            zi.operand_count_visible, buf, sizeof(buf), addr, nullptr);

        const char* sp = std::strchr(buf, ' ');
        if (sp) {
            const size_t mnemonic_len = (std::min)(static_cast<size_t>(sp - buf), sizeof(out.mnemonic) - 1);
            std::memcpy(out.mnemonic, buf, mnemonic_len);
            out.mnemonic[mnemonic_len] = '\0';
            out.set_op_str(sp + 1);
        } else {
            out.set_mnemonic(buf);
            out.op_str[0] = '\0';
        }
    }

    out.op_count = 0;
    for (u8 i = 0; i < zi.operand_count_visible && i < 4; ++i) {
        auto& zop = zo[i];
        auto& op = out.ops[i];
        op.size = zop.size;
        op.read = (zop.actions & ZYDIS_OPERAND_ACTION_READ) != 0;
        op.write = (zop.actions & ZYDIS_OPERAND_ACTION_WRITE) != 0;

        switch (zop.type) {
        case ZYDIS_OPERAND_TYPE_REGISTER:
            op.type = OpType::Reg;
            op.reg = static_cast<u16>(zop.reg.value);
            break;
        case ZYDIS_OPERAND_TYPE_IMMEDIATE:
            op.type = OpType::Imm;
            if (zop.imm.is_relative)
                ZydisCalcAbsoluteAddress(&zi, &zop, addr, &op.val);
            else
                op.val = zop.imm.value.u;
            break;
        case ZYDIS_OPERAND_TYPE_MEMORY:
            op.type = OpType::Mem;
            op.mem.base = static_cast<u16>(zop.mem.base);
            op.mem.index = static_cast<u16>(zop.mem.index);
            op.mem.scale = zop.mem.scale;
            op.mem.disp = zop.mem.disp.value;
            if (zop.mem.base == ZYDIS_REGISTER_RIP || zop.mem.base == ZYDIS_REGISTER_EIP)
                ZydisCalcAbsoluteAddress(&zi, &zop, addr, &op.val);
            break;
        default:
            op.type = OpType::None;
            break;
        }
        ++out.op_count;
    }
    return true;
}

std::string Disassembler::format_text(const Insn& insn, Arch arch) {
    if (insn.op_str[0] != '\0') {
        std::string text(insn.mnemonic);
        text += ' ';
        text += insn.op_str;
        return text;
    }
    // Operand text was skipped at decode time; re-decode the stored bytes.
    // Rare path (unlifted instructions in a decompiled function), so a
    // thread-local helper decoder is plenty.
    thread_local Disassembler helper;
    helper.set_arch(arch);
    Insn full{};
    if (insn.len == 0 ||
        !helper.decode(insn.addr, insn.bytes, insn.len, full, true))
        return std::string(insn.mnemonic);
    std::string text(full.mnemonic);
    if (full.op_str[0] != '\0') {
        text += ' ';
        text += full.op_str;
    }
    return text;
}

std::vector<Insn> Disassembler::decode_range(va_t start, const u8* data, size_t len) {
    return decode_range(start, data, len, nullptr);
}

std::vector<Insn> Disassembler::decode_range(va_t start, const u8* data, size_t len,
                                             const std::function<bool()>& cancelled) {
    std::vector<Insn> result;
    result.reserve(len / 4);
    size_t off = 0;
    size_t last_probe = 0;
    while (off < len) {
        if (cancelled && off - last_probe >= 4096) {
            last_probe = off;
            if (cancelled()) break;
        }
        Insn insn{};
        if (decode(start + off, data + off, len - off, insn)) {
            off += insn.len;
            result.push_back(std::move(insn));
        } else {
            Insn bad{};
            bad.addr = start + off;
            bad.len = 1;
            bad.type = InsnType::Unknown;
            bad.bytes[0] = data[off];
            bad.set_mnemonic("db");
            char tmp[16];
            std::snprintf(tmp, sizeof(tmp), "0x%02X", data[off]);
            bad.set_op_str(tmp);
            result.push_back(std::move(bad));
            ++off;
        }
    }
    return result;
}

}
