#pragma once
#include "core/types.h"
#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <functional>

namespace hype {

enum class InsnType : u8 {
    Unknown, Nop, Mov, Push, Pop,
    Call, Ret, Jmp, Jcc,
    Cmp, Test, Setcc,
    Add, Sub, Mul, Div, Imul, Idiv,
    Inc, Dec,
    And, Or, Xor, Not, Shl, Shr, Sar, Rol, Ror,
    Lea, Int, Syscall, Movsx, Movzx, Other
};

enum class OpType : u8 { None, Reg, Imm, Mem };

// Field order is chosen for size, not readability: the natural ordering pads
// this out to 40 bytes, and an Insn carries four of them for every decoded
// instruction in the image. Keeping the 8-byte members first packs it to 32
struct Operand {
    u64    val  = 0;
    struct { i64 disp; u16 base; u16 index; u8 scale; } mem{};
    u16    reg  = 0;
    u16    size = 0;
    OpType type = OpType::None;
    bool   read = false;
    bool   write = false;
};

// Also ordered for size — an image with tens of millions of instructions
// keeps one of these per instruction in the DB and another per basic block
struct Insn {
    va_t        addr;
    Operand     ops[4];
    char        op_str[64];
    char        mnemonic[12];
    u8          bytes[15];
    u8          len;
    InsnType    type;
    u8          op_count;
    u16         mnemonic_id;

    void set_mnemonic(const char* s) {
        std::strncpy(mnemonic, s, sizeof(mnemonic) - 1);
        mnemonic[sizeof(mnemonic) - 1] = '\0';
    }
    void set_mnemonic(const std::string& s) { set_mnemonic(s.c_str()); }

    void set_op_str(const char* s) {
        std::strncpy(op_str, s, sizeof(op_str) - 1);
        op_str[sizeof(op_str) - 1] = '\0';
    }
    void set_op_str(const std::string& s) { set_op_str(s.c_str()); }

    bool is_branch()   const { return type == InsnType::Jmp || type == InsnType::Jcc; }
    bool is_call()     const { return type == InsnType::Call; }
    bool is_ret()      const { return type == InsnType::Ret; }
    bool is_cond_jmp() const { return type == InsnType::Jcc; }

    va_t branch_target() const {
        if (op_count > 0 && ops[0].type == OpType::Imm)
            return ops[0].val;
        return 0;
    }
};

class Disassembler {
public:
    Disassembler();
    ~Disassembler();

    void set_arch(Arch arch);
    bool decode(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len);
    // Cancellation-aware variant: probes the predicate every 4 KiB of input
    // so a section sweep can be interrupted between chunks, not after it.
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len,
                                   const std::function<bool()>& cancelled);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
