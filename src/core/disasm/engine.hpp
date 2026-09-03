#pragma once

// zydis x64 wrapper producing fully resolved instruction records without
// exposing zydis types

#include <cstdint>
#include <optional>
#include <string>

#include <Zydis/Zydis.h>

namespace slop::core::disasm {

enum class flow_t : uint8_t {
    none,
    call,
    jmp,          // unconditional jump
    jcc,          // conditional jump
    ret,
};

enum class op_class_t : uint8_t { none, reg, mem, imm };

struct operand_t {
    op_class_t    cls      = op_class_t::none;
    bool          read     = false;
    bool          write    = false;
    ZydisRegister reg      = ZYDIS_REGISTER_NONE;
    // Memory form
    ZydisRegister mem_base  = ZYDIS_REGISTER_NONE;
    ZydisRegister mem_index = ZYDIS_REGISTER_NONE;
    uint8_t       scale     = 1;
    int64_t       disp      = 0;
    // Immediate form
    uint64_t      imm       = 0;
};

struct insn_t {
    uint64_t   va       = 0;
    uint8_t    length   = 0;
    uint8_t    bytes[ZYDIS_MAX_INSTRUCTION_LENGTH] = {};
    flow_t     flow     = flow_t::none;

    std::string text;                 // "mov rax, rbx"

    ZydisMnemonic mnemonic = ZYDIS_MNEMONIC_INVALID;
    uint8_t       op_count = 0;
    operand_t     ops[ZYDIS_MAX_OPERAND_COUNT_VISIBLE];

    // Absolute branch destination when flow != none/jcc-with-no-target
    bool       has_rel_target = false;
    uint64_t   rel_target     = 0;

    // First rip-relative memory operand's absolute VA (data references)
    bool       has_rip_rel    = false;
    uint64_t   rip_rel_target = 0;

    const operand_t* find_reg(ZydisRegister r) const {
        for (uint8_t i = 0; i < op_count; ++i)
            if (ops[i].cls == op_class_t::reg && ops[i].reg == r) return &ops[i];
        return nullptr;
    }
};

class engine_t {
public:
    engine_t();
    ~engine_t() = default;

    engine_t(const engine_t&)            = delete;
    engine_t& operator=(const engine_t&) = delete;

    bool init(bool x64 = true);
    bool ok() const noexcept { return initialized_; }

    // Decode one instruction at `va` reading from buf (>= len bytes avail)
    // Const: the underlying Zydis decoder/formatter carry no cross-call state
    //
    // want_text off skips formatting and leaves insn_t::text empty. The index
    // builds sweep every executable byte and never look at the text, and
    // filling it costs a heap allocation per instruction
    std::optional<insn_t> decode(uint64_t va, const uint8_t* buf,
                                 size_t len, bool want_text = true) const;

private:
    ZydisDecoder           decoder_{};
    mutable ZydisFormatter formatter_{};
    bool                   initialized_ = false;
    bool                   x64_ = true;
};

} // namespace slop::core::disasm
