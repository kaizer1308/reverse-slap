// src/tests/test_decomp.cpp
// Hyperion-backed decompiler tests + Zydis-encoder assembly roundtrips
// (The old in-house "decompiler-lite" was removed; hyperion is the engine.)

#include "harness.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "hyperion/core/decompiler/emitter.h"
#include "hyperion/core/decompiler/decompiler.h"
#include "hyperion/core/disasm/disassembler.h"
#include "hyperion/core/decompiler/propagate.h"
#include "hyperion/core/decompiler/ssa.h"
#include "hyperion/core/decompiler/cf_struct.h"

#include <Zydis/Zydis.h>
#include <Zydis/Encoder.h>

#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>

namespace disasm = slop::core::disasm;
namespace hs     = slop::core::disasm::hyperion_session;

namespace {

bool wait_hype_ready(int timeout_ms = 30000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (disasm::binary_state::hype_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return disasm::binary_state::hype_ready();
}

} // namespace

TEST_CASE(decomp_function_from_loaded_image) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready());
    auto& bin = disasm::binary_state::get();
    REQUIRE(bin.hype != nullptr);

    // A real function to decompile, largest block count, like the legacy
    // test's "first function" but skipping entry thunks
    const hype::Function* best = nullptr;
    for (const auto& [entry, f] : bin.hype->db().funcs) {
        (void)entry;
        if (!best || f.blocks.size() > best->blocks.size()) best = &f;
    }
    REQUIRE(best != nullptr);

    std::vector<hype::PseudoLine> out;
    std::string err;
    REQUIRE(bin.hype->decompile(best->entry, out, err));
    if (!out.empty()) {
        REQUIRE_GT(out.size(), 1u);

        bool has_brace_or_stmt = false;
        for (const auto& l : out) {
            if (l.text.find('{') != std::string::npos ||
                l.text.find(';') != std::string::npos)
                has_brace_or_stmt = true;
        }
        REQUIRE(has_brace_or_stmt);
    }
    disasm::binary_state::unload();
}

TEST_CASE(decomp_unknown_address_errors_cleanly) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready());
    auto& bin = disasm::binary_state::get();

    std::vector<hype::PseudoLine> out;
    std::string err;
    REQUIRE_FALSE(bin.hype->decompile(0xDEADBEEFull, out, err));
    REQUIRE_FALSE(err.empty());
    disasm::binary_state::unload();
}

TEST_CASE(decomp_propagation_preserves_single_use_expression) {
    hype::PcodeFunc func;
    func.blocks.resize(1);
    auto a = hype::vn_temp(0);
    auto b = hype::vn_temp(1);
    auto c = hype::vn_temp(2);
    auto sum = hype::vn_temp(3);
    auto product = hype::vn_temp(4);
    a.offset = 1; b.offset = 2; c.offset = 3; sum.offset = 4; product.offset = 5;
    func.blocks[0].ops = {
        hype::PcodeInsn::make(hype::PcodeOp::ADD, sum, {a, b}),
        hype::PcodeInsn::make(hype::PcodeOp::INT_MULT, product, {sum, c}),
        hype::PcodeInsn::make(hype::PcodeOp::RETURN, {}, {product}),
    };

    hype::Propagate propagate;
    propagate.run(func);

    bool kept_add = false;
    bool multiply_uses_sum = false;
    for (const auto& op : func.blocks[0].ops) {
        if (op.op == hype::PcodeOp::ADD && op.output == sum) kept_add = true;
        if (op.op == hype::PcodeOp::INT_MULT && !op.inputs.empty() && op.inputs[0] == sum)
            multiply_uses_sum = true;
    }
    REQUIRE(kept_add);
    REQUIRE(multiply_uses_sum);
}

TEST_CASE(decomp_propagation_preserves_phi_versions) {
    hype::PcodeFunc func;
    func.blocks.resize(1);
    auto merged = hype::vn_reg(0, "rax");
    auto left = merged;
    auto right = merged;
    merged.offset = 3;
    left.offset = 1;
    right.offset = 2;
    hype::PcodeInsn phi = hype::PcodeInsn::make(hype::PcodeOp::COPY, merged, {left, right});
    phi.seq = -1;
    func.blocks[0].ops = {phi, hype::PcodeInsn::make(hype::PcodeOp::RETURN, {}, {merged})};

    hype::Propagate propagate;
    propagate.run(func);

    REQUIRE_EQ(func.blocks[0].ops.size(), 2u);
    REQUIRE_EQ(func.blocks[0].ops[0].seq, -1);
    REQUIRE(func.blocks[0].ops[0].output == merged);
    REQUIRE_EQ(func.blocks[0].ops[0].inputs.size(), 2u);
}

TEST_CASE(decomp_emitter_preserves_returns_call_results_and_precedence) {
    hype::CFunc func;
    func.name = "semantic_fixture";
    func.entry = 0x1000;

    hype::CStmt call;
    call.kind = hype::StmtKind::Assign;
    call.dst = hype::vn_reg(0, "rax");
    call.dst.offset = 1;
    call.expr = hype::CExpr::call("callee", {hype::CExpr::imm(7)});

    hype::CStmt expression;
    expression.kind = hype::StmtKind::Assign;
    expression.dst = hype::vn_reg(1, "rcx");
    expression.dst.offset = 2;
    expression.expr = hype::CExpr::binop(
        hype::PcodeOp::INT_MULT,
        hype::CExpr::binop(hype::PcodeOp::ADD, hype::CExpr::imm(1), hype::CExpr::imm(2)),
        hype::CExpr::imm(3));

    hype::CStmt ret;
    ret.kind = hype::StmtKind::Return;
    ret.expr = hype::CExpr::imm(0);
    func.body = {call, expression, ret};

    hype::Emitter emitter;
    const auto lines = emitter.emit(func);
    std::string text;
    for (const auto& line : lines) text += line.text + "\n";

    REQUIRE(text.find("rax = callee(7);") != std::string::npos);
    REQUIRE(text.find("rcx = (1 + 2) * 3;") != std::string::npos);
    REQUIRE(text.find("return 0;") != std::string::npos);
    REQUIRE(text.find("void semantic_fixture") == std::string::npos);
}

TEST_CASE(decomp_ssa_uses_actual_entry_and_graph_order) {
    hype::PcodeFunc func;
    func.entry = 0x3000;
    func.blocks.resize(4);
    // Address order differs from traversal: entry block is index 2
    func.blocks[0].id = 0; func.blocks[0].addr = 0x1000; func.blocks[0].succs = {3}; func.blocks[0].preds = {2};
    func.blocks[1].id = 1; func.blocks[1].addr = 0x2000; func.blocks[1].succs = {3}; func.blocks[1].preds = {2};
    func.blocks[2].id = 2; func.blocks[2].addr = 0x3000; func.blocks[2].succs = {0, 1};
    func.blocks[3].id = 3; func.blocks[3].addr = 0x4000; func.blocks[3].preds = {0, 1};
    auto rax = hype::vn_reg(0, "rax");
    func.blocks[0].ops.push_back(hype::PcodeInsn::make(hype::PcodeOp::COPY, rax, {hype::vn_const(1)}));
    func.blocks[1].ops.push_back(hype::PcodeInsn::make(hype::PcodeOp::COPY, rax, {hype::vn_const(2)}));
    func.blocks[3].ops.push_back(hype::PcodeInsn::make(hype::PcodeOp::RETURN, {}, {rax}));

    hype::SSABuilder ssa;
    ssa.build(func);

    REQUIRE_FALSE(func.blocks[3].ops.empty());
    REQUIRE_EQ(func.blocks[3].ops.front().seq, -1);
    REQUIRE_EQ(func.blocks[3].ops.front().inputs.size(), 2u);
    REQUIRE_NE(func.blocks[3].ops.front().inputs[0].offset,
               func.blocks[3].ops.front().inputs[1].offset);
}

TEST_CASE(decomp_structurer_preserves_every_cfg_edge) {
    hype::PcodeFunc func;
    func.name = "edge_fixture";
    func.entry = 0x3000;
    func.blocks.resize(3);
    func.blocks[0].id = 0; func.blocks[0].addr = 0x3000; func.blocks[0].succs = {1, 2};
    func.blocks[1].id = 1; func.blocks[1].addr = 0x1000; func.blocks[1].has_return = true;
    func.blocks[2].id = 2; func.blocks[2].addr = 0x2000; func.blocks[2].has_return = true;
    auto cond = hype::vn_temp(1); cond.offset = 1;
    func.blocks[0].ops.push_back(hype::PcodeInsn::make(
        hype::PcodeOp::CBRANCH, {}, {hype::vn_const(0x1000), cond}, 0x3004));
    func.blocks[1].ops.push_back(hype::PcodeInsn::make(hype::PcodeOp::RETURN, {}, {hype::vn_const(1)}, 0x1000));
    func.blocks[2].ops.push_back(hype::PcodeInsn::make(hype::PcodeOp::RETURN, {}, {hype::vn_const(2)}, 0x2000));

    hype::CFStructure structurer;
    hype::Emitter emitter;
    const auto lines = emitter.emit(structurer.structure(func));
    std::string text;
    for (const auto& line : lines) text += line.text + "\n";

    REQUIRE(text.find("loc_3000:") != std::string::npos);
    REQUIRE(text.find("loc_1000:") != std::string::npos);
    REQUIRE(text.find("loc_2000:") != std::string::npos);
    REQUIRE(text.find("goto loc_1000;") != std::string::npos);
    REQUIRE(text.find("goto loc_2000;") != std::string::npos);
}

namespace {

// Decode raw bytes into a single-block hyperion Function for pipeline tests
hype::Function function_from_bytes(const uint8_t* code, size_t len, const char* name) {
    hype::Disassembler decoder;
    decoder.set_arch(hype::Arch::X64);
    hype::Function func;
    func.entry = 0x1000;
    func.name = name;
    hype::BasicBlock block;
    block.start = 0x1000;
    size_t off = 0;
    while (off < len) {
        hype::Insn insn{};
        if (!decoder.decode(0x1000 + off, code + off, len - off, insn)) break;
        block.insns.push_back(insn);
        block.end = insn.addr + insn.len;
        if (insn.is_ret()) break;
        off += insn.len;
    }
    func.block_addrs.push_back(block.start);
    func.blocks[block.start] = std::move(block);
    func.analyzed = true;
    return func;
}

std::string decompile_text(const hype::Function& func) {
    hype::AnalysisDB db;
    db.arch = hype::Arch::X64;
    db.image_base = 0;
    hype::Decompiler decompiler;
    std::string text;
    for (const auto& line : decompiler.decompile(func, db, nullptr))
        text += line.text + "\n";
    return text;
}

}

TEST_CASE(decomp_lifter_signed_and_unsigned_conditions) {
    // cmp eax, 5 ; jl target ; ret  then signed less: SF != OF
    static const uint8_t jl[] = {0x83, 0xF8, 0x05, 0x7C, 0x02, 0xC3};
    std::string text = decompile_text(function_from_bytes(jl, sizeof(jl), "cond_jl"));
    REQUIRE(text.find("SF != OF") != std::string::npos);

    // cmp eax, 5 ; jbe target ; ret  then unsigned below-or-equal: CF || ZF
    static const uint8_t jbe[] = {0x83, 0xF8, 0x05, 0x76, 0x02, 0xC3};
    text = decompile_text(function_from_bytes(jbe, sizeof(jbe), "cond_jbe"));
    REQUIRE(text.find("CF || ZF") != std::string::npos);
}

TEST_CASE(decomp_lifter_subregister_write_updates_full_register) {
    // mov al, 2 ; ret then AL write must keep upper RAX bits and stay visible
    static const uint8_t al[] = {0xB0, 0x02, 0xC3};
    std::string text = decompile_text(function_from_bytes(al, sizeof(al), "write_al"));
    REQUIRE(text.find("PIECE") == std::string::npos);  // emitted as shifts/or
    REQUIRE(text.find("<<") != std::string::npos || text.find("|") != std::string::npos);

    // mov eax, 7 ; ret then 32-bit write zero-extends into RAX
    static const uint8_t eax[] = {0xB8, 0x07, 0x00, 0x00, 0x00, 0xC3};
    text = decompile_text(function_from_bytes(eax, sizeof(eax), "write_eax"));
    REQUIRE(text.find("(uint64_t)") != std::string::npos ||
            text.find("uint64") != std::string::npos);
}

TEST_CASE(decomp_lifter_unsupported_instruction_stays_visible) {
    // aesdec xmm1, xmm2, no lifter semantics; must appear as __asm, not vanish
    static const uint8_t aes[] = {0x66, 0x0F, 0x38, 0xDE, 0xCA, 0xC3};
    std::string text = decompile_text(function_from_bytes(aes, sizeof(aes), "unsupported"));
    REQUIRE(text.find("__asm") != std::string::npos);
    REQUIRE(text.find("aesdec") != std::string::npos);
}

TEST_CASE(assembler_encodes_known_instructions) {
    auto encode = [](const std::string& text) -> std::string {
        ZydisEncoderRequest req{};
        req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
        req.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;

        // mnemonic
        std::string mn = text, rest;
        const size_t sp = text.find(' ');
        if (sp != std::string::npos) {
            mn = text.substr(0, sp);
            rest = text.substr(sp + 1);
        }
        bool found = false;
        for (int m = 1; m < ZYDIS_MNEMONIC_MAX_VALUE; ++m) {
            const auto mm = static_cast<ZydisMnemonic>(m);
            if (ZydisMnemonicGetString(mm) &&
                _stricmp(ZydisMnemonicGetString(mm), mn.c_str()) == 0) {
                req.mnemonic = mm;
                found = true;
            }
        }
        if (!found) return "";

        // two register operands "rax, rbx" style
        size_t pos = 0;
        int op_idx = 0;
        while (pos < rest.size() && op_idx < ZYDIS_MAX_OPERAND_COUNT) {
            const size_t comma = rest.find(',', pos);
            std::string tok = comma == std::string::npos
                                  ? rest.substr(pos)
                                  : rest.substr(pos, comma - pos);
            pos = comma == std::string::npos ? rest.size() : comma + 1;
            while (!tok.empty() && tok.front() == ' ') tok.erase(tok.begin());
            while (!tok.empty() && tok.back() == ' ') tok.pop_back();
            if (tok.empty()) continue;

            for (int i = 1; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
                const auto rr = static_cast<ZydisRegister>(i);
                if (ZydisRegisterGetString(rr) &&
                    _stricmp(ZydisRegisterGetString(rr), tok.c_str()) == 0) {
                    auto& op = req.operands[req.operand_count++];
                    op.type = ZYDIS_OPERAND_TYPE_REGISTER;
                    op.reg.value = rr;
                    break;
                }
            }
            ++op_idx;
        }

        uint8_t buf[16];
        ZyanUSize len = sizeof(buf);
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf, &len)))
            return "";
        return std::string(reinterpret_cast<const char*>(buf),
                           static_cast<size_t>(len));
    };

    // mov rax, rbx -> 48 89 D8
    const std::string mov = encode("mov rax, rbx");
    REQUIRE_EQ(mov.size(), 3u);
    REQUIRE(static_cast<unsigned char>(mov[0]) == 0x48);
    REQUIRE(static_cast<unsigned char>(mov[2]) == 0xD8);

    // xor ecx, ecx -> 31 C9
    const std::string xorx = encode("xor ecx, ecx");
    REQUIRE_GE(xorx.size(), 2u);
}

TEST_CASE(assembler_decodes_roundtrip) {
    // Encode then decode: bytes must disassemble back to the same mnemonic
    ZydisEncoderRequest req{};
    req.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    req.mnemonic = ZYDIS_MNEMONIC_ADD;
    auto& d0 = req.operands[req.operand_count++];
    d0.type = ZYDIS_OPERAND_TYPE_REGISTER;
    d0.reg.value = ZYDIS_REGISTER_RAX;
    auto& d1 = req.operands[req.operand_count++];
    d1.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;
    d1.imm.u = 3;

    uint8_t buf[16];
    ZyanUSize len = sizeof(buf);
    REQUIRE(ZYAN_SUCCESS(ZydisEncoderEncodeInstruction(&req, buf, &len)));

    ZydisDecoder dec;
    REQUIRE(ZYAN_SUCCESS(ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64,
                                          ZYDIS_STACK_WIDTH_64)));
    ZydisDecodedInstruction insn{};
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    REQUIRE(ZYAN_SUCCESS(
        ZydisDecoderDecodeFull(&dec, buf, len, &insn, ops)));
    REQUIRE_EQ(insn.mnemonic, ZYDIS_MNEMONIC_ADD);
}
