#pragma once

#include "core/disasm/engine.hpp"
#include "core/disasm/hyperion_session.hpp"

#include <array>
#include <cstring>
#include <map>
#include <string>
#include <vector>

// This measures wrapper fidelity to the pinned Zydis decoder, not independent
// ISA correctness or code/data discovery precision. Every input is decoded at
// its supplied boundary; failed/truncated decodes count as well as successes.
namespace disasm_accuracy {
namespace ds = slop::core::disasm;

struct sample {
    std::vector<uint8_t> bytes;
    uint64_t address = 0x140001000;
};

struct result {
    size_t cases = 0;
    size_t decoded = 0;
    size_t exact = 0;
    std::map<std::string, size_t> mismatches;

    void check(bool equal, const char* field, bool& match) {
        if (!equal) { ++mismatches[field]; match = false; }
    }
};

inline std::vector<sample> fixtures(bool x64) {
    std::vector<sample> samples{
        {{0x48, 0x89, 0xE8}},                         // mov / dec in x86
        {{0x48, 0x0F, 0x44, 0xC1}},                   // cmovz
        {{0x0F, 0x44, 0xC1}},
        {{0xF3, 0xA4}},                               // rep movsb
        {{0xF0, 0x0F, 0xB1, 0x0B}},                   // lock cmpxchg [rbx], ecx
        {{0xE8, 0xFB, 0xFF, 0xFF, 0xFF}},             // call self
        {{0x75, 0xFC}},                               // backward conditional branch
        {{0xE2, 0xFE}},                               // loop self
        {{0xFF, 0x15, 0x10, 0x00, 0x00, 0x00}},       // indirect call (not its slot)
        {{0xFF, 0x25, 0x10, 0x00, 0x00, 0x00}},
        {{0xFF, 0xD0}},                               // call rax/eax
        {{0x67, 0x48, 0x8B, 0x05, 0x10, 0, 0, 0}},   // EIP-relative x64
        {{0x48, 0x8B, 0x04, 0x25, 0, 0x20, 0x40, 0}}, // absolute disp32
        {{0x8B, 0x05, 0, 0x20, 0x40, 0}},
        {{0xA1, 0, 0x20, 0x40, 0, 0, 0, 0, 0}},      // moffs
        {{0x48, 0x8B, 0x44, 0x8B, 0xF0}},             // indexed memory
        {{0xC3}}, {{0xC2, 0x10, 0}}, {{0xCB}},
        {{0xCF}}, {{0x48, 0xCF}},                      // interrupt returns
        {{0x0F, 0x0B}}, {{0x90}},
        {{0x62, 0xF1, 0x64, 0x49, 0xC2, 0xCC, 0x03}}, // vcmpps, five operands
        {{0xC4, 0xE2, 0xE5, 0x96, 0xC1}},             // long FMA mnemonic
        {{0xE9, 0x10, 0, 0, 0}, 0xFFFFFFFC},          // 32-bit EIP wrap
        {{0xEB, 0xF0}, 0},
        {{0x66, 0xE9, 0x10, 0}, 0xFFFF},              // 16-bit target in x86
        {{0x9A, 0x78, 0x56, 0x34, 0x12, 0x33, 0}},   // far pointer: no flat target
        {{0xFF, 0xFF}}, {{0x0F}}, {{}}
    };
    if (!x64)
        for (auto& entry : samples)
            if (entry.address == 0x140001000) entry.address = 0x401000;
    const size_t full_count = samples.size();
    for (size_t i = 0; i < full_count; ++i) {
        for (size_t length = 1; length < samples[i].bytes.size(); ++length) {
            sample truncated{samples[i].bytes, samples[i].address};
            truncated.bytes.resize(length);
            samples.push_back(std::move(truncated));
        }
    }
    return samples;
}

inline std::vector<sample> random_samples(bool x64, size_t count = 16384) {
    uint32_t state = 0x5A17C0DE;
    const auto next = [&state] {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        return state;
    };
    std::vector<sample> samples;
    samples.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        sample entry;
        entry.address = (x64 ? 0x140000000ull : 0x400000ull) + i * 16;
        entry.bytes.resize(1 + next() % ZYDIS_MAX_INSTRUCTION_LENGTH);
        for (auto& byte : entry.bytes) byte = static_cast<uint8_t>(next());
        samples.push_back(std::move(entry));
    }
    return samples;
}

inline result evaluate(const std::vector<sample>& samples, bool x64) {
    ZydisDecoder reference{};
    ZydisDecoderInit(&reference,
        x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
        x64 ? ZYDIS_STACK_WIDTH_64 : ZYDIS_STACK_WIDTH_32);
    ds::engine_t legacy;
    legacy.init(x64);
    hype::Disassembler decoder;
    decoder.set_arch(x64 ? hype::Arch::X64 : hype::Arch::X86);
    hype::Insn actual{}; // Deliberately reused: stale fields must not leak.
    result report;
    for (const auto& entry : samples) {
        ++report.cases;
        bool match = true;
        ZydisDecodedInstruction instruction{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        const bool valid = ZYAN_SUCCESS(ZydisDecoderDecodeFull(&reference,
            entry.bytes.data(), entry.bytes.size(), &instruction, operands));
        const bool ok = decoder.decode(entry.address, entry.bytes.data(),
                                       entry.bytes.size(), actual, false);
        const auto old = legacy.decode(entry.address, entry.bytes.data(), entry.bytes.size(), false);
        report.check(ok == valid, "hyperion.valid", match);
        report.check(old.has_value() == valid, "legacy.valid", match);
        if (!valid || !ok || !old) { report.exact += match; continue; }
        ++report.decoded;
        const auto converted = ds::hyperion_session::session_t::convert(actual);
        report.check(actual.len == instruction.length && old->length == instruction.length,
                     "length", match);
        report.check(actual.mnemonic_id == instruction.mnemonic && old->mnemonic == instruction.mnemonic,
                     "mnemonic_id", match);
        report.check(actual.op_count == instruction.operand_count_visible &&
                     converted.op_count == instruction.operand_count_visible &&
                     old->op_count == instruction.operand_count_visible, "operand_count", match);
        const auto category = instruction.meta.category;
        const auto flow = category == ZYDIS_CATEGORY_CALL ? ds::flow_t::call :
                          category == ZYDIS_CATEGORY_UNCOND_BR ? ds::flow_t::jmp :
                          category == ZYDIS_CATEGORY_COND_BR ? ds::flow_t::jcc :
                          category == ZYDIS_CATEGORY_RET ? ds::flow_t::ret : ds::flow_t::none;
        report.check(old->flow == flow && converted.flow == flow, "flow", match);
        uint64_t target = 0, ip_memory = 0;
        bool has_target = false, has_ip_memory = false;
        for (uint8_t i = 0; i < instruction.operand_count_visible; ++i) {
            const auto& source = operands[i];
            uint64_t absolute = 0;
            const bool resolved = ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(
                &instruction, &source, entry.address, &absolute));
            if (!x64 && source.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && source.imm.is_relative)
                absolute = static_cast<uint32_t>(absolute);
            if (source.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && source.imm.is_relative && resolved &&
                (flow == ds::flow_t::call || flow == ds::flow_t::jmp || flow == ds::flow_t::jcc)) {
                has_target = true; target = absolute;
            }
            if (source.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                (source.mem.base == ZYDIS_REGISTER_RIP || source.mem.base == ZYDIS_REGISTER_EIP) && resolved) {
                has_ip_memory = true; ip_memory = absolute;
            }
            if (i >= actual.op_count) continue;
            const auto& op = actual.ops[i];
            const bool read = (source.actions & ZYDIS_OPERAND_ACTION_MASK_READ) != 0;
            const bool write = (source.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) != 0;
            report.check(op.size == source.size, "operand_size", match);
            report.check(op.read == read && op.write == write && old->ops[i].read == read &&
                         old->ops[i].write == write && converted.ops[i].read == read &&
                         converted.ops[i].write == write, "operand_actions", match);
            switch (source.type) {
            case ZYDIS_OPERAND_TYPE_REGISTER:
                report.check(op.type == hype::OpType::Reg && op.reg == source.reg.value &&
                             old->ops[i].reg == source.reg.value && converted.ops[i].reg == source.reg.value,
                             "register", match);
                break;
            case ZYDIS_OPERAND_TYPE_IMMEDIATE:
                report.check(op.type == hype::OpType::Imm &&
                             op.val == (source.imm.is_relative ? absolute : source.imm.value.u),
                             "immediate", match);
                break;
            case ZYDIS_OPERAND_TYPE_MEMORY:
                report.check(op.type == hype::OpType::Mem && op.mem.base == source.mem.base &&
                             op.mem.index == source.mem.index && op.mem.scale == source.mem.scale &&
                             op.mem.disp == source.mem.disp.value, "memory_shape", match);
                report.check(op.val == (resolved ? absolute : 0), "memory_address", match);
                break;
            default: break; // The compact records do not represent far pointers.
            }
        }
        report.check(old->has_rel_target == has_target && converted.has_rel_target == has_target &&
                     (!has_target || (old->rel_target == target && converted.rel_target == target)),
                     "branch_target", match);
        report.check(old->has_rip_rel == has_ip_memory && converted.has_rip_rel == has_ip_memory &&
                     (!has_ip_memory || (old->rip_rel_target == ip_memory && converted.rip_rel_target == ip_memory)),
                     "ip_memory", match);
        report.exact += match;
    }
    return report;
}
} // namespace disasm_accuracy
