#include "harness.hpp"
#include "disasm_accuracy.hpp"
#include "core/disasm/xrefs.hpp"

namespace {
void require_exact(const disasm_accuracy::result& report) {
    for (const auto& [field, count] : report.mismatches)
        std::printf("  %s: %zu mismatches\n", field.c_str(), count);
    std::printf("  accuracy: %zu/%zu exact, %zu valid\n", report.exact, report.cases, report.decoded);
    REQUIRE_GT(report.decoded, 0u);
    REQUIRE_EQ(report.exact, report.cases);
}
}

TEST_CASE(disasm_accuracy_x64_fixtures) {
    require_exact(disasm_accuracy::evaluate(disasm_accuracy::fixtures(true), true));
}

TEST_CASE(disasm_accuracy_x86_fixtures) {
    require_exact(disasm_accuracy::evaluate(disasm_accuracy::fixtures(false), false));
}

TEST_CASE(disasm_accuracy_x64_random) {
    require_exact(disasm_accuracy::evaluate(disasm_accuracy::random_samples(true), true));
}

TEST_CASE(disasm_accuracy_x86_random) {
    require_exact(disasm_accuracy::evaluate(disasm_accuracy::random_samples(false), false));
}

TEST_CASE(disasm_accuracy_reused_record_clears_inactive_fields) {
    hype::Disassembler decoder;
    hype::Insn out{};
    const uint8_t load[] = {0x48, 0x8B, 0x05, 0x10, 0, 0, 0};
    const uint8_t ret[] = {0xC3};
    REQUIRE(decoder.decode(0x1000, load, sizeof(load), out));
    REQUIRE(decoder.decode(0x2000, ret, sizeof(ret), out));
    REQUIRE_EQ(out.op_count, 0u);
    for (const auto& operand : out.ops) {
        CHECK(operand.type == hype::OpType::None);
        CHECK(operand.val == 0);
        CHECK(!operand.read && !operand.write);
    }
    for (size_t i = out.len; i < sizeof(out.bytes); ++i) CHECK(out.bytes[i] == 0);
}

TEST_CASE(disasm_accuracy_golden_targets_and_fifth_operand) {
    hype::Disassembler decoder;
    hype::Insn out{};
    const uint8_t compare[] = {0x62, 0xF1, 0x64, 0x49, 0xC2, 0xCC, 0x03};
    REQUIRE(decoder.decode(0x1000, compare, sizeof(compare), out));
    REQUIRE_EQ(out.op_count, 5u);
    CHECK(out.ops[4].type == hype::OpType::Imm);
    CHECK(out.ops[4].val == 3);
    CHECK(out.ops[0].write);

    const uint8_t eip_load[] = {0x67, 0x48, 0x8B, 0x05, 0x10, 0, 0, 0};
    disasm_accuracy::ds::engine_t engine;
    REQUIRE(engine.init());
    const auto load = engine.decode(0x1FFFFFFFC, eip_load, sizeof(eip_load));
    REQUIRE(load.has_value());
    CHECK(load->has_rip_rel);
    CHECK(load->rip_rel_target == 0x14);

    decoder.set_arch(hype::Arch::X86);
    const uint8_t jump[] = {0xE9, 0x10, 0, 0, 0};
    REQUIRE(decoder.decode(0xFFFFFFFC, jump, sizeof(jump), out));
    CHECK(out.branch_target() == 0x11);
    const uint8_t absolute[] = {0x8B, 0x05, 0, 0x20, 0x40, 0};
    REQUIRE(decoder.decode(0x401000, absolute, sizeof(absolute), out));
    CHECK(out.ops[1].val == 0x402000);
}

TEST_CASE(disasm_accuracy_indirect_slot_is_data_not_code_xref) {
    namespace ds = disasm_accuracy::ds;
    const std::vector<uint8_t> bytes{
        0xFF, 0x15, 0xFA, 0x0F, 0, 0, // call [rip+0xFFA] -> slot 0x402000
        0xE8, 0x05, 0, 0, 0,          // direct call -> 0x401010
        0xC3
    };
    ds::pe_image_t image;
    image.ok = true;
    image.image_base = 0x400000;
    image.size_of_image = 0x3000;
    ds::pe_section_t text;
    text.rva = 0x1000;
    text.raw_size = static_cast<uint32_t>(bytes.size());
    text.characteristics = 0x60000020;
    image.sections.push_back(text);
    ds::engine_t engine;
    REQUIRE(engine.init());
    ds::xref_index_t refs;
    REQUIRE(refs.build(image, bytes, engine, image.image_base));
    const auto& slot_refs = refs.refs_to(0x402000);
    REQUIRE(slot_refs.size() == 1);
    CHECK(slot_refs.front().kind == ds::xref_kind_t::data);
    const auto& calls = refs.refs_to(0x401010);
    REQUIRE(calls.size() == 1);
    CHECK(calls.front().kind == ds::xref_kind_t::call);
}

TEST_CASE(disasm_accuracy_iret_terminates_cfg) {
    hype::PEImage image{};
    image.arch = hype::Arch::X64;
    image.base = 0x400000;
    image.entry = 0x401000;
    hype::Segment text{};
    text.name = ".text";
    text.va = image.entry;
    text.flags = 0x60000020;
    text.data = {0x48, 0xCF, 0xB8, 0x2A, 0, 0, 0, 0xC3}; // iretq; unreachable mov/ret
    text.size = text.file_sz = text.data.size();
    image.segments.push_back(std::move(text));
    hype::WorkerPool pool(1);
    hype::Analyzer analyzer(image, pool);
    analyzer.run();
    const auto& database = analyzer.db();
    REQUIRE(database.insns.size() == 1);
    CHECK(database.insns.at(image.entry).is_ret());
    const auto& function = database.funcs.at(image.entry);
    REQUIRE(function.blocks.size() == 1);
    CHECK(function.blocks.begin()->second.succs.empty());
    CHECK(function.blocks.begin()->second.end == image.entry + 2);
}
