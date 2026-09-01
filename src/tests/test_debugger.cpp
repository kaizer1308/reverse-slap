// src/tests/test_debugger.cpp
// Pure planning/store logic for the debugger engine. The OS debug loop is
// exercised live against SlopTarget by manual QA; everything derivable here

#include "harness.hpp"

#include "core/debugger/debugger.hpp"
#include "core/disasm/engine.hpp"

#include <cstring>

using namespace slop::core::debugger;
namespace disasm = slop::core::disasm;

namespace {

disasm::insn_t decode_one(disasm::engine_t& e, uint64_t va,
                          const uint8_t* code, size_t len) {
    auto insn = e.decode(va, code, len);
    if (!insn.has_value()) {
        // Return a zero-length insn so planners can be probed defensively
        disasm::insn_t dummy;
        dummy.va = va;
        return dummy;
    }
    return *insn;
}

} // namespace

TEST_CASE(step_over_call_plants_temp_bp_after) {
    disasm::engine_t e;
    REQUIRE(e.init());

    const uint8_t code[] = {0xE8, 0x10, 0x00, 0x00, 0x00};   // call +0x10
    const uint64_t va = 0x14001000;
    const auto insn = decode_one(e, va, code, sizeof(code));

    const auto plan = plan_step_over(insn);
    REQUIRE_EQ(plan.kind, step_action_t::temp_breakpoint);
    REQUIRE_EQ(plan.temp_addr, va + 5);
}

TEST_CASE(step_over_plain_insn_single_steps) {
    disasm::engine_t e;
    REQUIRE(e.init());

    const uint8_t code[] = {0x48, 0x89, 0xE8};               // mov rax,rbp
    const auto insn = decode_one(e, 0x1000, code, sizeof(code));

    const auto plan = plan_step_over(insn);
    REQUIRE_EQ(plan.kind, step_action_t::trap_flag);
}

TEST_CASE(step_over_jcc_single_steps_through) {
    disasm::engine_t e;
    REQUIRE(e.init());

    const uint8_t code[] = {0x74, 0x20};                     // je short
    const auto insn = decode_one(e, 0x1000, code, sizeof(code));

    // Conditional jumps must be stepped THROUGH (trap flag), not skipped:
    // both paths are legitimate step targets
    const auto plan = plan_step_over(insn);
    REQUIRE_EQ(plan.kind, step_action_t::trap_flag);
}

TEST_CASE(step_out_targets_return_address) {
    const uint64_t rsp = 0x00FFA000;
    const uint64_t ret = 0x1400ABCD;
    const auto plan = plan_step_out(rsp, ret);
    REQUIRE_EQ(plan.kind, step_action_t::temp_breakpoint);
    REQUIRE_EQ(plan.temp_addr, ret);                          // [rsp] == ret
}

TEST_CASE(bp_store_full_lifecycle) {
    bp_store_t store;

    REQUIRE(store.add(0x1000, 0x90, false));
    REQUIRE(store.add(0x2000, 0x48, true));                   // hardware

    REQUIRE_EQ(store.size(), 2u);

    auto* b1 = store.find(0x1000);
    REQUIRE(b1 != nullptr);
    REQUIRE_EQ(b1->orig_byte, 0x90);
    REQUIRE(!b1->hardware);

    auto* b2 = store.find(0x2000);
    REQUIRE(b2 != nullptr);
    REQUIRE(b2->hardware);

    REQUIRE(store.remove(0x1000));
    REQUIRE(!store.remove(0x1000));                           // already gone
    REQUIRE_EQ(store.size(), 1u);
    REQUIRE(store.find(0x1000) == nullptr);
}

TEST_CASE(bp_store_rejects_duplicate_addresses) {
    bp_store_t store;
    REQUIRE(store.add(0x5000, 0xCC, false));
    REQUIRE(!store.add(0x5000, 0x90, false));                 // same addr twice
    REQUIRE_EQ(store.size(), 1u);
}
