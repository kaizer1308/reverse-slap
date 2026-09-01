// src/tests/test_emu.cpp
// Unicorn emulation engine + dynamic taint propagation. Hermetic: synthetic
// code snippets only, no target processes

#include "harness.hpp"

#include "core/emu/session.hpp"
#include "core/emu/taint.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <vector>

using namespace slop::core::emu;

namespace {

run_request_t base_req(std::initializer_list<uint8_t> code,
                       uint64_t code_base = 0x400000) {
    run_request_t req;
    req.code = std::vector<uint8_t>(code.begin(), code.end());
    req.code_base = code_base;
    return req;
}

} // namespace

TEST_CASE(taint_canonical_reg_maps_subregisters) {
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_AL), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_AH), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_EAX), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_RAX), (uint32_t)ZYDIS_REGISTER_RAX);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_R8D), (uint32_t)ZYDIS_REGISTER_R8);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_R15W), (uint32_t)ZYDIS_REGISTER_R15);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_XMM0), 0u);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_CS), 0u);
}

TEST_CASE(taint_shadow_memory_roundtrip) {
    taint_tracker_t t;
    t.mark_memory(0x1000, 4);
    REQUIRE(t.memory_any(0x1000, 4));
    REQUIRE(t.memory_any(0x0FFC, 8));       // spans the marked bytes
    REQUIRE(!t.memory_any(0x1010, 4));

    auto ranges = t.tainted_ranges();
    REQUIRE_EQ(ranges.size(), 1u);
    REQUIRE_EQ(ranges[0].addr, 0x1000ull);
    REQUIRE_EQ(ranges[0].len, 4u);
}

TEST_CASE(emu_add_run_and_return_sentinel) {
    // mov eax,2 / add eax,3 / ret
    auto req = base_req({0xB8, 0x02, 0x00, 0x00, 0x00,
                         0x83, 0xC0, 0x03,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.instructions, 3u);
    REQUIRE_EQ(r.regs["rax"], 5u);
}

TEST_CASE(emu_count_budget_stops_loops) {
    // jmp $  (EB FE)
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 500;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "count");
    REQUIRE_EQ(r.instructions, 500u);
}

TEST_CASE(emu_until_address_stops_before_exec) {
    // nop / nop / ret, stop at the second nop
    const uint64_t base = 0x400000;
    auto req = base_req({0x90, 0x90, 0xC3}, base);
    req.until_addr = base + 1;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "until");
    REQUIRE_EQ(r.instructions, 1u);   // first nop executed; second not reached
}

TEST_CASE(emu_invalid_memory_read_reports_fault) {
    // mov eax,[0xDEAD0000] / ret
    auto req = base_req({0xA1, 0x00, 0x00, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(r.fault.has_value());
    REQUIRE_EQ(r.fault->addr, 0xDEAD0000ull);
}

TEST_CASE(emu_register_seeding_and_data_map) {
    // add rax, rcx / ret ; rcx seeded to 7, rax seeded to 35
    auto req = base_req({0x48, 0x01, 0xC8,
                         0xC3});
    req.regs["rax"] = 35;
    req.regs["rcx"] = 7;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 42u);
}

TEST_CASE(taint_propagates_through_memory_load_store) {
    // mov al,[0x500000]      A0 00 00 30 00 00 00 00 00
    // mov [0x500100],al      88 04 25 00 01 30 00
    // ret                    C3
    auto req = base_req({0xA0, 0x00, 0x00, 0x50, 0x00, 0x00, 0x00, 0x00, 0x00,
                         0x88, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x200, 0x41);
    req.maps.push_back(data);

    req.taint_sources.push_back({0x500000, 8});   // input window tainted
    req.watch_addr = 0x500100;
    req.watch_len  = 8;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");

    bool out_marked = false;
    for (const auto& rg : r.taint_ranges) {
        if (rg.addr <= 0x500107 && rg.addr + rg.len > 0x500100)
            out_marked = true;
    }
    REQUIRE(out_marked);
    REQUIRE(r.output_tainted);
    REQUIRE(!r.taint_events.empty());
}

TEST_CASE(taint_propagates_through_registers) {
    // mov cl,[0x500000]      8B 0D ... -> use mov ecx,[..] then xor into eax
    // mov edx,[0x500000]     8B 14 25 00 00 30 00
    // xor eax,edx            31 D0   (eax untainted before, edx tainted after load)
    // mov [0x500200],eax     89 04 25 00 02 30 00
    // ret                    C3
    auto req = base_req({0x8B, 0x14, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x31, 0xD0,
                         0x89, 0x04, 0x25, 0x00, 0x02, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x300, 0);
    req.maps.push_back(data);
    req.regs["rax"] = 0;

    req.taint_sources.push_back({0x500000, 4});
    req.watch_addr = 0x500200;
    req.watch_len  = 4;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.output_tainted);
}

TEST_CASE(taint_zeroing_idiom_clears_flow) {
    // mov edx,[0x500000]     tainted
    // xor edx,edx            zeroing clears
    // mov [0x500200],edx     store must NOT be tainted
    // ret
    auto req = base_req({0x8B, 0x14, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0x31, 0xD2,
                         0x89, 0x14, 0x25, 0x00, 0x02, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x300, 0);
    req.maps.push_back(data);

    req.taint_sources.push_back({0x500000, 4});
    req.watch_addr = 0x500200;
    req.watch_len  = 4;

    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE(!r.output_tainted);
}

TEST_CASE(emu_trace_captures_instruction_text) {
    // inc eax / dec eax / ret
    auto req = base_req({0xFF, 0xC0,
                         0xFF, 0xC8,
                         0xC3});
    req.trace = true;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_EQ(r.trace.size(), 3u);
    bool saw_inc = false, saw_dec = false;
    for (const auto& t : r.trace) {
        std::string lower = t.text;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower.find("inc") != std::string::npos) saw_inc = true;
        if (lower.find("dec") != std::string::npos) saw_dec = true;
    }
    REQUIRE(saw_inc);
    REQUIRE(saw_dec);
}

