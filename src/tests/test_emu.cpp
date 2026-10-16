// src/tests/test_emu.cpp
// Unicorn emulation engine + dynamic taint propagation. Hermetic: synthetic
// code snippets only, no target processes

#include "harness.hpp"

#include "core/emu/session.hpp"
#include "core/emu/taint.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <map>
#include <thread>
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

TEST_CASE(emu_timeout_reports_timeout_reason) {
    // jmp $ with an instruction budget it can never reach
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 1ull << 40;
    req.timeout_ms = 200;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "timeout");
    REQUIRE_GT(r.instructions, 0u);
}

TEST_CASE(emu_cancel_token_stops_running_loop) {
    // jmp $ with a 20 s budget; cancellation must end it long before that
    auto req = base_req({0xEB, 0xFE});
    req.max_instructions = 1ull << 40;
    req.timeout_ms = 20000;
    slop::core::infra::cancel_source_t source;
    req.cancel = source.token();

    const auto started = std::chrono::steady_clock::now();
    std::thread canceller([&source] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        source.request();
    });
    auto r = emulate_run(req);
    canceller.join();
    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cancelled");
    REQUIRE_LT(elapsed, 5000);
}


namespace {

// Page source over a sparse fake image: page va -> bytes (zero padded)
page_source_t fake_pages(std::map<uint64_t, std::vector<uint8_t>> pages) {
    return [pages = std::move(pages)](uint64_t page, uint8_t* out) {
        auto it = pages.find(page);
        if (it == pages.end()) return false;
        std::memset(out, 0, kPageSize);
        std::memcpy(out, it->second.data(), std::min(it->second.size(), kPageSize));
        return true;
    };
}

} // namespace

TEST_CASE(emu_page_in_follows_call_outside_slice) {
    // call 0x401000 / ret ; the callee page is only in the source
    auto req = base_req({0xE8, 0xFB, 0x0F, 0x00, 0x00,
                         0xC3});
    req.page_in = fake_pages({{0x401000, {0xB8, 0x34, 0x12, 0x00, 0x00,   // mov eax,0x1234
                                          0xC3}}});                       // ret
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x1234u);
    REQUIRE_EQ(r.paged_in, 1u);
    REQUIRE(!r.fault.has_value());
}

TEST_CASE(emu_page_in_completes_partial_code_page) {
    // a 2-byte slice runs on into the source's bytes, not zero fill
    auto req = base_req({0x90, 0x90});
    req.page_in = fake_pages({{0x400000, {0x90, 0x90,
                                          0xB8, 0x07, 0x00, 0x00, 0x00,   // mov eax,7
                                          0xC3}}});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 7u);
    REQUIRE_EQ(r.paged_in, 0u);   // completion is not demand paging
}

TEST_CASE(emu_page_in_refusal_and_budget_still_fault) {
    // mov eax,[0xDEAD0000] / ret, the source has no such page
    auto req = base_req({0xA1, 0x00, 0x00, 0xAD, 0xDE, 0x00, 0x00, 0x00, 0x00,
                         0xC3});
    req.page_in = fake_pages({});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(!r.page_in_exhausted);

    // the page exists but the budget is spent
    req.page_in = fake_pages({{0xDEAD0000, {0x11}}});
    req.page_in_max = 0;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(r.page_in_exhausted);

    req.page_in_max = 1;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x11u);
}

namespace {

// mov ecx,0x11 / call [rip+0x1FF5] (IAT slot 0x402000) / add rax,1 / ret
run_request_t import_call_req() {
    auto req = base_req({0xB9, 0x11, 0x00, 0x00, 0x00,
                         0xFF, 0x15, 0xF5, 0x1F, 0x00, 0x00,
                         0x48, 0x83, 0xC0, 0x01,
                         0xC3});
    req.imports.push_back({0x402000, "kernel32.dll!Sleep"});
    req.api_ret = 41;
    req.trace = true;
    return req;
}

void require_one_sleep_call(const run_result_t& r) {
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs.at("rax"), 42u);
    REQUIRE_EQ(r.total_api_calls, 1u);
    REQUIRE_EQ(r.api_calls.size(), 1u);
    REQUIRE_STR_EQ(r.api_calls[0].name.c_str(), "kernel32.dll!Sleep");
    REQUIRE_EQ(r.api_calls[0].ip, 0x400005ull);
    REQUIRE_EQ(r.api_calls[0].ret, 0x40000Bull);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x11ull);
    bool traced = false;
    for (const auto& t : r.trace)
        if (t.text == "api kernel32.dll!Sleep") traced = true;
    REQUIRE(traced);
}

} // namespace

TEST_CASE(emu_import_stub_in_mapped_iat) {
    auto req = import_call_req();
    emu_mem_region_t iat;
    iat.addr = 0x402000;
    iat.bytes.assign(8, 0);
    req.maps.push_back(iat);
    require_one_sleep_call(emulate_run(req));
}

TEST_CASE(emu_import_stub_patched_on_page_in) {
    // the IAT page holds the on-disk hint/name rva until the stub patch lands
    auto req = import_call_req();
    req.page_in = fake_pages({{0x402000, {0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}});
    auto r = emulate_run(req);
    require_one_sleep_call(r);
    REQUIRE_EQ(r.paged_in, 1u);
}

TEST_CASE(emu_teb_peb_behind_gs) {
    // mov rax,gs:[0x30] / mov rcx,gs:[0x60] / mov rdx,[rcx+0x10] /
    // movzx r8d,byte [rcx+2] / ret
    auto req = base_req({0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,
                         0x65, 0x48, 0x8B, 0x0C, 0x25, 0x60, 0x00, 0x00, 0x00,
                         0x48, 0x8B, 0x51, 0x10,
                         0x44, 0x0F, 0xB6, 0x41, 0x02,
                         0xC3});
    req.image_base = 0x140000000;
    req.regs["r8"] = 0xFF;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.teb_mapped);
    REQUIRE_EQ(r.regs["rax"], r.regs["gs_base"]);
    REQUIRE_EQ(r.regs["rcx"], r.regs["gs_base"] + 0x2000);
    REQUIRE_EQ(r.regs["rdx"], 0x140000000ull);
    REQUIRE_EQ(r.regs["r8"], 0u);             // BeingDebugged

    // a caller gs_base replaces the fake TEB
    req.regs["gs_base"] = 0x500000;
    emu_mem_region_t teb;
    teb.addr = 0x500000;
    teb.bytes.assign(0x100, 0);
    teb.bytes[0x30] = 0x77;
    req.maps.push_back(teb);
    req.code.resize(9);                       // just the first load
    req.code.push_back(0xC3);
    r = emulate_run(req);
    REQUIRE(!r.teb_mapped);
    REQUIRE_EQ(r.regs["rax"], 0x77u);
}

TEST_CASE(emu_dump_and_write_values) {
    // mov dword [0x500000],0xDEADBEEF / ret
    auto req = base_req({0xC7, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                         0xEF, 0xBE, 0xAD, 0xDE,
                         0xC3});
    emu_mem_region_t data;
    data.addr = 0x500000;
    data.bytes.assign(0x10, 0);
    req.maps.push_back(data);
    // untouched source page, an unmapped range, and one straddling the end
    req.page_in = fake_pages({{0x600000, {0xAA, 0xBB}}});
    req.dumps = {{0x500000, 8}, {0x600000, 2}, {0x900000, 4}, {0x500FFE, 4}};
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");

    REQUIRE_EQ(r.writes.size(), 1u);
    REQUIRE_EQ(r.writes[0].len, 4u);
    REQUIRE_EQ(r.writes[0].value, 0xDEADBEEFull);

    REQUIRE_EQ(r.memory.size(), 4u);
    const std::vector<uint8_t> want = {0xEF, 0xBE, 0xAD, 0xDE, 0, 0, 0, 0};
    REQUIRE(r.memory[0].bytes == want);
    REQUIRE(r.memory[1].bytes == std::vector<uint8_t>({0xAA, 0xBB}));
    REQUIRE(r.memory[2].bytes.empty());
    REQUIRE_EQ(r.memory[3].bytes.size(), 2u);   // cut at the unmapped page
    REQUIRE_EQ(r.paged_in, 0u);                 // dumps never map pages
}
