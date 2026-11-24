// src/tests/test_emu.cpp
// Unicorn emulation engine + dynamic taint propagation. Hermetic: synthetic
// code snippets only, no target processes

#include "harness.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/emu/image.hpp"
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
    // one id per vector register whatever its width, so SSE copies carry taint
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_XMM0), (uint32_t)ZYDIS_REGISTER_ZMM0);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_YMM9), (uint32_t)ZYDIS_REGISTER_ZMM9);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_EFLAGS), (uint32_t)ZYDIS_REGISTER_RFLAGS);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_CS), 0u);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_RIP), 0u);
    REQUIRE_EQ(taint_canonical_reg(ZYDIS_REGISTER_ST0), 0u);
    REQUIRE_STR_EQ(taint_reg_name(ZYDIS_REGISTER_R10).c_str(), "r10");
    REQUIRE_STR_EQ(taint_reg_name(ZYDIS_REGISTER_ZMM3).c_str(), "xmm3");
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

TEST_CASE(emu_smallest_stack_runs) {
    auto req = base_req({0xB8, 0x02, 0x00, 0x00, 0x00,
                         0xC3});
    req.stack_size = 0x1000;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 2u);
}

TEST_CASE(emu_regs_rsp_is_the_entry_stack_pointer) {
    auto req = base_req({0x48, 0x89, 0xE0,
                         0xC3});
    req.regs["rsp"] = 0x380000;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x380000ull);
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
    req.imports.push_back({0x402000, "user32.dll!MessageBoxW"});
    req.api_ret = 41;
    req.trace = true;
    return req;
}

void require_one_stub_call(const run_result_t& r) {
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs.at("rax"), 42u);
    REQUIRE_EQ(r.total_api_calls, 1u);
    REQUIRE_EQ(r.api_calls.size(), 1u);
    REQUIRE_STR_EQ(r.api_calls[0].name.c_str(), "user32.dll!MessageBoxW");
    REQUIRE_EQ(r.api_calls[0].ip, 0x400005ull);
    REQUIRE_EQ(r.api_calls[0].ret, 0x40000Bull);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x11ull);
    bool traced = false;
    for (const auto& t : r.trace)
        if (t.text == "api user32.dll!MessageBoxW") traced = true;
    REQUIRE(traced);
}

} // namespace

TEST_CASE(emu_import_stub_in_mapped_iat) {
    auto req = import_call_req();
    emu_mem_region_t iat;
    iat.addr = 0x402000;
    iat.bytes.assign(8, 0);
    req.maps.push_back(iat);
    require_one_stub_call(emulate_run(req));
}

TEST_CASE(emu_import_stub_patched_on_page_in) {
    // the IAT page holds the on-disk hint/name rva until the stub patch lands
    auto req = import_call_req();
    req.page_in = fake_pages({{0x402000, {0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}});
    auto r = emulate_run(req);
    require_one_stub_call(r);
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

// === taint precision ===

TEST_CASE(taint_ranges_are_exact_at_page_edges) {
    taint_tracker_t t;
    t.mark_memory(0x1FFE, 2);        // run ending on the last byte of a page
    t.mark_memory(0x2FFF, 2);        // run crossing into the next page
    t.mark_memory(0x9000, 1);        // first byte of a page far away
    auto ranges = t.tainted_ranges();
    REQUIRE_EQ(ranges.size(), 3u);
    REQUIRE_EQ(ranges[0].addr, 0x1FFEull);
    REQUIRE_EQ(ranges[0].len, 2u);
    REQUIRE_EQ(ranges[1].addr, 0x2FFFull);
    REQUIRE_EQ(ranges[1].len, 2u);
    REQUIRE_EQ(ranges[2].addr, 0x9000ull);
    REQUIRE_EQ(ranges[2].len, 1u);

    // a run open at the very end of the last page keeps its real length
    taint_tracker_t tail;
    tail.mark_memory(0x4FFD, 3);
    ranges = tail.tainted_ranges();
    REQUIRE_EQ(ranges.size(), 1u);
    REQUIRE_EQ(ranges[0].addr, 0x4FFDull);
    REQUIRE_EQ(ranges[0].len, 3u);
}

TEST_CASE(taint_shadow_clear_and_copy) {
    taint_tracker_t t;
    t.mark_memory(0x1000, 8);
    t.clear_memory(0x1002, 2);
    REQUIRE(t.memory_any(0x1000, 2));
    REQUIRE(!t.memory_any(0x1002, 2));
    REQUIRE(t.memory_any(0x1004, 4));
    t.clear_memory(0x0, 0x100000);   // spans untracked pages
    REQUIRE(!t.memory_any(0x1000, 8));

    // byte-for-byte, clean source bytes untaint the destination
    t.mark_memory(0x2001, 2);
    t.mark_memory(0x3000, 4);
    t.copy_memory(0x3000, 0x2000, 4);
    REQUIRE(!t.memory_any(0x3000, 1));
    REQUIRE(t.memory_any(0x3001, 1));
    REQUIRE(t.memory_any(0x3002, 1));
    REQUIRE(!t.memory_any(0x3003, 1));
    // overlapping, destination ahead of the source
    t.copy_memory(0x2002, 0x2001, 2);
    REQUIRE(t.memory_any(0x2001, 1));
    REQUIRE(t.memory_any(0x2002, 2));
    REQUIRE(!t.memory_any(0x2004, 1));
}

namespace {

constexpr uint64_t kSrc = 0x500000, kDst = 0x500100, kDst2 = 0x500200;

// code over a zeroed data page, [kSrc, kSrc + taint_len) tainted
run_result_t run_tainted(std::initializer_list<uint8_t> code, size_t taint_len = 4,
                         uint64_t watch = kDst, size_t watch_len = 4) {
    auto req = base_req(code);
    emu_mem_region_t data;
    data.addr = kSrc;
    data.bytes.assign(0x1000, 0x5A);
    req.maps.push_back(data);
    req.taint_sources.push_back({kSrc, taint_len});
    req.watch_addr = watch;
    req.watch_len  = watch_len;
    return emulate_run(req);
}

bool range_tainted(const run_result_t& r, uint64_t addr, size_t len) {
    for (const auto& rg : r.taint_ranges)
        if (rg.addr < addr + len && rg.addr + rg.len > addr) return true;
    return false;
}

} // namespace

TEST_CASE(taint_stack_pointer_is_not_a_carrier) {
    // mov eax,[src] / push rax / pop rbx / xor ecx,ecx / push rcx / pop rdx /
    // mov [dst],edx / mov [dst2],ebx / ret
    // pushing a tainted value must not taint rsp, or every later push and pop
    // carries taint (the clean rcx round trip here came out tainted)
    auto r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0x50, 0x5B,
                          0x31, 0xC9,
                          0x51, 0x5A,
                          0x89, 0x14, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0x89, 0x1C, 0x25, 0x00, 0x02, 0x50, 0x00,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(!r.output_tainted);                 // edx was a constant
    REQUIRE(range_tainted(r, kDst2, 4));        // ebx went through the stack
}

TEST_CASE(taint_lea_arithmetic_propagates) {
    // mov edx,[src] / lea eax,[rdx+rdx*2] / mov [dst],eax / ret
    auto r = run_tainted({0x8B, 0x14, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0x8D, 0x04, 0x52,
                          0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.output_tainted);
}

TEST_CASE(taint_clean_store_clears_memory) {
    // mov dword [src],0 / ret : the tainted input is overwritten by a constant
    auto r = run_tainted({0xC7, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00, 0, 0, 0, 0,
                          0xC3}, 4, kSrc, 4);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(!r.output_tainted);
    REQUIRE(r.taint_ranges.empty());
}

TEST_CASE(taint_flows_through_sse_registers) {
    // movdqu xmm0,[src] / movdqu [dst],xmm0 / ret : how compilers copy structs
    auto r = run_tainted({0xF3, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0xF3, 0x0F, 0x7F, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.output_tainted);
    bool saw_xmm = false;
    for (const auto& e : r.taint_events)
        if (e.kind == "reg" && e.target == "xmm0") saw_xmm = true;
    REQUIRE(saw_xmm);

    // movdqu xmm0,[src] / pxor xmm0,xmm0 / movdqu [dst],xmm0 / ret
    r = run_tainted({0xF3, 0x0F, 0x6F, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                     0x66, 0x0F, 0xEF, 0xC0,
                     0xF3, 0x0F, 0x7F, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                     0xC3});
    REQUIRE(!r.output_tainted);
}

TEST_CASE(taint_partial_and_conditional_writes_keep_old_taint) {
    // mov eax,[src] / test esp,esp / cmovz eax,ecx (not taken) / mov [dst],eax / ret
    auto r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0x85, 0xE4,
                          0x0F, 0x44, 0xC1,
                          0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.output_tainted);

    // mov eax,[src] / mov al,0 / mov [dst],eax / ret : three bytes are still input
    r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                     0xB0, 0x00,
                     0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                     0xC3});
    REQUIRE(r.output_tainted);

    // mov eax,[src] / xor al,al / mov [dst],eax / ret : same for a partial zeroing
    r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                     0x30, 0xC0,
                     0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                     0xC3});
    REQUIRE(r.output_tainted);

    // mov eax,[src] / mov eax,7 / mov [dst],eax / ret : a full write replaces it
    r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                     0xB8, 0x07, 0x00, 0x00, 0x00,
                     0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                     0xC3});
    REQUIRE(!r.output_tainted);
}

TEST_CASE(taint_xchg_swaps_and_call_pushes_clean) {
    // mov eax,[src] / xor ecx,ecx / xchg ecx,eax / mov [dst],eax / mov [dst2],ecx / ret
    auto r = run_tainted({0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0x31, 0xC9,
                          0x91,
                          0x89, 0x04, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0x89, 0x0C, 0x25, 0x00, 0x02, 0x50, 0x00,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(!r.output_tainted);
    REQUIRE(range_tainted(r, kDst2, 4));

    // mov rax,[src] / lea rax,[rip+2] / call rax / ret ; target: ret
    // the return address a call pushes is never input data
    r = run_tainted({0x48, 0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                     0x48, 0x8D, 0x05, 0x03, 0x00, 0x00, 0x00,
                     0xFF, 0xD0,
                     0xC3,
                     0xC3}, 8);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.taint_ranges.size(), 1u);      // just the source
    REQUIRE_EQ(r.taint_ranges[0].addr, kSrc);
}

TEST_CASE(taint_event_cap_keeps_propagation_sound) {
    // mov esi,600 / L: mov eax,[src] / mov [dst],ecx / xor eax,eax / dec esi /
    // jnz L / ret : 600 "rax tainted" events against a cap of 512. Hitting
    // the cap used to skip the per-instruction reset, so the clean store
    // after the load came out tainted
    auto r = run_tainted({0xBE, 0x58, 0x02, 0x00, 0x00,
                          0x8B, 0x04, 0x25, 0x00, 0x00, 0x50, 0x00,
                          0x89, 0x0C, 0x25, 0x00, 0x01, 0x50, 0x00,
                          0x31, 0xC0,
                          0xFF, 0xCE,
                          0x75, 0xEC,
                          0xC3});
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.taint_events.size(), taint_tracker_t::kMaxEvents);
    REQUIRE(!r.output_tainted);
    REQUIRE_EQ(r.taint_ranges.size(), 1u);
}

TEST_CASE(taint_rep_movsb_copies_byte_granular) {
    // mov esi,src / mov edi,dst / mov ecx,8 / rep movsb / mov [dst2],esi / ret
    auto req = base_req({0xBE, 0x00, 0x00, 0x50, 0x00,
                         0xBF, 0x00, 0x01, 0x50, 0x00,
                         0xB9, 0x08, 0x00, 0x00, 0x00,
                         0xF3, 0xA4,
                         0x89, 0x34, 0x25, 0x00, 0x02, 0x50, 0x00,
                         0xC3});
    emu_mem_region_t data;
    data.addr = kSrc;
    data.bytes.assign(0x1000, 0x5A);
    req.maps.push_back(data);
    req.taint_sources.push_back({kSrc + 2, 2});   // two bytes in the middle
    req.trace = true;
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.taint_ranges.size(), 2u);
    REQUIRE_EQ(r.taint_ranges[1].addr, kDst + 2);
    REQUIRE_EQ(r.taint_ranges[1].len, 2u);
    REQUIRE(!range_tainted(r, kDst2, 4));         // the pointers are not data

    // one trace line for the whole rep, eight iterations
    REQUIRE_EQ(r.trace.size(), 6u);
    REQUIRE_EQ(r.trace[3].repeat, 8u);
    REQUIRE_EQ(r.trace[4].repeat, 1u);
    // the budget counts every iteration, plus the pass that sees rcx at zero
    REQUIRE_EQ(r.instructions, 14u);

    // the count is settled when the rep is left, even with the trace full by
    // then and rcx reused afterwards
    //   mov ecx,3 / rep stosb / mov ecx,0x99 / ret   (rdi at the data page)
    auto full = base_req({0xB9, 0x03, 0x00, 0x00, 0x00, 0xF3, 0xAA,
                          0xB9, 0x99, 0x00, 0x00, 0x00, 0xC3});
    full.maps.push_back(data);
    full.regs["rdi"] = kDst;
    full.trace = true;
    full.trace_max = 2;
    auto f = emulate_run(full);
    REQUIRE_STR_EQ(f.stopped_reason.c_str(), "return");
    REQUIRE_EQ(f.trace.size(), 2u);
    REQUIRE_EQ(f.trace[1].repeat, 3u);

    // a budget that runs out mid-rep still reports what ran
    req.max_instructions = 3 + 5;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "count");
    REQUIRE_EQ(r.trace.size(), 4u);
    REQUIRE_EQ(r.trace[3].repeat, 5u);
}

// === CPU environment ===

TEST_CASE(emu_cpu_starts_like_a_windows_user_thread) {
    // mov eax,cs / mov ebx,ss / pushfq / pop rcx / sub rsp,0x18 / fnstcw [rsp] /
    // stmxcsr [rsp+8] / movzx edx,word [rsp] / mov esi,[rsp+8] / add rsp,0x18 / ret
    auto req = base_req({0x8C, 0xC8,
                         0x8C, 0xD3,
                         0x9C, 0x59,
                         0x48, 0x83, 0xEC, 0x18,
                         0xD9, 0x3C, 0x24,
                         0x0F, 0xAE, 0x5C, 0x24, 0x08,
                         0x0F, 0xB7, 0x14, 0x24,
                         0x8B, 0x74, 0x24, 0x08,
                         0x48, 0x83, 0xC4, 0x18,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x33u);       // ring 3 long-mode code
    REQUIRE_EQ(r.regs["rbx"], 0x2Bu);
    REQUIRE_EQ(r.regs["rcx"], 0x202u);      // interrupts enabled
    REQUIRE_EQ(r.regs["rdx"], 0x27Fu);      // x87 control word
    REQUIRE_EQ(r.regs["rsi"], 0x1F80u);     // mxcsr

    req.kernel_mode = true;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x10u);
    REQUIRE_EQ(r.regs["rbx"], 0x18u);

    // a caller rflags still wins
    req.regs["rflags"] = 0x246;
    r = emulate_run(req);
    REQUIRE_EQ(r.regs["rcx"], 0x246u);
}

TEST_CASE(emu_privileged_instructions_fault_in_user_mode) {
    // hlt / mov eax,1 / ret
    auto req = base_req({0xF4, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3});
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");   // was "count"
    REQUIRE(r.exception.has_value());
    REQUIRE_EQ(r.exception->vector, 13);
    REQUIRE_EQ(r.exception->code, 0xC0000096u);
    REQUIRE_STR_EQ(r.exception->name.c_str(), "privileged_instruction");
    REQUIRE_EQ(r.exception->ip, 0x400000ull);
    REQUIRE_EQ(r.regs["rax"], 0u);

    // ring 0: hlt parks the cpu, and it is reported as that
    req.kernel_mode = true;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "halt");
    REQUIRE(!r.exception.has_value());

    // cli / mov rax,cr0 / in al,dx / sti / ret : fine for a driver
    auto drv = base_req({0xFA, 0x0F, 0x20, 0xC0, 0xEC, 0xFB, 0xC3});
    drv.kernel_mode = true;
    r = emulate_run(drv);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    drv.kernel_mode = false;
    r = emulate_run(drv);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE_EQ(r.exception->ip, 0x400000ull);

    // in al,dx / ret : the VMware backdoor probe faults on real Windows
    r = emulate_run(base_req({0xEC, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE_STR_EQ(r.exception->name.c_str(), "privileged_instruction");
}

TEST_CASE(emu_cpu_exceptions_name_the_vector) {
    // xor ecx,ecx / mov eax,1 / div ecx / ret
    auto r = emulate_run(base_req({0x31, 0xC9, 0xB8, 0x01, 0x00, 0x00, 0x00,
                                   0xF7, 0xF1, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE(r.exception.has_value());
    REQUIRE_EQ(r.exception->vector, 0);
    REQUIRE_EQ(r.exception->code, 0xC0000094u);
    REQUIRE_EQ(r.exception->ip, 0x400007ull);
    REQUIRE(!r.exception->insn.empty());

    // nop / int3 / ret
    r = emulate_run(base_req({0x90, 0xCC, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE_EQ(r.exception->vector, 3);
    REQUIRE_EQ(r.exception->code, 0x80000003u);
    REQUIRE_EQ(r.exception->ip, 0x400001ull);

    // mov ecx,7 / int 29h : __fastfail(FAST_FAIL_FATAL_APP_EXIT)
    r = emulate_run(base_req({0xB9, 0x07, 0x00, 0x00, 0x00, 0xCD, 0x29, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE_STR_EQ(r.exception->name.c_str(), "fail_fast");
    REQUIRE_EQ(r.exception->code, 0xC0000409u);
    REQUIRE_EQ(r.regs["rcx"], 7u);

    // ud2
    r = emulate_run(base_req({0x0F, 0x0B}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_insn");
    REQUIRE_EQ(r.exception->code, 0xC000001Du);

    // pushfq / or dword [rsp],0x100 / popfq / nop / nop / ret : the trap flag
    // single-steps the instruction after popfq
    r = emulate_run(base_req({0x9C, 0x81, 0x0C, 0x24, 0x00, 0x01, 0x00, 0x00,
                              0x9D, 0x90, 0x90, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE_STR_EQ(r.exception->name.c_str(), "single_step");
}

TEST_CASE(emu_syscalls_are_logged_and_answered) {
    // mov r10,rcx / mov eax,0x55 / syscall / ret
    auto req = base_req({0x4C, 0x8B, 0xD1,
                         0xB8, 0x55, 0x00, 0x00, 0x00,
                         0x0F, 0x05,
                         0xC3});
    req.regs["rcx"] = 0x1111;
    req.regs["rdx"] = 0x2222;
    req.api_ret = 0xC0000022;   // STATUS_ACCESS_DENIED
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.total_api_calls, 1u);
    REQUIRE_STR_EQ(r.api_calls[0].name.c_str(), "syscall:0x55");
    REQUIRE_EQ(r.api_calls[0].ip, 0x400008ull);
    REQUIRE_EQ(r.api_calls[0].ret, 0x40000Aull);
    REQUIRE_EQ(r.api_calls[0].args[0], 0x1111ull);
    REQUIRE_EQ(r.api_calls[0].args[1], 0x2222ull);
    REQUIRE_EQ(r.regs["rax"], 0xC0000022ull);   // was left at the syscall number
    REQUIRE_EQ(r.regs["rcx"], 0x40000Aull);     // sysret clobbers rcx and r11
    REQUIRE_EQ(r.regs["r11"], 0x202ull);
}

TEST_CASE(emu_time_stamp_counter_is_deterministic) {
    // rdtsc / shl rdx,32 / or rax,rdx / mov rbx,rax / rdtsc / shl rdx,32 /
    // or rax,rdx / ret
    auto req = base_req({0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0,
                         0x48, 0x89, 0xC3,
                         0x0F, 0x31, 0x48, 0xC1, 0xE2, 0x20, 0x48, 0x09, 0xD0,
                         0xC3});
    auto a = emulate_run(req);
    auto b = emulate_run(req);
    REQUIRE_STR_EQ(a.stopped_reason.c_str(), "return");
    REQUIRE_EQ(a.regs["rax"], b.regs["rax"]);         // was the host clock
    REQUIRE_EQ(a.regs["rbx"], b.regs["rbx"]);
    REQUIRE_GT(a.regs["rax"], a.regs["rbx"]);         // and it moves forward
    REQUIRE_LT(a.regs["rax"] - a.regs["rbx"], 1000u);
}

TEST_CASE(emu_cpuid_reports_bare_metal) {
    // mov eax,1 / cpuid / mov r8d,ecx / mov eax,0x40000000 / cpuid / ret
    auto r = emulate_run(base_req({0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2,
                                   0x41, 0x89, 0xC8,
                                   0xB8, 0x00, 0x00, 0x00, 0x40, 0x0F, 0xA2,
                                   0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["r8"] & 0x80000000u, 0u);       // no hypervisor bit
    REQUIRE_NE(r.regs["r8"] & (1u << 20), 0u);        // SSE4.2 is still there
    REQUIRE_EQ(r.regs["r8"] & (1u << 28), 0u);        // AVX is not offered
    REQUIRE_EQ(r.regs["rbx"], 0u);                    // no hypervisor vendor leaf
    REQUIRE_EQ(r.regs["rcx"], 0u);

    // cpuid as the last instruction before the budget runs out
    auto req = base_req({0xB8, 0x01, 0x00, 0x00, 0x00, 0x0F, 0xA2, 0x90, 0x90});
    req.max_instructions = 2;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "count");
    REQUIRE_EQ(r.regs["rcx"] & 0x80000000u, 0u);
}

TEST_CASE(emu_avx_is_refused_not_miscomputed) {
    // movq xmm0,rax / movq xmm1,rbx / movq xmm2,rcx / vpxor xmm0,xmm1,xmm2 /
    // movq rax,xmm0 / ret
    // The cpu core runs VEX.128 as legacy SSE and drops the first source:
    // this used to return 0x0F ^ 0x33 instead of 0xF0 ^ 0x33
    auto req = base_req({0x66, 0x48, 0x0F, 0x6E, 0xC0,
                         0x66, 0x48, 0x0F, 0x6E, 0xCB,
                         0x66, 0x48, 0x0F, 0x6E, 0xD1,
                         0xC5, 0xF1, 0xEF, 0xC2,
                         0x66, 0x48, 0x0F, 0x7E, 0xC0,
                         0xC3});
    req.regs["rax"] = 0x0F;
    req.regs["rbx"] = 0xF0;
    req.regs["rcx"] = 0x33;
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "unsupported_insn");
    REQUIRE(r.exception.has_value());
    REQUIRE_EQ(r.exception->ip, 0x40000Full);
    REQUIRE_EQ(r.instructions, 3u);
    REQUIRE_EQ(r.regs["rax"], 0x0Fu);            // nothing wrong was computed

    // vpxor xmm0,xmm0,xmm2: destination is the first source, same as pxor
    req.code[16] = 0xF9;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x0Fu ^ 0x33u);

    // vpxor ymm0,ymm1,ymm2: 256-bit is not implemented at all
    req.code[16] = 0xF5;
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_insn");
    REQUIRE_EQ(r.exception->ip, 0x40000Full);
    REQUIRE(r.exception->insn.find("ymm") != std::string::npos);

    // mov ecx,0x0F / mov edx,0xFF / andn eax,ecx,edx / ret : BMI is VEX too,
    // and correct
    r = emulate_run(base_req({0xB9, 0x0F, 0x00, 0x00, 0x00,
                              0xBA, 0xFF, 0x00, 0x00, 0x00,
                              0xC4, 0xE2, 0x70, 0xF2, 0xC2,
                              0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0xF0u);
}

TEST_CASE(emu_avx_scan_follows_self_modifying_code) {
    //  00: C6 05 0A 00 00 00 F9    mov byte [rip+0xA],0xF9   -> offset 0x11
    //  07: EB 00                   jmp +0 (ends the block)
    //  09: 66 48 0F 6E D1          movq xmm2,rcx
    //  0E: 90 90                   nop nop
    //  10: C5 F1 EF C2             vpxor xmm0,xmm1,xmm2 -> xmm0,xmm0,xmm2
    //  14: C3                      ret
    // the three-operand form is rewritten to the safe one before it runs
    auto req = base_req({0xC6, 0x05, 0x0A, 0x00, 0x00, 0x00, 0xF9,
                         0xEB, 0x00,
                         0x66, 0x48, 0x0F, 0x6E, 0xD1,
                         0x90, 0x90,
                         0xC5, 0xF1, 0xEF, 0xC2,
                         0xC3});
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");

    //  00: B9 02 00 00 00          mov ecx,2
    //  05: 66 48 0F 6E D0          movq xmm2,rax              <- L
    //  0A: C5 F9 EF C2             vpxor xmm0,xmm0,xmm2       (safe)
    //  0E: C6 05 F6 FF FF FF F1    mov byte [rip-0xA],0xF1    -> offset 0x0B
    //  15: FF C9                   dec ecx
    //  17: 75 EC                   jnz L
    //  19: C3                      ret
    // the block was scanned while it was safe; the store into it has to make
    // the second pass look again
    r = emulate_run(base_req({0xB9, 0x02, 0x00, 0x00, 0x00,
                              0x66, 0x48, 0x0F, 0x6E, 0xD0,
                              0xC5, 0xF9, 0xEF, 0xC2,
                              0xC6, 0x05, 0xF6, 0xFF, 0xFF, 0xFF, 0xF1,
                              0xFF, 0xC9,
                              0x75, 0xEC,
                              0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "unsupported_insn");
    REQUIRE_EQ(r.exception->ip, 0x40000Aull);
    REQUIRE_EQ(r.regs["rcx"], 1u);
}

TEST_CASE(emu_kernel_half_addresses_work) {
    // lea rax,[rip+0x100] / mov dword [rax],0x11223344 / mov ebx,[rax] / ret
    const uint64_t base = 0xFFFFF80012340000ull;
    auto req = base_req({0x48, 0x8D, 0x05, 0x00, 0x01, 0x00, 0x00,
                         0xC7, 0x00, 0x44, 0x33, 0x22, 0x11,
                         0x8B, 0x18,
                         0xC3}, base);
    req.kernel_mode = true;
    req.dumps = {{base + 0x107, 4}};
    auto r = emulate_run(req);
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");   // was invalid_mem_fetch
    REQUIRE_EQ(r.regs["rbx"], 0x11223344u);
    REQUIRE_EQ(r.writes.size(), 1u);
    REQUIRE_EQ(r.writes[0].addr, base + 0x107);           // a real va, not its low 52 bits
    REQUIRE(r.memory[0].bytes == std::vector<uint8_t>({0x44, 0x33, 0x22, 0x11}));

    // mov rax,0xFFFFF80099990000 / mov eax,[rax] : paged in at the kernel va
    auto pg = base_req({0x48, 0xB8, 0x00, 0x00, 0x99, 0x99, 0x00, 0xF8, 0xFF, 0xFF,
                        0x8B, 0x00, 0xC3}, base);
    pg.kernel_mode = true;
    pg.page_in = fake_pages({{0xFFFFF80099990000ull, {0x78, 0x56, 0x34, 0x12}}});
    r = emulate_run(pg);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x12345678u);

    pg.page_in = fake_pages({});
    r = emulate_run(pg);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE_EQ(r.fault->addr, 0xFFFFF80099990000ull);

    // mov rax,0xFFFFF7800000026C / mov eax,[rax] : the shared data page at
    // its kernel address (KI_USER_SHARED_DATA)
    auto ku = base_req({0x48, 0xB8, 0x6C, 0x02, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF,
                        0x8B, 0x00, 0xC3}, base);
    ku.kernel_mode = true;
    r = emulate_run(ku);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 10u);
}

TEST_CASE(emu_fault_address_keeps_stray_high_bits) {
    // mov rax,0x4000000000001000 / mov eax,[rax+8] / ret
    auto r = emulate_run(base_req({0x48, 0xB8, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
                                   0x8B, 0x40, 0x08, 0xC3}));
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE_EQ(r.fault->addr, 0x4000000000001008ull);   // was 0x1008
    REQUIRE_EQ(r.fault->ip, 0x40000Aull);
}

TEST_CASE(emu_shared_user_data_page) {
    // mov eax,[0x7FFE026C] / mov ebx,[0x7FFE0260] / movzx ecx,byte [0x7FFE02D4] / ret
    auto req = base_req({0x8B, 0x04, 0x25, 0x6C, 0x02, 0xFE, 0x7F,
                         0x8B, 0x1C, 0x25, 0x60, 0x02, 0xFE, 0x7F,
                         0x0F, 0xB6, 0x0C, 0x25, 0xD4, 0x02, 0xFE, 0x7F,
                         0xC3});
    req.regs["rcx"] = 0xFF;
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");   // was invalid_mem_read
    REQUIRE_EQ(r.regs["rax"], 10u);                       // NtMajorVersion
    REQUIRE_GT(r.regs["rbx"], 10000u);                    // NtBuildNumber
    REQUIRE_EQ(r.regs["rcx"], 0u);                        // KdDebuggerEnabled
    REQUIRE_EQ(r.paged_in, 0u);

    // an attached process supplies its own
    std::vector<uint8_t> real(0x300, 0);
    real[0x26C] = 6;
    req.page_in = fake_pages({{0x7FFE0000, real}});
    r = emulate_run(req);
    REQUIRE_EQ(r.regs["rax"], 6u);
    REQUIRE_EQ(r.paged_in, 1u);
}

TEST_CASE(emu_shared_user_data_clocks_advance_at_both_addresses) {
    auto req = base_req({0x8B, 0x04, 0x25, 0x08, 0x00, 0xFE, 0x7F,
                         0x48, 0xBB, 0x08, 0x00, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF,
                         0x8B, 0x1B,
                         0xB9, 0xA0, 0x86, 0x01, 0x00,
                         0xFF, 0xC9,
                         0x75, 0xFC,
                         0x8B, 0x14, 0x25, 0x08, 0x00, 0xFE, 0x7F,
                         0x48, 0xBE, 0x08, 0x00, 0x00, 0x00, 0x80, 0xF7, 0xFF, 0xFF,
                         0x8B, 0x36,
                         0xC3});
    req.kernel_mode = true;
    req.max_instructions = 1000000;
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_GT(r.regs["rdx"], r.regs["rax"]);
    REQUIRE_GT(r.regs["rsi"], r.regs["rbx"]);
}

TEST_CASE(emu_teb_tls_and_peb_fields) {
    // mov rax,gs:[0x58] / mov rax,[rax+rcx*8] / mov eax,[rax+4] /
    // mov rdx,gs:[0x60] / mov ebx,[rdx+0x118] / mov rsi,[rdx+0x30] /
    // mov esi,[rsi+0x70] / ret
    auto req = base_req({0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00,
                         0x48, 0x8B, 0x04, 0xC8,
                         0x8B, 0x40, 0x04,
                         0x65, 0x48, 0x8B, 0x14, 0x25, 0x60, 0x00, 0x00, 0x00,
                         0x8B, 0x9A, 0x18, 0x01, 0x00, 0x00,
                         0x48, 0x8B, 0x72, 0x30,
                         0x8B, 0x76, 0x70,
                         0xC3});
    req.has_tls   = true;
    req.tls_index = 3;
    req.tls_block = {0, 0, 0, 0, 0xEF, 0xBE, 0xAD, 0xDE};
    req.regs["rcx"] = 3;
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(r.tls_mapped);
    REQUIRE_EQ(r.regs["rax"], 0xDEADBEEFu);   // the image's thread_local data
    REQUIRE_EQ(r.regs["rbx"], 10u);           // PEB.OSMajorVersion
    REQUIRE_EQ(r.regs["rsi"], 2u);            // ProcessHeap->Flags: HEAP_GROWABLE

    // without a TLS directory the pointer stays null, as in a thread without one
    req.has_tls = false;
    r = emulate_run(req);
    REQUIRE(!r.tls_mapped);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
}

// === api models ===

namespace {

constexpr uint64_t kIat = 0x402000;

// Win64 code that calls imports through an IAT at kIat, over a data page at kSrc
struct api_code_t {
    std::vector<uint8_t>     b;
    std::vector<std::string> imports;

    api_code_t& raw(std::initializer_list<uint8_t> x) { b.insert(b.end(), x); return *this; }
    api_code_t& imm32(uint32_t v) {
        for (int i = 0; i < 4; ++i) b.push_back(static_cast<uint8_t>(v >> (8 * i)));
        return *this;
    }
    api_code_t& rcx(uint32_t v) { return raw({0x48, 0xC7, 0xC1}).imm32(v); }
    api_code_t& rdx(uint32_t v) { return raw({0x48, 0xC7, 0xC2}).imm32(v); }
    api_code_t& r8(uint32_t v)  { return raw({0x49, 0xC7, 0xC0}).imm32(v); }
    api_code_t& r9(uint32_t v)  { return raw({0x49, 0xC7, 0xC1}).imm32(v); }
    // call qword [rip+rel32] through the import's slot
    api_code_t& call(const std::string& import) {
        size_t slot = 0;
        while (slot < imports.size() && imports[slot] != import) ++slot;
        if (slot == imports.size()) imports.push_back(import);
        raw({0xFF, 0x15});
        const uint64_t next = 0x400000 + b.size() + 4;
        return imm32(static_cast<uint32_t>(kIat + slot * 8 - next));
    }
    api_code_t& ret() { return raw({0xC3}); }

    run_request_t request() const {
        run_request_t req;
        req.code = b;
        req.code_base = 0x400000;
        for (size_t i = 0; i < imports.size(); ++i)
            req.imports.push_back({kIat + i * 8, imports[i]});
        emu_mem_region_t iat;
        iat.addr = kIat;
        iat.bytes.assign(0x100, 0);
        req.maps.push_back(iat);
        emu_mem_region_t data;
        data.addr = kSrc;
        data.bytes.assign(0x1000, 0);
        const char text[] = "hello, slop";
        std::memcpy(data.bytes.data(), text, sizeof(text));
        req.maps.push_back(data);
        return req;
    }
};

} // namespace

TEST_CASE(emu_api_model_memory_and_strings) {
    // strlen(src) -> rbx ; memcpy(dst, src, rbx + 1) ; memset(dst + 5, '!', 2) ;
    // strcmp(dst, src) -> rax
    api_code_t c;
    c.rcx(kSrc).call("vcruntime140.dll!strlen").raw({0x48, 0x89, 0xC3});      // mov rbx,rax
    c.rcx(kDst).rdx(kSrc).raw({0x4C, 0x8D, 0x43, 0x01})                       // lea r8,[rbx+1]
     .call("vcruntime140.dll!memcpy").raw({0x48, 0x89, 0xC6});                // mov rsi,rax
    c.rcx(kDst + 5).rdx('!').r8(2).call("vcruntime140.dll!memset");
    c.rcx(kDst).rdx(kSrc).call("ucrtbase.dll!strcmp").ret();
    auto req = c.request();
    req.dumps = {{kDst, 12}};
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rbx"], 11u);                       // strlen("hello, slop")
    REQUIRE_EQ(r.regs["rsi"], kDst);                      // memcpy returns dst
    REQUIRE_EQ(r.memory[0].bytes.size(), 12u);
    REQUIRE(std::memcmp(r.memory[0].bytes.data(), "hello!!slop", 12) == 0);
    REQUIRE_EQ(r.regs["rax"], 0xFFFFFFFFu);               // '!' sorts before ',': int -1 in eax
    REQUIRE_EQ(r.total_api_calls, 4u);
    for (const auto& call : r.api_calls) REQUIRE(call.modeled);
    REQUIRE_EQ(r.api_calls[0].rax, 11u);
    // the model's stores are in the write log, attributed to the call
    bool saw_copy = false;
    for (const auto& w : r.writes)
        if (w.addr == kDst && w.len == 12 && w.ip == r.api_calls[1].ip) saw_copy = true;
    REQUIRE(saw_copy);
}

TEST_CASE(emu_api_model_heap) {
    // p = malloc(0x20) ; memset(p, 0xAB, 0x20) ; q = HeapAlloc(GetProcessHeap(), 8, 0x1000) ;
    // rax = *p ; rdi = q ; rsi = *q
    api_code_t c;
    c.rcx(0x20).call("ucrtbase.dll!malloc").raw({0x48, 0x89, 0xC3});          // mov rbx,rax
    c.raw({0x48, 0x89, 0xC1}).rdx(0xAB).r8(0x20).call("vcruntime140.dll!memset");
    c.call("kernel32.dll!GetProcessHeap").raw({0x48, 0x89, 0xC1})             // mov rcx,rax
     .rdx(8).r8(0x1000).call("kernel32.dll!HeapAlloc")
     .raw({0x48, 0x89, 0xC7})                                                 // mov rdi,rax
     .raw({0x48, 0x8B, 0x30})                                                 // mov rsi,[rax]
     .raw({0x48, 0x8B, 0x03})                                                 // mov rax,[rbx]
     .ret();
    auto r = emulate_run(c.request());
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");   // malloc returning 0 faulted here
    REQUIRE_EQ(r.regs["rax"], 0xABABABABABABABABull);
    REQUIRE_NE(r.regs["rbx"], 0u);
    REQUIRE_EQ(r.regs["rbx"] & 0xF, 0u);                  // 16-byte aligned
    REQUIRE_NE(r.regs["rdi"], r.regs["rbx"]);
    REQUIRE_EQ(r.regs["rsi"], 0u);                        // fresh memory is zeroed
    REQUIRE_GE(r.heap_used, 0x1020u);

    // the heap is finite: a huge request fails like the real one
    api_code_t big;
    big.raw({0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0x7F})                       // mov rcx,0x7FFFFFFF
       .call("ucrtbase.dll!malloc").ret();
    r = emulate_run(big.request());
    REQUIRE_EQ(r.regs["rax"], 0u);

    // VirtualAlloc(0x700000, 0x2000, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE) ; *rax = 7
    api_code_t va;
    va.rcx(0x700000).rdx(0x2000).r8(0x3000).r9(4).call("kernel32.dll!VirtualAlloc")
      .raw({0xC7, 0x80, 0xFC, 0x1F, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00})      // mov dword [rax+0x1FFC],7
      .ret();
    r = emulate_run(va.request());
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rax"], 0x700000u);
}

TEST_CASE(emu_api_model_overrides) {
    api_code_t c;
    c.rcx(0x20).call("ucrtbase.dll!malloc").ret();

    // a per-import return value beats the model: force the failure path
    auto req = c.request();
    req.imports[0].has_ret = true;
    req.imports[0].ret = 0;
    auto r = emulate_run(req);
    REQUIRE_EQ(r.regs["rax"], 0u);
    REQUIRE(!r.api_calls[0].modeled);

    // models off: every import is the plain api_ret stub again
    req = c.request();
    req.api_models = false;
    req.api_ret = 0x1234;
    r = emulate_run(req);
    REQUIRE_EQ(r.regs["rax"], 0x1234u);
    REQUIRE(!r.api_calls[0].modeled);
    REQUIRE_EQ(r.heap_used, 0u);
}

TEST_CASE(emu_jump_into_stub_padding_is_not_an_import_call) {
    auto req = base_req({0x48, 0x8B, 0x04, 0x25, 0x00, 0x20, 0x40, 0x00,
                         0x48, 0xFF, 0xC0,
                         0xFF, 0xE0});
    req.imports.push_back({kIat, "kernel32.dll!GetLastError"});
    emu_mem_region_t iat;
    iat.addr = kIat;
    iat.bytes.assign(0x100, 0);
    req.maps.push_back(iat);
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "cpu_exception");
    REQUIRE(r.exception.has_value());
    REQUIRE_STR_EQ(r.exception->name.c_str(), "breakpoint");
    REQUIRE(r.api_calls.empty());
    REQUIRE_EQ(r.total_api_calls, 0u);

    req.code.erase(req.code.begin() + 8, req.code.begin() + 11);
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.total_api_calls, 1u);
}

TEST_CASE(emu_api_model_exit_and_raise_stop_the_run) {
    // ExitProcess(7) ; mov eax,1 ; ret : nothing after the call may run
    api_code_t c;
    c.rcx(7).call("kernel32.dll!ExitProcess").raw({0xB8, 0x01, 0x00, 0x00, 0x00}).ret();
    auto r = emulate_run(c.request());
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "exit");     // was "return" with rax=1
    REQUIRE(r.exit.has_value());
    REQUIRE_EQ(r.exit->code, 7u);
    REQUIRE_STR_EQ(r.exit->api.c_str(), "kernel32.dll!ExitProcess");
    REQUIRE_NE(r.regs["rax"], 1u);
    REQUIRE_EQ(r.total_api_calls, 1u);

    // RaiseException(0xE0001234, 0, 0, 0)
    api_code_t x;
    x.raw({0xB9, 0x34, 0x12, 0x00, 0xE0}).rdx(0).r8(0).r9(0)
     .call("kernel32.dll!RaiseException").raw({0xB8, 0x01, 0x00, 0x00, 0x00}).ret();
    r = emulate_run(x.request());
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "api_exception");
    REQUIRE(r.exception.has_value());
    REQUIRE_EQ(r.exception->code, 0xE0001234u);
    REQUIRE_EQ(r.exception->vector, -1);
    REQUIRE_EQ(r.exception->ip, r.api_calls[0].ip);
}

TEST_CASE(emu_api_model_teb_state_and_clock) {
    // SetLastError(5) ; GetLastError() -> rbx ; TlsAlloc() -> rsi ;
    // TlsSetValue(rsi, 0x77) ; TlsGetValue(rsi) -> rdi ; IsDebuggerPresent() -> r12 ;
    // GetTickCount() -> r13 ; Sleep(1000) ; GetTickCount() - r13 -> rax
    api_code_t c;
    c.rcx(5).call("kernel32.dll!SetLastError");
    c.call("kernel32.dll!GetLastError").raw({0x48, 0x89, 0xC3});              // mov rbx,rax
    c.call("kernel32.dll!TlsAlloc").raw({0x48, 0x89, 0xC6});                  // mov rsi,rax
    c.raw({0x48, 0x89, 0xF1}).rdx(0x77).call("kernel32.dll!TlsSetValue");     // mov rcx,rsi
    c.raw({0x48, 0x89, 0xF1}).call("kernel32.dll!TlsGetValue").raw({0x48, 0x89, 0xC7});
    c.call("kernel32.dll!IsDebuggerPresent").raw({0x49, 0x89, 0xC4});         // mov r12,rax
    c.call("kernel32.dll!GetTickCount").raw({0x49, 0x89, 0xC5});              // mov r13,rax
    c.rcx(1000).call("kernel32.dll!Sleep");
    c.call("kernel32.dll!GetTickCount").raw({0x4C, 0x29, 0xE8}).ret();        // sub rax,r13
    auto req = c.request();
    req.regs["r12"] = 0xFF;
    req.dumps = {{0x140000 + 0x68, 4}};   // TEB.LastErrorValue
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE_EQ(r.regs["rbx"], 5u);
    REQUIRE_LT(r.regs["rsi"], 64u);
    REQUIRE_EQ(r.regs["rdi"], 0x77u);
    REQUIRE_EQ(r.regs["r12"], 0u);
    REQUIRE_GE(r.regs["rax"], 1000u);     // a skipped sleep would read ~0
    REQUIRE_LT(r.regs["rax"], 1010u);
    // TlsGetValue reset the last error, the way the real one does
    REQUIRE(r.memory[0].bytes == std::vector<uint8_t>({0, 0, 0, 0}));
}

TEST_CASE(emu_api_model_fault_is_attributed_to_the_call) {
    // memcpy(dst, 0x900000, 0x10) : the source is not mapped anywhere
    api_code_t c;
    c.rcx(kDst).rdx(0x900000).r8(0x10).call("vcruntime140.dll!memcpy").ret();
    auto r = emulate_run(c.request());
    REQUIRE(r.ok);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE(r.fault.has_value());
    REQUIRE_EQ(r.fault->addr, 0x900000ull);
    REQUIRE_EQ(r.fault->ip, r.api_calls[0].ip);

    // a garbage length walks until it leaves mapped memory, then faults
    api_code_t wild;
    wild.rcx(kSrc).rdx(kDst).raw({0x49, 0xB8, 0, 0, 0, 0, 0, 0x01, 0, 0})      // mov r8,1<<40
        .call("vcruntime140.dll!memcpy").ret();
    r = emulate_run(wild.request());
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_read");
    REQUIRE_EQ(r.fault->addr, kSrc + 0x1000);

    // a copy that runs off the end of its destination stores what fits first
    api_code_t tail;
    tail.rcx(kSrc + 0xFF8).rdx(kSrc).r8(0x10).call("vcruntime140.dll!memcpy").ret();
    auto req = tail.request();
    req.dumps = {{kSrc + 0xFF8, 8}};
    r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "invalid_mem_write");
    REQUIRE_EQ(r.fault->addr, kSrc + 0x1000);
}

TEST_CASE(taint_flows_through_api_models) {
    // memcpy(dst, src, 8) ; strlen(src) -> [dst2]
    api_code_t c;
    c.rcx(kDst).rdx(kSrc).r8(8).call("vcruntime140.dll!memcpy");
    c.rcx(kSrc).call("vcruntime140.dll!strlen")
     .raw({0x89, 0x04, 0x25}).imm32(static_cast<uint32_t>(kDst2)).ret();      // mov [dst2],eax
    auto req = c.request();
    req.taint_sources.push_back({kSrc + 1, 2});
    req.watch_addr = kDst2;
    req.watch_len  = 4;
    auto r = emulate_run(req);
    REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
    REQUIRE(range_tainted(r, kDst + 1, 2));      // the copy carried the two bytes
    REQUIRE(!range_tainted(r, kDst, 1));
    REQUIRE(!range_tainted(r, kDst + 3, 5));
    REQUIRE(r.output_tainted);                   // a length computed from tainted bytes
}

// === the image as the loader maps it ===

namespace {

// A PE32+ with one section at rva 0x1000 holding a TLS directory, its
// template, the base relocations for the directory's pointers, and code
struct tls_pe_t {
    static constexpr uint64_t kImageBase = 0x140000000ull;
    static constexpr uint32_t kTlsDir = 0x1000, kTemplate = 0x1100, kIndex = 0x1200,
                              kReloc = 0x1300, kCode = 0x1400;
    std::vector<uint8_t> file;
    slop::core::disasm::pe_image_t pe;

    explicit tls_pe_t(uint16_t subsystem = 3) {
        file.assign(0x400 + 0x600, 0);
        auto put = [this](size_t off, uint64_t v, size_t n) { std::memcpy(file.data() + off, &v, n); };
        put(0, 0x5A4D, 2);                    // MZ
        put(0x3C, 0x40, 4);                   // e_lfanew
        put(0x40, 0x00004550, 4);             // PE signature
        put(0x44, 0x8664, 2);                 // machine
        put(0x46, 1, 2);                      // sections
        put(0x54, 240, 2);                    // optional header size
        put(0x56, 0x0022, 2);                 // executable, large address aware
        const size_t oh = 0x58;
        put(oh, 0x20B, 2);                    // PE32+
        put(oh + 16, kCode, 4);               // entry
        put(oh + 24, kImageBase, 8);
        put(oh + 32, 0x1000, 4);              // section alignment
        put(oh + 36, 0x200, 4);               // file alignment
        put(oh + 56, 0x3000, 4);              // size of image
        put(oh + 60, 0x400, 4);               // size of headers
        put(oh + 68, subsystem, 2);
        put(oh + 108, 16, 4);                 // number of data directories
        const size_t dd = oh + 112;
        put(dd + 5 * 8, kReloc, 4);           // base relocations
        put(dd + 5 * 8 + 4, 16, 4);
        put(dd + 9 * 8, kTlsDir, 4);          // TLS
        put(dd + 9 * 8 + 4, 40, 4);
        const size_t sh = oh + 240;
        std::memcpy(file.data() + sh, ".slop", 5);
        put(sh + 8, 0x2000, 4);               // virtual size
        put(sh + 12, 0x1000, 4);              // rva
        put(sh + 16, 0x600, 4);               // raw size
        put(sh + 20, 0x400, 4);               // raw offset
        put(sh + 36, 0xE0000020, 4);          // code, rwx

        auto at = [](uint32_t rva) { return size_t{0x400} + (rva - 0x1000); };
        // IMAGE_TLS_DIRECTORY64: 8 template bytes, 8 more of zero fill
        put(at(kTlsDir), kImageBase + kTemplate, 8);
        put(at(kTlsDir) + 8, kImageBase + kTemplate + 8, 8);
        put(at(kTlsDir) + 16, kImageBase + kIndex, 8);
        put(at(kTlsDir) + 32, 8, 4);
        for (uint8_t i = 0; i < 8; ++i) file[at(kTemplate) + i] = static_cast<uint8_t>(i + 1);
        // one block for page 0x1000: DIR64 fixups on the three pointers
        put(at(kReloc), 0x1000, 4);
        put(at(kReloc) + 4, 16, 4);
        put(at(kReloc) + 8, 0xA000, 2);
        put(at(kReloc) + 10, 0xA008, 2);
        put(at(kReloc) + 12, 0xA010, 2);
        // mov rax,gs:[0x58] / mov rax,[rax] / mov rbx,[rax+8] / mov rax,[rax] / ret
        const uint8_t code[] = {0x65, 0x48, 0x8B, 0x04, 0x25, 0x58, 0x00, 0x00, 0x00,
                                0x48, 0x8B, 0x00,
                                0x48, 0x8B, 0x58, 0x08,
                                0x48, 0x8B, 0x00,
                                0xC3};
        std::memcpy(file.data() + at(kCode), code, sizeof(code));
        pe = slop::core::disasm::pe_parse(file.data(), file.size());
    }

    image_bytes_t bytes() const { return {&pe, file.data(), file.size(), true}; }
};

} // namespace

TEST_CASE(emu_image_view_relocates_and_supplies_tls) {
    tls_pe_t img;
    REQUIRE(img.pe.ok);
    REQUIRE(!image_is_kernel(img.pe));

    for (const uint64_t base : {tls_pe_t::kImageBase, uint64_t{0x7FF612340000ull}}) {
        auto view = image_view_t::make(img.bytes(), base);
        // the directory's pointers follow the image wherever it is loaded
        uint64_t start = 0;
        view->read(img.bytes(), tls_pe_t::kTlsDir, 8, reinterpret_cast<uint8_t*>(&start));
        REQUIRE_EQ(start, base + tls_pe_t::kTemplate);
        // a read that begins in the middle of a fixup still sees it applied
        uint8_t mid[4] = {};
        view->read(img.bytes(), tls_pe_t::kTlsDir + 4, 4, mid);
        REQUIRE_EQ(mid[0], static_cast<uint8_t>((base + tls_pe_t::kTemplate) >> 32));

        run_request_t req;
        REQUIRE(attach_image(&req, img.bytes(), base));
        REQUIRE_EQ(req.image_base, base);
        REQUIRE(!req.kernel_mode);
        REQUIRE(req.has_tls);
        REQUIRE_EQ(req.tls_index, 0u);
        REQUIRE(req.tls_block == std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8,
                                                       0, 0, 0, 0, 0, 0, 0, 0}));

        // the thread_local read a compiler emits: TEB -> slot array -> block
        req.code.resize(20);
        view->read(img.bytes(), tls_pe_t::kCode, req.code.size(), req.code.data());
        req.code_base = base + tls_pe_t::kCode;
        req.regs["rbx"] = 0xFF;
        auto r = emulate_run(req);
        REQUIRE_STR_EQ(r.stopped_reason.c_str(), "return");
        REQUIRE(r.tls_mapped);
        REQUIRE_EQ(r.regs["rax"], 0x0807060504030201ull);
        REQUIRE_EQ(r.regs["rbx"], 0u);        // the zero-filled tail
    }

    // a driver: native subsystem and no ntdll import, so it runs in ring 0
    tls_pe_t drv(1);
    REQUIRE(image_is_kernel(drv.pe));
    run_request_t req;
    REQUIRE(attach_image(&req, drv.bytes(), tls_pe_t::kImageBase));
    REQUIRE(req.kernel_mode);

    // 32-bit code is not something this cpu runs
    slop::core::disasm::pe_image_t x86 = img.pe;
    x86.pe32plus = false;
    x86.machine  = 0x14C;
    run_request_t none;
    REQUIRE(!attach_image(&none, {&x86, img.file.data(), img.file.size(), true},
                          tls_pe_t::kImageBase));
}
