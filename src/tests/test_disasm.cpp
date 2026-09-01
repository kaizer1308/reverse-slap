// src/tests/test_disasm.cpp
// Tests for core/disasm: engine, pe_parser, strings, function_index, xrefs
// Uses the real built SlopTarget.exe as a live PE fixture

#include "harness.hpp"

#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/disasm/strings.hpp"
#include "core/disasm/xrefs.hpp"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

using namespace slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

} // namespace

// === engine ===

TEST_CASE(engine_decode_pe32_default_widths) {
    engine_t engine;
    REQUIRE(engine.init(false));
    static const uint8_t bytes[] = {0x8B, 0x01};
    const auto instruction = engine.decode(0x401000, bytes, sizeof(bytes));
    REQUIRE(instruction.has_value());
    REQUIRE_EQ(instruction->length, 2u);
    REQUIRE_EQ(instruction->ops[0].reg, ZYDIS_REGISTER_EAX);
    REQUIRE_EQ(instruction->ops[1].mem_base, ZYDIS_REGISTER_ECX);
}

TEST_CASE(engine_init_and_decode_mov) {
    engine_t e;
    REQUIRE(e.init());

    // 48 89 E8 = mov rax, rbp (formatter uppercases mnemonics)
    const uint8_t code[] = {0x48, 0x89, 0xE8};
    auto insn = e.decode(0x140001000, code, sizeof(code));
    REQUIRE(insn.has_value());
    REQUIRE_EQ(insn->length, 3);

    std::string lower = insn->text;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    REQUIRE(lower.find("mov") != std::string::npos);
    REQUIRE(lower.find("rax") != std::string::npos);
    REQUIRE(lower.find("rbp") != std::string::npos);
    REQUIRE(insn->flow == flow_t::none);
}

TEST_CASE(engine_call_rel32_resolves_target) {
    engine_t e;
    REQUIRE(e.init());

    // e8 10 00 00 00 = call +0x10 -> target = va + 5 + 16
    const uint8_t code[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    const uint64_t va = 0x140010000;
    auto insn = e.decode(va, code, sizeof(code));
    REQUIRE(insn.has_value());
    REQUIRE(insn->flow == flow_t::call);
    REQUIRE(insn->has_rel_target);
    REQUIRE_EQ(insn->rel_target, va + 5 + 0x10);
}

TEST_CASE(engine_ret_and_garbage) {
    engine_t e;
    REQUIRE(e.init());

    const uint8_t ret_b[] = {0xC3};
    auto r = e.decode(0x1000, ret_b, sizeof(ret_b));
    REQUIRE(r.has_value());
    REQUIRE(r->flow == flow_t::ret);

    const uint8_t junk[] = {0xFF, 0xFF};
    REQUIRE(!e.decode(0x1000, junk, sizeof(junk)).has_value());
}

// === pe_parser against the real SlopTarget.exe ===

TEST_CASE(pe_parse_slop_target_headers) {
    const auto& bytes = slop_target_bytes();
    REQUIRE_GT(bytes.size(), 1024u);

    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE(pe.pe32plus);
    REQUIRE_EQ(pe.machine, 0x8664);          // AMD64
    REQUIRE(pe.entry_rva != 0);
    REQUIRE_GE(pe.sections.size(), 3u);       // .text/.rdata/.data at minimum
    REQUIRE(pe.image_base != 0);

    // Entry point must map back into the file
    REQUIRE(pe.rva_to_offset(pe.entry_rva).has_value());
}

TEST_CASE(pe_parse_slop_target_sections_roundtrip) {
    auto pe = pe_parse(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(pe.ok);

    bool has_text = false;
    bool text_exec = false;
    for (const auto& s : pe.sections) {
        if (std::string(s.name) == ".text") {
            has_text = true;
            text_exec = s.is_executable();
        }
    }
    REQUIRE(has_text);
    REQUIRE(text_exec);

    // offset_to_va inverts va_to_offset for the entrypoint
    auto entry_off = pe.rva_to_offset(pe.entry_rva);
    REQUIRE(entry_off.has_value());
    auto entry_va = pe.offset_to_va(*entry_off);
    REQUIRE(entry_va.has_value());
    REQUIRE_EQ(*entry_va, pe.image_base + pe.entry_rva);
}

TEST_CASE(pe_parse_imports_present) {
    auto pe = pe_parse(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(pe.ok);
    REQUIRE(!pe.imports.empty());

    bool any_kernel32 = false;
    for (const auto& dll : pe.imports) {
        // Every import must have a plausible DLL name
        REQUIRE(!dll.dll.empty());
        if (_stricmp(dll.dll.c_str(), "KERNEL32.dll") == 0)
            any_kernel32 = true;
    }
    REQUIRE(any_kernel32);   // MSVC-linked exes always import kernel32
}

// === strings: synthetic determinism first ===

TEST_CASE(strings_synthetic_ascii_and_utf16) {
    // Layout: non-printable junk, "hello world\0", junk byte, UTF-16 L"ABC\0"
    std::vector<uint8_t> buf;
    const uintptr_t base = 0x1000;

    buf.insert(buf.end(), {0xAA, 0xBB, 0xCC});                    // @0 non-printable
    const size_t ascii_off = buf.size();
    for (const char c : std::string("hello world"))
        buf.push_back(static_cast<uint8_t>(c));
    buf.push_back(0x00);
    buf.push_back(0xEE);                                          // separator junk

    const size_t u16_off = buf.size();
    buf.insert(buf.end(), {'A', 0x00, 'B', 0x00, 'C', 0x00, 0x00, 0x00});

    auto hits = extract_strings(buf.data(), buf.size(), base, 2);
    REQUIRE_GE(hits.size(), 2u);

    bool found_a = false, found_u = false;
    for (const auto& h : hits) {
        if (!h.utf16 && h.text == "hello world" && h.va == base + ascii_off)
            found_a = true;
        if (h.utf16 && h.text == "ABC" && h.va == base + u16_off)
            found_u = true;
    }
    REQUIRE(found_a);
    REQUIRE(found_u);
}

TEST_CASE(strings_reject_short_and_unterminated) {
    std::vector<uint8_t> buf;
    for (const char c : std::string("abc"))                       // too short (<4)
        buf.push_back(static_cast<uint8_t>(c));
    buf.push_back(0x00);
    for (const char c : std::string("no-terminator-string"))      // truly unterminated
        buf.push_back(static_cast<uint8_t>(c));                   // (std::string range excludes NUL)

    string_stats_t st;
    auto hits = extract_strings(buf.data(), buf.size(), 0x2000, 4, 1000, &st);
    REQUIRE(hits.empty());
    REQUIRE(!st.truncated);
}

TEST_CASE(strings_scan_real_image_finds_data) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Scan every non-executable section with raw data
    size_t total_hits = 0;
    for (const auto& s : pe.sections) {
        if (s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > bytes.size()) continue;
        auto hits = extract_strings(bytes.data() + s.raw_offset, s.raw_size,
                                    pe.image_base + s.rva, 6);
        total_hits += hits.size();
        for (const auto& h : hits) {
            REQUIRE(!h.text.empty());
            REQUIRE(h.text.size() >= 6u);
        }
    }
    REQUIRE_GT(total_hits, 10u);   // MSVC binaries carry plenty of strings
}

// === function index + xrefs against the real image ===

TEST_CASE(function_index_discovers_entrypoint) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    engine_t eng;
    REQUIRE(eng.init());

    function_index_t fi;
    REQUIRE(fi.build(pe, bytes, eng, pe.image_base));
    REQUIRE(!fi.functions().empty());

    const uint64_t entry_va = pe.image_base + pe.entry_rva;

    // Entrypoint must be a discovered function start..
    bool entry_listed = false;
    for (const auto& f : fi.functions())
        if (f.va == entry_va) { entry_listed = true; break; }
    REQUIRE(entry_listed);

    // ...and containing() resolves it
    auto owner = fi.containing(entry_va);
    REQUIRE(owner.has_value());
    REQUIRE_EQ(*owner, entry_va);
}

TEST_CASE(xref_index_builds_and_consistent) {
    const auto& bytes = slop_target_bytes();
    auto pe = pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    engine_t eng;
    REQUIRE(eng.init());

    xref_index_t xi;
    REQUIRE(xi.build(pe, bytes, eng, pe.image_base));

    // A linked exe has plenty of calls + rip-relative data refs
    REQUIRE_GT(xi.total(), 20u);

    // Spot-check consistency on a sample of targets
    auto targets = xi.targets();
    REQUIRE(!targets.empty());
    size_t checked = 0;
    size_t seen_refs = 0;
    for (uint64_t t : targets) {
        const auto& refs = xi.refs_to(t);
        seen_refs += refs.size();
        for (const auto& r : refs)
            REQUIRE_EQ(r.to, t);
        if (++checked >= 64) break;
    }
    REQUIRE(seen_refs > 0);
}
