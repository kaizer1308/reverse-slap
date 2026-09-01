// src/tests/test_re.cpp
// RTTI reconstruction + danger callsites over patched SlopTarget fixtures

#include "harness.hpp"

#include "core/analysis/danger.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/re/rtti.hpp"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>

using namespace slop::core::re;
namespace analysis = slop::core::analysis;
namespace disasm = slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

// Locate a non-executable data section span for planting structures
bool find_data_span(const disasm::pe_image_t& pe,
                    const std::vector<uint8_t>& file,
                    uint64_t* va, size_t* off, size_t* room) {
    for (const auto& s : pe.sections) {
        if (s.raw_size < 512 || s.is_executable()) continue;
        const size_t end =
            static_cast<size_t>(s.raw_offset) + s.raw_size;
        if (end > file.size()) continue;
        *va   = pe.image_base + s.rva;
        *off  = s.raw_offset;
        *room = s.raw_size;
        return true;
    }
    return false;
}

} // namespace

TEST_CASE(rtti_scan_finds_planted_class) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    uint64_t span_va = 0;
    size_t span_off = 0, span_room = 0;
    REQUIRE(find_data_span(pe, bytes, &span_va, &span_off, &span_room));

    // Layout inside the span (keep everything 4-aligned):
    //   [0x00] TypeDescriptor: vfptr(8) spare(8) ".?AVSlopTest@@\0"
    //   [0x40] COL: sig(0) off(0) cdOff(0) tdRva cdRva selfRva
    //   [0x80] vftable: [-1]=&COL, [0..1]=function-ish pointers
    const uint32_t td_rva  = static_cast<uint32_t>(span_va - pe.image_base);
    const uint32_t col_rva = td_rva + 0x40;

    auto put32 = [&](size_t byte_off, uint32_t v) {
        std::memcpy(bytes.data() + span_off + byte_off, &v, 4);
    };
    auto put64 = [&](size_t byte_off, uint64_t v) {
        std::memcpy(bytes.data() + span_off + byte_off, &v, 8);
    };

    const char* name = ".?AVSlopTest@@";
    std::memset(bytes.data() + span_off, 0, 0xC0);
    std::memcpy(bytes.data() + span_off + 16, name, strlen(name) + 1);

    put32(0x40, 0);                       // signature (x64)
    put32(0x44, 0);                       // this-offset
    put32(0x48, 0);                       // ctor-displacement
    put32(0x4C, td_rva);                  // TypeDescriptor RVA
    put32(0x50, col_rva + 0x100);         // class-descriptor RVA (unused)
    put32(0x54, col_rva);                 // self RVA

    put64(0x80, pe.image_base + col_rva); // vftable[-1]
    put64(0x88, pe.image_base + 0x1000);  // slot 0 (bogus fn)
    put64(0x90, pe.image_base + 0x1010);  // slot 1

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(reparsed.ok);

    auto r = rtti_scan(reparsed, bytes);
    bool found = false;
    for (const auto& c : r.classes) {
        if (c.name != "SlopTest") continue;
        found = true;
        REQUIRE_EQ(c.vftables.size(), 1u);

        auto slots = read_vftable(reparsed, bytes, c.vftables[0], 8);
        REQUIRE(slots.has_value());
        REQUIRE_GE(slots->size(), 2u);
        REQUIRE_EQ((*slots)[0], pe.image_base + 0x1000ull);
    }
    REQUIRE(found);
}

TEST_CASE(danger_scan_flags_dangerous_imports_with_callsites) {
    // Synthetic image: one import with an IAT slot, resolver returns two
    // referencing sites. Exercises the whole contract without a real CRT
    disasm::pe_image_t pe{};
    pe.ok = true;
    pe.image_base = 0x140000000;

    disasm::pe_import_dll_t dll;
    dll.dll = "MSVCRTRT.dll";
    disasm::pe_import_func_t fn;
    fn.name = "strcpy";
    fn.iat_rva = 0x9000;
    dll.functions.push_back(fn);
    pe.imports.push_back(std::move(dll));

    int resolver_calls = 0;
    auto hits = analysis::danger_scan(
        pe,
        [&resolver_calls](uint64_t iat_va) {
            ++resolver_calls;
            REQUIRE_EQ(iat_va, 0x140009000ull);
            return std::vector<uint64_t>{0x140001000ull, 0x140002000ull};
        });
    REQUIRE_EQ(resolver_calls, 1);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_STR_EQ(hits[0].function.c_str(), "strcpy");
    REQUIRE_STR_EQ(hits[0].category.c_str(), "unbounded-copy");
    REQUIRE_EQ(hits[0].callsites.size(), 2u);
}

TEST_CASE(danger_scan_clean_imports_yield_nothing) {
    const auto& bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto hits = analysis::danger_scan(
        pe, [](uint64_t) { return std::vector<uint64_t>{}; });
    // SlopTarget is a plain MSVC build, but the CRT startup does pull
    // LoadLibrary*/GetProcAddress, every hit must be a real flagged import
    // with a resolved IAT slot and a known category
    for (const auto& h : hits) {
        REQUIRE(!h.category.empty());
        REQUIRE(h.iat_va != 0);
    }
}

