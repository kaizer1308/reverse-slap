// src/tests/test_memory.cpp
// Tests for core/memory: CE-port memscan engine, aob, pointer_scan, snapshot

#include "harness.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/pointer_scan.hpp"
#include "core/memory/snapshot.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <unordered_map>
#include <vector>

using namespace slop::core::memory;
using slop::core::infra::cancel_token_t;

// ---------------------------------------------------------------------------
// Sparse page-backed fake reader, deterministic, no live process needed
// ---------------------------------------------------------------------------

namespace {

constexpr size_t kPageSize = 4096;

struct fake_reader_t final : public reader_t {
    std::unordered_map<uintptr_t, std::vector<uint8_t>> pages;

    uint8_t* ptr(uintptr_t addr) {
        const uintptr_t page = addr & ~(kPageSize - 1);
        auto it = pages.find(page);
        if (it == pages.end()) return nullptr;
        return it->second.data() + (addr - page);
    }

    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto* out = static_cast<uint8_t*>(dst);
        while (len > 0) {
            const uintptr_t page = addr & ~(kPageSize - 1);
            auto it = pages.find(page);
            if (it == pages.end()) return false;
            const size_t off  = addr - page;
            const size_t avail = kPageSize - off;
            const size_t n = len < avail ? len : avail;
            std::memcpy(out, it->second.data() + off, n);
            out += n;
            addr += n;
            len -= n;
        }
        return true;
    }

    void write(uintptr_t addr, const void* src, size_t len) {
        auto* in = static_cast<const uint8_t*>(src);
        while (len > 0) {
            const uintptr_t page = addr & ~(kPageSize - 1);
            auto& buf = pages[page];
            if (buf.empty()) buf.assign(kPageSize, 0xEE);
            const size_t off  = addr - page;
            const size_t avail = kPageSize - off;
            const size_t n = len < avail ? len : avail;
            std::memcpy(buf.data() + off, in, n);
            in += n;
            addr += n;
            len -= n;
        }
    }
};

constexpr uint32_t kRW     = 0x04;      // PAGE_READWRITE
constexpr uint32_t kRO     = 0x02;      // PAGE_READONLY
constexpr uint32_t kExec   = 0x20;      // PAGE_EXECUTE_READ
constexpr uint32_t kPrivate = 0x20000;  // MEM_PRIVATE
constexpr uint32_t kImage   = 0x1000000;

scan_region_t rw_region(uintptr_t base, size_t size) {
    return {base, size, kRW, kPrivate};
}

} // namespace

// Reusable error-string scratch for aob_compile calls that don't inspect it
std::string& err_placeholder() {
    static std::string e;
    e.clear();
    return e;
}

// === aob: compile ===

TEST_CASE(aob_compile_spaced) {
    auto p = aob_compile("DE AD BE EF", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 4u);
    REQUIRE_EQ(p->nibble_mask[0], 0xFF);
    REQUIRE_EQ(p->bytes[3], 0xEF);
}

TEST_CASE(aob_compile_wildcards) {
    auto p = aob_compile("DE ?? BE", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 3u);
    REQUIRE_EQ(p->nibble_mask[0], 0xFF);
    REQUIRE_EQ(p->nibble_mask[1], 0x00);
    REQUIRE_EQ(p->nibble_mask[2], 0xFF);
}

TEST_CASE(aob_compile_nibble_wildcards) {
    auto p = aob_compile("D? ?E", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->nibble_mask[0], 0xF0);   // high nibble literal
    REQUIRE_EQ(p->nibble_mask[1], 0x0F);   // low nibble literal
    const uint8_t buf1[] = {0xDE, 0x8E};
    REQUIRE(aob_match(*p, buf1, sizeof(buf1)));
    const uint8_t buf2[] = {0x5E, 0x8F};
    REQUIRE(!aob_match(*p, buf2, sizeof(buf2)));
}

TEST_CASE(aob_compile_star_wildcard) {
    auto p = aob_compile("DE * BE", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->nibble_mask[1], 0x00);
}

TEST_CASE(aob_compile_compact) {
    auto p = aob_compile("DEADBEEF", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 4u);
    REQUIRE_EQ(p->bytes[1], 0xAD);
}

TEST_CASE(aob_compile_0x_prefix) {
    auto p = aob_compile("0xDE, 0xAD", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->size(), 2u);
    REQUIRE_EQ(p->bytes[0], 0xDE);
}

TEST_CASE(aob_compile_rejects_odd_compact) {
    auto p = aob_compile("DEA", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_compile_rejects_garbage) {
    auto p = aob_compile("ZZ QQ", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_compile_rejects_empty) {
    auto p = aob_compile("   ", err_placeholder());
    REQUIRE(!p.has_value());
}

TEST_CASE(aob_to_string_roundtrip) {
    auto p = aob_compile("de ?? ef", err_placeholder());
    REQUIRE(p.has_value());
    REQUIRE_STR_EQ(aob_to_string(*p), "DE ?? EF");
}

TEST_CASE(aob_from_bytes_format) {
    const uint8_t data[] = {0x01, 0xAB};
    REQUIRE_STR_EQ(aob_from_bytes(data, sizeof(data)), "01 AB");
}

// === aob: match + scan ===

TEST_CASE(aob_match_basic) {
    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0x00, 0xCA, 0xFE, 0xBA, 0x99};
    REQUIRE(!aob_match(*p, buf, sizeof(buf)));        // not anchored at 0
    REQUIRE(aob_match(*p, buf + 1, sizeof(buf) - 1)); // anchored at +1
    REQUIRE(aob_contains(*p, buf, sizeof(buf)));      // sliding search
}

TEST_CASE(aob_match_wildcard_hits_anything) {
    auto p = aob_compile("CA ?? BA", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0xCA, 0x77, 0xBA};
    REQUIRE(aob_match(*p, buf, sizeof(buf)));
}

TEST_CASE(aob_match_fails_when_pattern_longer) {
    auto p = aob_compile("01 02 03 04 05", err_placeholder());
    REQUIRE(p.has_value());
    const uint8_t buf[] = {0x01, 0x02};
    REQUIRE(!aob_match(*p, buf, sizeof(buf)));
}

TEST_CASE(aob_scan_finds_planted_pattern) {
    fake_reader_t r;
    uint8_t planted[16]{};
    planted[5] = 0xCA;
    planted[6] = 0xFE;
    planted[7] = 0xBA;
    r.write(0x10000, planted, sizeof(planted));

    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());

    auto hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p,
                         aob_scan_options_t{}, cancel_token_t{}, nullptr);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_EQ(hits[0], 0x10005u);
}

TEST_CASE(aob_scan_alignment) {
    fake_reader_t r;
    uint8_t planted[16]{};
    planted[1] = 0xCA; planted[2] = 0xFE; planted[3] = 0xBA;
    r.write(0x10000, planted, sizeof(planted));

    auto p = aob_compile("CA FE BA", err_placeholder());
    REQUIRE(p.has_value());

    // Pattern starts at +1 (not 4-aligned): alignment 4 skips it
    aob_scan_options_t opt;
    opt.alignment = 4;
    auto hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p, opt,
                         cancel_token_t{}, nullptr);
    REQUIRE(hits.empty());

    opt.alignment = 1;
    hits = aob_scan(r, {rw_region(0x10000, 0x1000)}, *p, opt,
                    cancel_token_t{}, nullptr);
    REQUIRE_EQ(hits.size(), 1u);
    REQUIRE_EQ(hits[0], 0x10001u);
}

// === memscan: widths + comparison kernel ===

TEST_CASE(value_sizes_correct) {
    REQUIRE_EQ(value_size(value_width_t::i8), 1u);
    REQUIRE_EQ(value_size(value_width_t::u16), 2u);
    REQUIRE_EQ(value_size(value_width_t::f32), 4u);
    REQUIRE_EQ(value_size(value_width_t::f64), 8u);
}

namespace {

scan_config_t cfg_for(scan_type_t t, value_width_t w, double v1, double v2 = 0) {
    scan_config_t c;
    c.type  = t;
    c.width = w;
    c.value1 = v1;
    c.value2 = v2;
    return c;
}

} // namespace

TEST_CASE(compare_signed_vs_unsigned_increased) {
    // i8: -1 (0xFF) -> 0 (0x00) is an INCREASE as signed..
    REQUIRE(check_value(cfg_for(scan_type_t::increased, value_width_t::i8, 0),
                        value_width_t::i8, 0x00, 0xFF));
    // ...but a DECREASE as unsigned (255 -> 0)
    REQUIRE(!check_value(cfg_for(scan_type_t::increased, value_width_t::u8, 0),
                         value_width_t::u8, 0x00, 0xFF));
    REQUIRE(check_value(cfg_for(scan_type_t::decreased, value_width_t::u8, 0),
                        value_width_t::u8, 0x00, 0xFF));
}

TEST_CASE(compare_exact_and_changed_unchanged) {
    REQUIRE(check_value(cfg_for(scan_type_t::exact_value, value_width_t::i32, 42),
                        value_width_t::i32, 42, 7));
    REQUIRE(!check_value(cfg_for(scan_type_t::exact_value, value_width_t::i32, 41),
                         value_width_t::i32, 42, 7));

    REQUIRE(check_value(cfg_for(scan_type_t::changed, value_width_t::u32, 0),
                        value_width_t::u32, 2, 1));
    REQUIRE(!check_value(cfg_for(scan_type_t::changed, value_width_t::u32, 0),
                         value_width_t::u32, 9, 9));
    REQUIRE(check_value(cfg_for(scan_type_t::unchanged, value_width_t::u32, 0),
                        value_width_t::u32, 9, 9));
}

TEST_CASE(compare_between_bigger_smaller) {
    REQUIRE(check_value(cfg_for(scan_type_t::between, value_width_t::u32, 10, 20),
                        value_width_t::u32, 15, 0));
    REQUIRE(!check_value(cfg_for(scan_type_t::between, value_width_t::u32, 10, 20),
                         value_width_t::u32, 25, 0));
    REQUIRE(check_value(cfg_for(scan_type_t::bigger_than, value_width_t::i32, 5),
                        value_width_t::i32, 6, 0));
    REQUIRE(check_value(cfg_for(scan_type_t::smaller_than, value_width_t::i32, 5),
                        value_width_t::i32, 4, 0));
}

TEST_CASE(compare_increased_by_decreased_by) {
    // check_value takes (curr, prev): 10 = 7 + 3
    REQUIRE(check_value(cfg_for(scan_type_t::increased_by, value_width_t::u32, 3),
                        value_width_t::u32, 10, 7));
    REQUIRE(!check_value(cfg_for(scan_type_t::increased_by, value_width_t::u32, 3),
                         value_width_t::u32, 11, 7));
    REQUIRE(check_value(cfg_for(scan_type_t::decreased_by, value_width_t::u32, 3),
                        value_width_t::u32, 4, 7));
}

TEST_CASE(compare_float_widths) {
    const uint64_t f_one  = value_from_double(value_width_t::f32, 1.0);
    const uint64_t f_two  = value_from_double(value_width_t::f32, 2.0);
    REQUIRE(check_value(cfg_for(scan_type_t::increased, value_width_t::f32, 0),
                        value_width_t::f32, f_two, f_one));
    REQUIRE(check_value(cfg_for(scan_type_t::exact_value, value_width_t::f64, 3.5),
                        value_width_t::f64,
                        value_from_double(value_width_t::f64, 3.5),
                        value_from_double(value_width_t::f64, 3.5)));
}

TEST_CASE(compare_float_rounding_truncated) {
    // CE truncated: value <= v < value + 10^-accuracy
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::truncated;
    c.float_accuracy = 1; // window [100.5, 100.6)
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.55), 0));
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.5), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.6), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.49), 0));
}

TEST_CASE(compare_float_rounding_extreme) {
    // CE extreme rounding: value - eps <= v <= value + eps
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::extreme;
    c.float_accuracy = 1; // window [100.4, 100.6]
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.44), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.39), 0));
}

TEST_CASE(compare_float_rounding_rounded) {
    // CE rounded: RoundTo(v, -accuracy) == RoundTo(value, -accuracy)
    // banker's rounding: RoundTo(100.5, 0) = 100, RoundTo(100.4, 0) = 100,
    // RoundTo(100.6, 0) = 101
    scan_config_t c = cfg_for(scan_type_t::exact_value, value_width_t::f32, 100.5);
    c.rounding = rounding_t::rounded;
    c.float_accuracy = 0; // integer rounding
    REQUIRE(check_value(c, value_width_t::f32,
                        value_from_double(value_width_t::f32, 100.4), 0));
    REQUIRE(!check_value(c, value_width_t::f32,
                         value_from_double(value_width_t::f32, 100.6), 0));
}

TEST_CASE(float_accuracy_from_text_derivation) {
    REQUIRE_EQ(float_accuracy_from_text("100.5"), 1u);
    REQUIRE_EQ(float_accuracy_from_text("100.25"), 2u);
    REQUIRE_EQ(float_accuracy_from_text("100"), 0u);
    REQUIRE_EQ(float_accuracy_from_text("1e3"), 0u);
    REQUIRE_EQ(float_accuracy_from_text("1.5e2"), 1u);
}

// === memscan: parse / format ===

TEST_CASE(parse_and_format_roundtrip_ints) {
    uint64_t bits = 0;
    REQUIRE(parse_value_text(value_width_t::i32, "-42", bits));
    REQUIRE_EQ(bits, static_cast<uint64_t>(0xFFFFFFD6u));
    REQUIRE_STR_EQ(format_value_text(value_width_t::i32, bits), "-42");

    REQUIRE(parse_value_text(value_width_t::u64, "0xDEADBEEF", bits));
    REQUIRE_EQ(bits, 0xDEADBEEFull);
    REQUIRE_STR_EQ(format_value_text(value_width_t::u64, bits), "3735928559");

    REQUIRE(!parse_value_text(value_width_t::u8, "-1", bits));   // unsigned rejects sign
    REQUIRE(!parse_value_text(value_width_t::i32, "abc", bits));
}

TEST_CASE(parse_and_format_roundtrip_floats) {
    uint64_t bits = 0;
    REQUIRE(parse_value_text(value_width_t::f32, "3.5", bits));
    REQUIRE_STR_EQ(format_value_text(value_width_t::f32, bits),
                   format_value_text(value_width_t::f32,
                                     value_from_double(value_width_t::f32, 3.5)));
    REQUIRE(!parse_value_text(value_width_t::f32, "not-a-float", bits));
}

// === memscan: region filtering (CE region walk) ===

TEST_CASE(filter_regions_drops_guard_and_noaccess) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000, kRW | 0x100 /*guard*/, kPrivate},
        {0x20000, 0x1000, 0x01 /*noaccess*/,    kPrivate},
        {0x30000, 0x1000, kRW,                  kPrivate},
    };
    auto out = filter_regions(in, scan_config_t{});
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x30000u);
}

TEST_CASE(filter_regions_writable_pref) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000, kRW,  kPrivate},
        {0x20000, 0x1000, kRO,  kPrivate},
    };
    scan_config_t cfg;
    cfg.writable = region_pref_t::include; // writable only
    auto out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x10000u);

    cfg.writable = region_pref_t::exclude; // read-only only
    out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x20000u);
}

TEST_CASE(filter_regions_type_and_range) {
    std::vector<scan_region_t> in = {
        {0x10000, 0x1000,   kRW, kImage},
        {0x20000, 0x10000,  kRW, kPrivate},   // extends past the range end
        {0x30000, 0x1000,   kRW, kPrivate},
    };
    scan_config_t cfg;
    cfg.mem_image = false;              // drop module-backed
    cfg.begin = 0x20000;                // clip to [0x20000, 0x28000)
    cfg.end   = 0x28000;
    auto out = filter_regions(in, cfg);
    REQUIRE_EQ(out.size(), 1u);
    REQUIRE_EQ(out[0].base, 0x20000u);
    REQUIRE_EQ(out[0].size, 0x8000u);   // clipped at the range end
}

// === memscan: first scan (address list) ===

TEST_CASE(first_scan_exact_finds_aligned_u32) {
    fake_reader_t r;
    const uint32_t needle = 1337;
    r.write(0x20010, &needle, 4);
    r.write(0x20100, &needle, 4);
    const uint32_t other = 9999;
    r.write(0x20200, &other, 4);

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 1337);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x20000, 0x2000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 2u);
    REQUIRE_EQ(engine.stats().found, engine.results().size());
    REQUIRE(!engine.stats().truncated);
    REQUIRE(engine.has_results());
}

TEST_CASE(first_scan_skips_unmapped_hole) {
    fake_reader_t r;
    // Only one mapped page inside the scanned region
    const uint32_t needle = 777;
    r.write(0x30004, &needle, 4);

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 777);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x30000, 0x2000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x30004u);
}

TEST_CASE(first_scan_alignment_changes_slot_count) {
    fake_reader_t r;
    const uint8_t z[32]{};
    r.write(0x40000, z, sizeof(z)); // materialize the page with zeros

    // Address-list scan (exact 0): hit count equals the slot count, so the
    // fastscan stepping is observable through results
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x40000, 0x20)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 8u);

    cfg.fast = fastscan_method_t::off;
    memscan_t e2;
    REQUIRE(e2.first_scan(r, {rw_region(0x40000, 0x20)}, cfg,
                          cancel_token_t{}, nullptr));
    REQUIRE_EQ(e2.results().size(), 29u); // 32 - 4 + 1
}

TEST_CASE(first_scan_truncates_at_max_results) {
    fake_reader_t r;
    const uint8_t z[256]{};
    r.write(0x50000, z, sizeof(z)); // materialize the page

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 0);
    cfg.max_results = 5;
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x50000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 5u);
    REQUIRE(engine.stats().truncated);
}

TEST_CASE(first_scan_ends_with_fastscan) {
    fake_reader_t r;
    const uint32_t needle = 42;
    r.write(0x6010C, &needle, 4);   // ends in 0x0C
    r.write(0x60104, &needle, 4);   // ends in 0x04 (must be skipped)

    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 42);
    cfg.fast = fastscan_method_t::ends_with;
    cfg.fast_digits = 2;
    cfg.fast_tail   = 0x0C;         // addresses ending in "0C"

    memscan_t engine;
    REQUIRE(engine.first_scan(r, {rw_region(0x60000, 0x1000)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x6010Cu);
}

// === memscan: unknown-initial region scan + FirstNextScan ===

TEST_CASE(unknown_scan_stashes_then_firstnext_increased) {
    fake_reader_t r;
    const uint32_t v1 = 100;
    r.write(0x60000, &v1, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::unknown_initial, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x60000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));

    // Unknown scan: no address rows, stash alive
    REQUIRE(engine.results().empty());
    REQUIRE(engine.region_scan_active());
    REQUIRE_EQ(engine.stats().slots_tracked, 0x100u); // one page run

    // Mutate upward; firstnext (increased) builds the address list
    const uint32_t v2 = 250;
    r.write(0x60000, &v2, 4);

    scan_config_t ncfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x60000u);
    REQUIRE_EQ(engine.results()[0].bits, static_cast<uint64_t>(250));
    REQUIRE(!engine.region_scan_active()); // stash consumed
}

TEST_CASE(unknown_scan_firstnext_unchanged) {
    fake_reader_t r;
    const uint8_t z[64]{};
    r.write(0x70000, z, sizeof(z));

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::unknown_initial, value_width_t::u32, 0);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x70000, 0x40)}, cfg,
                              cancel_token_t{}, nullptr));

    scan_config_t ncfg = cfg_for(scan_type_t::unchanged, value_width_t::u32, 0);
    ncfg.fast = fastscan_method_t::alignment;   // keep the first scan's stepping
    ncfg.fast_alignment = 4;
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 16u); // 64 bytes / 4 unchanged slots
}

// === memscan: NextNextScan (address list) ===

TEST_CASE(rescan_kinds_filter_correctly) {
    fake_reader_t r;
    const uint32_t v1 = 100;
    r.write(0x80000, &v1, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 100);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x80000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);

    // Mutate our known address upward
    const uint32_t v2 = 250;
    r.write(0x80000, &v2, 4);

    scan_config_t ncfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);
    REQUIRE_EQ(engine.results()[0].address, 0x80000u);
    REQUIRE_EQ(engine.results()[0].bits, static_cast<uint64_t>(250));

    // Exact rescan against 100: now 250 -> zero hits
    scan_config_t ecfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 100);
    REQUIRE(engine.next_scan(r, ecfg, cancel_token_t{}, nullptr));
    REQUIRE(engine.results().empty());
}

TEST_CASE(rescan_drops_freed_addresses) {
    fake_reader_t r;
    const uint32_t v = 5;
    r.write(0x90000, &v, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 5);
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;
    REQUIRE(engine.first_scan(r, {rw_region(0x90000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));
    REQUIRE_EQ(engine.results().size(), 1u);

    // Simulate free: remove the page entirely
    r.pages.erase(0x90000);

    scan_config_t ncfg = cfg_for(scan_type_t::unchanged, value_width_t::u32, 0);
    REQUIRE(engine.next_scan(r, ncfg, cancel_token_t{}, nullptr));
    REQUIRE(engine.results().empty());
}

TEST_CASE(rescan_without_previous_fails) {
    fake_reader_t r;
    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::increased, value_width_t::u32, 0);
    std::string err;
    REQUIRE(!engine.next_scan(r, cfg, cancel_token_t{}, &err));
    REQUIRE(!err.empty());
}

// === memscan: all-types scan ===

TEST_CASE(all_types_scan_matches_multiple_widths) {
    fake_reader_t r;
    const uint32_t needle = 7;                    // also 7 as u8, u16; and 7.0f? no, bits differ
    r.write(0xA0004, &needle, 4);

    memscan_t engine;
    scan_config_t cfg = cfg_for(scan_type_t::exact_value, value_width_t::u32, 7);
    cfg.scan_all_types = true;
    cfg.fast = fastscan_method_t::alignment;
    cfg.fast_alignment = 4;

    REQUIRE(engine.first_scan(r, {rw_region(0xA0000, 0x100)}, cfg,
                              cancel_token_t{}, nullptr));

    // u8 7 at 0xA0004, u16 7 at 0xA0004, u32 7 at 0xA0004 -> 3 rows
    size_t u8_hits = 0, u16_hits = 0, u32_hits = 0;
    for (const auto& h : engine.results()) {
        if (h.matched == value_width_t::u8)  ++u8_hits;
        if (h.matched == value_width_t::u16) ++u16_hits;
        if (h.matched == value_width_t::u32) ++u32_hits;
    }
    REQUIRE_EQ(u8_hits, 1u);
    REQUIRE_EQ(u16_hits, 1u);
    REQUIRE_EQ(u32_hits, 1u);
}

// === pointer scan ===

TEST_CASE(pointer_scan_depth_one) {
    fake_reader_t r;
    const uintptr_t kTarget  = 0x90000;
    const uintptr_t kHolder  = 0xA0000;
    const uint64_t val = kTarget - 16; // holder + off 16 -> target
    r.write(kHolder, &val, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 1;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;

    auto chains = pointer_scan(r, {rw_region(0xA0000, 0x10000)}, opt,
                               cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);

    bool found = false;
    for (auto& c : chains) {
        if (c.depth() == 1 && c.addresses[0] == kHolder && c.offsets[0] == 16)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(pointer_scan_depth_two_chain) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kMid    = 0xA0000; // points to target
    const uintptr_t kRoot   = 0xB0000; // points near mid

    const uint64_t mid_val = kTarget - 16;
    const uint64_t root_val = kMid - 8;
    r.write(kMid, &mid_val, 8);
    r.write(kRoot, &root_val, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 2;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;

    auto chains = pointer_scan(r, {rw_region(0xA0000, 0x20000)}, opt,
                               cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);

    bool found = false;
    for (auto& c : chains) {
        if (c.depth() == 2 &&
            c.addresses[0] == kRoot && c.offsets[0] == 8 &&
            c.addresses[1] == kMid && c.offsets[1] == 16)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(pointer_scan_static_roots_filter) {
    fake_reader_t r;
    const uintptr_t kTarget = 0x90000;
    const uintptr_t kHeapRoot  = 0xA0000; // private-memory holder
    const uintptr_t kCodeRoot  = 0xB0000; // module-backed holder
    const uint64_t v1 = kTarget - 16;
    const uint64_t v2 = kTarget - 16;
    r.write(kHeapRoot, &v1, 8);
    r.write(kCodeRoot, &v2, 8);

    pointer_scan_options_t opt;
    opt.target     = kTarget;
    opt.depth      = 1;
    opt.min_offset = -4096;
    opt.max_offset = 4096;
    opt.alignment  = 8;
    opt.only_module_backed = true;

    std::vector<scan_region_t> regions = {
        {kHeapRoot, 0x1000, kRW, kPrivate},   // private heap
        {kCodeRoot, 0x1000, kRO, kImage},     // module image
    };
    auto chains = pointer_scan(r, regions, opt, cancel_token_t{}, nullptr);
    REQUIRE_GE(chains.size(), 1u);
    for (auto& c : chains)
        REQUIRE_EQ(c.addresses[0], kCodeRoot); // only module-backed roots
}

// === snapshot ===

TEST_CASE(snapshot_capture_and_diff) {
    fake_reader_t r;
    std::vector<uint8_t> region(256);
    for (size_t i = 0; i < region.size(); ++i) region[i] = static_cast<uint8_t>(i);
    r.write(0xD0000, region.data(), region.size());

    auto snap_a = snapshot_capture(r, 0xD0000, 256, cancel_token_t{},
                                   slop::core::infra::limits::max_snapshot_region_bytes);
    REQUIRE(snap_a.complete);
    REQUIRE_EQ(snap_a.bytes[10], 10);

    // Mutate two runs: [50..54) and [100..101)
    const uint8_t five[5] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
    r.write(0xD0000 + 50, five, 5);
    const uint8_t one[1] = {0xBB};
    r.write(0xD0000 + 100, one, 1);

    auto snap_b = snapshot_capture(r, 0xD0000, 256, cancel_token_t{},
                                   slop::core::infra::limits::max_snapshot_region_bytes);
    auto d = snapshot_diff(snap_a, snap_b);
    REQUIRE(d.valid);
    REQUIRE_EQ(d.changed.size(), 2u);
    REQUIRE_EQ(d.changed[0].offset, 50u);
    REQUIRE_EQ(d.changed[0].length, 5u);
    REQUIRE_EQ(d.changed[1].offset, 100u);
    REQUIRE_EQ(d.changed[1].length, 1u);
}

TEST_CASE(snapshot_diff_invalid_on_mismatch) {
    region_snapshot_t a, b;
    a.base = 0x1000; a.bytes = {1, 2, 3};
    b.base = 0x1000; b.bytes = {1, 2};
    auto d = snapshot_diff(a, b);
    REQUIRE(!d.valid);

    b.bytes = {9, 9, 9};
    b.base = 0x2000;
    d = snapshot_diff(a, b);
    REQUIRE(!d.valid);
}
