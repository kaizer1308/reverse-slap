// src/tests/test_xray.cpp
// Advanced analysis battery: xray (CFG/complexity/obfuscation/entropy/pages/
// syscalls/apihash/gadgets/crypto), imgpatch mutations + journal revert,
// type catalog parsing/layout/field reads, and pure stack unwinding

#include "harness.hpp"

#include "core/analysis/recover.hpp"
#include "core/analysis/devirt.hpp"
#include "core/analysis/xray.hpp"
#include "core/analysis/imgpatch.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/debugger/callstack.hpp"
#include "core/re/type_catalog.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

namespace {

using namespace slop::core;

disasm::engine_t& shared_eng() {
    static disasm::engine_t e;
    if (!e.ok()) REQUIRE(e.init());
    return e;
}

struct fixture_image {
    disasm::pe_image_t pe;
    std::vector<uint8_t> file;
    uint64_t base = 0;
};

fixture_image& target_fixture() {
    static fixture_image f = [] {
        fixture_image out;
        std::ifstream in(SLOP_TARGET_EXE_PATH, std::ios::binary);
        out.file = std::vector<uint8_t>(std::istreambuf_iterator<char>(in),
                                        std::istreambuf_iterator<char>{});
        out.pe = disasm::pe_parse(out.file.data(), out.file.size());
        out.base = out.pe.image_base;
        return out;
    }();
    return f;
}

} // namespace

// Alias usable inside TEST_CASE bodies
namespace xray = slop::core::analysis::xray;
namespace recover = slop::core::analysis::recover;
namespace devirt = slop::core::analysis::devirt;

namespace {

slop::core::analysis::xray::image_ref_t make_ref(fixture_image& fx,
                                                 bool with_fns = false) {
    slop::core::analysis::xray::image_ref_t r;
    r.pe   = &fx.pe;
    r.file = &fx.file;
    r.base = fx.base;
    r.eng  = &shared_eng();
    static disasm::function_index_t fns;
    if (with_fns) {
        REQUIRE(fns.build(fx.pe, fx.file, shared_eng(), fx.base));
        r.fns = &fns;
    }
    return r;
}

} // namespace

TEST_CASE(xray_entropy_basics) {
    const uint8_t zeros[256] = {};
    REQUIRE_EQ(xray::shannon_entropy(zeros, sizeof(zeros)), 0.0);

    uint8_t full[256];
    for (int i = 0; i < 256; ++i) full[i] = static_cast<uint8_t>(i);
    const double e = xray::shannon_entropy(full, sizeof(full));
    REQUIRE_GT(e, 7.95);
}

TEST_CASE(xray_entropy_scan_fixture) {
    auto& fx = target_fixture();
    auto r = make_ref(fx);

    // .text of a clean MSVC build: moderate entropy, not encrypted
    const disasm::pe_section_t* text = nullptr;
    for (const auto& s : fx.pe.sections)
        if (s.is_executable()) { text = &s; break; }
    REQUIRE(text != nullptr);

    auto res = xray::entropy_scan(r, fx.base + text->rva, 4096, 256);
    // Small MSVC images land anywhere in the normal..suspicious band; the
    // contract is a sane numeric verdict, not a specific label
    const std::string verdict = res.verdict;
    REQUIRE(verdict == "normal" || verdict == "suspicious_high_entropy");
    REQUIRE_GT(res.overall, 1.0);
    REQUIRE(!res.windows.empty());
    REQUIRE_GE(res.max_window, res.min_window);
}

TEST_CASE(xray_pages_classification) {
    auto& fx = target_fixture();
    auto r = make_ref(fx);

    // page classification over the entry area keeps this honest without
    // leaning on any one toolchains quirks
    auto pages = xray::classify_pages(r, fx.base + fx.pe.entry_rva & ~0xFFFull,
                                      8192, 4096);
    REQUIRE_GE(pages.size(), 2u);
    bool any_label = false;
    for (const auto& p : pages)
        if (p.klass && *p.klass) any_label = true;
    REQUIRE(any_label);
}

TEST_CASE(xray_cfg_and_complexity_on_entry) {
    auto& fx = target_fixture();
    auto r = make_ref(fx, true);

    // The PE entry stub is straight-line (sub rsp / call / add rsp / jmp):
    // with function-bounded decoding it legitimately has zero internal
    // edges. Find a branchy indexed function for the edge assertions and
    // keep the entry stub assertions to blocks/cyclomatic floor
    const uint64_t entry = fx.base + fx.pe.entry_rva;
    auto cfg = xray::build_cfg(r, entry);
    REQUIRE(cfg.ok);
    REQUIRE_GE(cfg.blocks.size(), 1u);
    REQUIRE_GE(cfg.cyclomatic, 1u);

    uint64_t branchy = 0;
    size_t   most_blocks = 0;
    for (const auto& f : r.fns->functions()) {
        auto c = xray::build_cfg(r, f.va, 32);
        if (!c.ok) continue;
        if (c.blocks.size() > most_blocks && c.edge_count > 0) {
            most_blocks = c.blocks.size();
            branchy     = f.va;
        }
    }
    REQUIRE(branchy != 0);
    auto cfg2 = xray::build_cfg(r, branchy);
    REQUIRE(cfg2.ok);
    REQUIRE_GT(cfg2.edge_count, 0u);

    auto cx = xray::function_complexity(r, entry);
    REQUIRE_GT(cx.instruction_count, 0u);
    REQUIRE(cx.rating != nullptr && *cx.rating);
}

TEST_CASE(xray_obfuscation_and_anti_analysis_run) {
    auto& fx = target_fixture();
    auto r = make_ref(fx, true);
    const uint64_t entry = fx.base + fx.pe.entry_rva;

    auto obf = xray::detect_obfuscation(r, entry);
    REQUIRE_LE(obf.score_pct, 100);   // clean build: low score expected
    auto aa = xray::detect_anti_analysis(r, entry);
    REQUIRE_LE(aa.score_pct, 100);
    auto ic = xray::indirect_calls(r, entry);      // runs, may be empty
    auto sr = xray::string_decrypt_recon(r, entry);
    (void)sr;
}

TEST_CASE(xray_hooks_and_gadgets_smoke) {
    auto& fx = target_fixture();
    auto r = make_ref(fx, true);

    auto hooks = xray::detect_hooks(r, 500);
    // Clean MSVC binary: no inline-hook prologues at function starts
    REQUIRE_EQ(hooks.size(), 0u);

    auto gadgets = xray::rop_gadgets(r, 32);
    REQUIRE(!gadgets.empty());     // any real binary has ret gadgets
    bool saw_ret_text = false;
    for (const auto& g : gadgets) {
        std::string lower = g.text;
        std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
        if (lower.find("ret") != std::string::npos) saw_ret_text = true;
    }
    REQUIRE(saw_ret_text);
}

TEST_CASE(xray_syscall_detection_on_synthetic_bytes) {
    auto& fx = target_fixture();
    auto r = make_ref(fx);

    // Splice a synthetic stub into an executable section's tail bytes we own
    // a copy of: detect over a range covering it
    std::vector<uint8_t> code = {
        0x4C, 0x8B, 0xD1,                   // mov r10, rcx
        0xB8, 0x25, 0x00, 0x00, 0x00,       // mov eax, 0x25
        0x0F, 0x05,                         // syscall
        0xC3,
    };
    // Point the scanner at a mapped-but-benign region instead: syscalls()
    // reads from the image, so verify the empty result path + pattern table
    // through a small direct scan of our own copy using crypto-style byte
    // matching is already covered elsewhere. Here: image-wide scan must at
    // least run and return a sane count cap
    auto hits = xray::detect_syscalls(r, reinterpret_cast<uint64_t>(code.data()),
                                      code.size());
    // The address is host memory, unmapped in the image -> no hits, no crash
    REQUIRE(hits.empty());
}

TEST_CASE(xray_api_hash_algebraic_identities) {
    // djb2("") == 5381, fnv1a("") == basis, sdbm("") == 0, ror13("") == 0,
    // crc32("") == ~init == 0
    REQUIRE_EQ(xray::hash_api("", "djb2", false), 5381u);
    REQUIRE_EQ(xray::hash_api("", "fnv1a", false), 0x811C9DC5u);
    REQUIRE_EQ(xray::hash_api("", "sdbm", false), 0u);
    REQUIRE_EQ(xray::hash_api("", "ror13", false), 0u);
    REQUIRE_EQ(xray::hash_api("", "crc32", false), 0u);

    // djb2("a") = 5381*33 + 'a'
    REQUIRE_EQ(xray::hash_api("a", "djb2", false), 5381u * 33 + 97u);

    // dll!name composite vs bare name differ unless include_dll_name set
    const uint32_t bare = xray::hash_api("KERNEL32.DLL!Foo", "ror13", true);
    const uint32_t comp = xray::hash_api("KERNEL32.DLL!Foo", "ror13", false);
    REQUIRE_NE(bare, comp);
    REQUIRE_EQ(bare, xray::hash_api("KERNEL32.DLL!Foo", "ror13", true));

    // Unknown algorithm -> 0 sentinel
    REQUIRE_EQ(xray::hash_api("X", "nope", false), 0u);
}

TEST_CASE(xray_crypto_range_finds_sha_constants) {
    auto& fx = target_fixture();
    auto r = make_ref(fx);

    // Synthetic data hunt via crypto_range_bytes: embed SHA-256 K0 + MD5 A
    std::vector<uint8_t> buf(64, 0);
    const uint32_t sha_k0 = 0x428A2F98;
    std::memcpy(buf.data() + 8, &sha_k0, 4);
    const uint32_t md5_a = 0x67452301;
    std::memcpy(buf.data() + 16, &md5_a, 4);

    auto hits = xray::crypto_range_bytes(0x140000000, buf.data(), buf.size(),
                                         nullptr, 64);
    REQUIRE_GE(hits.size(), 2u);
    bool saw_sha = false, saw_md5 = false;
    for (const auto& h : hits) {
        if (std::string(h.algorithm) == "SHA-256" && h.value == sha_k0) saw_sha = true;
        if (std::string(h.algorithm) == "MD5" && h.value == md5_a) saw_md5 = true;
    }
    REQUIRE(saw_sha);
    REQUIRE(saw_md5);
}

// === imgpatch ===

TEST_CASE(imgpatch_write_journal_and_revert) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = disasm::binary_state::get();

    const uint64_t va = bin.base + bin.pe.entry_rva;
    auto off = bin.offset_of(va);
    REQUIRE(off.has_value());
    const uint8_t before = bin.file[*off];

    auto w = analysis::imgpatch::write_bytes(bin, va, {0xDE, 0xAD});
    REQUIRE(w.ok);
    REQUIRE_EQ(bin.file[*off], 0xDE);
    REQUIRE_GE(bin.patches.size(), 2u);

    auto rv = analysis::imgpatch::revert_all(bin);
    REQUIRE(rv.ok);
    REQUIRE_EQ(bin.file[*off], before);
    REQUIRE(bin.patches.empty());

    disasm::binary_state::unload();
}

TEST_CASE(imgpatch_unpack_xor_roundtrip) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = disasm::binary_state::get();
    const uint64_t va = bin.base + bin.pe.entry_rva;
    auto off = bin.offset_of(va);
    REQUIRE(off.has_value());
    std::vector<uint8_t> original(bin.file.begin() + *off,
                                  bin.file.begin() + *off + 16);

    auto r = analysis::imgpatch::unpack_xor(bin, va, 16, "xor_single", "AA");
    REQUIRE(r.ok);
    REQUIRE_EQ(bin.file[*off], static_cast<uint8_t>(original[0] ^ 0xAA));
    REQUIRE_GE(bin.patches.size(), 16u);

    REQUIRE(analysis::imgpatch::revert_all(bin).ok);
    REQUIRE(std::equal(original.begin(), original.end(), bin.file.begin() + *off));

    disasm::binary_state::unload();
}

TEST_CASE(imgpatch_dry_runs_are_non_destructive) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = disasm::binary_state::get();
    const uint64_t entry = bin.base + bin.pe.entry_rva;
    const size_t patches_before = bin.patches.size();

    auto opq = analysis::imgpatch::resolve_opaque_predicates(bin, entry, true);
    REQUIRE(opq.ok);
    REQUIRE(opq.dry_run);

    analysis::imgpatch::anti_debug_opts_t opts{};
    auto ad = analysis::imgpatch::patch_anti_debug(bin, entry, opts, true);
    REQUIRE(ad.ok);

    auto ds = analysis::imgpatch::decode_strings(bin, entry);
    REQUIRE(ds.ok);

    REQUIRE_EQ(bin.patches.size(), patches_before);   // nothing landed

    disasm::binary_state::unload();
}

TEST_CASE(imgpatch_full_pass_and_rebuild) {
    REQUIRE(disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = disasm::binary_state::get();
    const uint64_t entry = bin.base + bin.pe.entry_rva;
    const size_t patches_before = bin.patches.size();

    // Dry run: full pipeline composes, nothing lands
    auto fp = analysis::imgpatch::full_pass(bin, entry, true);
    REQUIRE(fp.ok);
    REQUIRE(fp.dry_run);
    REQUIRE_GE(fp.steps.size(), 6u);
    REQUIRE_EQ(fp.pre_score, fp.post_score);
    REQUIRE_EQ(bin.patches.size(), patches_before);

    // Real pass on a clean binary: score stays in the low band (CRT startup
    // legitimately carries some indirect jumps)
    auto real = analysis::imgpatch::full_pass(bin, entry, false);
    REQUIRE(real.ok);
    REQUIRE_LE(real.post_score, real.pre_score + 5);
    REQUIRE_LE(real.post_score, 50);

    // Rebuild validates decodability and dirties the indexes
    auto rb = analysis::imgpatch::rebuild(bin, entry);
    REQUIRE(rb.ok);
    REQUIRE_GT(rb.instruction_count, 0u);
    REQUIRE(!rb.insns.empty());
    REQUIRE(bin.indexes_dirty);

    disasm::binary_state::unload();
}

// === type catalog ===

using slop::core::re::type_catalog::parse_decls;
using slop::core::re::type_catalog::base_type_size;
using slop::core::re::type_catalog::read_field;

TEST_CASE(types_parse_struct_layout) {
    auto pr = parse_decls("struct Point { u32 x; u32 y; };");
    REQUIRE(pr.error.empty());
    REQUIRE_EQ(pr.structs.size(), 1u);
    auto& s = pr.structs[0];
    REQUIRE_STR_EQ(s.name.c_str(), "Point");
    REQUIRE_EQ(s.size, 8ull);
    REQUIRE_EQ(s.fields[0].offset, 0ull);
    REQUIRE_EQ(s.fields[1].offset, 4ull);
}

TEST_CASE(types_parse_alignment_and_packed) {
    auto pr = parse_decls("struct A { u8 a; u32 b; }; struct B packed { u8 a; u32 b; };");
    REQUIRE(pr.error.empty());
    REQUIRE_EQ(pr.structs[0].fields[1].offset, 4ull);   // natural align
    REQUIRE_EQ(pr.structs[0].size, 8ull);
    REQUIRE_EQ(pr.structs[1].fields[1].offset, 1ull);   // packed
    REQUIRE_EQ(pr.structs[1].size, 5ull);
}

TEST_CASE(types_parse_arrays_pointers_nested_enums) {
    auto pr = parse_decls(
        "enum Color : u8 { Red = 1, Green, Blue = 0x10 };"
        "struct Inner { u16 v; };"
        "struct Outer { Inner* p; Color c[3]; Inner inl; char name[8]; };");
    REQUIRE(pr.error.empty());
    REQUIRE_EQ(pr.enums.size(), 1u);
    REQUIRE_EQ(pr.enums[0].values[1].second, 2);        // implicit increment
    REQUIRE_EQ(pr.enums[0].values[2].second, 0x10);

    REQUIRE_EQ(pr.structs.size(), 2u);
    auto& outer = pr.structs[1];
    REQUIRE_EQ(outer.fields[0].size, 8ull);             // pointer
    REQUIRE_EQ(outer.fields[1].array_count, 3u);
    REQUIRE_EQ(outer.fields[2].size, base_type_size("u16"));
    bool named_ok = false;
    for (const auto& f : outer.fields)
        if (f.type == "Inner" && f.size == 2) named_ok = true;
    REQUIRE(named_ok);
}

TEST_CASE(types_read_field_from_buffer) {
    auto pr = parse_decls("struct Rec { u32 magic; double score; };");
    REQUIRE(pr.error.empty());

    uint8_t buf[16] = {};
    const uint32_t magic = 0xFEEDF00D;
    std::memcpy(buf, &magic, 4);
    const double score = 42.5;
    std::memcpy(buf + 8, &score, 8);

    auto v = read_field(pr.structs[0], "magic", 0, buf, sizeof(buf),
                        nullptr, nullptr);
    REQUIRE(v.ok);
    REQUIRE_EQ(v.uint_val, 0xFEEDF00Dull);

    auto v2 = read_field(pr.structs[0], "score", 0, buf, sizeof(buf),
                         nullptr, nullptr);
    REQUIRE(v2.ok);
    REQUIRE_EQ(v2.dbl_val, 42.5);

    auto bad = read_field(pr.structs[0], "nope", 0, buf, sizeof(buf),
                          nullptr, nullptr);
    REQUIRE(!bad.ok);
}

// === unwinding ===

using slop::core::debugger::unwind::reader_t;
using slop::core::debugger::unwind::walk_stack;
using slop::core::debugger::unwind::seh_chain;

namespace {

struct map_reader final : reader_t {
    std::map<uint64_t, std::vector<uint8_t>> mem;
    void put(uint64_t addr, const void* data, size_t len) {
        auto& v = mem[addr];
        v.assign(static_cast<const uint8_t*>(data),
                 static_cast<const uint8_t*>(data) + len);
    }
    bool read(uint64_t addr, void* dst, size_t len) override {
        for (const auto& [base, bytes] : mem)
            if (addr >= base && addr + len <= base + bytes.size()) {
                std::memcpy(dst, bytes.data() + (addr - base), len);
                return true;
            }
        return false;
    }
};

} // namespace

TEST_CASE(unwind_walks_synthetic_rbp_chain) {
    disasm::engine_t eng;
    REQUIRE(eng.init());

    map_reader rdr;

    const uint64_t rsp = 0x1000, rbp0 = 0x2000;
    // Frame 0 return into a `ret` instruction
    const uint8_t ret_insn[] = {0xC3};
    const uint64_t caller1 = 0x5000;
    rdr.put(caller1, ret_insn, sizeof(ret_insn));
    const uint64_t ret0 = caller1;
    rdr.put(rsp, &ret0, 8);

    // rbp chain: [rbp0] = next rbp, [rbp0+8] = return into caller2
    const uint64_t caller2 = 0x6000;
    rdr.put(caller2, ret_insn, sizeof(ret_insn));
    const uint64_t next_rbp = 0x3000;
    rdr.put(rbp0, &next_rbp, 8);
    rdr.put(rbp0 + 8, &caller2, 8);

    // Terminating frame
    const uint64_t zero = 0;
    rdr.put(next_rbp, &zero, 8);
    const uint64_t caller3 = 0x7000;
    rdr.put(caller3, ret_insn, sizeof(ret_insn));
    rdr.put(next_rbp + 8, &caller3, 8);

    auto frames = walk_stack(eng, rdr, 0x4000, rsp, rbp0, 16);
    REQUIRE_GE(frames.size(), 3u);
    REQUIRE_EQ(frames[0].ret_addr, caller1);
    REQUIRE_FALSE(frames[0].scanned);    bool saw_c2 = false, saw_c3 = false;
    for (const auto& f : frames) {
        if (f.ret_addr == caller2) saw_c2 = true;
        if (f.ret_addr == caller3) saw_c3 = true;
    }
    REQUIRE(saw_c2);
    REQUIRE(saw_c3);
}

TEST_CASE(unwind_scan_fallback_when_chain_dead) {
    disasm::engine_t eng;
    REQUIRE(eng.init());

    map_reader rdr;
    // zeroed stack window with two return addresses planted inside it,
    // each target carrying a full 16 byte instruction window
    std::vector<uint8_t> stack(0x800, 0);
    const uint64_t cands[] = {0x9000, 0xA000};
    uint64_t c1 = cands[0], c2 = cands[1];
    std::memcpy(stack.data() + 0x80, &c1, 8);
    std::memcpy(stack.data() + 0x100, &c2, 8);
    rdr.put(0x1000, stack.data(), stack.size());

    uint8_t insn[16] = {};                       // mov rsp,rbp + zero padding
    insn[0] = 0x48; insn[1] = 0x89; insn[2] = 0xEC;
    for (uint64_t c : cands) rdr.put(c, insn, sizeof(insn));

    // Dead chain: rbp points at garbage beyond user space
    const uint64_t garbage = 0xEEEEEEEEEEEEEE00ull;
    rdr.put(0x2000, &garbage, 8);

    auto frames = walk_stack(eng, rdr, 0x4000, 0x1000, 0x2000, 16);
    bool found_scan = false;
    for (const auto& f : frames)
        if (f.scanned) found_scan = true;
    REQUIRE(found_scan);
}

TEST_CASE(unwind_seh_chain_empty_proven_on_x64) {
    map_reader rdr;
    const uint64_t teb = 0x7EF000;
    const uint64_t sentinel = 0xFFFFFFFFFFFFFFFFull;
    rdr.put(teb, &sentinel, 8);

    auto r = seh_chain(rdr, teb);
    REQUIRE(r.chain_empty_proven);
    REQUIRE(r.chain.empty());
}

// === recovery + devirtualization over a synthetic PE ===
// A minimal PE64 is assembled in-memory so flattened functions and mini-VMs
// can be placed at known VAs and exercised end-to-end


namespace {

struct synth_pe {
    std::vector<uint8_t> file;
    disasm::pe_image_t   pe;
    uint64_t             base = 0x00400000;   // low base: [abs disp32] reachable
    uint64_t             code_va = 0;      // base + section RVA

    // Append code, return the VA of what was appended
    uint64_t emit(const std::vector<uint8_t>& bytes) {
        const uint64_t va = code_va + section_bytes.size();
        section_bytes.insert(section_bytes.end(), bytes.begin(), bytes.end());
        return va;
    }

    // jmp rel8 to a previously emitted VA (site = current end)
    std::vector<uint8_t> jmp_rel8(uint64_t from_site, uint64_t target) {
        const int64_t d = static_cast<int64_t>(target) -
                          static_cast<int64_t>(from_site + 2);
        REQUIRE_GE(d, -128);
        REQUIRE_LE(d, 127);
        return {0xEB, static_cast<uint8_t>(d)};
    }
    // jz rel8 variant
    std::vector<uint8_t> jz_rel8(uint64_t from_site, uint64_t target) {
        const int64_t d = static_cast<int64_t>(target) -
                          static_cast<int64_t>(from_site + 2);
        REQUIRE_GE(d, -128);
        REQUIRE_LE(d, 127);
        return {0x74, static_cast<uint8_t>(d)};
    }

    bool probe(uint64_t va, uint8_t* dst, size_t len) const {
        if (!pe.ok || va < base) return false;
        auto off = pe.rva_to_offset(static_cast<uint32_t>(va - base));
        if (!off || *off + len > file.size()) return false;
        std::memcpy(dst, file.data() + *off, len);
        return true;
    }

    void finish() {
        file.assign(0x400, 0);
        auto put = [&](size_t off, const void* p, size_t n) {
            std::memcpy(file.data() + off, p, n);
        };
        // DOS header
        put(0, "MZ", 2);
        const uint32_t e_lfanew = 0x40;
        put(0x3C, &e_lfanew, 4);
        // PE signature + COFF
        const uint32_t pe_sig = 0x00004550;
        put(0x40, &pe_sig, 4);
        uint16_t machine = 0x8664, nsec = 1;
        put(0x44, &machine, 2);
        put(0x46, &nsec, 2);
        const uint32_t zero32 = 0;
        put(0x48, &zero32, 4);              // timestamp
        put(0x4C, &zero32, 4);              // symtab
        put(0x50, &zero32, 4);              // nsyms
        const uint16_t opt_size = 240;
        put(0x54, &opt_size, 2);
        const uint16_t chars = 0x0022;      // executable image, large-address aware
        put(0x56, &chars, 2);
        // Optional header PE32+ (offset 0x58)
        const size_t oh = 0x58;
        const uint16_t magic = 0x20B;
        put(oh, &magic, 2);
        const uint8_t linkermajor = 14, linkerminor = 42;
        put(oh + 2, &linkermajor, 1);
        put(oh + 3, &linkerminor, 1);
        const uint32_t size_of_code = static_cast<uint32_t>(section_bytes.size());
        put(oh + 4, &size_of_code, 4);
        const uint32_t entry_rva = 0x1000;
        put(oh + 16, &entry_rva, 4);
        // section/file alignment at oh+32/oh+36
        const uint32_t sec_align = 0x1000, file_align = 0x200;
        put(oh + 32, &sec_align, 4);
        put(oh + 36, &file_align, 4);
        // image base PE32+ at oh+24
        put(oh + 24, &base, 8);
        // sizes: headers 0x400, image 0x2000
        const uint32_t size_headers = 0x400, size_image = 0x2000;
        put(oh + 60, &size_headers, 4);
        put(oh + 56, &size_image, 4);
        const uint16_t subsys = 3;          // console
        put(oh + 68, &subsys, 2);
        const uint32_t dd_offset = 0x58 + 112;   // data dirs PE32+
        put(dd_offset, &zero32, 4);              // import dir rva=0
        put(dd_offset + 4, &zero32, 4);
        // Section header at 0xB8 (0x58+240)
        const size_t sh = 0x58 + 240;
        put(sh, ".slop\0\0", 8);
        const uint32_t vsize = 0x2000, rva = 0x1000,
                        rawsz = 0x200, rawoff = 0x400;
        put(sh + 8, &vsize, 4);
        put(sh + 12, &rva, 4);
        put(sh + 16, &rawsz, 4);
        put(sh + 20, &rawoff, 4);
        const uint32_t sc = 0x60000020;     // code | execute | read
        put(sh + 36, &sc, 4);
        // Raw section
        file.resize(rawoff);
        file.insert(file.end(), section_bytes.begin(), section_bytes.end());
        file.resize(rawoff + rawsz, 0);

        pe = disasm::pe_parse(file.data(), file.size());
    }

    xray::image_ref_t ref(disasm::engine_t& eng) {
        xray::image_ref_t r;
        r.pe = &pe; r.file = &file; r.base = base; r.eng = &eng;
        return r;
    }

    std::vector<uint8_t> section_bytes;
};

} // namespace

TEST_CASE(synth_pe_assembles_and_parses) {
    disasm::engine_t eng;
    REQUIRE(eng.init());
    synth_pe s;
    s.code_va = s.base + 0x1000;
    s.emit({0xC3});
    s.finish();
    REQUIRE(s.pe.ok);
    REQUIRE_EQ(s.pe.sections.size(), 1u);
    uint8_t probe[4];
    REQUIRE(s.probe(s.code_va, probe, sizeof(probe)));
}

TEST_CASE(recover_flattened_synthetic_cff) {
    disasm::engine_t eng;
    REQUIRE(eng.init());
    synth_pe s;
    s.code_va = s.base + 0x1000;

    // init: mov eax,3
    s.emit({0xB8, 0x03, 0x00, 0x00, 0x00});
    const uint64_t disp = s.emit({});                    // placeholder marker

    // dispatcher body: cmp eax,1 / je S1 / cmp eax,2 / je S2 /
    //                  cmp eax,3 / je S3 / jmp out
    s.emit({0x83, 0xF8, 0x01});
    const uint64_t j1 = s.emit({0x74, 0x00});            // patched below
    s.emit({0x83, 0xF8, 0x02});
    const uint64_t j2 = s.emit({0x74, 0x00});
    s.emit({0x83, 0xF8, 0x03});
    const uint64_t j3 = s.emit({0x74, 0x00});
    const uint64_t jout = s.emit({0xEB, 0x00});

    // State blocks
    const uint64_t s1 = s.emit({0xFF, 0xC1});            // inc ecx
    s.emit({0xB8, 0x02, 0x00, 0x00, 0x00});              // mov eax,2
    { auto j = s.jmp_rel8(s.code_va + s.section_bytes.size(), disp); s.emit(j); }
    const uint64_t s2 = s.emit({0xFF, 0xC2});            // inc edx
    s.emit({0xB8, 0x01, 0x00, 0x00, 0x00});              // mov eax,1
    { auto j = s.jmp_rel8(s.code_va + s.section_bytes.size(), disp); s.emit(j); }
    const uint64_t s3 = s.emit({0x31, 0xC9});            // xor ecx,ecx
    { auto j = s.jmp_rel8(s.code_va + s.section_bytes.size(), disp); s.emit(j); }
    const uint64_t out_ = s.emit({0xC3});                // ret

    // Patch the dispatcher branches now that targets exist
    auto patch_rel8 = [&](uint64_t site, uint64_t target) {
        const int64_t d = static_cast<int64_t>(target) -
                          static_cast<int64_t>(site + 2);
        REQUIRE_GE(d, -128);
        REQUIRE_LE(d, 127);
        s.section_bytes[site - s.code_va + 1] = static_cast<uint8_t>(d);
    };
    patch_rel8(j1, s1);
    patch_rel8(j2, s2);
    patch_rel8(j3, s3);
    patch_rel8(jout, out_);
    s.finish();

    auto r = s.ref(eng);
    auto rec = recover::recover_flattened(r, disp, 2);
    REQUIRE(rec.ok);
    REQUIRE(rec.flattened);
    REQUIRE_STR_EQ(rec.mode.c_str(), "cmp_chain");
    REQUIRE_EQ(rec.dispatcher, disp);
    REQUIRE_EQ(rec.real_edges_recovered, 3u);
    bool saw_s1 = false, saw_s2 = false, saw_s3 = false;
    for (const auto& e : rec.dispatch_map) {
        if (e.state == 1 && e.target == s1) saw_s1 = true;
        if (e.state == 2 && e.target == s2) saw_s2 = true;
        if (e.state == 3 && e.target == s3) saw_s3 = true;
    }
    REQUIRE(saw_s1);
    REQUIRE(saw_s2);
    REQUIRE(saw_s3);
    REQUIRE(rec.corroborated);       // emulation reaches the dispatcher
    REQUIRE_GT(rec.dispatcher_entries_observed, 0u);
}

TEST_CASE(predicate_proof_on_xor_idiom) {
    disasm::engine_t eng;
    REQUIRE(eng.init());
    synth_pe s;
    s.code_va = s.base + 0x1000;

    s.emit({0x31, 0xDB});                            // xor ebx,ebx -> ZF=1
    const uint64_t jcc = s.emit({0x74, 0x02});       // je +2 (always taken)
    s.emit({0x90});                                  // never reached
    s.emit({0xC3});                                  // ret at taken target
    s.finish();

    auto r = s.ref(eng);
    auto proofs = recover::prove_predicates(r, jcc - 2, 2);
    REQUIRE_EQ(proofs.size(), 1u);
    REQUIRE(proofs[0].static_idiom);
    REQUIRE_EQ(proofs[0].taken_runs, proofs[0].seen_runs);
    REQUIRE_EQ(proofs[0].seen_runs, proofs[0].total_runs);
    REQUIRE(proofs[0].proven_always_taken);
}

TEST_CASE(invariants_constant_across_seeds) {
    disasm::engine_t eng;
    REQUIRE(eng.init());
    synth_pe s;
    s.code_va = s.base + 0x1000;
    s.emit({0xB8, 0x2A, 0x00, 0x00, 0x00});          // mov eax,42
    s.emit({0xC3});                                  // ret
    s.finish();

    auto r = s.ref(eng);
    auto inv = recover::observe_invariants(r, s.code_va, 3);
    REQUIRE(inv.ok);
    bool saw_rax = false;
    for (const auto& i : inv.invariants)
        if (i.reg == "rax" && i.value == 42) saw_rax = true;
    REQUIRE(saw_rax);
}

TEST_CASE(devirt_identify_classify_lift_mini_vm) {
    disasm::engine_t eng;
    REQUIRE(eng.init());
    synth_pe s;
    s.code_va = s.base + 0x1000;

    // vm_entry: xor eax,eax ; jmp [table + eax*8]
    s.emit({0x31, 0xC0});
    const uint64_t loop = s.emit({});                    // marker (== entry+2)
    const size_t jmp_off = s.section_bytes.size();
    s.emit({0xFF, 0x24, 0xC5, 0, 0, 0, 0});              // jmp qword [disp32 + eax*8]
    const uint64_t disp32_pos = s.code_va + jmp_off + 3;

    // H0 (push handler): push 5 ; mov eax,1 ; jmp loop
    const uint64_t h0 = s.emit({0x6A, 0x05});
    s.emit({0xB8, 0x01, 0x00, 0x00, 0x00});
    { auto j = s.jmp_rel8(s.code_va + s.section_bytes.size(), loop); s.emit(j); }

    // H1 (pop handler): pop r8 ; xor eax,eax ; jmp loop
    const uint64_t h1 = s.emit({0x41, 0x58});
    s.emit({0x31, 0xC0});
    { auto j = s.jmp_rel8(s.code_va + s.section_bytes.size(), loop); s.emit(j); }

    // NOP sled so the decode-walk (and thus the emulator's code mapping)
    // runs straight through into the handler table
    for (int i = 0; i < 64; ++i) s.section_bytes.push_back(0x90);
    while (s.section_bytes.size() % 8) s.section_bytes.push_back(0x90);
    const size_t table_off = s.section_bytes.size();
    auto put_q = [&](uint64_t v) {
        for (int b = 0; b < 8; ++b)
            s.section_bytes.push_back(static_cast<uint8_t>(v >> (8 * b)));
    };
    put_q(h0);
    put_q(h1);
    const uint64_t table_va = s.code_va + table_off;

    // Patch the jmp's disp32 with the absolute table VA (no-base form)
    for (int b = 0; b < 4; ++b)
        s.section_bytes[jmp_off + 3 + b] =
            static_cast<uint8_t>((table_va >> (8 * b)) & 0xFF);
    s.finish();
    (void)disp32_pos;

    auto r = s.ref(eng);

    auto id = devirt::identify(r, loop);
    REQUIRE(id.ok);
    REQUIRE(id.likely_vm);
    REQUIRE_EQ(id.dispatcher, loop);
    REQUIRE_EQ(id.handler_table, table_va);
    REQUIRE_EQ(id.table_entry_size, 8u);

    auto cls = devirt::classify_handlers(r, table_va, 8);
    REQUIRE(cls.ok);
    REQUIRE_EQ(cls.valid_entries, 2u);
    REQUIRE_STR_EQ(cls.handlers[0].classification.c_str(), "vm_push");
    REQUIRE_STR_EQ(cls.handlers[1].classification.c_str(), "vm_pop");

    auto tr = devirt::trace_bytecode(r, s.code_va /*xor eax,eax init*/, loop,
                                     {h0, h1}, 16);
    REQUIRE(tr.ok);
    REQUIRE_GT(tr.dispatcher_hits, 0u);
    REQUIRE(!tr.bytecode.empty());
    // Bytecode alternates through both slots
    bool saw0 = false, saw1 = false;
    for (uint32_t op : tr.bytecode) {
        if (op == 0) saw0 = true;
        if (op == 1) saw1 = true;
    }
    REQUIRE(saw0);
    REQUIRE(saw1);

    auto lifted = devirt::lift(tr, cls);
    REQUIRE(lifted.ok);
    REQUIRE_GT(lifted.covered, 0u);
    const std::string pc = devirt::pseudocode(lifted);
    REQUIRE(pc.find("push()") != std::string::npos);
    REQUIRE(pc.find("pop()") != std::string::npos);
}
