// src/tests/test_hyperion.cpp
// Hyperion engine integration: decode parity vs the legacy Zydis wrapper,
// analyzer sanity on SlopTarget.exe, decompiler determinism, and the
// hype::Insn → slop insn_t compat shim.

#include "harness.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/disasm/hyperion_session.hpp"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace hs = slop::core::disasm::hyperion_session;
namespace ds = slop::core::disasm::binary_state;
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

// Wait for background hyperion analysis with a generous timeout (analysis of
// SlopTarget is sub-second, but CI machines vary).
bool wait_hype_ready(int timeout_ms = 30000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ds::hype_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return ds::hype_ready();
}

} // namespace

TEST_CASE(hyperion_session_analyzes_slop_target) {
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready());

    auto& bin = ds::get();
    REQUIRE(bin.hype != nullptr);

    const auto& db = bin.hype->db();
    REQUIRE_GT(db.funcs.size(), 0u);
    REQUIRE_GT(db.insns.size(), 0u);
    REQUIRE_GT(db.strings.size(), 0u);

    // Every function with decoded code at its entry has at least one basic
    // block. Entries that were never decoded (an unreached .pdata entry, a
    // stub with no code) are name placeholders with no blocks rather than
    // zero-length ones.
    for (const auto& [entry, f] : db.funcs) {
        (void)entry;
        if (db.insns.count(f.entry)) REQUIRE_FALSE(f.blocks.empty());
    }

    ds::unload();
    REQUIRE_FALSE(ds::hype_ready());
}

TEST_CASE(hyperion_decode_parity_with_legacy_engine) {
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = ds::get();

    // Walk the first executable section, decoding via both engines.
    const auto* text = &bin.pe.sections.front();
    for (const auto& s : bin.pe.sections)
        if (s.is_executable()) { text = &s; break; }

    disasm::engine_t eng;
    REQUIRE(eng.init());

    const uint64_t va0 = bin.base + text->rva;
    const uint8_t*  p  = bin.file.data() + text->raw_offset;
    const size_t    n  = std::min<size_t>(text->raw_size, 4096);  // bounded

    size_t off = 0, parity = 0, decoded = 0;
    while (off + 1 < n) {
        auto legacy = eng.decode(va0 + off, p + off, n - off);
        hype::Insn hin;
        bool hok = hs::shared_decoder().decode(va0 + off, p + off, n - off, hin);
        if (legacy && hok) {
            ++decoded;
            const auto conv = hs::session_t::convert(hin);
            const bool same_len  = conv.length == legacy->length;
            const bool same_mnem = conv.mnemonic == legacy->mnemonic;
            bool same_target = true;
            if (legacy->has_rel_target && conv.has_rel_target)
                same_target = conv.rel_target == legacy->rel_target;
            if (same_len && same_mnem && same_target) ++parity;
        }
        const size_t step = legacy ? legacy->length : hok ? hin.len : 1;
        off += step ? step : 1;
    }
    // Almost everything must agree — tolerate a few classification edge
    // cases (e.g. exotic prefixes) but require the overwhelming majority.
    REQUIRE_GT(decoded, 100u);
    REQUIRE_GT(parity, decoded * 95 / 100);
    ds::unload();
}

TEST_CASE(hyperion_decompile_deterministic_and_sane) {
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready());
    auto& bin = ds::get();

    // Find a real (non-thunk) function: prefer one with several blocks.
    const hype::Function* best = nullptr;
    for (const auto& [entry, f] : bin.hype->db().funcs) {
        if (f.blocks.size() < 2) continue;
        if (!best || f.blocks.size() > best->blocks.size()) best = &f;
    }
    REQUIRE(best != nullptr);

    std::vector<hype::PseudoLine> a, b;
    std::string err;
    REQUIRE(bin.hype->decompile(best->entry, a, err));
    REQUIRE(bin.hype->decompile(best->entry, b, err));
    REQUIRE_GT(a.size(), 3u);

    // Determinism: identical output across runs.
    REQUIRE_EQ(a.size(), b.size());
    for (size_t i = 0; i < a.size(); ++i)
        REQUIRE_STR_EQ(a[i].text, b[i].text);

    // Output looks like C: braces + a statement marker.
    bool has_brace = false, has_stmt = false;
    for (const auto& l : a) {
        if (l.text.find('{') != std::string::npos) has_brace = true;
        if (l.text.find(';') != std::string::npos) has_stmt = true;
    }
    REQUIRE(has_brace);
    REQUIRE(has_stmt);

    ds::unload();
}

TEST_CASE(hyperion_decompile_entry_point_function) {
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready());
    auto& bin = ds::get();

    const hype::Function* f = bin.hype->function_entry(bin.base + bin.pe.entry_rva);
    if (!f) f = bin.hype->function_at(bin.base + bin.pe.entry_rva);
    REQUIRE(f != nullptr);

    std::vector<hype::PseudoLine> out;
    std::string err;
    REQUIRE(bin.hype->decompile(f->entry, out, err));

    ds::unload();
}

TEST_CASE(hyperion_analyze_stop_cancels_or_noops) {
    // stop() racing a fast analysis must land in a consistent state:
    // either the cancel won (not ready, "cancelled" error) or the analysis
    // won (ready, DB usable). And stop() on a settled session never flips
    // ready back off.
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    auto& bin = ds::get();
    REQUIRE(bin.hype != nullptr);

    ds::hype_stop();

    const bool ready = wait_hype_ready(5000);
    if (!ready) {
        // Cancel won the race: error explains it, DB never reported usable.
        const std::string err = bin.hype->error();
        REQUIRE(err.find("cancelled") != std::string::npos);
        REQUIRE_FALSE(bin.hype->ready());
    }

    // Settled-session stop() is a no-op: ready state survives untouched.
    if (bin.hype->ready()) {
        const size_t funcs_before = bin.hype->db().funcs.size();
        ds::hype_stop();
        REQUIRE(bin.hype->ready());
        REQUIRE_EQ(bin.hype->db().funcs.size(), funcs_before);
    }
    ds::unload();
}

TEST_CASE(hyperion_status_snapshot_tracks_lifecycle) {
    // No binary: empty snapshot, and stop() without a session is safe.
    REQUIRE_FALSE(ds::hype_status().has_image);
    ds::hype_stop();

    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    {
        const auto st = ds::hype_status();
        REQUIRE(st.has_image);
        REQUIRE(st.engine_present);
        // Either still running or already done — both valid immediately
        // after load; never "not ready and not running and no error".
        if (!st.ready && !st.running)
            REQUIRE_FALSE(st.engine_error.empty());
    }
    REQUIRE(wait_hype_ready());
    {
        const auto st = ds::hype_status();
        REQUIRE(st.ready);
        REQUIRE_FALSE(st.running);
        REQUIRE_EQ(st.progress, 1.0f);
    }
    ds::unload();
    REQUIRE_FALSE(ds::hype_status().has_image);
}

TEST_CASE(hyperion_decode_without_text_keeps_classification) {
    // Analysis builds skip the formatter: mnemonic id, type, operands and
    // branch targets must be intact with op_str empty, and format_text()
    // must restore display text from the stored bytes on demand.
    hype::Disassembler decoder;
    decoder.set_arch(hype::Arch::X64);
    hype::Insn out{};

    static const uint8_t call[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    REQUIRE(decoder.decode(0x140001000, call, sizeof(call), out, false));
    REQUIRE(out.op_str[0] == '\0');
    REQUIRE(out.mnemonic[0] != '\0');
    REQUIRE(out.type == hype::InsnType::Call);
    REQUIRE_EQ(out.branch_target(), 0x140001000ull + 5 + 0x10);

    const std::string text = hype::Disassembler::format_text(out, hype::Arch::X64);
    REQUIRE(text.find("call") != std::string::npos);

    // Full-text decode still embeds operands directly.
    hype::Insn full{};
    REQUIRE(decoder.decode(0x140001000, call, sizeof(call), full));
    REQUIRE(full.op_str[0] != '\0');
    REQUIRE_EQ(hype::Disassembler::format_text(full, hype::Arch::X64), text);
}

TEST_CASE(hyperion_parallel_matches_serial) {
    // Single-threaded analysis must produce the same database as the
    // multi-threaded run: same decoded set, functions, xrefs and strings.
    // SLOP_WORKER_THREADS is read per session (no cache), so the suite can
    // flip counts within one process.
    const auto& bytes = slop_target_bytes();

    _putenv_s("SLOP_WORKER_THREADS", "1");
    hs::session_t serial;
    REQUIRE(serial.start_sync(bytes.data(), bytes.size(), 0));
    const auto& sdb = serial.db();
    const size_t s_insns = sdb.insns.size(), s_funcs = sdb.funcs.size();
    const size_t s_xrefs = sdb.xrefs.size(), s_strings = sdb.strings.size();
    const size_t s_vtables = sdb.vtables.size(), s_globals = sdb.globals.size();
    uint64_t s_sum = 0;
    for (const auto& [addr, insn] : sdb.insns) s_sum += addr;
    REQUIRE_GT(s_insns, 1000u);

    _putenv_s("SLOP_WORKER_THREADS", "");
    hs::session_t parallel;
    REQUIRE(parallel.start_sync(bytes.data(), bytes.size(), 0));
    const auto& pdb = parallel.db();
    REQUIRE_EQ(pdb.insns.size(), s_insns);
    REQUIRE_EQ(pdb.funcs.size(), s_funcs);
    REQUIRE_EQ(pdb.xrefs.size(), s_xrefs);
    REQUIRE_EQ(pdb.strings.size(), s_strings);
    REQUIRE_EQ(pdb.vtables.size(), s_vtables);
    REQUIRE_EQ(pdb.globals.size(), s_globals);
    uint64_t p_sum = 0;
    for (const auto& [addr, insn] : pdb.insns) p_sum += addr;
    REQUIRE_EQ(p_sum, s_sum);
}

TEST_CASE(hyperion_parallel_deterministic) {
    // Two multi-threaded runs must agree exactly (chunk merges are index
    // ordered, descent claims are atomic): catches data races that only
    // show up as fluctuating counts.
    const auto& bytes = slop_target_bytes();
    _putenv_s("SLOP_WORKER_THREADS", "");

    size_t prev_insns = 0, prev_funcs = 0, prev_xrefs = 0;
    uint64_t prev_sum = 0;
    for (int run = 0; run < 2; ++run) {
        hs::session_t session;
        REQUIRE(session.start_sync(bytes.data(), bytes.size(), 0));
        const auto& db = session.db();
        uint64_t sum = 0;
        size_t blocks = 0, edges = 0;
        for (const auto& [entry, f] : db.funcs) {
            (void)entry;
            blocks += f.blocks.size();
            for (const auto& [ba, bb] : f.blocks) {
                (void)ba;
                edges += bb.succs.size();
            }
        }
        for (const auto& [addr, insn] : db.insns) sum += addr;
        if (run > 0) {
            REQUIRE_EQ(db.insns.size(), prev_insns);
            REQUIRE_EQ(db.funcs.size(), prev_funcs);
            REQUIRE_EQ(db.xrefs.size(), prev_xrefs);
            REQUIRE_EQ(sum, prev_sum);
        }
        prev_insns = db.insns.size();
        prev_funcs = db.funcs.size();
        prev_xrefs = db.xrefs.size();
        prev_sum = sum;
        REQUIRE_GT(blocks, 0u);
        REQUIRE_GT(edges, 0u);
    }
}

TEST_CASE(hyperion_decoder_preserves_operand_actions) {
    hype::Disassembler decoder;
    decoder.set_arch(hype::Arch::X64);
    hype::Insn out{};

    static const uint8_t load[] = {0x48, 0x8B, 0x01};       // mov rax, [rcx]
    REQUIRE(decoder.decode(0x1000, load, sizeof(load), out));
    REQUIRE(out.ops[0].write);
    REQUIRE_FALSE(out.ops[0].read);
    REQUIRE(out.ops[1].read);
    REQUIRE_FALSE(out.ops[1].write);

    static const uint8_t store[] = {0x48, 0x89, 0x01};      // mov [rcx], rax
    REQUIRE(decoder.decode(0x1000, store, sizeof(store), out));
    REQUIRE_FALSE(out.ops[0].read);
    REQUIRE(out.ops[0].write);
    REQUIRE(out.ops[1].read);

    static const uint8_t rmw[] = {0x48, 0x01, 0x01};        // add [rcx], rax
    REQUIRE(decoder.decode(0x1000, rmw, sizeof(rmw), out));
    REQUIRE(out.ops[0].read);
    REQUIRE(out.ops[0].write);
}

TEST_CASE(hyperion_converter_flow_and_targets) {
    // call rel32 / jcc rel32 / rip-relative lea — the fields every legacy
    // consumer (xray/devirt/recover/debugger) reads.
    static const uint8_t code_call[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    static const uint8_t code_jcc[]  = {0x75, 0x0A};
    static const uint8_t code_lea[]  = {0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00};

    disasm::insn_t out;
    REQUIRE(hs::session_t::decode(0x140001000, code_call, sizeof(code_call), out));
    REQUIRE(out.flow == disasm::flow_t::call);
    REQUIRE(out.has_rel_target);
    REQUIRE_EQ(out.rel_target, 0x140001000ull + 5 + 0x10);

    REQUIRE(hs::session_t::decode(0x140001000, code_jcc, sizeof(code_jcc), out));
    REQUIRE(out.flow == disasm::flow_t::jcc);
    REQUIRE(out.has_rel_target);
    REQUIRE_EQ(out.rel_target, 0x140001000ull + 2 + 0x0A);

    REQUIRE(hs::session_t::decode(0x140001000, code_lea, sizeof(code_lea), out));
    REQUIRE(out.flow == disasm::flow_t::none);
    REQUIRE(out.has_rip_rel);
    REQUIRE_EQ(out.rip_rel_target, 0x140001000ull + 7 + 0x10);
    REQUIRE_EQ(out.ops[0].reg, ZYDIS_REGISTER_RAX);
    REQUIRE(out.ops[0].write);   // lea dest is written
}

TEST_CASE(hyperion_decoder_classifies_signed_and_conditional_operations) {
    hype::Disassembler decoder;
    decoder.set_arch(hype::Arch::X64);
    hype::Insn out{};

    static const uint8_t jz[]    = {0x74, 0x02};
    static const uint8_t movzx[] = {0x0F, 0xB6, 0xC0};
    static const uint8_t movsx[] = {0x0F, 0xBE, 0xC0};
    static const uint8_t imul[]  = {0x48, 0x0F, 0xAF, 0xC1};
    static const uint8_t idiv[]  = {0x48, 0xF7, 0xF9};
    static const uint8_t sar[]   = {0x48, 0xD1, 0xF8};

    REQUIRE(decoder.decode(0x1000, jz, sizeof(jz), out));
    REQUIRE(out.type == hype::InsnType::Jcc);
    REQUIRE(decoder.decode(0x1000, movzx, sizeof(movzx), out));
    REQUIRE(out.type == hype::InsnType::Movzx);
    REQUIRE(decoder.decode(0x1000, movsx, sizeof(movsx), out));
    REQUIRE(out.type == hype::InsnType::Movsx);
    REQUIRE(decoder.decode(0x1000, imul, sizeof(imul), out));
    REQUIRE(out.type == hype::InsnType::Imul);
    REQUIRE(decoder.decode(0x1000, idiv, sizeof(idiv), out));
    REQUIRE(out.type == hype::InsnType::Idiv);
    REQUIRE(decoder.decode(0x1000, sar, sizeof(sar), out));
    REQUIRE(out.type == hype::InsnType::Sar);
}

TEST_CASE(hyperion_pe_load_buffer_matches_path_load) {
    hype::PELoader from_path, from_buf;
    auto a = from_path.load(SLOP_TARGET_EXE_PATH);
    auto b = from_buf.load_buffer(slop_target_bytes().data(),
                                  slop_target_bytes().size());
    REQUIRE(a.has_value());
    REQUIRE(b.has_value());
    REQUIRE_EQ(a->segments.size(), b->segments.size());
    REQUIRE_EQ(a->imports.size(), b->imports.size());
    REQUIRE_EQ(a->exports.size(), b->exports.size());
    REQUIRE_EQ(a->base, b->base);
    REQUIRE_EQ(a->entry, b->entry);
    for (size_t i = 0; i < a->segments.size(); ++i) {
        REQUIRE_STR_EQ(a->segments[i].name, b->segments[i].name);
        REQUIRE_EQ(a->segments[i].va, b->segments[i].va);
        REQUIRE_EQ(a->segments[i].size, b->segments[i].size);
    }
}

TEST_CASE(hyperion_reanalysis_preserves_runtime_base) {
    constexpr uint64_t runtime_base = 0x180000000ull;
    hype::PELoader loader;
    auto parsed = loader.load_buffer(slop_target_bytes().data(), slop_target_bytes().size());
    REQUIRE(parsed.has_value());
    if (parsed->base == runtime_base) return;

    hs::session_t session;
    REQUIRE(session.start_sync(slop_target_bytes().data(), slop_target_bytes().size(), runtime_base));
    REQUIRE_EQ(session.image().base, runtime_base);

    session.reanalyze(slop_target_bytes());
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    while (session.running() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));

    REQUIRE(session.ready());
    REQUIRE_EQ(session.image().base, runtime_base);
    REQUIRE(session.function_entry(session.image().entry) != nullptr);
}
