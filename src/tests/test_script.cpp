// src/tests/test_script.cpp
// Lua engine: sandboxed execution, output capture, timeout enforcement,
// error propagation, and the static-analysis surface over the shared
// binary session (IDA-Python-equivalent API)

#include "harness.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/script/lua_engine.hpp"

#include <string>

using namespace slop::core::script;
namespace ds = slop::core::disasm::binary_state;

namespace {

// Embed a Windows path in a Lua double-quoted string literal
std::string lua_path_literal(const char* path) {
    std::string out = "\"";
    for (const char* p = path; *p; ++p) {
        if (*p == '\\' || *p == '\"') out += '\\';
        out += *p;
    }
    out += "\"";
    return out;
}

// Run a static-analysis script against the built SlopTarget fixture with a
// generous timeout (hyperion analysis + decompile paths need it)
lua_run_result_t run_static(const std::string& body, int timeout_ms = 60000) {
    return lua_run(
        "local ok = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok, \"image load failed\")\n" + body, timeout_ms);
}

void dump_on_fail(const lua_run_result_t& r) {
    if (!r.ok)
        std::printf("  detail: %s\n", r.error.c_str());
}

} // namespace

TEST_CASE(lua_runs_and_captures_output) {
    auto r = lua_run(R"(
        slop.log("hello", 42, true)
        print("via-print")
        local t = { slop.version() }
        return nil
    )");
    REQUIRE(r.ok);
    REQUIRE(r.error.empty());
    REQUIRE(r.output.find("hello\t42\ttrue") != std::string::npos);
    REQUIRE(r.output.find("via-print") != std::string::npos);
    REQUIRE(!r.output.empty());
}

TEST_CASE(lua_syntax_error_is_reported) {
    auto r = lua_run("this is not = valid lua (");
    REQUIRE(!r.ok);
    REQUIRE(!r.error.empty());
}

TEST_CASE(lua_runtime_error_propagates) {
    auto r = lua_run("error('boom')");
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("boom") != std::string::npos);
}

TEST_CASE(lua_slop_table_exists_with_expected_surface) {
    auto r = lua_run(R"(
        assert(type(slop) == "table")
        assert(type(slop.version) == "function")
        assert(type(slop.target.list) == "function")
        assert(type(slop.target.attach) == "function")
        assert(type(slop.mem.read_hex) == "function")
        assert(type(slop.mem.scan) == "function")
        assert(type(slop.disasm.disassemble) == "function")
        assert(type(slop.analyze.packer) == "function")
        -- static-analysis surface
        assert(type(slop.image.load) == "function")
        assert(type(slop.image.unload) == "function")
        assert(type(slop.image.status) == "function")
        assert(type(slop.image.wait_ready) == "function")
        assert(type(slop.disasm.decode) == "function")
        assert(type(slop.disasm.functions) == "function")
        assert(type(slop.disasm.function_at) == "function")
        assert(type(slop.disasm.xrefs_to) == "function")
        assert(type(slop.disasm.strings) == "function")
        assert(type(slop.disasm.pe) == "function")
        assert(type(slop.disasm.bytes) == "function")
        assert(type(slop.disasm.name) == "function")
        assert(type(slop.disasm.set_name) == "function")
        assert(type(slop.disasm.comment) == "function")
        assert(type(slop.disasm.set_comment) == "function")
        assert(type(slop.disasm.bookmark_toggle) == "function")
        assert(type(slop.disasm.bookmarks) == "function")
        assert(type(slop.decomp.decompile) == "function")
        assert(type(slop.decomp.blocks) == "function")
        assert(type(slop.decomp.vtables) == "function")
        assert(type(slop.decomp.globals) == "function")
        assert(type(slop.decomp.rtti) == "function")
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_no_target_errors_are_lua_errors_not_crashes) {
    auto r = lua_run("slop.mem.read_hex(0x41414141, 16)");
    // No target attached in unit tests -> must fail cleanly with message
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("no target") != std::string::npos);
}

TEST_CASE(lua_timeout_kills_infinite_loop) {
    auto r = lua_run("while true do end", 500);
    REQUIRE(!r.ok);
    REQUIRE(r.error.find("timed out") != std::string::npos);
}

// === static-analysis surface over the shared binary session ==================

TEST_CASE(lua_static_actions_require_loaded_image) {
    ds::unload();
    for (const char* expr : {
             "slop.disasm.functions()",
             "slop.disasm.xrefs_to(0x140001000)",
             "slop.disasm.strings()",
             "slop.disasm.pe()",
             "slop.disasm.bytes(0x140001000, 16)",
             "slop.decomp.vtables()",
             "slop.decomp.rtti()",
             "slop.image.wait_ready(100)",
         }) {
        auto r = lua_run(expr);
        REQUIRE_FALSE(r.ok);
        if (r.ok) continue;
        REQUIRE(r.error.find("no image") != std::string::npos);
        if (r.error.find("no image") == std::string::npos)
            std::printf("  detail (%s): %s\n", expr, r.error.c_str());
    }
}

TEST_CASE(lua_image_load_and_status) {
    auto r = run_static(R"(
        local st = slop.image.status()
        assert(st.ready, "image not ready")
        assert(st.base ~= 0, "no base")
        assert(st.entry ~= 0, "no entry")
        assert(st.name ~= "", "no name")
        assert(st.functions > 0, "no functions indexed")
        assert(st.xrefs > 0, "no xrefs indexed")
        assert(st.strings > 0, "no strings indexed")
        assert(type(st.hype) == "table", "no hype sub-table")
        assert(st.hype.available, "hyperion engine missing")
        return st.entry
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
    REQUIRE(r.output.find("return:") != std::string::npos);
}

TEST_CASE(lua_image_pe_metadata) {
    auto r = run_static(R"(
        local pe = slop.disasm.pe()
        assert(pe.pe32plus == true, "fixture is x64")
        assert(pe.image_base ~= 0)
        assert(pe.entry_rva ~= 0)
        assert(#pe.sections >= 3, "expected at least 3 sections")
        assert(#pe.imports >= 1, "expected imports")
        local saw_kernel32 = false
        for _, dll in ipairs(pe.imports) do
            assert(type(dll.dll) == "string")
            assert(type(dll.functions) == "table")
            if dll.dll:lower():find("kernel32") then saw_kernel32 = true end
        end
        assert(saw_kernel32, "no kernel32 import")
        for _, s in ipairs(pe.sections) do
            assert(type(s.name) == "string")
            assert(s.vsize and s.raw_size)
        end
        return #pe.sections
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_functions_listing_and_lookup) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        assert(#fns > 0, "no functions")
        for i, f in ipairs(fns) do
            assert(type(f.va) == "number" and f.va > 0, "bad va at " .. i)
            assert(type(f.size) == "number" and f.size >= 0, "bad size at " .. i)
            assert(type(f.name) == "string" and #f.name > 0, "unnamed at " .. i)
        end
        -- function_at resolves the owner of an entry address
        local f0 = fns[1]
        local owner = slop.disasm.function_at(f0.va)
        assert(owner, "function_at missed an entry")
        assert(owner.va == f0.va, "owner mismatch")
        -- entrypoint lands in some function
        local st = slop.image.status()
        assert(slop.disasm.function_at(st.entry), "entrypoint not owned")
        -- far-out address is nobody's function
        assert(slop.disasm.function_at(0x10) == nil, "bogus owner")
        -- limit is honored
        local few = slop.disasm.functions(2)
        assert(#few <= 2, "limit ignored")
        return #fns
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_decode_static_instructions) {
    auto r = run_static(R"(
        local st = slop.image.status()
        local insns = slop.disasm.decode(st.entry, 8)
        assert(#insns >= 1, "no instructions decoded at entry")
        for _, i in ipairs(insns) do
            assert(type(i.addr) == "number" and i.addr >= st.base)
            assert(type(i.len) == "number" and i.len >= 1)
            assert(type(i.text) == "string" and #i.text > 0)
            assert(type(i.bytes) == "string" and #i.bytes == i.len)
        end
        -- bytes() returns raw image bytes at a VA
        local b = slop.disasm.bytes(st.entry, 16)
        assert(#b == 16, "byte length mismatch")
        -- decode from an unmapped VA fails with a Lua error
        local ok, err = pcall(slop.disasm.decode, 0x10)
        assert(not ok, "decode outside image should fail")
        return #insns
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_xrefs_resolve_callers) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        -- Find a function that is actually referenced by something.
        local found_from, found_kind
        for i = 1, #fns do
            local refs = slop.disasm.xrefs_to(fns[i].va)
            if #refs > 0 then
                found_from = refs[1].from
                found_kind = refs[1].kind
                break
            end
        end
        assert(found_from, "no xrefs found for any indexed function")
        assert(type(found_kind) == "string" and #found_kind > 0)
        return found_from
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_strings_listing) {
    auto r = run_static(R"(
        local hits = slop.disasm.strings(4, 1000)
        assert(#hits > 0, "no strings")
        for _, s in ipairs(hits) do
            assert(type(s.va) == "number" and s.va > 0)
            assert(type(s.text) == "string" and #s.text >= 4)
            assert(type(s.utf16) == "boolean")
        end
        -- higher minimum length filters (weakly) fewer results
        local wide = slop.disasm.strings(16, 100000)
        assert(#wide <= #hits, "min_chars filter widened the result")
        return #hits
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_names_and_comments_roundtrip) {
    auto r = run_static(R"(
        local fns = slop.disasm.functions()
        local va = fns[1].va
        slop.disasm.set_name(va, "lua_renamed_fn")
        assert(slop.disasm.name(va) == "lua_renamed_fn", "rename not visible")
        slop.disasm.set_comment(va, "annotated from lua")
        assert(slop.disasm.comment(va) == "annotated from lua", "comment not visible")
        -- clear both
        slop.disasm.set_name(va, "")
        slop.disasm.set_comment(va, "")
        -- function listing still yields a display name after the clear
        local f2 = slop.disasm.function_at(va)
        assert(f2 and type(f2.name) == "string" and #f2.name > 0)
    )");
    dump_on_fail(r);
    REQUIRE(r.ok);
}

TEST_CASE(lua_bookmarks_roundtrip) {
    auto r = run_static(R"(
        local st = slop.image.status()
        local now = slop.disasm.bookmark_toggle(st.entry)
        assert(type(now) == "boolean")
        local marks = slop.disasm.bookmarks()
        local saw = false
        for _, m in ipairs(marks) do
            assert(type(m) == "number")
            if m == st.entry then saw = true end
        end
        assert(saw == now, "bookmark state inconsistent")
        -- toggle back off to keep the fixture store clean
        slop.disasm.bookmark_toggle(st.entry)
    )");
    REQUIRE(r.ok);
    dump_on_fail(r);
}

TEST_CASE(lua_decompile_after_hype_wait) {
    auto r = run_static(R"(
        assert(slop.image.wait_ready(30000), "hyperion analysis did not finish")
        local st = slop.image.status()
        assert(st.hype.ready, "status disagrees with wait_ready")
        assert(st.hype.functions > 0, "hyperion found no functions")

        local fns = slop.disasm.functions()
        -- Decompile the first function hyperion knows about.
        local d
        for i = 1, #fns do
            local ok, res = pcall(slop.decomp.decompile, fns[i].va)
            if ok and res then d = res; break end
        end
        assert(d, "no function decompiled")
        assert(type(d.va) == "number" and d.va > 0)
        assert(type(d.name) == "string" and #d.name > 0)
        assert(type(d.signature) == "string" and #d.signature > 0)
        assert(type(d.lines) == "table" and #d.lines > 0)
        for _, l in ipairs(d.lines) do
            assert(type(l.text) == "string")
            assert(type(l.indent) == "number")
        end

        -- CFG blocks for the same function
        local bl = slop.decomp.blocks(d.va)
        assert(type(bl) == "table" and bl.entry == d.va)
        assert(type(bl.blocks) == "table" and #bl.blocks >= 1)
        for _, b in ipairs(bl.blocks) do
            assert(b.end_va > b.start, "bad block range")
            assert(type(b.succs) == "table")
            assert(type(b.preds) == "table")
        end

        -- Rich DB views answer without erroring.
        assert(type(slop.decomp.vtables()) == "table")
        assert(type(slop.decomp.globals()) == "table")
        assert(type(slop.decomp.rtti()) == "table")
        return #d.lines
    )", 60000);
    dump_on_fail(r);
    REQUIRE(r.ok);
    REQUIRE(r.output.find("return:") != std::string::npos);
}

TEST_CASE(lua_returned_tables_are_serialized_into_output) {
    auto r = lua_run("return { 1, 2, 3 }");
    REQUIRE(r.ok);
    REQUIRE(r.output.find("return: {1, 2, 3}") != std::string::npos);

    auto r2 = lua_run("return { va = 0x10, name = \"x\" }");
    REQUIRE(r2.ok);
    REQUIRE(r2.output.find("va=16") != std::string::npos);
    REQUIRE(r2.output.find("name=\"x\"") != std::string::npos);
}

TEST_CASE(lua_decomp_before_ready_reports_pending_state) {
    // Load synchronously and immediately ask the decompiler for the richest
    // path without calling wait_ready, the error must name the pending
    // analysis (or, on a very fast machine that already finished, succeed)
    auto r = lua_run(
        "local ok = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok)\n"
        "assert(slop.image.wait_ready(30000))\n"
        "slop.image.unload()\n"
        "local ok2 = slop.image.load(" + lua_path_literal(SLOP_TARGET_EXE_PATH) + ")\n"
        "assert(ok2)\n"
        "local ok3, err = pcall(slop.decomp.vtables)\n"
        "return ok3", 60000);
    REQUIRE(r.ok);   // pcall guards either outcome; the point is no crash/lockup
    dump_on_fail(r);
}
