// src/tests/test_mcp.cpp
// MCP protocol + tool-surface tests: real server on an ephemeral port, driven
// by a real HTTP client, initialize / tools/list / tools/call / health, plus
// error paths. Kernel-independent (user backend, no target required)

#include "harness.hpp"

#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"
#include "core/disasm/binary_state.hpp"

#include <windows.h>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;

struct server_fixture_t {
    server_fixture_t() {
        slop::core::mcp::server_config_t cfg;
        cfg.port = 0;   // ephemeral
        REQUIRE(slop::core::mcp::start(cfg));
        port_ = slop::core::mcp::port();
        REQUIRE_GT(port_, 0);
        cli_ = std::make_unique<httplib::Client>("127.0.0.1", port_);
        cli_->set_connection_timeout(std::chrono::seconds(2));
        cli_->set_read_timeout(std::chrono::seconds(10));
        cli_->set_write_timeout(std::chrono::seconds(10));
    }
    ~server_fixture_t() {
        // Close the client socket before joining server workers. Reversing
        // this order can leave stop() waiting on a worker that is itself
        // waiting for this still-live client connection to close
        if (cli_) {
            cli_->stop();
            cli_.reset();
        }
        slop::core::mcp::stop();
    }

    json rpc(const std::string& method, const json& params = json::object()) {
        json req = {{"jsonrpc", "2.0"}, {"id", 42}, {"method", method}};
        if (!params.is_null()) req["params"] = params;
        auto res = cli_->Post("/mcp", req.dump(), "application/json");
        REQUIRE(res);
        if (res->status != 200)
            std::printf("  [rpc %s] status=%d body=%.400s\n",
                        method.c_str(), res->status, res->body.c_str());
        REQUIRE_EQ(res->status, 200);
        return json::parse(res->body);
    }

    // tools/call helper then returns the parsed payload + error flag
    json call(const std::string& tool, const json& args, bool& is_error) {
        json res = rpc("tools/call", {{"name", tool}, {"arguments", args}});
        REQUIRE(res.contains("result"));
        is_error = res.at("result").value("isError", false);
        const auto& content = res.at("result").at("content");
        REQUIRE(!content.empty());
        return json::parse(content.at(0).at("text").get<std::string>());
    }

    uint16_t port() const { return port_; }

    uint16_t port_ = 0;
    std::unique_ptr<httplib::Client> cli_;
};

} // namespace

TEST_CASE(mcp_initialize_handshake) {
    server_fixture_t fx;
    json res = fx.rpc("initialize");
    REQUIRE(res.contains("result"));
    REQUIRE_STR_EQ(res.at("result").at("protocolVersion").get<std::string>(), "2025-06-18");
    REQUIRE_STR_EQ(res.at("result").at("serverInfo").at("name").get<std::string>(), "reverse-slop");
    REQUIRE(res.at("result").at("capabilities").contains("tools"));

    // Session context rides the handshake: the agent knows what the app has
    // attached / loaded without probing
    const json& st = res.at("result").at("state");
    REQUIRE(st.contains("backend"));
    REQUIRE(st.at("target").contains("attached"));
    REQUIRE(st.at("image").contains("ready"));
    REQUIRE(st.contains("debugger"));   // live debug sessions are visible up front

    // Server-level usage guidance: non-empty, and it points at the two
    // status actions an agent should open with
    const std::string instructions =
        res.at("result").at("instructions").get<std::string>();
    REQUIRE(!instructions.empty());
    REQUIRE(instructions.find("target.status") != std::string::npos);
    REQUIRE(instructions.find("disasm.loaded") != std::string::npos);
}

TEST_CASE(mcp_unknown_action_errors_enumerate_actions) {
    server_fixture_t fx;
    bool is_error = false;

    // A mistyped action must carry the valid set so the agent self-corrects
    // in one round trip instead of re-fetching tools/list
    json payload = fx.call("target", {{"action", "lst"}}, is_error);
    REQUIRE(is_error);
    const std::string err = payload.at("error").get<std::string>();
    REQUIRE(err.find("list") != std::string::npos);
    REQUIRE(err.find("attach") != std::string::npos);
    REQUIRE(err.find("dump_module") != std::string::npos);

    payload = fx.call("memory", {{"action", "reed"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("scan") !=
            std::string::npos);

    payload = fx.call("disasm", {{"action", "fnuctions"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("functions") !=
            std::string::npos);

    payload = fx.call("debugger", {{"action", "brk"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("bp_set") !=
            std::string::npos);

    payload = fx.call("fs", {{"action", "sve"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.at("error").get<std::string>().find("write_file") !=
            std::string::npos);
}

TEST_CASE(mcp_ping_and_health) {
    server_fixture_t fx;
    json res = fx.rpc("ping");
    REQUIRE(res.contains("result"));

    auto health = fx.cli_->Get("/health");
    REQUIRE(health);
    REQUIRE_EQ(health->status, 200);
    json h = json::parse(health->body);
    REQUIRE_EQ(h.value("ok", false), true);
}

TEST_CASE(mcp_tools_list_twenty_three_consolidated) {
    server_fixture_t fx;
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");
    REQUIRE_EQ(tools.size(), 23u);

    bool seen_target = false, seen_memory = false, seen_disasm = false,
         seen_debugger = false, seen_driver = false, seen_inject = false,
         seen_emulate = false, seen_analyze = false,
         seen_network = false, seen_proxy = false,
         seen_persist = false, seen_re = false, seen_script = false,
         seen_frida = false, seen_decomp = false, seen_xray = false,
         seen_patch = false,
         seen_types = false, seen_notes = false, seen_devirt = false;
    for (const auto& t : tools) {
        const std::string n = t.at("name").get<std::string>();
        if (n == "target")   seen_target = true;
        if (n == "memory")   seen_memory = true;
        if (n == "disasm")   seen_disasm = true;
        if (n == "debugger") seen_debugger = true;
        if (n == "driver")   seen_driver = true;
        if (n == "inject")   seen_inject = true;
        if (n == "emulate")  seen_emulate = true;
        if (n == "analyze")  seen_analyze = true;
        if (n == "network")  seen_network = true;
        if (n == "proxy")    seen_proxy = true;
        if (n == "persist")  seen_persist = true;
        if (n == "re")       seen_re = true;
        if (n == "script")   seen_script = true;
        if (n == "frida")    seen_frida = true;
        if (n == "decomp")   seen_decomp = true;
        if (n == "xray")     seen_xray = true;
        if (n == "patch")    seen_patch = true;
        if (n == "types")    seen_types = true;
        if (n == "notes")    seen_notes = true;
        if (n == "devirt")   seen_devirt = true;
        REQUIRE(t.contains("inputSchema"));
        REQUIRE(t.contains("description"));
        REQUIRE(t.at("description").is_string());
        REQUIRE_GT(t.at("description").get<std::string>().size(), 120u);
        const auto& schema = t.at("inputSchema");
        REQUIRE_STR_EQ(schema.at("type").get<std::string>(), "object");
        REQUIRE(schema.at("properties").contains("action"));
        REQUIRE(schema.at("properties").at("action").contains("enum"));
        REQUIRE(!schema.at("properties").at("action").at("enum").empty());
        REQUIRE(std::find(schema.at("required").begin(), schema.at("required").end(), "action") !=
                schema.at("required").end());
    }
    REQUIRE(seen_target);
    REQUIRE(seen_memory);
    REQUIRE(seen_disasm);
    REQUIRE(seen_debugger);
    REQUIRE(seen_driver);
    REQUIRE(seen_inject);
    REQUIRE(seen_emulate);
    REQUIRE(seen_analyze);
    REQUIRE(seen_network);
    REQUIRE(seen_proxy);
    REQUIRE(seen_persist);
    REQUIRE(seen_re);
    REQUIRE(seen_script);
    REQUIRE(seen_frida);
    REQUIRE(seen_decomp);
    REQUIRE(seen_xray);
    REQUIRE(seen_patch);
    REQUIRE(seen_types);
    REQUIRE(seen_notes);
    REQUIRE(seen_devirt);
}

TEST_CASE(mcp_devirt_exposes_themida_sidecars) {
    server_fixture_t fx;
    bool is_error = false;
    const json payload = fx.call("devirt", {{"action", "themida_status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.at("engine").get<std::string>(), "Magicmida");
    REQUIRE(payload.contains("x86_available"));
    REQUIRE(payload.contains("x64_available"));
    REQUIRE(payload.contains("x64_scyllahide_available"));

    json tools = json::array();
    slop::core::mcp::list_tools(tools);
    const auto it = std::find_if(tools.begin(), tools.end(), [](const json& tool) {
        return tool.at("name") == "devirt";
    });
    REQUIRE(it != tools.end());
    const auto& actions = it->at("inputSchema").at("properties").at("action").at("enum");
    REQUIRE(std::find(actions.begin(), actions.end(), "themida_start") != actions.end());
}

TEST_CASE(mcp_tool_descriptions_expose_workflow_context) {
    json tools = json::array();
    slop::core::mcp::list_tools(tools);

    const auto description = [&tools](const std::string& name) {
        const auto it = std::find_if(tools.begin(), tools.end(), [&name](const json& tool) {
            return tool.at("name").get<std::string>() == name;
        });
        REQUIRE(it != tools.end());
        return it->at("description").get<std::string>();
    };

    REQUIRE(description("target").find("action='status'") != std::string::npos);
    REQUIRE(description("memory").find("attached") != std::string::npos);
    REQUIRE(description("disasm").find("hype.ready") != std::string::npos);
    REQUIRE(description("debugger").find("wait_halt") != std::string::npos);
    REQUIRE(description("driver").find("structured errors") != std::string::npos);
    REQUIRE(description("patch").find("does not patch live target memory") != std::string::npos);
    REQUIRE(description("decomp").find("function-start addr") != std::string::npos);
    REQUIRE(description("frida").find("session handle") != std::string::npos);
}

TEST_CASE(mcp_unknown_method_and_tool) {
    server_fixture_t fx;
    json res = fx.rpc("bogus/method");
    REQUIRE(res.contains("error"));
    REQUIRE_EQ(res.at("error").at("code").get<int>(), -32601);

    bool is_error = false;
    json payload = fx.call("nope", json::object(), is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_parse_error_is_400) {
    server_fixture_t fx;
    auto res = fx.cli_->Post("/mcp", "{not json", "application/json");
    REQUIRE(res);
    REQUIRE_EQ(res->status, 400);
    json body = json::parse(res->body);
    REQUIRE_EQ(body.at("error").at("code").get<int>(), -32700);
}

TEST_CASE(mcp_tool_errors_without_target) {
    server_fixture_t fx;

    bool is_error = true;
    json payload = fx.call("memory", {{"action", "read"}, {"addr", 0x41414141}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    is_error = false;
    payload = fx.call("memory", {{"action", "frobnicate"}}, is_error);
    REQUIRE(is_error);

    is_error = false;
    payload = fx.call("debugger", {{"action", "regs"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_driver_status_shape) {
    server_fixture_t fx;
    bool is_error = true;
    json payload = fx.call("driver", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("kernel_active"));
    REQUIRE(payload.contains("hwbp_supported"));
    REQUIRE(payload.contains("device"));
}

TEST_CASE(mcp_target_status_shape) {
    server_fixture_t fx;
    bool is_error = true;
    json payload = fx.call("target", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("backend"));
    REQUIRE(payload.contains("kernel"));
    REQUIRE(payload.contains("attached"));
    REQUIRE_EQ(payload.value("attached", true), false);

    // Loaded-image state rides status too
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.at("image").value("ready", true), false);

    // And it reflects the shared session the moment a binary is loaded
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("target", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("image").value("ready", false), true);
    REQUIRE_GT(payload.at("image").value("functions", 0u), 0u);
    REQUIRE(!std::string(payload.at("image").value("name", "")).empty());
    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_bad_action_rejected) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("target", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    is_error = false;
    payload = fx.call("disasm", {}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_server_stop_is_clean) {
    {
        server_fixture_t fx;
        json res = fx.rpc("ping");
        REQUIRE(res.contains("result"));
    }
    REQUIRE(!slop::core::mcp::running());
    // Restart on the same ephemeral flow must still work
    server_fixture_t fx2;
    json res = fx2.rpc("ping");
    REQUIRE(res.contains("result"));
}

// === loaded-file visibility (UI session shared with MCP) ===

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

TEST_CASE(mcp_disasm_loaded_reports_state) {
    server_fixture_t fx;
    bool is_error = true;

    // Nothing loaded yet: not an error, just ready=false + hint
    json payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
    REQUIRE(payload.contains("hint"));
    // Target context rides along so one call shows both halves of the session
    REQUIRE(payload.contains("target"));
    REQUIRE_EQ(payload.at("target").value("attached", true), false);

    // Load the fixture through the shared core state, as the UI would
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", false), true);
    REQUIRE(payload.contains("path"));
    REQUIRE(payload.contains("base"));
    REQUIRE_GT(payload.value("functions", 0u), 0u);
    REQUIRE_GE(payload.value("sections", 0u), 3u);

    slop::core::disasm::binary_state::unload();
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
}

TEST_CASE(mcp_disasm_static_actions_use_loaded_binary) {
    server_fixture_t fx;
    bool is_error = false;

    // No path, nothing loaded -> actionable error
    json payload = fx.call("disasm", {{"action", "pe"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    // Every static action now works with zero arguments
    payload = fx.call("disasm", {{"action", "pe"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_GE(payload.at("sections").size(), 3u);

    payload = fx.call("disasm", {{"action", "functions"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total", 0u), 0u);
    REQUIRE(!payload.at("functions").empty());

    payload = fx.call("disasm", {{"action", "strings"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total_scanned", 0u), 0u);

    slop::core::disasm::binary_state::unload();

    // Explicit path still takes the private-cache route
    payload = fx.call("disasm", {{"action", "pe"}, {"path", SLOP_TARGET_EXE_PATH}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
}

TEST_CASE(mcp_disasm_symbols_roundtrip_and_file_disassemble) {
    server_fixture_t fx;
    bool is_error = true;

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(loaded.value("ready", false), true);
    const uint64_t base     = loaded.at("base").get<uint64_t>();
    const uint64_t entry_va = loaded.value("entry_va", base);

    // Rename a function over MCP; it must come back through symbols list
    json res = fx.call("disasm", {{"action", "symbol_set"},
                                  {"addr", entry_va}, {"name", "ai_entry_point"}},
                       is_error);
    REQUIRE(!is_error);
    REQUIRE(res.value("cleared", true) == false);

    res = fx.call("disasm", {{"action", "symbols"}}, is_error);
    REQUIRE(!is_error);
    bool found = false;
    for (const auto& s : res.at("symbols")) {
        if (s.value("va", 0ull) == entry_va && s.value("name", "") == "ai_entry_point")
            found = true;
    }
    REQUIRE(found);

    // The rename must surface in functions output too (shared session)
    res = fx.call("disasm", {{"action", "functions"}, {"limit", 10000}}, is_error);
    REQUIRE(!is_error);
    found = false;
    for (const auto& f : res.at("functions")) {
        if (f.value("va", 0ull) == entry_va)
            found = f.value("symbol", "") == "ai_entry_point";
    }
    REQUIRE(found);

    // File-backed disassembly with NO attached target: entry point decodes
    res = fx.call("disasm", {{"action", "disassemble"}, {"addr", entry_va}, {"count", 8}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(res.value("count", 0u), 0u);
    REQUIRE(!res.at("instructions").empty());

    // Clearing via empty name
    res = fx.call("disasm", {{"action", "symbol_set"}, {"addr", entry_va}, {"name", ""}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE(res.value("cleared", false) == true);

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_volt_regressions_arg_aliases_limits_assemble) {
    // Issues 1-5 + 14-15: base/addr aliases, apihash names, honored limits,
    // multi-instruction assemble, devirt guidance, predicate/iat counters.
    server_fixture_t fx;
    bool is_error = true;

    // assemble needs no image: "xor eax, eax; ret" is 31 C0 C3
    json res = fx.call("disasm", {{"action", "assemble"},
                                  {"text", "xor eax, eax; ret"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(res.value("length", 0u), 3u);
    REQUIRE_STR_EQ(res.value("bytes", "").c_str(), "31c0c3");

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE_EQ(loaded.value("ready", false), true);
    const uint64_t base = loaded.at("base").get<uint64_t>();
    const uint64_t entry_va = loaded.value("entry_va", base);

    // xray.entropy accepts base= alias + honors limit as window cap
    res = fx.call("xray", {{"action", "entropy"}, {"base", base},
                           {"size", 4096}, {"window_size", 256},
                           {"limit", 5}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("overall_entropy"));
    REQUIRE_LE(res.at("windows").size(), 5u);
    REQUIRE(res.contains("total_windows"));

    // xray.pages honors limit
    res = fx.call("xray", {{"action", "pages"}, {"base", base},
                           {"size", 8192}, {"limit", 2}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(res.at("pages").size(), 2u);
    REQUIRE(res.contains("total_pages"));

    // xray.apihash accepts plain API names (hashed with the algorithm)
    res = fx.call("xray", {{"action", "apihash"},
                           {"hashes", {"LoadLibraryA", "GetProcAddress"}}},
                  is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("name_inputs"));
    REQUIRE_EQ(res.at("name_inputs").size(), 2u);

    // disasm.xrefs honors limit
    res = fx.call("disasm", {{"action", "xrefs"}, {"addr", entry_va},
                             {"limit", 5}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(res.at("refs_to").size(), 5u);
    REQUIRE(res.contains("total"));

    // devirt.trace without handlers: structured guidance, not bare "missing"
    res = fx.call("devirt", {{"action", "trace"}, {"addr", entry_va}},
                  is_error);
    REQUIRE(is_error);
    REQUIRE(res.at("error").get<std::string>().find("handler_table") !=
            std::string::npos);

    // devirt.handlers accepts addr= as a table alias (clean entry has no
    // valid table, but the error must come from classification, not arg parse)
    res = fx.call("devirt", {{"action", "handlers"}, {"addr", base + 0x400}},
                  is_error);
    REQUIRE(is_error);
    const std::string herr = res.at("error").get<std::string>();
    REQUIRE(herr.find("missing numeric argument") == std::string::npos);

    // prove_predicates reports completed/failed/faulted denominators
    res = fx.call("devirt", {{"action", "prove_predicates"},
                             {"addr", entry_va}, {"runs", 2}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(res.contains("completed_runs"));
    REQUIRE(res.contains("failed_runs"));
    REQUIRE(res.contains("faulted_runs"));

    // iat_audit default audits parsed IAT slots only (no 500k+ overcount)
    res = fx.call("devirt", {{"action", "iat_audit"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(res.value("named", 0u), 0u);
    REQUIRE_LE(res.value("slots_scanned", 1000000u),
               res.value("named", 0u) + res.value("unnamed_valid", 0u) +
                   res.value("invalid", 0u));

    slop::core::disasm::binary_state::unload();
}

// === new memory / target / debugger surfaces ===

TEST_CASE(mcp_memory_new_actions_shape) {
    server_fixture_t fx;
    bool is_error = false;

    // All need a target; verify clean structured errors, not crashes
    json payload = fx.call("memory", {{"action", "pointerscan"}, {"target", 0x41414141}},
                           is_error);
    REQUIRE(is_error);

    payload = fx.call("memory", {{"action", "snapshot"}, {"addr", 0x41414141}}, is_error);
    REQUIRE(is_error);

    payload = fx.call("memory", {{"action", "diff"}, {"a", 1}, {"b", 2}}, is_error);
    REQUIRE(is_error);

    // Snapshot listing works without a target (empty store)
    payload = fx.call("memory", {{"action", "snapshots"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("memory", {{"action", "snapshot_free"}, {"all", true}}, is_error);
    REQUIRE(!is_error);
}

TEST_CASE(mcp_memory_ce_scan_state_and_validation) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("memory", {{"action", "scan_reset"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.value("reset", false));

    payload = fx.call("memory", {{"action", "scan_state"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_FALSE(payload.value("active", true));
    REQUIRE(payload.contains("region_scan_active"));
    REQUIRE(payload.contains("slots_tracked"));

    // Handler-level CE argument validation happens before the live scan, but
    // all scan/rescan actions still require an attached target
    payload = fx.call("memory",
                      {{"action", "scan"}, {"kind", "bogus"},
                       {"width", "u32"}, {"value", 1}}, is_error);
    REQUIRE(is_error);

    payload = fx.call("memory",
                      {{"action", "scan"}, {"kind", "exact"},
                       {"width", "u32"}, {"value", 1},
                       {"rounding", "bogus"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_target_handles_needs_session) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("target", {{"action", "handles"}}, is_error);
    REQUIRE(is_error);   // no target attached in unit-test environment
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_target_attach_populates_shared_session) {
    server_fixture_t fx;
    bool is_error = true;
    slop::core::disasm::binary_state::unload();   // deterministic start

    // The user-mode backend can open our own process: full round trip with
    // no second host process needed
    json payload = fx.call("target",
                           {{"action", "attach"},
                            {"pid", static_cast<uint64_t>(GetCurrentProcessId())}},
                           is_error);
    if (is_error) return;   // locked-down environment: nothing further to assert

    REQUIRE_EQ(payload.value("attached", false), true);
    // Main module was readable from disk -> shared session auto-populated
    REQUIRE_EQ(payload.value("image_auto_loaded", false), true);
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.at("image").value("ready", false), true);
    REQUIRE_GT(payload.at("image").value("functions", 0u), 0u);

    // Static tools now see it with zero arguments, no explicit 'path'
    payload = fx.call("disasm", {{"action", "functions"}, {"limit", 10}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(!payload.at("functions").empty());
    REQUIRE(!std::string(payload.value("image", "")).empty());

    // Never leak the session into later tests
    payload = fx.call("target", {{"action", "detach"}}, is_error);
    REQUIRE(!is_error);
    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_debugger_hwbp_requires_kernel_backend) {
    server_fixture_t fx;
    bool is_error = false;
    // User-mode backend active in tests: hw path must refuse cleanly
    json payload = fx.call("debugger",
                           {{"action", "bp_set"}, {"addr", 0x41414141},
                            {"hw", true}, {"type", 3}, {"len", 1}},
                           is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    // Bad len rejected even before backend checks would matter
    payload = fx.call("debugger", {{"action", "bp_set"}, {"addr", 1}, {"hw", true},
                                   {"len", 3}}, is_error);
    // Kernel check fires first without a driver, either way it's an error,
    // never a silent success
    REQUIRE(is_error);
}

TEST_CASE(mcp_debugger_status_reports_stealth_context) {
    server_fixture_t fx;
    bool is_error = true;
    const json payload = fx.call("debugger", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    // Stealth context fields ride status so agents can see which engine
    // flavor and anti-debug posture is live
    REQUIRE(payload.contains("mode"));
    REQUIRE(payload.contains("backend"));
    REQUIRE(payload.contains("stealth_peb_spoof"));
    REQUIRE(payload.contains("stealth_kernel_debug"));
    REQUIRE(payload.contains("hwbp_supported"));
    REQUIRE(payload.contains("veh_page"));
}

TEST_CASE(mcp_debugger_suspend_resume_require_attachment) {
    server_fixture_t fx;
    bool is_error = false;
    // Without an attached debugger both freeze/thaw actions must refuse
    // cleanly (never a silent success that suspends nothing)
    json payload = fx.call("debugger", {{"action", "suspend_all"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    payload = fx.call("debugger", {{"action", "resume_all"}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_driver_backend_preference_roundtrip) {
    server_fixture_t fx;
    bool is_error = true;
    // Query: reports preference + active badge without touching the driver
    json payload = fx.call("driver", {{"action", "backend"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("preference"));
    REQUIRE(payload.contains("active"));
    REQUIRE(payload.contains("kernel_active"));

    // Set: valid values round-trip; invalid values refuse
    payload = fx.call("driver", {{"action", "backend"}, {"pref", "user"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("preference").get<std::string>(), "user");

    payload = fx.call("driver", {{"action", "backend"}, {"pref", "auto"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("preference").get<std::string>(), "auto");

    payload = fx.call("driver", {{"action", "backend"}, {"pref", "bogus"}},
                      is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_schemas_expose_new_actions) {
    server_fixture_t fx;
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");

    auto enum_of = [](const json& tools, const char* name) -> json {
        for (const auto& t : tools)
            if (t.at("name") == name)
                return t.at("inputSchema").at("properties").at("action").at("enum");
        return json::array();
    };

    const json mem = enum_of(tools, "memory");
    REQUIRE(std::find(mem.begin(), mem.end(), "pointerscan") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "snapshot") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "diff") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "scan_state") != mem.end());
    REQUIRE(std::find(mem.begin(), mem.end(), "scan_reset") != mem.end());

    const json* mem_tool = nullptr;
    for (const auto& t : tools)
        if (t.at("name") == "memory") mem_tool = &t;
    REQUIRE(mem_tool != nullptr);
    if (mem_tool) {
        const auto& props = mem_tool->at("inputSchema").at("properties");
        const auto& kinds = props.at("kind").at("enum");
        const auto& widths = props.at("width").at("enum");
        const auto& rounding = props.at("rounding").at("enum");
        REQUIRE(std::find(kinds.begin(), kinds.end(), "between") != kinds.end());
        REQUIRE(std::find(kinds.begin(), kinds.end(), "increased_percent") != kinds.end());
        REQUIRE(std::find(kinds.begin(), kinds.end(), "decreased_percent") != kinds.end());
        REQUIRE(std::find(widths.begin(), widths.end(), "all") != widths.end());
        REQUIRE(std::find(rounding.begin(), rounding.end(), "truncated") != rounding.end());
        REQUIRE(props.contains("tail"));
        REQUIRE(props.contains("copy_on_write"));
        REQUIRE(props.contains("static_roots"));
        REQUIRE(props.contains("frontier_cap"));
    }

    const json tgt = enum_of(tools, "target");
    REQUIRE(std::find(tgt.begin(), tgt.end(), "handles") != tgt.end());

    // Stealth-debugger + backend-switching surfaces are declared
    const json dbg = enum_of(tools, "debugger");
    REQUIRE(std::find(dbg.begin(), dbg.end(), "suspend_all") != dbg.end());
    REQUIRE(std::find(dbg.begin(), dbg.end(), "resume_all") != dbg.end());

    const json drv = enum_of(tools, "driver");
    REQUIRE(std::find(drv.begin(), drv.end(), "backend") != drv.end());

    const json dis = enum_of(tools, "disasm");
    bool ok = false;
    ok |= std::find(dis.begin(), dis.end(), "loaded") != dis.end();
    ok |= std::find(dis.begin(), dis.end(), "symbols") != dis.end();
    ok |= std::find(dis.begin(), dis.end(), "symbol_set") != dis.end();
    REQUIRE(ok);
}

// === emulate + analyze over the wire ===

TEST_CASE(mcp_emulate_run_hex_payload) {
    server_fixture_t fx;
    bool is_error = true;

    // mov eax,2 / add eax,3 / ret
    json payload = fx.call("emulate",
                           {{"action", "run"},
                            {"hex", "B80200000083C003C3"}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_STR_EQ(payload.value("stopped_reason", "").c_str(), "return");
    REQUIRE_EQ(payload.value("instructions", 0u), 3u);

    const auto& regs = payload.at("regs");
    REQUIRE(regs.is_object());
    bool saw_rax5 = false;
    for (auto it = regs.begin(); it != regs.end(); ++it)
        if (it.key() == "rax" && it.value() == 5) saw_rax5 = true;
    REQUIRE(saw_rax5);
}

TEST_CASE(mcp_emulate_taint_over_http) {
    server_fixture_t fx;
    bool is_error = true;

    // mov edx,[0x500000] / xor eax,eax / add eax,edx / mov [0x500200],eax / ret
    json payload = fx.call(
        "emulate",
        {{"action", "run"},
         {"hex", "8B14250000500031C001D089042500025000C3"},
         {"maps", json::array({json{{"addr", 0x500000},
                                    {"hex", std::string(0x600, 'A')}}})},
         {"taint", json::array({json{{"addr", 0x500000}, {"len", 4}}})},
         {"watch_addr", 0x500200},
         {"watch_len", 4}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.value("output_tainted", false) == true);
    REQUIRE(!payload.at("taint_events").empty());
}

TEST_CASE(mcp_emulate_rejects_bad_input) {
    server_fixture_t fx;
    bool is_error = false;
    json payload = fx.call("emulate", {{"action", "run"}}, is_error);
    REQUIRE(is_error);                       // no code source
    payload = fx.call("emulate", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);                       // unknown action
}

TEST_CASE(mcp_analyze_packer_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    // Nothing loaded: actionable error, not a crash
    json payload = fx.call("analyze", {{"action", "packer"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    payload = fx.call("analyze", {{"action", "packer"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("image"));
    REQUIRE_EQ(payload.value("packed", true), false);   // clean MSVC build
    REQUIRE(payload.value("confidence", 1.0) < 0.5);
    slop::core::disasm::binary_state::unload();

    payload = fx.call("analyze",
                      {{"action", "packer"}, {"path", SLOP_TARGET_EXE_PATH}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("sections"));
}

TEST_CASE(mcp_analyze_signatures_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json payload = fx.call("analyze", {{"action", "signatures"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("signatures"));
    REQUIRE(payload.contains("count"));

    // Explicit path route works too
    payload = fx.call("analyze",
                      {{"action", "signatures"}, {"path", SLOP_TARGET_EXE_PATH}},
                      is_error);
    REQUIRE(!is_error);
    slop::core::disasm::binary_state::unload();
}



// === network / proxy / persist / re / script surfaces ===

TEST_CASE(mcp_network_shape_without_kernel) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("network", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("kernel_available"));
    REQUIRE(payload.contains("store_packets"));
    REQUIRE(payload.contains("proxy_running"));

    // Kernel capture paths refuse cleanly when the driver is absent
    payload = fx.call("network", {{"action", "capture_start"}}, is_error);
    if (payload.value("kernel_available", true) == false) {
        REQUIRE(is_error);
        REQUIRE(payload.contains("error"));
    }

    // Store-backed actions work without any kernel
    payload = fx.call("network", {{"action", "packets"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network", {{"action", "streams"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("count", -1), 0);

    payload = fx.call("network",
                      {{"action", "stream_data"}, {"id", 999}}, is_error);
    REQUIRE(is_error);   // unknown stream

    payload = fx.call("network", {{"action", "frobnicate"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_network_kernel_query_kit_surface) {
    server_fixture_t fx;

    // The AiDA-parity query/inspect actions are registered in the schema and
    // degrade to structured errors when the kernel driver is absent
    static const char* kQueryActions[] = {
        "connections", "deep_inspect", "wfp_callouts", "socket_handles",
        "tcpip_dump", "interfaces", "dns_spoof_list",
        "block_ip", "block_port", "block_process",
    };
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");
    std::string network_schema;
    for (const auto& t : tools)
        if (t.at("name").get<std::string>() == "network")
            network_schema = t.at("inputSchema").dump();
    REQUIRE(!network_schema.empty());
    for (const char* a : kQueryActions)
        REQUIRE_NE(network_schema.find(std::string("\"") + a + "\""),
                   std::string::npos);

    // Machine-independent: probe whether slopdrvr is live, then assert the
    // matching contract (structured refusal without it)
    bool is_error = false;
    json status = fx.call("network", {{"action", "status"}}, is_error);
    REQUIRE(!is_error);
    const bool kernel_live = status.value("kernel_available", false) == true;

    for (const char* a : kQueryActions) {
        json args = {{"action", a}};
        if (std::string(a) == "block_ip")
            args["ip"] = "192.0.2.1";      // valid arg; failure is driver-side
        json payload = fx.call("network", args, is_error);
        if (!kernel_live) {
            REQUIRE(is_error);
            REQUIRE(payload.contains("error"));
        }
    }

    // block_ip rejects a malformed address before touching the driver
    is_error = false;
    json payload = fx.call("network",
                           {{"action", "block_ip"}, {"ip", "not-an-ip"}},
                           is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_driver_kernel_extras_surface) {
    server_fixture_t fx;

    // read_teb / peb_modules / integrity_checks / sniff_buffers are registered
    // in the driver tool schema
    json res = fx.rpc("tools/list");
    const auto& tools = res.at("result").at("tools");
    std::string driver_schema;
    for (const auto& t : tools)
        if (t.at("name").get<std::string>() == "driver")
            driver_schema = t.at("inputSchema").dump();
    REQUIRE(!driver_schema.empty());
    for (const char* a : {"log_config", "read_teb", "peb_modules",
                          "integrity_checks", "sniff_buffers"})
        REQUIRE_NE(driver_schema.find(std::string("\"") + a + "\""),
                   std::string::npos);

    // log_config validates its range before touching the driver
    bool is_error = false;
    json payload = fx.call("driver",
                           {{"action", "log_config"}, {"level", 9}},
                           is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));

    is_error = false;
    payload = fx.call("driver",
                      {{"action", "log_config"}, {"cap_mb", 0}},
                      is_error);
    REQUIRE(is_error);

    // Argument validation runs ahead of the kernel work in every reachable
    // state (no driver / driver without target / attached), so these all
    // refuse with a structured error
    payload = fx.call("driver", {{"action", "read_teb"}}, is_error);
    REQUIRE(is_error);                       // missing tid (or no driver)
    REQUIRE(payload.contains("error"));

    payload = fx.call("driver",
                      {{"action", "peb_modules"}, {"order", "bogus"}},
                      is_error);
    REQUIRE(is_error);                       // bad order (or no driver/pid)

    payload = fx.call("driver",
                      {{"action", "sniff_buffers"}, {"op", "start"}},
                      is_error);
    REQUIRE(is_error);                       // missing addr
    REQUIRE(payload.contains("error"));
}

TEST_CASE(mcp_proxy_lifecycle_and_entries) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("proxy", {{"action", "start"}, {"port", 0}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("running", false), true);
    const uint64_t port = payload.value("port", 0u);
    REQUIRE_GT(port, 0);

    payload = fx.call("proxy", {{"action", "entries"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("entries"));

    payload = fx.call("proxy", {{"action", "stop"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("running", true), false);
}

TEST_CASE(mcp_persist_roundtrip) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "persist",
        {{"action", "save"}, {"name", "mcp_test_session"},
         {"data", json{{"pid", 4242}, {"note", "hello"}}}},
        is_error);
    REQUIRE(!is_error);
    const uint64_t id = payload.value("id", 0ull);
    REQUIRE_GT(id, 0ull);

    payload = fx.call("persist", {{"action", "list"}}, is_error);
    REQUIRE(!is_error);
    bool found = false;
    for (const auto& s : payload.at("sessions"))
        if (s.value("name", "") == "mcp_test_session") found = true;
    REQUIRE(found);

    payload = fx.call("persist", {{"action", "load"}, {"id", id}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.at("data").at("note").get<std::string>().c_str(),
                   "hello");

    payload = fx.call("persist", {{"action", "delete"}, {"id", id}},
                      is_error);
    REQUIRE(!is_error);

    payload = fx.call("persist", {{"action", "load"}, {"id", id}}, is_error);
    REQUIRE(is_error);   // deleted

    // kv helpers
    payload = fx.call("persist",
                      {{"action", "kv_set"}, {"key", "k"},
                       {"value", json{{"x", 1}}}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("persist", {{"action", "kv_get"}, {"key", "k"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("value").at("x").get<int>(), 1);
}

TEST_CASE(mcp_re_actions_on_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    // No image loaded: actionable error
    json payload = fx.call("re", {{"action", "rtti_scan"}}, is_error);
    REQUIRE(is_error);

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));

    payload = fx.call("re", {{"action", "rtti_scan"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("classes"));

    payload = fx.call("re", {{"action", "danger"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("hits"));

    payload = fx.call("re",
                      {{"action", "libsig"},
                       {"sigset",
                        R"([{"name":"probe","pattern":"48 89 5C 24 ??","offset":0}])"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("hits"));

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_script_run_roundtrip) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "script",
        {{"action", "run"}, {"code", "slop.log('answer', 6 * 7)"}},
        is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE(payload.at("output").get<std::string>().find("answer\t42") !=
            std::string::npos);

    // Error path: script failure surfaces as structured output
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "error('nope')"}},
                      is_error);
    REQUIRE(!is_error);   // tool succeeded; script failed inside
    REQUIRE_EQ(payload.value("ok", true), false);
    REQUIRE(payload.at("error").get<std::string>().find("nope") !=
            std::string::npos);

    payload = fx.call("script", {{"action", "explode"}}, is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_script_static_analysis_surface) {
    server_fixture_t fx;
    bool is_error = false;

    // The script tool drives the shared static-analysis session: load the
    // fixture through Lua, walk functions, rename, and read the rename back
    // through the MCP disasm tool, proving the two surfaces interoperate
    const std::string code = std::string(R"(
        assert(slop.image.load(")") + SLOP_TARGET_EXE_PATH + R"("), "load failed")
        local fns = slop.disasm.functions()
        assert(#fns > 0, "no functions")
        slop.disasm.set_name(fns[1].va, "lua_entry")
        assert(slop.disasm.name(fns[1].va) == "lua_entry")
        local insn = slop.disasm.decode(slop.image.status().entry, 2)
        assert(#insn >= 1, "no decode")
        return #fns
    )";
    json payload = fx.call("script",
                           {{"action", "run"}, {"code", code},
                            {"timeout_ms", 30000}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);

    // The rename is visible to the MCP symbol surface (shared session)
    payload = fx.call("disasm", {{"action", "symbols"}}, is_error);
    REQUIRE(!is_error);
    const auto& syms = payload.at("symbols");
    bool saw = false;
    for (const auto& s : syms)
        if (s.value("name", "") == "lua_entry") saw = true;
    REQUIRE(saw);

    // Lua-side unload tears down the shared session for the MCP side too
    payload = fx.call("script",
                      {{"action", "run"}, {"code", "slop.image.unload()"}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ready", true), false);
}

// === phase 11: xray / patch / types / notes + debugger extensions ===

TEST_CASE(mcp_xray_actions_over_loaded_image) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("xray", {{"action", "entropy"}}, is_error);
    REQUIRE(is_error);   // nothing loaded

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    payload = fx.call("xray",
                      {{"action", "entropy"}, {"addr", entry},
                       {"size", 4096}, {"window_size", 256}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("overall_entropy"));
    {
        const std::string v = payload.value("verdict", "");
        REQUIRE(v == "normal" || v == "suspicious_high_entropy");
    }

    payload = fx.call("xray", {{"action", "cfg"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("block_count", 0u), 1u);
    REQUIRE_GT(payload.value("cyclomatic_complexity", 0ull), 0ull);

    payload = fx.call("xray", {{"action", "complexity"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("instruction_count", 0u), 0u);
    REQUIRE(payload.contains("complexity_rating"));

    payload = fx.call("xray", {{"action", "obfuscation"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_LE(payload.value("obfuscation_score_pct", 101), 100);

    payload = fx.call("xray", {{"action", "anti_analysis"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("detections"));

    payload = fx.call("xray", {{"action", "cff"}, {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("flattened"));

    payload = fx.call("xray",
                      {{"action", "pages"}, {"addr", entry}, {"size", 8192}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("total_pages", 0u), 0u);
    REQUIRE(payload.contains("summary"));

    payload = fx.call("xray", {{"action", "gadgets"}, {"limit", 16}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("count", 0u), 0u);

    payload = fx.call("xray",
                      {{"action", "apihash"},
                       {"hashes", json::array({0xDEADBEEF})},
                       {"algorithm", "ror13"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("total_queried", 0u), 1u);
    REQUIRE_EQ(payload.value("resolved_count", -1), 0);

    payload = fx.call("xray", {{"action", "bogus"}}, is_error);
    REQUIRE(is_error);

    slop::core::disasm::binary_state::unload();
}

TEST_CASE(mcp_patch_journal_roundtrip) {
    server_fixture_t fx;
    bool is_error = true;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    // Dry run never lands bytes
    json payload = fx.call("patch",
                           {{"action", "resolve_opaque"}, {"addr", entry},
                            {"dry_run", true}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("dry_run", false), true);

    // Real write through the journal, then revert
    payload = fx.call("patch",
                      {{"action", "write_bytes"}, {"addr", entry},
                       {"hex", "9090"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("bytes_changed", 0ull), 2ull);

    payload = fx.call("patch", {{"action", "journal"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("total", 0u), 2u);
    REQUIRE_EQ(payload.value("indexes_dirty", false), true);

    payload = fx.call("patch", {{"action", "revert_all"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("bytes_changed", 0ull), 2ull);

    // Static actions still serve after mutation (lazy index rebuild path)
    payload = fx.call("disasm", {{"action", "functions"}, {"limit", 5}}, is_error);
    REQUIRE(!is_error);

    slop::core::disasm::binary_state::unload();

    // No image: structured error
    payload = fx.call("patch", {{"action", "write_bytes"}, {"addr", 1},
                                {"hex", "CC"}},
                      is_error);
    REQUIRE(is_error);
}

TEST_CASE(mcp_types_declare_and_read) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call(
        "types",
        {{"action", "declare"},
         {"decl", "struct SlopRec packed { u32 magic; u64 counter; };"}
        },
        is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("declared", 0u), 1u);

    payload = fx.call("types", {{"action", "get_struct"}, {"name", "SlopRec"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("size", 0ull), 12ull);   // packed u32+u64
    REQUIRE_EQ(payload.at("fields").at(1).value("offset", 0ull), 4ull);

    // Field read out of the live target (attached to ourselves by the attach
    // test pattern, here read from the loaded image's mapped header instead)
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t base = loaded.at("base").get<uint64_t>();
    payload = fx.call("types",
                      {{"action", "read_field"}, {"struct", "SlopRec"},
                       {"field", "magic"}, {"addr", base + 0x200}},
                      is_error);
    if (!is_error) {
        REQUIRE_EQ(payload.value("source", ""), "file");
        REQUIRE(payload.contains("uint"));
    } else {
        // Unmapped scratch VA in this image: structured failure is fine
        REQUIRE(payload.contains("error"));
    }
    slop::core::disasm::binary_state::unload();

    payload = fx.call(
        "types",
        {{"action", "create_enum"}, {"name", "SlopMode"},
         {"underlying", "u8"},
         {"values", json::array({json{{"name", "Off"}, {"value", 0}},
                                 json{{"name", "On"}, {"value", 1}}})}},
        is_error);
    REQUIRE(!is_error);
    payload = fx.call("types", {{"action", "get_enum"}, {"name", "SlopMode"}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.at("values").size(), 2u);
}

TEST_CASE(mcp_notes_comments_and_bookmarks) {
    server_fixture_t fx;
    bool is_error = true;
    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();

    json payload = fx.call("notes",
                           {{"action", "set_comment"}, {"addr", entry},
                            {"text", "ai says hi"}},
                           is_error);
    REQUIRE(!is_error);

    payload = fx.call("notes", {{"action", "get_comment"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_STR_EQ(payload.value("comment", "").c_str(), "ai says hi");

    payload = fx.call("notes", {{"action", "comments"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("count", 0u), 1u);

    // Toggle flips state deterministically; the per-hash store may already
    // carry a bookmark from an earlier run, so don't assume the direction
    json t1 = fx.call("notes", {{"action", "bookmark_toggle"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    json t2 = fx.call("notes", {{"action", "bookmark_toggle"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_NE(t1.value("bookmarked", true), t2.value("bookmarked", false));

    payload = fx.call("notes", {{"action", "bookmarks"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("count"));

    // Clear comment via empty text
    payload = fx.call("notes",
                      {{"action", "set_comment"}, {"addr", entry},
                       {"text", ""}},
                      is_error);
    REQUIRE(!is_error);
    payload = fx.call("notes", {{"action", "get_comment"}, {"addr", entry}},
                      is_error);
    REQUIRE_STR_EQ(payload.value("comment", "x").c_str(), "");

    slop::core::disasm::binary_state::unload();

    payload = fx.call("notes", {{"action", "comments"}}, is_error);
    REQUIRE(is_error);   // needs a loaded image
}

TEST_CASE(mcp_devirt_and_full_pass_over_wire) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("devirt", {{"action", "identify"}, {"addr", 1}},
                           is_error);
    REQUIRE(is_error);   // nothing loaded

    REQUIRE(slop::core::disasm::binary_state::load_file(SLOP_TARGET_EXE_PATH));
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    const uint64_t entry = loaded.at("entry_va").get<uint64_t>();
    const uint64_t base = loaded.at("base").get<uint64_t>();

    // Clean MSVC entry: not a VM, recovery reports none
    payload = fx.call("devirt", {{"action", "identify"}, {"addr", entry}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("likely_vm", true), false);
    REQUIRE(payload.contains("confidence_pct"));

    payload = fx.call("devirt",
                      {{"action", "recover_cfg"}, {"addr", entry},
                       {"runs", 2}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("flattened", true), false);
    REQUIRE_STR_EQ(payload.value("mode", "").c_str(), "none");

    payload = fx.call("devirt",
                      {{"action", "prove_predicates"}, {"addr", entry},
                       {"runs", 2}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("predicates"));

    payload = fx.call("devirt", {{"action", "iat_audit"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_GT(payload.value("named", 0u), 0u);   // real imports recognized

    // Handlers against a bogus table: structured error
    payload = fx.call("devirt",
                      {{"action", "handlers"},
                       {"table", base + 0x400}, {"entry_size", 8}},
                      is_error);
    REQUIRE(is_error);

    // patch.full_pass dry-run over the wire
    payload = fx.call("patch",
                      {{"action", "full_pass"}, {"addr", entry},
                       {"dry_run", true}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE_GE(payload.value("pre_obfuscation_score", -1), 0);
    REQUIRE(payload.contains("steps"));

    slop::core::disasm::binary_state::unload();

    payload = fx.call("patch", {{"action", "rebuild"}, {"addr", 1}}, is_error);
    REQUIRE(is_error);   // image unloaded
}

TEST_CASE(mcp_debugger_new_action_error_paths) {
    server_fixture_t fx;
    bool is_error = false;

    // All require a paused debugger; clean structured errors without one
    for (const char* action : {"callstack", "seh", "trace_run"}) {
        json payload = fx.call("debugger", {{"action", action}}, is_error);
        REQUIRE(is_error);
        REQUIRE(payload.contains("error"));
    }

    json payload = fx.call("debugger",
                           {{"action", "set_register"}, {"name", "rax"},
                            {"value", 1}},
                           is_error);
    REQUIRE(is_error);

    payload = fx.call("debugger",
                      {{"action", "watchpoint_set"}, {"addr", 0x41414141}},
                      is_error);
    REQUIRE(is_error);   // user backend in tests -> kernel required

    payload = fx.call("debugger",
                      {{"action", "bp_set"}, {"addr", 0x42424242},
                       {"condition", "rax == 123"}, {"auto_continue", true},
                       {"log", "hit"}},
                      is_error);
    // No target attached in this environment: set itself fails first
    REQUIRE(is_error);

    payload = fx.call("memory",
                      {{"action", "live_crypto"},
                       {"begin", 0x41414141}, {"end", 0x41414241}},
                      is_error);
    REQUIRE(is_error);   // no target

    payload = fx.call("network", {{"action", "intercept_list"}}, is_error);
    REQUIRE(is_error);   // no kernel driver
}



// hyperion engine surface (decompiler + analyzer-backed actions)

namespace {

bool wait_hype_ready_mcp(int timeout_ms = 30000) {
    namespace ds = slop::core::disasm::binary_state;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ds::hype_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return ds::hype_ready();
}

} // namespace

TEST_CASE(mcp_decomp_function_hyperion_engine) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Locate a real function through the hyperion-enriched listing
    json loaded = fx.call("disasm", {{"action", "loaded"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(loaded.contains("hype"));
    REQUIRE_EQ(loaded.at("hype").value("ready", false), true);
    REQUIRE_GT(loaded.at("hype").value("functions", 0), 0);

    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 64}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(fns.at("functions").size() > 0);
    // Every row carries its provenance (index vs hyperion analyzer DB)
    for (const auto& f : fns.at("functions")) {
        REQUIRE(f.contains("source"));
        const std::string src = f.value("source", "");
        REQUIRE(src == "index" || src == "hyperion");
    }
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();

    json payload = fx.call("decomp", {{"action", "function"},
                                      {"addr", some_fn}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("engine", ""), "hyperion");
    REQUIRE(payload.contains("signature"));
    REQUIRE(payload.at("lines").size() > 0);
    REQUIRE(payload.contains("function_va"));
    REQUIRE(payload.contains("vars"));

    // Unknown address -> structured error, fast unmapped-VA reject
    // (must never wedge the engine on addresses outside the image)
    payload = fx.call("decomp", {{"action", "function"},
                                 {"addr", 0x1BADBEEFull}}, is_error);
    REQUIRE(is_error);
    REQUIRE(payload.contains("error"));
    REQUIRE(payload.at("error").get<std::string>().find("not mapped") !=
            std::string::npos);

    ds::unload();
}

TEST_CASE(mcp_disasm_hyperion_blocks_vtables_globals) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // blocks: function containing the image entry point
    namespace dsm = slop::core::disasm;
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;

    json blocks = fx.call("disasm", {{"action", "blocks"}, {"addr", entry}},
                          is_error);
    REQUIRE(!is_error);
    REQUIRE(blocks.contains("blocks"));
    REQUIRE(blocks.at("blocks").size() > 0);
    REQUIRE(blocks.at("blocks").at(0).contains("succs"));
    REQUIRE(blocks.contains("entry"));

    // globals + vtables respond with count fields (may be empty on a small
    // fixture, but must be well-formed and non-error)
    json globals = fx.call("disasm", {{"action", "globals"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(globals.contains("count"));
    json vts = fx.call("disasm", {{"action", "vtables"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE(vts.contains("count"));

    // xrefs now carry hyperion kind names
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 64}}, is_error);
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();
    json xr = fx.call("disasm", {{"action", "xrefs"}, {"addr", some_fn}},
                      is_error);
    REQUIRE(!is_error);
    REQUIRE(xr.contains("refs_to"));

    ds::unload();
}

TEST_CASE(mcp_analyze_diff_self_identical) {
    server_fixture_t fx;
    bool is_error = false;

    json payload = fx.call("analyze",
                           {{"action", "diff"},
                            {"path_a", SLOP_TARGET_EXE_PATH},
                            {"path_b", SLOP_TARGET_EXE_PATH}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE(payload.contains("totals"));
    REQUIRE_GT(payload.at("totals").value("identical", -1), 0);
    // Self-diff reports no changed functions
    REQUIRE_EQ(payload.value("count", 1), 0);
}

TEST_CASE(mcp_types_format_at_renders_struct) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));

    server_fixture_t fx;
    bool is_error = false;

    // Declare a small struct, then render it over the entry-point bytes
    json decl = fx.call("types",
                        {{"action", "declare"},
                         {"decl", "struct HypeHdr { u32 magic; u32 size; u64 stamp; };"}},
                        is_error);
    REQUIRE(!is_error);

    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;
    json payload = fx.call("types",
                           {{"action", "format_at"},
                            {"addr", entry}, {"type", "HypeHdr"}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("source", ""), "file");
    REQUIRE(payload.at("rendered").get<std::string>().find("HypeHdr") !=
            std::string::npos);

    ds::unload();
}

TEST_CASE(mcp_persist_hype_project_roundtrip) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Rename a function over MCP, save the .hdb, merge-load it back
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 8}}, is_error);
    const uint64_t some_fn =
        fns.at("functions").at(0).at("va").get<uint64_t>();
    REQUIRE(!fx.call("disasm",
                     {{"action", "symbol_set"}, {"addr", some_fn},
                      {"name", "hype_roundtrip_fn"}},
                     is_error)
                 .is_null());

    const std::string dir = std::string(std::getenv("TEMP") ? std::getenv("TEMP")
                                                            : ".") +
                            "\\slop_hype_test_proj";
    json saved = fx.call("persist", {{"action", "hype_save"}, {"dir", dir}},
                         is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(saved.value("ok", false), true);

    json loaded = fx.call("persist", {{"action", "hype_load"}, {"dir", dir}},
                          is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(loaded.value("ok", false), true);
    REQUIRE_GT(loaded.value("merged_names", 0), 0);

    ds::unload();
}

TEST_CASE(mcp_hype_reanalysis_after_patch) {
    namespace ds = slop::core::disasm::binary_state;
    REQUIRE(ds::load_file(SLOP_TARGET_EXE_PATH));
    REQUIRE(wait_hype_ready_mcp());

    server_fixture_t fx;
    bool is_error = false;

    // Any mapped byte write goes through the imgpatch journal and dirties
    // the indexes; the next functions/xrefs/strings call rebuilds them and
    // kicks a hyperion re-analysis over the patched bytes
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;

    json w = fx.call("patch",
                     {{"action", "write_bytes"}, {"addr", entry},
                      {"hex", "90"}},
                     is_error);
    REQUIRE(!is_error);

    // Trigger the lazy rebuild + reanalyze
    json fns = fx.call("disasm",
                       {{"action", "functions"}, {"limit", 16}}, is_error);
    REQUIRE(!is_error);

    // Re-analysis started synchronously inside the handler: not ready now..
    REQUIRE_FALSE(ds::hype_ready());
    // ...and completes again
    REQUIRE(wait_hype_ready_mcp());

    // Decompiler still works over the patched image
    json decomp = fx.call("decomp", {{"action", "function"},
                                     {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(decomp.value("engine", ""), "hyperion");

    ds::unload();
}

TEST_CASE(mcp_disasm_load_unload_shared_session) {
    namespace ds = slop::core::disasm::binary_state;
    ds::unload();

    server_fixture_t fx;
    bool is_error = false;

    // Load straight into the shared session, same path the UI's
    // "open file..." takes, hyperion analysis included
    json payload = fx.call("disasm",
                           {{"action", "load"},
                            {"path", SLOP_TARGET_EXE_PATH}},
                           is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("ok", false), true);
    REQUIRE_EQ(payload.value("ready", false), true);
    REQUIRE(payload.contains("hype"));
    REQUIRE(wait_hype_ready_mcp());

    // The decompiler runs against the shared session's engine
    auto& b = ds::get();
    const uint64_t entry = b.base + b.pe.entry_rva;
    payload = fx.call("decomp", {{"action", "function"},
                                 {"addr", entry}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_EQ(payload.value("engine", ""), "hyperion");

    // Unload tears it all down
    payload = fx.call("disasm", {{"action", "unload"}}, is_error);
    REQUIRE(!is_error);
    REQUIRE_FALSE(ds::has_binary());
}
