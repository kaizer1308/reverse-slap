// src/tests/test_frida.cpp
// Frida service + MCP tool-surface tests. Uses the live local device where
// possible (enumerate) and spawn/attach against the SlopTarget.exe fixture
// for the full session + script + RPC round-trip. Runs without the kernel
// driver, frida's local backend needs only user-mode privileges

#include "harness.hpp"

#include "core/frida/frida_service.hpp"
#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"

#include <windows.h>

#include <nlohmann/json.hpp>
#include <httplib.h>

#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

namespace {

using json = nlohmann::json;
using slop::core::frida::frida_service_t;

bool find_target_pid(const std::string& name, uint32_t* pid) {
    std::vector<slop::core::frida::process_info_t> ps;
    std::string err;
    if (!frida_service_t::get().enumerate_processes("", "", &ps, &err)) return false;
    for (auto& p : ps)
        if (p.name == name) {
            *pid = p.pid;
            return true;
        }
    return false;
}

} // namespace

TEST_CASE(frida_version) {
    const std::string v = frida_service_t::get().version();
    REQUIRE_FALSE(v.empty());
    REQUIRE(v.rfind("17.", 0) == 0);   // devkit 17.x
    std::printf("  frida version: %s\n", v.c_str());
}

TEST_CASE(frida_devices_local) {
    std::vector<slop::core::frida::device_info_t> devices;
    std::string err;
    REQUIRE(frida_service_t::get().list_devices(&devices, &err));
    REQUIRE_FALSE(devices.empty());
    bool has_local = false;
    for (auto& d : devices) {
        std::printf("  device: %s (%s) type=%s\n", d.id.c_str(), d.name.c_str(),
                    d.dtype.c_str());
        if (d.dtype == "local") has_local = true;
    }
    REQUIRE(has_local);
}

TEST_CASE(frida_enumerate_processes) {
    std::vector<slop::core::frida::process_info_t> ps;
    std::string err;
    REQUIRE(frida_service_t::get().enumerate_processes("", "minimal", &ps, &err));
    REQUIRE_FALSE(ps.empty());
    bool saw_self = false;
    const DWORD self_pid = GetCurrentProcessId();
    for (auto& p : ps)
        if (p.pid == self_pid) saw_self = true;
    REQUIRE(saw_self);
}

TEST_CASE(frida_find_process) {
    std::optional<slop::core::frida::process_info_t> p;
    std::string err;
    // Self by image name (find_process_by_name matches executable name)
    // NOTE: pid equality is not asserted, a stale same-named instance from a
    // parallel test run can win the name race; the contract is the name hit
    char self_name[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, self_name, MAX_PATH);
    std::string base = self_name;
    const size_t slash = base.find_last_of("\\/");
    if (slash != std::string::npos) base = base.substr(slash + 1);
    REQUIRE(frida_service_t::get().find_process("", base, &p, &err));
    REQUIRE(p.has_value());
    REQUIRE_EQ(p->name, base);
    std::printf("  found %s pid=%u (self=%u)\n", base.c_str(), p->pid,
                GetCurrentProcessId());

    // A process that certainly does not exist
    std::optional<slop::core::frida::process_info_t> none;
    REQUIRE(frida_service_t::get().find_process(
        "", "slop-no-such-process-zzz", &none, &err));
    REQUIRE_FALSE(none.has_value());
}

// Full agent round-trip: spawn the SlopTarget fixture, attach, load a script
// that hooks/exports via rpc, call an export, collect a message, kill
TEST_CASE(frida_spawn_session_script_rpc) {
    auto& svc = frida_service_t::get();
    std::string err;

    uint32_t pid = 0;
    REQUIRE(svc.spawn("", SLOP_TARGET_EXE_PATH, {}, {}, "", &pid, &err));
    REQUIRE_GT(pid, 0u);
    std::printf("  spawned SlopTarget pid=%u\n", pid);
    // Never leak a suspended spawn: REQUIRE throws past cleanup on failure
    struct kill_guard_t {
        uint32_t pid;
        ~kill_guard_t() {
            std::string e;
            frida_service_t::get().kill("", pid, &e);
        }
    } kill_guard{pid};

    std::string session;
    REQUIRE(svc.attach("", pid, "", &session, &err));
    REQUIRE_FALSE(session.empty());

    // Script: export an rpc method + send a message on load
    const std::string src = R"JS(
        rpc.exports = {
            add: function (a, b) { return a + b; },
            greet: function (name) { return "hi " + name; }
        };
        send({ kind: "hello", pid: Process.id });
    )JS";
    std::string script;
    REQUIRE(svc.create_script(session, "test", src, "qjs", &script, &err));
    REQUIRE(svc.load_script(script, &err));

    // Drain the hello message
    std::vector<slop::core::frida::script_message_t> msgs;
    size_t dropped = 0;
    bool saw_hello = false;
    for (int i = 0; i < 50 && !saw_hello; i++) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        REQUIRE(svc.read_messages(script, 64, &msgs, &dropped, &err));
        for (auto& m : msgs) {
            const json j = json::parse(m.json, nullptr, false);
            if (!j.is_discarded() && j.contains("payload") &&
                j["payload"].contains("kind") && j["payload"]["kind"] == "hello")
                saw_hello = true;
        }
        msgs.clear();
    }
    REQUIRE(saw_hello);

    // RPC round-trip
    std::string reply;
    REQUIRE(svc.rpc_call(script, "add", "[19, 23]", 15000, &reply, &err));
    if (reply.empty())
        std::printf("  rpc reply empty, err=%s\n", err.c_str());
    const json r = json::parse(reply, nullptr, false);
    REQUIRE_FALSE(r.is_discarded());
    REQUIRE(r.is_array());
    REQUIRE_EQ(r.size(), 4u);
    REQUIRE_EQ(r.at(2).get<std::string>(), "ok");
    REQUIRE_EQ(r.at(3).get<int>(), 42);

    std::string reply2;
    REQUIRE(svc.rpc_call(script, "greet", "[\"lo\"]", 15000, &reply2, &err));
    const json r2 = json::parse(reply2, nullptr, false);
    REQUIRE_EQ(r2.at(3).get<std::string>(), "hi lo");

    // RPC error path: unknown method -> "error" reply, not a transport failure
    std::string reply3;
    REQUIRE(svc.rpc_call(script, "nope", "[]", 15000, &reply3, &err));
    const json r3 = json::parse(reply3, nullptr, false);
    REQUIRE_EQ(r3.at(2).get<std::string>(), "error");

    // Frida bytecode is a usable artifact, not a dead-end compiler response
    std::string bytecode_b64;
    REQUIRE(svc.compile_script(session, src, "qjs", &bytecode_b64, &err));
    REQUIRE_FALSE(bytecode_b64.empty());
    std::string bytecode_script;
    REQUIRE(svc.create_script_from_bytes(session, "compiled", bytecode_b64, "qjs",
                                         &bytecode_script, &err));
    REQUIRE(svc.load_script(bytecode_script, &err));
    std::string compiled_reply;
    REQUIRE(svc.rpc_call(bytecode_script, "add", "[20, 22]", 15000,
                         &compiled_reply, &err));
    const json compiled = json::parse(compiled_reply, nullptr, false);
    REQUIRE_EQ(compiled.at(3).get<int>(), 42);
    REQUIRE(svc.destroy_script(bytecode_script, &err));

    // Snapshot output can seed a subsequent source-created script
    std::string snapshot_b64;
    REQUIRE(svc.snapshot_script(session, "globalThis.snapshotSeed = 40;", "v8",
                                &snapshot_b64, &err));
    REQUIRE_FALSE(snapshot_b64.empty());
    std::string snapshot_script;
    REQUIRE(svc.create_script_with_snapshot(
        session, "snapshot",
        "rpc.exports = { value: function () { return snapshotSeed + 2; } };",
        snapshot_b64, "v8", &snapshot_script, &err));
    REQUIRE(svc.load_script(snapshot_script, &err));
    std::string snapshot_reply;
    REQUIRE(svc.rpc_call(snapshot_script, "value", "[]", 15000,
                         &snapshot_reply, &err));
    const json snapshot_result = json::parse(snapshot_reply, nullptr, false);
    REQUIRE_EQ(snapshot_result.at(3).get<int>(), 42);
    REQUIRE(svc.destroy_script(snapshot_script, &err));

    // Unload is terminal in Frida; stale handles must not remain reloadable
    std::string unload_script;
    REQUIRE(svc.create_script(session, "unload", "send('loaded');", "qjs",
                              &unload_script, &err));
    REQUIRE(svc.load_script(unload_script, &err));
    REQUIRE(svc.unload_script(unload_script, &err));
    REQUIRE_FALSE(svc.load_script(unload_script, &err));

    // Teardown cancels unresolved RPCs instead of holding the service for the
    // entire timeout
    const std::string hanging_src = R"JS(
        rpc.exports = {
            hang: function () { return new Promise(function () {}); }
        };
    )JS";
    std::string hanging_script;
    REQUIRE(svc.create_script(session, "hanging", hanging_src, "qjs",
                              &hanging_script, &err));
    REQUIRE(svc.load_script(hanging_script, &err));
    std::atomic_bool rpc_finished = false;
    bool rpc_ok = true;
    std::string rpc_error;
    std::thread rpc_thread([&] {
        std::string ignored;
        rpc_ok = svc.rpc_call(hanging_script, "hang", "[]", 15000,
                              &ignored, &rpc_error);
        rpc_finished.store(true, std::memory_order_release);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    REQUIRE(svc.destroy_script(hanging_script, &err));
    rpc_thread.join();
    REQUIRE(rpc_finished.load(std::memory_order_acquire));
    REQUIRE_FALSE(rpc_ok);
    REQUIRE(rpc_error.find("script destroyed") != std::string::npos);

    // Teardown: destroy script, detach (kills the spawned child), kill
    REQUIRE(svc.destroy_script(script, &err));
    REQUIRE(svc.detach_session(session, &err));
    REQUIRE(svc.kill("", pid, &err));
}

TEST_CASE(frida_piped_spawn_output) {
    auto& svc = frida_service_t::get();
    std::string err;
    uint32_t pid = 0;
    REQUIRE(svc.spawn_piped("", SLOP_TARGET_EXE_PATH, {}, {}, "", &pid, &err));
    struct kill_guard_t {
        uint32_t pid;
        ~kill_guard_t() {
            std::string ignored;
            frida_service_t::get().kill("", pid, &ignored);
        }
    } kill_guard{pid};
    REQUIRE(svc.resume("", pid, &err));

    bool saw_banner = false;
    std::string stdout_text;
    for (int i = 0; i < 50 && !saw_banner; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::vector<slop::core::frida::spawn_output_t> output;
        size_t remaining = 0, dropped = 0;
        REQUIRE(svc.read_spawn_output("", pid, 64, &output, &remaining, &dropped, &err));
        for (const auto& event : output) {
            const std::string text(event.data.begin(), event.data.end());
            if (event.fd == 1) stdout_text += text;
        }
        saw_banner = stdout_text.find("SlopTarget") != std::string::npos;
    }
    REQUIRE(saw_banner);
    REQUIRE(svc.kill("", pid, &err));
}

TEST_CASE(frida_mcp_request_cancellation) {
    auto& svc = frida_service_t::get();
    std::string err;
    uint32_t pid = 0;
    REQUIRE(svc.spawn("", SLOP_TARGET_EXE_PATH, {}, {}, "", &pid, &err));
    struct cleanup_t {
        uint32_t pid;
        ~cleanup_t() {
            slop::core::mcp::stop();
            std::string ignored;
            frida_service_t::get().kill("", pid, &ignored);
        }
    } cleanup{pid};
    std::string session;
    REQUIRE(svc.attach("", pid, "", &session, &err));
    std::string script;
    REQUIRE(svc.create_script(
        session, "cancel",
        "rpc.exports = { hang: function () { return new Promise(function () {}); } };",
        "qjs", &script, &err));
    REQUIRE(svc.load_script(script, &err));

    slop::core::mcp::server_config_t cfg;
    cfg.port = 0;
    REQUIRE(slop::core::mcp::start(cfg));
    const uint16_t port = slop::core::mcp::port();
    httplib::Client caller("127.0.0.1", port);
    httplib::Client canceller("127.0.0.1", port);
    caller.set_read_timeout(std::chrono::seconds(10));
    const httplib::Headers headers{{"Mcp-Session-Id", "frida-cancel-test"}};
    json response;
    std::thread call_thread([&] {
        const json request = {
            {"jsonrpc", "2.0"}, {"id", "hang-1"}, {"method", "tools/call"},
            {"params", {{"name", "frida"},
                        {"arguments", {{"action", "rpc"}, {"script", script},
                                       {"method", "hang"}, {"timeout_ms", 25000}}}}}
        };
        auto result = caller.Post("/mcp", headers, request.dump(), "application/json");
        REQUIRE(result);
        if (result) response = json::parse(result->body);
    });
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    const json cancel = {{"jsonrpc", "2.0"},
                         {"method", "notifications/cancelled"},
                         {"params", {{"requestId", "hang-1"}, {"reason", "test"}}}};
    auto cancel_result = canceller.Post("/mcp", headers, cancel.dump(), "application/json");
    REQUIRE(cancel_result);
    if (cancel_result) REQUIRE_EQ(cancel_result->status, 204);
    call_thread.join();
    REQUIRE(response.contains("result"));
    REQUIRE(response.at("result").value("isError", false));
    const std::string payload = response.at("result").at("content").at(0).at("text");
    REQUIRE(payload.find("cancelled") != std::string::npos);

    REQUIRE(svc.destroy_script(script, &err));
    REQUIRE(svc.detach_session(session, &err));
    REQUIRE(svc.kill("", pid, &err));
    caller.stop();
    canceller.stop();
    slop::core::mcp::stop();
}

TEST_CASE(frida_mcp_tool_surface) {
    // The frida MCP tool must exist and answer status without any handles
    bool is_error = false;
    json out = slop::core::mcp::call_tool("frida", {{"action", "status"}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE(out.value("available", false));
    REQUIRE(out.value("initialized", false));
    REQUIRE(out.value("version", "").rfind("17.", 0) == 0);

    json ps = slop::core::mcp::call_tool("frida",
                                         {{"action", "ps"}, {"limit", 20}}, is_error);
    REQUIRE_FALSE(is_error);
    REQUIRE(ps.contains("processes"));
    REQUIRE_GT(ps.at("processes").size(), 0u);

    // Unknown action -> structured error
    json bad = slop::core::mcp::call_tool("frida", {{"action", "bogus"}}, is_error);
    REQUIRE(is_error);

    // Unknown handle -> structured error, never a crash
    json nope = slop::core::mcp::call_tool("frida",
                                           {{"action", "messages"},
                                            {"script", "sc999"}}, is_error);
    REQUIRE(is_error);

    json bad_pid = slop::core::mcp::call_tool(
        "frida", {{"action", "attach"}, {"pid", 0x100000000ull}}, is_error);
    REQUIRE(is_error);

    json bad_hex = slop::core::mcp::call_tool(
        "frida", {{"action", "input"}, {"pid", 1}, {"hex", "abc"}}, is_error);
    REQUIRE(is_error);
}
