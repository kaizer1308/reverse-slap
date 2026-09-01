// src/core/mcp/mcp_server.cpp
// the mcp server, jsonrpc over http with a keepalive stream on the side
// every tool call funnels through one mutex so parallel requests cant race

#include "core/mcp/mcp_server.hpp"
#include "core/mcp/mcp_tools.hpp"

#include "core/infra/event_bus.hpp"

#include <httplib.h>

#include <nlohmann/json.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <vector>

namespace slop::core::mcp {

namespace {

using json = nlohmann::json;

std::unique_ptr<httplib::Server> g_srv;
std::unique_ptr<std::thread>     g_thread;
std::atomic<bool>                g_running{false};
std::atomic<uint16_t>            g_port{0};
server_config_t                  g_cfg{};
std::mutex                       g_active_mu;
std::map<std::string, std::shared_ptr<infra::cancel_source_t>> g_active;

constexpr const char* kProtocolVersion = "2025-06-18";
constexpr const char* kServerName      = "reverse-slop";
constexpr const char* kServerVersion   = "0.1.0";

// the little intro agents get when they connect so they know how to drive us
constexpr const char* kInstructions =
    "Windows reverse-engineering workbench. One tool per domain, each "
    "dispatched by an 'action' enum; read a tool's description before first "
    "use. Core model: ONE shared session, the UI and every tool see the same "
    "attached target and the same loaded binary (see 'state' in this "
    "response). Open every session with target.status and disasm.loaded. "
    "Static flow: disasm.load(path) -> poll disasm.loaded until "
    "image.hype.ready=true -> functions/xrefs/strings -> decomp.function. "
    "Live flow: target.list -> target.attach(pid) -> memory.scan. Actions "
    "fail fast with structured errors when a precondition is missing (target "
    "attached, image.ready, image.hype.ready), re-check state rather than "
    "retrying. driver.status reports whether the slopdrvr kernel backend is "
    "active; kernel-only actions return structured errors when it is not. "
    "Annotations (disasm.symbol_set, notes, types) persist per binary hash "
    "and are shared with the UI.";

json rpc_error(int code, const std::string& message, const json& id) {
    return {{"jsonrpc", "2.0"}, {"error", {{"code", code}, {"message", message}}}, {"id", id}};
}

json rpc_result(const json& result, const json& id) {
    return {{"jsonrpc", "2.0"}, {"result", result}, {"id", id}};
}

std::optional<std::string> request_key(const std::string& session, const json& id) {
    if (id.is_string())
        return session + std::string("\0s:", 3) + id.get<std::string>();
    if (id.is_number_unsigned())
        return session + std::string("\0u:", 3) + std::to_string(id.get<uint64_t>());
    if (id.is_number_integer())
        return session + std::string("\0i:", 3) + std::to_string(id.get<int64_t>());
    return std::nullopt;
}

void cancel_active(const std::string& session, const json& id) {
    const auto key = request_key(session, id);
    if (!key) return;
    std::shared_ptr<infra::cancel_source_t> source;
    {
        std::lock_guard lk(g_active_mu);
        auto it = g_active.find(*key);
        if (it != g_active.end()) source = it->second;
    }
    if (source) source->request();
}

json handle_request(const json& req, const std::string& session) {
    if (!req.contains("method") || !req.at("method").is_string())
        return rpc_error(-32600, "invalid request: missing method", req.value("id", json(nullptr)));

    const std::string method = req.at("method").get<std::string>();
    const json& id = req.contains("id") ? req.at("id") : json(nullptr);
    const json params = req.contains("params") ? req.at("params") : json::object();

    if (method == "initialize") {
        return rpc_result({
            {"protocolVersion", kProtocolVersion},
            {"capabilities", {{"tools", {{"listChanged", false}}}}},
            {"serverInfo", {{"name", kServerName}, {"version", kServerVersion}}},
            {"instructions", kInstructions},
            // tell the agent what we already have going so it doesnt start blind
            {"state", session_state()}
        }, id);
    }

    if (method == "notifications/initialized") {
        return json();   // notifications never get a reply
    }

    if (method == "notifications/cancelled") {
        if (params.contains("requestId")) cancel_active(session, params.at("requestId"));
        return json();
    }

    if (method == "ping") {
        return rpc_result(json::object(), id);
    }

    if (method == "tools/list") {
        json tools = json::array();
        list_tools(tools);
        return rpc_result({{"tools", tools}}, id);
    }

    if (method == "tools/call") {
        if (!params.contains("name") || !params.at("name").is_string())
            return rpc_error(-32602, "tools/call: missing tool name", id);
        const std::string name = params.at("name").get<std::string>();
        const json args = params.contains("arguments") ? params.at("arguments") : json::object();

        bool is_error = false;
        auto source = std::make_shared<infra::cancel_source_t>();
        const auto key = request_key(session, id);
        if (key) {
            std::lock_guard lk(g_active_mu);
            if (g_active.contains(*key))
                return rpc_error(-32600, "duplicate active request id", id);
            g_active[*key] = source;
        }
        struct registration_guard_t {
            std::optional<std::string> key;
            std::shared_ptr<infra::cancel_source_t> source;
            ~registration_guard_t() {
                if (!key) return;
                std::lock_guard lk(g_active_mu);
                auto it = g_active.find(*key);
                if (it != g_active.end() && it->second == source) g_active.erase(it);
            }
        } registration{key, source};
        json payload = call_tool(name, args, is_error, source->token());
        // memory reads can hand back junk bytes so swap bad utf8 instead of 500ing
        return rpc_result({
            {"content", json::array({
                {{"type", "text"}, {"text", payload.dump(2, ' ', true,
                                                          json::error_handler_t::replace)}}
            })},
            {"isError", is_error}
        }, id);
    }

    return rpc_error(-32601, "method not found: " + method, id);
}

// /api is the same tools but raw json for the ui so it only parses once
// also keeps front end only actions out of the agent facing tools list
json handle_api(const json& req, infra::cancel_token_t cancel) {
    if (!req.is_object())
        return {{"ok", false}, {"error", "api: request must be an object"}};
    if (!req.contains("tool") || !req.at("tool").is_string())
        return {{"ok", false}, {"error", "api: missing tool"}};
    if (!req.contains("action") || !req.at("action").is_string())
        return {{"ok", false}, {"error", "api: missing action"}};

    const std::string tool = req.at("tool").get<std::string>();
    json args = req.contains("params") && req.at("params").is_object()
                    ? req.at("params")
                    : json::object();
    args["action"] = req.at("action");

    bool is_error = false;
    json payload = call_tool(tool, args, is_error, cancel);
    json out{{"ok", !is_error}, {"data", std::move(payload)}};
    if (req.contains("id")) out["id"] = req.at("id");
    return out;
}

bool authorized(const httplib::Request& req) {
    if (g_cfg.token.empty()) return true;
    const auto auth = req.get_header_value("Authorization");
    return auth == ("Bearer " + g_cfg.token);
}

// the webview is cross origin so it needs cors, only tauri and the vite dev port get in
bool apply_cors(const httplib::Request& req, httplib::Response& res) {
    static const char* kAllowed[] = {
        "http://tauri.localhost",  "https://tauri.localhost",
        "tauri://localhost",       "http://localhost:1420",
        "http://127.0.0.1:1420",
    };
    const auto origin = req.get_header_value("Origin");
    if (origin.empty()) return true;      // no origin means not a browser, let it through
    for (const char* a : kAllowed) {
        if (origin != a) continue;
        res.set_header("Access-Control-Allow-Origin", origin);
        res.set_header("Vary", "Origin");
        res.set_header("Access-Control-Allow-Headers",
                       "Authorization, Content-Type, Mcp-Session-Id");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Max-Age", "600");
        return true;
    }
    return false;
}

} // namespace

bool start(const server_config_t& cfg) {
    if (g_running) return true;

    g_cfg = cfg;
    auto srv = std::make_unique<httplib::Server>();

    // cap the body so a wild client cant eat all the ram
    srv->set_payload_max_length(32ull << 20);
    srv->set_read_timeout(std::chrono::seconds(30));
    srv->set_write_timeout(std::chrono::seconds(30));

    srv->set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr ep) {
        std::string msg = "internal error";
        try { if (ep) std::rethrow_exception(ep); }
        catch (const std::exception& e) { msg = e.what(); }
        catch (...) {}
        res.status = 500;
        res.set_content(json({{"jsonrpc", "2.0"},
                              {"error", {{"code", -32603}, {"message", msg}}},
                              {"id", nullptr}}).dump(), "application/json");
    });

    srv->Get("/health", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(json({{"ok", true}, {"server", kServerName},
                              {"version", kServerVersion}}).dump(), "application/json");
    });

    srv->Post("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        if (!authorized(req)) {
            res.status = 401;
            res.set_content(json({{"error", "unauthorized"}}).dump(), "application/json");
            return;
        }
        json req_json = json::parse(req.body, nullptr, false);
        if (req_json.is_discarded()) {
            res.status = 400;
            res.set_content(rpc_error(-32700, "parse error", nullptr).dump(), "application/json");
            return;
        }
        const std::string session = req.has_header("Mcp-Session-Id")
            ? req.get_header_value("Mcp-Session-Id") : "<legacy>";

        // jsonrpc allows whole batches in one post
        if (req_json.is_array()) {
            json out = json::array();
            for (const auto& r : req_json) {
                json resp = handle_request(r, session);
                if (!resp.is_null()) out.push_back(std::move(resp));
            }
            // nothing but notifications means we say nothing back
            if (out.empty()) {
                res.status = 204;
                return;
            }
            res.set_content(out.dump(), "application/json");
            return;
        }

        json resp = handle_request(req_json, session);
        if (resp.is_null()) {
            res.status = 204;   // nothing to answer
            return;
        }
        res.set_content(resp.dump(), "application/json");
    });

    srv->Options("/api", [](const httplib::Request& req, httplib::Response& res) {
        res.status = apply_cors(req, res) ? 204 : 403;
    });

    srv->Post("/api", [](const httplib::Request& req, httplib::Response& res) {
        if (!apply_cors(req, res)) {
            res.status = 403;
            res.set_content(json({{"ok", false}, {"error", "origin not allowed"}}).dump(),
                            "application/json");
            return;
        }
        if (!authorized(req)) {
            res.status = 401;
            res.set_content(json({{"ok", false}, {"error", "unauthorized"}}).dump(),
                            "application/json");
            return;
        }
        json body = json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            res.set_content(json({{"ok", false}, {"error", "parse error"}}).dump(),
                            "application/json");
            return;
        }

        // let the ui batch a bunch of calls so opening a view is one round trip
        auto source = std::make_shared<infra::cancel_source_t>();
        json out;
        if (body.is_array()) {
            out = json::array();
            for (const auto& r : body)
                out.push_back(handle_api(r, source->token()));
        } else {
            out = handle_api(body, source->token());
        }
        res.set_content(out.dump(-1, ' ', false, json::error_handler_t::replace),
                        "application/json");
    });

    srv->Get("/mcp", [](const httplib::Request& req, httplib::Response& res) {
        // gate the stream too or it leaks to anyone when a token is set
        if (!authorized(req)) {
            res.status = 401;
            res.set_content(json({{"error", "unauthorized"}}).dump(), "application/json");
            return;
        }
        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        // keepalive pings run on this worker thread, never the shared work queue
        res.set_content_provider(
            "text/event-stream",
            [](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0) {
                    return sink.write("event: endpoint\ndata: /mcp\n\n", 28);
                }
                // poll in small chunks so shutdown doesnt sit on a long sleep
                for (int i = 0; i < 150 && g_running.load(); ++i)
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                if (!g_running.load()) return false;
                return sink.write(": keepalive\n\n", 13);
            });
    });

    // event stream for the ui, way better than polling every bit of state 60 times a second
    srv->Get("/events", [](const httplib::Request& req, httplib::Response& res) {
        if (!apply_cors(req, res)) {
            res.status = 403;
            return;
        }
        // eventsource cant send headers so this one route takes the token as a query param
        const bool token_param =
            !g_cfg.token.empty() && req.get_param_value("token") == g_cfg.token;
        if (!authorized(req) && !token_param) {
            res.status = 401;
            res.set_content(json({{"ok", false}, {"error", "unauthorized"}}).dump(),
                            "application/json");
            return;
        }

        res.set_header("Content-Type", "text/event-stream");
        res.set_header("Cache-Control", "no-cache");
        res.set_header("X-Accel-Buffering", "no");

        auto sub = infra::event_bus::subscribe();
        // cursor for the client so a reconnect can pull the output it missed
        const uint64_t revision = infra::event_bus::output_revision();

        res.set_content_provider(
            "text/event-stream",
            [sub, revision](size_t offset, httplib::DataSink& sink) -> bool {
                if (offset == 0) {
                    const std::string hello =
                        "event: hello\ndata: " +
                        json({{"output_revision", revision}}).dump() + "\n\n";
                    return sink.write(hello.data(), hello.size());
                }
                if (!g_running.load()) return false;
                std::string batch;
                if (!sub->wait(batch, 1000)) return false;   // bus closed
                if (batch.empty()) {
                    if (!g_running.load()) return false;
                    static constexpr char kPing[] = ": keepalive\n\n";
                    return sink.write(kPing, sizeof(kPing) - 1);
                }
                return sink.write(batch.data(), batch.size());
            });
    });

    if (cfg.port == 0) {
        const int actual = srv->bind_to_any_port("127.0.0.1");
        if (actual <= 0) return false;
        g_port = static_cast<uint16_t>(actual);
    } else {
        if (!srv->bind_to_port("127.0.0.1", cfg.port)) return false;
        g_port = cfg.port;
    }
    g_srv = std::move(srv);
    g_running = true;
    g_thread = std::make_unique<std::thread>([] {
        g_srv->listen_after_bind();
    });
    g_srv->wait_until_ready();
    if (!g_srv->is_running()) {
        g_running = false;
        if (g_thread->joinable()) g_thread->join();
        g_thread.reset();
        g_srv.reset();
        g_port = 0;
        return false;
    }
    return true;
}

void stop() {
    if (!g_running.exchange(false)) return;
    // nudge the parked event streams so the join below is instant
    infra::event_bus::publish("server.stopping", nlohmann::json::object());
    std::vector<std::shared_ptr<infra::cancel_source_t>> active;
    {
        std::lock_guard lk(g_active_mu);
        for (const auto& [key, source] : g_active) {
            (void)key;
            active.push_back(source);
        }
    }
    for (const auto& source : active) source->request();
    if (g_srv) g_srv->stop();
    if (g_thread && g_thread->joinable()) g_thread->join();
    g_thread.reset();
    g_srv.reset();
    g_port = 0;
    {
        std::lock_guard lk(g_active_mu);
        g_active.clear();
    }
    shutdown_tools();
}

bool running() { return g_running; }
uint16_t port() { return g_port; }

} // namespace slop::core::mcp
