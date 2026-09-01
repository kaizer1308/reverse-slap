#include "core/process/target_service.hpp"

#include "core/runtime/backend_registry.hpp"

#include <algorithm>
#include <mutex>

namespace slop::core::process {

namespace {

// the session is mutated from mcp workers and read from the ui, every
// access takes the lock and hands out a copy
std::mutex g_session_mu;
std::shared_ptr<runtime::session_t> g_session;

} // namespace

void target_init() {
    // Backend registry is initialised by the app boot; nothing else to stage
}

void target_shutdown() {
    target_detach();
}

bool target_attach(uint32_t pid) {
    std::lock_guard lk(g_session_mu);

    // tear the old session down before opening the new one or its destructor
    // clears the new context
    if (g_session) {
        g_session->close();
        g_session.reset();
    }

    auto s = std::make_shared<runtime::session_t>();
    if (!s->open(pid)) return false;
    g_session = std::move(s);
    return true;
}

void target_detach() {
    std::lock_guard lk(g_session_mu);
    if (g_session) {
        g_session->close();
        g_session.reset();
    }
}

std::shared_ptr<runtime::session_t> active_session() {
    std::lock_guard lk(g_session_mu);
    return g_session;
}

void target_tick() {
    // Heartbeat: drop the session if the target died. Work on a local copy  
    // the session may be replaced concurrently by an MCP attach
    std::shared_ptr<runtime::session_t> s;
    {
        std::lock_guard lk(g_session_mu);
        s = g_session;
    }
    if (!s) return;

    auto procs = runtime::active().enum_processes();
    if (!procs.ok) return;
    const uint32_t pid = s->pid();
    const bool alive = std::any_of(procs.items.begin(), procs.items.end(),
                                   [pid](const runtime::process_info_t& p) { return p.pid == pid; });
    if (!alive) {
        std::lock_guard lk(g_session_mu);
        if (g_session == s) {
            g_session->close();
            g_session.reset();
        }
    }
}

} // namespace slop::core::process
