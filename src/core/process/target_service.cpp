#include "core/process/target_service.hpp"

#include "core/runtime/backend_registry.hpp"

#include <algorithm>
#include <mutex>

namespace slop::core::process {

namespace {

// the session is replaced from mcp workers and read from the ui, every
// access takes the lock and hands out a reference. A published session never
// changes again, it is torn down when its last holder lets go
std::mutex g_session_mu;
runtime::session_ref g_session;

} // namespace

void target_init() {
    // Backend registry is initialised by the app boot; nothing else to stage
}

void target_shutdown() {
    target_detach();
}

bool target_attach(uint32_t pid) {
    std::lock_guard lk(g_session_mu);

    // let go of the old session before opening the new one, a reader still
    // holding it keeps a session that works until that reader is done
    g_session.reset();

    auto s = std::make_shared<runtime::session_t>();
    if (!s->open(pid)) return false;
    g_session = std::move(s);
    return true;
}

void target_detach() {
    std::lock_guard lk(g_session_mu);
    g_session.reset();
}

runtime::session_ref active_session() {
    std::lock_guard lk(g_session_mu);
    return g_session;
}

void target_tick() {
    // Heartbeat: drop the session if the target died. Work on a local copy  
    // the session may be replaced concurrently by an MCP attach
    runtime::session_ref s;
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
        if (g_session == s) g_session.reset();
    }
}

} // namespace slop::core::process
