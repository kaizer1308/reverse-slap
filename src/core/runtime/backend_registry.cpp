#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_winotify.hpp"
#include "core/runtime/ptwalk.hpp"
#include "core/runtime/xorstr.hpp"

#include <cstdio>
#include <windows.h>

namespace slop::core::runtime {

namespace {

backend_usermode_t g_user{};
backend_kernel_t   g_kernel{};
backend_winotify_t g_winotify{};
backend_t*         g_active = nullptr;

backend_pref_t     g_pref = backend_pref_t::force_kernel;
bool               g_initialized = false;
bool               g_stealth_applied = false;

void run_stealth_init(winotify::driver_t& dev) {
    if (g_stealth_applied) return;

    const std::uint32_t pid = GetCurrentProcessId();
    void* device_handle = dev.native_handle();

    // run full anti-cheat evasion chain. no log file — the results are
    // available via the driver.stealth_full MCP action if needed.
    ptwalk::run_full_stealth(dev, device_handle, pid);

    g_stealth_applied = true;
}

backend_t* connect_kernel() {
    if (g_winotify.connect()) {
        // run full anti-cheat evasion chain immediately after driver connect
        if (g_winotify.device())
            run_stealth_init(*g_winotify.device());
        return &g_winotify;
    }
    g_winotify.disconnect();
    if (g_kernel.connect()) return &g_kernel;
    g_kernel.disconnect();
    return nullptr;
}

void apply_preference() {
    switch (g_pref) {
    case backend_pref_t::force_user:
        g_kernel.disconnect();
        g_winotify.disconnect();
        g_active = &g_user;
        break;

    case backend_pref_t::force_kernel:
    case backend_pref_t::auto_detect:
    default: {
        backend_t* kernel = connect_kernel();
        g_active = kernel ? kernel : static_cast<backend_t*>(&g_user);
        break;
    }
    }
}

} // namespace

void registry_init() {
    apply_preference();
    g_initialized = true;
}

backend_t& active() {
    return g_active ? *g_active : static_cast<backend_t&>(g_user);
}

backend_kind_t active_kind() noexcept {
    return active().kind();
}

const char* active_badge() noexcept {
    return active().badge();
}

bool set_backend_preference(backend_pref_t pref) {
    g_pref = pref;
    if (g_initialized) apply_preference();
    return active_kind() == backend_kind_t::kernel;
}

backend_pref_t current_preference() noexcept {
    return g_pref;
}

void registry_shutdown() {
    // restore cloaked handle before unload so we can cleanly close it
    if (g_winotify.device() && g_winotify.device()->is_connected()) {
        ptwalk::uncloak_handle_table_entry(*g_winotify.device());
        g_winotify.device()->unload();
    }
    g_winotify.disconnect();
    g_kernel.disconnect();
    g_active = nullptr;
    g_initialized = false;
    g_stealth_applied = false;
}

} // namespace slop::core::runtime
