#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/backend_kernel.hpp"

namespace slop::core::runtime {

namespace {

backend_usermode_t g_user{};
backend_kernel_t   g_kernel{};
backend_t*         g_active = nullptr;

backend_pref_t     g_pref = backend_pref_t::auto_detect;
bool               g_initialized = false;

void apply_preference() {
    switch (g_pref) {
    case backend_pref_t::force_user:
        g_kernel.disconnect();
        g_active = &g_user;
        break;

    case backend_pref_t::force_kernel:
        g_active = g_kernel.connect() ? static_cast<backend_t*>(&g_kernel)
                                      : static_cast<backend_t*>(&g_user);
        break;

    case backend_pref_t::auto_detect:
    default:
        // Probe the driver; fall back silently
        if (!g_kernel.connect()) g_kernel.disconnect();
        g_active = g_kernel.connect() ? static_cast<backend_t*>(&g_kernel)
                                      : static_cast<backend_t*>(&g_user);
        break;
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

} // namespace slop::core::runtime
