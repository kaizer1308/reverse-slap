#include "core/runtime/nt_api.hpp"

namespace slop::core::runtime::nt {

namespace {

api_t g_api{};
bool  g_init = false;

void resolve() {
    if (g_init) return;
    g_init      = true;
    g_api.loaded = true;
    // TODO: resolve actual NT function pointers via GetProcAddress on ntdll.dll
}

} // namespace

const api_t& api() {
    resolve();
    return g_api;
}

} // namespace slop::core::runtime::nt
