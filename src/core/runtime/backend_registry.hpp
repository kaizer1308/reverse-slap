#pragma once

// src/core/runtime/backend_registry.hpp
// the backend registry picks the kernel path when the driver is around
// and hot swaps live so the badge is honest

#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

enum class backend_pref_t : uint8_t { auto_detect, force_user, force_kernel };

void             registry_init();
backend_t&       active();
backend_kind_t   active_kind() noexcept;
const char*      active_badge() noexcept;

// live switch, returns true when a kernel backend is active
bool set_backend_preference(backend_pref_t pref);
backend_pref_t current_preference() noexcept;

// disconnects the active backend and unloads the winotify driver when this
// process staged it, safe to call on every shutdown path
void registry_shutdown();

} // namespace slop::core::runtime
