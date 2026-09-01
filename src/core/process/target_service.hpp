#pragma once

// src/core/process/target_service.hpp
// Central target lifecycle, attach, detach, session management

#include <cstdint>
#include <memory>

#include "core/runtime/backend.hpp"
#include "core/runtime/session.hpp"

namespace slop::core::process {

// Initialise the target service (call once at startup)
void target_init();

// Shut down, detaches active session if any
void target_shutdown();

// Attach to a process by PID. Returns true on success
bool target_attach(uint32_t pid);

// Detach from the current target
void target_detach();

// Returns the active session, or nullptr if none
std::shared_ptr<runtime::session_t> active_session();

// Per-frame tick, drives deferred operations, heartbeat checks
void target_tick();

} // namespace slop::core::process
