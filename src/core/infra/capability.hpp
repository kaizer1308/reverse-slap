#pragma once

// src/core/infra/capability.hpp
// every ui action carries an enabled flag and a reason

namespace slop::core::infra {

struct command_state_t {
    bool        enabled         = false;
    const char* disabled_reason = nullptr;

    static constexpr command_state_t ok()              { return { true,  nullptr }; }
    static constexpr command_state_t no(const char* r) { return { false, r }; }
    constexpr explicit operator bool() const noexcept  { return enabled; }
};

} // namespace slop::core::infra
