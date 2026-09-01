#pragma once

// src/core/infra/clock.hpp
// tiny steady clock helpers

#include <chrono>
#include <cstdint>

namespace slop::core::infra {

inline int64_t steady_ms() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count();
}

inline int64_t wall_ms() noexcept {
    using namespace std::chrono;
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

} // namespace slop::core::infra
