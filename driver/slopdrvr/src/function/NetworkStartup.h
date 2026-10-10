#pragma once

#include <stdint.h>

namespace net_capture {

constexpr bool startup_is_fatal(uint32_t status) noexcept {
    // STATUS_FWP_ALREADY_EXISTS leaves capture unavailable, not the core bridge.
    return (status & 0x80000000u) != 0 && status != 0xC0220009u;
}

} // namespace net_capture
