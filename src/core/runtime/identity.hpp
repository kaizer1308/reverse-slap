#pragma once

// src/core/runtime/identity.hpp
// Process identity, who we are, what we can do, integrity level

#include <cstdint>
#include <string>

namespace slop::core::runtime::identity {

struct self_info_t {
    uint32_t    pid         = 0;
    uint32_t    session_id  = 0;
    bool        elevated    = false;
    bool        debug_priv  = false;
    std::string exe_path;
    std::string user_name;
    std::string computer_name;
};

struct integrity_t {
    uint32_t    level       = 0;   // SECURITY_MANDATORY_*_RID
    std::string label;             // "Medium", "High", "System"
};

// Capture current process identity. Call once at startup
self_info_t capture();

// Validate runtime environment (returns true if usable)
bool validate(const self_info_t& info);

} // namespace slop::core::runtime::identity
