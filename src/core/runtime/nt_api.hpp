#pragma once

// src/core/runtime/nt_api.hpp
// Lazy-resolved NT API function pointers for low-level operations

#include <cstdint>

namespace slop::core::runtime::nt {

struct api_t {
    bool loaded = false;
};

const api_t& api();

} // namespace slop::core::runtime::nt
