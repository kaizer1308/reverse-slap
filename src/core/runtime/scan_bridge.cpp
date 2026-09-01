// src/core/runtime/scan_bridge.cpp

#include "core/runtime/scan_bridge.hpp"

#include "core/runtime/backend_registry.hpp"

#include <windows.h>

namespace slop::core::runtime {

std::vector<memory::scan_region_t> target_scan_regions(const target_handle_t& h) {
    std::vector<memory::scan_region_t> out;
    auto res = active().enum_regions(h);
    if (!res.ok) return out;
    out.reserve(res.items.size());
    for (const auto& r : res.items) {
        const bool commit = (r.state & MEM_COMMIT) != 0;
        if (!commit || r.size == 0) continue;
        if (r.protect & PAGE_GUARD) continue;
        out.push_back({r.base, r.size, r.protect, r.type});
    }
    return out;
}

} // namespace slop::core::runtime
