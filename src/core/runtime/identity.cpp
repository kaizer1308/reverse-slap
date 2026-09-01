#include "core/runtime/identity.hpp"

namespace slop::core::runtime::identity {

self_info_t capture() {
    self_info_t info{};
    // TODO: populate from GetCurrentProcessId, GetModuleFileName, token queries
    return info;
}

bool validate(const self_info_t& /*info*/) {
    // TODO: check for minimum requirements (elevation, integrity, etc.)
    return true;
}

} // namespace slop::core::runtime::identity
