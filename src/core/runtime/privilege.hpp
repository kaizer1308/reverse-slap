#pragma once

// src/core/runtime/privilege.hpp
// Token privilege helpers (SeDebugPrivilege, etc.)

namespace slop::core::runtime::privilege {

bool enable_debug();
bool has_debug();

} // namespace slop::core::runtime::privilege
