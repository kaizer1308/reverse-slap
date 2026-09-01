#pragma once

// fault tolerant read helper that bisects unreadable ranges down to a leaf size

#include <cstddef>
#include <cstdint>
#include <functional>

#include "core/infra/cancel.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory::detail {

// read the range, unreadable parts get halved down to min leaf, every
// readable run goes to the sink in any order
void resilient_read(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                    const slop::core::infra::cancel_token_t& tok,
                    const std::function<void(uintptr_t, const uint8_t*, size_t)>& sink);

} // namespace slop::core::memory::detail
