// src/core/memory/read_util.cpp

#include "core/memory/read_util.hpp"

#include <vector>

namespace slop::core::memory::detail {

void resilient_read(reader_t& r, uintptr_t addr, size_t len, size_t min_leaf,
                    const slop::core::infra::cancel_token_t& tok,
                    const std::function<void(uintptr_t, const uint8_t*, size_t)>& sink) {
    if (min_leaf == 0) min_leaf = 1;

    struct seg_t { uintptr_t addr; size_t len; };
    std::vector<seg_t> stack{ {addr, len} };

    while (!stack.empty()) {
        if (tok.cancelled()) return;
        const seg_t s = stack.back();
        stack.pop_back();

        std::vector<uint8_t> buf(s.len);
        if (r.read(s.addr, buf.data(), s.len)) {
            sink(s.addr, buf.data(), s.len);
            continue;
        }
        if (s.len <= min_leaf) continue; // unreadable leaf: contribute nothing
        const size_t half = std::max<size_t>((s.len / 2 / min_leaf) * min_leaf, min_leaf);
        stack.push_back({s.addr, half});
        stack.push_back({s.addr + half, s.len - half});
    }
}

} // namespace slop::core::memory::detail
