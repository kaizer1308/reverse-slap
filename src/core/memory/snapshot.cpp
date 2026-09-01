// src/core/memory/snapshot.cpp

#include "core/memory/snapshot.hpp"

#include "core/infra/limits.hpp"

#include <cstring>
#include <vector>

namespace slop::core::memory {

region_snapshot_t snapshot_capture(reader_t& r, uintptr_t base, size_t size,
                                   const slop::core::infra::cancel_token_t& tok,
                                   uint64_t max_bytes) {
    region_snapshot_t snap;
    snap.base = base;

    if (size == 0) { snap.complete = true; return snap; }

    bool clamped = false;
    if (static_cast<uint64_t>(size) > max_bytes) {
        size = static_cast<size_t>(max_bytes);
        clamped = true;
    }

    snap.bytes.assign(size, 0x00);
    snap.size = size;

    constexpr size_t kChunk = 1u << 20;
    bool holes = false;

    size_t cursor = 0;
    while (cursor < size) {
        if (tok.cancelled()) { snap.complete = false; return snap; }

        const size_t want = std::min(kChunk, size - cursor);

        if (r.read(base + cursor, snap.bytes.data() + cursor, want)) {
            cursor += want;
            continue;
        }

        // Bisect down to byte granularity, zero-filling unreadable leaves
        size_t seg_off = cursor;
        size_t seg_len = want;
        struct seg_t { size_t off; size_t len; };
        std::vector<seg_t> stack{ {seg_off, seg_len} };

        while (!stack.empty()) {
            if (tok.cancelled()) { snap.complete = false; return snap; }
            const seg_t s = stack.back();
            stack.pop_back();

            if (r.read(base + s.off, snap.bytes.data() + s.off, s.len)) continue;
            if (s.len == 1) { holes = true; continue; }
            const size_t half = s.len / 2;
            stack.push_back({s.off, half});
            stack.push_back({s.off + half, s.len - half});
        }
        cursor += want;
    }

    snap.complete = !holes && !clamped;
    return snap;
}

snapshot_diff_t snapshot_diff(const region_snapshot_t& a, const region_snapshot_t& b) {
    snapshot_diff_t d;
    if (a.base != b.base || a.size != b.size || a.bytes.size() != b.bytes.size())
        return d; // valid stays false

    d.valid = true;
    const size_t n = a.bytes.size();

    size_t i = 0;
    while (i < n) {
        if (a.bytes[i] == b.bytes[i]) { ++i; continue; }
        const size_t start = i;
        while (i < n && a.bytes[i] != b.bytes[i]) ++i;
        d.changed.push_back({start, i - start});
        if (d.changed.size() >= infra::limits::max_diff_ranges) break;
    }
    return d;
}

} // namespace slop::core::memory
