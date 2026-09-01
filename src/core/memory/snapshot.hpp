#pragma once

// src/core/memory/snapshot.hpp
// Region snapshots + byte-level diffing for state-change analysis

#include <cstdint>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory {

struct region_snapshot_t {
    uintptr_t              base     = 0;
    size_t                 size     = 0;
    std::vector<uint8_t>   bytes;
    bool                   complete = false;  // false if capped or partially unreadable
};

// Capture up to max_bytes of [base, base+size). Unreadable chunks are
// bisected; holes are zero-filled and marked via complete=false
region_snapshot_t snapshot_capture(reader_t& r, uintptr_t base, size_t size,
                                   const slop::core::infra::cancel_token_t& tok,
                                   uint64_t max_bytes);

struct snapshot_span_t {
    size_t offset;   // relative to region base
    size_t length;
};

struct snapshot_diff_t {
    std::vector<snapshot_span_t> changed;
    bool valid = false;   // false when inputs mismatch (base/size differ)
};

// Byte-precise diff with adjacent-byte coalescing into spans
// Capped at infra::limits::max_diff_ranges spans
snapshot_diff_t snapshot_diff(const region_snapshot_t& a, const region_snapshot_t& b);

} // namespace slop::core::memory
