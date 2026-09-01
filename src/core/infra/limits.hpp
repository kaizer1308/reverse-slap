#pragma once

// src/core/infra/limits.hpp
// all the caps in one place, tweak them but never blow past one quietly

#include <cstddef>
#include <cstdint>

namespace slop::core::infra::limits {

inline constexpr size_t   max_regions_enumerated    = 65536;
inline constexpr size_t   max_handles_enumerated    = 65536;
inline constexpr size_t   max_scan_hits             = 5'000'000;
inline constexpr uint64_t max_stash_bytes           = 1ull << 30;     // 1 GiB unknown-scan memory copy
inline constexpr size_t   max_hits_per_chunk        = 2'000'000;
inline constexpr size_t   scan_chunk_bytes          = 1u << 20;       // 1 MiB stride
inline constexpr size_t   refine_batch_bytes        = 256u << 10;     // 256 KiB
inline constexpr uint64_t max_region_scan_bytes     = 512ull << 20;   // 512 MiB
inline constexpr size_t   max_pointer_edges         = 40'000'000;     // ~640 MB @ 16 B
inline constexpr int      max_pointer_depth         = 7;
inline constexpr size_t   max_pointer_chains        = 100'000;
inline constexpr uint64_t max_snapshot_bytes        = 1ull << 30;     // 1 GiB
inline constexpr uint64_t max_snapshot_region_bytes = 256ull << 20;   // 256 MiB
inline constexpr size_t   max_snapshot_regions      = 4096;
inline constexpr size_t   max_diff_ranges           = 250'000;
inline constexpr size_t   max_aob_matches           = 100'000;
inline constexpr size_t   max_watch_entries         = 4096;
inline constexpr size_t   ui_inline_sort_rows       = 100'000;
inline constexpr size_t   diag_ring_capacity        = 8192;
inline constexpr size_t   scan_history_depth        = 10;
inline constexpr size_t   max_live_jobs             = 64;
inline constexpr size_t   pool_queue_cap            = 4096;
inline constexpr uint32_t pool_max_workers          = 32;

} // namespace slop::core::infra::limits
