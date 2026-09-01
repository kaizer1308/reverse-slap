#pragma once

// aob scan ported from cheat engine, ?? and * wildcard bytes, nibble
// wildcards, compact hex, chunked reads that bisect holes

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory {

struct aob_pattern_t {
    std::vector<uint8_t> bytes;      // literal nibbles (wildcard nibbles hold 0)
    std::vector<uint8_t> nibble_mask; // bit per nibble: 1 = must match

    size_t size() const noexcept { return bytes.size(); }
    bool   has_wildcards() const noexcept;
};

// Compile a user pattern. On failure returns nullopt and fills err
std::optional<aob_pattern_t> aob_compile(std::string_view text, std::string& err);

// Match pattern AT the start of the buffer (anchored). Pattern longer than
// buffer never matches
bool aob_match(const aob_pattern_t& p, const uint8_t* data, size_t len) noexcept;

// Match pattern at ANY offset in the buffer (sliding search)
bool aob_contains(const aob_pattern_t& p, const uint8_t* data, size_t len) noexcept;

// Render pattern back to canonical spaced text ("AA ?? B?")
std::string aob_to_string(const aob_pattern_t& p);

// Format raw selection bytes as a copy-paste-ready pattern ("41 42 43")
std::string aob_from_bytes(const uint8_t* data, size_t len);

struct aob_scan_options_t {
    uint32_t alignment = 1;                    // fastscan: addr % N == 0
    size_t   max_results = 0;                  // 0 -> infra::limits::max_aob_matches
    size_t   chunk_bytes = 0;                  // 0 -> infra::limits::scan_chunk_bytes
    uint32_t threads     = 0;                  // 0 -> hardware concurrency
};

struct aob_stats_t {
    uint64_t bytes_scanned = 0;
    size_t   matches       = 0;
    bool     truncated     = false;
    bool     cancelled     = false;
};

// Scan the given regions (pre-filtered by the caller, typically
// filter_regions with the scan config's preferences)
std::vector<uintptr_t> aob_scan(reader_t& r,
                                const std::vector<scan_region_t>& regions,
                                const aob_pattern_t& p,
                                const aob_scan_options_t& opt,
                                const slop::core::infra::cancel_token_t& tok,
                                aob_stats_t* stats);

} // namespace slop::core::memory
