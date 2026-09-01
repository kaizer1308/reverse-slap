#pragma once

// the scan engine port, every ce scan type, int and float widths with
// rounding modes, all width scans, fastscan and region preferences
// first scan stashes the memory for relational rescans then switches to
// per address re reads, regions split across worker threads
// reads ride the injected reader so no user mode handle touches the target

#include <atomic>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "core/infra/cancel.hpp"
#include "core/memory/reader.hpp"

namespace slop::core::memory {

// Widths (kept for parse/format/watchlist + result rows)

enum class value_width_t : uint8_t {
    i8, u8,
    i16, u16,
    i32, u32,
    i64, u64,
    f32, f64
};

size_t value_size(value_width_t w) noexcept;
bool   width_is_signed(value_width_t w) noexcept;
bool   width_is_float(value_width_t w) noexcept;

// CE scan option (TScanOption)

enum class scan_type_t : uint8_t {
    exact_value,
    between,           // value1 <= v <= value2
    bigger_than,
    smaller_than,
    unknown_initial,   // first scan only: record the whole region set
    increased,
    increased_by,      // value1 = delta
    decreased,
    decreased_by,
    increased_percent, // value1/value2 = pct window (value2 defaults to value1)
    decreased_percent,
    changed,
    unchanged
};

// CE float rounding (TRoundingType)

enum class rounding_t : uint8_t {
    exact,             // bit/value equality
    rounded,           // RoundTo(v, -accuracy) == RoundTo(value, -accuracy)
    truncated,         // value <= v < value + 10^-accuracy
    extreme            // value - 10^-accuracy <= v <= value + 10^-accuracy
};

// CE fastscan method (TFastScanMethod)

enum class fastscan_method_t : uint8_t {
    off,               // step 1 (every byte)
    alignment,         // step = fast_alignment (addr % N == 0)
    ends_with          // step = 16^fast_digits, addr & (step-1) == fast_tail
};

// CE region preference (Tscanregionpreference)

enum class region_pref_t : uint8_t { any, include, exclude };

// Regions

struct scan_region_t {
    uintptr_t base    = 0;
    size_t    size    = 0;
    uint32_t  protect = 0;   // Win32 PAGE_* flags
    uint32_t  type    = 0;   // MEM_PRIVATE / MEM_MAPPED / MEM_IMAGE
};

// CE region walk: drop guard/noaccess (and nocache/writecombine) regions and
// apply the tri-state writable/executable/copy-on-write + memory-type prefs
std::vector<scan_region_t> filter_regions(const std::vector<scan_region_t>& in,
                                          const struct scan_config_t& cfg);

// Config

struct scan_config_t {
    scan_type_t     type     = scan_type_t::exact_value;
    value_width_t   width    = value_width_t::u32;
    bool            scan_all_types = false;   // CE vtAll
    rounding_t      rounding = rounding_t::exact;

    double          value1 = 0;   // operand (or lower bound / delta / pct)
    double          value2 = 0;   // upper bound (between) / pct window end
    uint32_t        float_accuracy = 0;   // decimals derived from value text

    fastscan_method_t fast    = fastscan_method_t::off;
    uint32_t          fast_alignment = 4;   // alignment mode step
    uint32_t          fast_digits    = 0;   // ends_with: hex digit count
    uint64_t          fast_tail      = 0;   // ends_with: required tail value

    region_pref_t  writable     = region_pref_t::any;
    region_pref_t  executable   = region_pref_t::any;
    region_pref_t  copy_on_write= region_pref_t::any;
    bool           mem_private  = true;
    bool           mem_image    = true;
    bool           mem_mapped   = true;

    uintptr_t      begin = 0;      // optional [begin,end) clamp
    uintptr_t      end   = 0;

    size_t         max_results = 0;   // 0 -> infra::limits::max_scan_hits
    uint32_t       threads     = 0;   // 0 -> hardware concurrency
    size_t         chunk_bytes = 0;   // 0 -> infra::limits::scan_chunk_bytes
};

// Results

struct scan_result_t {
    uintptr_t     address = 0;
    uint64_t      bits    = 0;             // raw value in `matched` encoding
    value_width_t matched = value_width_t::u32; // type that hit (all-scans)
};

struct scan_stats_t {
    uint64_t regions         = 0;
    uint64_t regions_scanned = 0;
    uint64_t bytes_scanned   = 0;
    uint64_t slots_scanned   = 0;
    size_t   found           = 0;
    size_t   slots_tracked   = 0;   // unknown-initial stash size
    bool     truncated       = false;
    bool     cancelled       = false;
};

// Live progress (atomics, shared with worker threads)
struct scan_progress_t {
    std::atomic<uint64_t> bytes{0};
    std::atomic<uint64_t> found{0};
    std::atomic<uint64_t> regions_done{0};
    std::atomic<bool>     cancelled{false};

    void clear() noexcept {
        bytes.store(0, std::memory_order_relaxed);
        found.store(0, std::memory_order_relaxed);
        regions_done.store(0, std::memory_order_relaxed);
        cancelled.store(false, std::memory_order_relaxed);
    }
};

// CE previousMemoryBuffer entry: one copy of a successfully read run
struct region_copy_t {
    uintptr_t            base = 0;
    std::vector<uint8_t> bytes;
};

// Comparison kernel

// CE-port predicate. `curr` = freshly read bits, `prev` = stored bits
// (ignored for first-scan types). `w` selects the encoding
bool check_value(const scan_config_t& cfg, value_width_t w,
                 uint64_t curr, uint64_t prev) noexcept;

// Value text helpers (UI + tests)

bool        parse_value_text(value_width_t w, std::string_view text, uint64_t& out_bits);
std::string format_value_text(value_width_t w, uint64_t bits);
uint64_t    value_from_double(value_width_t w, double v);
double      value_to_double(value_width_t w, uint64_t bits);

// Count decimals in a value string (CE floataccuracy derivation); returns 0
// when the text has no fractional part (CE then uses +/-1 windows)
uint32_t    float_accuracy_from_text(std::string_view text) noexcept;

// The engine (TMemScan)

class memscan_t {
public:
    memscan_t() = default;
    ~memscan_t() = default;
    memscan_t(const memscan_t&)            = delete;
    memscan_t& operator=(const memscan_t&) = delete;

    // first scan walks the regions, relational types degrade to unknown
    // initial, the engine stashes a copy for the next relational scan
    bool first_scan(reader_t& r,
                    std::vector<scan_region_t> regions,
                    const scan_config_t& cfg,
                    const infra::cancel_token_t& tok,
                    std::string* err = nullptr);

    // next scan re walks the stash while its alive then switches to per
    // address re reads
    bool next_scan(reader_t& r,
                   const scan_config_t& cfg,
                   const infra::cancel_token_t& tok,
                   std::string* err = nullptr);

    void reset();

    const std::vector<scan_result_t>& results() const noexcept { return results_; }
    scan_stats_t                      stats()   const noexcept { return stats_; }
    const scan_progress_t&            progress() const noexcept { return progress_; }

    // Region scans keep no address rows (the stash is the result set) but
    // still count as "has results" so the UI offers a next scan
    bool has_results() const noexcept {
        return !results_.empty() || address_list_ || region_scan_active_;
    }
    bool region_scan_active() const noexcept { return region_scan_active_; }
    value_width_t last_width() const noexcept { return last_width_; }

private:
    std::vector<scan_result_t> results_;
    std::vector<region_copy_t> stash_;
    scan_stats_t               stats_{};
    scan_progress_t            progress_{};
    value_width_t              last_width_ = value_width_t::u32;
    bool                       region_scan_active_ = false;
    bool                       address_list_      = false; // results_ hold live addresses
};

} // namespace slop::core::memory
