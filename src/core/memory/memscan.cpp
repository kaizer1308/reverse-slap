// src/core/memory/memscan.cpp
// the scan engine, a behavioral port of cheat engines memscan (gpl 3.0 upstream)
// rounding windows, fastscan stepping and region preferences all follow upstream

#include "core/memory/memscan.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/read_util.hpp"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <mutex>
#include <thread>

namespace slop::core::memory {

// Width helpers

size_t value_size(value_width_t w) noexcept {
    switch (w) {
    case value_width_t::i8:
    case value_width_t::u8: return 1;
    case value_width_t::i16:
    case value_width_t::u16: return 2;
    case value_width_t::i32:
    case value_width_t::u32:
    case value_width_t::f32: return 4;
    case value_width_t::i64:
    case value_width_t::u64:
    case value_width_t::f64: return 8;
    }
    return 0;
}

bool width_is_signed(value_width_t w) noexcept {
    return w == value_width_t::i8 || w == value_width_t::i16 ||
           w == value_width_t::i32 || w == value_width_t::i64;
}

bool width_is_float(value_width_t w) noexcept {
    return w == value_width_t::f32 || w == value_width_t::f64;
}

// Value text helpers (UI + tests)

namespace {

int64_t sign_extend(uint64_t bits, value_width_t w) noexcept {
    switch (w) {
    case value_width_t::i8:  return static_cast<int64_t>(static_cast<int8_t>(bits));
    case value_width_t::i16: return static_cast<int64_t>(static_cast<int16_t>(bits));
    case value_width_t::i32: return static_cast<int64_t>(static_cast<int32_t>(bits));
    default:                 return static_cast<int64_t>(bits);
    }
}

template <typename T>
T bits_as(uint64_t bits) noexcept {
    T v;
    std::memcpy(&v, &bits, sizeof(T));
    return v;
}

uint64_t load_bits(const uint8_t* p, size_t n) noexcept {
    uint64_t bits = 0;
    std::memcpy(&bits, p, n);
    return bits;
}

// Delphi RoundTo(v, -digits): nearest multiple of 10^-digits, ties to even
// (matches FPC/Delphi banker's rounding)
double round_to(double v, uint32_t digits) noexcept {
    const double p = std::pow(10.0, static_cast<double>(digits));
    return std::nearbyint(v * p) / p;
}

// CE extreme/truncated window epsilon: 10^-accuracy, or 1 when the value
// text carried no decimals (configurescanroutine: maxsvalue:=svalue+1)
double round_eps(uint32_t accuracy) noexcept {
    return accuracy ? std::pow(10.0, -static_cast<double>(accuracy)) : 1.0;
}

} // namespace

uint64_t value_from_double(value_width_t w, double v) {
    uint64_t bits = 0;
    switch (w) {
    case value_width_t::f32: { const float f = static_cast<float>(v); std::memcpy(&bits, &f, 4); break; }
    case value_width_t::f64: { std::memcpy(&bits, &v, 8); break; }
    case value_width_t::i8:  bits = static_cast<uint64_t>(static_cast<uint8_t>(static_cast<int8_t>(v))); break;
    case value_width_t::u8:  bits = static_cast<uint64_t>(static_cast<uint8_t>(v)); break;
    case value_width_t::i16: bits = static_cast<uint64_t>(static_cast<uint16_t>(static_cast<int16_t>(v))); break;
    case value_width_t::u16: bits = static_cast<uint64_t>(static_cast<uint16_t>(v)); break;
    case value_width_t::i32: bits = static_cast<uint64_t>(static_cast<uint32_t>(static_cast<int32_t>(v))); break;
    case value_width_t::u32: bits = static_cast<uint64_t>(static_cast<uint32_t>(v)); break;
    case value_width_t::i64: bits = static_cast<uint64_t>(static_cast<int64_t>(v)); break;
    case value_width_t::u64: bits = static_cast<uint64_t>(v); break;
    }
    return bits;
}

double value_to_double(value_width_t w, uint64_t bits) {
    switch (w) {
    case value_width_t::f32: return static_cast<double>(bits_as<float>(bits));
    case value_width_t::f64: return bits_as<double>(bits);
    case value_width_t::i8:
    case value_width_t::i16:
    case value_width_t::i32:
    case value_width_t::i64: return static_cast<double>(sign_extend(bits, w));
    default:                 return static_cast<double>(bits);
    }
}

bool parse_value_text(value_width_t w, std::string_view text, uint64_t& out_bits) {
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    if (text.empty() || text.size() >= 64) return false;

    char buf[64]{};
    std::memcpy(buf, text.data(), text.size());

    char* endp = nullptr;

    if (width_is_float(w)) {
        const double v = std::strtod(buf, &endp);
        if (endp != buf + text.size()) return false;
        out_bits = value_from_double(w, v);
        return true;
    }

    errno = 0;
    if (width_is_signed(w)) {
        const long long v = std::strtoll(buf, &endp, 0);
        if (errno != 0 || endp != buf + text.size()) return false;
        out_bits = static_cast<uint64_t>(v);
    } else {
        if (buf[0] == '-') return false;
        const unsigned long long v = std::strtoull(buf, &endp, 0);
        if (errno != 0 || endp != buf + text.size()) return false;
        out_bits = static_cast<uint64_t>(v);
    }

    const size_t n = value_size(w);
    if (n < 8) {
        const uint64_t mask = (1ull << (n * 8)) - 1;
        out_bits &= mask;
    }
    return true;
}

std::string format_value_text(value_width_t w, uint64_t bits) {
    char buf[48]{};
    switch (w) {
    case value_width_t::i8:
    case value_width_t::i16:
    case value_width_t::i32:
    case value_width_t::i64:
        std::snprintf(buf, sizeof(buf), "%lld", static_cast<long long>(sign_extend(bits, w)));
        break;
    case value_width_t::u8:
    case value_width_t::u16:
    case value_width_t::u32:
    case value_width_t::u64:
        std::snprintf(buf, sizeof(buf), "%llu", static_cast<unsigned long long>(bits));
        break;
    case value_width_t::f32:
        std::snprintf(buf, sizeof(buf), "%.9g", static_cast<double>(bits_as<float>(bits)));
        break;
    case value_width_t::f64:
        std::snprintf(buf, sizeof(buf), "%.17g", bits_as<double>(bits));
        break;
    }
    return std::string(buf);
}

uint32_t float_accuracy_from_text(std::string_view text) noexcept {
    // CE floataccuracy derivation: digits after the decimal separator; 0
    // when absent or when the text uses exponent notation
    const size_t dot = text.find('.');
    if (dot == std::string_view::npos) return 0;
    const size_t e = text.find_first_of("eE");
    if (e != std::string_view::npos && e < dot) return 0;
    const size_t end = (e == std::string_view::npos) ? text.size() : e;
    if (end <= dot + 1) return 0;
    if (end - dot - 1 > 15) return 15;
    return static_cast<uint32_t>(end - dot - 1);
}

// Region filtering (TScanController walk)

namespace {

constexpr uint32_t kPageNoAccess      = 0x01;
constexpr uint32_t kPageGuard         = 0x100;
constexpr uint32_t kPageNoCache       = 0x200;
constexpr uint32_t kPageWriteCombine  = 0x400;
constexpr uint32_t kMemImage          = 0x1000000;
constexpr uint32_t kMemMapped         = 0x40000;
constexpr uint32_t kMemPrivate        = 0x20000;

bool pref_pass(region_pref_t pref, bool flag) noexcept {
    switch (pref) {
    case region_pref_t::any:     return true;
    case region_pref_t::include: return flag;
    case region_pref_t::exclude: return !flag;
    }
    return true;
}

} // namespace

std::vector<scan_region_t> filter_regions(const std::vector<scan_region_t>& in,
                                          const scan_config_t& cfg) {
    std::vector<scan_region_t> out;
    out.reserve(in.size());

    const uintptr_t begin = cfg.begin;
    const uintptr_t end   = cfg.end;

    for (const auto& reg : in) {
        if (reg.size == 0) continue;

        // Clip to the caller range first
        uintptr_t rbase = reg.base;
        uintptr_t rend  = reg.base + reg.size;
        if (end != 0) {
            if (rbase >= end) continue;
            if (rend > end) rend = end;
        }
        if (begin != 0) {
            if (rend <= begin) continue;
            if (rbase < begin) rbase = begin;
        }
        if (rend <= rbase) continue;

        const uint32_t prot = reg.protect;

        // CE validRegion core: no guard, no noaccess, no nocache/writecombine
        if (prot & kPageGuard)        continue;
        if (prot & kPageNoAccess)     continue;
        if (prot & kPageNoCache)      continue;
        if (prot & kPageWriteCombine) continue;

        // Memory-type checkboxes (scan_mem_private/image/mapped)
        const bool is_image   = (reg.type & kMemImage)   != 0;
        const bool is_mapped  = (reg.type & kMemMapped)  != 0;
        const bool is_private = (reg.type & kMemPrivate) != 0;
        if (is_image   && !cfg.mem_image)   continue;
        if (is_mapped  && !cfg.mem_mapped)  continue;
        if (is_private && !cfg.mem_private) continue;

        // Tri-state writable / executable / copy-on-write preferences
        const bool writable = (prot & 0x04 /*PAGE_READWRITE*/)        != 0 ||
                              (prot & 0x08 /*PAGE_WRITECOPY*/)         != 0 ||
                              (prot & 0x40 /*PAGE_EXECUTE_READWRITE*/) != 0 ||
                              (prot & 0x80 /*PAGE_EXECUTE_WRITECOPY*/) != 0;
        const bool executable = (prot & 0x10 /*PAGE_EXECUTE*/)      != 0 ||
                                (prot & 0x20 /*PAGE_EXECUTE_READ*/) != 0 ||
                                (prot & 0x40) != 0 || (prot & 0x80) != 0;
        const bool cow = (prot & 0x08) != 0 || (prot & 0x80) != 0;

        if (!pref_pass(cfg.writable, writable))         continue;
        if (!pref_pass(cfg.executable, executable))     continue;
        if (!pref_pass(cfg.copy_on_write, cow))         continue;

        out.push_back({rbase, static_cast<size_t>(rend - rbase), prot, reg.type});
    }
    return out;
}

// Comparison kernel (TCheckRoutine family)

namespace {

bool is_relational(scan_type_t t) noexcept {
    switch (t) {
    case scan_type_t::unknown_initial:
    case scan_type_t::increased:
    case scan_type_t::increased_by:
    case scan_type_t::decreased:
    case scan_type_t::decreased_by:
    case scan_type_t::increased_percent:
    case scan_type_t::decreased_percent:
    case scan_type_t::changed:
    case scan_type_t::unchanged:
        return true;
    default:
        return false;
    }
}

template <typename F>
bool float_check(const scan_config_t& cfg, F curr, F prev) noexcept {
    // ce parses the operand into the scan types own precision so windows and
    // comparisons run in float space
    const F v1 = static_cast<F>(cfg.value1);
    const F v2 = static_cast<F>(cfg.value2);
    const F p  = prev;
    const uint32_t acc = cfg.float_accuracy;

    switch (cfg.type) {
    case scan_type_t::unknown_initial:
        return true;

    case scan_type_t::exact_value:
        switch (cfg.rounding) {
        case rounding_t::exact:
            return curr == v1;
        case rounding_t::rounded:
            return round_to(static_cast<double>(curr), acc) ==
                   round_to(static_cast<double>(v1), acc);
        case rounding_t::truncated: {
            const F hi = static_cast<F>(static_cast<double>(v1) + round_eps(acc));
            return curr >= v1 && curr < hi;
        }
        case rounding_t::extreme: {
            const F eps = static_cast<F>(round_eps(acc));
            return curr >= static_cast<F>(static_cast<double>(v1) - static_cast<double>(eps)) &&
                   curr <= static_cast<F>(static_cast<double>(v1) + static_cast<double>(eps));
        }
        }
        return false;

    case scan_type_t::between:
        return curr >= v1 && curr <= v2;
    case scan_type_t::bigger_than:
        return curr > v1;
    case scan_type_t::smaller_than:
        return curr < v1;

    case scan_type_t::increased:
        return curr > p;
    case scan_type_t::increased_by:
        return curr != p &&
               round_to(static_cast<double>(curr), acc) ==
                   round_to(static_cast<double>(p) + static_cast<double>(v1), acc);
    case scan_type_t::decreased:
        return curr < p;
    case scan_type_t::decreased_by:
        return curr != p &&
               round_to(static_cast<double>(curr), acc) ==
                   round_to(static_cast<double>(p) - static_cast<double>(v1), acc);

    case scan_type_t::increased_percent:
        return static_cast<double>(curr) >
                   static_cast<double>(p) + static_cast<double>(p) * cfg.value1 &&
               static_cast<double>(curr) <
                   static_cast<double>(p) + static_cast<double>(p) * cfg.value2;
    case scan_type_t::decreased_percent:
        return static_cast<double>(curr) >
                   static_cast<double>(p) - static_cast<double>(p) * cfg.value2 &&
               static_cast<double>(curr) <
                   static_cast<double>(p) - static_cast<double>(p) * cfg.value1;

    case scan_type_t::changed:
        return curr != p;
    case scan_type_t::unchanged:
        return curr == p;
    }
    return false;
}

bool int_check(const scan_config_t& cfg, value_width_t w,
               uint64_t curr, uint64_t prev) noexcept {
    if (cfg.type == scan_type_t::unknown_initial) return true;
    if (cfg.type == scan_type_t::changed)   return curr != prev;
    if (cfg.type == scan_type_t::unchanged) return curr == prev;

    if (cfg.type == scan_type_t::increased_percent ||
        cfg.type == scan_type_t::decreased_percent)
        return false; // percentage scans are float-only (CE)

    // Widen to signed 64-bit space; zero-extend unsigned, sign-extend signed
    const int64_t sc = width_is_signed(w) ? sign_extend(curr, w)
                                          : static_cast<int64_t>(curr);
    const int64_t sp = width_is_signed(w) ? sign_extend(prev, w)
                                          : static_cast<int64_t>(prev);
    auto operand = [&](double v) -> int64_t {
        uint64_t bits = value_from_double(w, v);
        const size_t n = value_size(w);
        if (n < 8) bits &= (1ull << (n * 8)) - 1;
        return width_is_signed(w) ? sign_extend(bits, w)
                                  : static_cast<int64_t>(bits);
    };
    const int64_t s1 = operand(cfg.value1);
    const int64_t s2 = operand(cfg.value2);

    switch (cfg.type) {
    case scan_type_t::exact_value:  return sc == s1;
    case scan_type_t::between:      return sc >= s1 && sc <= s2;
    case scan_type_t::bigger_than:  return sc > s1;
    case scan_type_t::smaller_than: return sc < s1;
    case scan_type_t::increased:    return sc > sp;
    case scan_type_t::decreased:    return sc < sp;
    case scan_type_t::increased_by: return sc - sp == s1;
    case scan_type_t::decreased_by: return sp - sc == s1;
    default:                        return false;
    }
}

} // namespace

bool check_value(const scan_config_t& cfg, value_width_t w,
                 uint64_t curr, uint64_t prev) noexcept {
    if (width_is_float(w)) {
        if (w == value_width_t::f32)
            return float_check<float>(cfg, bits_as<float>(curr), bits_as<float>(prev));
        return float_check<double>(cfg, bits_as<double>(curr), bits_as<double>(prev));
    }
    return int_check(cfg, w, curr, prev);
}

// Fastscan stepping (FirstScanmem fastscan setup)

namespace {

struct fastscan_t {
    size_t    step    = 1;   // candidate stride in bytes
    uintptr_t require = 0;   // alignment mode: 0; ends_with: tail value
    uintptr_t mask    = 0;   // ends_with: step-1

    // First candidate offset >= base where the constraint holds
    size_t first_offset(uintptr_t base) const noexcept {
        if (step <= 1) return 0;
        if (mask == 0) { // alignment mode: addr % step == 0
            const uintptr_t r = base % step;
            return static_cast<size_t>(r ? step - r : 0);
        }
        // ends_with mode: (base + off) & mask == require
        const uintptr_t cur = base & mask;
        if (cur == require) return 0;
        const uintptr_t delta = (require - cur) & mask;
        return static_cast<size_t>(delta ? delta : step);
    }
};

fastscan_t make_fastscan(const scan_config_t& cfg) noexcept {
    fastscan_t fs;
    switch (cfg.fast) {
    case fastscan_method_t::off:
        break;
    case fastscan_method_t::alignment:
        fs.step = cfg.fast_alignment ? cfg.fast_alignment : 1;
        break;
    case fastscan_method_t::ends_with: {
        const uint32_t digits = std::min<uint32_t>(cfg.fast_digits, 8);
        uint64_t step = 1;
        for (uint32_t i = 0; i < digits; ++i) step *= 16;
        fs.step    = static_cast<size_t>(step);
        fs.mask    = fs.step - 1;
        fs.require = cfg.fast_tail & fs.mask;
        break;
    }
    }
    if (fs.step == 0) fs.step = 1;
    return fs;
}

// Widths participating in an all-scan, CE order (byte..double)
constexpr value_width_t kAllWidths[] = {
    value_width_t::u8, value_width_t::u16, value_width_t::u32,
    value_width_t::u64, value_width_t::f32, value_width_t::f64
};

// ce alignment gating, word needs even addresses and the bigger widths
// need 4 alignment under fastscan
bool width_gate(const fastscan_t& fs, value_width_t w, uintptr_t addr) noexcept {
    if (fs.step <= 1) return true;
    switch (w) {
    case value_width_t::u16:
    case value_width_t::i16:
        return (addr % 2) == 0;
    case value_width_t::u32:
    case value_width_t::i32:
    case value_width_t::u64:
    case value_width_t::i64:
    case value_width_t::f32:
    case value_width_t::f64:
        return (addr % 4) == 0;
    default:
        return true;
    }
}

// Worker-local accumulator; merged once at the end (zero contention)
struct worker_out_t {
    std::vector<scan_result_t> results;
    std::vector<region_copy_t> stash;
    uint64_t bytes_scanned   = 0;
    uint64_t slots_scanned   = 0;
    uint64_t regions_scanned = 0;
    size_t   slots_tracked   = 0;
    bool     truncated       = false;
};

// Run the value-scan kernel over one contiguous run of memory. `old` holds
// the previous contents (firstnext scans) or is null (first scan)
void scan_run(const scan_config_t& cfg, const fastscan_t& fs,
              uintptr_t base, const uint8_t* data, size_t len,
              const uint8_t* old, worker_out_t& out, scan_progress_t& prog) {
    const size_t slot = value_size(cfg.width);
    if (slot == 0) return;

    const bool all = cfg.scan_all_types;
    if (len < (all ? 1 : slot)) return;

    const size_t last_off = all ? len - 1 : len - slot;
    size_t off = fs.first_offset(base);

    for (; off <= last_off; off += fs.step) {
        const uintptr_t addr = base + off;

        if (all) {
            for (const value_width_t w : kAllWidths) {
                const size_t n = value_size(w);
                if (off + n > len) continue;
                if (!width_gate(fs, w, addr)) continue;
                const uint64_t curr = load_bits(data + off, n);
                const uint64_t prev = old ? load_bits(old + off, n) : 0;
                if (check_value(cfg, w, curr, prev)) {
                    out.results.push_back({addr, curr, w});
                    ++prog.found;
                }
            }
            ++out.slots_scanned;
        } else {
            if (off + slot > len) break;
            const uint64_t curr = load_bits(data + off, slot);
            const uint64_t prev = old ? load_bits(old + off, slot) : 0;
            ++out.slots_scanned;
            if (check_value(cfg, cfg.width, curr, prev)) {
                out.results.push_back({addr, curr, cfg.width});
                ++prog.found;
            }
        }
    }
}

void merge_workers(std::vector<worker_out_t>& outs,
                   size_t max_results,
                   std::vector<scan_result_t>& results_out,
                   scan_stats_t& st) {
    size_t total = 0;
    for (const auto& o : outs) total += o.results.size();
    results_out.clear();
    results_out.reserve(std::min(total, max_results));

    bool truncated = false;
    for (auto& o : outs) {
        truncated |= o.truncated;
        st.bytes_scanned   += o.bytes_scanned;
        st.slots_scanned   += o.slots_scanned;
        st.regions_scanned += o.regions_scanned;
        st.slots_tracked   += o.slots_tracked;
        for (auto& hit : o.results) {
            if (results_out.size() >= max_results) { truncated = true; break; }
            results_out.push_back(std::move(hit));
        }
    }
    std::sort(results_out.begin(), results_out.end(),
              [](const scan_result_t& a, const scan_result_t& b) {
                  if (a.address != b.address) return a.address < b.address;
                  return a.matched < b.matched;
              });
    st.truncated |= truncated;
    st.found = results_out.size();
}

unsigned worker_count(const scan_config_t& cfg) noexcept {
    unsigned n = cfg.threads ? cfg.threads : std::thread::hardware_concurrency();
    return std::max(1u, std::min(n, 64u));
}

// First scan (TScanController.firstScan thread fan-out)

// Region-scan walks stash readable runs into the worker copy. The value
// kernel only runs for address-list scans; unknown scans keep just bytes
void walk_region(reader_t& r, const scan_region_t& reg,
                 const scan_config_t& cfg, const fastscan_t& fs,
                 const infra::cancel_token_t& tok, bool stash_mode,
                 std::atomic<uint64_t>& stash_used, uint64_t stash_budget,
                 worker_out_t& out, scan_progress_t& prog) {
    const size_t chunk = cfg.chunk_bytes ? cfg.chunk_bytes
                                         : infra::limits::scan_chunk_bytes;

    auto sink = [&](uintptr_t run_addr, const uint8_t* data, size_t len) {
        out.bytes_scanned += len;
        prog.bytes += len;

        if (stash_mode) {
            // Atomic add-then-check: tiny over-admission is acceptable
            const uint64_t used = stash_used.fetch_add(len,
                                                       std::memory_order_relaxed) + len;
            if (used > stash_budget) {
                out.truncated = true;
                return;
            }
            region_copy_t rc;
            rc.base  = run_addr;
            rc.bytes.assign(data, data + len);
            out.stash.push_back(std::move(rc));
            out.slots_tracked += len;
            out.slots_scanned += len / value_size(cfg.width);
            return; // no address rows for region scans
        }

        scan_run(cfg, fs, run_addr, data, len, nullptr, out, prog);
    };

    uintptr_t cursor = reg.base;
    const uintptr_t end = reg.base + reg.size;
    while (cursor < end) {
        if (tok.cancelled()) break;
        const size_t want = static_cast<size_t>(std::min<uint64_t>(chunk, end - cursor));
        detail::resilient_read(r, cursor, want, 4096, tok, sink);
        if (out.truncated) break;
        cursor += want;
    }
    ++out.regions_scanned;
    prog.regions_done++;
}

} // namespace

// memscan_t

void memscan_t::reset() {
    results_.clear();
    results_.shrink_to_fit();
    stash_.clear();
    stash_.shrink_to_fit();
    stats_ = {};
    progress_.clear();
    region_scan_active_ = false;
    address_list_ = false;
    last_width_ = value_width_t::u32;
}

bool memscan_t::first_scan(reader_t& r,
                           std::vector<scan_region_t> regions,
                           const scan_config_t& cfg,
                           const infra::cancel_token_t& tok,
                           std::string* err) {
    (void)err;
    reset();
    last_width_ = cfg.width;

    const size_t max_results = cfg.max_results ? cfg.max_results
                                               : infra::limits::max_scan_hits;
    const fastscan_t fs = make_fastscan(cfg);

    regions = filter_regions(regions, cfg);
    stats_.regions = regions.size();
    if (regions.empty()) return true;

    // CE: relational types on a first scan degrade to an unknown scan
    scan_config_t run_cfg = cfg;
    if (is_relational(run_cfg.type)) run_cfg.type = scan_type_t::unknown_initial;
    const bool region_scan = run_cfg.type == scan_type_t::unknown_initial;
    if (!run_cfg.chunk_bytes) run_cfg.chunk_bytes = infra::limits::scan_chunk_bytes;

    const uint64_t stash_budget = region_scan ? infra::limits::max_stash_bytes : 0;

    const unsigned nw = std::max(1u, std::min(worker_count(run_cfg),
                                              static_cast<unsigned>(regions.size())));
    std::vector<worker_out_t> outs(nw);
    std::vector<std::thread>  pool;
    std::atomic<uint64_t>     stash_used{0};
    std::atomic<bool>         aborted{false};

    // Address-list scans cap rows per worker so one thread cannot hog the
    // whole budget (the merge still enforces the global cap)
    const size_t worker_cap = region_scan
        ? std::numeric_limits<size_t>::max()
        : max_results;

    for (unsigned i = 0; i < nw; ++i) {
        pool.emplace_back([&, i] {
            worker_out_t& out = outs[i];
            for (size_t k = i; k < regions.size(); k += nw) {
                if (aborted.load(std::memory_order_relaxed) || tok.cancelled()) break;
                walk_region(r, regions[k], run_cfg, fs, tok, region_scan,
                            stash_used, stash_budget, out, progress_);
                if (out.truncated) aborted.store(true, std::memory_order_relaxed);
                if (!region_scan && out.results.size() >= worker_cap) {
                    out.truncated = true;
                    aborted.store(true, std::memory_order_relaxed);
                    break;
                }
            }
        });
    }
    for (auto& t : pool) t.join();

    std::vector<scan_result_t> results;
    merge_workers(outs, region_scan ? 0 : max_results, results, stats_);
    if (region_scan) stats_.found = 0; // the stash is the result set

    if (region_scan) {
        size_t total = 0;
        for (const auto& o : outs) total += o.stash.size();
        stash_.reserve(total);
        for (auto& o : outs)
            for (auto& rc : o.stash) stash_.push_back(std::move(rc));
        std::sort(stash_.begin(), stash_.end(),
                  [](const region_copy_t& a, const region_copy_t& b) {
                      return a.base < b.base;
                  });
        region_scan_active_ = !stash_.empty();
        address_list_ = false;
        results_.clear();
        progress_.found.store(0, std::memory_order_relaxed);
    } else {
        results_ = std::move(results);
        address_list_ = !results_.empty();
        region_scan_active_ = false;
        progress_.found.store(results_.size(), std::memory_order_relaxed);
    }

    stats_.cancelled = tok.cancelled();
    return true;
}

bool memscan_t::next_scan(reader_t& r,
                          const scan_config_t& cfg,
                          const infra::cancel_token_t& tok,
                          std::string* err) {
    if (!region_scan_active_ && !address_list_) {
        if (err) *err = "no previous scan";
        return false;
    }
    if (cfg.type == scan_type_t::unknown_initial) return true; // passthrough

    const size_t max_results = cfg.max_results ? cfg.max_results
                                               : infra::limits::max_scan_hits;
    const fastscan_t fs = make_fastscan(cfg);

    scan_config_t run_cfg = cfg;
    if (!run_cfg.chunk_bytes) run_cfg.chunk_bytes = infra::limits::scan_chunk_bytes;

    scan_stats_t st{};
    st.regions = stats_.regions;

    std::vector<scan_result_t> out;

    if (region_scan_active_) {
        // FirstNextScan: re-read the stashed memory, compare old vs new per
        // slot, emit the first address list, then drop the stash
        const unsigned nw = std::max(1u, std::min(worker_count(run_cfg),
            static_cast<unsigned>(stash_.size() ? stash_.size() : 1)));
        std::vector<worker_out_t> outs(nw);
        std::vector<std::thread>  pool;
        std::atomic<bool>         aborted{false};

        for (unsigned i = 0; i < nw; ++i) {
            pool.emplace_back([&, i] {
                worker_out_t& out = outs[i];
                for (size_t k = i; k < stash_.size(); k += nw) {
                    if (aborted.load(std::memory_order_relaxed) || tok.cancelled()) break;
                    const region_copy_t& rc = stash_[k];

                    auto sink = [&](uintptr_t run_addr, const uint8_t* fresh, size_t len) {
                        const size_t old_off = static_cast<size_t>(run_addr - rc.base);
                        if (old_off > rc.bytes.size()) return;
                        const size_t comparable =
                            std::min(len, rc.bytes.size() - old_off);
                        if (comparable == 0) return;
                        out.bytes_scanned += comparable;
                        progress_.bytes += comparable;
                        scan_run(run_cfg, fs, run_addr, fresh, comparable,
                                 rc.bytes.data() + old_off, out, progress_);
                        if (out.results.size() >= max_results) {
                            out.truncated = true;
                        }
                    };

                    detail::resilient_read(r, rc.base, rc.bytes.size(), 4096,
                                           tok, sink);
                    if (out.truncated) {
                        aborted.store(true, std::memory_order_relaxed);
                        break;
                    }
                }
            });
        }
        for (auto& t : pool) t.join();

        merge_workers(outs, max_results, out, st);
        stash_.clear();
        stash_.shrink_to_fit();
        region_scan_active_ = false;
    } else {
        // NextNextScan: re-read each stored address, compare stored bits
        const std::vector<scan_result_t> prev = std::move(results_);
        const unsigned nw = worker_count(run_cfg);
        std::vector<worker_out_t> outs(nw);
        std::vector<std::thread>  pool;
        std::atomic<size_t>       next_item{0};

        for (unsigned i = 0; i < nw; ++i) {
            pool.emplace_back([&, i] {
                worker_out_t& out = outs[i];
                while (!tok.cancelled()) {
                    const size_t idx = next_item.fetch_add(64, std::memory_order_relaxed);
                    if (idx >= prev.size()) break;
                    const size_t n = std::min<size_t>(64, prev.size() - idx);
                    for (size_t k = 0; k < n; ++k) {
                        const scan_result_t& row = prev[idx + k];
                        const size_t vs = value_size(row.matched);
                        uint64_t bits = 0;
                        if (!r.read(row.address, &bits, vs)) continue; // freed
                        ++out.slots_scanned;
                        if (check_value(run_cfg, row.matched, bits, row.bits)) {
                            out.results.push_back({row.address, bits, row.matched});
                            if (out.results.size() >= max_results) {
                                out.truncated = true;
                                return;
                            }
                        }
                    }
                }
            });
        }
        for (auto& t : pool) t.join();

        merge_workers(outs, max_results, out, st);
    }

    results_ = std::move(out);
    address_list_ = !results_.empty();
    st.regions_scanned += stats_.regions_scanned;
    st.bytes_scanned   += stats_.bytes_scanned;
    st.slots_tracked   = stats_.slots_tracked;
    stats_ = st;
    last_width_ = cfg.width;
    progress_.found.store(results_.size(), std::memory_order_relaxed);
    stats_.cancelled = tok.cancelled();
    return true;
}

} // namespace slop::core::memory
