// src/core/emu/winapi.cpp

#include "core/emu/winapi.hpp"

#include <algorithm>
#include <cstring>
#include <iterator>
#include <string>
#include <type_traits>
#include <vector>

namespace slop::core::emu {

namespace {

constexpr size_t   kPage     = 0x1000;
// Scans and compares stop here. Copies and fills are not capped: they walk
// until they are done or fault, like the real routine handed a bad length
constexpr uint64_t kMaxBytes = 64ull << 20;

constexpr uint32_t kErrorModNotFound   = 126;
constexpr uint32_t kTlsOutOfIndexes    = 0xFFFFFFFFu;
constexpr uint64_t kTebLastError       = 0x68;
constexpr uint64_t kTebProcessId       = 0x40;
constexpr uint64_t kTebThreadId        = 0x48;
constexpr uint64_t kTebPeb             = 0x60;
constexpr uint64_t kTebTlsSlots        = 0x1480;

// reads / writes of fixed-size values; a failed read leaves 0

template <typename T>
T rd(api_host_t& h, uint64_t addr) {
    T v{};
    h.read(addr, &v, sizeof(v));
    return v;
}

template <typename T>
bool wr(api_host_t& h, uint64_t addr, T v) {
    return h.write(addr, &v, sizeof(v));
}

// TEB fields; a run without a thread block (gs_base 0) has none
template <typename T>
T teb_rd(api_host_t& h, uint64_t off) {
    const uint64_t teb = h.gs_base();
    return teb ? rd<T>(h, teb + off) : T{};
}

template <typename T>
bool teb_wr(api_host_t& h, uint64_t off, T v) {
    const uint64_t teb = h.gs_base();
    return teb && wr<T>(h, teb + off, v);
}

void set_last_error(api_host_t& h, uint32_t code) {
    teb_wr<uint32_t>(h, kTebLastError, code);
}

// Length in units of `unit` bytes up to the terminator, scanning a page at a
// time so the walk faults exactly where a real one would. false on a fault
// or when no terminator shows up inside the cap
bool scan_len(api_host_t& h, uint64_t s, size_t unit, uint64_t max_units, uint64_t* out) {
    uint8_t buf[kPage];
    uint64_t n = 0;
    while (n < max_units) {
        const uint64_t at = s + n * unit;
        size_t chunk = kPage - static_cast<size_t>(at & (kPage - 1));
        chunk -= chunk % unit;
        if (chunk == 0) chunk = unit;                       // unit straddles the page end
        chunk = static_cast<size_t>(std::min<uint64_t>(chunk, (max_units - n) * unit));
        if (!h.read(at, buf, chunk)) return false;
        for (size_t i = 0; i + unit <= chunk; i += unit) {
            bool zero = true;
            for (size_t b = 0; b < unit; ++b) zero = zero && buf[i + b] == 0;
            if (zero) { *out = n + i / unit; return true; }
        }
        n += chunk / unit;
    }
    *out = max_units;
    return true;   // strnlen-style: ran into the bound
}

bool str_len(api_host_t& h, uint64_t s, size_t unit, uint64_t* out) {
    return scan_len(h, s, unit, kMaxBytes / unit, out);
}

bool load(api_host_t& h, uint64_t addr, uint64_t len, std::vector<uint8_t>* out) {
    if (len > kMaxBytes) len = kMaxBytes;
    out->resize(static_cast<size_t>(len));
    return len == 0 || h.read(addr, out->data(), out->size());
}

// An int comes back in eax; writing eax clears the upper half of rax
uint64_t int_result(int v) { return static_cast<uint32_t>(v); }

// memory

uint64_t m_memcpy(api_host_t& h) {
    const uint64_t dst = h.arg(0), src = h.arg(1), n = h.arg(2);
    h.copy(dst, src, static_cast<size_t>(n));
    h.taint_result(h.arg_tainted(0));
    return dst;
}

uint64_t m_memset(api_host_t& h) {
    const uint64_t dst = h.arg(0), n = h.arg(2);
    h.fill(dst, static_cast<uint8_t>(h.arg(1)), static_cast<size_t>(n), h.arg_tainted(1));
    h.taint_result(h.arg_tainted(0));
    return dst;
}

// memcpy_s / memmove_s (dst, dst_size, src, count)
uint64_t m_memcpy_s(api_host_t& h) {
    const uint64_t dst = h.arg(0), cap = h.arg(1), src = h.arg(2), n = h.arg(3);
    if (n == 0) return 0;
    if (!dst) return 22;                                   // EINVAL
    if (!src || cap < n) {
        h.fill(dst, 0, static_cast<size_t>(cap), false);
        return !src ? 22 : 34;                             // EINVAL : ERANGE
    }
    h.copy(dst, src, static_cast<size_t>(n));
    return 0;
}

uint64_t m_memcmp(api_host_t& h) {
    const uint64_t a = h.arg(0), b = h.arg(1), n = std::min(h.arg(2), kMaxBytes);
    std::vector<uint8_t> x, y;
    if (!load(h, a, n, &x) || !load(h, b, n, &y)) return 0;
    h.taint_result(h.tainted(a, x.size()) || h.tainted(b, y.size()));
    const int r = n ? std::memcmp(x.data(), y.data(), x.size()) : 0;
    return int_result(r < 0 ? -1 : r > 0 ? 1 : 0);
}

// RtlCompareMemory: count of leading bytes that match
uint64_t m_rtl_compare(api_host_t& h) {
    const uint64_t a = h.arg(0), b = h.arg(1), n = std::min(h.arg(2), kMaxBytes);
    std::vector<uint8_t> x, y;
    if (!load(h, a, n, &x) || !load(h, b, n, &y)) return 0;
    h.taint_result(h.tainted(a, x.size()) || h.tainted(b, y.size()));
    size_t i = 0;
    while (i < x.size() && x[i] == y[i]) ++i;
    return i;
}

uint64_t m_memchr(api_host_t& h) {
    const uint64_t s = h.arg(0), n = std::min(h.arg(2), kMaxBytes);
    std::vector<uint8_t> x;
    if (!load(h, s, n, &x)) return 0;
    h.taint_result(h.tainted(s, x.size()));
    const auto it = std::find(x.begin(), x.end(), static_cast<uint8_t>(h.arg(1)));
    return it == x.end() ? 0 : s + static_cast<uint64_t>(it - x.begin());
}

uint64_t m_rtl_zero(api_host_t& h) {        // (dst, len)
    h.fill(h.arg(0), 0, static_cast<size_t>(h.arg(1)), false);
    return 0;
}

uint64_t m_rtl_fill(api_host_t& h) {        // (dst, len, fill)
    h.fill(h.arg(0), static_cast<uint8_t>(h.arg(2)), static_cast<size_t>(h.arg(1)),
           h.arg_tainted(2));
    return 0;
}

// strings

template <size_t Unit>
uint64_t m_strlen(api_host_t& h) {
    uint64_t n = 0;
    if (!str_len(h, h.arg(0), Unit, &n)) return 0;
    h.taint_result(h.tainted(h.arg(0), static_cast<size_t>((n + 1) * Unit)));
    return n;
}

template <size_t Unit>
uint64_t m_strnlen(api_host_t& h) {
    uint64_t n = 0;
    if (!scan_len(h, h.arg(0), Unit, std::min(h.arg(1), kMaxBytes / Unit), &n)) return 0;
    h.taint_result(h.tainted(h.arg(0), static_cast<size_t>(n * Unit)));
    return n;
}

// lstrlen: NULL is 0, not a fault
template <size_t Unit>
uint64_t m_lstrlen(api_host_t& h) {
    return h.arg(0) ? m_strlen<Unit>(h) : 0;
}

template <typename Ch>
uint64_t read_unit(const std::vector<uint8_t>& b, size_t i) {
    Ch c{};
    std::memcpy(&c, b.data() + i * sizeof(Ch), sizeof(Ch));
    // strcmp compares as unsigned char, wcscmp as wchar_t (unsigned on Windows)
    return static_cast<uint64_t>(static_cast<std::make_unsigned_t<Ch>>(c));
}

// strcmp / strncmp / wcscmp / wcsncmp
template <typename Ch, bool Bounded>
uint64_t m_strcmp(api_host_t& h) {
    const size_t unit = sizeof(Ch);
    const uint64_t a = h.arg(0), b = h.arg(1);
    uint64_t bound = kMaxBytes / unit;
    if constexpr (Bounded) bound = std::min(h.arg(2), bound);
    uint64_t la = 0, lb = 0;
    if (!scan_len(h, a, unit, bound, &la) || !scan_len(h, b, unit, bound, &lb)) return 0;
    // compare through the shorter string's terminator, or up to the bound
    const uint64_t n = std::min(std::min(la, lb) + 1, bound);
    std::vector<uint8_t> x, y;
    if (!load(h, a, n * unit, &x) || !load(h, b, n * unit, &y)) return 0;
    h.taint_result(h.tainted(a, x.size()) || h.tainted(b, y.size()));
    for (size_t i = 0; i < static_cast<size_t>(n); ++i) {
        const uint64_t ca = read_unit<Ch>(x, i), cb = read_unit<Ch>(y, i);
        if (ca != cb) return int_result(ca < cb ? -1 : 1);
    }
    return 0;
}

// strcpy / wcscpy / lstrcpy: copy through the terminator, return dst
template <size_t Unit>
uint64_t m_strcpy(api_host_t& h) {
    const uint64_t dst = h.arg(0), src = h.arg(1);
    uint64_t n = 0;
    if (!str_len(h, src, Unit, &n)) return 0;
    h.copy(dst, src, static_cast<size_t>((n + 1) * Unit));
    h.taint_result(h.arg_tainted(0));
    return dst;
}

// strncpy / wcsncpy: exactly count units, zero padded, no terminator when
// the source is longer
template <size_t Unit>
uint64_t m_strncpy(api_host_t& h) {
    const uint64_t dst = h.arg(0), src = h.arg(1);
    const uint64_t count = std::min(h.arg(2), kMaxBytes / Unit);
    uint64_t n = 0;
    if (!scan_len(h, src, Unit, count, &n)) return 0;
    if (n && !h.copy(dst, src, static_cast<size_t>(n * Unit))) return 0;
    if (count > n)
        h.fill(dst + n * Unit, 0, static_cast<size_t>((count - n) * Unit), false);
    h.taint_result(h.arg_tainted(0));
    return dst;
}

// strcat / wcscat / lstrcat
template <size_t Unit>
uint64_t m_strcat(api_host_t& h) {
    const uint64_t dst = h.arg(0), src = h.arg(1);
    uint64_t ld = 0, ls = 0;
    if (!str_len(h, dst, Unit, &ld) || !str_len(h, src, Unit, &ls)) return 0;
    h.copy(dst + ld * Unit, src, static_cast<size_t>((ls + 1) * Unit));
    h.taint_result(h.arg_tainted(0));
    return dst;
}

// strcpy_s / wcscpy_s (dst, dst_units, src)
template <size_t Unit>
uint64_t m_strcpy_s(api_host_t& h) {
    const uint64_t dst = h.arg(0), cap = h.arg(1), src = h.arg(2);
    if (!dst || cap == 0) return 22;                       // EINVAL
    if (!src) { h.fill(dst, 0, Unit, false); return 22; }
    uint64_t n = 0;
    if (!scan_len(h, src, Unit, std::min(cap, kMaxBytes / Unit), &n)) return 0;
    if (n >= cap) { h.fill(dst, 0, Unit, false); return 34; }   // ERANGE
    h.copy(dst, src, static_cast<size_t>((n + 1) * Unit));
    return 0;
}

// strchr / strrchr / wcschr / wcsrchr; the terminator itself is findable
template <typename Ch, bool Last>
uint64_t m_strchr(api_host_t& h) {
    const size_t unit = sizeof(Ch);
    const uint64_t s = h.arg(0);
    const uint64_t want = static_cast<uint64_t>(
        static_cast<std::make_unsigned_t<Ch>>(static_cast<Ch>(h.arg(1))));
    uint64_t n = 0;
    std::vector<uint8_t> x;
    if (!str_len(h, s, unit, &n) || !load(h, s, (n + 1) * unit, &x)) return 0;
    h.taint_result(h.tainted(s, x.size()));
    uint64_t hit = 0;
    bool found = false;
    for (size_t i = 0; i <= static_cast<size_t>(n); ++i) {
        if (read_unit<Ch>(x, i) != want) continue;
        hit = s + i * unit;
        found = true;
        if constexpr (!Last) break;
    }
    return found ? hit : 0;
}

// strstr / wcsstr
template <typename Ch>
uint64_t m_strstr(api_host_t& h) {
    const size_t unit = sizeof(Ch);
    const uint64_t hay = h.arg(0), needle = h.arg(1);
    uint64_t lh = 0, ln = 0;
    std::vector<uint8_t> x, y;
    if (!str_len(h, hay, unit, &lh) || !str_len(h, needle, unit, &ln) ||
        !load(h, hay, lh * unit, &x) || !load(h, needle, ln * unit, &y))
        return 0;
    h.taint_result(h.tainted(hay, x.size()) || h.tainted(needle, y.size()));
    if (ln == 0) return hay;
    if (ln > lh) return 0;
    for (size_t i = 0; i + ln <= lh; ++i)
        if (std::memcmp(x.data() + i * unit, y.data(), static_cast<size_t>(ln * unit)) == 0)
            return hay + i * unit;
    return 0;
}

// heap

constexpr uint64_t kHeapZeroAlign = 16;

uint64_t m_malloc(api_host_t& h)   { return h.alloc(h.arg(0), kHeapZeroAlign); }

uint64_t m_calloc(api_host_t& h) {
    const uint64_t n = h.arg(0), size = h.arg(1);
    if (size && n > ~0ull / size) return 0;                // overflow
    return h.alloc(n * size, kHeapZeroAlign);
}

// Move a block into a fresh one of new_size; old == 0 is a plain alloc
uint64_t regrow(api_host_t& h, uint64_t old, uint64_t new_size) {
    const uint64_t fresh = h.alloc(new_size, kHeapZeroAlign);
    uint64_t old_size = 0;
    if (fresh && old && h.alloc_size(old, &old_size))
        h.copy(fresh, old, static_cast<size_t>(std::min(old_size, new_size)));
    return fresh;
}

uint64_t m_realloc(api_host_t& h) {
    if (h.arg(0) && h.arg(1) == 0) return 0;               // realloc(p, 0) frees
    return regrow(h, h.arg(0), h.arg(1));
}

uint64_t m_free(api_host_t&)       { return 0; }

uint64_t m_msize(api_host_t& h) {
    uint64_t size = 0;
    return h.alloc_size(h.arg(0), &size) ? size : ~0ull;
}

uint64_t m_aligned_malloc(api_host_t& h) {                 // (size, alignment)
    const uint64_t align = h.arg(1);
    if (align == 0 || (align & (align - 1)) || align > (1u << 20)) return 0;
    return h.alloc(h.arg(0), std::max(align, kHeapZeroAlign));
}

uint64_t m_get_process_heap(api_host_t& h) { return h.heap_handle(); }
uint64_t m_heap_alloc(api_host_t& h)       { return h.alloc(h.arg(2), kHeapZeroAlign); }     // (heap, flags, size)
uint64_t m_heap_realloc(api_host_t& h)     { return regrow(h, h.arg(2), h.arg(3)); }        // (heap, flags, ptr, size)
uint64_t m_heap_size(api_host_t& h) {                                                       // (heap, flags, ptr)
    uint64_t size = 0;
    return h.alloc_size(h.arg(2), &size) ? size : ~0ull;
}
uint64_t m_true(api_host_t&)  { return 1; }
uint64_t m_zero(api_host_t&)  { return 0; }

// LocalAlloc / GlobalAlloc (flags, size): fixed memory, the handle is the pointer
uint64_t m_local_alloc(api_host_t& h)   { return h.alloc(h.arg(1), kHeapZeroAlign); }
uint64_t m_local_realloc(api_host_t& h) { return regrow(h, h.arg(0), h.arg(1)); }           // (mem, size, flags)
uint64_t m_identity(api_host_t& h)      { return h.arg(0); }

// VirtualAlloc (addr, size, type, protect) / VirtualAllocEx (process, ...)
uint64_t virtual_alloc(api_host_t& h, uint64_t addr, uint64_t size) {
    if (size == 0) return 0;
    if (addr == 0) return h.alloc((size + kPage - 1) & ~(kPage - 1), 0x10000);
    const uint64_t base = addr & ~(kPage - 1);
    return h.map_fixed(base, size + (addr - base)) ? base : 0;
}
uint64_t m_virtual_alloc(api_host_t& h)    { return virtual_alloc(h, h.arg(0), h.arg(1)); }
uint64_t m_virtual_alloc_ex(api_host_t& h) {
    if (h.arg(0) != ~0ull) return 0;                       // only the current process
    return virtual_alloc(h, h.arg(1), h.arg(2));
}

// VirtualProtect (addr, size, new, *old): every page is rwx here
uint64_t m_virtual_protect(api_host_t& h) {
    if (h.arg(3) && !wr<uint32_t>(h, h.arg(3), 0x40)) return 0;   // PAGE_EXECUTE_READWRITE
    return 1;
}

// kernel pools: (type, size[, tag]) and ExAllocatePool2/3 (flags, size, tag)
uint64_t m_pool_alloc(api_host_t& h) { return h.alloc(h.arg(1), kHeapZeroAlign); }

// TEB-backed state

uint64_t m_get_last_error(api_host_t& h) { return teb_rd<uint32_t>(h, kTebLastError); }
uint64_t m_set_last_error(api_host_t& h) {
    set_last_error(h, static_cast<uint32_t>(h.arg(0)));
    return 0;
}
uint64_t m_current_pid(api_host_t& h) { return teb_rd<uint32_t>(h, kTebProcessId); }
uint64_t m_current_tid(api_host_t& h) { return teb_rd<uint32_t>(h, kTebThreadId); }
uint64_t m_current_process(api_host_t&) { return ~0ull; }        // (HANDLE)-1
uint64_t m_current_thread(api_host_t&)  { return ~0ull - 1; }    // (HANDLE)-2

uint64_t m_is_debugger_present(api_host_t& h) {
    const uint64_t peb = teb_rd<uint64_t>(h, kTebPeb);
    return peb ? rd<uint8_t>(h, peb + 2) : 0;                     // PEB.BeingDebugged
}
uint64_t m_check_remote_debugger(api_host_t& h) {                 // (process, *present)
    return wr<uint32_t>(h, h.arg(1), 0) ? 1 : 0;
}

uint64_t m_tls_alloc(api_host_t& h) {
    const uint64_t i = h.tls_alloc();
    return i == ~0ull ? kTlsOutOfIndexes : i;
}
uint64_t m_tls_get(api_host_t& h) {
    const uint64_t i = h.arg(0);
    set_last_error(h, i < 64 ? 0 : 87);                           // ERROR_INVALID_PARAMETER
    return i < 64 ? teb_rd<uint64_t>(h, kTebTlsSlots + i * 8) : 0;
}
uint64_t m_tls_set(api_host_t& h) {
    const uint64_t i = h.arg(0);
    if (i >= 64) { set_last_error(h, 87); return 0; }
    return teb_wr<uint64_t>(h, kTebTlsSlots + i * 8, h.arg(1)) ? 1 : 0;
}
uint64_t m_fls_alloc(api_host_t& h) { return h.fls_alloc(); }
uint64_t m_fls_get(api_host_t& h)   { set_last_error(h, 0); return h.fls_get(h.arg(0)); }
uint64_t m_fls_set(api_host_t& h)   { h.fls_set(h.arg(0), h.arg(1)); return 1; }

// clock

uint64_t ticks_100ns(api_host_t& h) { return h.clock_ns() / 100; }
uint64_t m_tick_count(api_host_t& h)   { return static_cast<uint32_t>(h.clock_ns() / 1000000); }
uint64_t m_tick_count64(api_host_t& h) { return h.clock_ns() / 1000000; }
uint64_t m_qpc(api_host_t& h) {
    return wr<uint64_t>(h, h.arg(0), ticks_100ns(h)) ? 1 : 0;
}
uint64_t m_qpf(api_host_t& h) {
    return wr<uint64_t>(h, h.arg(0), kQpcFrequency) ? 1 : 0;
}
uint64_t file_time(api_host_t& h) {
    return kBootFileTime + (h.clock_ns() - kBootUptimeNs) / 100;
}
uint64_t m_system_time_as_file_time(api_host_t& h) {
    wr<uint64_t>(h, h.arg(0), file_time(h));
    return 0;
}
uint64_t m_sleep(api_host_t& h) {
    const uint64_t ms = static_cast<uint32_t>(h.arg(0));
    if (ms != 0xFFFFFFFFu) h.sleep_ns(ms * 1000000);              // INFINITE: nothing to wait out
    return 0;
}
// time / _time64 (*out): seconds since 1970
uint64_t m_time64(api_host_t& h) {
    const uint64_t secs = (file_time(h) - kUnixEpochDelta) / 10000000;
    if (h.arg(0)) wr<uint64_t>(h, h.arg(0), secs);
    return secs;
}
// KeQueryPerformanceCounter (*frequency) returns the counter
uint64_t m_ke_qpc(api_host_t& h) {
    if (h.arg(0)) wr<uint64_t>(h, h.arg(0), kQpcFrequency);
    return ticks_100ns(h);
}

// process environment

uint64_t m_get_module_handle(api_host_t& h) {
    if (h.arg(0) == 0) return h.image_base();
    set_last_error(h, kErrorModNotFound);          // no other module is loaded
    return 0;
}
// GetModuleHandleEx (flags, name, *module)
uint64_t m_get_module_handle_ex(api_host_t& h) {
    const bool self = h.arg(1) == 0;
    if (h.arg(2)) wr<uint64_t>(h, h.arg(2), self ? h.image_base() : 0);
    if (!self) set_last_error(h, kErrorModNotFound);
    return self ? 1 : 0;
}

uint64_t m_processor_feature(api_host_t& h) { return processor_feature(h.arg(0)) ? 1 : 0; }

// GetSystemInfo / GetNativeSystemInfo (*SYSTEM_INFO)
uint64_t m_system_info(api_host_t& h) {
    uint8_t si[48] = {};
    auto put = [&si](size_t off, uint64_t v, size_t n) { std::memcpy(si + off, &v, n); };
    put(0, 9, 2);                        // PROCESSOR_ARCHITECTURE_AMD64
    put(4, kPage, 4);                    // dwPageSize
    put(8, 0x10000, 8);                  // lpMinimumApplicationAddress
    put(16, 0x00007FFFFFFEFFFFull, 8);   // lpMaximumApplicationAddress
    put(24, 0xF, 8);                     // dwActiveProcessorMask
    put(32, 4, 4);                       // dwNumberOfProcessors
    put(36, 8664, 4);                    // dwProcessorType
    put(40, 0x10000, 4);                 // dwAllocationGranularity
    put(44, 6, 2);                       // wProcessorLevel
    put(46, 0x3C03, 2);                  // wProcessorRevision (model 60, stepping 3)
    h.write(h.arg(0), si, sizeof(si));
    return 0;
}

// critical sections: one thread, so a lock never blocks
uint64_t init_cs(api_host_t& h, uint64_t spin) {
    uint8_t cs[40] = {};
    const int32_t unlocked = -1;
    std::memcpy(cs + 8, &unlocked, 4);       // LockCount
    std::memcpy(cs + 32, &spin, 8);          // SpinCount
    h.write(h.arg(0), cs, sizeof(cs));
    return 1;
}
uint64_t m_init_cs(api_host_t& h)      { init_cs(h, 0); return 0; }
uint64_t m_init_cs_spin(api_host_t& h) { return init_cs(h, static_cast<uint32_t>(h.arg(1))); }
uint64_t m_init_ptr(api_host_t& h)     { wr<uint64_t>(h, h.arg(0), 0); return 0; }   // SRW lock, condvar
uint64_t m_init_slist(api_host_t& h) {
    const uint64_t zero[2] = {};
    h.write(h.arg(0), zero, sizeof(zero));
    return 0;
}

// never return

uint64_t m_exit0(api_host_t& h) { h.exit_process(h.arg(0)); return 0; }
uint64_t m_abort(api_host_t& h) { h.exit_process(3); return 0; }          // abort's exit code

// TerminateProcess / NtTerminateProcess: only the current process ends the run
uint64_t m_terminate_process(api_host_t& h) {
    if (h.arg(0) == ~0ull || h.arg(0) == 0) h.exit_process(h.arg(1));
    return 1;
}

uint64_t m_raise_exception(api_host_t& h) {
    h.raise(static_cast<uint32_t>(h.arg(0)), "raised");
    return 0;
}
// RtlRaiseException (*EXCEPTION_RECORD): the code is the first field
uint64_t m_rtl_raise_exception(api_host_t& h) {
    h.raise(rd<uint32_t>(h, h.arg(0)), "raised");
    return 0;
}
uint64_t m_cxx_throw(api_host_t& h) {
    h.raise(0xE06D7363u, "cxx_throw");                // MSVC C++ exception
    return 0;
}
uint64_t m_fail_fast(api_host_t& h) {
    h.raise(0xC0000409u, "fail_fast");                // STATUS_STACK_BUFFER_OVERRUN
    return 0;
}
uint64_t m_invalid_parameter(api_host_t& h) {
    h.raise(0xC0000417u, "invalid_c_runtime_parameter");
    return 0;
}
uint64_t m_bugcheck(api_host_t& h) {
    h.exit_process(h.arg(0));                         // the bug check code
    return 0;
}

struct entry_t {
    std::string_view name;
    api_model_fn     fn;
};

// sorted by name at first use; keep one line per import
const entry_t kModels[] = {
    // memory
    {"memcpy", m_memcpy}, {"memmove", m_memcpy}, {"memset", m_memset},
    {"memcmp", m_memcmp}, {"memchr", m_memchr},
    {"memcpy_s", m_memcpy_s}, {"memmove_s", m_memcpy_s},
    {"RtlMoveMemory", m_memcpy}, {"RtlCopyMemory", m_memcpy},
    {"RtlZeroMemory", m_rtl_zero}, {"RtlSecureZeroMemory", m_rtl_zero},
    {"RtlFillMemory", m_rtl_fill}, {"RtlCompareMemory", m_rtl_compare},
    // strings
    {"strlen", m_strlen<1>}, {"wcslen", m_strlen<2>},
    {"strnlen", m_strnlen<1>}, {"wcsnlen", m_strnlen<2>},
    {"lstrlenA", m_lstrlen<1>}, {"lstrlenW", m_lstrlen<2>},
    {"strcmp", m_strcmp<char, false>}, {"strncmp", m_strcmp<char, true>},
    {"wcscmp", m_strcmp<char16_t, false>}, {"wcsncmp", m_strcmp<char16_t, true>},
    {"strcpy", m_strcpy<1>}, {"wcscpy", m_strcpy<2>},
    {"lstrcpyA", m_strcpy<1>}, {"lstrcpyW", m_strcpy<2>},
    {"strncpy", m_strncpy<1>}, {"wcsncpy", m_strncpy<2>},
    {"strcat", m_strcat<1>}, {"wcscat", m_strcat<2>},
    {"lstrcatA", m_strcat<1>}, {"lstrcatW", m_strcat<2>},
    {"strcpy_s", m_strcpy_s<1>}, {"wcscpy_s", m_strcpy_s<2>},
    {"strchr", m_strchr<char, false>}, {"strrchr", m_strchr<char, true>},
    {"wcschr", m_strchr<char16_t, false>}, {"wcsrchr", m_strchr<char16_t, true>},
    {"strstr", m_strstr<char>}, {"wcsstr", m_strstr<char16_t>},
    // C heap
    {"malloc", m_malloc}, {"calloc", m_calloc}, {"realloc", m_realloc}, {"free", m_free},
    {"_malloc_base", m_malloc}, {"_calloc_base", m_calloc},
    {"_realloc_base", m_realloc}, {"_free_base", m_free},
    {"_msize", m_msize}, {"_aligned_malloc", m_aligned_malloc}, {"_aligned_free", m_free},
    {"??2@YAPEAX_K@Z", m_malloc},                          // operator new(size_t)
    {"??_U@YAPEAX_K@Z", m_malloc},                         // operator new[](size_t)
    {"??2@YAPEAX_KAEBUnothrow_t@std@@@Z", m_malloc},
    {"??_U@YAPEAX_KAEBUnothrow_t@std@@@Z", m_malloc},
    {"??3@YAXPEAX@Z", m_free}, {"??3@YAXPEAX_K@Z", m_free},     // operator delete
    {"??_V@YAXPEAX@Z", m_free}, {"??_V@YAXPEAX_K@Z", m_free},   // operator delete[]
    // Win32 heap and virtual memory
    {"GetProcessHeap", m_get_process_heap},
    {"HeapAlloc", m_heap_alloc}, {"RtlAllocateHeap", m_heap_alloc},
    {"HeapReAlloc", m_heap_realloc}, {"RtlReAllocateHeap", m_heap_realloc},
    {"HeapSize", m_heap_size}, {"RtlSizeHeap", m_heap_size},
    {"HeapFree", m_true}, {"RtlFreeHeap", m_true}, {"HeapValidate", m_true},
    {"LocalAlloc", m_local_alloc}, {"GlobalAlloc", m_local_alloc},
    {"LocalReAlloc", m_local_realloc}, {"GlobalReAlloc", m_local_realloc},
    {"LocalFree", m_zero}, {"GlobalFree", m_zero},
    {"LocalLock", m_identity}, {"GlobalLock", m_identity},
    {"LocalUnlock", m_true}, {"GlobalUnlock", m_true},
    {"VirtualAlloc", m_virtual_alloc}, {"VirtualAllocEx", m_virtual_alloc_ex},
    {"VirtualFree", m_true}, {"VirtualProtect", m_virtual_protect},
    {"CoTaskMemAlloc", m_malloc}, {"CoTaskMemFree", m_free},
    // kernel pools
    {"ExAllocatePool", m_pool_alloc}, {"ExAllocatePoolWithTag", m_pool_alloc},
    {"ExAllocatePool2", m_pool_alloc}, {"ExAllocatePool3", m_pool_alloc},
    {"ExAllocatePoolZero", m_pool_alloc}, {"ExAllocatePoolUninitialized", m_pool_alloc},
    {"ExAllocatePoolWithQuotaTag", m_pool_alloc},
    {"ExFreePool", m_free}, {"ExFreePoolWithTag", m_free},
    // TEB-backed state
    {"GetLastError", m_get_last_error}, {"RtlGetLastWin32Error", m_get_last_error},
    {"SetLastError", m_set_last_error}, {"RtlSetLastWin32Error", m_set_last_error},
    {"GetCurrentProcessId", m_current_pid}, {"GetCurrentThreadId", m_current_tid},
    {"GetCurrentProcess", m_current_process}, {"GetCurrentThread", m_current_thread},
    {"IsDebuggerPresent", m_is_debugger_present},
    {"CheckRemoteDebuggerPresent", m_check_remote_debugger},
    {"TlsAlloc", m_tls_alloc}, {"TlsGetValue", m_tls_get}, {"TlsSetValue", m_tls_set},
    {"TlsFree", m_true},
    {"FlsAlloc", m_fls_alloc}, {"FlsGetValue", m_fls_get}, {"FlsSetValue", m_fls_set},
    {"FlsFree", m_true},
    {"EncodePointer", m_identity}, {"DecodePointer", m_identity},
    {"RtlEncodePointer", m_identity}, {"RtlDecodePointer", m_identity},
    {"EncodeSystemPointer", m_identity}, {"DecodeSystemPointer", m_identity},
    // clock
    {"GetTickCount", m_tick_count}, {"GetTickCount64", m_tick_count64},
    {"timeGetTime", m_tick_count},
    {"QueryPerformanceCounter", m_qpc}, {"QueryPerformanceFrequency", m_qpf},
    {"RtlQueryPerformanceCounter", m_qpc}, {"RtlQueryPerformanceFrequency", m_qpf},
    {"GetSystemTimeAsFileTime", m_system_time_as_file_time},
    {"GetSystemTimePreciseAsFileTime", m_system_time_as_file_time},
    {"KeQuerySystemTimePrecise", m_system_time_as_file_time},
    {"Sleep", m_sleep}, {"SleepEx", m_sleep},
    {"_time64", m_time64}, {"time", m_time64},
    {"KeQueryPerformanceCounter", m_ke_qpc},
    // process environment
    {"GetModuleHandleA", m_get_module_handle}, {"GetModuleHandleW", m_get_module_handle},
    {"GetModuleHandleExA", m_get_module_handle_ex},
    {"GetModuleHandleExW", m_get_module_handle_ex},
    {"IsProcessorFeaturePresent", m_processor_feature},
    {"GetSystemInfo", m_system_info}, {"GetNativeSystemInfo", m_system_info},
    // locks, single threaded
    {"InitializeCriticalSection", m_init_cs},
    {"InitializeCriticalSectionAndSpinCount", m_init_cs_spin},
    {"InitializeCriticalSectionEx", m_init_cs_spin},
    {"EnterCriticalSection", m_zero}, {"LeaveCriticalSection", m_zero},
    {"DeleteCriticalSection", m_zero}, {"TryEnterCriticalSection", m_true},
    {"InitializeSRWLock", m_init_ptr}, {"InitializeConditionVariable", m_init_ptr},
    {"AcquireSRWLockExclusive", m_zero}, {"AcquireSRWLockShared", m_zero},
    {"ReleaseSRWLockExclusive", m_zero}, {"ReleaseSRWLockShared", m_zero},
    {"TryAcquireSRWLockExclusive", m_true}, {"TryAcquireSRWLockShared", m_true},
    {"InitializeSListHead", m_init_slist}, {"RtlInitializeSListHead", m_init_slist},
    // never return
    {"ExitProcess", m_exit0}, {"ExitThread", m_exit0},
    {"RtlExitUserProcess", m_exit0}, {"RtlExitUserThread", m_exit0},
    {"exit", m_exit0}, {"_exit", m_exit0}, {"_Exit", m_exit0}, {"quick_exit", m_exit0},
    {"FatalExit", m_exit0}, {"_amsg_exit", m_exit0},
    {"abort", m_abort}, {"terminate", m_abort}, {"?terminate@@YAXXZ", m_abort},
    {"__std_terminate", m_abort},
    {"TerminateProcess", m_terminate_process},
    {"NtTerminateProcess", m_terminate_process}, {"ZwTerminateProcess", m_terminate_process},
    {"RaiseException", m_raise_exception}, {"RtlRaiseException", m_rtl_raise_exception},
    {"_CxxThrowException", m_cxx_throw},
    {"?_Xlength_error@std@@YAXPEBD@Z", m_cxx_throw},
    {"?_Xout_of_range@std@@YAXPEBD@Z", m_cxx_throw},
    {"?_Xinvalid_argument@std@@YAXPEBD@Z", m_cxx_throw},
    {"?_Xoverflow_error@std@@YAXPEBD@Z", m_cxx_throw},
    {"?_Xruntime_error@std@@YAXPEBD@Z", m_cxx_throw},
    {"?_Xbad_alloc@std@@YAXXZ", m_cxx_throw},
    {"?_Xbad_function_call@std@@YAXXZ", m_cxx_throw},
    {"RaiseFailFastException", m_fail_fast},
    {"_invalid_parameter_noinfo_noreturn", m_invalid_parameter},
    {"_invoke_watson", m_invalid_parameter},
    {"KeBugCheck", m_bugcheck}, {"KeBugCheckEx", m_bugcheck},
};

} // namespace

api_model_fn find_api_model(std::string_view function) {
    static const std::vector<entry_t> sorted = [] {
        std::vector<entry_t> v(std::begin(kModels), std::end(kModels));
        std::sort(v.begin(), v.end(),
                  [](const entry_t& a, const entry_t& b) { return a.name < b.name; });
        return v;
    }();
    const auto it = std::lower_bound(
        sorted.begin(), sorted.end(), function,
        [](const entry_t& e, std::string_view name) { return e.name < name; });
    return it != sorted.end() && it->name == function ? it->fn : nullptr;
}

bool processor_feature(uint64_t feature) {
    switch (feature) {
    case 3:   // PF_MMX_INSTRUCTIONS_AVAILABLE
    case 6:   // PF_XMMI_INSTRUCTIONS_AVAILABLE (SSE)
    case 8:   // PF_RDTSC_INSTRUCTION_AVAILABLE
    case 9:   // PF_PAE_ENABLED
    case 10:  // PF_XMMI64_INSTRUCTIONS_AVAILABLE (SSE2)
    case 12:  // PF_NX_ENABLED
    case 13:  // PF_SSE3_INSTRUCTIONS_AVAILABLE
    case 14:  // PF_COMPARE_EXCHANGE128
    case 17:  // PF_XSAVE_ENABLED
    case 20:  // PF_SECOND_LEVEL_ADDRESS_TRANSLATION
    case 22:  // PF_RDWRFSGSBASE_AVAILABLE
    case 23:  // PF_FASTFAIL_AVAILABLE
    case 28:  // PF_RDRAND_INSTRUCTION_AVAILABLE
    case 32:  // PF_RDTSCP_INSTRUCTION_AVAILABLE
    case 36:  // PF_SSSE3_INSTRUCTIONS_AVAILABLE
    case 37:  // PF_SSE4_1_INSTRUCTIONS_AVAILABLE
    case 38:  // PF_SSE4_2_INSTRUCTIONS_AVAILABLE
        return true;
    default:  // AVX (39), AVX2 (40), AVX512F (41) and the ARM ones
        return false;
    }
}

} // namespace slop::core::emu
