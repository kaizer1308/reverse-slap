// src/core/runtime/game_tools.hpp
// Stealth game analysis toolkit: pointer scanner, snapshot diff, AOB
// generator, struct dissector, encrypted pointer decoder, offset database,
// crypto constant scanner, RTTI/VMT walker. All reads go through the active
// backend (kernel phys path when winotify is loaded) — no handles in the
// target, no API calls in target context, no toolhelp snapshots.
#pragma once

#include "core/runtime/backend.hpp"
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace slop::core::runtime::game_tools {

// ── read helper: all scanning goes through this ──────────────────────────
// wraps backend_t::read_memory so every tool automatically rides the
// kernel phys path when the winotify transport is loaded
struct reader_t {
    backend_t*       be  = nullptr;
    target_handle_t  h   = {};
    bool read(std::uint64_t va, void* buf, std::size_t len) const {
        if (!be) return false;
        // chunk large reads: the winotify backend's MmCopyVirtualMemory
        // ioctl has a per-call size limit. chunk at 1MB to stay safe.
        constexpr std::size_t kChunk = 1024 * 1024;
        auto* dst = static_cast<std::uint8_t*>(buf);
        for (std::size_t off = 0; off < len; off += kChunk) {
            const std::size_t piece = (std::min)(kChunk, len - off);
            if (!be->read_memory(h, va + off, dst + off, piece).ok)
                return false;
        }
        return true;
    }
};

// ── 1. pointer scanner / chain walker ────────────────────────────────────

struct pointer_chain_t {
    std::uint64_t              base_module;
    std::string                module_name;
    std::vector<std::int64_t>  offsets;      // [base+off0] -> [+off1] -> ... -> target
    std::uint64_t              resolved;     // current resolved value
};

struct pointer_scan_config_t {
    std::uint64_t target_address  = 0;
    std::uint32_t max_depth       = 5;
    std::uint32_t max_offset      = 0x2000;
    std::uint32_t alignment       = 8;
    std::size_t   max_results     = 256;
};

std::vector<pointer_chain_t> scan_pointer_chains(
    const reader_t& r,
    const std::vector<module_info_t>& modules,
    const std::vector<region_info_t>& regions,
    const pointer_scan_config_t& cfg);

bool resolve_chain(const reader_t& r, const pointer_chain_t& chain,
                   std::uint64_t& out);

// ── 2. snapshot diff ─────────────────────────────────────────────────────

struct snapshot_t {
    std::uint64_t              base = 0;
    std::size_t                size = 0;
    std::vector<std::uint8_t>  data;
    int64_t                    timestamp_ms = 0;
};

struct diff_entry_t {
    std::uint64_t offset;
    std::uint8_t  old_val;
    std::uint8_t  new_val;
};

snapshot_t take_snapshot(const reader_t& r, std::uint64_t base,
                        std::size_t size);

std::vector<diff_entry_t> diff_snapshots(const snapshot_t& a,
                                         const snapshot_t& b);

// ── 3. AOB pattern generator ─────────────────────────────────────────────

struct aob_pattern_t {
    std::string label;
    std::string pattern;       // "48 8B 05 ?? ?? ?? ?? 48 85 C0"
    std::uint64_t origin_va;
    std::size_t   byte_count;
};

// generate a pattern from bytes at va with auto-wildcarding of relocs
aob_pattern_t generate_aob(const reader_t& r, std::uint64_t va,
                           std::size_t length,
                           const std::string& label = "");

// scan for an aob pattern in a region, return all hit addresses
std::vector<std::uint64_t> scan_aob(const reader_t& r,
                                     std::uint64_t base, std::size_t size,
                                     const std::string& pattern);

// ── 4. struct dissector ──────────────────────────────────────────────────

enum class field_type_t : uint8_t {
    u8, u16, u32, u64, i8, i16, i32, i64,
    f32, f64, ptr, vec3, str, pad
};

struct struct_field_t {
    std::string  name;
    field_type_t type    = field_type_t::u32;
    std::size_t  offset  = 0;
    std::size_t  size    = 0;     // auto-computed from type if 0
    std::size_t  count   = 1;    // array count
};

struct struct_def_t {
    std::string                  name;
    std::vector<struct_field_t>  fields;
    std::size_t                  total_size = 0;   // auto-computed
};

struct field_value_t {
    std::string  name;
    field_type_t type;
    std::string  display;          // formatted string
    std::uint64_t raw_u64 = 0;     // raw value for ptr/int fields
};

std::size_t field_type_size(field_type_t t);
std::size_t compute_struct_size(const struct_def_t& def);

std::vector<field_value_t> read_struct(const reader_t& r,
                                        std::uint64_t base,
                                        const struct_def_t& def);

// ── 5. encrypted pointer decoder ─────────────────────────────────────────

struct decoded_pointer_t {
    std::uint64_t raw;
    std::uint64_t decoded;
    std::string   method;          // "xor", "ror", "sub", "add"
    std::uint64_t key;
};

// try common transforms to decode a value that should point into [lo, hi]
decoded_pointer_t try_decode_pointer(std::uint64_t raw,
                                      std::uint64_t expected_lo,
                                      std::uint64_t expected_hi);

// scan a region for values that decode to valid pointers
std::vector<decoded_pointer_t> scan_encrypted_pointers(
    const reader_t& r, std::uint64_t base, std::size_t size,
    std::uint64_t expected_lo, std::uint64_t expected_hi,
    std::size_t max_results = 512);

// ── 6. offset database ──────────────────────────────────────────────────

struct offset_entry_t {
    std::string   label;
    std::string   module;        // e.g. "client.dll"
    std::int64_t  offset = 0;    // relative to module base
    std::string   signature;     // AOB that resolves to this offset
    std::string   comment;
    int64_t       updated_ms = 0;
};

class offset_db_t {
public:
    void add(offset_entry_t e);
    void remove(const std::string& label);
    const offset_entry_t* find(const std::string& label) const;
    const std::vector<offset_entry_t>& all() const { return entries_; }
    bool save(const std::string& path) const;
    bool load(const std::string& path);
    void clear() { entries_.clear(); }
private:
    std::vector<offset_entry_t> entries_;
};

// ── 7. crypto constant scanner ───────────────────────────────────────────

struct crypto_hit_t {
    std::uint64_t address;
    std::string   algorithm;      // "AES", "SHA-256", "CRC-32", etc.
    std::string   constant_name;  // "S-box", "round constant", etc.
};

std::vector<crypto_hit_t> scan_crypto_constants(
    const reader_t& r, std::uint64_t base, std::size_t size,
    std::size_t max_results = 256);

// ── 8. RTTI / VMT walker ─────────────────────────────────────────────────

struct rtti_class_t {
    std::uint64_t vtable_va;
    std::string   class_name;      // demangled
    std::string   raw_name;        // mangled
    std::vector<std::uint64_t> method_vas;
    std::vector<std::string>   base_classes;
};

std::vector<rtti_class_t> scan_rtti(const reader_t& r,
                                     std::uint64_t module_base,
                                     std::uint32_t module_size,
                                     std::size_t max_results = 1024);

// ── 9. binary map / heatmap ──────────────────────────────────────────────

struct map_block_t {
    std::uint64_t va;
    float         entropy;         // 0.0–8.0
    enum class kind_t : uint8_t {
        code, data, rdata, bss, rsrc, reloc, unknown
    } kind = kind_t::unknown;
};

std::vector<map_block_t> build_binary_map(
    const reader_t& r, std::uint64_t module_base,
    std::uint32_t module_size, std::size_t block_size = 256);

} // namespace slop::core::runtime::game_tools
