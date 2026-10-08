// src/core/runtime/game_tools.cpp
// implementation of the stealth game analysis toolkit. every read goes
// through reader_t which wraps backend_t::read_memory — the kernel phys
// path when winotify is loaded. zero handles, zero api calls in target.

#include "core/runtime/game_tools.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

namespace slop::core::runtime::game_tools {

// ── helpers ──────────────────────────────────────────────────────────────

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

static float shannon_entropy(const uint8_t* data, size_t len) {
    if (!len) return 0.0f;
    uint32_t freq[256] = {};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    float ent = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        float p = static_cast<float>(freq[i]) / static_cast<float>(len);
        ent -= p * std::log2f(p);
    }
    return ent;
}

// ── 1. pointer scanner ──────────────────────────────────────────────────

std::vector<pointer_chain_t> scan_pointer_chains(
    const reader_t& r,
    const std::vector<module_info_t>& modules,
    const std::vector<region_info_t>& regions,
    const pointer_scan_config_t& cfg)
{
    std::vector<pointer_chain_t> results;
    if (!cfg.target_address || !r.be) return results;

    // build a set of valid pointer targets: all committed private/image regions
    struct range_t { uint64_t lo, hi; };
    std::vector<range_t> valid;
    for (const auto& reg : regions) {
        if (reg.state != 0x1000) continue;   // MEM_COMMIT only
        valid.push_back({ reg.base, reg.base + reg.size });
    }
    std::sort(valid.begin(), valid.end(),
              [](const range_t& a, const range_t& b) { return a.lo < b.lo; });

    auto is_valid_ptr = [&](uint64_t v) -> bool {
        if (v < 0x10000 || v > 0x7FFFFFFFFFFF) return false;
        // binary search
        auto it = std::upper_bound(valid.begin(), valid.end(), v,
            [](uint64_t val, const range_t& rng) { return val < rng.lo; });
        if (it == valid.begin()) return false;
        --it;
        return v >= it->lo && v < it->hi;
    };

    // for each module, scan its writable sections for pointers that
    // eventually reach cfg.target_address within max_depth hops
    // depth-1 scan: find all pointers that directly contain target
    std::vector<uint64_t> depth1;

    for (const auto& reg : regions) {
        if (reg.state != 0x1000) continue;
        if (reg.size > 64 * 1024 * 1024) continue;   // skip huge regions

        const size_t chunk = std::min<size_t>(reg.size, 4 * 1024 * 1024);
        std::vector<uint8_t> buf(chunk);

        for (uint64_t off = 0; off < reg.size; off += chunk) {
            const size_t read_sz = std::min<size_t>(chunk, reg.size - off);
            if (!r.read(reg.base + off, buf.data(), read_sz)) continue;

            for (size_t i = 0; i + 8 <= read_sz; i += cfg.alignment) {
                uint64_t val = 0;
                std::memcpy(&val, buf.data() + i, 8);
                if (val >= cfg.target_address &&
                    val < cfg.target_address + cfg.max_offset) {
                    depth1.push_back(reg.base + off + i);
                    if (depth1.size() > 65536) goto depth1_done;
                }
            }
        }
    }
depth1_done:

    // for each depth-1 hit, check if it falls inside a known module
    for (uint64_t addr : depth1) {
        for (const auto& mod : modules) {
            if (addr >= mod.base && addr < mod.base + mod.size) {
                pointer_chain_t chain;
                chain.base_module = mod.base;
                chain.module_name = mod.name;
                chain.offsets.push_back(static_cast<int64_t>(addr - mod.base));
                chain.offsets.push_back(
                    static_cast<int64_t>(cfg.target_address -
                        (addr - (addr - mod.base))));

                // resolve to verify
                uint64_t resolved = 0;
                uint64_t ptr = 0;
                if (r.read(addr, &ptr, 8)) {
                    chain.resolved = ptr;
                    chain.offsets.clear();
                    chain.offsets.push_back(
                        static_cast<int64_t>(addr - mod.base));
                    int64_t final_off = static_cast<int64_t>(
                        cfg.target_address - ptr);
                    if (std::abs(final_off) <=
                        static_cast<int64_t>(cfg.max_offset)) {
                        chain.offsets.push_back(final_off);
                    }
                    results.push_back(chain);
                }
                if (results.size() >= cfg.max_results) return results;
                break;
            }
        }
    }

    // depth-2+: for each depth-1, scan for pointers to it
    if (cfg.max_depth >= 2 && results.size() < cfg.max_results) {
        std::vector<pointer_chain_t> deeper;
        for (const auto& d1 : depth1) {
            for (const auto& mod : modules) {
                const size_t scan_sz = std::min<size_t>(mod.size, 4 * 1024 * 1024);
                std::vector<uint8_t> buf(scan_sz);
                if (!r.read(mod.base, buf.data(), scan_sz)) continue;

                for (size_t i = 0; i + 8 <= scan_sz; i += cfg.alignment) {
                    uint64_t val = 0;
                    std::memcpy(&val, buf.data() + i, 8);
                    if (val >= d1 - cfg.max_offset && val <= d1 + cfg.max_offset) {
                        pointer_chain_t chain;
                        chain.base_module = mod.base;
                        chain.module_name = mod.name;
                        chain.offsets.push_back(
                            static_cast<int64_t>(mod.base + i - mod.base));
                        chain.offsets.push_back(
                            static_cast<int64_t>(d1 - val));

                        // read the second level
                        uint64_t ptr2 = 0;
                        if (r.read(d1, &ptr2, 8)) {
                            int64_t off2 = static_cast<int64_t>(
                                cfg.target_address - ptr2);
                            if (std::abs(off2) <=
                                static_cast<int64_t>(cfg.max_offset)) {
                                chain.offsets.push_back(off2);
                                chain.resolved = ptr2 + off2;
                                deeper.push_back(chain);
                            }
                        }
                        if (deeper.size() >= cfg.max_results) goto done;
                    }
                }
            }
        }
done:
        for (auto& c : deeper) results.push_back(std::move(c));
    }

    return results;
}

bool resolve_chain(const reader_t& r, const pointer_chain_t& chain,
                   uint64_t& out) {
    if (chain.offsets.empty()) return false;
    uint64_t addr = chain.base_module + chain.offsets[0];
    for (size_t i = 1; i < chain.offsets.size(); ++i) {
        uint64_t ptr = 0;
        if (!r.read(addr, &ptr, 8)) return false;
        addr = ptr + chain.offsets[i];
    }
    out = addr;
    return true;
}

// ── 2. snapshot diff ─────────────────────────────────────────────────────

snapshot_t take_snapshot(const reader_t& r, uint64_t base, size_t size) {
    snapshot_t s;
    s.base = base;
    s.size = size;
    s.data.resize(size, 0);
    s.timestamp_ms = now_ms();
    r.read(base, s.data.data(), size);
    return s;
}

std::vector<diff_entry_t> diff_snapshots(const snapshot_t& a,
                                          const snapshot_t& b) {
    std::vector<diff_entry_t> diffs;
    if (a.base != b.base || a.size != b.size) return diffs;
    const size_t len = std::min(a.data.size(), b.data.size());
    for (size_t i = 0; i < len; ++i) {
        if (a.data[i] != b.data[i]) {
            diffs.push_back({ i, a.data[i], b.data[i] });
        }
    }
    return diffs;
}

// ── 3. AOB pattern generator ─────────────────────────────────────────────

aob_pattern_t generate_aob(const reader_t& r, uint64_t va, size_t length,
                            const std::string& label) {
    aob_pattern_t pat;
    pat.label = label;
    pat.origin_va = va;
    pat.byte_count = length;

    std::vector<uint8_t> bytes(length);
    if (!r.read(va, bytes.data(), length)) {
        pat.pattern = "(unreadable)";
        return pat;
    }

    // auto-wildcard: bytes that look like relocation targets
    // (4-byte relative offsets that would change on rebase)
    // heuristic: if 4 consecutive bytes form a value > 0x1000 at an
    // instruction boundary that follows E8/E9/0F8x (call/jmp/jcc), wildcard
    std::vector<bool> wild(length, false);
    for (size_t i = 0; i + 4 < length; ++i) {
        if (i > 0) {
            uint8_t prev = bytes[i - 1];
            // E8 = call rel32, E9 = jmp rel32
            if (prev == 0xE8 || prev == 0xE9) {
                wild[i] = wild[i+1] = wild[i+2] = wild[i+3] = true;
                continue;
            }
            // 0F 8x = jcc rel32
            if (i > 1 && bytes[i - 2] == 0x0F &&
                (prev & 0xF0) == 0x80) {
                wild[i] = wild[i+1] = wild[i+2] = wild[i+3] = true;
                continue;
            }
            // 48 8B 05/0D/15/1D/25/2D/35/3D = RIP-relative lea/mov
            if (i > 2 && bytes[i - 3] == 0x48 &&
                bytes[i - 2] == 0x8B &&
                (bytes[i - 1] & 0xC7) == 0x05) {
                wild[i] = wild[i+1] = wild[i+2] = wild[i+3] = true;
                continue;
            }
            // 48 8D 05/0D/15/1D/25/2D/35/3D = RIP-relative lea
            if (i > 2 && bytes[i - 3] == 0x48 &&
                bytes[i - 2] == 0x8D &&
                (bytes[i - 1] & 0xC7) == 0x05) {
                wild[i] = wild[i+1] = wild[i+2] = wild[i+3] = true;
                continue;
            }
        }
    }

    std::ostringstream ss;
    for (size_t i = 0; i < length; ++i) {
        if (i > 0) ss << ' ';
        if (wild[i]) {
            ss << "??";
        } else {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02X", bytes[i]);
            ss << hex;
        }
    }
    pat.pattern = ss.str();
    return pat;
}

std::vector<uint64_t> scan_aob(const reader_t& r, uint64_t base,
                                size_t size, const std::string& pattern) {
    // parse pattern string
    struct pat_byte { uint8_t val; bool wild; };
    std::vector<pat_byte> pat;
    {
        std::istringstream ss(pattern);
        std::string tok;
        while (ss >> tok) {
            if (tok == "?" || tok == "??") {
                pat.push_back({ 0, true });
            } else {
                pat.push_back({ static_cast<uint8_t>(
                    std::strtoul(tok.c_str(), nullptr, 16)), false });
            }
        }
    }
    if (pat.empty()) return {};

    std::vector<uint64_t> hits;
    const size_t chunk = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(chunk + pat.size());

    for (uint64_t off = 0; off < size; off += chunk) {
        const size_t read_sz = std::min<size_t>(
            chunk + pat.size() - 1, size - off);
        if (!r.read(base + off, buf.data(), read_sz)) continue;

        for (size_t i = 0; i + pat.size() <= read_sz; ++i) {
            bool match = true;
            for (size_t j = 0; j < pat.size() && match; ++j) {
                if (!pat[j].wild && buf[i + j] != pat[j].val)
                    match = false;
            }
            if (match) {
                hits.push_back(base + off + i);
                if (hits.size() > 4096) return hits;
            }
        }
    }
    return hits;
}

// ── 4. struct dissector ──────────────────────────────────────────────────

size_t field_type_size(field_type_t t) {
    switch (t) {
    case field_type_t::u8:  case field_type_t::i8:  return 1;
    case field_type_t::u16: case field_type_t::i16: return 2;
    case field_type_t::u32: case field_type_t::i32: case field_type_t::f32: return 4;
    case field_type_t::u64: case field_type_t::i64: case field_type_t::f64:
    case field_type_t::ptr: return 8;
    case field_type_t::vec3: return 12;
    case field_type_t::str: return 256;
    case field_type_t::pad: return 1;
    }
    return 4;
}

size_t compute_struct_size(const struct_def_t& def) {
    size_t sz = 0;
    for (const auto& f : def.fields) {
        size_t end = f.offset + (f.size ? f.size : field_type_size(f.type)) * f.count;
        if (end > sz) sz = end;
    }
    return sz;
}

std::vector<field_value_t> read_struct(const reader_t& r, uint64_t base,
                                        const struct_def_t& def) {
    const size_t total = compute_struct_size(def);
    std::vector<uint8_t> buf(total, 0);
    r.read(base, buf.data(), total);

    std::vector<field_value_t> vals;
    for (const auto& f : def.fields) {
        if (f.type == field_type_t::pad) continue;
        const size_t fsz = f.size ? f.size : field_type_size(f.type);
        if (f.offset + fsz > total) continue;

        field_value_t v;
        v.name = f.name;
        v.type = f.type;

        const uint8_t* p = buf.data() + f.offset;
        char tmp[128];
        switch (f.type) {
        case field_type_t::u8:  { uint8_t  x; std::memcpy(&x, p, 1); std::snprintf(tmp, sizeof(tmp), "%u (0x%02X)", x, x); v.raw_u64 = x; break; }
        case field_type_t::u16: { uint16_t x; std::memcpy(&x, p, 2); std::snprintf(tmp, sizeof(tmp), "%u (0x%04X)", x, x); v.raw_u64 = x; break; }
        case field_type_t::u32: { uint32_t x; std::memcpy(&x, p, 4); std::snprintf(tmp, sizeof(tmp), "%u (0x%08X)", x, x); v.raw_u64 = x; break; }
        case field_type_t::u64: { uint64_t x; std::memcpy(&x, p, 8); std::snprintf(tmp, sizeof(tmp), "0x%016llX", (unsigned long long)x); v.raw_u64 = x; break; }
        case field_type_t::i8:  { int8_t   x; std::memcpy(&x, p, 1); std::snprintf(tmp, sizeof(tmp), "%d", x); v.raw_u64 = static_cast<uint64_t>(x); break; }
        case field_type_t::i16: { int16_t  x; std::memcpy(&x, p, 2); std::snprintf(tmp, sizeof(tmp), "%d", x); v.raw_u64 = static_cast<uint64_t>(x); break; }
        case field_type_t::i32: { int32_t  x; std::memcpy(&x, p, 4); std::snprintf(tmp, sizeof(tmp), "%d (0x%08X)", x, static_cast<uint32_t>(x)); v.raw_u64 = static_cast<uint64_t>(x); break; }
        case field_type_t::i64: { int64_t  x; std::memcpy(&x, p, 8); std::snprintf(tmp, sizeof(tmp), "%lld", (long long)x); v.raw_u64 = static_cast<uint64_t>(x); break; }
        case field_type_t::f32: { float    x; std::memcpy(&x, p, 4); std::snprintf(tmp, sizeof(tmp), "%.6f", x); break; }
        case field_type_t::f64: { double   x; std::memcpy(&x, p, 8); std::snprintf(tmp, sizeof(tmp), "%.10f", x); break; }
        case field_type_t::ptr: { uint64_t x; std::memcpy(&x, p, 8); std::snprintf(tmp, sizeof(tmp), "-> 0x%016llX", (unsigned long long)x); v.raw_u64 = x; break; }
        case field_type_t::vec3: {
            float xyz[3]; std::memcpy(xyz, p, 12);
            std::snprintf(tmp, sizeof(tmp), "(%.2f, %.2f, %.2f)", xyz[0], xyz[1], xyz[2]);
            break;
        }
        case field_type_t::str: {
            size_t slen = 0;
            while (slen < fsz && p[slen]) ++slen;
            std::snprintf(tmp, sizeof(tmp), "\"%.*s\"",
                          static_cast<int>(std::min<size_t>(slen, 60)),
                          reinterpret_cast<const char*>(p));
            break;
        }
        default: tmp[0] = 0;
        }
        v.display = tmp;
        vals.push_back(v);
    }
    return vals;
}

// ── 5. encrypted pointer decoder ─────────────────────────────────────────

decoded_pointer_t try_decode_pointer(uint64_t raw, uint64_t lo, uint64_t hi) {
    decoded_pointer_t best;
    best.raw = raw;
    best.decoded = 0;
    best.key = 0;

    // try XOR with keys derived from common patterns
    for (int bits = 8; bits <= 64; bits += 8) {
        uint64_t mask = (bits == 64) ? ~0ull : ((1ull << bits) - 1);
        for (uint64_t key_cand : { raw ^ lo, raw ^ hi,
                                    raw ^ ((lo + hi) / 2) }) {
            key_cand &= mask;
            uint64_t decoded = raw ^ key_cand;
            if (decoded >= lo && decoded < hi) {
                best.decoded = decoded;
                best.key = key_cand;
                best.method = "xor";
                return best;
            }
        }
    }

    // try ROR (rotate right) with small rotation amounts
    for (int rot = 1; rot < 64; ++rot) {
        uint64_t decoded = (raw >> rot) | (raw << (64 - rot));
        if (decoded >= lo && decoded < hi) {
            best.decoded = decoded;
            best.key = rot;
            best.method = "ror";
            return best;
        }
    }

    // try SUB / ADD
    {
        uint64_t sub_key = raw - lo;
        uint64_t decoded = raw - sub_key;
        if (decoded >= lo && decoded < hi) {
            best.decoded = decoded;
            best.key = sub_key;
            best.method = "sub";
            return best;
        }
    }

    return best;
}

std::vector<decoded_pointer_t> scan_encrypted_pointers(
    const reader_t& r, uint64_t base, size_t size,
    uint64_t lo, uint64_t hi, size_t max_results)
{
    std::vector<decoded_pointer_t> results;
    const size_t chunk = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(chunk);

    for (uint64_t off = 0; off < size; off += chunk) {
        const size_t read_sz = std::min<size_t>(chunk, size - off);
        if (!r.read(base + off, buf.data(), read_sz)) continue;

        for (size_t i = 0; i + 8 <= read_sz; i += 8) {
            uint64_t val = 0;
            std::memcpy(&val, buf.data() + i, 8);
            if (val == 0 || (val >= lo && val < hi)) continue;  // skip already-valid
            auto d = try_decode_pointer(val, lo, hi);
            if (d.decoded >= lo && d.decoded < hi) {
                results.push_back(d);
                if (results.size() >= max_results) return results;
            }
        }
    }
    return results;
}

// ── 6. offset database ──────────────────────────────────────────────────

void offset_db_t::add(offset_entry_t e) {
    // replace if same label exists
    for (auto& ex : entries_) {
        if (ex.label == e.label) { ex = std::move(e); return; }
    }
    entries_.push_back(std::move(e));
}

void offset_db_t::remove(const std::string& label) {
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
        [&](const offset_entry_t& e) { return e.label == label; }),
        entries_.end());
}

const offset_entry_t* offset_db_t::find(const std::string& label) const {
    for (const auto& e : entries_) {
        if (e.label == label) return &e;
    }
    return nullptr;
}

bool offset_db_t::save(const std::string& path) const {
    std::ofstream f(path);
    if (!f) return false;
    f << "[\n";
    for (size_t i = 0; i < entries_.size(); ++i) {
        const auto& e = entries_[i];
        // minimal json: escape quotes in string fields
        auto esc = [](const std::string& s) {
            std::string out;
            for (char c : s) {
                if (c == '"') out += "\\\"";
                else if (c == '\\') out += "\\\\";
                else out += c;
            }
            return out;
        };
        char hex[32];
        std::snprintf(hex, sizeof(hex), "0x%llx", (unsigned long long)e.offset);
        f << "  {\"label\":\"" << esc(e.label)
          << "\",\"module\":\"" << esc(e.module)
          << "\",\"offset\":" << hex
          << ",\"signature\":\"" << esc(e.signature)
          << "\",\"comment\":\"" << esc(e.comment) << "\"}";
        if (i + 1 < entries_.size()) f << ",";
        f << "\n";
    }
    f << "]\n";
    return true;
}

bool offset_db_t::load(const std::string& path) {
    std::ifstream f(path);
    if (!f) return false;
    entries_.clear();
    // minimal json array parser: find objects between { }
    std::string content((std::istreambuf_iterator<char>(f)),
                         std::istreambuf_iterator<char>());
    size_t pos = 0;
    auto skip_ws = [&]() { while (pos < content.size() && content[pos] <= ' ') ++pos; };
    auto read_str = [&]() -> std::string {
        std::string out;
        if (pos >= content.size() || content[pos] != '"') return out;
        ++pos;
        while (pos < content.size() && content[pos] != '"') {
            if (content[pos] == '\\' && pos + 1 < content.size()) { out += content[++pos]; }
            else out += content[pos];
            ++pos;
        }
        if (pos < content.size()) ++pos; // skip closing quote
        return out;
    };

    skip_ws();
    if (pos < content.size() && content[pos] == '[') ++pos;

    while (pos < content.size()) {
        skip_ws();
        if (content[pos] == ']') break;
        if (content[pos] == ',') { ++pos; continue; }
        if (content[pos] != '{') break;
        ++pos;

        offset_entry_t e;
        while (pos < content.size() && content[pos] != '}') {
            skip_ws();
            if (content[pos] == ',') { ++pos; continue; }
            std::string key = read_str();
            skip_ws();
            if (pos < content.size() && content[pos] == ':') ++pos;
            skip_ws();
            if (key == "label") e.label = read_str();
            else if (key == "module") e.module = read_str();
            else if (key == "signature") e.signature = read_str();
            else if (key == "comment") e.comment = read_str();
            else if (key == "offset") {
                // parse number (decimal or 0x hex)
                size_t start = pos;
                while (pos < content.size() && content[pos] != ',' && content[pos] != '}') ++pos;
                std::string num(content.data() + start, pos - start);
                e.offset = std::strtoll(num.c_str(), nullptr, 0);
            }
            else {
                // skip unknown value
                if (pos < content.size() && content[pos] == '"') read_str();
                else while (pos < content.size() && content[pos] != ',' && content[pos] != '}') ++pos;
            }
        }
        if (pos < content.size()) ++pos; // skip }
        e.updated_ms = now_ms();
        entries_.push_back(std::move(e));
    }
    return true;
}

// ── 7. crypto constant scanner ───────────────────────────────────────────

namespace {

// AES S-box (first 16 bytes are a strong fingerprint)
static constexpr uint8_t kAesSbox[16] = {
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
    0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76
};

// SHA-256 initial hash values (first 32 bytes)
static constexpr uint8_t kSha256Init[32] = {
    0x67, 0xe6, 0x09, 0x6a, 0x85, 0xae, 0x67, 0xbb,
    0x72, 0xf3, 0x6e, 0x3c, 0x3a, 0xf5, 0x4f, 0xa5,
    0x7f, 0x52, 0x0e, 0x51, 0x8c, 0x68, 0x05, 0x9b,
    0xab, 0xd9, 0x83, 0x1f, 0x19, 0xcd, 0xe0, 0x5b
};

// CRC-32 table (first 4 entries as uint32)
static constexpr uint32_t kCrc32Start[4] = {
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA
};

// MD5 T table first 4 entries
static constexpr uint32_t kMd5T[4] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee
};

struct known_const_t {
    const uint8_t* data;
    size_t         len;
    const char*    algo;
    const char*    name;
};

} // namespace

std::vector<crypto_hit_t> scan_crypto_constants(
    const reader_t& r, uint64_t base, size_t size, size_t max_results)
{
    const known_const_t consts[] = {
        { kAesSbox,     sizeof(kAesSbox),     "AES",     "S-box" },
        { kSha256Init,  sizeof(kSha256Init),  "SHA-256", "initial H" },
        { reinterpret_cast<const uint8_t*>(kCrc32Start),
          sizeof(kCrc32Start), "CRC-32", "table" },
        { reinterpret_cast<const uint8_t*>(kMd5T),
          sizeof(kMd5T), "MD5", "T table" },
    };

    std::vector<crypto_hit_t> hits;
    const size_t chunk = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(chunk);

    for (uint64_t off = 0; off < size; off += chunk) {
        const size_t read_sz = std::min<size_t>(chunk, size - off);
        if (!r.read(base + off, buf.data(), read_sz)) continue;

        for (const auto& kc : consts) {
            for (size_t i = 0; i + kc.len <= read_sz; ++i) {
                if (std::memcmp(buf.data() + i, kc.data, kc.len) == 0) {
                    hits.push_back({ base + off + i, kc.algo, kc.name });
                    if (hits.size() >= max_results) return hits;
                }
            }
        }
    }
    return hits;
}

// ── 8. RTTI / VMT walker ─────────────────────────────────────────────────

std::vector<rtti_class_t> scan_rtti(const reader_t& r,
                                     uint64_t module_base,
                                     uint32_t module_size,
                                     size_t max_results)
{
    std::vector<rtti_class_t> results;
    if (!module_base || !module_size) return results;

    // read the module image
    const size_t read_sz = std::min<size_t>(module_size, 64 * 1024 * 1024);
    std::vector<uint8_t> img(read_sz);
    if (!r.read(module_base, img.data(), read_sz)) return results;

    // scan for MSVC RTTI: look for the ".?AV" mangled class name prefix
    // which appears in the type_info::raw_name. the TypeDescriptor contains:
    //   +0x00: pVFTable (pointer to type_info vtable)
    //   +0x08: spare (null)
    //   +0x10: name[] (starts with ".?AV" for classes)
    const char marker[] = ".?AV";
    const size_t marker_len = 4;

    for (size_t i = 0x10; i + marker_len < read_sz; ++i) {
        if (std::memcmp(img.data() + i, marker, marker_len) != 0) continue;

        // found a potential TypeDescriptor name at img offset i
        // the TypeDescriptor starts at i - 0x10
        if (i < 0x10) continue;
        const size_t td_off = i - 0x10;

        // read the raw class name (null-terminated)
        size_t name_end = i;
        while (name_end < read_sz && img[name_end]) ++name_end;
        if (name_end - i > 256) continue;   // sanity cap
        std::string raw_name(reinterpret_cast<const char*>(img.data() + i),
                              name_end - i);

        // demangle: strip ".?AV" prefix and "@@" suffix
        std::string class_name = raw_name;
        if (class_name.size() > 4 && class_name.substr(0, 4) == ".?AV") {
            class_name = class_name.substr(4);
        }
        auto at_pos = class_name.find("@@");
        if (at_pos != std::string::npos) {
            class_name = class_name.substr(0, at_pos);
        }

        // now find vtables that reference this TypeDescriptor by scanning
        // for the CompleteObjectLocator (COL). the COL structure on x64:
        //   +0x00: signature (1 for x64)
        //   +0x04: offset
        //   +0x08: cdOffset
        //   +0x0C: pTypeDescriptor (rva from module base)
        //   +0x10: pClassDescriptor (rva)
        //   +0x14: pSelf (rva to self)
        // the TypeDescriptor rva = td_off
        const uint32_t td_rva = static_cast<uint32_t>(td_off);

        for (size_t j = 0; j + 0x18 <= read_sz; j += 4) {
            uint32_t sig = 0;
            std::memcpy(&sig, img.data() + j, 4);
            if (sig != 1) continue;   // x64 COL signature

            uint32_t td_ref = 0;
            std::memcpy(&td_ref, img.data() + j + 0x0C, 4);
            if (td_ref != td_rva) continue;

            // found a COL at offset j. the vtable pointer is the qword
            // that points to COL_va - 8 (the pointer-to-COL sits at
            // vtable[-1]). scan for a pointer to module_base + j
            const uint64_t col_va = module_base + j;

            for (size_t k = 0; k + 8 <= read_sz; k += 8) {
                uint64_t ptr = 0;
                std::memcpy(&ptr, img.data() + k, 8);
                if (ptr == col_va) {
                    // k is the offset of the COL pointer; vtable starts at k+8
                    rtti_class_t cls;
                    cls.vtable_va = module_base + k + 8;
                    cls.class_name = class_name;
                    cls.raw_name = raw_name;

                    // walk the vtable: read pointers until one is outside the module
                    for (size_t m = k + 8; m + 8 <= read_sz; m += 8) {
                        uint64_t method = 0;
                        std::memcpy(&method, img.data() + m, 8);
                        if (method < module_base ||
                            method >= module_base + module_size) break;
                        cls.method_vas.push_back(method);
                        if (cls.method_vas.size() > 128) break;
                    }

                    results.push_back(std::move(cls));
                    if (results.size() >= max_results) return results;
                    break;
                }
            }
        }
    }

    return results;
}

// ── 9. binary map / heatmap ──────────────────────────────────────────────

std::vector<map_block_t> build_binary_map(const reader_t& r,
                                           uint64_t module_base,
                                           uint32_t module_size,
                                           size_t block_size) {
    std::vector<map_block_t> blocks;
    if (!module_base || !module_size) return blocks;

    // read PE headers to classify sections
    uint8_t hdr[0x400] = {};
    if (!r.read(module_base, hdr, sizeof(hdr))) return blocks;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return blocks;

    uint32_t e_lfanew = 0;
    std::memcpy(&e_lfanew, hdr + 0x3C, 4);
    if (e_lfanew + 0x18 > sizeof(hdr)) return blocks;

    uint16_t num_sections = 0;
    std::memcpy(&num_sections, hdr + e_lfanew + 6, 2);
    uint16_t opt_size = 0;
    std::memcpy(&opt_size, hdr + e_lfanew + 0x14, 2);
    const size_t sec_start = e_lfanew + 0x18 + opt_size;

    struct sec_range {
        uint32_t va_start, va_end;
        uint32_t chars;
        char name[9];
    };
    std::vector<sec_range> sections;
    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t off = sec_start + 40 * i;
        if (off + 40 > sizeof(hdr)) break;
        sec_range sr{};
        std::memcpy(sr.name, hdr + off, 8); sr.name[8] = 0;
        std::memcpy(&sr.va_start, hdr + off + 12, 4);
        uint32_t vsize = 0;
        std::memcpy(&vsize, hdr + off + 8, 4);
        sr.va_end = sr.va_start + vsize;
        std::memcpy(&sr.chars, hdr + off + 36, 4);
        sections.push_back(sr);
    }

    auto classify = [&](uint32_t rva) -> map_block_t::kind_t {
        for (const auto& s : sections) {
            if (rva >= s.va_start && rva < s.va_end) {
                if (s.chars & 0x20)       return map_block_t::kind_t::code;
                if (s.chars & 0x40) {
                    if (s.chars & 0x80000000)  return map_block_t::kind_t::data;
                    return map_block_t::kind_t::rdata;
                }
                if (s.chars & 0x80)       return map_block_t::kind_t::bss;
                if (std::strncmp(s.name, ".rsrc", 5) == 0)
                    return map_block_t::kind_t::rsrc;
                if (std::strncmp(s.name, ".reloc", 6) == 0)
                    return map_block_t::kind_t::reloc;
            }
        }
        return map_block_t::kind_t::unknown;
    };

    // build blocks
    std::vector<uint8_t> buf(block_size);
    for (uint32_t rva = 0; rva < module_size; rva += static_cast<uint32_t>(block_size)) {
        const size_t read_sz = std::min<size_t>(block_size, module_size - rva);
        map_block_t blk;
        blk.va = module_base + rva;
        blk.kind = classify(rva);
        if (r.read(module_base + rva, buf.data(), read_sz)) {
            blk.entropy = shannon_entropy(buf.data(), read_sz);
        }
        blocks.push_back(blk);
    }

    return blocks;
}

} // namespace slop::core::runtime::game_tools
