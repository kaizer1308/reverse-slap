// src/core/analysis/signatures.cpp

#include "core/analysis/signatures.hpp"

#include <algorithm>

namespace slop::core::analysis {

namespace {

struct const_sig_t {
    const char* name;
    std::vector<uint8_t> bytes;
};

std::vector<uint8_t> to_bytes(std::initializer_list<uint8_t> b) {
    return {b.begin(), b.end()};
}

const std::vector<const_sig_t>& sig_table() {
    static const std::vector<const_sig_t> table = {
        // AES forward S-box, first 16 entries
        {"AES S-box (forward)", to_bytes({0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B,
                                         0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B,
                                         0xFE, 0xD7, 0xAB, 0x76})},
        // AES inverse S-box, first 16 entries
        {"AES S-box (inverse)", to_bytes({0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36,
                                         0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E,
                                         0x81, 0xF3, 0xD7, 0xFB})},
        // SHA-256 round constants K[0..7]
        {"SHA-256 K constants", to_bytes({0x42, 0x8A, 0x2F, 0x98, 0x71, 0x37,
                                         0x44, 0x91, 0xB5, 0xC0, 0xFB, 0xCF,
                                         0xE9, 0xB5, 0xDB, 0xA5, 0x39, 0x56,
                                         0xC2, 0x5B, 0x59, 0xF1, 0x11, 0xF1,
                                         0x92, 0x3F, 0x9A, 0x4A, 0xAB, 0x1C,
                                         0x5E, 0xD5})},
        // SHA-1 / MD5 family initial state (BE dwords)
        {"SHA-1 IV", to_bytes({0x67, 0x45, 0x23, 0x01, 0xEF, 0xCD, 0xAB, 0x89,
                               0x98, 0xBA, 0xDC, 0xFE, 0x10, 0x32, 0x54, 0x76,
                               0xC3, 0xD2, 0xE1, 0xF0})},
        // MD5 init state (LE dwords)
        {"MD5 IV", to_bytes({0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                             0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10})},
        // CRC32 reflected polynomial table, first 8 entries (LE)
        {"CRC-32 table", to_bytes({0x00, 0x00, 0x00, 0x00, 0x96, 0x30, 0x07,
                                   0x77, 0x2C, 0x61, 0x0E, 0xEE, 0xBA, 0x51,
                                   0x8D, 0x42})},
        // Blowfish initial P-array (hex digits of pi, BE)
        {"Blowfish P-array", to_bytes({0x24, 0x3F, 0x6A, 0x88, 0x85, 0xA3,
                                       0x08, 0xD3, 0x13, 0x19, 0x8A, 0x2E,
                                       0x03, 0x70, 0x73, 0x44})},
        // Base64 standard alphabet prefix
        {"Base64 alphabet", to_bytes({'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X'})},
        // Base64 URL-safe alphabet prefix
        {"Base64url alphabet", to_bytes({'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                         'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                         'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                         'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                         '-', '_'})},
        // Common stream magics
        {"gzip stream", to_bytes({0x1F, 0x8B, 0x08})},
        {"zlib stream (default)", to_bytes({0x78, 0x9C})},
    };
    return table;
}

} // namespace

std::vector<signature_hit_t> crypto_hunt(const disasm::pe_image_t& pe,
                                         const std::vector<uint8_t>& file,
                                         size_t limit) {
    std::vector<signature_hit_t> hits;
    if (!pe.ok || file.empty()) return hits;

    auto scan_region = [&](size_t begin, size_t end, bool overlay) {
        for (const auto& sig : sig_table()) {
            if (hits.size() >= limit) return;
            const auto& n = sig.bytes;
            if (end < n.size() || file.size() < n.size()) continue;
            const size_t stop = std::min(end, file.size()) - (n.size() - 1);
            for (size_t i = begin; i <= stop; ++i) {
                if (file[i] != n[0]) continue;
                if (std::equal(n.begin(), n.end(), file.data() + i)) {
                    signature_hit_t h;
                    h.name       = sig.name;
                    h.offset     = i;
                    h.in_overlay = overlay;
                    if (!overlay) {
                        if (auto va = pe.offset_to_va(i)) h.va = *va;
                    }
                    hits.push_back(std::move(h));
                    break;   // one hit per signature per region
                }
            }
        }
    };

    for (const auto& sec : pe.sections) {
        if (sec.raw_size == 0) continue;
        const size_t begin = sec.raw_offset;
        if (begin + sec.raw_size > file.size()) continue;
        scan_region(begin, begin + sec.raw_size, false);
        if (hits.size() >= limit) return hits;
    }

    uint64_t end_of_raw = 0;
    for (const auto& sec : pe.sections)
        end_of_raw = std::max<uint64_t>(
            end_of_raw, static_cast<uint64_t>(sec.raw_offset) + sec.raw_size);
    if (end_of_raw > 0 && file.size() > end_of_raw)
        scan_region(static_cast<size_t>(end_of_raw), file.size(), true);

    return hits;
}

} // namespace slop::core::analysis
