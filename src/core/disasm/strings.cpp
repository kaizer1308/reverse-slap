// src/core/disasm/strings.cpp

#include "core/disasm/strings.hpp"

namespace slop::core::disasm {

namespace {

bool ascii_printable(uint8_t c) noexcept {
    return (c >= 0x20 && c <= 0x7E) || c == '\t' || c == '\n' || c == '\r';
}

bool utf16_printable(uint8_t lo, uint8_t hi) noexcept {
    return hi == 0x00 && ascii_printable(lo);
}

} // namespace

std::vector<string_hit_t> extract_strings(const uint8_t* data, size_t len,
                                          uintptr_t va_base,
                                          size_t min_chars,
                                          size_t max_results,
                                          string_stats_t* stats) {
    std::vector<string_hit_t> out;
    string_stats_t local{};
    auto& st = stats ? *stats : local;
    st.scanned = 0;
    st.hits = 0;
    st.truncated = false;

    size_t i = 0;
    while (i < len) {
        ++st.scanned;

        // UTF-16LE candidate: printable, NUL, printable, NUL ..
        if (i + 2 * static_cast<int>(min_chars) <= len &&
            utf16_printable(data[i], data[i + 1])) {
            size_t j = i;
            std::string s;
            s.reserve(64);
            while (j + 1 < len && utf16_printable(data[j], data[j + 1]) && s.size() < 4096) {
                s.push_back(static_cast<char>(data[j]));
                j += 2;
            }
            // Must be terminated by NUL pair and long enough
            if (s.size() >= min_chars && j + 1 < len &&
                data[j] == 0x00 && data[j + 1] == 0x00) {
                string_hit_t h;
                h.va    = va_base + i;
                h.text  = std::move(s);
                h.utf16 = true;
                out.push_back(std::move(h));
                ++st.hits;
                if (out.size() >= max_results) { st.truncated = true; return out; }
                i = j + 2;
                continue;
            }
            // Fall through to ASCII handling for this byte
        }

        // ASCII run
        if (ascii_printable(data[i])) {
            size_t j = i;
            std::string s;
            s.reserve(64);
            while (j < len && ascii_printable(data[j]) && s.size() < 4096) {
                s.push_back(static_cast<char>(data[j]));
                ++j;
            }
            const bool terminated = j < len && data[j] == 0x00;
            if (terminated && s.size() >= min_chars) {
                // Skip pure-whitespace noise
                const bool meaningful = s.find_first_not_of(" \t\r\n") != std::string::npos;
                if (meaningful) {
                    string_hit_t h;
                    h.va   = va_base + i;
                    h.text = std::move(s);
                    out.push_back(std::move(h));
                    ++st.hits;
                    if (out.size() >= max_results) { st.truncated = true; return out; }
                    i = j + 1;
                    continue;
                }
            }
            i = j > i ? j : i + 1;
            continue;
        }

        ++i;
    }

    st.hits = out.size();
    return out;
}

} // namespace slop::core::disasm
