#pragma once

// src/core/disasm/strings.hpp
// ASCII + UTF-16LE string extraction over a byte image

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::disasm {

struct string_hit_t {
    uintptr_t   va    = 0;
    std::string text;
    bool        utf16 = false;
};

struct string_stats_t {
    size_t scanned   = 0;
    size_t hits      = 0;
    bool   truncated = false;
};

// Scan [data, data+len) mapped at va_base. Strings must be NUL-terminated
// and >= min_chars. UTF-16 runs are preferred when they qualify
std::vector<string_hit_t> extract_strings(const uint8_t* data, size_t len,
                                          uintptr_t va_base,
                                          size_t min_chars = 4,
                                          size_t max_results = 200'000,
                                          string_stats_t* stats = nullptr);

} // namespace slop::core::disasm
