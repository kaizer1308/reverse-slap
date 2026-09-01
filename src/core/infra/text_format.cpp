#include "core/infra/text_format.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace slop::core::infra::fmt {

const char* dialect_label(copy_dialect_t d) noexcept {
    switch (d) {
    case copy_dialect_t::hex_space:    return "Hex (spaced)";
    case copy_dialect_t::hex_nospace:  return "Hex (compact)";
    case copy_dialect_t::c_array:      return "C array";
    case copy_dialect_t::python_bytes: return "Python bytes";
    case copy_dialect_t::rust_array:   return "Rust array";
    case copy_dialect_t::raw_string:   return "Raw string";
    default: return "Unknown";
    }
}

std::string format_hex(std::span<const uint8_t> data, bool uppercase) {
    std::string out;
    out.reserve(data.size() * 3);
    const char* fmt = uppercase ? "%02X" : "%02x";
    char buf[4];
    for (size_t i = 0; i < data.size(); ++i) {
        if (i > 0) out += ' ';
        std::snprintf(buf, sizeof(buf), fmt, data[i]);
        out += buf;
    }
    return out;
}

std::string format_as(std::span<const uint8_t> data, copy_dialect_t dialect) {
    char buf[8];
    std::string out;

    switch (dialect) {
    case copy_dialect_t::hex_space:
        return format_hex(data, true);

    case copy_dialect_t::hex_nospace:
        out.reserve(data.size() * 2);
        for (auto b : data) {
            std::snprintf(buf, sizeof(buf), "%02X", b);
            out += buf;
        }
        return out;

    case copy_dialect_t::c_array:
        out = "{ ";
        for (size_t i = 0; i < data.size(); ++i) {
            if (i > 0) out += ", ";
            std::snprintf(buf, sizeof(buf), "0x%02X", data[i]);
            out += buf;
        }
        out += " }";
        return out;

    case copy_dialect_t::python_bytes:
        out = "b'";
        for (auto b : data) {
            std::snprintf(buf, sizeof(buf), "\\x%02X", b);
            out += buf;
        }
        out += "'";
        return out;

    case copy_dialect_t::rust_array:
        out = "[";
        for (size_t i = 0; i < data.size(); ++i) {
            if (i > 0) out += ", ";
            std::snprintf(buf, sizeof(buf), "0x%02X", data[i]);
            out += buf;
        }
        out += "]";
        return out;

    case copy_dialect_t::raw_string:
        out.reserve(data.size());
        for (auto b : data) {
            if (b >= 0x20 && b < 0x7F)
                out += static_cast<char>(b);
            else {
                std::snprintf(buf, sizeof(buf), "\\x%02X", b);
                out += buf;
            }
        }
        return out;

    default:
        return format_hex(data, true);
    }
}

bool parse_hex(std::string_view text, std::vector<uint8_t>& out, std::string& err) {
    out.clear();
    std::string clean;
    clean.reserve(text.size());

    // strip whitespace commas and 0x
    for (size_t i = 0; i < text.size(); ++i) {
        char c = text[i];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',') continue;
        if (c == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            ++i;
            continue;
        }
        if (c == '\\' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
            ++i;
            continue;
        }
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            err = "invalid hex character '";
            err += c;
            err += "'";
            return false;
        }
        clean += c;
    }

    if (clean.size() % 2 != 0) {
        err = "odd number of hex digits";
        return false;
    }

    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        char pair[3] = { clean[i], clean[i + 1], '\0' };
        out.push_back(static_cast<uint8_t>(std::strtoul(pair, nullptr, 16)));
    }
    return true;
}

std::string format_address(uint64_t va, uint32_t pointer_width) {
    char buf[32];
    if (pointer_width <= 4)
        std::snprintf(buf, sizeof(buf), "0x%08X", static_cast<uint32_t>(va));
    else
        std::snprintf(buf, sizeof(buf), "0x%016llX", static_cast<unsigned long long>(va));
    return buf;
}

std::string format_bytes(uint64_t bytes) {
    char buf[64];
    if (bytes < 1024)
        std::snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
    else if (bytes < 1024ull * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f KiB", static_cast<double>(bytes) / 1024.0);
    else if (bytes < 1024ull * 1024 * 1024)
        std::snprintf(buf, sizeof(buf), "%.1f MiB", static_cast<double>(bytes) / (1024.0 * 1024.0));
    else
        std::snprintf(buf, sizeof(buf), "%.2f GiB", static_cast<double>(bytes) / (1024.0 * 1024.0 * 1024.0));
    return buf;
}

std::string base64(std::span<const uint8_t> data) {
    static constexpr char kTable[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        uint32_t v = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < data.size()) v |= static_cast<uint32_t>(data[i + 1]) << 8;
        if (i + 2 < data.size()) v |= static_cast<uint32_t>(data[i + 2]);
        out += kTable[(v >> 18) & 63];
        out += kTable[(v >> 12) & 63];
        out += (i + 1 < data.size()) ? kTable[(v >> 6) & 63] : '=';
        out += (i + 2 < data.size()) ? kTable[v & 63] : '=';
    }
    return out;
}

} // namespace slop::core::infra::fmt
