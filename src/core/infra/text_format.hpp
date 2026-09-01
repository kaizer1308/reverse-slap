#pragma once

// src/core/infra/text_format.hpp
// hex formatting and parsing helpers

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace slop::core::infra::fmt {

enum class copy_dialect_t : uint8_t {
    hex_space,     // "DE AD BE EF"
    hex_nospace,   // "DEADBEEF"
    c_array,       // "{ 0xDE, 0xAD, 0xBE, 0xEF }"
    python_bytes,  // "b'\\xDE\\xAD\\xBE\\xEF'"
    rust_array,    // "[0xDE, 0xAD, 0xBE, 0xEF]"
    raw_string,    // printable ascii or escaped
    COUNT
};

const char* dialect_label(copy_dialect_t d) noexcept;

std::string format_hex(std::span<const uint8_t> data, bool uppercase = true);
std::string format_as(std::span<const uint8_t> data, copy_dialect_t dialect);

// plain base64 for binary that has to survive json
std::string base64(std::span<const uint8_t> data);

// parses spaced, packed or \\x style hex
bool parse_hex(std::string_view text, std::vector<uint8_t>& out, std::string& err);

// 0x address padded to pointer width
std::string format_address(uint64_t va, uint32_t pointer_width = 8);

// 1.5 MiB style byte counts
std::string format_bytes(uint64_t bytes);

} // namespace slop::core::infra::fmt
