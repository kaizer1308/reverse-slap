#pragma once

// src/core/util/zip_reader.hpp
// read-only in-memory zip archive: central directory (zip64 aware),
// stored + deflate extraction with size and crc-32 checks

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace slop::core::util::zip {

struct entry_t {
    std::string name;                  // as stored, '/' separators
    uint16_t    method = 0;            // 0 stored, 8 deflate
    uint16_t    flags  = 0;
    uint32_t    crc32  = 0;
    uint64_t    compressed_size     = 0;
    uint64_t    uncompressed_size   = 0;
    uint64_t    local_header_offset = 0;
    bool is_directory() const noexcept { return !name.empty() && name.back() == '/'; }
    bool is_encrypted() const noexcept { return (flags & 1u) != 0; }
};

// "PK\x03\x04" (or an empty archive's "PK\x05\x06") at offset 0
bool has_zip_magic(const uint8_t* data, size_t len) noexcept;

class archive_t {
public:
    static constexpr uint64_t kDefaultMaxEntry = 2ull << 30;   // 2 GiB
    // Parse the central directory (ZIP64 aware). Borrows `data`, which must
    // outlive the archive
    bool open(const uint8_t* data, size_t len, std::string* error = nullptr);
    const std::vector<entry_t>& entries() const noexcept;
    const entry_t* find(std::string_view name) const;   // exact match
    // Stored or deflate; checks sizes and CRC-32. False + error on encrypted
    // entries, other methods, size > max_size, truncated or corrupt data
    bool extract(const entry_t& e, std::vector<uint8_t>& out,
                 std::string* error = nullptr,
                 uint64_t max_size = kDefaultMaxEntry) const;

private:
    const uint8_t*                          data_ = nullptr;
    size_t                                  len_  = 0;
    std::vector<entry_t>                    entries_;
    std::unordered_map<std::string, size_t> index_;   // name -> entries_ position (first wins)
};

} // namespace slop::core::util::zip
