#pragma once

// host filesystem helpers behind the mcp fs tool

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::util {

struct file_entry_t {
    std::string name;
    std::string path;
    uint64_t    size = 0;
    bool        directory = false;
};

bool read_file(const std::string& path, std::vector<uint8_t>* out,
               size_t max_bytes, std::string* error = nullptr);
bool write_file(const std::string& path, const std::vector<uint8_t>& bytes,
                bool append, std::string* error = nullptr);
std::vector<file_entry_t> list_directory(const std::string& dir,
                                         std::string* error = nullptr);
bool create_directory(const std::string& path, std::string* error = nullptr);
bool delete_path(const std::string& path, std::string* error = nullptr);

// Recursive filename search under `root` (case-insensitive substring or
// exact match when the needle has no wildcards)
std::vector<file_entry_t> search_files(const std::string& root,
                                       const std::string& needle,
                                       size_t max_results);

// Content grep: literal substring match across files under root
struct grep_hit_t {
    std::string path;
    uint32_t    line = 0;
    std::string text;
};
std::vector<grep_hit_t> grep_in_files(const std::string& root,
                                      const std::string& needle,
                                      const std::string& glob_suffix,
                                      size_t max_hits);

} // namespace slop::core::util
