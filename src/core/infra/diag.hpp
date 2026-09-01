#pragma once

// src/core/infra/diag.hpp
// little tagged log ring the engines push into

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace slop::core::infra::diag {

enum class level_t : uint8_t { trace = 0, info, warn, error };

struct entry_t {
    int64_t     timestamp_ms = 0;
    level_t     level        = level_t::info;
    std::string tag;         // "boot", "scanner", "attach", "pointer", etc
    std::string message;
};

void init();
void shutdown();

void log(level_t level, std::string_view tag, std::string_view message);

inline void trace(std::string_view tag, std::string_view msg) { log(level_t::trace, tag, msg); }
inline void info (std::string_view tag, std::string_view msg) { log(level_t::info,  tag, msg); }
inline void warn (std::string_view tag, std::string_view msg) { log(level_t::warn,  tag, msg); }
inline void error(std::string_view tag, std::string_view msg) { log(level_t::error, tag, msg); }

// snapshot of everything newer than the given revision
struct snapshot_t {
    std::vector<entry_t> entries;
    uint64_t             revision = 0;
};
snapshot_t snapshot(uint64_t since_revision = 0);

uint64_t revision() noexcept;

} // namespace slop::core::infra::diag
