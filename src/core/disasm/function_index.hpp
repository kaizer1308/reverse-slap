#pragma once

// function discovery, recursive descent from entry exports and calls,
// then a prologue heuristic sweep for the rest

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/disasm/pe_parser.hpp"

namespace slop::core::disasm {

struct function_t {
    uint64_t va   = 0;
    size_t   size = 0;   // decoded extent; may grow when blocks merge
};

struct function_stats_t {
    size_t seeds          = 0;
    size_t rd_functions   = 0;   // found by recursive descent
    size_t heuristic_fns  = 0;   // found by prologue heuristics
    bool   truncated      = false;
};

class function_index_t {
public:
    // Build over a parsed image + its file bytes. `base` overrides the
    // preferred image base for VA math (use actual load base at runtime)
    bool build(const pe_image_t& pe, const std::vector<uint8_t>& file,
               engine_t& eng, uint64_t base,
               size_t max_functions = 100'000,
               const std::function<void(float)>& progress = {});

    const std::vector<function_t>& functions() const noexcept { return fns_; }
    std::optional<uint64_t> containing(uint64_t va) const;   // innermost fn start
    const function_stats_t& stats() const noexcept { return stats_; }

private:
    std::vector<function_t> fns_;
    function_stats_t        stats_{};
};

} // namespace slop::core::disasm