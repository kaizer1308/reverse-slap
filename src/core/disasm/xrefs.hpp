#pragma once

// static xref index over executable sections, calls jumps and rip relative
// data refs, linear sweep with byte resync

#include <cstdint>
#include <unordered_map>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/disasm/pe_parser.hpp"

namespace slop::core::disasm {

enum class xref_kind_t : uint8_t { call, jmp, data };

struct xref_t {
    uint64_t     from = 0;
    uint64_t     to   = 0;
    xref_kind_t  kind = xref_kind_t::call;
};

class xref_index_t {
public:
    bool build(const pe_image_t& pe, const std::vector<uint8_t>& file,
               engine_t& eng, uint64_t base,
               size_t max_refs = 4'000'000);

    // All references pointing AT va
    const std::vector<xref_t>& refs_to(uint64_t va) const;

    // Distinct target VAs (for iteration/inspection)
    std::vector<uint64_t> targets() const;

    size_t total() const noexcept { return total_; }

private:
    std::unordered_map<uint64_t, std::vector<xref_t>> by_target_;
    static const std::vector<xref_t> kEmpty;
    size_t total_ = 0;
};

} // namespace slop::core::disasm
