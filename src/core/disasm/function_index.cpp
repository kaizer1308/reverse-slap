// src/core/disasm/function_index.cpp

#include "core/disasm/function_index.hpp"

#include "core/infra/diag.hpp"

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace slop::core::disasm {

namespace {

struct exec_range_t {
    uint64_t va;
    size_t   file_off;
    size_t   len;         // raw bytes available
};

std::vector<exec_range_t> exec_ranges(const pe_image_t& pe, uint64_t base,
                                      const std::vector<uint8_t>& file) {
    std::vector<exec_range_t> out;
    for (const auto& s : pe.sections) {
        if (!s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > file.size()) continue;
        out.push_back({base + s.rva, s.raw_offset, s.raw_size});
    }
    return out;
}

const exec_range_t* range_for_va(const std::vector<exec_range_t>& rs, uint64_t va) {
    for (const auto& r : rs)
        if (va >= r.va && va < r.va + r.len)
            return &r;
    return nullptr;
}

// Common MSVC/GCC x64 prologues
bool looks_like_prologue(const uint8_t* p, size_t avail) {
    if (avail < 5) return false;
    static constexpr uint8_t kP1[] = {0x48, 0x89, 0x5C, 0x24}; // mov [rsp+x],rbx
    static constexpr uint8_t kP2[] = {0x48, 0x89, 0x4C, 0x24}; // mov [rsp+x],rcx
    static constexpr uint8_t kP3[] = {0x48, 0x89, 0x74, 0x24}; // mov [rsp+x],rsi
    static constexpr uint8_t kP4[] = {0x4C, 0x89, 0x44, 0x24}; // mov [rsp+x],r8
    static constexpr uint8_t kP5[] = {0x48, 0x83, 0xEC};       // sub rsp, imm8
    static constexpr uint8_t kP6[] = {0x48, 0x81, 0xEC};       // sub rsp, imm32
    static constexpr uint8_t kP7[] = {0x48, 0x8B, 0xC4};       // mov rax,rsp
    for (const auto* pat : {kP1, kP2, kP3, kP4}) {
        if (std::memcmp(p, pat, 4) == 0) return true;
    }
    if (avail >= 3 && (std::memcmp(p, kP5, 3) == 0 || std::memcmp(p, kP6, 3) == 0 ||
                       std::memcmp(p, kP7, 3) == 0))
        return true;
    return false;
}

bool good_preceding_boundary(const uint8_t* prev) noexcept {
    const uint8_t c = *prev;
    return c == 0xCC /* int3 pad */ || c == 0xC3 /* ret */;
}

} // namespace

bool function_index_t::build(const pe_image_t& pe, const std::vector<uint8_t>& file,
                             engine_t& eng, uint64_t base,
                             size_t max_functions,
                             const std::function<void(float)>& progress) {
    fns_.clear();
    stats_ = {};

    if (!pe.ok || !eng.ok()) return false;

    const auto ranges = exec_ranges(pe, base, file);
    if (ranges.empty()) return false;

    std::unordered_map<uint64_t, size_t> extent;   // fn start -> last decoded end off
    std::unordered_set<uint64_t> claimed;

    // Recursive descent
    std::vector<uint64_t> worklist;

    const auto push_target = [&](uint64_t va) {
        if (range_for_va(ranges, va)) worklist.push_back(va);
    };

    push_target(base + pe.entry_rva);
    ++stats_.seeds;
    for (const auto& e : pe.exports) {
        if (e.rva && !e.forwarded) { push_target(base + e.rva); ++stats_.seeds; }
    }

    while (!worklist.empty()) {
        if (fns_.size() + claimed.size() >= max_functions) { stats_.truncated = true; break; }

        const uint64_t start = worklist.back();
        worklist.pop_back();
        if (!claimed.insert(start).second) continue;

        const exec_range_t* rng = range_for_va(ranges, start);
        if (!rng) continue;

        uint64_t va = start;
        bool terminated_cleanly = false;

        while (true) {
            const uint64_t off_in_range = static_cast<size_t>(va - rng->va);
            if (off_in_range >= rng->len) break;

            auto insn = eng.decode(va, file.data() + rng->file_off + off_in_range,
                                   rng->len - static_cast<size_t>(off_in_range), false);
            if (!insn) break;

            if (insn->flow == flow_t::call && insn->has_rel_target)
                push_target(insn->rel_target);

            if (insn->flow == flow_t::ret) { terminated_cleanly = true; break; }
            if (insn->flow == flow_t::jmp) {
                // Unconditional jump out of the linear window ends the block
                terminated_cleanly = true;
                break;
            }

            va += insn->length;
        }

        extent[start] = static_cast<size_t>(va - start) +
                        (terminated_cleanly ? 0u : 1u);
        if (extent[start] == 0) extent[start] = 1;
    }

    for (const auto& [start, sz] : extent) {
        // jmp thunks are one instruction and five bytes so allow size one entries
        if (sz >= 1) {
            fns_.push_back({start, sz});
            ++stats_.rd_functions;
        }
    }

    // Recursive descent already decoded these spans. Without this the sweep
    // below re-validates candidates in the middle of known functions, decoding
    // up to 2048 instructions each time, which on a large image is most of
    // the index build
    std::vector<std::pair<uint64_t, uint64_t>> covered;   // sorted [start, end)
    covered.reserve(extent.size());
    for (const auto& [start, sz] : extent) covered.emplace_back(start, start + sz);
    std::sort(covered.begin(), covered.end());
    const auto is_covered = [&covered](uint64_t va) {
        auto it = std::upper_bound(covered.begin(), covered.end(), va,
            [](uint64_t v, const std::pair<uint64_t, uint64_t>& r) { return v < r.first; });
        return it != covered.begin() && va < std::prev(it)->second;
    };

    // Prologue heuristic sweep over unclaimed bytes
    for (const auto& rng : ranges) {
        if (fns_.size() >= max_functions) { stats_.truncated = true; break; }

        const size_t scan_end = rng.len > 1 ? rng.len - 1 : 0;
        for (size_t off = 1; off < scan_end; ++off) {
            if ((off & 0xFFF) == 0) {
                if (progress) progress(static_cast<float>(fns_.size()) /
                                       static_cast<float>(max_functions));
            }
            if (fns_.size() >= max_functions) { stats_.truncated = true; break; }

            const uint8_t* p = file.data() + rng.file_off + off;
            if (!good_preceding_boundary(p - 1)) continue;
            if (!looks_like_prologue(p, rng.len - off)) continue;

            const uint64_t cand = rng.va + off;
            if (claimed.count(cand) || is_covered(cand)) continue;

            // Validate by decoding toward an eventual ret within 16 KiB
            uint64_t va = cand;
            bool ok = false;
            for (int steps = 0; steps < 2048; ++steps) {
                const uint64_t o = va - rng.va;
                if (o >= rng.len) break;
                auto insn = eng.decode(va, file.data() + rng.file_off + o,
                                       rng.len - static_cast<size_t>(o), false);
                if (!insn) break;
                if (insn->flow == flow_t::ret) { ok = true; break; }
                va += insn->length;
            }
            if (!ok) continue;

            fns_.push_back({cand, static_cast<size_t>(va + 1 - cand)});
            ++stats_.heuristic_fns;
        }
    }

    // Merge + sort; sizes clipped at next function start
    std::sort(fns_.begin(), fns_.end(),
              [](const function_t& a, const function_t& b) { return a.va < b.va; });
    fns_.erase(std::unique(fns_.begin(), fns_.end(),
                           [](const function_t& a, const function_t& b) {
                               return a.va == b.va;
                           }),
               fns_.end());
    for (size_t i = 0; i + 1 < fns_.size(); ++i)
        fns_[i].size = std::min(fns_[i].size,
                                static_cast<size_t>(fns_[i + 1].va - fns_[i].va));

    slop::core::infra::diag::info("fnindex", "discovered " + std::to_string(fns_.size()) +
              " functions (" +
              std::to_string(stats_.rd_functions) + " rd, " +
              std::to_string(stats_.heuristic_fns) + " heur)");
    return true;
}

std::optional<uint64_t> function_index_t::containing(uint64_t va) const {
    // Binary search: greatest start <= va
    auto it = std::upper_bound(fns_.begin(), fns_.end(), va,
        [](uint64_t v, const function_t& f) { return v < f.va; });
    if (it == fns_.begin()) return std::nullopt;
    --it;
    if (va < it->va + it->size) return it->va;
    return std::nullopt;
}

} // namespace slop::core::disasm
