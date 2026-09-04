#include "bindiff.h"
#include <fmt/format.h>
#include <algorithm>
#include <chrono>
#include <unordered_map>
#include <unordered_set>
#include <numeric>

namespace hype {

uint64_t BinDiff::now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::vector<DiffResult> BinDiff::compare(const AnalysisDB& a, const AnalysisDB& b) {
    return compare_budgeted(a, b, options_t{}).results;
}

BinDiff::outcome_t BinDiff::compare_budgeted(const AnalysisDB& a,
                                             const AnalysisDB& b,
                                             const options_t& opt) {
    outcome_t out;
    std::unordered_set<va_t> matched_b;

    // Name index for the fast path: legacy code scanned all of b for every
    // function in a (O(N*M) string compares before any similarity work).
    std::unordered_multimap<std::string, va_t> names_b;
    names_b.reserve(b.funcs.size() * 2 + 1);
    for (const auto& [eb, fb] : b.funcs) {
        if (!fb.name.empty()) names_b.emplace(fb.name, eb);
    }

    // Byte cache: legacy recomputed func_bytes(fa) once per pair (each call
    // sorts blocks + copies all insn bytes), turning O(N*M) pairs into
    // O(N*M*(sort+alloc)). Cache once per function instead.
    std::unordered_map<va_t, std::vector<u8>> bytes_a, bytes_b;
    bytes_a.reserve(a.funcs.size() * 2 + 1);
    bytes_b.reserve(b.funcs.size() * 2 + 1);
    auto bytes_of_a = [&](va_t va, const Function& f) -> const std::vector<u8>& {
        auto it = bytes_a.find(va);
        if (it != bytes_a.end()) return it->second;
        return bytes_a.emplace(va, func_bytes(f)).first->second;
    };
    auto bytes_of_b = [&](va_t va, const Function& f) -> const std::vector<u8>& {
        auto it = bytes_b.find(va);
        if (it != bytes_b.end()) return it->second;
        return bytes_b.emplace(va, func_bytes(f)).first->second;
    };

    auto check_stop = [&]() -> bool {
        if (opt.cancel && *opt.cancel && (*opt.cancel)()) {
            out.cancelled = true;
            return true;
        }
        if (opt.deadline_ms && now_ms() >= opt.deadline_ms) {
            out.timed_out = true;
            return true;
        }
        return false;
    };

    for (const auto& [ea, fa] : a.funcs) {
        if (check_stop()) break;
        bool found = false;
        if (!fa.name.empty()) {
            auto range = names_b.equal_range(fa.name);
            for (auto it = range.first; it != range.second; ++it) {
                const va_t eb = it->second;
                if (matched_b.count(eb)) continue;
                const auto fit = b.funcs.find(eb);
                if (fit == b.funcs.end()) continue;
                const float sim = compute_similarity_cached(
                    bytes_of_a(ea, fa), bytes_of_b(eb, fit->second));
                ++out.pairs_evaluated;
                auto st = sim >= 0.999f ? DiffResult::Identical : DiffResult::Modified;
                out.results.push_back({ea, eb, fa.name, sim, st});
                matched_b.insert(eb);
                found = true;
                break;
            }
        }
        if (found) continue;

        float best_sim = 0.f;
        va_t best_eb = 0;
        const auto& ba = bytes_of_a(ea, fa);
        for (const auto& [eb, fb] : b.funcs) {
            if (matched_b.count(eb)) continue;
            const auto& bb = bytes_of_b(eb, fb);
            // Size prefilter: byte-compare pairs 4x apart cannot reach 0.5.
            if (!ba.empty() && !bb.empty()) {
                const size_t mx = std::max(ba.size(), bb.size());
                const size_t mn = std::min(ba.size(), bb.size());
                if (mx > static_cast<size_t>(static_cast<float>(mn) * opt.size_prefilter_ratio)) {
                    ++out.pairs_skipped_size;
                    continue;
                }
            }
            if (opt.max_pairs && out.pairs_evaluated >= opt.max_pairs) {
                out.timed_out = true;
                break;
            }
            const float sim = compute_similarity_cached(ba, bb);
            ++out.pairs_evaluated;
            if (sim > best_sim) { best_sim = sim; best_eb = eb; }
            if ((out.pairs_evaluated & 0xFFF) == 0 && check_stop()) break;
        }
        if (out.cancelled || out.timed_out) {
            // Budget exhausted: this and all remaining a-funcs report as
            // removed (the trailing b-loop reports unmatched as added), so
            // totals stay meaningful without more pair evaluations.
            std::string nm = fa.name.empty() ? fmt::format("sub_{:X}", ea) : fa.name;
            out.results.push_back({ea, 0, nm, 0.f, DiffResult::Removed});
            continue;
        }
        if (best_sim >= 0.5f && best_eb) {
            auto st = best_sim >= 0.999f ? DiffResult::Identical : DiffResult::Modified;
            std::string nm = fa.name.empty() ? fmt::format("sub_{:X}", ea) : fa.name;
            out.results.push_back({ea, best_eb, nm, best_sim, st});
            matched_b.insert(best_eb);
        } else {
            std::string nm = fa.name.empty() ? fmt::format("sub_{:X}", ea) : fa.name;
            out.results.push_back({ea, 0, nm, 0.f, DiffResult::Removed});
        }
    }

    for (const auto& [eb, fb] : b.funcs) {
        if (matched_b.count(eb)) continue;
        std::string nm = fb.name.empty() ? fmt::format("sub_{:X}", eb) : fb.name;
        out.results.push_back({0, eb, nm, 0.f, DiffResult::Added});
    }

    std::sort(out.results.begin(), out.results.end(), [](const auto& x, const auto& y) {
        return x.status < y.status;
    });
    return out;
}

float BinDiff::compute_similarity(const Function& fa, const Function& fb) {
    auto ba = func_bytes(fa);
    auto bb = func_bytes(fb);
    return compute_similarity_cached(ba, bb);
}

float BinDiff::compute_similarity_cached(const std::vector<u8>& ba,
                                         const std::vector<u8>& bb) {
    if (ba.empty() && bb.empty()) return 1.f;
    if (ba.empty() || bb.empty()) return 0.f;

    size_t match = 0;
    size_t total = std::max(ba.size(), bb.size());
    size_t cmp_len = std::min(ba.size(), bb.size());
    for (size_t i = 0; i < cmp_len; ++i)
        if (ba[i] == bb[i]) ++match;

    return static_cast<float>(match) / static_cast<float>(total);
}

std::vector<u8> BinDiff::func_bytes(const Function& f) {
    std::vector<u8> out;
    std::vector<const BasicBlock*> blocks;
    blocks.reserve(f.blocks.size());
    for (const auto& [_, bb] : f.blocks)
        blocks.push_back(&bb);
    std::sort(blocks.begin(), blocks.end(), [](const BasicBlock* a, const BasicBlock* b) {
        return a->start < b->start;
    });
    for (const BasicBlock* bb : blocks)
        for (const auto& insn : bb->insns)
            out.insert(out.end(), insn.bytes, insn.bytes + insn.len);
    return out;
}

}
