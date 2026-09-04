#pragma once
#include "analysis_db.h"
#include <cstdint>
#include <functional>
#include <vector>
#include <string>

namespace hype {

struct DiffResult {
    va_t        addr_a;
    va_t        addr_b;
    std::string name;
    float       similarity;
    enum Status : u8 { Added, Removed, Modified, Identical };
    Status      status;
};

class BinDiff {
public:
    struct options_t {
        // Abort the quadratic fallback once this many similarity pairs have
        // been evaluated; remaining functions are reported as added/removed.
        // 0 = no cap (legacy behavior, can hang on 10k+ function binaries).
        size_t max_pairs = 500000;
        // Skip byte-compare pairs whose sizes differ by more than this ratio.
        float size_prefilter_ratio = 4.0f;
        // Optional cooperative cancel + wall-clock deadline.
        const std::function<bool()>* cancel = nullptr;
        uint64_t deadline_ms = 0; // steady_clock ms, 0 = none
    };
    struct outcome_t {
        std::vector<DiffResult> results;
        bool timed_out = false;
        bool cancelled = false;
        size_t pairs_evaluated = 0;
        size_t pairs_skipped_size = 0;
    };
    std::vector<DiffResult> compare(const AnalysisDB& a, const AnalysisDB& b);
    outcome_t compare_budgeted(const AnalysisDB& a, const AnalysisDB& b,
                               const options_t& opt = {});

private:
    float compute_similarity(const Function& fa, const Function& fb);
    float compute_similarity_cached(const std::vector<u8>& ba,
                                    const std::vector<u8>& bb);
    std::vector<u8> func_bytes(const Function& f);
    static uint64_t now_ms();
};

}
