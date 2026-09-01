#include "core/disasm/hyperion_session.hpp"
#include "core/loader/pe_loader.h"

#include <nlohmann/json.hpp>
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <fstream>
#include <iostream>
#include <numeric>
#include <string>
#include <vector>

namespace {
using clock_type = std::chrono::steady_clock;

std::vector<hype::u8> read_file(const char* path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(input), std::istreambuf_iterator<char>()};
}

double median(std::vector<double> values) {
    std::sort(values.begin(), values.end());
    const size_t middle = values.size() / 2;
    return values.size() % 2 ? values[middle] : (values[middle - 1] + values[middle]) / 2.0;
}

size_t private_bytes() {
    PROCESS_MEMORY_COUNTERS_EX counters{};
    counters.cb = sizeof(counters);
    if (!GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&counters), sizeof(counters)))
        return 0;
    return counters.PrivateUsage;
}

nlohmann::json benchmark_image(const char* label, const char* path) {
    const auto bytes = read_file(path);
    if (bytes.empty()) throw std::runtime_error(std::string("cannot read ") + path);

    std::vector<double> analysis_ms;
    std::vector<double> decompile_ms;
    nlohmann::json facts;
    size_t peak_private = 0;

    for (int run = 0; run < 6; ++run) {
        slop::core::disasm::hyperion_session::session_t session;
        const auto start = clock_type::now();
        if (!session.start_sync(bytes.data(), bytes.size(), 0))
            throw std::runtime_error(session.error());
        const double elapsed = std::chrono::duration<double, std::milli>(clock_type::now() - start).count();
        if (run) analysis_ms.push_back(elapsed);
        peak_private = std::max(peak_private, private_bytes());

        const auto& db = session.db();
        size_t blocks = 0, edges = 0;
        for (const auto& [entry, function] : db.funcs) {
            (void)entry;
            blocks += function.blocks.size();
            for (const auto& [block_addr, block] : function.blocks) {
                (void)block_addr;
                edges += block.succs.size();
            }
        }
        facts = {{"instructions", db.insns.size()}, {"functions", db.funcs.size()},
                 {"blocks", blocks}, {"edges", edges}, {"xrefs", db.xrefs.size()}};

        for (const auto& export_entry : session.image().exports) {
            if (export_entry.name != "loop_sum" && export_entry.name != "sparse_switch" &&
                export_entry.name != "call_chain") continue;
            std::vector<hype::PseudoLine> lines;
            std::string error;
            const auto decomp_start = clock_type::now();
            if (!session.decompile(export_entry.addr, lines, error))
                throw std::runtime_error(error);
            decompile_ms.push_back(std::chrono::duration<double, std::milli>(clock_type::now() - decomp_start).count());
        }
    }

    const double analysis_median = median(analysis_ms);
    std::vector<double> deviations;
    deviations.reserve(analysis_ms.size());
    for (double value : analysis_ms) deviations.push_back(std::abs(value - analysis_median));

    return {{"label", label}, {"path", path}, {"analysis_runs_ms", analysis_ms},
            {"analysis_median_ms", analysis_median}, {"analysis_mad_ms", median(deviations)},
            {"decompile_median_ms", decompile_ms.empty() ? 0.0 : median(decompile_ms)},
            {"peak_private_bytes", peak_private}, {"facts", facts}};
}
}

int main(int argc, char** argv) {
    std::string output_path;
    for (int i = 1; i + 1 < argc; ++i)
        if (std::string(argv[i]) == "--output") output_path = argv[++i];

    try {
        nlohmann::json result;
        result["images"] = nlohmann::json::array({
            benchmark_image("o0", SLOP_DECOMP_TARGET_O0_PATH),
            benchmark_image("o2", SLOP_DECOMP_TARGET_O2_PATH),
        });
        const std::string text = result.dump(2);
        std::cout << text << '\n';
        if (!output_path.empty()) {
            std::ofstream output(output_path);
            output << text << '\n';
        }
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "benchmark failed: " << error.what() << '\n';
        return 1;
    }
}
