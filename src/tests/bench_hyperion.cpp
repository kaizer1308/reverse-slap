#include "core/disasm/binary_state.hpp"
#include "core/infra/diag.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/loader/pe_loader.h"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>
#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
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

nlohmann::json benchmark_image(const std::string& label, const std::string& path,
                               int runs, bool decompile_exports) {
    const auto bytes = read_file(path.c_str());
    if (bytes.empty()) throw std::runtime_error("cannot read " + path);

    std::vector<double> analysis_ms;
    std::vector<double> decompile_ms;
    nlohmann::json facts;
    size_t peak_private = 0;

    for (int run = 0; run < runs; ++run) {
        slop::core::disasm::hyperion_session::session_t session;
        const auto start = clock_type::now();
        if (!session.start_sync(bytes.data(), bytes.size(), 0))
            throw std::runtime_error(session.error());
        const double elapsed = std::chrono::duration<double, std::milli>(clock_type::now() - start).count();
        if (run) analysis_ms.push_back(elapsed);
        peak_private = std::max(peak_private, private_bytes());

        std::cerr << "[bench] " << label << " run " << run << ": "
                  << elapsed << " ms, private "
                  << (private_bytes() / (1024 * 1024)) << " MiB" << std::endl;

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

        if (!decompile_exports) continue;
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

    if (analysis_ms.empty()) analysis_ms.push_back(0.0);
    const double analysis_median = median(analysis_ms);
    std::vector<double> deviations;
    deviations.reserve(analysis_ms.size());
    for (double value : analysis_ms) deviations.push_back(std::abs(value - analysis_median));

    return {{"label", label}, {"path", path}, {"analysis_runs_ms", analysis_ms},
            {"analysis_median_ms", analysis_median}, {"analysis_mad_ms", median(deviations)},
            {"decompile_median_ms", decompile_ms.empty() ? 0.0 : median(decompile_ms)},
            {"peak_private_bytes", peak_private}, {"facts", facts}};
}

// Times the synchronous half of opening an image in the app: PE parse,
// function index, xref index and strings. The hyperion pass it kicks off runs
// on its own thread and is cancelled straight away so it does not pollute the
// measurement
nlohmann::json benchmark_load(const std::string& label, const std::string& path,
                              int runs) {
    namespace binary_state = slop::core::disasm::binary_state;
    std::vector<double> load_ms;
    nlohmann::json facts;
    uint64_t diag_rev = slop::core::infra::diag::revision();
    for (int run = 0; run < runs; ++run) {
        const auto start = clock_type::now();
        const bool ok = binary_state::load_file(path);
        const double elapsed = std::chrono::duration<double, std::milli>(clock_type::now() - start).count();
        binary_state::hype_stop();
        if (!ok) throw std::runtime_error("load_file failed for " + path);
        const auto& bin = binary_state::get();
        facts = {{"functions", bin.fns.functions().size()},
                 {"xrefs", bin.xrefs.total()},
                 {"strings", bin.strings.size()}};
        std::cerr << "[bench] load " << label << " run " << run << ": " << elapsed
                  << " ms" << std::endl;
        for (const auto& entry : slop::core::infra::diag::snapshot(diag_rev).entries)
            if (entry.tag == "disasm" || entry.tag == "fnindex")
                std::cerr << "[diag] " << entry.tag << ": " << entry.message << std::endl;
        diag_rev = slop::core::infra::diag::revision();
        load_ms.push_back(elapsed);
        binary_state::unload();
    }
    return {{"label", label}, {"path", path}, {"load_runs_ms", load_ms},
            {"load_median_ms", median(load_ms)}, {"facts", facts}};
}
}

int main(int argc, char** argv) {
    // the analyzer logs its per-phase timings at debug
    spdlog::set_level(spdlog::level::debug);
    std::string output_path;
    // --image label=path may repeat; when given it replaces the built-in pair
    // so a real-world binary can be profiled without editing the harness
    std::vector<std::pair<std::string, std::string>> images;
    int runs = 6;
    bool load_only = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--output" && i + 1 < argc) { output_path = argv[++i]; continue; }
        if (arg == "--runs" && i + 1 < argc) { runs = std::atoi(argv[++i]); continue; }
        if (arg == "--load") { load_only = true; continue; }
        if (arg == "--image" && i + 1 < argc) {
            const std::string spec = argv[++i];
            const size_t eq = spec.find('=');
            if (eq == std::string::npos) images.emplace_back(spec, spec);
            else images.emplace_back(spec.substr(0, eq), spec.substr(eq + 1));
        }
    }
    if (runs < 1) runs = 1;

    try {
        nlohmann::json result;
        if (images.empty()) {
            result["images"] = nlohmann::json::array({
                benchmark_image("o0", SLOP_DECOMP_TARGET_O0_PATH, runs, true),
                benchmark_image("o2", SLOP_DECOMP_TARGET_O2_PATH, runs, true),
            });
        } else {
            result["images"] = nlohmann::json::array();
            for (const auto& [label, path] : images)
                result["images"].push_back(load_only ? benchmark_load(label, path, runs)
                                                     : benchmark_image(label, path, runs, false));
        }
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
