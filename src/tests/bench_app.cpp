#include "core/memory/memscan.hpp"
#include "core/network/traffic_store.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/diag.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/mcp/mcp_tools.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <new>
#include <stdexcept>

namespace {
std::atomic<bool> measuring{false};
std::atomic<size_t> allocated{0}, allocations{0}, largest{0};
}

void* operator new(size_t n) {
    void* p = std::malloc(n ? n : 1);
    if (!p) throw std::bad_alloc{};
    if (measuring.load(std::memory_order_relaxed)) {
        allocated.fetch_add(n, std::memory_order_relaxed);
        allocations.fetch_add(1, std::memory_order_relaxed);
        auto old = largest.load();
        while (old < n && !largest.compare_exchange_weak(old, n)) {}
    }
    return p;
}
void* operator new[](size_t n) { return ::operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, size_t) noexcept { std::free(p); }
void operator delete[](void* p, size_t) noexcept { std::free(p); }

using namespace slop::core;
using json = nlohmann::json;

class buffer_reader final : public memory::reader_t {
public:
    std::vector<uint8_t> bytes = std::vector<uint8_t>(4 * 1024 * 1024, 42);
    bool read(uintptr_t addr, void* dst, size_t len) override {
        if (addr < 0x10000 || addr - 0x10000 > bytes.size() ||
            len > bytes.size() - (addr - 0x10000)) return false;
        std::memcpy(dst, bytes.data() + addr - 0x10000, len);
        return true;
    }
};

template<class F>
json bench(const char* name, int iterations, F&& fn) {
    const auto expected = fn();
    std::vector<double> samples;
    for (int run = 0; run < 7; ++run) {
        const auto start = std::chrono::steady_clock::now();
        for (int i = 0; i < iterations; ++i)
            if (fn() != expected) throw std::runtime_error("unstable benchmark result");
        samples.push_back(std::chrono::duration<double, std::milli>(
            std::chrono::steady_clock::now() - start).count() / iterations);
    }
    allocated = 0; allocations = 0; largest = 0;
    measuring = true;
    const auto actual = fn();
    measuring = false;
    if (actual != expected) throw std::runtime_error("allocation pass result differs");
    auto sorted = samples;
    std::sort(sorted.begin(), sorted.end());
    return {{"name", name}, {"median_ms", sorted[3]}, {"samples_ms", samples},
        {"result", expected}, {"iterations", iterations},
        {"allocated_bytes", allocated.load()}, {"allocations", allocations.load()},
        {"largest_allocation_bytes", largest.load()}};
}

int main(int argc, char** argv) {
    json rows = json::array();
    buffer_reader reader;
    auto scan = [&] {
        memory::scan_config_t cfg;
        cfg.width = memory::value_width_t::u8; cfg.value1 = 42;
        cfg.threads = 1; cfg.max_results = 1000;
        memory::memscan_t scanner;
        scanner.first_scan(reader, {{0x10000, reader.bytes.size(), 4, 0x20000}}, cfg, {});
        uint64_t sum = 0;
        for (const auto& hit : scanner.results()) sum += hit.address + hit.bits;
        return sum;
    };
    rows.push_back(bench("scan_dense_4m_cap1000", 1, scan));
    std::fill(reader.bytes.begin(), reader.bytes.end(), uint8_t{0});
    reader.bytes.back() = 42;
    rows.push_back(bench("scan_sparse_4m", 2, scan));

    network::traffic_store_t traffic(2);
    network::packet_record_t pkt;
    pkt.protocol = 6; pkt.local_addr = "127.0.0.1"; pkt.remote_addr = "10.0.0.1";
    pkt.payload.assign(1024 * 1024, 65);
    traffic.add(pkt); pkt.direction = 1; traffic.add(pkt);
    rows.push_back(bench("traffic_slice_4k_from_2m", 200, [&] {
        auto bytes = traffic.stream_bytes(1, 1024 * 1024 - 2048, 4096);
        uint64_t sum = 0; for (auto b : *bytes) sum += b; return sum;
    }));
    infra::event_bus::reset();
    for (int i = 0; i < 4096; ++i) infra::event_bus::output("benchmark output entry");
    rows.push_back(bench("output_idle_4096", 1000, [] {
        return infra::event_bus::output_since(4096).size();
    }));
    auto subscriber = infra::event_bus::subscribe();
    json payload = {{"values", std::vector<int>(4096, 42)}};
    uint64_t seq = 0;
    rows.push_back(bench("event_changed_16k", 50, [&] {
        payload["seq"] = ++seq;
        infra::event_bus::publish_changed("bench", payload);
        std::string frame; subscriber->wait(frame, 0);
        return frame.empty() ? 0 : 1;
    }));
    infra::diag::init();
    for (int i = 0; i < 8192; ++i) infra::diag::info("bench", std::string(128, 'x'));
    {
        std::lock_guard lock(disasm::binary_state::state_mutex());
        auto& symbols = disasm::binary_state::get().symbols;
        for (uint64_t i = 0; i < 100000; ++i) symbols[i + 0x10000] = "benchmark_symbol_" + std::to_string(i);
    }
    for (const auto* action : {"output", "diag"}) {
        rows.push_back(bench(action, 10, [&] {
            bool error = false;
            auto result = mcp::call_tool("app", {{"action", action}, {"since", 4096}, {"limit", 32}}, error);
            if (error) throw std::runtime_error(result.dump());
            return result.dump().size();
        }));
    }
    json report = {{"schema", 1}, {"runs", 7}, {"compiler_msvc", _MSC_VER},
        {"memory_metric", "ordinary C++ requested allocation volume in separate pass; not peak RSS; excludes malloc/aligned allocations"},
        {"workloads", rows}};
    if (argc > 1) { std::ofstream out(argv[1]); out << report.dump(2) << '\n'; }
    std::cout << report.dump(2) << '\n';
}
