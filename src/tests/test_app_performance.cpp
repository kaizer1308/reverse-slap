#include "harness.hpp"
#include "core/memory/memscan.hpp"
#include "core/network/traffic_store.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/event_bus.hpp"
#include "core/mcp/mcp_tools.hpp"
#include <algorithm>
#include <cstring>
#include <limits>

using namespace slop::core;

TEST_CASE(app_perf_stream_slices_match_concatenation) {
    network::traffic_store_t store;
    network::packet_record_t packet;
    packet.protocol = 6; packet.payload = {1, 2, 3};
    store.add(packet);
    packet.direction = 1; packet.payload = {4, 5}; store.add(packet);
    const std::vector<uint8_t> merged{1, 2, 3, 4, 5};
    for (size_t offset = 0; offset < 8; ++offset) {
        for (size_t len : {size_t{0}, size_t{1}, size_t{3}, size_t{10}, std::numeric_limits<size_t>::max()}) {
            const size_t start = std::min(offset, merged.size());
            const size_t take = std::min(len, merged.size() - start);
            const auto actual = store.stream_bytes(1, offset, len);
            REQUIRE(actual.has_value());
            CHECK(*actual == std::vector<uint8_t>(merged.begin() + start, merged.begin() + start + take));
        }
    }
    CHECK(!store.stream_bytes(999, 0, 2));
}

TEST_CASE(app_perf_diag_tail_and_revision) {
    infra::diag::init();
    for (int i = 0; i < 9000; ++i) infra::diag::info("test", std::to_string(i));
    auto tail = infra::diag::snapshot(0, 2);
    REQUIRE(tail.entries.size() == 2);
    CHECK(tail.entries[0].message == "8998");
    CHECK(tail.revision == 9000);
    CHECK(infra::diag::snapshot(8999, 32).entries.size() == 1);
    CHECK(infra::diag::snapshot(9000, 32).entries.empty());
    CHECK(infra::diag::snapshot(0, 0).entries.empty());
    bool error = false;
    const auto reply = mcp::call_tool("app", {{"action", "diag"}, {"limit", 2}}, error);
    CHECK(!error);
    CHECK(reply.dump().find("8999") != std::string::npos);
}

TEST_CASE(app_perf_output_cursor_eviction_and_clear) {
    infra::event_bus::reset();
    for (int i = 0; i < 5000; ++i) infra::event_bus::output("line");
    CHECK(infra::event_bus::output_since(0).size() == 4096);
    auto tail = infra::event_bus::output_since(4998);
    REQUIRE(tail.size() == 2);
    CHECK(tail.front().seq == 4999);
    CHECK(infra::event_bus::output_since(5000).empty());
    infra::event_bus::output_clear();
    infra::event_bus::output("after clear");
    CHECK(infra::event_bus::output_since(5000).size() == 1);
    infra::event_bus::reset();
}

TEST_CASE(app_perf_changed_event_serialization_and_dedup) {
    infra::event_bus::reset();
    auto subscriber = infra::event_bus::subscribe();
    const nlohmann::json data = {{"text", "a\nb"}, {"value", 42}};
    std::string frame;
    infra::event_bus::publish_changed("state", data);
    REQUIRE(subscriber->wait(frame, 0));
    CHECK(frame == "event: state\ndata: " + data.dump() + "\n\n");
    infra::event_bus::publish_changed("state", data);
    REQUIRE(subscriber->wait(frame, 0));
    CHECK(frame.empty());
    infra::event_bus::reset();
}

TEST_CASE(app_perf_dense_scan_stops_inside_chunk) {
    struct reader final : memory::reader_t {
        size_t calls = 0;
        bool read(uintptr_t, void* dst, size_t n) override {
            ++calls; std::memset(dst, 0, n); return true;
        }
    } r;
    for (bool all : {false, true}) {
        memory::scan_config_t cfg;
        cfg.width = memory::value_width_t::u8;
        cfg.max_results = 3; cfg.threads = 1; cfg.scan_all_types = all;
        cfg.chunk_bytes = 4096;
        memory::memscan_t scan;
        r.calls = 0;
        REQUIRE(scan.first_scan(r, {{0x10000, 1024 * 1024, 4, 0x20000}}, cfg, {}));
        CHECK(scan.results().size() == 3);
        CHECK(scan.stats().truncated);
        CHECK(r.calls == 1);
        CHECK(scan.stats().slots_scanned <= 3);
    }
}
