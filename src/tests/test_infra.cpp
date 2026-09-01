// src/tests/test_infra.cpp
// Tests for core/infra: cancel, published, pool, jobs, diag, text_format

#include "harness.hpp"

#include "core/infra/cancel.hpp"
#include "core/infra/published.hpp"
#include "core/infra/work_queue.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/text_format.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/capability.hpp"

#include <atomic>
#include <chrono>
#include <thread>
#include <vector>

// === cancel ===

TEST_CASE(cancel_token_default_not_cancelled) {
    slop::core::infra::cancel_token_t tok;
    REQUIRE(!tok.cancelled());
}

TEST_CASE(cancel_source_request) {
    slop::core::infra::cancel_source_t src;
    auto tok = src.token();
    REQUIRE(!tok.cancelled());
    src.request();
    REQUIRE(tok.cancelled());
    REQUIRE(src.requested());
}

TEST_CASE(cancel_multiple_tokens_share_flag) {
    slop::core::infra::cancel_source_t src;
    auto t1 = src.token();
    auto t2 = src.token();
    src.request();
    REQUIRE(t1.cancelled());
    REQUIRE(t2.cancelled());
}

// === published ===

TEST_CASE(published_default_non_null) {
    slop::core::infra::published_t<int> pub;
    auto val = pub.get();
    REQUIRE(val != nullptr);
    REQUIRE_EQ(*val, 0);
}

TEST_CASE(published_publish_updates_value) {
    slop::core::infra::published_t<int> pub;
    pub.publish(std::make_shared<const int>(42));
    REQUIRE_EQ(*pub.get(), 42);
    REQUIRE_EQ(pub.revision(), 1u);
}

TEST_CASE(published_revision_increments) {
    slop::core::infra::published_t<int> pub;
    pub.publish(std::make_shared<const int>(1));
    pub.publish(std::make_shared<const int>(2));
    pub.publish(std::make_shared<const int>(3));
    REQUIRE_EQ(pub.revision(), 3u);
    REQUIRE_EQ(*pub.get(), 3);
}

// === capability ===

TEST_CASE(command_state_ok) {
    auto cs = slop::core::infra::command_state_t::ok();
    REQUIRE(cs.enabled);
    REQUIRE(cs.disabled_reason == nullptr);
    REQUIRE(static_cast<bool>(cs));
}

TEST_CASE(command_state_no) {
    auto cs = slop::core::infra::command_state_t::no("not attached");
    REQUIRE(!cs.enabled);
    REQUIRE_STR_EQ(cs.disabled_reason, "not attached");
    REQUIRE(!static_cast<bool>(cs));
}

// === text_format ===

TEST_CASE(format_hex_basic) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto s = slop::core::infra::fmt::format_hex(data);
    REQUIRE_STR_EQ(s, "DE AD BE EF");
}

TEST_CASE(format_as_c_array) {
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::c_array);
    REQUIRE_STR_EQ(s, "{ 0x01, 0x02, 0x03 }");
}

TEST_CASE(format_as_python_bytes) {
    std::vector<uint8_t> data = {0xCA, 0xFE};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::python_bytes);
    REQUIRE_STR_EQ(s, "b'\\xCA\\xFE'");
}

TEST_CASE(format_as_rust_array) {
    std::vector<uint8_t> data = {0xAA, 0xBB};
    auto s = slop::core::infra::fmt::format_as(data, slop::core::infra::fmt::copy_dialect_t::rust_array);
    REQUIRE_STR_EQ(s, "[0xAA, 0xBB]");
}

TEST_CASE(parse_hex_spaced) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("DE AD BE EF", out, err));
    REQUIRE_EQ(out.size(), 4u);
    REQUIRE_EQ(out[0], 0xDE);
    REQUIRE_EQ(out[3], 0xEF);
}

TEST_CASE(parse_hex_compact) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("DEADBEEF", out, err));
    REQUIRE_EQ(out.size(), 4u);
}

TEST_CASE(parse_hex_0x_prefix) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(slop::core::infra::fmt::parse_hex("0xDE, 0xAD", out, err));
    REQUIRE_EQ(out.size(), 2u);
    REQUIRE_EQ(out[0], 0xDE);
    REQUIRE_EQ(out[1], 0xAD);
}

TEST_CASE(parse_hex_odd_digits_fails) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(!slop::core::infra::fmt::parse_hex("DEA", out, err));
    REQUIRE(err.find("odd") != std::string::npos);
}

TEST_CASE(parse_hex_invalid_char_fails) {
    std::vector<uint8_t> out;
    std::string err;
    REQUIRE(!slop::core::infra::fmt::parse_hex("DXAD", out, err));
    REQUIRE(err.find("invalid") != std::string::npos);
}

TEST_CASE(format_address_64bit) {
    auto s = slop::core::infra::fmt::format_address(0x7FF6ABCD1234, 8);
    REQUIRE_STR_EQ(s, "0x00007FF6ABCD1234");
}

TEST_CASE(format_address_32bit) {
    auto s = slop::core::infra::fmt::format_address(0x00401000, 4);
    REQUIRE_STR_EQ(s, "0x00401000");
}

TEST_CASE(format_bytes_units) {
    REQUIRE(slop::core::infra::fmt::format_bytes(512).find("B") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2048).find("KiB") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2u << 20).find("MiB") != std::string::npos);
    REQUIRE(slop::core::infra::fmt::format_bytes(2ull << 30).find("GiB") != std::string::npos);
}

// === diag ===

TEST_CASE(diag_log_and_snapshot) {
    slop::core::infra::diag::init();
    slop::core::infra::diag::info("test", "hello world");
    slop::core::infra::diag::warn("test", "warning msg");
    auto snap = slop::core::infra::diag::snapshot(0);
    REQUIRE_EQ(snap.entries.size(), 2u);
    REQUIRE_STR_EQ(snap.entries[0].tag, "test");
    REQUIRE_STR_EQ(snap.entries[0].message, "hello world");
    REQUIRE_EQ(snap.entries[0].level, slop::core::infra::diag::level_t::info);
    REQUIRE_EQ(snap.entries[1].level, slop::core::infra::diag::level_t::warn);
    REQUIRE_EQ(snap.revision, 2u);
    slop::core::infra::diag::shutdown();
}

TEST_CASE(diag_snapshot_since_revision) {
    slop::core::infra::diag::init();
    slop::core::infra::diag::info("a", "one");
    slop::core::infra::diag::info("b", "two");
    slop::core::infra::diag::info("c", "three");
    auto snap = slop::core::infra::diag::snapshot(1);
    // revision 1 means "give me entries after revision 1" = entries 2 and 3
    REQUIRE_EQ(snap.entries.size(), 2u);
    REQUIRE_STR_EQ(snap.entries[0].message, "two");
    slop::core::infra::diag::shutdown();
}

// === clock ===

TEST_CASE(clock_steady_ms_positive) {
    auto ms = slop::core::infra::steady_ms();
    REQUIRE(ms > 0);
}

TEST_CASE(clock_wall_ms_reasonable) {
    auto ms = slop::core::infra::wall_ms();
    // Should be after 2020-01-01 in epoch ms
    REQUIRE(ms > 1577836800000LL);
}

// === pool ===

TEST_CASE(pool_submit_and_complete) {
    slop::core::infra::pool::start(2);
    std::atomic<int> counter{0};
    for (int i = 0; i < 100; ++i) {
        slop::core::infra::pool::submit([&] { counter.fetch_add(1); });
    }
    // Wait for completion
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    auto stats = slop::core::infra::pool::snapshot();
    REQUIRE_EQ(counter.load(), 100);
    REQUIRE(stats.completed >= 100u);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(pool_parallel_for_basic) {
    slop::core::infra::pool::start(4);
    std::vector<std::atomic<int>> results(50);
    for (auto& a : results) a.store(0);

    slop::core::infra::cancel_source_t src;
    slop::core::infra::pool::parallel_for(50, src.token(),
        [&](size_t idx, uint32_t /*slot*/) {
            results[idx].store(static_cast<int>(idx * 2));
        });

    for (size_t i = 0; i < 50; ++i) {
        REQUIRE_EQ(results[i].load(), static_cast<int>(i * 2));
    }
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(pool_parallel_for_cancel) {
    slop::core::infra::pool::start(4);
    std::atomic<int> count{0};
    slop::core::infra::cancel_source_t src;

    // Cancel after a short delay
    std::thread canceller([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        src.request();
    });

    slop::core::infra::pool::parallel_for(1000000, src.token(),
        [&](size_t /*idx*/, uint32_t /*slot*/) {
            count.fetch_add(1);
            std::this_thread::sleep_for(std::chrono::microseconds(1));
        });

    canceller.join();
    // Should have been cancelled before completing all 1M items
    REQUIRE(count.load() < 1000000);
    slop::core::infra::pool::stop(1000);
}

// === jobs ===

TEST_CASE(jobs_submit_and_complete) {
    slop::core::infra::pool::start(2);
    std::atomic<bool> ran{false};

    auto id = slop::core::infra::jobs::submit({
        .label = "test job",
        .owner = "test",
        .body = [&](slop::core::infra::job_context_t& ctx) {
            (void)ctx;
            ran.store(true);
        }
    });
    REQUIRE(id != 0);

    // Wait for it to finish
    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(!slop::core::infra::jobs::alive(id));
    REQUIRE(ran.load());

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    REQUIRE(snap != nullptr);
    REQUIRE(!snap->empty());
    REQUIRE_EQ((*snap)[0].state, slop::core::infra::job_state_t::succeeded);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(jobs_cancel) {
    slop::core::infra::jobs::reset();
    slop::core::infra::pool::start(2);

    auto id = slop::core::infra::jobs::submit({
        .label = "cancellable",
        .owner = "test",
        .cancellable = true,
        .body = [](slop::core::infra::job_context_t& ctx) {
            while (!ctx.cancelled()) {
                std::this_thread::sleep_for(std::chrono::milliseconds(5));
            }
        }
    });
    REQUIRE(id != 0);

    std::this_thread::sleep_for(std::chrono::milliseconds(20));
    REQUIRE(slop::core::infra::jobs::cancel(id));

    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    REQUIRE(!slop::core::infra::jobs::alive(id));

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    bool found_cancelled = false;
    for (auto& j : *snap) {
        if (j.id == id && j.state == slop::core::infra::job_state_t::cancelled)
            found_cancelled = true;
    }
    REQUIRE(found_cancelled);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}

TEST_CASE(jobs_progress_reporting) {
    slop::core::infra::jobs::reset();
    slop::core::infra::pool::start(2);

    auto id = slop::core::infra::jobs::submit({
        .label = "progress test",
        .owner = "test",
        .body = [](slop::core::infra::job_context_t& ctx) {
            ctx.set_stage("step 1");
            ctx.set_progress(0.5f);
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
            ctx.set_stage("step 2");
            ctx.set_progress(1.0f);
        }
    });

    for (int i = 0; i < 100 && slop::core::infra::jobs::alive(id); ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    slop::core::infra::jobs::reap();
    auto snap = slop::core::infra::jobs::snapshot();
    bool found = false;
    for (auto& j : *snap) {
        if (j.id == id) {
            found = true;
            REQUIRE_EQ(j.state, slop::core::infra::job_state_t::succeeded);
        }
    }
    REQUIRE(found);

    slop::core::infra::jobs::shutdown(1000);
    slop::core::infra::pool::stop(1000);
}
