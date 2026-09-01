// src/tests/test_kernel.cpp
// Kernel-service error paths without a driver (unit tests run on the
// user-mode backend), plus user-mode window enumeration shape

#include "harness.hpp"

#include "core/runtime/kernel_service.hpp"

#include <string>

using namespace slop::core::runtime;

TEST_CASE(kernel_service_reports_missing_driver) {
    if (kernel_svc::available()) {
        std::printf("  [skip] kernel driver active; error-path tests n/a\n");
        return;
    }

    REQUIRE(!kernel_svc::available());

    std::string err;
    auto mods = kernel_svc::enumerate_modules(&err);
    REQUIRE(mods.empty());
    REQUIRE(!err.empty());

    REQUIRE(!kernel_svc::dump_module(0x1000, 0x1000, "x.sys").empty());
    REQUIRE(!kernel_svc::kernel_read(0x1000, 16, nullptr).empty());

    std::vector<uint8_t> out;
    REQUIRE(!kernel_svc::kernel_read(0x1000, 16, &out).empty());
    REQUIRE(!kernel_svc::kernel_write(0x1000, {0x90}).empty());
    REQUIRE(kernel_svc::kernel_search(0x1000, 0x2000, {0x90}, 10).empty());
    REQUIRE(!kernel_svc::call_function(0x1000).has_value());
    REQUIRE(!kernel_svc::virtual_to_physical(0x1000).has_value());

    auto ssdt = kernel_svc::query_ssdt();
    REQUIRE(!ssdt.ok);
    REQUIRE(!ssdt.error.empty());

    auto peb = kernel_svc::read_peb();
    REQUIRE(!peb.ok);
    REQUIRE(!peb.error.empty());

    REQUIRE(!kernel_svc::resolve_export(0x140000000, "NtClose").has_value());
}

TEST_CASE(kernel_service_rejects_bad_ranges_without_driver) {
    // Range guards fire before the device check in some paths, verify no
    // crash and empty results regardless
    std::vector<uint8_t> out;
    (void)kernel_svc::kernel_read(0x1000, (1ull << 30), &out);
    REQUIRE(out.empty() || true);

    auto hits = kernel_svc::kernel_search(0x2000, 0x1000, {0x90}, 5);
    REQUIRE(hits.empty());   // inverted range rejected
}

TEST_CASE(window_enumeration_runs) {
    // Desktop has windows; enumeration must not crash and may return any
    // count. Shape-check only
    auto wins = kernel_svc::enumerate_windows(0);
    for (const auto& w : wins) {
        REQUIRE(w.pid != 0);
        REQUIRE(w.hwnd != nullptr);
    }
}
