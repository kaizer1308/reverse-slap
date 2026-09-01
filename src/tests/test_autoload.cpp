// src/tests/test_autoload.cpp
// Boot-time driver autoload: artifact discovery + ensure_loaded state
// machine, exercised through injected probe/spawn lambdas

#include "harness.hpp"

#include "core/runtime/driver_autoload.hpp"

#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <process.h>
#include <fstream>
#include <string>
#include <vector>

using namespace slop::core::runtime::driver_autoload;

namespace {

std::string temp_dir_named(const char* suffix) {
    char p[MAX_PATH];
    std::snprintf(p, sizeof(p), "%s\\slop_al_%s_%u", std::getenv("TEMP"),
                  suffix, static_cast<unsigned>(::_getpid()));
    return p;
}

} // namespace

TEST_CASE(autoload_find_artifacts_build_layout) {
    // Simulate the build tree: build\app\<exe>, build\mapper\..., build\driver\..
    const std::string root = temp_dir_named("layout");
    CreateDirectoryA(root.c_str(), nullptr);
    const std::string app_dir = root + "\\app";
    CreateDirectoryA(app_dir.c_str(), nullptr);
    CreateDirectoryA((root + "\\mapper").c_str(), nullptr);
    CreateDirectoryA((root + "\\driver").c_str(), nullptr);

    { std::ofstream f(root + "\\mapper\\slop_mapper.exe"); f << "x"; }
    { std::ofstream f(root + "\\driver\\slopdrvr.sys"); f << "MZ"; }

    auto art = find_artifacts(app_dir);
    REQUIRE(art.mapper_found);
    REQUIRE(art.sys_found);
    REQUIRE(art.mapper_exe.find("mapper") != std::string::npos);
    REQUIRE(art.driver_sys.find("driver") != std::string::npos);
}

TEST_CASE(autoload_find_artifacts_side_by_side) {
    const std::string dir = temp_dir_named("flat");
    CreateDirectoryA(dir.c_str(), nullptr);
    { std::ofstream f(dir + "\\slop_mapper.exe"); f << "x"; }
    { std::ofstream f(dir + "\\slopdrvr.sys"); f << "MZ"; }

    auto art = find_artifacts(dir);
    REQUIRE(art.complete());
    REQUIRE(art.mapper_exe == dir + "\\slop_mapper.exe");
}

TEST_CASE(autoload_find_artifacts_missing_reports_incomplete) {
    const std::string dir = temp_dir_named("empty");
    CreateDirectoryA(dir.c_str(), nullptr);
    auto art = find_artifacts(dir);
    REQUIRE(!art.complete());
    REQUIRE(!art.mapper_found);
    RemoveDirectoryA(dir.c_str());
}

TEST_CASE(autoload_skips_spawn_when_already_loaded) {
    int spawn_calls = 0;
    auto report = ensure_loaded_with(
        true, "M", "S",
        [] { return true; },   // device present
        [&](const std::string&, const std::string&, std::string*) {
            ++spawn_calls;
            return 0;
        });
    REQUIRE(report.was_loaded);
    REQUIRE(report.ok);
    REQUIRE(!report.attempted);
    REQUIRE_EQ(spawn_calls, 0);
}

TEST_CASE(autoload_spawns_and_confirms) {
    int spawn_calls = 0;
    bool present_after_spawn = false;
    int probe_calls = 0;

    auto report = ensure_loaded_with(
        true, "M", "S",
        [&] {
            ++probe_calls;
            return probe_calls > 1;   // absent first, present after spawn
        },
        [&](const std::string& mapper, const std::string& sys,
            std::string* tail) {
            ++spawn_calls;
            REQUIRE(mapper == "M");
            REQUIRE(sys == "S");
            if (tail) *tail = "=== FINAL: load ok ===";
            present_after_spawn = true;
            return 0;
        });

    REQUIRE_EQ(spawn_calls, 1);
    REQUIRE(report.attempted);
    REQUIRE(report.ok);
    REQUIRE(!report.was_loaded);
    REQUIRE(present_after_spawn);
    REQUIRE(report.log_tail.find("FINAL") != std::string::npos);
}

TEST_CASE(autoload_mapper_failure_is_structured_not_fatal) {
    auto report = ensure_loaded_with(
        true, "M", "S",
        [] { return false; },
        [](const std::string&, const std::string&, std::string*) {
            return 3;   // mapper exit code 3
        });
    REQUIRE(report.attempted);
    REQUIRE(!report.ok);
    REQUIRE(report.error.find("3") != std::string::npos);
}

TEST_CASE(autoload_missing_artifacts_reported_without_spawn) {
    int spawn_calls = 0;
    auto report = ensure_loaded(
        "",   // no exe dir -> nothing discoverable
        [] { return false; },
        [&](const std::string&, const std::string&, std::string*) {
            ++spawn_calls;
            return 0;
        });
    REQUIRE(!report.attempted);
    REQUIRE(!report.ok);
    REQUIRE(!report.error.empty());
    REQUIRE_EQ(spawn_calls, 0);
}

// clean-shutdown state machine

TEST_CASE(unload_noop_when_driver_absent) {
    bool identity_called = false, shutdown_called = false,
         release_called = false;
    auto rep = request_unload_with(
        [] { return false; },                          // probe: absent
        [&](std::wstring&) { identity_called = true; return false; },
        [&] { shutdown_called = true; return true; },
        [&] { release_called = true; },
        [](const std::wstring&) -> long { return 0; });
    REQUIRE(!rep.was_loaded);
    REQUIRE(!rep.attempted);
    REQUIRE(rep.ok);                                   // clean by definition
    REQUIRE(!identity_called);
    REQUIRE(!shutdown_called);
    REQUIRE(!release_called);
}

TEST_CASE(unload_happy_path_queries_then_arms_then_unloads) {
    // Order matters: identity -> arm quiesce -> release handles -> unload
    std::vector<int> order;
    auto rep = request_unload_with(
        [] { return true; },
        [&](std::wstring& out) { order.push_back(1); out = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xAb12Cd"; return true; },
        [&] { order.push_back(2); return true; },
        [&] { order.push_back(3); },
        [&](const std::wstring& path) {
            order.push_back(4);
            REQUIRE_EQ(path, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\xAb12Cd");
            return 0;
        });
    REQUIRE(rep.was_loaded);
    REQUIRE(rep.attempted);
    REQUIRE(rep.ok);
    REQUIRE(rep.service_path.find("xAb12Cd") != std::string::npos);
    REQUIRE(order.size() == 4u);
    REQUIRE_EQ(order[0], 1);
    REQUIRE_EQ(order[1], 2);
    REQUIRE_EQ(order[2], 3);
    REQUIRE_EQ(order[3], 4);
}

TEST_CASE(unload_refuses_when_identity_query_fails) {
    // Driver present but won't tell us its service key (old build): we must
    // NOT arm the quiesce flag, the app would wedge itself out of the
    // driver with nothing to gain
    bool shutdown_called = false, release_called = false;
    auto rep = request_unload_with(
        [] { return true; },
        [](std::wstring&) { return false; },
        [&] { shutdown_called = true; return true; },
        [&] { release_called = true; },
        [](const std::wstring&) -> long { return 0; });
    REQUIRE(rep.was_loaded);
    REQUIRE(rep.attempted);
    REQUIRE(!rep.ok);
    REQUIRE(!rep.error.empty());
    REQUIRE(!shutdown_called);
    REQUIRE(!release_called);
}

TEST_CASE(unload_reports_service_refusal) {
    // Handles already released when the service refuses: state must say
    // !ok with the NTSTATUS in the error text
    auto rep = request_unload_with(
        [] { return true; },
        [](std::wstring& out) { out = L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\zz"; return true; },
        [] { return true; },
        [] {},
        [](const std::wstring&) -> long { return 0xC0000034L; }); // OBJECT_NAME_NOT_FOUND
    REQUIRE(rep.was_loaded);
    REQUIRE(!rep.ok);
    REQUIRE(rep.error.find("C0000034") != std::string::npos);
}

