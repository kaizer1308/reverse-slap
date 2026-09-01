#pragma once

// src/tests/harness.hpp
// Minimal test harness, no external deps. Reports pass/fail per test case

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <functional>
#include <stdexcept>

namespace slop_test {

struct test_case_t {
    const char* name;
    std::function<void()> fn;
};

inline std::vector<test_case_t>& registry() {
    static std::vector<test_case_t> r;
    return r;
}

inline int g_failures = 0;
inline int g_assertions = 0;
inline const char* g_current_test = nullptr;

struct registrar_t {
    registrar_t(const char* name, std::function<void()> fn) {
        registry().push_back({name, std::move(fn)});
    }
};

#define TEST_CASE(name) \
    static void test_##name(); \
    static slop_test::registrar_t reg_##name(#name, test_##name); \
    static void test_##name()

#define CHECK(expr) do { \
    ++slop_test::g_assertions; \
    if (!(expr)) { \
        std::printf("  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE(expr) do { \
    ++slop_test::g_assertions; \
    if (!(expr)) { \
        std::printf("  FAIL: %s:%d: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
        throw std::runtime_error("fatal test prerequisite failed"); \
    } \
} while(0)

#define REQUIRE_EQ(a, b) do { \
    ++slop_test::g_assertions; \
    if ((a) != (b)) { \
        std::printf("  FAIL: %s:%d: %s != %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_STR_EQ(a, b) do { \
    ++slop_test::g_assertions; \
    if (std::string(a) != std::string(b)) { \
        std::printf("  FAIL: %s:%d: \"%s\" != \"%s\"\n", __FILE__, __LINE__, \
            std::string(a).c_str(), std::string(b).c_str()); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_GE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) >= (b))) { \
        std::printf("  FAIL: %s:%d: %s < %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_LE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) <= (b))) { \
        std::printf("  FAIL: %s:%d: %s > %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_LT(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) < (b))) { \
        std::printf("  FAIL: %s:%d: %s >= %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_NE(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) != (b))) { \
        std::printf("  FAIL: %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_FALSE(expr) do { \
    ++slop_test::g_assertions; \
    if ((expr)) { \
        std::printf("  FAIL: %s:%d: expected false: %s\n", __FILE__, __LINE__, #expr); \
        ++slop_test::g_failures; \
    } \
} while(0)

#define REQUIRE_GT(a, b) do { \
    ++slop_test::g_assertions; \
    if (!((a) > (b))) { \
        std::printf("  FAIL: %s:%d: %s <= %s\n", __FILE__, __LINE__, #a, #b); \
        ++slop_test::g_failures; \
    } \
} while(0)

inline int run_all() {
    int passed = 0, failed = 0;
    const char* filter = std::getenv("SLOP_TEST_FILTER");
    for (auto& tc : registry()) {
        if (filter && *filter && std::strstr(tc.name, filter) == nullptr) continue;
        g_current_test = tc.name;
        int before = g_failures;
        std::printf("[RUN ] %s\n", tc.name);
        try {
            tc.fn();
        } catch (const std::exception& e) {
            std::printf("  FAIL: %s threw: %s\n", tc.name, e.what());
            ++g_failures;
        } catch (...) {
            std::printf("  FAIL: %s threw unknown exception\n", tc.name);
            ++g_failures;
        }
        if (g_failures == before) {
            std::printf("[PASS] %s\n", tc.name);
            ++passed;
        } else {
            std::printf("[FAIL] %s\n", tc.name);
            ++failed;
        }
    }
    std::printf("\n=== %d passed, %d failed, %d assertions ===\n",
        passed, failed, g_assertions);
    return failed > 0 ? 1 : 0;
}

} // namespace slop_test
