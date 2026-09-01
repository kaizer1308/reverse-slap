// src/tests/test_main.cpp
// Entry point for slop_tests, runs all registered test cases

#include "harness.hpp"

int main() {
    // Unbuffered so a hard crash never swallows progress output
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    return slop_test::run_all();
}
