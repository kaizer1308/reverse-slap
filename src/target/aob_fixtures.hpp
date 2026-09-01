#pragma once

// src/target/aob_fixtures.hpp
// Functions with known instruction patterns for AOB signature generation testing

#include <cstdint>

namespace slop_target {

// Contains a rip-relative mov + 32-bit immediate compare
// Gives the wildcarder both a raw.disp and a raw.imm span
extern volatile int32_t g_aob_sentinel;

#pragma optimize("", off)
__declspec(noinline) int32_t aob_unique_fn();
__declspec(noinline) int32_t aob_twin_a();
__declspec(noinline) int32_t aob_twin_b();
#pragma optimize("", on)

uint64_t aob_unique_fn_addr();
uint64_t aob_twin_a_addr();
uint64_t aob_twin_b_addr();

} // namespace slop_target
