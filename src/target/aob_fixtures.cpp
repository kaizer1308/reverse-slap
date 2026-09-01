#include "aob_fixtures.hpp"

namespace slop_target {

volatile int32_t g_aob_sentinel = 0xDEAD;

// Disable optimizations so instruction layout is predictable for AOB testing
#pragma optimize("", off)

__declspec(noinline) int32_t aob_unique_fn() {
    // rip-relative access to g_aob_sentinel (generates a disp32)
    // + compare with 32-bit immediate (generates an imm32)
    int32_t val = g_aob_sentinel;
    if (val == 0x13374242) {
        return val + 1;
    }
    return val * 3 + 0x7F;
}

__declspec(noinline) int32_t aob_twin_a() {
    // Identical prologue to twin_b, tests uniqueness scoring
    int32_t x = 0;
    for (int i = 0; i < 10; ++i) {
        x += i * 3;
    }
    // Differing tail: addition
    return x + 0xAAAA;
}

__declspec(noinline) int32_t aob_twin_b() {
    // Identical prologue to twin_a, tests uniqueness scoring
    int32_t x = 0;
    for (int i = 0; i < 10; ++i) {
        x += i * 3;
    }
    // Differing tail: subtraction
    return x - 0xBBBB;
}

#pragma optimize("", on)

uint64_t aob_unique_fn_addr() { return reinterpret_cast<uint64_t>(&aob_unique_fn); }
uint64_t aob_twin_a_addr()    { return reinterpret_cast<uint64_t>(&aob_twin_a); }
uint64_t aob_twin_b_addr()    { return reinterpret_cast<uint64_t>(&aob_twin_b); }

} // namespace slop_target
