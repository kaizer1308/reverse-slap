#pragma once

// src/target/known_values.hpp
// Known-address value bank for scanner testing

#include <cstdint>

namespace slop_target {

struct value_bank_t {
    volatile int32_t  health        = 1000;
    volatile int32_t  score         = 0;
    volatile int16_t  ammo          = 30;
    volatile int64_t  gold          = 1'000'000;
    volatile int8_t   level_signed  = 7;
    volatile uint8_t  level_unsigned = 7;
    volatile float    speed         = 1.5f;
    volatile double   precision     = 3.14159265358979;
    volatile char     player_name[32]  = "SlopPlayer";
    volatile wchar_t  wide_name[32]    = L"SlopWide";
    volatile uint8_t  magic_bytes[16]  = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x13, 0x37, 0xC0, 0xDE, 0xFA, 0xCE, 0xD0, 0x0D
    };
    volatile int32_t  frozen_probe  = 0;
};

// Static instance in .data for stable addresses
extern value_bank_t g_values;

// Heap-allocated instance for a second target
extern value_bank_t* g_heap_values;

void values_init();
void values_tick();
void values_set(const char* name, const char* value);
void values_inc(const char* name);
void values_dec(const char* name);

} // namespace slop_target
