#pragma once

#include <cstdint>

#ifndef SLOP_STEALTH_SEED
#define SLOP_STEALTH_SEED "slopdrvr-reverse-slap-2026-10"
#endif

namespace slop_stealth {

constexpr std::uint64_t fnv1a64(const char* text) {
    std::uint64_t h = 14695981039346656037ull;
    while (*text) {
        h ^= static_cast<unsigned char>(*text);
        h *= 1099511628211ull;
        ++text;
    }
    return h;
}

constexpr std::uint64_t kSeedHash = fnv1a64(SLOP_STEALTH_SEED);

constexpr std::uint32_t kIoctlFunctionBase =
    0x100u + static_cast<std::uint32_t>((kSeedHash >> 32) & 0x6FFu);

constexpr char kDeviceLeafHex[13] = {
    "0123456789ABCDEF"[(kSeedHash >> 60) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 56) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 52) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 48) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 44) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 40) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 36) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 32) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 28) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 24) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 20) & 0xF],
    "0123456789ABCDEF"[(kSeedHash >> 16) & 0xF],
    '\0'
};

__forceinline std::uint64_t mix64(std::uint64_t x) {
    x ^= x >> 30;
    x *= 0xBF58476D1CE4E5B9ull;
    x ^= x >> 27;
    x *= 0x94D049BB133111EBull;
    x ^= x >> 31;
    return x;
}

__forceinline std::uint64_t auth_response(std::uint64_t boot_nonce, std::uint64_t pid) {
    return mix64(kSeedHash ^ boot_nonce ^ pid);
}

} // namespace slop_stealth
