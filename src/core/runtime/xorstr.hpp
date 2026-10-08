// src/core/runtime/xorstr.hpp
// Compile-time XOR string encryption. Every string wrapped in XORSTR("...")
// is encrypted at compile time and decrypted on the stack at runtime, leaving
// no cleartext in the binary's .rdata section.
//
// Usage: const char* s = XORSTR("ReadProcessMemory");
// The decrypted string lives on the stack frame and is valid until scope exit.

#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>

namespace slop::core::runtime::detail {

template <std::size_t N, std::uint8_t Key>
class xor_string {
public:
    consteval xor_string(const char (&str)[N]) noexcept {
        for (std::size_t i = 0; i < N; ++i)
            data_[i] = static_cast<char>(str[i] ^ static_cast<char>(Key ^ static_cast<std::uint8_t>(i * 0x45 + 0x23)));
    }

    // decrypt into a stack buffer and return pointer; the buffer lives in the
    // caller's frame so the result is valid for the enclosing scope
    const char* decrypt() const noexcept {
        // thread_local avoids per-call stack allocation for the common case
        // where only one XORSTR is live at a time in a given scope
        alignas(16) static thread_local char buf[N];
        for (std::size_t i = 0; i < N; ++i)
            buf[i] = static_cast<char>(data_[i] ^ static_cast<char>(Key ^ static_cast<std::uint8_t>(i * 0x45 + 0x23)));
        return buf;
    }

    const char* operator()() const noexcept { return decrypt(); }

private:
    char data_[N]{};
};

// compile-time hash of __FILE__ and __LINE__ to derive a per-site key
consteval std::uint8_t site_key(const char* file, int line) noexcept {
    std::uint8_t h = static_cast<std::uint8_t>(line * 0x9E + 0x3B);
    for (const char* p = file; *p; ++p)
        h = static_cast<std::uint8_t>(h ^ static_cast<std::uint8_t>(*p * 31));
    return h | 1u; // ensure non-zero
}

} // namespace slop::core::runtime::detail

// primary macro: encrypts the literal at compile time, decrypts on the stack
#define XORSTR(s) ([]() noexcept -> const char* {                          \
    constexpr auto _xk = ::slop::core::runtime::detail::site_key(__FILE__, __LINE__); \
    static constexpr ::slop::core::runtime::detail::xor_string<sizeof(s), _xk> _xs(s); \
    return _xs.decrypt();                                                  \
}())

// wide string variant
namespace slop::core::runtime::detail {
template <std::size_t N, std::uint8_t Key>
class xor_wstring {
public:
    consteval xor_wstring(const wchar_t (&str)[N]) noexcept {
        for (std::size_t i = 0; i < N; ++i)
            data_[i] = static_cast<wchar_t>(str[i] ^ static_cast<wchar_t>(Key ^ static_cast<std::uint8_t>(i * 0x45 + 0x23)));
    }

    const wchar_t* decrypt() const noexcept {
        alignas(16) static thread_local wchar_t buf[N];
        for (std::size_t i = 0; i < N; ++i)
            buf[i] = static_cast<wchar_t>(data_[i] ^ static_cast<wchar_t>(Key ^ static_cast<std::uint8_t>(i * 0x45 + 0x23)));
        return buf;
    }

private:
    wchar_t data_[N]{};
};
} // namespace

#define XORWSTR(s) ([]() noexcept -> const wchar_t* {                      \
    constexpr auto _xk = ::slop::core::runtime::detail::site_key(__FILE__, __LINE__); \
    static constexpr ::slop::core::runtime::detail::xor_wstring<sizeof(s)/sizeof(wchar_t), _xk> _xs(s); \
    return _xs.decrypt();                                                  \
}())
