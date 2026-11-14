#pragma once

// raii wrapper over a unicorn x64 engine, headers stay confined to this folder

#include <cstdint>
#include <cstddef>

struct uc_struct;

namespace slop::core::emu {

// Unicorn runs x86-64 without paging and truncates every address to 52 bits
// before it looks memory up, so a kernel-half va (0xFFFF8000'00000000 and up)
// is backed by its low 52 bits. map/read/write take real vas and fold them;
// memory hooks report the folded address and unfold_addr gives the va back
constexpr uint64_t fold_addr(uint64_t va) noexcept { return va & 0x000FFFFFFFFFFFFFull; }
constexpr uint64_t unfold_addr(uint64_t a) noexcept {
    // bits 47..51 all set only happens for a folded kernel-half address
    return (a >> 47) == 0x1F ? a | 0xFFF0000000000000ull : a;
}

class unicorn_t {
public:
    unicorn_t();                                   // UC_ARCH_X86 / UC_MODE_64
    ~unicorn_t();

    unicorn_t(const unicorn_t&)            = delete;
    unicorn_t& operator=(const unicorn_t&) = delete;

    bool     ok() const noexcept { return uc_ != nullptr; }
    uc_struct* handle() const noexcept { return uc_; }

    // Page-aligned internally; sizes rounded up to 4 KiB
    bool map(uint64_t addr, size_t len);
    bool write(uint64_t addr, const void* data, size_t len);
    bool read(uint64_t addr, void* out, size_t len) const;

private:
    uc_struct* uc_ = nullptr;
};

} // namespace slop::core::emu
