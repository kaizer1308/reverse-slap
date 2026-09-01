#pragma once

// raii wrapper over a unicorn x64 engine, headers stay confined to this folder

#include <cstdint>
#include <cstddef>

struct uc_struct;

namespace slop::core::emu {

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
