#pragma once

// minimal read abstraction, a session in production and a fake in tests

#include <cstddef>
#include <cstdint>

namespace slop::core::memory {

class reader_t {
public:
    virtual ~reader_t() = default;

    // Read len bytes at addr. Returns false if any part is unreadable
    // (unmapped, no access, target died). Partial reads never happen
    virtual bool read(uintptr_t addr, void* dst, size_t len) = 0;
};

} // namespace slop::core::memory
