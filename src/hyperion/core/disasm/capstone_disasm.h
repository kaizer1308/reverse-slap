#pragma once
#include "core/types.h"
#include "disassembler.h"
#include <memory>
#include <vector>
#include <functional>

namespace hype {

class CapstoneDisasm {
public:
    CapstoneDisasm();
    ~CapstoneDisasm();

    void set_arch(Arch arch);
    bool decode(va_t addr, const u8* data, size_t len, Insn& out);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len);
    std::vector<Insn> decode_range(va_t start, const u8* data, size_t len,
                                   const std::function<bool()>& cancelled);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
