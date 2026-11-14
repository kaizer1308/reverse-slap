#pragma once

// what one decoded instruction means to the emulator: whether the cpu core
// runs it correctly, whether its hook repeats, and where taint flows through
// it. Pure zydis, internal to core/emu

#include <cstddef>
#include <cstdint>

#include <Zydis/Zydis.h>

#include "core/emu/taint.hpp"

namespace slop::core::emu {

// F2/F3 on movs, cmps, stos, lods, scas, ins, outs: the code hook fires once
// per iteration of these
bool is_rep_string(const uint8_t* bytes, size_t n);

// A VEX instruction Unicorn's x86 core would run with the wrong result
// instead of rejecting it
bool vex_miscomputed(const ZydisDecodedInstruction& zin, const ZydisDecodedOperand* ops);

// One instruction's operands as taint sources and destinations, given the
// taint the registers hold before it runs
taint_tracker_t::insn_sources_t taint_sources(const taint_tracker_t& taint,
                                              const ZydisDecodedInstruction& zin,
                                              const ZydisDecodedOperand* ops);

} // namespace slop::core::emu
