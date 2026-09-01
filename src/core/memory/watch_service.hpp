#pragma once

// the watchlist with freeze writes, lifted out of the scanner view so the
// ui, agents and front ends all share one list, the app tick services it
// and values go out as a batched event

#include <cstdint>
#include <string>
#include <vector>

#include "core/memory/memscan.hpp"

namespace slop::core::memory::watch {

struct entry_t {
    uint64_t      id          = 0;
    uint64_t      addr        = 0;
    value_width_t width       = value_width_t::u32;
    std::string   label;
    bool          freeze      = false;
    uint64_t      frozen_bits = 0;
};

struct value_t {
    uint64_t    id   = 0;
    uint64_t    addr = 0;
    bool        ok   = false;   // live read succeeded on the last pass
    bool        held = false;   // value is being held by a freeze write
    uint64_t    bits = 0;
    std::string text;           // format_value_text(width, bits)
};

// Add an entry. Returns its id, or 0 when the watch cap is reached
uint64_t add(uint64_t addr, value_width_t width, std::string label);

bool remove(uint64_t id);
void clear();

// Toggle the freeze hold. Turning it on latches the most recently sampled
// value, matching the ImGui checkbox behaviour it replaces
bool set_freeze(uint64_t id, bool on);

// Overwrite the target now and, when frozen, latch the new value as the hold
bool poke(uint64_t id, uint64_t bits, std::string* err = nullptr);

bool set_width(uint64_t id, value_width_t width);
bool set_label(uint64_t id, std::string label);

std::vector<entry_t> list();

// Values from the most recent service pass (no target reads on this path)
std::vector<value_t> values();

size_t size();

// one service pass, sample values, apply freezes, publish when anything
// moved, rate limited to about 10hz
void tick();

// Drop every entry and forget the sampling clock (app shutdown / detach)
void shutdown();

} // namespace slop::core::memory::watch
