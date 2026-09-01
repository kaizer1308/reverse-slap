#pragma once

// src/target/pointer_chain.hpp
// 3 level pointer chain for scanner testing

#include <cstdint>

namespace slop_target {

struct stats_t {
    uint8_t  pad[0x18]{};
    volatile int32_t hp = 9999;
};

struct entity_t {
    uint8_t  pad[0x20]{};
    stats_t* stats = nullptr;
};

struct world_t {
    uint8_t   pad[0x10]{};
    entity_t* player = nullptr;
};

extern world_t* g_world;

void chain_init();
void chain_realloc();   // Frees and reallocates intermediates (new addresses, same offsets)
void chain_shutdown();

// For the report: returns the addresses of the chain nodes
uint64_t chain_world_addr();
uint64_t chain_player_addr();
uint64_t chain_stats_addr();
uint64_t chain_hp_addr();

} // namespace slop_target
