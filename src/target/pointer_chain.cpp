#include "pointer_chain.hpp"

#include <cstdio>
#include <cstdint>

namespace slop_target {

world_t* g_world = nullptr;

void chain_init() {
    auto* stats  = new stats_t{};
    auto* entity = new entity_t{};
    entity->stats = stats;
    g_world = new world_t{};
    g_world->player = entity;
    std::printf("[chain] init: world=%p player=%p stats=%p hp=%p\n",
        static_cast<void*>(g_world),
        static_cast<void*>(g_world->player),
        static_cast<void*>(g_world->player->stats),
        static_cast<void*>(const_cast<int32_t*>(&g_world->player->stats->hp)));
}

void chain_realloc() {
    if (!g_world) { chain_init(); return; }

    // Save hp value
    const int32_t hp = g_world->player->stats->hp;

    // Free old
    delete g_world->player->stats;
    delete g_world->player;

    // Reallocate with fresh addresses
    auto* stats  = new stats_t{};
    stats->hp = hp;
    auto* entity = new entity_t{};
    entity->stats = stats;
    g_world->player = entity;

    std::printf("[chain] realloc: player=%p stats=%p hp=%p\n",
        static_cast<void*>(g_world->player),
        static_cast<void*>(g_world->player->stats),
        static_cast<void*>(const_cast<int32_t*>(&g_world->player->stats->hp)));
}

void chain_shutdown() {
    if (!g_world) return;
    if (g_world->player) {
        delete g_world->player->stats;
        delete g_world->player;
    }
    delete g_world;
    g_world = nullptr;
}

uint64_t chain_world_addr()  { return reinterpret_cast<uint64_t>(&g_world); }
uint64_t chain_player_addr() { return g_world ? reinterpret_cast<uint64_t>(&g_world->player) : 0; }
uint64_t chain_stats_addr()  { return (g_world && g_world->player) ? reinterpret_cast<uint64_t>(&g_world->player->stats) : 0; }
uint64_t chain_hp_addr()     { return (g_world && g_world->player && g_world->player->stats) ? reinterpret_cast<uint64_t>(&g_world->player->stats->hp) : 0; }

} // namespace slop_target
