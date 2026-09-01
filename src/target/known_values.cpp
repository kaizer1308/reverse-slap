#include "known_values.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace slop_target {

value_bank_t  g_values{};
value_bank_t* g_heap_values = nullptr;

void values_init() {
    g_heap_values = new value_bank_t{};
}

void values_tick() {
    // health decrements (test: decreased)
    if (g_values.health > 0) --g_values.health;

    // score increments (test: increased)
    g_values.score += 10;

    // speed drifts (test: float tolerance)
    g_values.speed += 0.01f;
    if (g_values.speed > 5.0f) g_values.speed = 1.5f;

    // frozen_probe: target writes 0 every tick
    // If a scanner freezes it to nonzero, this prints a complaint
    if (g_values.frozen_probe != 0) {
        std::printf("[!] frozen_probe is %d (external freeze detected)\n",
                    static_cast<int>(g_values.frozen_probe));
    }
    g_values.frozen_probe = 0;

    // Mirror to heap copy
    if (g_heap_values) {
        g_heap_values->health = g_values.health;
        g_heap_values->score  = g_values.score;
        g_heap_values->speed  = g_values.speed;
    }
}

void values_set(const char* name, const char* value) {
    if (!name || !value) return;

    if (std::strcmp(name, "health") == 0)       g_values.health = std::atoi(value);
    else if (std::strcmp(name, "score") == 0)   g_values.score  = std::atoi(value);
    else if (std::strcmp(name, "ammo") == 0)    g_values.ammo   = static_cast<int16_t>(std::atoi(value));
    else if (std::strcmp(name, "gold") == 0)    g_values.gold   = std::atoll(value);
    else if (std::strcmp(name, "level") == 0) {
        g_values.level_signed   = static_cast<int8_t>(std::atoi(value));
        g_values.level_unsigned = static_cast<uint8_t>(std::atoi(value));
    }
    else if (std::strcmp(name, "speed") == 0)     g_values.speed     = static_cast<float>(std::atof(value));
    else if (std::strcmp(name, "precision") == 0) g_values.precision = std::atof(value);
    else if (std::strcmp(name, "player_name") == 0) {
        std::strncpy(const_cast<char*>(g_values.player_name), value, 31);
        const_cast<char*>(g_values.player_name)[31] = '\0';
    }
    else if (std::strcmp(name, "frozen_probe") == 0) g_values.frozen_probe = std::atoi(value);
    else std::printf("[?] unknown value: %s\n", name);
}

void values_inc(const char* name) {
    if (!name) return;
    if (std::strcmp(name, "ammo") == 0)   ++g_values.ammo;
    else if (std::strcmp(name, "health") == 0) ++g_values.health;
    else if (std::strcmp(name, "score") == 0)  g_values.score += 10;
    else if (std::strcmp(name, "gold") == 0)   g_values.gold += 100;
    else std::printf("[?] unknown value: %s\n", name);
}

void values_dec(const char* name) {
    if (!name) return;
    if (std::strcmp(name, "ammo") == 0)   --g_values.ammo;
    else if (std::strcmp(name, "health") == 0) --g_values.health;
    else if (std::strcmp(name, "score") == 0)  g_values.score -= 10;
    else if (std::strcmp(name, "gold") == 0)   g_values.gold -= 100;
    else std::printf("[?] unknown value: %s\n", name);
}

} // namespace slop_target
