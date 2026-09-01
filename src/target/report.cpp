#include "report.hpp"
#include "known_values.hpp"
#include "pointer_chain.hpp"
#include "aob_fixtures.hpp"
#include "region_zoo.hpp"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>

#include <nlohmann/json.hpp>

namespace slop_target {

namespace {
uint64_t addr_of(const volatile void* p) { return reinterpret_cast<uint64_t>(p); }
} // namespace

void report_print() {
    std::printf("\n=== SlopTarget Address Report ===\n");
    std::printf("PID: %u\n", GetCurrentProcessId());
    std::printf("values.health:       0x%016llX\n", addr_of(&g_values.health));
    std::printf("values.score:        0x%016llX\n", addr_of(&g_values.score));
    std::printf("values.ammo:         0x%016llX\n", addr_of(&g_values.ammo));
    std::printf("values.gold:         0x%016llX\n", addr_of(&g_values.gold));
    std::printf("values.level_signed: 0x%016llX\n", addr_of(&g_values.level_signed));
    std::printf("values.speed:        0x%016llX\n", addr_of(&g_values.speed));
    std::printf("values.precision:    0x%016llX\n", addr_of(&g_values.precision));
    std::printf("values.player_name:  0x%016llX\n", addr_of(g_values.player_name));
    std::printf("values.magic_bytes:  0x%016llX\n", addr_of(g_values.magic_bytes));
    std::printf("values.frozen_probe: 0x%016llX\n", addr_of(&g_values.frozen_probe));
    std::printf("chain.g_world:       0x%016llX\n", chain_world_addr());
    std::printf("chain.hp:            0x%016llX\n", chain_hp_addr());
    std::printf("aob.unique_fn:       0x%016llX\n", aob_unique_fn_addr());
    std::printf("aob.twin_a:          0x%016llX\n", aob_twin_a_addr());
    std::printf("aob.twin_b:          0x%016llX\n", aob_twin_b_addr());
    std::printf("zoo.rw_block:        0x%016llX\n", addr_of(g_zoo.rw_block));
    std::printf("=================================\n\n");
}

void report_json() {
    nlohmann::json j;
    j["pid"] = GetCurrentProcessId();

    auto& vals = j["values"];
    vals["health"]       = addr_of(&g_values.health);
    vals["score"]        = addr_of(&g_values.score);
    vals["ammo"]         = addr_of(&g_values.ammo);
    vals["gold"]         = addr_of(&g_values.gold);
    vals["level_signed"] = addr_of(&g_values.level_signed);
    vals["level_unsigned"] = addr_of(&g_values.level_unsigned);
    vals["speed"]        = addr_of(&g_values.speed);
    vals["precision"]    = addr_of(&g_values.precision);
    vals["player_name"]  = addr_of(g_values.player_name);
    vals["wide_name"]    = addr_of(g_values.wide_name);
    vals["magic_bytes"]  = addr_of(g_values.magic_bytes);
    vals["frozen_probe"] = addr_of(&g_values.frozen_probe);

    auto& chain = j["chain"];
    chain["g_world_ptr"] = chain_world_addr();
    chain["player_ptr"]  = chain_player_addr();
    chain["stats_ptr"]   = chain_stats_addr();
    chain["hp"]          = chain_hp_addr();
    chain["offsets"]     = { 0x10, 0x20, 0x18 };

    auto& aob = j["aob"];
    aob["unique_fn"] = aob_unique_fn_addr();
    aob["twin_a"]    = aob_twin_a_addr();
    aob["twin_b"]    = aob_twin_b_addr();

    auto& zoo = j["zoo"];
    zoo["rw_block"]       = addr_of(g_zoo.rw_block);
    zoo["rw_size"]        = g_zoo.rw_size;
    zoo["noaccess_block"] = addr_of(g_zoo.noaccess_block);
    zoo["guard_block"]    = addr_of(g_zoo.guard_block);
    zoo["exec_block"]     = addr_of(g_zoo.exec_block);
    zoo["reserve_block"]  = addr_of(g_zoo.reserve_block);
    zoo["mapped_view"]    = addr_of(g_zoo.mapped_view);

    // Write to %TEMP%\sloptarget-<pid>.json
    char temp[MAX_PATH]{};
    DWORD tempLen = GetTempPathA(MAX_PATH, temp);
    if (tempLen == 0 || tempLen >= MAX_PATH) {
        std::strcpy(temp, ".\\");
    }
    std::string path = std::string(temp) + "sloptarget-"
                     + std::to_string(GetCurrentProcessId()) + ".json";

    std::printf("[report] attempting write to: %s\n", path.c_str());
    std::ofstream f(path, std::ios::trunc);
    if (f.is_open()) {
        f << j.dump(2);
        f.flush();
        f.close();
        std::printf("[report] written to %s\n", path.c_str());
    } else {
        std::printf("[report] failed to write %s\n", path.c_str());
    }
}

} // namespace slop_target
