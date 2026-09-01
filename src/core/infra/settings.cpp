#include "core/infra/settings.hpp"
#include "core/infra/paths.hpp"

#include <fstream>
#include <mutex>

#include <nlohmann/json.hpp>

namespace slop::core::infra::settings {

namespace {

std::mutex      g_mu;
nlohmann::json  g_data = nlohmann::json::object();

} // namespace

void load() {
    std::lock_guard lk(g_mu);
    std::ifstream f(paths::settings_file());
    if (!f.is_open()) {
        g_data = nlohmann::json::object();
        return;
    }
    try {
        f >> g_data;
    } catch (...) {
        g_data = nlohmann::json::object();
    }
}

void save() {
    std::lock_guard lk(g_mu);
    // write to a temp then rename
    const std::string tmp = paths::settings_file() + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) return;
        f << g_data.dump(2);
    }
    // best effort rename
    std::error_code ec;
    std::filesystem::rename(tmp, paths::settings_file(), ec);
    if (ec) {
        // fall back to remove then rename
        std::filesystem::remove(paths::settings_file(), ec);
        std::filesystem::rename(tmp, paths::settings_file(), ec);
    }
}

uint32_t layout_version() {
    std::lock_guard lk(g_mu);
    return g_data.value("layout_version", 0u);
}

void set_layout_version(uint32_t v) {
    std::lock_guard lk(g_mu);
    g_data["layout_version"] = v;
}

std::string last_target_name() {
    std::lock_guard lk(g_mu);
    return g_data.value("last_target_name", std::string{});
}

uint32_t last_target_pid() {
    std::lock_guard lk(g_mu);
    return g_data.value("last_target_pid", 0u);
}

void set_last_target(const std::string& name, uint32_t pid) {
    std::lock_guard lk(g_mu);
    g_data["last_target_name"] = name;
    g_data["last_target_pid"]  = pid;
}

bool mcp_enabled() {
    std::lock_guard lk(g_mu);
    return g_data.value("mcp_enabled", true);
}

uint16_t mcp_port() {
    std::lock_guard lk(g_mu);
    return static_cast<uint16_t>(g_data.value("mcp_port", 8765));
}

std::string mcp_token() {
    std::lock_guard lk(g_mu);
    return g_data.value("mcp_token", std::string{});
}

void set_mcp(bool enabled, uint16_t port, const std::string& token) {
    std::lock_guard lk(g_mu);
    g_data["mcp_enabled"] = enabled;
    g_data["mcp_port"]    = port;
    g_data["mcp_token"]   = token;
}

bool mcp_onboarded() {
    std::lock_guard lk(g_mu);
    return g_data.value("mcp_onboarded", false);
}

void set_mcp_onboarded(bool v) {
    std::lock_guard lk(g_mu);
    g_data["mcp_onboarded"] = v;
}

bool stealth_peb_spoof() {
    std::lock_guard lk(g_mu);
    return g_data.value("stealth_peb_spoof", true);
}

void set_stealth_peb_spoof(bool v) {
    std::lock_guard lk(g_mu);
    g_data["stealth_peb_spoof"] = v;
}

bool stealth_kernel_debug() {
    std::lock_guard lk(g_mu);
    return g_data.value("stealth_kernel_debug", true);
}

void set_stealth_kernel_debug(bool v) {
    std::lock_guard lk(g_mu);
    g_data["stealth_kernel_debug"] = v;
}

} // namespace slop::core::infra::settings
