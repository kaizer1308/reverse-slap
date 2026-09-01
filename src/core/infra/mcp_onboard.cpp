// src/core/infra/mcp_onboard.cpp
// drops the reverse-slop mcp entry into every ai client config we know about
// runs once on first boot and skips anything that already has us registered
//
// every client wants a slightly different entry shape:
//  - Claude Code: ~/.claude.json "mcpServers" entry with "type":"http", it
//    reads an entry with a url but no type as stdio and skips it
//  - Claude Desktop: stdio only, remote servers go through the connectors ui
//  - Cursor / Windsurf / OpenCode: bare "url" entries
//  - VS Code: settings.json "mcp.servers" entry with "type":"http"

#include "core/infra/mcp_onboard.hpp"
#include "core/infra/paths.hpp"

#include <nlohmann/json.hpp>

#include <windows.h>
#include <shlobj.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

namespace slop::core::infra::mcp_onboard {

namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

// path helpers

std::string env_or(const char* var, const std::string& fallback) {
    char buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA(var, buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return fallback;
    return std::string(buf, n);
}

std::string localappdata() { return env_or("LOCALAPPDATA", ""); }
std::string appdata()      { return env_or("APPDATA", ""); }
std::string userprofile()  { return env_or("USERPROFILE", ""); }

// json helpers

// parse result, a file we cant read never gets written back over
enum class read_t { ok, missing, corrupt };

read_t read_json_file(const std::string& path, json& out) {
    std::error_code ec;
    if (!fs::exists(path, ec) || ec) return read_t::missing;
    std::ifstream f(path);
    if (!f.is_open()) return read_t::corrupt;
    try {
        f >> out;
        return read_t::ok;
    } catch (...) {
        return read_t::corrupt;
    }
}

bool write_json_file(const std::string& path, const json& j) {
    // make sure the folder is there first
    std::error_code ec;
    fs::create_directories(fs::path(path).parent_path(), ec);

    const std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::trunc);
        if (!f.is_open()) return false;
        f << j.dump(2);
    }
    fs::rename(tmp, path, ec);
    if (ec) {
        fs::remove(path, ec);
        fs::rename(tmp, path, ec);
    }
    return !ec;
}

// entry builder

constexpr const char* kServerName = "reverse-slop";

// bare url entry, no "transport" key since nobody reads one
json make_mcp_entry(uint16_t port, const std::string& token) {
    json entry;
    entry["url"] = "http://127.0.0.1:" + std::to_string(port) + "/mcp";
    if (!token.empty()) {
        entry["headers"] = json::object({{"Authorization", "Bearer " + token}});
    }
    return entry;
}

// per client installers

// Each returns {client_name, installed, path, error}

// shared installer, keeps every other key and bails on a config it cant parse
install_result_t install_url_entry(const char* client, const std::string& path,
                                   uint16_t port, const std::string& token,
                                   bool with_type) {
    json cfg;
    switch (read_json_file(path, cfg)) {
    case read_t::corrupt:
        return {client, false, path, "config unparseable, left untouched"};
    case read_t::missing:
        cfg = json::object();
        break;
    default:
        break;
    }
    if (!cfg.contains("mcpServers") || !cfg.at("mcpServers").is_object())
        cfg["mcpServers"] = json::object();
    if (cfg.at("mcpServers").contains(kServerName))
        return {client, false, path, ""};

    json entry = make_mcp_entry(port, token);
    if (with_type) entry["type"] = "http";
    cfg["mcpServers"][kServerName] = std::move(entry);
    if (!write_json_file(path, cfg))
        return {client, false, path, "write failed"};
    return {client, true, path, ""};
}

// old builds wrote a dead entry into ~/.claude/settings.json, wipe just ours
void remove_legacy_claude_code_settings_entry() {
    const std::string path = userprofile() + "\\.claude\\settings.json";
    json settings;
    if (read_json_file(path, settings) != read_t::ok) return;
    if (!settings.contains("mcpServers") ||
        !settings.at("mcpServers").is_object() ||
        !settings.at("mcpServers").contains(kServerName))
        return;
    settings["mcpServers"].erase(kServerName);
    if (settings.at("mcpServers").empty()) settings.erase("mcpServers");
    write_json_file(path, settings);
}

install_result_t do_claude_code_global(uint16_t port, const std::string& token) {
    // ~/.claude.json is claude codes state file so only add our key and touch nothing else
    remove_legacy_claude_code_settings_entry();   // old builds wrote there
    return install_url_entry("Claude Code (global)", userprofile() + "\\.claude.json",
                             port, token, /*with_type=*/true);
}

install_result_t do_claude_desktop(uint16_t port, const std::string& token) {
    (void)port;
    (void)token;
    // desktop config only does stdio servers so all we can do here is clean up
    const std::string path = appdata() + "\\Claude\\claude_desktop_config.json";
    json cfg;
    if (read_json_file(path, cfg) == read_t::ok &&
        cfg.contains("mcpServers") && cfg.at("mcpServers").is_object() &&
        cfg.at("mcpServers").contains(kServerName)) {
        const json& e = cfg.at("mcpServers").at(kServerName);
        if (!e.contains("command")) {   // ours, a url entry a stdio client cant load
            cfg["mcpServers"].erase(kServerName);
            if (cfg.at("mcpServers").empty()) cfg.erase("mcpServers");
            write_json_file(path, cfg);
        }
    }
    return {"Claude Desktop", false, path,
            "desktop config is stdio-only; add remote MCP via the Connectors UI"};
}

install_result_t do_cursor(uint16_t port, const std::string& token) {
    return install_url_entry("Cursor", userprofile() + "\\.cursor\\mcp.json",
                             port, token, /*with_type=*/false);
}

install_result_t do_windsurf(uint16_t port, const std::string& token) {
    return install_url_entry("Windsurf",
                             userprofile() + "\\.codeium\\windsurf\\mcp_config.json",
                             port, token, /*with_type=*/false);
}

install_result_t do_vscode(uint16_t port, const std::string& token) {
    // vs code tucks servers under mcp.servers
    const std::string path = appdata() + "\\Code\\User\\settings.json";

    json settings;
    switch (read_json_file(path, settings)) {
    case read_t::corrupt:
        return {"VS Code", false, path, "config unparseable, left untouched"};
    case read_t::missing:
        settings = json::object();
        break;
    default:
        break;
    }

    // VS Code uses "mcp" -> "servers" -> { name: { ... } }
    if (!settings.contains("mcp"))
        settings["mcp"] = json::object();
    if (!settings["mcp"].contains("servers"))
        settings["mcp"]["servers"] = json::object();

    if (settings["mcp"]["servers"].contains(kServerName))
        return {"VS Code", false, path, ""};

    json entry;
    entry["type"] = "http";
    entry["url"] = "http://127.0.0.1:" + std::to_string(port) + "/mcp";
    if (!token.empty())
        entry["headers"] = json::object({{"Authorization", "Bearer " + token}});
    settings["mcp"]["servers"][kServerName] = entry;

    if (!write_json_file(path, settings))
        return {"VS Code", false, path, "write failed"};
    return {"VS Code", true, path, ""};
}

install_result_t do_opencode(uint16_t port, const std::string& token) {
    // ~/.config/opencode/config.json  (XDG on Linux; %USERPROFILE%\.config on Win)
    return install_url_entry("OpenCode",
                             userprofile() + "\\.config\\opencode\\config.json",
                             port, token, /*with_type=*/false);
}

} // namespace

// public api

std::vector<install_result_t> install_all(uint16_t port, const std::string& token) {
    std::vector<install_result_t> results;
    results.reserve(6);

    results.push_back(do_claude_code_global(port, token));
    results.push_back(do_claude_desktop(port, token));
    results.push_back(do_cursor(port, token));
    results.push_back(do_windsurf(port, token));
    results.push_back(do_vscode(port, token));
    results.push_back(do_opencode(port, token));

    return results;
}

std::vector<install_result_t> uninstall_all() {
    std::vector<install_result_t> results;

    auto remove_key = [&](const char* client, const std::string& path,
                          const char* servers_key, const char* parent_key = nullptr) {
        json cfg;
        switch (read_json_file(path, cfg)) {
        case read_t::missing:
            results.push_back({client, false, path, "file not found"});
            return;
        case read_t::corrupt:
            results.push_back({client, false, path, "config unparseable, left untouched"});
            return;
        default:
            break;
        }

        json* container = &cfg;
        if (parent_key && cfg.contains(parent_key))
            container = &cfg[parent_key];

        if (!container->contains(servers_key) ||
            !(*container)[servers_key].contains(kServerName)) {
            results.push_back({client, false, path, ""});
            return;
        }

        (*container)[servers_key].erase(kServerName);
        if (write_json_file(path, cfg))
            results.push_back({client, true, path, ""});
        else
            results.push_back({client, false, path, "write failed"});
    };

    remove_key("Claude Code (global)",
               userprofile() + "\\.claude.json", "mcpServers");
    // Pre-fix builds wrote into settings.json instead of .claude.json  
    // clean both so uninstall actually removes what install wrote
    remove_key("Claude Code (legacy settings)",
               userprofile() + "\\.claude\\settings.json", "mcpServers");
    remove_key("Claude Desktop",
               appdata() + "\\Claude\\claude_desktop_config.json", "mcpServers");
    remove_key("Cursor",
               userprofile() + "\\.cursor\\mcp.json", "mcpServers");
    remove_key("Windsurf",
               userprofile() + "\\.codeium\\windsurf\\mcp_config.json", "mcpServers");
    remove_key("VS Code",
               appdata() + "\\Code\\User\\settings.json", "servers", "mcp");
    remove_key("OpenCode",
               userprofile() + "\\.config\\opencode\\config.json", "mcpServers");

    return results;
}

} // namespace slop::core::infra::mcp_onboard
