#include "core/infra/paths.hpp"

#include <windows.h>
#include <shlobj.h>

#include <filesystem>

namespace slop::core::infra::paths {

namespace {
std::string g_app_data;
std::string g_settings_file;
std::string g_sessions_dir;
std::string g_crashes_dir;
} // namespace

void init() {
    char buf[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", buf, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) {
        // fall back to the working dir
        g_app_data = ".\\reverse-slop";
    } else {
        g_app_data = std::string(buf, n) + "\\reverse-slop";
    }

    g_settings_file = g_app_data + "\\settings.json";
    g_sessions_dir  = g_app_data + "\\sessions";
    g_crashes_dir   = g_app_data + "\\crashes";

    // make sure the folders exist
    std::error_code ec;
    std::filesystem::create_directories(g_app_data, ec);
    std::filesystem::create_directories(g_sessions_dir, ec);
    std::filesystem::create_directories(g_crashes_dir, ec);
}

const std::string& app_data()      { return g_app_data; }
const std::string& settings_file() { return g_settings_file; }
const std::string& sessions_dir()  { return g_sessions_dir; }
const std::string& crashes_dir()   { return g_crashes_dir; }

} // namespace slop::core::infra::paths
