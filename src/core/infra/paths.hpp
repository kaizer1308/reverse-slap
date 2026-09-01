#pragma once

// src/core/infra/paths.hpp
// where all the app data lives

#include <string>

namespace slop::core::infra::paths {

void init();

// everything exists after init
const std::string& app_data();       // %LOCALAPPDATA%\reverse-slop
const std::string& settings_file();  // .../settings.json
const std::string& sessions_dir();   // .../sessions
const std::string& crashes_dir();    // .../crashes

} // namespace slop::core::infra::paths
