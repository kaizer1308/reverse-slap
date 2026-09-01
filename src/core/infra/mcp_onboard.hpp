#pragma once

// src/core/infra/mcp_onboard.hpp
// first boot registration into the ai clients we know about
// claude desktop is stdio only so it just gets reported as unsupported

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::infra::mcp_onboard {

struct install_result_t {
    std::string client;     // which client we touched
    bool        installed;  // true when we actually wrote
    std::string path;       // the file we touched
    std::string error;      // empty when all good
};

// runs the whole sweep, one result per client
std::vector<install_result_t> install_all(uint16_t port, const std::string& token);

// removes everything we wrote, for an uninstall button
std::vector<install_result_t> uninstall_all();

} // namespace slop::core::infra::mcp_onboard
