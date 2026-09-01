#pragma once

// src/core/mcp/mcp_server.hpp
// the localhost mcp server, jsonrpc over http plus a keepalive stream
// loopback only and it runs on its own threads, never the shared work queue

#include <cstdint>
#include <string>

namespace slop::core::mcp {

struct server_config_t {
    uint16_t    port  = 8765;
    std::string token;          // empty = no auth
};

// starts the server, false if the port would not bind
bool start(const server_config_t& cfg);

// stop and join all the server threads
void stop();

// for the boot log and tests
bool running();
uint16_t port();

} // namespace slop::core::mcp
