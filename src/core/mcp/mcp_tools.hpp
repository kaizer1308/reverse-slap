#pragma once

// one tool per domain with an action param, all serialized through one mutex

#include <nlohmann/json.hpp>
#include <string>

#include "core/infra/cancel.hpp"

namespace slop::core::mcp {

// fills out the tools/list entries
void list_tools(nlohmann::json& out);

// runs a tool call, sets is_error on failure and never throws
nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel = {});

// drop tool state on shutdown
void shutdown_tools();

// session snapshot for the agent, rides the initialize result
nlohmann::json session_state();

} // namespace slop::core::mcp
