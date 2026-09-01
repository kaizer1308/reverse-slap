#pragma once

// src/core/infra/settings.hpp
// settings live in localappdata

#include <cstdint>
#include <string>

namespace slop::core::infra::settings {

void load();
void save();

// dock resets when this changes
uint32_t layout_version();
void     set_layout_version(uint32_t v);

// last target, for session restore
std::string last_target_name();
uint32_t    last_target_pid();
void        set_last_target(const std::string& name, uint32_t pid);

// MCP server
bool     mcp_enabled();
uint16_t mcp_port();
std::string mcp_token();
void     set_mcp(bool enabled, uint16_t port, const std::string& token);

// first run registration into ai clients
bool mcp_onboarded();
void set_mcp_onboarded(bool v);

// zero the debug flags in the targets peb right after a kernel attach
bool stealth_peb_spoof();
void set_stealth_peb_spoof(bool v);

// prefer the kernel event channel when the driver is around
bool stealth_kernel_debug();
void set_stealth_kernel_debug(bool v);

} // namespace slop::core::infra::settings
