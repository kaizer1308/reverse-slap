#pragma once

// src/core/net/web_fetch.hpp
// HTTP(S) fetch over WinHTTP backing the MCP web tool

#include <map>
#include <optional>
#include <string>

namespace slop::core::util {

struct http_response_t {
    uint32_t status = 0;
    std::string content_type;
    std::string body;
};

std::optional<http_response_t> http_get(const std::string& url,
                                        int timeout_ms = 15000,
                                        std::string* error = nullptr);
std::optional<http_response_t> http_post(const std::string& url,
                                         const std::string& body,
                                         const std::string& content_type,
                                         int timeout_ms = 15000,
                                         std::string* error = nullptr);

} // namespace slop::core::util
