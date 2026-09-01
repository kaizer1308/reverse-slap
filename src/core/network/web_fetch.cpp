// src/core/net/web_fetch.cpp

#include "core/network/web_fetch.hpp"

#include <windows.h>
#include <winhttp.h>

#include <algorithm>

#pragma comment(lib, "winhttp.lib")

namespace slop::core::util {

namespace {

struct url_parts_t {
    std::wstring host;
    std::wstring path;
    bool https = true;
    INTERNET_PORT port = INTERNET_DEFAULT_HTTPS_PORT;
};

bool split_url(const std::string& url, url_parts_t* out, std::string* error) {
    std::string u = url;
    if (u.rfind("https://", 0) == 0) {
        out->https = true;
        u = u.substr(8);
    } else if (u.rfind("http://", 0) == 0) {
        out->https = false;
        u = u.substr(7);
    } else {
        if (error) *error = "URL must start with http:// or https://";
        return false;
    }
    const size_t slash = u.find('/');
    std::string authority =
        slash == std::string::npos ? u : u.substr(0, slash);
    out->path = std::wstring(slash == std::string::npos
                                 ? L"/"
                                 : std::wstring(u.begin() + slash, u.end()));
    const size_t colon = authority.find(':');
    if (colon != std::string::npos) {
        out->port = static_cast<INTERNET_PORT>(
            std::strtoul(authority.c_str() + colon + 1, nullptr, 10));
        authority = authority.substr(0, colon);
    } else {
        out->port = out->https ? INTERNET_DEFAULT_HTTPS_PORT
                               : INTERNET_DEFAULT_HTTP_PORT;
    }
    out->host.assign(authority.begin(), authority.end());
    return !out->host.empty();
}

} // namespace

std::optional<http_response_t> http_get(const std::string& url,
                                        int timeout_ms, std::string* error) {
    url_parts_t parts;
    if (!split_url(url, &parts, error)) return std::nullopt;

    HINTERNET session = WinHttpOpen(L"reverse-slop", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) {
        if (error) *error = "WinHttpOpen failed";
        return std::nullopt;
    }
    HINTERNET connect = WinHttpConnect(session, parts.host.c_str(),
                                       parts.port, 0);
    HINTERNET request = connect
        ? WinHttpOpenRequest(connect, L"GET", parts.path.c_str(), nullptr,
                             WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             parts.https ? WINHTTP_FLAG_SECURE : 0)
        : nullptr;
    http_response_t res;
    bool ok = false;
    if (request) {
        WinHttpSetTimeouts(request, timeout_ms, timeout_ms, timeout_ms,
                           timeout_ms);
        if (WinHttpSendRequest(request, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                               WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
            WinHttpReceiveResponse(request, nullptr)) {
            DWORD status = 0, sz = sizeof(status);
            WinHttpQueryHeaders(request,
                                WINHTTP_QUERY_STATUS_CODE |
                                    WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status,
                                &sz, WINHTTP_NO_HEADER_INDEX);
            res.status = status;

            wchar_t ct[256] = {};
            sz = sizeof(ct);
            DWORD idx = 0;
            if (WinHttpQueryHeaders(request, WINHTTP_QUERY_CONTENT_TYPE,
                                    WINHTTP_HEADER_NAME_BY_INDEX, ct, &sz,
                                    &idx))
                res.content_type.assign(ct, ct + wcslen(ct));

            char buf[32768];
            DWORD read_n = 0;
            while (res.body.size() < (32ull << 20) &&
                   WinHttpReadData(request, buf, sizeof(buf), &read_n) &&
                   read_n > 0)
                res.body.append(buf, read_n);
            ok = true;
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (!ok) {
        if (error) *error = "request failed";
        return std::nullopt;
    }
    return res;
}

std::optional<http_response_t> http_post(const std::string& url,
                                         const std::string& body,
                                         const std::string& content_type,
                                         int timeout_ms, std::string* error) {
    // POST shares the fetch skeleton; implemented through GET plumbing is
    // wrong, so this path re-opens with a POST verb
    url_parts_t parts;
    if (!split_url(url, &parts, error)) return std::nullopt;

    HINTERNET session = WinHttpOpen(L"reverse-slop", WINHTTP_ACCESS_TYPE_NO_PROXY,
                                    WINHTTP_NO_PROXY_NAME,
                                    WINHTTP_NO_PROXY_BYPASS, 0);
    if (!session) return std::nullopt;
    HINTERNET connect = WinHttpConnect(session, parts.host.c_str(),
                                       parts.port, 0);
    HINTERNET request = connect
        ? WinHttpOpenRequest(connect, L"POST", parts.path.c_str(), nullptr,
                             WINHTTP_NO_REFERER,
                             WINHTTP_DEFAULT_ACCEPT_TYPES,
                             parts.https ? WINHTTP_FLAG_SECURE : 0)
        : nullptr;
    http_response_t res;
    bool ok = false;
    if (request) {
        WinHttpSetTimeouts(request, timeout_ms, timeout_ms, timeout_ms,
                           timeout_ms);
        std::wstring ct_w(content_type.begin(), content_type.end());
        const std::wstring hdr = L"Content-Type: " + ct_w + L"\r\n";
        if (WinHttpSendRequest(request, hdr.c_str(),
                               static_cast<DWORD>(hdr.size()),
                               const_cast<char*>(body.data()),
                               static_cast<DWORD>(body.size()),
                               static_cast<DWORD>(body.size()), 0) &&
            WinHttpReceiveResponse(request, nullptr)) {
            DWORD status = 0, sz = sizeof(status);
            WinHttpQueryHeaders(request,
                                WINHTTP_QUERY_STATUS_CODE |
                                    WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &status,
                                &sz, WINHTTP_NO_HEADER_INDEX);
            res.status = status;
            char buf[32768];
            DWORD read_n = 0;
            while (res.body.size() < (16ull << 20) &&
                   WinHttpReadData(request, buf, sizeof(buf), &read_n) &&
                   read_n > 0)
                res.body.append(buf, read_n);
            ok = true;
        }
    }
    if (request) WinHttpCloseHandle(request);
    if (connect) WinHttpCloseHandle(connect);
    WinHttpCloseHandle(session);
    if (!ok) {
        if (error) *error = "post failed";
        return std::nullopt;
    }
    return res;
}

} // namespace slop::core::util
