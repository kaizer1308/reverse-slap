// src/core/network/http_proxy.cpp
// plain winsock proxy, one accept thread plus a thread per connection

#include "core/network/http_proxy.hpp"

#include "core/network/traffic_store.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <atomic>
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

#pragma comment(lib, "ws2_32.lib")

namespace slop::core::network {

namespace {

constexpr size_t kMaxHeaderBytes = 128 * 1024;
constexpr size_t kMaxResponseHead = 8 * 1024;

struct wsa_init_t {
    wsa_init_t() { WSADATA d; WSAStartup(MAKEWORD(2, 2), &d); }
    ~wsa_init_t() { WSACleanup(); }
};

wsa_init_t& wsa() {
    static wsa_init_t w;
    return w;
}

void close_sock(SOCKET s) {
    if (s != INVALID_SOCKET) closesocket(s);
}

bool send_all(SOCKET s, const uint8_t* p, size_t n) {
    while (n > 0) {
        const int w = send(s, reinterpret_cast<const char*>(p),
                           static_cast<int>(std::min<size_t>(n, 0x10000)), 0);
        if (w <= 0) return false;
        p += w;
        n -= static_cast<size_t>(w);
    }
    return true;
}

// Find CRLFCRLF starting at `from`; returns header-end offset or npos
size_t find_header_end(const std::vector<uint8_t>& b, size_t from) {
    if (b.size() < 4) return std::string::npos;
    for (size_t i = from; i + 4 <= b.size(); ++i)
        if (b[i] == '\r' && b[i+1] == '\n' && b[i+2] == '\r' && b[i+3] == '\n')
            return i + 4;
    return std::string::npos;
}

// Reads until end of HTTP headers. Body bytes already received stay in buf
// beyond *out_len
bool read_headers(SOCKET s, std::vector<uint8_t>& buf, size_t* out_len,
                  size_t start_from = 0) {
    char chunk[4096];
    size_t scan_from = start_from;
    for (;;) {
        const size_t hit = find_header_end(buf, scan_from);
        if (hit != std::string::npos) {
            *out_len = hit;
            return true;
        }
        if (buf.size() > kMaxHeaderBytes) return false;
        const int r = recv(s, chunk, sizeof(chunk), 0);
        if (r <= 0) return false;
        const size_t prev = buf.size();
        buf.insert(buf.end(), chunk, chunk + r);
        if (scan_from + 3 < prev) scan_from = prev - 3;
    }
}

std::string to_lower(std::string s) {
    for (char& ch : s)
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return s;
}

// First header value matching `name` (case-insensitive)
std::string header_value(const std::vector<uint8_t>& raw,
                         const std::string& name) {
    std::string text(reinterpret_cast<const char*>(raw.data()),
                     std::min<size_t>(raw.size(), kMaxHeaderBytes));
    size_t pos = text.find("\r\n") + 2;   // skip request/status line
    while (pos < text.size()) {
        const size_t eol = text.find("\r\n", pos);
        if (eol == std::string::npos) break;
        const std::string line = text.substr(pos, eol - pos);
        pos = eol + 2;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (to_lower(line.substr(0, colon)) != name) continue;
        std::string val = line.substr(colon + 1);
        while (!val.empty() && val.front() == ' ') val.erase(val.begin());
        return val;
    }
    return "";
}

// Extract SNI from a TLS ClientHello inside `data`
std::string extract_sni(const uint8_t* d, size_t n) {
    if (n < 6 || d[0] != 0x16 || d[1] != 0x03) return "";
    size_t off = 5;                            // TLS record header
    if (off >= n || d[off] != 0x01) return ""; // not ClientHello
    off += 4;                                  // handshake type+len
    if (off + 34 > n) return "";
    off += 2 + 32;                             // version + random
    if (off >= n) return "";
    off += 1u + d[off];                        // session id
    if (off + 2 > n) return "";
    const uint16_t suites = static_cast<uint16_t>((d[off] << 8) | d[off + 1]);
    off += 2u + suites;
    if (off >= n) return "";
    off += 1u + d[off];                        // compression methods
    if (off + 2 > n) return "";
    const uint16_t ext_total = static_cast<uint16_t>((d[off] << 8) | d[off + 1]);
    size_t ext_end = off + 2 + ext_total;
    off += 2;
    while (off + 4 <= n && off <= ext_end) {
        const uint16_t type = static_cast<uint16_t>((d[off] << 8) | d[off + 1]);
        const uint16_t len  = static_cast<uint16_t>((d[off + 2] << 8) | d[off + 3]);
        off += 4;
        if (type == 0x0000 && len >= 5) {      // server_name list
            const uint8_t* sni = d + off;
            if (static_cast<size_t>(sni[2]) == 0x00) {
                const uint16_t name_len =
                    static_cast<uint16_t>((sni[3] << 8) | sni[4]);
                if (5u + name_len <= len)
                    return std::string(reinterpret_cast<const char*>(sni + 5),
                                       name_len);
            }
            return "";
        }
        off += len;
    }
    return "";
}

void pipe_both(SOCKET a, SOCKET b, std::atomic<bool>* cancel,
               size_t* up_bytes, size_t* down_bytes) {
    std::thread down([a, b, cancel, down_bytes]() {
        char buf[16384];
        int r;
        while (!cancel->load() &&
               (r = recv(b, buf, sizeof(buf), 0)) > 0) {
            *down_bytes += static_cast<size_t>(r);
            if (!send_all(a, reinterpret_cast<uint8_t*>(buf),
                          static_cast<size_t>(r)))
                break;
        }
        shutdown(a, SD_SEND);
    });
    down.detach();

    char buf[16384];
    int r;
    while (!cancel->load() && (r = recv(a, buf, sizeof(buf), 0)) > 0) {
        *up_bytes += static_cast<size_t>(r);
        if (!send_all(b, reinterpret_cast<uint8_t*>(buf),
                      static_cast<size_t>(r)))
            break;
    }
    shutdown(b, SD_SEND);
}

bool connect_host(const std::string& host, const std::string& port,
                  SOCKET* out) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), port.c_str(), &hints, &res) != 0 || !res)
        return false;
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) { freeaddrinfo(res); return false; }
    if (connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
        close_sock(s);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    *out = s;
    return true;
}

} // namespace

http_proxy_t::~http_proxy_t() { stop(); }

uint64_t http_proxy_t::record(proxy_entry_t e) {
    std::lock_guard lk(mu_);
    e.id = next_id_++;
    log_.push_back(std::move(e));
    if (log_.size() > 512) log_.erase(log_.begin());
    return log_.back().id;
}

bool http_proxy_t::start(uint16_t port, traffic_store_t* sink,
                         std::string* error) {
    (void)sink;
    wsa();
    if (listen_sock_) return true;

    SOCKET l = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (l == INVALID_SOCKET) {
        if (error) *error = "socket() failed";
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(l, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
        listen(l, 16) != 0) {
        if (error) *error = "bind/listen failed (port busy?)";
        close_sock(l);
        return false;
    }

    sockaddr_in bound{};
    int blen = sizeof(bound);
    getsockname(l, reinterpret_cast<sockaddr*>(&bound), &blen);
    port_ = ntohs(bound.sin_port);

    listen_sock_ = reinterpret_cast<void*>(static_cast<intptr_t>(l));
    quit_ = false;
    std::thread(&http_proxy_t::accept_loop, this).detach();
    return true;
}

void http_proxy_t::stop() {
    quit_ = true;
    SOCKET l = static_cast<SOCKET>(
        reinterpret_cast<intptr_t>(listen_sock_));
    if (l != 0 && l != INVALID_SOCKET) {
        close_sock(l);
        listen_sock_ = nullptr;
        std::this_thread::sleep_for(std::chrono::milliseconds(80));
    }
}

void http_proxy_t::accept_loop() {
    SOCKET l = static_cast<SOCKET>(
        reinterpret_cast<intptr_t>(listen_sock_));
    while (!quit_.load()) {
        sockaddr_in peer{};
        int plen = sizeof(peer);
        SOCKET c = accept(l, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (c == INVALID_SOCKET) break;
        std::thread(&http_proxy_t::handle_conn, this,
                    reinterpret_cast<void*>(static_cast<intptr_t>(c)))
            .detach();
    }
}

void http_proxy_t::handle_conn(void* sockp) {
    SOCKET c = static_cast<SOCKET>(reinterpret_cast<intptr_t>(sockp));

    std::vector<uint8_t> head;
    size_t head_len = 0;
    if (!read_headers(c, head, &head_len)) {
        close_sock(c);
        return;
    }

    proxy_entry_t entry;
    entry.at_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    entry.req_bytes = head_len;

    std::string first_line(
        reinterpret_cast<const char*>(head.data()),
        std::min<size_t>(head.size(), 2048));
    const size_t eol = first_line.find("\r\n");
    if (eol != std::string::npos) first_line.resize(eol);

    const size_t sp1 = first_line.find(' ');
    const size_t sp2 = first_line.find(' ', sp1 + 1);
    const std::string method = sp1 == std::string::npos ? ""
                                                       : first_line.substr(0, sp1);
    std::string target = (sp1 == std::string::npos || sp2 == std::string::npos)
                             ? "" : first_line.substr(sp1 + 1, sp2 - sp1 - 1);
    entry.method = method;

    if (_stricmp(method.c_str(), "CONNECT") == 0) {
        entry.kind = "connect";
        const size_t colon = target.rfind(':');
        entry.host = colon == std::string::npos ? target : target.substr(0, colon);
        entry.port = colon == std::string::npos ? "443" : target.substr(colon + 1);

        SOCKET remote = INVALID_SOCKET;
        if (!connect_host(entry.host, entry.port, &remote)) {
            constexpr char msg[] = "HTTP/1.1 502 bad gateway\r\n\r\n";
            send_all(c, reinterpret_cast<const uint8_t*>(msg), sizeof(msg) - 1);
            entry.status = 502;
            record(std::move(entry));
            close_sock(c);
            return;
        }

        uint8_t peek[4096];
        const int pr = recv(c, reinterpret_cast<char*>(peek), sizeof(peek),
                            MSG_PEEK);
        if (pr > 0) entry.sni = extract_sni(peek, static_cast<size_t>(pr));

        constexpr char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
        send_all(c, reinterpret_cast<const uint8_t*>(ok), sizeof(ok) - 1);
        entry.status = 200;

        std::atomic<bool> cancel{false};
        size_t up = 0, down = 0;
        pipe_both(c, remote, &cancel, &up, &down);
        cancel.store(true);
        close_sock(remote);
        entry.req_bytes  = up;
        entry.resp_bytes = down;
        record(std::move(entry));
        close_sock(c);
        return;
    }

    // Plain HTTP forwarding
    entry.kind = "http";
    std::string host = header_value(head, "host");
    std::string port = "80";
    if (!host.empty()) {
        const size_t colon = host.rfind(':');
        if (colon != std::string::npos) {
            port = host.substr(colon + 1);
            host = host.substr(0, colon);
        }
    }
    // Rewrite absolute-form targets into origin-form
    std::vector<uint8_t> fwd(head);
    if (target.rfind("http://", 0) == 0) {
        const size_t slash = target.find('/', 7);
        const std::string newline =
            method + " " +
            (slash == std::string::npos ? "/" : target.substr(slash)) +
            " HTTP/1.1";
        fwd.clear();
        fwd.insert(fwd.end(), newline.begin(), newline.end());
        const size_t first_eol = [&] {
            for (size_t i = 0; i + 2 <= head.size(); ++i)
                if (head[i] == '\r' && head[i + 1] == '\n') return i;
            return head.size();
        }();
        fwd.insert(fwd.end(), head.begin() + first_eol, head.end());
        if (host.empty()) {
            const size_t hbeg = 7;
            const size_t slash_a = target.find('/', hbeg);
            std::string authority = target.substr(
                hbeg, slash_a == std::string::npos ? std::string::npos
                                                   : slash_a - hbeg);
            const size_t colon = authority.rfind(':');
            if (colon != std::string::npos) {
                port = authority.substr(colon + 1);
                authority = authority.substr(0, colon);
            }
            host = authority;
        }
    } else if (target.size() > 0 && target[0] != '/') {
        target = "/";
    }
    entry.host = host;
    entry.port = port;
    entry.path = target;
    entry.raw_request = fwd;

    SOCKET remote = INVALID_SOCKET;
    if (!connect_host(host.empty() ? "127.0.0.1" : host, port, &remote)) {
        constexpr char msg[] = "HTTP/1.1 502 bad gateway\r\n\r\n";
        send_all(c, reinterpret_cast<const uint8_t*>(msg), sizeof(msg) - 1);
        entry.status = 502;
        record(std::move(entry));
        close_sock(c);
        return;
    }
    send_all(remote, fwd.data(), fwd.size());

    std::vector<uint8_t> resp;
    size_t resp_head_len = 0;
    const bool got = read_headers(remote, resp, &resp_head_len);
    entry.status = 0;
    if (got && resp.size() >= 12)
        entry.status = static_cast<uint32_t>(
            std::strtoul(reinterpret_cast<const char*>(resp.data()) + 9,
                         nullptr, 10));
    entry.response_head.assign(
        resp.begin(),
        resp.begin() + static_cast<long>(
                           std::min(resp.size(), kMaxResponseHead)));
    if (got) send_all(c, resp.data(), resp.size());

    // Log now, inspection value beats exact trailing-byte counts, and MCP
    // pollers must see the entry while bodies are still streaming
    entry.resp_bytes = resp.size();
    record(std::move(entry));

    std::atomic<bool> cancel{false};
    size_t up = 0, down = 0;
    pipe_both(c, remote, &cancel, &up, &down);
    cancel.store(true);
    close_sock(remote);
    close_sock(c);
}

std::vector<proxy_entry_t> http_proxy_t::recent(size_t max) const {
    std::lock_guard lk(mu_);
    std::vector<proxy_entry_t> out;
    const size_t start = log_.size() > max ? log_.size() - max : 0;
    for (size_t i = start; i < log_.size(); ++i) out.push_back(log_[i]);
    return out;
}

std::optional<proxy_entry_t> http_proxy_t::entry(uint64_t id) const {
    std::lock_guard lk(mu_);
    for (const auto& e : log_)
        if (e.id == id) return e;
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> http_proxy_t::replay(uint64_t id,
                                                         std::string* error) {
    auto e = entry(id);
    if (!e || e->kind != "http" || e->raw_request.empty()) {
        if (error) *error = "no replayable request with that id";
        return std::nullopt;
    }
    wsa();
    SOCKET remote = INVALID_SOCKET;
    if (!connect_host(e->host, e->port.empty() ? "80" : e->port, &remote)) {
        if (error) *error = "cannot reach " + e->host + ":" + e->port;
        return std::nullopt;
    }
    send_all(remote, e->raw_request.data(), e->raw_request.size());

    std::vector<uint8_t> resp;
    char buf[16384];
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::seconds(3);
    u_long nonblock = 1;
    ioctlsocket(remote, FIONBIO, &nonblock);
    while (std::chrono::steady_clock::now() < deadline &&
           resp.size() < (1u << 20)) {
        const int r = recv(remote, buf, sizeof(buf), 0);
        if (r > 0) {
            resp.insert(resp.end(), buf, buf + r);
        } else if (r == 0) {
            break;
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
    }
    close_sock(remote);
    return resp;
}

} // namespace slop::core::network
