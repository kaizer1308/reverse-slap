#pragma once

// localhost http inspection proxy, logs exchanges for replay and records
// sni from tunnels without decrypting them

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::network {

class traffic_store_t;

struct proxy_entry_t {
    uint64_t    id = 0;
    int64_t     at_ms = 0;
    std::string kind;              // "http" | "connect"
    std::string method;            // http only
    std::string host;
    std::string port;
    std::string path;
    uint32_t    status = 0;        // http response code (0 unknown)
    size_t      req_bytes = 0;
    size_t      resp_bytes = 0;
    std::string sni;               // connect only
    std::vector<uint8_t> raw_request;   // http only, capped
    std::vector<uint8_t> response_head; // first 8 KiB of response
};

class http_proxy_t {
public:
    ~http_proxy_t();

    bool start(uint16_t port, traffic_store_t* sink, std::string* error);
    void stop();
    bool running() const { return listen_sock_ != 0; }
    uint16_t port() const { return port_; }

    std::vector<proxy_entry_t> recent(size_t max = 128) const;
    std::optional<proxy_entry_t> entry(uint64_t id) const;

    // Re-send a logged plain-HTTP request verbatim. Returns response bytes
    std::optional<std::vector<uint8_t>> replay(uint64_t id, std::string* error);

private:
    void* listen_sock_ = nullptr;   // SOCKET, kept type-erased
    std::atomic<bool> quit_{false};
    uint16_t port_ = 0;

    mutable std::mutex mu_;
    std::vector<proxy_entry_t> log_;
    uint64_t next_id_ = 1;

    void accept_loop();
    void handle_conn(void* sock);

    uint64_t record(proxy_entry_t e);
};

} // namespace slop::core::network
