// src/tests/test_network.cpp
// Traffic store (ring, streams, filters, pcap), HTTP proxy over real
// loopback sockets with an httplib origin. Kernel capture paths are only
// shape-tested (driver not loadable in unit tests)

#include "harness.hpp"

#include "core/network/http_proxy.hpp"
#include "core/network/traffic_store.hpp"

#include <httplib.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>

using namespace slop::core::network;

namespace {

packet_record_t mk_packet(int sport, int dport,
                          const char* local = "10.0.0.2",
                          const char* remote = "93.184.216.34",
                          uint32_t dir = 0,
                          const std::string& body = "hello") {
    packet_record_t p;
    p.at_ms = 1700000000000;
    p.protocol = 6;
    p.direction = dir;
    p.local_addr = local;
    p.local_port = static_cast<uint16_t>(sport);
    p.remote_addr = remote;
    p.remote_port = static_cast<uint16_t>(dport);
    p.payload.assign(body.begin(), body.end());
    return p;
}

} // namespace

TEST_CASE(traffic_store_ring_and_ids) {
    traffic_store_t s(4);
    for (int i = 0; i < 10; ++i) s.add(mk_packet(1000 + i, 80));
    REQUIRE_EQ(s.size(), 4u);

    auto page = s.packets(0, 100);
    // Ring kept the newest four; ids are monotonic
    REQUIRE_EQ(page.items.size(), 4u);
    REQUIRE_GT(page.items.back().id, page.items.front().id);
}

TEST_CASE(traffic_store_stream_reassembly) {
    traffic_store_t s;
    s.add(mk_packet(1234, 80, "10.0.0.2", "1.1.1.1", 0, "GET / HT"));
    // Inbound: local = server side
    s.add(mk_packet(80, 1234, "1.1.1.1", "10.0.0.2", 1, "HTTP/1.1 200 OK"));

    auto streams = s.streams();
    REQUIRE_EQ(streams.size(), 1u);
    REQUIRE_EQ(streams[0].bytes, 23u);
    REQUIRE_EQ(streams[0].packets, 2u);

    auto bytes = s.stream_bytes(streams[0].id, 0, 1024);
    REQUIRE(bytes.has_value());
    std::string merged(reinterpret_cast<const char*>(bytes->data()),
                       bytes->size());
    REQUIRE(merged.find("GET / HT") == 0);           // client bytes first
    REQUIRE(merged.find("200 OK") != std::string::npos);

    // Offset past the end yields empty, unknown id yields nullopt
    auto empty_tail = s.stream_bytes(streams[0].id, 9999, 10);
    REQUIRE(empty_tail.has_value());
    REQUIRE(empty_tail->empty());
    REQUIRE(!s.stream_bytes(9999, 0, 1).has_value());
}

TEST_CASE(traffic_store_filter_expressions) {
    traffic_store_t s;
    auto http = mk_packet(1234, 80, "10.0.0.2", "1.1.1.1", 0, "GET /a");
    http.pid = 111;
    auto dns = mk_packet(5555, 53, "10.0.0.2", "8.8.8.8", 0, "\x00\x01query");
    dns.protocol = 17;
    dns.pid = 222;
    s.add(http);
    s.add(dns);

    REQUIRE_EQ(s.packets_filtered(0, 100, "port=80").items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "proto:udp").items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "pid:222").items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "text:GET").items.size(), 1u);
    REQUIRE_EQ(s.packets_filtered(0, 100, "host:8.8.8.8").items.size(), 1u);
    REQUIRE_EQ(
        s.packets_filtered(0, 100, "port=53;host:8.8.8.8").items.size(), 1u);
    // Unknown predicate never matches
    REQUIRE_EQ(s.packets_filtered(0, 100, "bogus:x").items.size(), 0u);
    // AND of conflicting predicates matches nothing
    REQUIRE_EQ(
        s.packets_filtered(0, 100, "port=80;port=53").items.size(), 0u);
}

TEST_CASE(pcap_export_produces_valid_header) {
    traffic_store_t s;
    s.add(mk_packet(1234, 80));

    char path[MAX_PATH];
    std::snprintf(path, sizeof(path), "%s\\slop_test_%u.pcap",
                  std::getenv("TEMP"), static_cast<unsigned>(::_getpid()));
    std::string err;
    const std::vector<packet_record_t> one = {mk_packet(1234, 80)};
    REQUIRE(s.write_pcap(path, one, &err));
    REQUIRE(err.empty());

    std::FILE* f = nullptr;
    fopen_s(&f, path, "rb");
    REQUIRE(f != nullptr);
    uint8_t hdr[24] = {};
    REQUIRE(fread(hdr, 1, 24, f) == 24);
    fclose(f);
    // magic d4 c3 b2 a1 (little-endian write of 0xa1b2c3d4)
    REQUIRE(hdr[0] == 0xd4 && hdr[1] == 0xc3 && hdr[2] == 0xb2 &&
            hdr[3] == 0xa1);
    REQUIRE(hdr[20] == 0x01);   // LINKTYPE_ETHERNET

    remove(path);
}

TEST_CASE(proxy_http_forward_and_log) {
    httplib::Server origin;
    origin.Get("/hi", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("origin-body", "text/plain");
    });
    int origin_port = origin.bind_to_any_port("127.0.0.1");
    REQUIRE_GT(origin_port, 0);
    std::thread origin_thread([&] { origin.listen_after_bind(); });

    http_proxy_t proxy;
    std::string err;
    REQUIRE(proxy.start(0, nullptr, &err));
    REQUIRE(proxy.running());
    REQUIRE_GT(proxy.port(), 0);

    {
        // Raw-socket client with Connection: close so the proxy finishes
        // the exchange deterministically
        SOCKET c = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        REQUIRE(c != INVALID_SOCKET);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = htons(proxy.port());
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        REQUIRE(connect(c, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0);
        std::string req = "GET /hi HTTP/1.1\r\nHost: 127.0.0.1:" +
                          std::to_string(origin_port) +
                          "\r\nConnection: close\r\n\r\n";
        send(c, req.c_str(), static_cast<int>(req.size()), 0);
        std::string resp;
        char buf[4096];
        int r;
        while ((r = recv(c, buf, sizeof(buf), 0)) > 0)
            resp.append(buf, static_cast<size_t>(r));
        REQUIRE(resp.find("origin-body") != std::string::npos);
        closesocket(c);
    }

    auto entries = proxy.recent(16);
    bool found = false;
    uint64_t replay_id = 0;
    for (const auto& e : entries) {
        if (e.kind == "http" && e.path == "/hi" && e.status == 200) {
            found = true;
            replay_id = e.id;
        }
    }
    REQUIRE(found);

    // Replay the logged request and get the same body back
    std::string rerr;
    auto resp = proxy.replay(replay_id, &rerr);
    REQUIRE(resp.has_value());
    std::string body(reinterpret_cast<const char*>(resp->data()), resp->size());
    REQUIRE(body.find("origin-body") != std::string::npos);

    proxy.stop();
    origin.stop();
    origin_thread.join();
}




