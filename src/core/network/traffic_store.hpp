#pragma once

// in memory traffic store, bounded packet ring, stream reassembly by
// tuple, display filters and pcap export with synthesized framing

#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::network {

struct packet_record_t {
    uint64_t              id = 0;          // monotonic store id
    int64_t               at_ms = 0;       // wall clock
    uint32_t              pid = 0;
    uint32_t              protocol = 0;    // 6 TCP / 17 UDP / 0 other
    uint32_t              direction = 0;   // 0 outbound, 1 inbound
    std::string           local_addr;
    uint16_t              local_port = 0;
    std::string           remote_addr;
    uint16_t              remote_port = 0;
    std::vector<uint8_t>  payload;
};

struct stream_summary_t {
    uint64_t    id = 0;
    std::string key;            // "tcp 127.0.0.1:1234<->10.0.0.1:80"
    std::string client_addr;    // initiator side (lower port heuristic v1)
    uint16_t    client_port = 0;
    std::string server_addr;
    uint16_t    server_port = 0;
    size_t      bytes = 0;
    size_t      packets = 0;
    int64_t     first_ms = 0;
    int64_t     last_ms = 0;
};

class traffic_store_t {
public:
    explicit traffic_store_t(size_t max_packets = 20000);

    void clear();
    void add(packet_record_t pkt);                       // assigns id

    // Packets newest-last within [from_id+1 .. to_id], capped
    struct page_t { std::vector<packet_record_t> items; bool truncated = false; };
    page_t packets(uint64_t from_id, size_t limit) const;

    // streams
    std::vector<stream_summary_t> streams() const;       // ordered by last activity
    std::optional<stream_summary_t> stream(uint64_t id) const;

    // Reassembled payload slice of one direction-merged stream
    // Returns raw bytes (client->server then server->client, arrival order)
    std::optional<std::vector<uint8_t>> stream_bytes(uint64_t id,
                                                     size_t offset, size_t len) const;

    // filtering, one predicate or anded with semicolons:
    //   port==80 | port=80        either side port
    //   host:1.2.3.4              either side address contains/prefix
    //   text:foo                  payload ASCII substring
    //   pid:4242
    //   proto:tcp|udp|num
    static bool eval_filter(const packet_record_t& p, const std::string& expr);
    page_t packets_filtered(uint64_t from_id, size_t limit,
                            const std::string& expr) const;

    // pcap export synthesizes eth ipv4 and tcp or udp headers around each payload
    bool write_pcap(const std::string& path,
                    const std::vector<packet_record_t>& pkts,
                    std::string* error = nullptr) const;

    size_t size() const;

private:
    struct stream_key_t {
        uint32_t protocol = 0;
        std::string a_addr; uint16_t a_port = 0;
        std::string b_addr; uint16_t b_port = 0;
        bool operator<(const stream_key_t& o) const {
            if (protocol != o.protocol) return protocol < o.protocol;
            if (a_addr != o.a_addr) return a_addr < o.a_addr;
            if (a_port != o.a_port) return a_port < o.a_port;
            if (b_addr != o.b_addr) return b_addr < o.b_addr;
            return b_port < o.b_port;
        }
    };

    mutable std::mutex mu_;
    std::deque<packet_record_t> pkts_;
    uint64_t next_id_ = 1;
    size_t max_packets_;

    struct stream_rec_t {
        stream_key_t key;
        std::vector<uint8_t> c2s;      // client -> server bytes
        std::vector<uint8_t> s2c;
        size_t c2s_packets = 0, s2c_packets = 0;
        int64_t first_ms = 0, last_ms = 0;
        uint64_t id = 0;
        bool has_client = false;
        std::string client_addr;
        uint16_t    client_port = 0;
        std::string server_addr;
        uint16_t    server_port = 0;
    };
    std::map<stream_key_t, stream_rec_t> streams_;
    uint64_t next_stream_id_ = 1;

    void index_stream(const packet_record_t& p);
};

} // namespace slop::core::network
