// src/core/network/traffic_store.cpp

#include "core/network/traffic_store.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace slop::core::network {

namespace {

constexpr uint32_t kProtoTcp = 6;
constexpr uint32_t kProtoUdp = 17;

#pragma pack(push, 1)
struct eth_header_t {
    uint8_t  dst[6] = {0x02, 0, 0, 0, 0, 1};
    uint8_t  src[6] = {0x02, 0, 0, 0, 0, 2};
    uint16_t ethertype = 0x0800;   // IPv4
};

struct ipv4_header_t {
    uint8_t  ver_ihl = 0x45;
    uint8_t  tos = 0;
    uint16_t total_len = 0;
    uint16_t id = 0;
    uint16_t flags_frag = 0x4000;  // DF
    uint8_t  ttl = 64;
    uint8_t  protocol = 6;
    uint16_t checksum = 0;         // synthesized captures are not verified
    uint32_t src = 0;
    uint32_t dst = 0;
};

struct tcp_header_t {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t  data_off = 0x50;
    uint8_t  flags = 0x18;         // PSH|ACK
    uint16_t window = 0xFFFF;
    uint16_t csum = 0;
    uint16_t urg = 0;
};                                  // 20 bytes

struct udp_header_t {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t len = 0;
    uint16_t csum = 0;
};                                  // 8 bytes
#pragma pack(pop)

uint16_t host_to_net16(uint16_t v) {
    return static_cast<uint16_t>((v << 8) | (v >> 8));
}

uint16_t ip_to_bytes(const std::string& addr, uint8_t out[16]) {
    std::memset(out, 0, 16);
    unsigned a, b, c, d = 0;
    if (std::sscanf(addr.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) == 4 &&
        a < 256 && b < 256 && c < 256 && d < 256) {
        out[0] = static_cast<uint8_t>(a);
        out[1] = static_cast<uint8_t>(b);
        out[2] = static_cast<uint8_t>(c);
        out[3] = static_cast<uint8_t>(d);
        return 4;
    }
    return 0;
}

bool addr_prefix_match(const std::string& addr, const std::string& needle) {
    return addr.rfind(needle, 0) == 0 || addr.find(needle) != std::string::npos;
}

bool payload_contains_ascii(const std::vector<uint8_t>& p,
                            const std::string& needle) {
    if (needle.empty()) return true;
    const auto it = std::search(p.begin(), p.end(), needle.begin(), needle.end());
    return it != p.end();
}

} // namespace

traffic_store_t::traffic_store_t(size_t max_packets)
    : max_packets_(max_packets) {}

void traffic_store_t::clear() {
    std::lock_guard lk(mu_);
    pkts_.clear();
    streams_.clear();
    next_id_ = 1;
    next_stream_id_ = 1;
}

void traffic_store_t::index_stream(const packet_record_t& p) {
    stream_key_t key;
    key.protocol = p.protocol;

    // Client side = lower (addr,port); stable tuple normalization
    bool local_is_a =
        p.local_addr < p.remote_addr ||
        (p.local_addr == p.remote_addr && p.local_port <= p.remote_port);
    key.a_addr = local_is_a ? p.local_addr : p.remote_addr;
    key.a_port = local_is_a ? p.local_port : p.remote_port;
    key.b_addr = local_is_a ? p.remote_addr : p.local_addr;
    key.b_port = local_is_a ? p.remote_port : p.local_port;

    auto it = streams_.find(key);
    if (it == streams_.end()) {
        stream_rec_t rec;
        rec.key = key;
        rec.id = next_stream_id_++;
        rec.first_ms = p.at_ms;
        it = streams_.emplace(key, std::move(rec)).first;
    }
    auto& s = it->second;
    s.last_ms = p.at_ms;
    if (!s.has_client && p.direction == 0) {
        s.has_client   = true;
        s.client_addr  = p.local_addr;
        s.client_port  = p.local_port;
        s.server_addr  = p.remote_addr;
        s.server_port  = p.remote_port;
    }
    constexpr size_t kMaxStreamPayloadBytes = 1024 * 1024; // 1 MiB per direction
    if (p.direction == 0) {
        if (s.c2s.size() < kMaxStreamPayloadBytes) {
            const size_t take = std::min(p.payload.size(), kMaxStreamPayloadBytes - s.c2s.size());
            s.c2s.insert(s.c2s.end(), p.payload.begin(), p.payload.begin() + take);
        }
        ++s.c2s_packets;
    } else {
        if (s.s2c.size() < kMaxStreamPayloadBytes) {
            const size_t take = std::min(p.payload.size(), kMaxStreamPayloadBytes - s.s2c.size());
            s.s2c.insert(s.s2c.end(), p.payload.begin(), p.payload.begin() + take);
        }
        ++s.s2c_packets;
    }
}

void traffic_store_t::add(packet_record_t pkt) {
    std::lock_guard lk(mu_);
    pkt.id = next_id_++;
    index_stream(pkt);
    pkts_.push_back(std::move(pkt));
    while (pkts_.size() > max_packets_) pkts_.pop_front();

    constexpr size_t kMaxStreams = 4096;
    if (streams_.size() > kMaxStreams) {
        auto oldest = streams_.begin();
        for (auto it = streams_.begin(); it != streams_.end(); ++it) {
            if (it->second.last_ms < oldest->second.last_ms) oldest = it;
        }
        streams_.erase(oldest);
    }
}

traffic_store_t::page_t traffic_store_t::packets(uint64_t from_id,
                                                 size_t limit) const {
    std::lock_guard lk(mu_);
    page_t out;
    for (const auto& p : pkts_) {
        if (p.id <= from_id) continue;
        if (out.items.size() >= limit) { out.truncated = true; break; }
        out.items.push_back(p);
    }
    return out;
}

size_t traffic_store_t::size() const {
    std::lock_guard lk(mu_);
    return pkts_.size();
}

std::vector<stream_summary_t> traffic_store_t::streams() const {
    std::lock_guard lk(mu_);
    std::vector<stream_summary_t> out;
    out.reserve(streams_.size());
    for (const auto& [key, s] : streams_) {
        stream_summary_t sum;
        sum.id = s.id;
        char buf[256];
        std::snprintf(buf, sizeof(buf), "%s %s:%u<->%s:%u",
                      key.protocol == kProtoTcp ? "tcp" :
                      key.protocol == kProtoUdp ? "udp" : "ip",
                      key.a_addr.c_str(), key.a_port,
                      key.b_addr.c_str(), key.b_port);
        sum.key         = buf;
        sum.client_addr = s.has_client ? s.client_addr : key.a_addr;
        sum.client_port = s.has_client ? s.client_port : key.a_port;
        sum.server_addr = s.has_client ? s.server_addr : key.b_addr;
        sum.server_port = s.has_client ? s.server_port : key.b_port;
        sum.bytes       = s.c2s.size() + s.s2c.size();
        sum.packets     = s.c2s_packets + s.s2c_packets;
        sum.first_ms    = s.first_ms;
        sum.last_ms     = s.last_ms;
        out.push_back(std::move(sum));
    }
    std::sort(out.begin(), out.end(),
              [](const stream_summary_t& a, const stream_summary_t& b) {
                  return a.last_ms > b.last_ms;
              });
    return out;
}

std::optional<stream_summary_t> traffic_store_t::stream(uint64_t id) const {
    auto all = streams();
    for (auto& s : all)
        if (s.id == id) return s;
    return std::nullopt;
}

std::optional<std::vector<uint8_t>> traffic_store_t::stream_bytes(
    uint64_t id, size_t offset, size_t len) const {
    std::lock_guard lk(mu_);
    for (const auto& [key, s] : streams_) {
        if (s.id != id) continue;
        std::vector<uint8_t> merged;
        merged.reserve(s.c2s.size() + s.s2c.size());
        merged.insert(merged.end(), s.c2s.begin(), s.c2s.end());
        merged.insert(merged.end(), s.s2c.begin(), s.s2c.end());
        if (offset >= merged.size()) return std::vector<uint8_t>{};
        const size_t take = std::min(len, merged.size() - offset);
        return std::vector<uint8_t>(merged.begin() + offset,
                                    merged.begin() + offset + take);
    }
    return std::nullopt;
}

bool traffic_store_t::eval_filter(const packet_record_t& p,
                                  const std::string& expr) {
    // ';' ANDs predicates. Empty expression matches everything
    size_t begin = 0;
    while (begin <= expr.size()) {
        size_t end = expr.find(';', begin);
        if (end == std::string::npos) end = expr.size();
        std::string term = expr.substr(begin, end - begin);
        begin = end + 1;
        // trim
        while (!term.empty() && (term.front() == ' ')) term.erase(term.begin());
        while (!term.empty() && (term.back() == ' ')) term.pop_back();
        if (term.empty()) continue;

        bool pass = false;
        if (term.rfind("port=", 0) == 0) {
            const uint16_t port = static_cast<uint16_t>(
                std::strtoul(term.c_str() + 5, nullptr, 10));
            pass = p.local_port == port || p.remote_port == port;
        } else if (term.rfind("host:", 0) == 0) {
            const std::string h = term.substr(5);
            pass = addr_prefix_match(p.local_addr, h) ||
                   addr_prefix_match(p.remote_addr, h);
        } else if (term.rfind("text:", 0) == 0) {
            pass = payload_contains_ascii(p.payload, term.substr(5));
        } else if (term.rfind("pid:", 0) == 0) {
            pass = p.pid == std::strtoul(term.c_str() + 4, nullptr, 10);
        } else if (term.rfind("proto:", 0) == 0) {
            const std::string pr = term.substr(6);
            if (pr == "tcp") pass = p.protocol == kProtoTcp;
            else if (pr == "udp") pass = p.protocol == kProtoUdp;
            else pass = p.protocol == std::strtoul(pr.c_str(), nullptr, 10);
        } else {
            pass = false;   // unknown predicate never matches silently
        }
        if (!pass) return false;
    }
    return true;
}

traffic_store_t::page_t traffic_store_t::packets_filtered(
    uint64_t from_id, size_t limit, const std::string& expr) const {
    std::lock_guard lk(mu_);
    page_t out;
    for (const auto& p : pkts_) {
        if (p.id <= from_id) continue;
        if (!eval_filter(p, expr)) continue;
        if (out.items.size() >= limit) { out.truncated = true; break; }
        out.items.push_back(p);
    }
    return out;
}

bool traffic_store_t::write_pcap(const std::string& path,
                                 const std::vector<packet_record_t>& pkts,
                                 std::string* error) const {
    std::FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "wb");
    if (!f) {
        if (error) *error = "cannot open output file";
        return false;
    }

#pragma pack(push, 1)
    struct pcap_global_t {
        uint32_t magic = 0xa1b2c3d4;
        uint16_t major = 2, minor = 4;
        uint32_t thiszone = 0, sigfigs = 0;
        uint32_t snaplen = 0x40000;
        uint32_t network = 1;   // LINKTYPE_ETHERNET
    };
    struct pcap_rec_hdr_t {
        uint32_t ts_sec, ts_usec, incl_len, orig_len;
    };
#pragma pack(pop)

    pcap_global_t gh;
    fwrite(&gh, sizeof(gh), 1, f);

    for (const auto& p : pkts) {
        uint8_t la[16], ra[16];
        ip_to_bytes(p.local_addr, la);
        ip_to_bytes(p.remote_addr, ra);

        const bool udp = p.protocol == kProtoUdp;
        const uint16_t sport = p.direction == 0 ? p.local_port : p.remote_port;
        const uint16_t dport = p.direction == 0 ? p.remote_port : p.local_port;
        const size_t l4_size = udp ? 8u : 20u;

        ipv4_header_t ip;
        ip.protocol = p.protocol == 0 ? kProtoTcp : p.protocol;
        std::memcpy(&ip.src, la, 4);
        std::memcpy(&ip.dst, ra, 4);
        uint16_t total = static_cast<uint16_t>(20 + l4_size + p.payload.size());
        ip.total_len = host_to_net16(total);

        eth_header_t eth;
        std::vector<uint8_t> frame;
        frame.reserve(sizeof(eth) + sizeof(ip) + l4_size + p.payload.size());
        frame.insert(frame.end(),
                     reinterpret_cast<const uint8_t*>(&eth),
                     reinterpret_cast<const uint8_t*>(&eth) + sizeof(eth));
        frame.insert(frame.end(),
                     reinterpret_cast<const uint8_t*>(&ip),
                     reinterpret_cast<const uint8_t*>(&ip) + sizeof(ip));
        if (udp) {
            udp_header_t u;
            u.src_port = host_to_net16(sport);
            u.dst_port = host_to_net16(dport);
            u.len      = host_to_net16(static_cast<uint16_t>(8 + p.payload.size()));
            frame.insert(frame.end(),
                         reinterpret_cast<const uint8_t*>(&u),
                         reinterpret_cast<const uint8_t*>(&u) + sizeof(u));
        } else {
            tcp_header_t t;
            t.src_port = host_to_net16(sport);
            t.dst_port = host_to_net16(dport);
            frame.insert(frame.end(),
                         reinterpret_cast<const uint8_t*>(&t),
                         reinterpret_cast<const uint8_t*>(&t) + sizeof(t));
        }
        frame.insert(frame.end(), p.payload.begin(), p.payload.end());

        pcap_rec_hdr_t rh;
        rh.ts_sec  = static_cast<uint32_t>(p.at_ms / 1000);
        rh.ts_usec = static_cast<uint32_t>((p.at_ms % 1000) * 1000);
        rh.incl_len = rh.orig_len = static_cast<uint32_t>(frame.size());
        fwrite(&rh, sizeof(rh), 1, f);
        fwrite(frame.data(), 1, frame.size(), f);
    }
    fclose(f);
    return true;
}

} // namespace slop::core::network
