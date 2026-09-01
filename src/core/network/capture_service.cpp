// src/core/network/capture_service.cpp

#include "core/network/capture_service.hpp"

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/voyager_comm.h"

#include <chrono>

namespace slop::core::network {

namespace {

voyager::device_t* active_device() {
    auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
    return k ? k->device() : nullptr;
}

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

std::string ip_to_text(const uint8_t a[16], uint32_t family) {
    char buf[64] = {};
    if (family == 2) {   // AF_INET6 stored as 16 bytes
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7],
                      a[8], a[9], a[10], a[11], a[12], a[13], a[14], a[15]);
        return buf;
    }
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
    return buf;
}

packet_record_t to_record(const voyager::device_t::captured_packet& p) {
    packet_record_t r;
    r.at_ms      = static_cast<int64_t>(p.timestamp / 1000);   // us -> ms best-effort
    r.pid        = p.pid;
    r.protocol   = p.protocol;
    r.direction  = p.direction;
    r.local_port = static_cast<uint16_t>(p.local_port);
    r.remote_port= static_cast<uint16_t>(p.remote_port);
    r.local_addr = ip_to_text(p.local_addr, p.address_family);
    r.remote_addr= ip_to_text(p.remote_addr, p.address_family);
    r.payload    = p.payload;
    return r;
}

} // namespace

bool capture::kernel_available() { return active_device() != nullptr; }

std::string capture::start(uint32_t filter_pid, uint32_t filter_port,
                           uint32_t filter_protocol) {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    return dev->start_capture(filter_pid, filter_port, filter_protocol)
               ? "" : "start_capture failed (driver rejected)";
}

std::string capture::stop() {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    return dev->stop_capture() ? "" : "stop_capture failed";
}

size_t capture::poll(traffic_store_t& sink, size_t max_packets) {
    auto* dev = active_device();
    if (!dev || max_packets == 0) return 0;
    auto packets = dev->get_captured_packets_bounded(
        static_cast<uint32_t>(std::min<size_t>(max_packets, 1024)), 250);
    size_t n = 0;
    for (auto& p : packets) {
        sink.add(to_record(p));
        ++n;
    }
    return n;
}

std::vector<dns_record_t> capture::dns_queries(uint32_t filter_pid) {
    std::vector<dns_record_t> out;
    auto* dev = active_device();
    if (!dev) return out;
    for (const auto& d : dev->get_dns_queries(filter_pid)) {
        dns_record_t r;
        r.timestamp     = d.timestamp;
        r.pid           = d.pid;
        r.query_type    = d.query_type;
        r.domain        = d.domain;
        r.resolved_addr = ip_to_text(d.resolved_addr, 2);
        r.response_code = d.response_code;
        r.ttl           = d.ttl;
        out.push_back(std::move(r));
    }
    return out;
}

std::string capture::add_filter_rule(const filter_rule_t& rule,
                                     uint32_t* out_rule_id) {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    uint32_t id = 0;
    if (!dev->add_filter_rule(rule.action, rule.direction, rule.protocol,
                              rule.pid, rule.port, nullptr, nullptr, &id))
        return "add_filter_rule failed";
    if (out_rule_id) *out_rule_id = id;
    return "";
}

std::string capture::remove_filter_rule(uint32_t rule_id) {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    return dev->remove_filter_rule(rule_id) ? "" : "remove_filter_rule failed";
}

std::string capture::clear_filter_rules() {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    return dev->clear_filter_rules() ? "" : "clear_filter_rules failed";
}

std::optional<net_stats_t> capture::stats() {
    auto* dev = active_device();
    if (!dev) return std::nullopt;
    voyager::device_t::network_stats s{};
    if (!dev->get_network_stats(s)) return std::nullopt;
    net_stats_t out;
    out.bytes_sent          = s.bytes_sent;
    out.bytes_received      = s.bytes_received;
    out.packets_sent        = s.packets_sent;
    out.packets_received    = s.packets_received;
    out.active_connections  = s.active_connections;
    out.capture_active      = s.capture_active != 0;
    out.total_captured      = s.total_captured;
    out.total_dropped       = s.total_dropped;
    out.total_dns_logged    = s.total_dns_logged;
    out.active_filter_rules = s.active_filter_rules;
    return out;
}

std::string capture::export_pcap(const std::string& path, uint32_t filter_pid,
                                 uint32_t max_packets) {
    auto* dev = active_device();
    if (!dev) return "kernel driver not active";
    voyager::device_t::pcap_export_result out{};
    if (!dev->export_pcap(filter_pid, 0, max_packets, &out))
        return "export_pcap failed";

    // the driver hands back ready made pcap records, wrap each frame as a
    // payload only record
    traffic_store_t tmp;
    std::vector<packet_record_t> recs;
    recs.reserve(out.packets.size());
    for (const auto& p : out.packets) {
        packet_record_t r;
        r.at_ms = static_cast<int64_t>(p.ts_sec) * 1000ll +
                  p.ts_usec / 1000;
        r.protocol = 6;
        r.local_addr  = "127.0.0.1";
        r.remote_addr = "127.0.0.1";
        r.payload     = p.data;
        recs.push_back(std::move(r));
    }
    std::string err;
    if (!tmp.write_pcap(path, recs, &err))
        return err;
    return "";
}

} // namespace slop::core::network


