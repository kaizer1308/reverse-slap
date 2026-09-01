#pragma once

// kernel wfp capture front end pulling packets into the traffic store,
// degrades gracefully when the bridge is down

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/network/traffic_store.hpp"

namespace slop::core::network {

struct dns_record_t {
    uint64_t    timestamp = 0;
    uint32_t    pid = 0;
    uint32_t    query_type = 0;
    std::string domain;
    std::string resolved_addr;
    uint32_t    response_code = 0;
    uint32_t    ttl = 0;
};

struct net_stats_t {
    uint64_t bytes_sent = 0, bytes_received = 0;
    uint64_t packets_sent = 0, packets_received = 0;
    uint32_t active_connections = 0;
    bool     capture_active = false;
    uint32_t total_captured = 0, total_dropped = 0;
    uint32_t total_dns_logged = 0, active_filter_rules = 0;
};

struct filter_rule_t {
    uint32_t action = 0;        // driver-defined action code
    uint32_t direction = 0;
    uint32_t protocol = 0;
    uint32_t pid = 0;
    uint32_t port = 0;
};

namespace capture {

bool kernel_available();

// Start kernel WFP capture. Zero filters = capture everything
std::string start(uint32_t filter_pid = 0, uint32_t filter_port = 0,
                  uint32_t filter_protocol = 0);

std::string stop();

// Pull newly captured packets into the store. Returns count pulled
size_t poll(traffic_store_t& sink, size_t max_packets = 512);

std::vector<dns_record_t> dns_queries(uint32_t filter_pid = 0);

// Returns rule id via out_rule_id on success
std::string add_filter_rule(const filter_rule_t& rule, uint32_t* out_rule_id);
std::string remove_filter_rule(uint32_t rule_id);
std::string clear_filter_rules();

std::optional<net_stats_t> stats();

// Driver-side pcap export (raw captured frames) written to `path`
std::string export_pcap(const std::string& path, uint32_t filter_pid = 0,
                        uint32_t max_packets = 4096);

} // namespace capture
} // namespace slop::core::network
