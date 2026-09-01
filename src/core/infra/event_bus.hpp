#pragma once

// src/core/infra/event_bus.hpp
// event hub for the front end plus the app output ring
// the ring keeps numbered lines so a late connection can catch up and
// the fan out pushes frames to everyone without waiting on slow readers

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json.hpp>

namespace slop::core::infra::event_bus {

// app output ring

struct output_line_t {
    uint64_t    seq = 0;   // monotonic, never reused
    int64_t     ms  = 0;   // wall clock at append
    std::string text;
};

// one output line, also goes out as an event
void output(std::string_view line);

// everything after the given seq, 0 for the whole ring
std::vector<output_line_t> output_since(uint64_t since);

// newest seq so far, 0 when empty
uint64_t output_revision() noexcept;

void output_clear();

// zero copy walk of the ring, keep it short and never re enter
void output_visit(const std::function<void(const output_line_t&)>& fn);

// event fan out

// serialize once, queue everywhere, never blocks
void publish(std::string_view type, const nlohmann::json& data);

// only sends when the payload actually changed so an idle engine stays quiet
void publish_changed(std::string_view type, const nlohmann::json& data);

class subscriber_t {
public:
    ~subscriber_t();

    subscriber_t(const subscriber_t&)            = delete;
    subscriber_t& operator=(const subscriber_t&) = delete;

    // drain queued frames, false once the bus is dead, empty means timeout
    bool wait(std::string& out, uint32_t timeout_ms);

    // frames dropped when the queue was full
    uint64_t dropped() const noexcept;

    struct impl_t;
    explicit subscriber_t(std::shared_ptr<impl_t> impl);

private:
    std::shared_ptr<impl_t> impl_;
};

std::shared_ptr<subscriber_t> subscribe();

size_t subscriber_count();

// wake everyone and close up shop
void shutdown();

// reset everything so tests can reuse the bus
void reset();

} // namespace slop::core::infra::event_bus
