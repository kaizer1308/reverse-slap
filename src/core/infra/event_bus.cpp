// src/core/infra/event_bus.cpp

#include "core/infra/event_bus.hpp"

#include "core/infra/clock.hpp"

#include <atomic>
#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace slop::core::infra::event_bus {

namespace {

using json = nlohmann::json;

constexpr size_t kMaxOutput      = 4096;   // lines retained for replay
constexpr size_t kMaxQueueFrames = 512;    // per-subscriber backlog

std::mutex                  g_out_mu;
std::deque<output_line_t>   g_out;
uint64_t                    g_out_seq = 0;

std::atomic<bool>           g_open{true};

std::mutex                                   g_last_mu;
std::unordered_map<std::string, std::string> g_last;   // type -> last payload

// frames are shared so a publish is one allocation no matter how many listeners
using frame_t = std::shared_ptr<const std::string>;

} // namespace

struct subscriber_t::impl_t {
    std::mutex              mu;
    std::condition_variable cv;
    std::deque<frame_t>     q;
    uint64_t                dropped = 0;
    bool                    closed  = false;

    void push(const frame_t& f) {
        {
            std::lock_guard lk(mu);
            if (closed) return;
            if (q.size() >= kMaxQueueFrames) {
                q.pop_front();     // drop oldest: fresh state beats stale
                ++dropped;
            }
            q.push_back(f);
        }
        cv.notify_one();
    }

    void close() {
        {
            std::lock_guard lk(mu);
            closed = true;
        }
        cv.notify_all();
    }
};

namespace {

std::mutex                                          g_sub_mu;
std::vector<std::weak_ptr<subscriber_t::impl_t>>    g_subs;

// one sse frame, bytes can be junk so bad utf8 gets swapped not thrown
frame_t make_frame(std::string_view type, std::string_view encoded) {
    std::string s;
    s.reserve(16 + type.size() + encoded.size());
    s += "event: ";
    s.append(type.data(), type.size());
    s += "\ndata: ";
    s += encoded;
    s += "\n\n";
    return std::make_shared<const std::string>(std::move(s));
}

void fan_out(const frame_t& f) {
    std::vector<std::shared_ptr<subscriber_t::impl_t>> live;
    {
        std::lock_guard lk(g_sub_mu);
        live.reserve(g_subs.size());
        for (auto it = g_subs.begin(); it != g_subs.end();) {
            if (auto sp = it->lock()) {
                live.push_back(std::move(sp));
                ++it;
            } else {
                it = g_subs.erase(it);   // reap dead subscribers lazily
            }
        }
    }
    // push outside the registry lock so publishes never stack up
    for (const auto& sp : live) sp->push(f);
}

} // namespace

// app output ring

void output(std::string_view line) {
    output_line_t rec;
    {
        std::lock_guard lk(g_out_mu);
        rec.seq  = ++g_out_seq;
        rec.ms   = wall_ms();
        rec.text.assign(line);
        if (g_out.size() >= kMaxOutput) g_out.pop_front();
        g_out.push_back(rec);
    }
    publish("output", json{{"seq", rec.seq}, {"ms", rec.ms}, {"text", rec.text}});
}

std::vector<output_line_t> output_since(uint64_t since) {
    std::vector<output_line_t> out;
    std::lock_guard lk(g_out_mu);
    const auto first = std::upper_bound(g_out.begin(), g_out.end(), since,
        [](uint64_t seq, const output_line_t& line) { return seq < line.seq; });
    out.assign(first, g_out.end());
    return out;
}

uint64_t output_revision() noexcept {
    std::lock_guard lk(g_out_mu);
    return g_out_seq;
}

void output_clear() {
    {
        std::lock_guard lk(g_out_mu);
        g_out.clear();
    }
    publish("output.cleared", json::object());
}

void output_visit(const std::function<void(const output_line_t&)>& fn) {
    if (!fn) return;
    std::lock_guard lk(g_out_mu);
    for (const auto& l : g_out) fn(l);
}

// event fan out

void publish(std::string_view type, const json& data) {
    if (!g_open.load(std::memory_order_acquire)) return;
    {
        std::lock_guard lk(g_sub_mu);
        if (g_subs.empty()) return;    // nobody listening: skip serialization
    }
    try {
        fan_out(make_frame(type, data.dump(-1, ' ', false, json::error_handler_t::replace)));
    } catch (...) {
        // a publish must never take down whoever called it
    }
}

void publish_changed(std::string_view type, const json& data) {
    if (!g_open.load(std::memory_order_acquire)) return;
    std::string encoded;
    try {
        encoded = data.dump(-1, ' ', false, json::error_handler_t::replace);
    } catch (...) {
        return;
    }
    {
        std::lock_guard lk(g_last_mu);
        auto [it, inserted] = g_last.try_emplace(std::string(type), encoded);
        if (!inserted) {
            if (it->second == encoded) return;   // unchanged: stay silent
            it->second = encoded;
        }
    }
    try {
        // Reuse the serialization used for change detection.
        std::lock_guard lk(g_sub_mu);
        if (g_subs.empty()) return;
    } catch (...) { return; }
    try { fan_out(make_frame(type, encoded)); } catch (...) {}
}

// subscriber

subscriber_t::subscriber_t(std::shared_ptr<impl_t> impl) : impl_(std::move(impl)) {}

subscriber_t::~subscriber_t() {
    if (impl_) impl_->close();
}

bool subscriber_t::wait(std::string& out, uint32_t timeout_ms) {
    out.clear();
    if (!impl_) return false;

    std::deque<frame_t> batch;
    {
        std::unique_lock lk(impl_->mu);
        if (impl_->q.empty() && !impl_->closed) {
            impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                               [this] { return !impl_->q.empty() || impl_->closed; });
        }
        batch.swap(impl_->q);
        if (batch.empty() && impl_->closed) return false;
    }
    // squash the backlog into one write, way cheaper than a send per frame
    size_t total = 0;
    for (const auto& f : batch) total += f->size();
    out.reserve(total);
    for (const auto& f : batch) out += *f;
    return true;
}

uint64_t subscriber_t::dropped() const noexcept {
    if (!impl_) return 0;
    std::lock_guard lk(impl_->mu);
    return impl_->dropped;
}

std::shared_ptr<subscriber_t> subscribe() {
    auto impl = std::make_shared<subscriber_t::impl_t>();
    if (!g_open.load(std::memory_order_acquire)) impl->closed = true;
    {
        std::lock_guard lk(g_sub_mu);
        g_subs.emplace_back(impl);
    }
    return std::make_shared<subscriber_t>(std::move(impl));
}

size_t subscriber_count() {
    std::lock_guard lk(g_sub_mu);
    size_t n = 0;
    for (const auto& w : g_subs)
        if (!w.expired()) ++n;
    return n;
}

void shutdown() {
    g_open.store(false, std::memory_order_release);
    std::vector<std::shared_ptr<subscriber_t::impl_t>> live;
    {
        std::lock_guard lk(g_sub_mu);
        for (const auto& w : g_subs)
            if (auto sp = w.lock()) live.push_back(std::move(sp));
        g_subs.clear();
    }
    for (const auto& sp : live) sp->close();
}

void reset() {
    shutdown();
    {
        std::lock_guard lk(g_out_mu);
        g_out.clear();
        g_out_seq = 0;
    }
    {
        std::lock_guard lk(g_last_mu);
        g_last.clear();
    }
    g_open.store(true, std::memory_order_release);
}

} // namespace slop::core::infra::event_bus
