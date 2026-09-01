// src/core/memory/watch_service.cpp

#include "core/memory/watch_service.hpp"

#include <algorithm>
#include <mutex>

#include "core/infra/clock.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/limits.hpp"
#include "core/process/target_service.hpp"

namespace slop::core::memory::watch {

namespace {

using json = nlohmann::json;
namespace bus = infra::event_bus;

// Ported verbatim from view_scanner.cpp: the watch pane never issued more than
// 64 target reads per pass, so a 4096-entry list could not stall the caller
constexpr int   kMaxLiveReads   = 64;
constexpr int64_t kSampleIntervalMs = 100;   // ~10 Hz

struct state_t {
    std::mutex           mu;
    std::vector<entry_t> entries;
    std::vector<value_t> last;
    uint64_t             next_id     = 1;
    int64_t              last_pass_ms = 0;
};

state_t& st() {
    static state_t s;
    return s;
}

entry_t* find(state_t& s, uint64_t id) {
    auto it = std::find_if(s.entries.begin(), s.entries.end(),
                           [id](const entry_t& e) { return e.id == id; });
    return it == s.entries.end() ? nullptr : &*it;
}

const char* width_name(value_width_t w) noexcept {
    switch (w) {
    case value_width_t::i8:  return "i8";
    case value_width_t::u8:  return "u8";
    case value_width_t::i16: return "i16";
    case value_width_t::u16: return "u16";
    case value_width_t::i32: return "i32";
    case value_width_t::u32: return "u32";
    case value_width_t::i64: return "i64";
    case value_width_t::u64: return "u64";
    case value_width_t::f32: return "f32";
    case value_width_t::f64: return "f64";
    }
    return "?";
}

json entry_json(const entry_t& e) {
    return json{{"id", e.id},
                {"addr", e.addr},
                {"width", width_name(e.width)},
                {"label", e.label},
                {"freeze", e.freeze},
                {"frozen_bits", e.frozen_bits},
                {"frozen_text", format_value_text(e.width, e.frozen_bits)}};
}

void publish_list_locked(const state_t& s) {
    json arr = json::array();
    for (const auto& e : s.entries) arr.push_back(entry_json(e));
    bus::publish("watch.list", json{{"entries", std::move(arr)}});
}

} // namespace

uint64_t add(uint64_t addr, value_width_t width, std::string label) {
    state_t& s = st();
    uint64_t id = 0;
    {
        std::lock_guard lk(s.mu);
        if (s.entries.size() >= infra::limits::max_watch_entries) return 0;
        entry_t e;
        e.id          = s.next_id++;
        e.addr        = addr;
        e.width       = width;
        e.label       = std::move(label);
        e.freeze      = false;
        e.frozen_bits = 0;
        id = e.id;
        s.entries.push_back(std::move(e));
        publish_list_locked(s);
    }
    return id;
}

bool remove(uint64_t id) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    const auto before = s.entries.size();
    s.entries.erase(std::remove_if(s.entries.begin(), s.entries.end(),
                                   [id](const entry_t& e) { return e.id == id; }),
                    s.entries.end());
    if (s.entries.size() == before) return false;
    s.last.erase(std::remove_if(s.last.begin(), s.last.end(),
                                [id](const value_t& v) { return v.id == id; }),
                 s.last.end());
    publish_list_locked(s);
    return true;
}

void clear() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.entries.clear();
    s.last.clear();
    publish_list_locked(s);
}

bool set_freeze(uint64_t id, bool on) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    if (on && !e->freeze) {
        // Latch whatever the last sample saw, exactly like ticking the ImGui
        // checkbox did, freezing must hold the value on screen, not zero
        auto it = std::find_if(s.last.begin(), s.last.end(),
                               [id](const value_t& v) { return v.id == id; });
        if (it != s.last.end() && it->ok) e->frozen_bits = it->bits;
    }
    e->freeze = on;
    publish_list_locked(s);
    return true;
}

bool poke(uint64_t id, uint64_t bits, std::string* err) {
    state_t& s = st();
    uint64_t  addr  = 0;
    size_t    n     = 0;
    bool      found = false;
    {
        std::lock_guard lk(s.mu);
        entry_t* e = find(s, id);
        if (!e) {
            if (err) *err = "no such watch entry";
            return false;
        }
        addr  = e->addr;
        n     = value_size(e->width);
        found = true;
        e->frozen_bits = bits;   // frozen or not, this is now the held value
    }
    if (!found) return false;

    auto session = process::active_session();
    if (!session || !session->valid()) {
        if (err) *err = "no target attached";
        return false;
    }
    const auto res = session->write(static_cast<uintptr_t>(addr), &bits, n);
    if (!res.ok && err) *err = "write failed";
    if (res.ok) {
        std::lock_guard lk(s.mu);
        publish_list_locked(s);
    }
    return res.ok;
}

bool set_width(uint64_t id, value_width_t width) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    e->width = width;
    publish_list_locked(s);
    return true;
}

bool set_label(uint64_t id, std::string label) {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    entry_t* e = find(s, id);
    if (!e) return false;
    e->label = std::move(label);
    publish_list_locked(s);
    return true;
}

std::vector<entry_t> list() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.entries;
}

std::vector<value_t> values() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.last;
}

size_t size() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    return s.entries.size();
}

void tick() {
    state_t& s = st();

    // Snapshot under the lock, then touch the target outside it: a kernel-path
    // read must never be holding the list mutex that the UI thread wants
    std::vector<entry_t> snap;
    {
        std::lock_guard lk(s.mu);
        if (s.entries.empty()) {
            if (!s.last.empty()) s.last.clear();
            return;
        }
        const int64_t now = infra::steady_ms();
        if (now - s.last_pass_ms < kSampleIntervalMs) return;
        s.last_pass_ms = now;
        snap = s.entries;
    }

    auto session = process::active_session();
    if (!session || !session->valid()) {
        std::lock_guard lk(s.mu);
        if (!s.last.empty()) {
            s.last.clear();
            bus::publish("watch.values", json{{"attached", false},
                                              {"values", json::array()}});
        }
        return;
    }

    std::vector<value_t> sampled;
    sampled.reserve(snap.size());
    int reads = 0;

    for (const auto& e : snap) {
        const size_t n = value_size(e.width);
        value_t v;
        v.id   = e.id;
        v.addr = e.addr;
        v.held = e.freeze;

        uint64_t bits = 0;
        if (reads < kMaxLiveReads &&
            session->read(static_cast<uintptr_t>(e.addr), &bits, n).ok) {
            ++reads;
            v.ok   = true;
            v.bits = bits;
        }

        if (e.freeze) {
            // frozen entries report the held value and write it back with the same
            // truncation the imgui path had
            v.bits = e.frozen_bits;
            v.ok   = true;
            uint64_t hold = e.frozen_bits;
            session->write(static_cast<uintptr_t>(e.addr), &hold, n);
        }

        v.text = v.ok ? format_value_text(e.width, v.bits) : std::string("-");
        sampled.push_back(std::move(v));
    }

    // Track live values into frozen_bits while unfrozen so that flipping the
    // freeze on latches the value the caller is looking at
    bool changed = false;
    {
        std::lock_guard lk(s.mu);
        for (const auto& v : sampled) {
            entry_t* e = find(s, v.id);
            if (e && !e->freeze && v.ok) e->frozen_bits = v.bits;
        }
        changed = s.last.size() != sampled.size();
        if (!changed) {
            for (size_t i = 0; i < sampled.size(); ++i) {
                if (s.last[i].id != sampled[i].id ||
                    s.last[i].ok != sampled[i].ok ||
                    s.last[i].bits != sampled[i].bits) {
                    changed = true;
                    break;
                }
            }
        }
        s.last = sampled;
    }

    if (!changed) return;   // nothing moved: keep the event stream quiet

    json arr = json::array();
    for (const auto& v : sampled)
        arr.push_back(json{{"id", v.id},
                           {"addr", v.addr},
                           {"ok", v.ok},
                           {"held", v.held},
                           {"bits", v.bits},
                           {"text", v.text}});
    bus::publish("watch.values", json{{"attached", true},
                                      {"values", std::move(arr)}});
}

void shutdown() {
    state_t& s = st();
    std::lock_guard lk(s.mu);
    s.entries.clear();
    s.last.clear();
    s.last_pass_ms = 0;
}

} // namespace slop::core::memory::watch
