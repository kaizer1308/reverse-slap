#include "core/infra/diag.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/limits.hpp"

#include <deque>
#include <mutex>

namespace slop::core::infra::diag {

namespace {

std::mutex              g_mu;
std::deque<entry_t>    g_ring;
uint64_t               g_revision = 0;

} // namespace

void init() {
    std::lock_guard lk(g_mu);
    g_ring.clear();
    g_revision = 0;
}

void shutdown() {
    // nothing to free, the ring is static
}

void log(level_t level, std::string_view tag, std::string_view message) {
    entry_t e;
    e.timestamp_ms = steady_ms();
    e.level        = level;
    e.tag          = std::string(tag);
    e.message      = std::string(message);

    std::lock_guard lk(g_mu);
    if (g_ring.size() >= limits::diag_ring_capacity) {
        g_ring.pop_front();
    }
    g_ring.push_back(std::move(e));
    ++g_revision;
}

snapshot_t snapshot(uint64_t since_revision) {
    snapshot_t out;
    std::lock_guard lk(g_mu);
    out.revision = g_revision;

    if (since_revision >= g_revision) return out;

    // count entries newer than the given revision
    const uint64_t oldest_rev = g_revision - g_ring.size();
    const uint64_t start_rev  = (since_revision > oldest_rev) ? since_revision : oldest_rev;
    const size_t   skip       = static_cast<size_t>(start_rev - oldest_rev);

    out.entries.reserve(g_ring.size() - skip);
    for (size_t i = skip; i < g_ring.size(); ++i) {
        out.entries.push_back(g_ring[i]);
    }
    return out;
}

uint64_t revision() noexcept {
    std::lock_guard lk(const_cast<std::mutex&>(g_mu));
    return g_revision;
}

} // namespace slop::core::infra::diag
