// src/core/infra/app_control.cpp

#include "core/infra/app_control.hpp"

#include <atomic>
#include <mutex>

#include "core/infra/event_bus.hpp"

namespace slop::core::infra::app_control {

namespace {
std::atomic<bool> g_quit{false};
std::mutex        g_mu;
std::string       g_reason;
} // namespace

void request_quit(std::string reason) {
    {
        std::lock_guard lk(g_mu);
        if (g_quit.load(std::memory_order_acquire)) return;   // first wins
        g_reason = std::move(reason);
    }
    g_quit.store(true, std::memory_order_release);
    event_bus::publish("app.quitting",
                       nlohmann::json{{"reason", quit_reason()}});
}

bool quit_requested() noexcept { return g_quit.load(std::memory_order_acquire); }

std::string quit_reason() {
    std::lock_guard lk(g_mu);
    return g_reason;
}

void reset() {
    std::lock_guard lk(g_mu);
    g_reason.clear();
    g_quit.store(false, std::memory_order_release);
}

} // namespace slop::core::infra::app_control
