// src/core/infra/deferred.cpp

#include "core/infra/deferred.hpp"

#include <algorithm>

namespace slop::core::infra {

deferred_manager_t& deferred_manager_t::get() {
    static deferred_manager_t m;
    return m;
}

bool deferred_manager_t::bind_executor(const std::string& kind,
                                       executor_t fn) {
    std::lock_guard lk(mu_);
    return executors_.emplace(kind, std::move(fn)).second;
}

uint64_t deferred_manager_t::submit(const std::string& kind,
                                    const std::string& params_json) {
    std::lock_guard lk(mu_);
    deferred_action_t a;
    a.id = next_id_++;
    a.kind = kind;
    a.params_json = params_json;
    a.status = "pending";
    a.created_ms = 0;   // caller-visible ordering via id
    actions_.push_back(std::move(a));
    while (actions_.size() > 256) actions_.pop_front();
    return actions_.back().id;
}

std::vector<deferred_action_t> deferred_manager_t::list() const {
    std::lock_guard lk(mu_);
    return {actions_.begin(), actions_.end()};
}

std::optional<deferred_action_t> deferred_manager_t::get(uint64_t id) const {
    std::lock_guard lk(mu_);
    for (const auto& a : actions_)
        if (a.id == id) return a;
    return std::nullopt;
}

size_t deferred_manager_t::execute_pending(const std::string& kind) {
    std::lock_guard lk(mu_);
    size_t ran = 0;
    for (auto& a : actions_) {
        if (a.status != "pending") continue;
        if (!kind.empty() && a.kind != kind) continue;
        const auto it = executors_.find(a.kind);
        if (it == executors_.end()) continue;
        std::string result;
        const bool ok = it->second(a.params_json, &result);
        a.status   = ok ? "done" : "failed";
        a.result_json = result;
        ++ran;
    }
    return ran;
}

bool deferred_manager_t::cancel(uint64_t id) {
    std::lock_guard lk(mu_);
    for (auto& a : actions_) {
        if (a.id == id && a.status == "pending") {
            a.status = "cancelled";
            return true;
        }
    }
    return false;
}

void deferred_manager_t::clear() {
    std::lock_guard lk(mu_);
    actions_.clear();
}

size_t deferred_manager_t::size() const {
    std::lock_guard lk(mu_);
    return actions_.size();
}

} // namespace slop::core::infra
