#pragma once

// src/core/infra/deferred.hpp
// queue up named actions and run them later on purpose

#include <cstdint>
#include <functional>
#include <map>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::infra {

struct deferred_action_t {
    uint64_t    id = 0;
    std::string kind;          // "call" | "kernel_read" | custom
    std::string params_json;   // opaque to the manager
    std::string status;        // pending | done | failed | cancelled
    std::string result_json;   // filled by the executor callback
    int64_t     created_ms = 0;
};

class deferred_manager_t {
public:
    static deferred_manager_t& get();

    // one executor per kind, false when its taken
    using executor_t =
        std::function<bool(const std::string& params_json, std::string* result_json)>;
    bool bind_executor(const std::string& kind, executor_t fn);

    uint64_t submit(const std::string& kind, const std::string& params_json);
    std::vector<deferred_action_t> list() const;
    std::optional<deferred_action_t> get(uint64_t id) const;

    // run everything pending, one kind or all
    size_t execute_pending(const std::string& kind = "");

    bool cancel(uint64_t id);
    void clear();
    size_t size() const;

private:
    mutable std::mutex mu_;
    std::deque<deferred_action_t> actions_;
    std::map<std::string, executor_t> executors_;
    uint64_t next_id_ = 1;
};

} // namespace slop::core::infra

