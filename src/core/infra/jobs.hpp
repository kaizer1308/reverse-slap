#pragma once

// src/core/infra/jobs.hpp
// long jobs each get their own thread so they cant starve the pool

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "core/infra/cancel.hpp"

namespace slop::core::infra {

enum class job_state_t : uint8_t { queued, running, succeeded, cancelled, failed };

struct job_snapshot_t {
    uint64_t    id          = 0;
    std::string label;
    std::string owner;
    std::string stage;
    std::string error;
    float       progress    = -1.0f;   // -1 = indeterminate
    job_state_t state       = job_state_t::queued;
    bool        cancellable = false;
    int64_t     started_ms  = 0;
    int64_t     finished_ms = 0;
};

class job_context_t {
public:
    const cancel_token_t& cancel() const noexcept;
    bool  cancelled() const noexcept;
    void  set_stage(std::string s);
    void  set_progress(float p);
    void  set_progress(uint64_t done, uint64_t total);
    void  fail(std::string message);
    uint64_t id() const noexcept;

    // internals, hands off
    struct impl_t;
    explicit job_context_t(impl_t* p) : impl_(p) {}
private:
    impl_t* impl_ = nullptr;
};

struct job_desc_t {
    std::string label;
    std::string owner;
    bool        cancellable = true;
    std::function<void(job_context_t&)> body;
};

using jobs_view_t = std::vector<job_snapshot_t>;

namespace jobs {

uint64_t submit(job_desc_t d);          // 0 = rejected (cap reached)
bool     cancel(uint64_t id);
bool     alive(uint64_t id);

std::shared_ptr<const jobs_view_t> snapshot();

// call once a frame to join finished jobs
void reap();

// cancel all and join what we can
void shutdown(uint32_t deadline_ms = 3000);

// clear the shutdown flag for tests
void reset();

} // namespace jobs
} // namespace slop::core::infra
