#pragma once

// src/core/infra/work_queue.hpp
// shared worker pool, pool tasks must never wait on other pool tasks

#include <cstdint>
#include <functional>

#include "core/infra/cancel.hpp"

namespace slop::core::infra::pool {

struct stats_t {
    uint32_t workers   = 0;
    uint32_t queued    = 0;
    uint32_t running   = 0;
    uint64_t completed = 0;
    uint64_t rejected  = 0;
};

// workers=0 means max(2, cores minus one)
void start(uint32_t workers = 0);

// drain, join, then detach stragglers
void stop(uint32_t drain_deadline_ms = 3000);

uint32_t worker_count() noexcept;
stats_t  snapshot();

// returns false when stopping or full
bool submit(std::function<void()> fn);

// spread count indices over the pool and wait, never call this from a worker
void parallel_for(size_t count, const cancel_token_t& tok,
                  const std::function<void(size_t index, uint32_t worker_slot)>& body,
                  uint32_t max_workers = 0);

} // namespace slop::core::infra::pool
