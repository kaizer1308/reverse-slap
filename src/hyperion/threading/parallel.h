#pragma once
// Fork-join parallel_for over the session WorkerPool, plus the worker
// thread-count config.
//
// Contract: fn(i) may run on any pool thread and must be thread-safe for
// concurrent calls with distinct i. Chunks are contiguous index ranges
// handed out in order, so per-chunk outputs merged by chunk index stay
// deterministic across runs. Never call from a pool worker thread itself
// (the call blocks waiting for pool tasks).

#include "worker_pool.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <future>
#include <thread>
#include <vector>

namespace hype {

// Worker threads for analysis parallelism. SLOP_WORKER_THREADS overrides
// (unset/0 = hardware_concurrency); clamped to [1, 16]. Read on every call
// with no cache so tests can switch counts within one process.
inline unsigned worker_thread_count() {
    unsigned n = 0;
    if (const char* env = std::getenv("SLOP_WORKER_THREADS")) {
        char* end = nullptr;
        const unsigned long v = std::strtoul(env, &end, 10);
        if (end != env) n = static_cast<unsigned>(v);
    }
    if (n == 0) n = std::thread::hardware_concurrency();
    if (n == 0) n = 4;
    return std::clamp(n, 1u, 16u);
}

// Contiguous chunking shared by both entry points below.
inline size_t chunk_count(WorkerPool& pool, size_t n) {
    if (n <= 1 || pool.thread_count() <= 1) return n == 0 ? 0 : 1;
    return std::min(n, static_cast<size_t>(pool.thread_count()) * 4);
}

// fn(chunk, begin, end) over contiguous chunks in index order.
template <typename F>
void parallel_for_chunks(WorkerPool& pool, size_t n, F&& fn) {
    const size_t chunks = chunk_count(pool, n);
    if (chunks <= 1) {
        if (n > 0) fn(static_cast<size_t>(0), static_cast<size_t>(0), n);
        return;
    }
    const size_t span = (n + chunks - 1) / chunks;
    std::vector<std::future<void>> futs;
    futs.reserve(chunks);
    for (size_t c = 0; c < chunks; ++c) {
        const size_t begin = c * span;
        const size_t end = std::min(n, begin + span);
        futs.push_back(pool.submit([begin, end, c, &fn] {
            fn(c, begin, end);
        }));
    }
    for (auto& f : futs) f.get();  // rethrows the first worker exception
}

// fn(i) for every i in [0, n).
template <typename F>
void parallel_for(WorkerPool& pool, size_t n, F&& fn) {
    parallel_for_chunks(pool, n, [&](size_t, size_t begin, size_t end) {
        for (size_t i = begin; i < end; ++i) fn(i);
    });
}

}  // namespace hype
