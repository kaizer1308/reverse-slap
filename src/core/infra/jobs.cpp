#include "core/infra/jobs.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/published.hpp"

#include <algorithm>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>

namespace slop::core::infra {

// job internals

struct job_context_t::impl_t {
    uint64_t           id = 0;
    cancel_source_t    cancel_src;
    cancel_token_t     tok;
    std::atomic<float> progress{-1.0f};
    std::mutex         mu;
    std::string        stage;
    std::string        error;
    job_state_t        state = job_state_t::queued;
    int64_t            started_ms  = 0;
    int64_t            finished_ms = 0;
    std::string        label;
    std::string        owner;
    bool               cancellable = true;
    std::thread        thread;
    bool               joined = false;

    impl_t() : tok(cancel_src.token()) {}
};

const cancel_token_t& job_context_t::cancel() const noexcept { return impl_->tok; }
bool job_context_t::cancelled() const noexcept { return impl_->tok.cancelled(); }
uint64_t job_context_t::id() const noexcept { return impl_->id; }

void job_context_t::set_stage(std::string s) {
    std::lock_guard lk(impl_->mu);
    impl_->stage = std::move(s);
}

void job_context_t::set_progress(float p) {
    impl_->progress.store(p, std::memory_order_relaxed);
}

void job_context_t::set_progress(uint64_t done, uint64_t total) {
    if (total == 0) return;
    set_progress(static_cast<float>(done) / static_cast<float>(total));
}

void job_context_t::fail(std::string message) {
    std::lock_guard lk(impl_->mu);
    impl_->error = std::move(message);
    impl_->state = job_state_t::failed;
}

// the jobs namespace

namespace jobs {

namespace {

std::mutex                                       g_mu;
std::vector<std::shared_ptr<job_context_t::impl_t>> g_jobs;
std::atomic<uint64_t>                            g_next_id{1};
published_t<jobs_view_t>                         g_published;
std::atomic<bool>                                g_shutting_down{false};

void rebuild_snapshot() {
    auto view = std::make_shared<jobs_view_t>();
    view->reserve(g_jobs.size());
    for (auto& j : g_jobs) {
        job_snapshot_t s;
        s.id          = j->id;
        s.label       = j->label;
        s.owner       = j->owner;
        s.cancellable = j->cancellable;
        s.progress    = j->progress.load(std::memory_order_relaxed);
        s.started_ms  = j->started_ms;
        s.finished_ms = j->finished_ms;
        {
            std::lock_guard lk(j->mu);
            s.stage = j->stage;
            s.error = j->error;
            s.state = j->state;
        }
        view->push_back(std::move(s));
    }
    g_published.publish(std::move(view));
}

} // namespace

uint64_t submit(job_desc_t d) {
    if (g_shutting_down.load(std::memory_order_acquire)) return 0;

    std::lock_guard lk(g_mu);
    // count live jobs
    size_t live = 0;
    for (auto& j : g_jobs) {
        std::lock_guard jlk(j->mu);
        if (j->state == job_state_t::queued || j->state == job_state_t::running)
            ++live;
    }
    if (live >= limits::max_live_jobs) return 0;

    auto impl        = std::make_shared<job_context_t::impl_t>();
    impl->id         = g_next_id.fetch_add(1, std::memory_order_relaxed);
    impl->label      = std::move(d.label);
    impl->owner      = std::move(d.owner);
    impl->cancellable = d.cancellable;

    const uint64_t job_id = impl->id;
    auto body = std::move(d.body);

    impl->thread = std::thread([impl, body = std::move(body)]() mutable {
        {
            std::lock_guard lk(impl->mu);
            impl->state      = job_state_t::running;
            impl->started_ms = steady_ms();
        }
        job_context_t ctx(impl.get());
        body(ctx);
        {
            std::lock_guard lk(impl->mu);
            if (impl->state == job_state_t::running) {
                impl->state = impl->tok.cancelled()
                    ? job_state_t::cancelled
                    : job_state_t::succeeded;
            }
            impl->finished_ms = steady_ms();
        }
    });

    g_jobs.push_back(std::move(impl));
    rebuild_snapshot();
    return job_id;
}

bool cancel(uint64_t id) {
    std::lock_guard lk(g_mu);
    for (auto& j : g_jobs) {
        if (j->id == id && j->cancellable) {
            j->cancel_src.request();
            return true;
        }
    }
    return false;
}

bool alive(uint64_t id) {
    std::lock_guard lk(g_mu);
    for (auto& j : g_jobs) {
        if (j->id != id) continue;
        std::lock_guard jlk(j->mu);
        return j->state == job_state_t::queued || j->state == job_state_t::running;
    }
    return false;
}

std::shared_ptr<const jobs_view_t> snapshot() {
    return g_published.get();
}

void reap() {
    std::lock_guard lk(g_mu);
    bool changed = false;
    for (auto& j : g_jobs) {
        if (j->joined) continue;
        std::lock_guard jlk(j->mu);
        if (j->state == job_state_t::queued || j->state == job_state_t::running)
            continue;
        // finished, join it
        if (j->thread.joinable()) j->thread.join();
        j->joined = true;
        changed = true;
    }
    // keep the last 32 finished jobs
    while (g_jobs.size() > 32) {
        auto it = std::find_if(g_jobs.begin(), g_jobs.end(), [](auto& j) { return j->joined; });
        if (it == g_jobs.end()) break;
        g_jobs.erase(it);
        changed = true;
    }
    if (changed) rebuild_snapshot();
}

void reset() {
    // let tests reuse the coordinator
    g_shutting_down.store(false, std::memory_order_release);
}

void shutdown(uint32_t deadline_ms) {
    g_shutting_down.store(true, std::memory_order_release);

    std::lock_guard lk(g_mu);
    // cancel everything
    for (auto& j : g_jobs) {
        j->cancel_src.request();
    }

    const auto deadline = std::chrono::steady_clock::now()
                        + std::chrono::milliseconds(deadline_ms);

    for (auto& j : g_jobs) {
        if (j->joined || !j->thread.joinable()) continue;
        const auto remaining = deadline - std::chrono::steady_clock::now();
        if (remaining > std::chrono::milliseconds(0)) {
            j->thread.join();
        } else {
            j->thread.detach();
        }
        j->joined = true;
    }
    g_jobs.clear();
}

} // namespace jobs
} // namespace slop::core::infra
