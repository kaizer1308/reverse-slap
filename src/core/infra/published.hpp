#pragma once

// src/core/infra/published.hpp
// one writer many readers snapshot, readers just copy the pointer

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>

namespace slop::core::infra {

template <class T>
class published_t {
public:
    published_t() {
        std::lock_guard lk(mu_);
        slot_ = std::make_shared<const T>();
    }

    std::shared_ptr<const T> get() const {
        std::lock_guard lk(mu_);
        return slot_;
    }

    void publish(std::shared_ptr<const T> v) {
        std::lock_guard lk(mu_);
        slot_ = std::move(v);
        rev_.fetch_add(1, std::memory_order_relaxed);
    }

    uint64_t revision() const noexcept {
        return rev_.load(std::memory_order_acquire);
    }

private:
    mutable std::mutex          mu_;
    std::shared_ptr<const T>    slot_;
    std::atomic<uint64_t>       rev_{0};
};

} // namespace slop::core::infra
