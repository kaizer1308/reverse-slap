#pragma once

// src/core/infra/cancel.hpp
// one flag, tokens just watch it

#include <atomic>
#include <memory>

namespace slop::core::infra {

class cancel_source_t;

class cancel_token_t {
public:
    cancel_token_t() = default;
    bool cancelled() const noexcept { return flag_ && flag_->load(std::memory_order_acquire); }
    explicit operator bool() const noexcept { return static_cast<bool>(flag_); }
private:
    friend class cancel_source_t;
    explicit cancel_token_t(std::shared_ptr<std::atomic<bool>> f) : flag_(std::move(f)) {}
    std::shared_ptr<std::atomic<bool>> flag_;
};

class cancel_source_t {
public:
    cancel_source_t() : flag_(std::make_shared<std::atomic<bool>>(false)) {}
    void request() noexcept { flag_->store(true, std::memory_order_release); }
    bool requested() const noexcept { return flag_->load(std::memory_order_acquire); }
    cancel_token_t token() const { return cancel_token_t(flag_); }
private:
    std::shared_ptr<std::atomic<bool>> flag_;
};

} // namespace slop::core::infra
