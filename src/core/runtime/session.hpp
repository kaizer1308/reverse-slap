#pragma once

// src/core/runtime/session.hpp
// Session object, wraps an attached target with cached info and hot-path forwarders

#include "core/runtime/backend.hpp"

#include <cstdint>
#include <memory>
#include <string>

namespace slop::core::runtime {

class session_t {
public:
    session_t() = default;
    ~session_t();

    session_t(const session_t&) = delete;
    session_t& operator=(const session_t&) = delete;
    session_t(session_t&& other) noexcept;
    session_t& operator=(session_t&& other) noexcept;

    // Lifecycle
    bool open(uint32_t pid);
    void close();
    bool valid() const noexcept;

    // Info
    uint32_t           pid() const noexcept;
    const std::string& name() const noexcept;
    arch_t             arch() const noexcept;
    int64_t            epoch_ms() const noexcept;

    // Hot-path forwarders
    io_result_t read(uintptr_t addr, void* buf, size_t len);
    io_result_t write(uintptr_t addr, const void* buf, size_t len);

    // Access to underlying handle
    const target_handle_t& handle() const noexcept;

private:
    target_handle_t m_handle{};
    process_info_t  m_info{};
    int64_t         m_epoch_ms = 0;
};

using session_ref = std::shared_ptr<const session_t>;

} // namespace slop::core::runtime
