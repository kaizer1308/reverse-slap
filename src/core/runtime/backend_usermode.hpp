#pragma once

// src/core/runtime/backend_usermode.hpp
// Win32 user-mode backend (OpenProcess / ReadProcessMemory / etc.)

#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

class backend_usermode_t final : public backend_t {
public:
    backend_usermode_t() = default;
    ~backend_usermode_t() override = default;

    // Identity
    backend_kind_t kind() const noexcept override;
    const char*    badge() const noexcept override;

    // Attach / Detach
    target_handle_t attach(uint32_t pid) override;
    void            detach(target_handle_t& h) override;

    // Memory
    io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) override;
    io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) override;
    io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t new_prot, uint32_t* old_prot) override;
    io_result_t allocate_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t prot, uintptr_t* out_addr) override;
    io_result_t free_memory(const target_handle_t& h, uintptr_t addr) override;

    // Enumeration
    enum_result_t<process_info_t> enum_processes() override;
    enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) override;
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override;

    // Thread context
    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    // Query
    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override;
};

} // namespace slop::core::runtime
