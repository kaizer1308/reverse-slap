// src/core/runtime/backend_winotify.hpp
// kernel backend over the WHQL-signed WinNotify driver, the stealth path:
// legit load, no mapper, no handle in the target, phys r/w through the
// kpti-correct dtb. ops the driver can't do fall back to the lazy user handle
// exactly like backend_kernel_t does

#pragma once

#include "core/runtime/backend.hpp"
#include "core/runtime/backend_usermode.hpp"
#include "core/runtime/winotify_driver.hpp"

#include <memory>

namespace slop::core::runtime {

class backend_winotify_t final : public backend_t {
public:
    backend_winotify_t() = default;
    ~backend_winotify_t() override;

    backend_winotify_t(const backend_winotify_t&)            = delete;
    backend_winotify_t& operator=(const backend_winotify_t&) = delete;

    bool connect();
    void disconnect();
    bool wipe_headers();   // zero the loaded image's pe headers via its own phys path

    backend_kind_t kind() const noexcept override;
    const char*    badge() const noexcept override;

    target_handle_t attach(uint32_t pid) override;
    void            detach(target_handle_t& h) override;

    io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) override;
    io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) override;
    io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len,
                               uint32_t new_prot, uint32_t* old_prot) override;
    io_result_t allocate_memory(const target_handle_t& h, uintptr_t hint, size_t len,
                                uint32_t prot, uintptr_t* out_addr) override;
    io_result_t free_memory(const target_handle_t& h, uintptr_t addr) override;

    enum_result_t<process_info_t> enum_processes() override { return user_.enum_processes(); }
    enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) override;
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override;

    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override { return user_.query_elevation(); }

    winotify::driver_t* device() const noexcept { return dev_.get(); }

private:
    std::uint64_t handle_dtb(const target_handle_t& h) const noexcept;

    std::unique_ptr<winotify::driver_t> dev_;
    backend_usermode_t                  user_;
};

} // namespace slop::core::runtime
