#pragma once

// src/core/runtime/backend_kernel.hpp
// kernel backend over the driver, no persistent handle in the target, everything rides ioctls
// a few ops still fall back to a lazy user handle

#include "core/runtime/backend.hpp"
#include "core/runtime/backend_usermode.hpp"

#include <memory>

namespace voyager {
class device_t;
}

namespace slop::core::runtime {

// walk the targets peb module list, shared with the peb_modules action
struct peb_module_info_t {
    uint64_t    base         = 0;
    uint64_t    entry_point  = 0;
    uint32_t    size         = 0;
    std::string name;
    std::string path;
    uint32_t    flags        = 0;
};
std::vector<peb_module_info_t> kernel_peb_modules(voyager::device_t& dev);

class backend_kernel_t final : public backend_t {
public:
    backend_kernel_t();
    ~backend_kernel_t() override;

    backend_kernel_t(const backend_kernel_t&)            = delete;
    backend_kernel_t& operator=(const backend_kernel_t&) = delete;

    bool connect();     // open \\.\slopdrvr
    void disconnect();

    // Identity
    backend_kind_t kind() const noexcept override;
    const char*    badge() const noexcept override;

    // Attach / Detach
    target_handle_t attach(uint32_t pid) override;
    void            detach(target_handle_t& h) override;

    // Memory (kernel)
    io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) override;
    io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) override;
    io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len,
                               uint32_t new_prot, uint32_t* old_prot) override;
    io_result_t allocate_memory(const target_handle_t& h, uintptr_t hint, size_t len,
                                uint32_t prot, uintptr_t* out_addr) override;
    io_result_t free_memory(const target_handle_t& h, uintptr_t addr) override;

    // regions threads and modules via the driver, processes and handles stay user mode
    enum_result_t<process_info_t> enum_processes() override { return user_.enum_processes(); }
    enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) override;
    enum_result_t<thread_info_t>  enum_threads(uint32_t pid) override;
    enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) override;
    enum_result_t<handle_info_t>  enum_handles(uint32_t pid) override { return user_.enum_handles(pid); }

    // Thread context: both directions through the driver (no OpenThread)
    io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) override;
    io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) override;

    // Query
    arch_t      query_arch(const target_handle_t& h) override;
    elevation_t query_elevation() override { return user_.query_elevation(); }

    // HW breakpoint surface (used by debugger when kernel badge is live)
    bool hwbp_supported() const noexcept { return hwbp_supported_; }
    bool set_hw_breakpoint(uint32_t pid, uint32_t slot, uint32_t tid,
                           uint64_t address, uint32_t length_bytes,
                           uint32_t type = 0);
    bool clear_hw_breakpoint(uint32_t pid, uint32_t slot, uint32_t tid);

    // opaque device for domain services, null when disconnected
    voyager::device_t* device() const noexcept { return dev_.get(); }

private:
    bool ready_for_pid(uint32_t pid) const noexcept;
    bool apply_hw_breakpoint(uint32_t tid, uint32_t slot, uint64_t address,
                             uint32_t length_bytes, bool set, uint32_t type);
    // Lazily open the legacy user handle for ops without a driver path
    target_handle_t& ensure_user_handle(target_handle_t& h);

    backend_usermode_t                 user_;
    std::unique_ptr<voyager::device_t> dev_;
    bool                               hwbp_supported_ = false;
};

} // namespace slop::core::runtime
