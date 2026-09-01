#pragma once

// src/core/runtime/backend.hpp
// one interface, two implementations, user mode and kernel

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::runtime {

// enums

enum class backend_kind_t : uint8_t {
    user_mode,
    kernel
};

enum class arch_t : uint8_t {
    unknown,
    x86,
    x64,
    arm64
};

enum class elevation_t : uint8_t {
    unknown,
    standard,
    elevated,
    system
};

// pod types

struct process_info_t {
    uint32_t    pid          = 0;
    uint32_t    parent_pid   = 0;
    arch_t      arch         = arch_t::unknown;
    elevation_t elevation    = elevation_t::unknown;
    std::string name;
    std::string path;
};

struct module_info_t {
    uintptr_t   base         = 0;
    uint32_t    size         = 0;
    std::string name;
    std::string path;
};

struct thread_info_t {
    uint32_t tid             = 0;
    uint32_t owner_pid       = 0;
    uintptr_t start_address  = 0;
    int32_t  priority        = 0;
};

struct region_info_t {
    uintptr_t base           = 0;
    size_t    size           = 0;
    uint32_t  protect        = 0;
    uint32_t  state          = 0;
    uint32_t  type           = 0;
};

struct handle_info_t {
    uintptr_t handle_value   = 0;
    uint32_t  type_index     = 0;
    uint32_t  granted_access = 0;
    std::string type_name;
    std::string object_name;
};

struct thread_context_t {
    uint64_t rip = 0;
    uint64_t rsp = 0;
    uint64_t rbp = 0;
    uint64_t rax = 0;
    uint64_t rbx = 0;
    uint64_t rcx = 0;
    uint64_t rdx = 0;
    uint64_t rsi = 0;
    uint64_t rdi = 0;
    uint64_t r8  = 0;
    uint64_t r9  = 0;
    uint64_t r10 = 0;
    uint64_t r11 = 0;
    uint64_t r12 = 0;
    uint64_t r13 = 0;
    uint64_t r14 = 0;
    uint64_t r15 = 0;
    uint64_t flags = 0;
};

struct target_handle_t {
    void*    native  = nullptr;
    uint32_t pid     = 0;
    bool     valid() const noexcept { return native != nullptr && pid != 0; }
};

struct io_result_t {
    bool     ok      = false;
    size_t   bytes   = 0;
    uint32_t error   = 0;
};

template <typename T>
struct enum_result_t {
    bool           ok    = false;
    uint32_t       error = 0;
    std::vector<T> items;
};

// the backend interface

class backend_t {
public:
    virtual ~backend_t() = default;

    // identity
    virtual backend_kind_t kind() const noexcept = 0;
    virtual const char*    badge() const noexcept = 0;

    // attach and detach
    virtual target_handle_t attach(uint32_t pid) = 0;
    virtual void            detach(target_handle_t& h) = 0;

    // memory
    virtual io_result_t read_memory(const target_handle_t& h, uintptr_t addr, void* buf, size_t len) = 0;
    virtual io_result_t write_memory(const target_handle_t& h, uintptr_t addr, const void* buf, size_t len) = 0;
    virtual io_result_t protect_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t new_prot, uint32_t* old_prot) = 0;
    virtual io_result_t allocate_memory(const target_handle_t& h, uintptr_t addr, size_t len, uint32_t prot, uintptr_t* out_addr) = 0;
    virtual io_result_t free_memory(const target_handle_t& h, uintptr_t addr) = 0;

    // enumeration
    virtual enum_result_t<process_info_t> enum_processes() = 0;
    virtual enum_result_t<module_info_t>  enum_modules(const target_handle_t& h) = 0;
    virtual enum_result_t<thread_info_t>  enum_threads(uint32_t pid) = 0;
    virtual enum_result_t<region_info_t>  enum_regions(const target_handle_t& h) = 0;
    virtual enum_result_t<handle_info_t>  enum_handles(uint32_t pid) = 0;

    // thread context
    virtual io_result_t get_thread_context(uint32_t tid, thread_context_t& ctx) = 0;
    virtual io_result_t set_thread_context(uint32_t tid, const thread_context_t& ctx) = 0;

    // query
    virtual arch_t      query_arch(const target_handle_t& h) = 0;
    virtual elevation_t query_elevation() = 0;
};

} // namespace slop::core::runtime
