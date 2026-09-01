#pragma once

// src/core/runtime/kernel_service.hpp
// kernel domain operations over the driver, everything degrades to an error string when the bridge is down

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace slop::core::runtime {

struct kernel_module_t {
    uint64_t    base = 0;
    uint32_t    size = 0;
    std::string name;
};

struct window_info_t {
    void*       hwnd = nullptr;
    uint32_t    pid = 0;
    std::string title;
    std::string klass;
};

namespace kernel_svc {

bool available();

std::vector<kernel_module_t> enumerate_modules(std::string* error = nullptr);

// dump a loaded drivers memory image to a pe file
std::string dump_module(uint64_t base, uint32_t size,
                        const std::string& out_path);

std::string kernel_read(uint64_t addr, size_t len,
                        std::vector<uint8_t>* out);
std::string kernel_write(uint64_t addr, const std::vector<uint8_t>& bytes);
std::vector<uint64_t> kernel_search(uint64_t begin, uint64_t end,
                                    const std::vector<uint8_t>& pattern,
                                    size_t max_hits);

std::optional<uint64_t> call_function(uint64_t addr, uint64_t a1 = 0,
                                      uint64_t a2 = 0, uint64_t a3 = 0,
                                      uint64_t a4 = 0);
std::optional<uint64_t> virtual_to_physical(uint64_t va);

struct ssdt_result_t {
    bool ok = false;
    std::string error;
    uint64_t lstar = 0;
    uint64_t service_table = 0;
    uint32_t service_limit = 0;
    // Decoded handler addresses (table_base + entry>>4), capped at 512
    std::vector<uint64_t> handlers;
};
ssdt_result_t query_ssdt();

struct peb_result_t {
    bool ok = false;
    std::string error;
    uint64_t peb_address = 0;
    uint64_t image_base = 0;
    uint64_t ldr_address = 0;
    uint64_t process_heap = 0;
    uint32_t being_debugged = 0;
};
peb_result_t read_peb();

// resolve an export through the driver
std::optional<uint64_t> resolve_export(uint64_t module_base,
                                       const std::string& export_name);

std::vector<window_info_t> enumerate_windows(uint32_t filter_pid);

} // namespace kernel_svc
} // namespace slop::core::runtime
