#pragma once

// security artifact detection with no new kernel code, hidden modules,
// minifilters, etw sessions, kernel callbacks through the bridge

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::detect {

struct module_entry_t {
    uint64_t    base = 0;
    uint32_t    size = 0;
    std::string name;
};

struct hidden_module_report_t {
    std::vector<module_entry_t> psapi_only;    // in EnumDeviceDrivers, missing
                                               // from SystemModuleInformation
    std::vector<module_entry_t> sysinfo_only;  // vice versa
};

hidden_module_report_t detect_hidden_modules(std::string* error = nullptr);

struct minifilter_t {
    std::string name;
    std::string altitude;
    uint32_t    frame_id = 0;
};
std::vector<minifilter_t> enumerate_minifilters(std::string* error = nullptr);

struct etw_session_t {
    uint64_t    handle = 0;
    uint32_t    buffers_written = 0;
    uint32_t    events_lost = 0;
    std::string logger_name;
};
std::vector<etw_session_t> enumerate_etw_sessions(std::string* error = nullptr);

struct callback_entry_t {
    std::string kind;      // "process" | "thread" | "image"
    uint64_t    slot = 0;
    uint64_t    handler = 0;
};
struct callback_report_t {
    bool ok = false;
    std::string error;
    std::vector<callback_entry_t> entries;
};
callback_report_t enumerate_kernel_callbacks();

} // namespace slop::core::detect
