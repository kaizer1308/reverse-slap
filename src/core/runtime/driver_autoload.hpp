#pragma once

// src/core/runtime/driver_autoload.hpp
// boot time driver bring up, probe, find the mapper, run it, probe again, seams are injectable for tests

#include <functional>
#include <optional>
#include <string>

namespace slop::core::runtime::driver_autoload {

struct artifact_paths_t {
    std::string mapper_exe;
    std::string driver_sys;
    bool mapper_found = false;
    bool sys_found    = false;
    bool complete() const noexcept { return mapper_found && sys_found; }
};

// exe dir first, then the build tree two levels up
artifact_paths_t find_artifacts(const std::string& exe_dir);

bool device_present();

// Returns process exit code, or -1 when the process could not be spawned
using spawn_fn = std::function<int(const std::string& mapper_exe,
                                   const std::string& sys_path,
                                   std::string* log_tail)>;

struct load_report_t {
    bool        was_loaded   = false;
    bool        attempted    = false;
    bool        ok           = false;
    std::string error;          // non-fatal description when !ok
    std::string log_tail;       // mapper log excerpt when attempted
};

// the state machine over explicit inputs, the unit test seam
load_report_t ensure_loaded_with(bool artifacts_available,
                                 const std::string& mapper_exe,
                                 const std::string& sys_path,
                                 const std::function<bool()>& probe,
                                 const spawn_fn& spawn);

// Directory-based discovery + delegation
load_report_t ensure_loaded(const std::string& exe_dir,
                            const std::function<bool()>& probe,
                            const spawn_fn& spawn);

// real system wrapper, live probe plus createprocess with a 60s timeout
load_report_t ensure_loaded_real(const std::string& exe_dir);

// clean shutdown asks the driver for its key, arms the quiesce flag, releases the
// handles, unloads and deletes the key, failure just leaves it loaded
struct unload_report_t {
    bool        was_loaded = false;   // device present on entry
    bool        attempted  = false;   // unload path entered
    bool        ok         = false;   // service gone (or was never loaded)
    std::string service_path;         // registry key reported by the driver
    std::string error;                // reason when !ok
};

// injectable seams, ntstatus stands in as a plain long
// test harness
using unload_service_fn = std::function<long(const std::wstring& service_path)>;

unload_report_t request_unload_with(
    const std::function<bool()>& probe,
    const std::function<bool(std::wstring&)>& query_identity,
    const std::function<bool()>& arm_shutdown,
    const std::function<void()>& release_handles,
    const unload_service_fn& unload_service);

// Live path: drives the kernel backend's voyager device through the seams
unload_report_t request_driver_unload();

} // namespace slop::core::runtime::driver_autoload
