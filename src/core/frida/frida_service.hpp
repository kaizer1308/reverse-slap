#pragma once

// frida over the official devkit, one process wide singleton owns the device
// manager, sessions and scripts tracked by string handles, one mutex for
// the tables and one per script for the queues

#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// the dll boundary exists because fridas bundled glib collides with the
// unicorn shim in one static link
#if defined(_WIN32)
#  if defined(SLOP_FRIDA_BUILD)
#    define SLOP_FRIDA_API __declspec(dllexport)
#  else
#    define SLOP_FRIDA_API __declspec(dllimport)
#  endif
#else
#  define SLOP_FRIDA_API
#endif

namespace slop::core::frida {

// One agent->host message: raw JSON body + optional binary payload
struct script_message_t {
    int64_t              at_ms = 0;
    std::string          json;
    std::vector<uint8_t> data;
};

struct script_info_t {
    std::string handle;
    std::string name;
    std::string session;
    std::string runtime;              // "qjs" | "v8"
    bool        loaded = false;
    size_t      dropped = 0;          // ring overflows since last drain
};

struct session_info_t {
    std::string handle;
    uint32_t    pid = 0;
    std::string device;
    bool        detached = false;
    std::string detach_reason;
    uint32_t    crash_pid = 0;
    std::string crash_process;
    std::string crash_summary;
    std::string crash_report;
    std::map<std::string, std::string> crash_parameters;
    size_t      scripts = 0;
};

struct remote_options_t {
    std::string certificate_path;
    std::string certificate_pem;
    std::string origin;
    std::string token;
    int         keepalive_interval = -1;
};

struct spawn_output_t {
    int64_t              at_ms = 0;
    uint32_t             pid = 0;
    int                  fd = 0;
    bool                 eof = false;
    std::vector<uint8_t> data;
};

struct device_info_t {
    std::string id;
    std::string name;
    std::string dtype;                // "local" | "remote" | "usb"
};

struct process_info_t {
    uint32_t    pid = 0;
    std::string name;
    std::map<std::string, std::string> parameters;
};

struct application_info_t {
    std::string identifier;
    std::string name;
    uint32_t    pid = 0;
};

struct spawn_info_t {
    uint32_t    pid = 0;
    std::string identifier;
};

struct child_info_t {
    uint32_t    pid = 0;
    uint32_t    parent_pid = 0;
    std::string origin;               // "fork" | "exec" | "spawn"
    std::string identifier;
};

class SLOP_FRIDA_API frida_service_t {
public:
    static frida_service_t& get();
    ~frida_service_t();
    frida_service_t(const frida_service_t&) = delete;
    frida_service_t& operator=(const frida_service_t&) = delete;

    std::string version() const;
    bool        initialized() const;

    // Idempotent; creates the device manager on first use
    bool init(std::string* error);
    void shutdown();

    // Devices (empty device_id selects the local device everywhere below)
    bool list_devices(std::vector<device_info_t>* out, std::string* error);
    bool remote_add(const std::string& address, std::string* error);
    bool remote_add(const std::string& address, const remote_options_t& options,
                    std::string* error);
    bool remote_remove(const std::string& address, std::string* error);

    bool enumerate_processes(const std::string& device_id, const std::string& scope,
                             std::vector<process_info_t>* out, std::string* error);
    bool find_process(const std::string& device_id, const std::string& name,
                      std::optional<process_info_t>* out, std::string* error);
    bool enumerate_applications(const std::string& device_id, const std::string& scope,
                                std::vector<application_info_t>* out, std::string* error);
    bool frontmost_application(const std::string& device_id,
                               std::optional<application_info_t>* out, std::string* error);

    // Spawn / process lifecycle
    bool spawn(const std::string& device_id, const std::string& program,
               const std::vector<std::string>& argv, const std::vector<std::string>& env,
               const std::string& cwd, uint32_t* pid, std::string* error);
    bool spawn_piped(const std::string& device_id, const std::string& program,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& env, const std::string& cwd,
                     uint32_t* pid, std::string* error);
    bool read_spawn_output(const std::string& device_id, uint32_t pid, size_t max,
                           std::vector<spawn_output_t>* out, size_t* remaining,
                           size_t* dropped, std::string* error);
    bool input(const std::string& device_id, uint32_t pid,
               const std::vector<uint8_t>& data, std::string* error);
    bool resume(const std::string& device_id, uint32_t pid, std::string* error);
    bool kill(const std::string& device_id, uint32_t pid, std::string* error);
    bool enable_spawn_gating(const std::string& device_id, std::string* error);
    bool disable_spawn_gating(const std::string& device_id, std::string* error);
    bool pending_spawn(const std::string& device_id, std::vector<spawn_info_t>* out,
                       std::string* error);
    bool pending_children(const std::string& device_id, std::vector<child_info_t>* out,
                          std::string* error);

    // Sessions
    bool attach(const std::string& device_id, uint32_t pid, const std::string& realm,
                std::string* handle, std::string* error);
    bool detach_session(const std::string& handle, std::string* error);
    bool resume_session(const std::string& handle, std::string* error);
    bool enable_child_gating(const std::string& handle, std::string* error);
    bool disable_child_gating(const std::string& handle, std::string* error);
    bool list_sessions(std::vector<session_info_t>* out) const;

    // Scripts
    bool create_script(const std::string& session, const std::string& name,
                       const std::string& source, const std::string& runtime,
                       std::string* handle, std::string* error);
    bool create_script_from_bytes(const std::string& session, const std::string& name,
                                  const std::string& bytecode_b64,
                                  const std::string& runtime,
                                  std::string* handle, std::string* error);
    bool create_script_with_snapshot(const std::string& session, const std::string& name,
                                     const std::string& source,
                                     const std::string& snapshot_b64,
                                     const std::string& runtime,
                                     std::string* handle, std::string* error);
    bool load_script(const std::string& handle, std::string* error);
    bool unload_script(const std::string& handle, std::string* error);
    bool post_message(const std::string& handle, const std::string& message_json,
                      std::string* error);
    bool destroy_script(const std::string& handle, std::string* error);
    bool enable_script_debugger(const std::string& handle, uint16_t port, std::string* error);
    bool disable_script_debugger(const std::string& handle, std::string* error);
    bool list_scripts(std::vector<script_info_t>* out) const;

    // Non-blocking drain of a script's message ring (up to max; sets the
    // drop counter accumulated since the last drain)
    bool read_messages(const std::string& handle, size_t max,
                       std::vector<script_message_t>* out, size_t* dropped,
                       std::string* error);

    // rpc.exports invocation over the frida:rpc wire protocol. args_json is a
    // JSON array of arguments. Blocks up to timeout_ms for the reply
    bool rpc_call(const std::string& script, const std::string& method,
                   const std::string& args_json, int timeout_ms,
                   std::string* result_json, std::string* error,
                   std::function<bool()> cancelled = {});

    // frida-compile bundling of a TypeScript/JS project entrypoint
    bool compile_project(const std::string& entrypoint, const std::string& project_root,
                         std::string* output, std::string* error,
                         std::function<bool()> cancelled = {});

    // Compile plain JS to agent bytecode (base64), pairs with create_script
    bool compile_script(const std::string& session, const std::string& source,
                        const std::string& runtime, std::string* b64, std::string* error,
                        std::function<bool()> cancelled = {});

    // Snapshot an embed script into a runtime snapshot blob (base64)
    bool snapshot_script(const std::string& session, const std::string& embed_script,
                         const std::string& runtime, std::string* b64, std::string* error,
                         std::function<bool()> cancelled = {});

private:
    frida_service_t();

    // All frida-typed state lives in the .cpp (keeps frida-core.h out of
    // every TU that touches this header, it is a 2.6 MB umbrella header)
    struct impl_t;
    impl_t* impl_ = nullptr;

    // Full teardown of scripts/sessions/manager. call_mu held
    void teardown_locked();

    // Unload + release every script whose handle is in `handles`
    void destroy_session_scripts_locked(const std::vector<std::string>& handles);

    bool spawn_impl_locked(const std::string& device_id, const std::string& program,
                           const std::vector<std::string>& argv,
                           const std::vector<std::string>& env,
                           const std::string& cwd, bool piped, uint32_t* pid,
                           std::string* error);
};

} // namespace slop::core::frida
