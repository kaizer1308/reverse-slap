// src/core/frida/frida_service.cpp
// frida core embedding, one singleton owns the device manager and the handle tables
// every stored frida pointer is ours to unref and message callbacks only ever
// take the per script ring lock so a stuck rpc can never wedge fridas worker

#include "core/frida/frida_service.hpp"

#include "frida-core.h"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

static_assert(std::string_view{FRIDA_VERSION} == "17.17.0",
              "frida-core header does not match the pinned devkit version");

namespace slop::core::frida {

namespace {

using clock = std::chrono::steady_clock;

int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               clock::now().time_since_epoch())
        .count();
}

std::string take_gerror(GError* e) {
    std::string s = (e && e->message) ? e->message : "unknown frida error";
    if (e) g_error_free(e);
    return s;
}

// frida-core bundles its own GLib, pull the runtime up before any object is
// created (idempotent, mirrors frida_init() in the devkit example)
struct frida_lib_init_t {
    frida_lib_init_t() { frida_init(); }
};
frida_lib_init_t g_frida_lib_init;

constexpr size_t k_msg_ring_max = 4096;   // per script, bounded
constexpr size_t k_output_ring_max = 4096;

// Extract the rpc id from a raw ["frida:rpc", id, ...] reply without a JSON
// parser: the id is the number between the first comma and the next comma
std::optional<uint64_t> rpc_reply_id(const std::string& json) {
    // expected shape: ["frida:rpc",<id>,"ok",... (no spaces, agent serializer)
    const size_t open = json.find('[');
    const size_t c1 = json.find(',', open == std::string::npos ? 0 : open);
    if (c1 == std::string::npos) return std::nullopt;
    const size_t c2 = json.find(',', c1 + 1);
    if (c2 == std::string::npos) return std::nullopt;
    const std::string tok = json.substr(c1 + 1, c2 - c1 - 1);
    if (tok.empty()) return std::nullopt;
    try {
        return std::stoull(tok);
    } catch (...) {
        return std::nullopt;
    }
}

// rpc replies ride a send message with the frida rpc array nested in the
// payload so it needs a real json parse
std::optional<std::string> rpc_reply_payload(const std::string& json) {
    const auto j = nlohmann::json::parse(json, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    if (!j.contains("type") || !j.contains("payload")) return std::nullopt;
    const auto& t = j.at("type");
    const auto& p = j.at("payload");
    if (!t.is_string() || t != "send" || !p.is_array() || p.empty()) return std::nullopt;
    if (!p.at(0).is_string() || p.at(0) != "frida:rpc") return std::nullopt;
    if (p.size() < 3 || !p.at(2).is_string()) return std::nullopt;
    const std::string op = p.at(2);
    if (op != "ok" && op != "error") return std::nullopt;
    return p.dump();
}

std::string base64(const void* p, size_t len) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    auto* b = static_cast<const uint8_t*>(p);
    std::string out;
    out.reserve(((len + 2) / 3) * 4);
    for (size_t i = 0; i < len; i += 3) {
        uint32_t v = (uint32_t(b[i]) << 16);
        if (i + 1 < len) v |= (uint32_t(b[i + 1]) << 8);
        if (i + 2 < len) v |= uint32_t(b[i + 2]);
        out += tbl[(v >> 18) & 63];
        out += tbl[(v >> 12) & 63];
        out += (i + 1 < len) ? tbl[(v >> 6) & 63] : '=';
        out += (i + 2 < len) ? tbl[v & 63] : '=';
    }
    return out;
}

std::vector<uint8_t> decode_base64(const std::string& input, bool* valid) {
    *valid = false;
    if (input.empty() || input.size() % 4 != 0) return {};
    for (const char c : input) {
        if (!(c >= 'A' && c <= 'Z') && !(c >= 'a' && c <= 'z') &&
            !(c >= '0' && c <= '9') && c != '+' && c != '/' && c != '=')
            return {};
    }
    gsize len = 0;
    guchar* decoded = g_base64_decode(input.c_str(), &len);
    if (!decoded && len != 0) return {};
    std::vector<uint8_t> out;
    if (decoded && len != 0) out.assign(decoded, decoded + len);
    g_free(decoded);
    *valid = true;
    return out;
}

class cancellable_monitor_t {
public:
    explicit cancellable_monitor_t(std::function<bool()> cancelled)
        : cancellable_(g_cancellable_new()), cancelled_(std::move(cancelled)) {
        if (cancelled_) {
            monitor_ = std::thread([this] {
                while (!stopped_.load(std::memory_order_acquire)) {
                    if (cancelled_()) {
                        g_cancellable_cancel(cancellable_);
                        return;
                    }
                    std::this_thread::sleep_for(std::chrono::milliseconds(10));
                }
            });
        }
    }

    ~cancellable_monitor_t() {
        stopped_.store(true, std::memory_order_release);
        if (monitor_.joinable()) monitor_.join();
        g_object_unref(cancellable_);
    }

    cancellable_monitor_t(const cancellable_monitor_t&) = delete;
    cancellable_monitor_t& operator=(const cancellable_monitor_t&) = delete;

    GCancellable* get() const noexcept { return cancellable_; }

private:
    GCancellable* cancellable_ = nullptr;
    std::function<bool()> cancelled_;
    std::atomic_bool stopped_{false};
    std::thread monitor_;
};

// JSON-escape a bare string into a JSON string literal (no surrounding
// whitespace, used to build the frida:rpc request envelope by hand)
std::string json_string_literal(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 2);
    out += '"';
    for (char c : s) {
        switch (c) {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                char buf[8];
                snprintf(buf, sizeof(buf), "\\u%04x", c);
                out += buf;
            } else {
                out += c;
            }
        }
    }
    out += '"';
    return out;
}

} // namespace

struct frida_service_t::impl_t {
    FridaDeviceManager* manager = nullptr;

    struct rpc_wait_t {
        std::mutex              mu;
        std::condition_variable cv;
        bool                    done = false;
        std::string             reply_json;   // full ["frida:rpc", id, ...] text
        std::string             error;
    };

    struct session_rec_t {
        FridaSession* obj = nullptr;
        uint32_t      pid = 0;
        std::string   device_id;
        gulong        detach_handler = 0;
        std::atomic_bool detached{false};
        mutable std::mutex detach_mu;
        std::string   detach_reason;
        uint32_t      crash_pid = 0;
        std::string   crash_process;
        std::string   crash_summary;
        std::string   crash_report;
        std::map<std::string, std::string> crash_parameters;
        bool          child_gating = false;
        std::vector<std::string> scripts;   // handles, teardown order
    };

    struct output_device_t {
        FridaDevice* obj = nullptr;
        gulong handler = 0;
    };

    std::mutex output_mu;
    std::map<std::string, output_device_t> output_devices;
    std::map<uint32_t, std::deque<spawn_output_t>> output_rings;
    std::map<uint32_t, size_t> output_dropped;

    struct script_rec_t {
        FridaScript* obj = nullptr;
        std::string  name;
        std::string  session;
        std::string  runtime;
        gulong       message_handler = 0;
        bool         loaded = false;

        // Keeps the Frida object alive while an RPC request is posted
        std::mutex obj_mu;

        // Callback-visible state. ring_mu guards ring/dropped/waits/next_rpc_id
        std::mutex ring_mu;
        std::deque<script_message_t> ring;
        size_t      dropped = 0;
        uint64_t    next_rpc_id = 1;
        std::map<uint64_t, std::shared_ptr<rpc_wait_t>> waits;
    };

    std::map<std::string, session_rec_t> sessions;
    std::map<std::string, std::shared_ptr<script_rec_t>> scripts;
    uint32_t next_session = 1;
    uint32_t next_script  = 1;

    // Serializes public entry points. Safe to hold across frida sync calls:
    // our callbacks never call back into the public surface
    mutable std::mutex call_mu;

    static void cancel_waits(script_rec_t& rec, const std::string& reason) {
        std::vector<std::shared_ptr<rpc_wait_t>> waits;
        {
            std::lock_guard rlk(rec.ring_mu);
            for (const auto& [id, wait] : rec.waits) {
                (void)id;
                waits.push_back(wait);
            }
            rec.waits.clear();
        }
        for (const auto& wait : waits) {
            std::lock_guard wlk(wait->mu);
            wait->error = reason;
            wait->done = true;
            wait->cv.notify_all();
        }
    }

    bool ensure_manager(std::string* error) {
        if (manager) return true;
        manager = frida_device_manager_new();
        if (!manager) {
            if (error) *error = "frida_device_manager_new failed";
            return false;
        }
        return true;
    }

    FridaDevice* resolve_device(const std::string& id, std::string* error) {
        if (!ensure_manager(error)) return nullptr;
        GError* e = nullptr;
        FridaDevice* dev = nullptr;
        if (id.empty() || id == "local") {
            dev = frida_device_manager_find_device_by_type_sync(
                manager, FRIDA_DEVICE_TYPE_LOCAL, 5000, nullptr, &e);
            if (!dev && e == nullptr)
                dev = frida_device_manager_find_device_by_id_sync(
                    manager, "local", 5000, nullptr, &e);
        } else {
            dev = frida_device_manager_find_device_by_id_sync(
                manager, id.c_str(), 5000, nullptr, &e);
        }
        if (!dev) {
            if (error) *error = e ? take_gerror(e) : ("device not found: " + id);
            else if (e) g_error_free(e);
            return nullptr;
        }
        if (e) g_error_free(e);
        return dev;   // caller owns one ref
    }

    static std::string dtype_name(FridaDeviceType t) {
        switch (t) {
        case FRIDA_DEVICE_TYPE_LOCAL:  return "local";
        case FRIDA_DEVICE_TYPE_REMOTE: return "remote";
        case FRIDA_DEVICE_TYPE_USB:    return "usb";
        }
        return "unknown";
    }

    static FridaScope parse_scope(const std::string& s) {
        if (s == "minimal") return FRIDA_SCOPE_MINIMAL;
        if (s == "full")    return FRIDA_SCOPE_FULL;
        return FRIDA_SCOPE_METADATA;
    }

    static FridaScriptRuntime parse_runtime(const std::string& s) {
        if (s == "v8")  return FRIDA_SCRIPT_RUNTIME_V8;
        if (s == "qjs") return FRIDA_SCRIPT_RUNTIME_QJS;
        return FRIDA_SCRIPT_RUNTIME_DEFAULT;
    }

    static std::string detach_reason_name(FridaSessionDetachReason reason) {
        switch (reason) {
        case FRIDA_SESSION_DETACH_REASON_APPLICATION_REQUESTED:
            return "application_requested";
        case FRIDA_SESSION_DETACH_REASON_PROCESS_REPLACED:
            return "process_replaced";
        case FRIDA_SESSION_DETACH_REASON_PROCESS_TERMINATED:
            return "process_terminated";
        case FRIDA_SESSION_DETACH_REASON_CONNECTION_TERMINATED:
            return "connection_terminated";
        case FRIDA_SESSION_DETACH_REASON_DEVICE_LOST:
            return "device_lost";
        }
        return "unknown";
    }

    // parameters hash: gchar* -> GVariant* (see frida-core.gir)
    static std::map<std::string, std::string> flatten_params(GHashTable* ht) {
        std::map<std::string, std::string> out;
        if (!ht) return out;
        GList* keys = g_hash_table_get_keys(ht);
        for (GList* k = keys; k; k = k->next) {
            const char* key = static_cast<const char*>(k->data);
            if (!key) continue;
            GVariant* v = static_cast<GVariant*>(g_hash_table_lookup(ht, key));
            if (!v) continue;
            gchar* s = g_variant_print(v, FALSE);
            if (s) {
                out[key] = s;
                g_free(s);
            }
        }
        g_list_free(keys);
        return out;
    }

    // GObject signal sinks (frida worker threads; take only ring_mu)

    static void on_script_message(FridaScript* /*script*/, const gchar* message,
                                  GBytes* data, gpointer user_data) {
        auto* rec = static_cast<script_rec_t*>(user_data);
        if (!rec || !message) return;

        // RPC replies bypass the ring and go straight to the waiter
        if (const auto reply = rpc_reply_payload(message)) {
            const auto id = rpc_reply_id(*reply);
            std::shared_ptr<rpc_wait_t> wait;
            {
                std::lock_guard lk(rec->ring_mu);
                if (id) {
                    auto it = rec->waits.find(*id);
                    if (it != rec->waits.end()) wait = it->second;
                }
            }
            if (wait) {
                std::lock_guard wl(wait->mu);
                wait->reply_json = *reply;
                wait->done = true;
                wait->cv.notify_all();
            }
            return;
        }

        script_message_t m;
        m.at_ms = now_ms();
        m.json = message;
        if (data) {
            gsize len = 0;
            gconstpointer p = g_bytes_get_data(data, &len);
            if (p && len)
                m.data.assign(static_cast<const uint8_t*>(p),
                              static_cast<const uint8_t*>(p) + len);
        }
        std::lock_guard lk(rec->ring_mu);
        if (rec->ring.size() >= k_msg_ring_max) {
            rec->ring.pop_front();
            rec->dropped++;
        }
        rec->ring.push_back(std::move(m));
    }

    static void on_session_detached(FridaSession* /*s*/, FridaSessionDetachReason reason,
                                    FridaCrash* crash, gpointer user_data) {
        auto* rec = static_cast<session_rec_t*>(user_data);
        if (!rec) return;
        {
            std::lock_guard lk(rec->detach_mu);
            rec->detach_reason = detach_reason_name(reason);
            if (crash) {
                rec->crash_pid = frida_crash_get_pid(crash);
                const char* process = frida_crash_get_process_name(crash);
                const char* summary = frida_crash_get_summary(crash);
                const char* report = frida_crash_get_report(crash);
                rec->crash_process = process ? process : "";
                rec->crash_summary = summary ? summary : "";
                rec->crash_report = report ? report : "";
                rec->crash_parameters = flatten_params(frida_crash_get_parameters(crash));
            }
        }
        rec->detached.store(true, std::memory_order_release);
    }

    static void on_device_output(FridaDevice* /*device*/, guint pid, gint fd,
                                 GBytes* data, gpointer user_data) {
        auto* self = static_cast<impl_t*>(user_data);
        if (!self || !data) return;
        spawn_output_t event;
        event.at_ms = now_ms();
        event.pid = pid;
        event.fd = fd;
        gsize len = 0;
        gconstpointer bytes = g_bytes_get_data(data, &len);
        event.eof = len == 0;
        if (bytes && len) {
            const auto* first = static_cast<const uint8_t*>(bytes);
            event.data.assign(first, first + len);
        }
        std::lock_guard lk(self->output_mu);
        auto& ring = self->output_rings[pid];
        if (ring.size() >= k_output_ring_max) {
            ring.pop_front();
            self->output_dropped[pid]++;
        }
        ring.push_back(std::move(event));
    }

    bool ensure_output_device(const std::string& id, FridaDevice* dev) {
        const std::string key = id.empty() ? "local" : id;
        std::lock_guard lk(output_mu);
        if (output_devices.contains(key)) return true;
        g_object_ref(dev);
        output_device_t rec;
        rec.obj = dev;
        rec.handler = g_signal_connect(
            dev, "output", G_CALLBACK(&impl_t::on_device_output), this);
        output_devices.emplace(key, rec);
        return true;
    }
};

// singleton

frida_service_t& frida_service_t::get() {
    static frida_service_t inst;
    return inst;
}

frida_service_t::frida_service_t() : impl_(new impl_t()) {}

// frida owns glib workers with wild static destruction order, the app shuts
// this down explicitly through shutdown_tools
frida_service_t::~frida_service_t() = default;

std::string frida_service_t::version() const {
    const char* v = frida_version_string();
    return v ? v : "";
}

bool frida_service_t::initialized() const {
    std::lock_guard lk(impl_->call_mu);
    return impl_->manager != nullptr;
}

bool frida_service_t::init(std::string* error) {
    std::lock_guard lk(impl_->call_mu);
    return impl_->ensure_manager(error);
}

void frida_service_t::shutdown() {
    std::lock_guard lk(impl_->call_mu);
    teardown_locked();
}

// Shared teardown used by shutdown() and detach_session(); call_mu held
void frida_service_t::teardown_locked() {
    for (auto& [h, rec_ptr] : impl_->scripts) {
        (void)h;
        auto& rec = *rec_ptr;
        std::lock_guard olk(rec.obj_mu);
        impl_t::cancel_waits(rec, "frida service shut down");
        if (rec.obj && rec.loaded) {
            frida_script_unload_sync(rec.obj, nullptr, nullptr);
            rec.loaded = false;
        }
        if (rec.obj) {
            if (rec.message_handler)
                g_signal_handler_disconnect(rec.obj, rec.message_handler);
            frida_unref(rec.obj);
            rec.obj = nullptr;
        }
    }
    impl_->scripts.clear();
    for (auto& [h, rec] : impl_->sessions) {
        (void)h;
        if (rec.obj) {
            if (!rec.detached.load(std::memory_order_acquire))
                frida_session_detach_sync(rec.obj, nullptr, nullptr);
            if (rec.detach_handler)
                g_signal_handler_disconnect(rec.obj, rec.detach_handler);
            frida_unref(rec.obj);
            rec.obj = nullptr;
        }
    }
    impl_->sessions.clear();
    {
        std::lock_guard olk(impl_->output_mu);
        for (auto& [id, rec] : impl_->output_devices) {
            (void)id;
            if (rec.obj && rec.handler)
                g_signal_handler_disconnect(rec.obj, rec.handler);
            if (rec.obj) frida_unref(rec.obj);
        }
        impl_->output_devices.clear();
        impl_->output_rings.clear();
        impl_->output_dropped.clear();
    }
    if (impl_->manager) {
        frida_device_manager_close_sync(impl_->manager, nullptr, nullptr);
        frida_unref(impl_->manager);
        impl_->manager = nullptr;
    }
}

// devices

bool frida_service_t::list_devices(std::vector<device_info_t>* out, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    GError* e = nullptr;
    FridaDeviceList* list =
        frida_device_manager_enumerate_devices_sync(impl_->manager, nullptr, &e);
    if (!list) {
        if (error) *error = take_gerror(e);
        return false;
    }
    std::vector<device_info_t> res;
    const gint n = frida_device_list_size(list);
    for (gint i = 0; i < n; i++) {
        FridaDevice* d = frida_device_list_get(list, i);
        if (!d) continue;
        device_info_t di;
        const char* id = frida_device_get_id(d);
        const char* nm = frida_device_get_name(d);
        di.id   = id ? id : "";
        di.name = nm ? nm : "";
        di.dtype = impl_t::dtype_name(frida_device_get_dtype(d));
        res.push_back(std::move(di));
        frida_unref(d);
    }
    frida_unref(list);
    *out = std::move(res);
    return true;
}

bool frida_service_t::remote_add(const std::string& address, std::string* error) {
    return remote_add(address, remote_options_t{}, error);
}

bool frida_service_t::remote_add(const std::string& address,
                                 const remote_options_t& options,
                                 std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    GError* e = nullptr;
    FridaRemoteDeviceOptions* opt = frida_remote_device_options_new();
    GTlsCertificate* certificate = nullptr;
    if (!options.certificate_pem.empty()) {
        certificate = g_tls_certificate_new_from_pem(
            options.certificate_pem.c_str(), options.certificate_pem.size(), &e);
    } else if (!options.certificate_path.empty()) {
        certificate = g_tls_certificate_new_from_file(
            options.certificate_path.c_str(), &e);
    }
    if (e) {
        frida_unref(opt);
        if (error) *error = take_gerror(e);
        return false;
    }
    if (certificate)
        frida_remote_device_options_set_certificate(opt, certificate);
    if (!options.origin.empty())
        frida_remote_device_options_set_origin(opt, options.origin.c_str());
    if (!options.token.empty())
        frida_remote_device_options_set_token(opt, options.token.c_str());
    if (options.keepalive_interval >= -1)
        frida_remote_device_options_set_keepalive_interval(
            opt, options.keepalive_interval);
    FridaDevice* d = frida_device_manager_add_remote_device_sync(
        impl_->manager, address.c_str(), opt, nullptr, &e);
    if (d) frida_unref(d);   // manager keeps its own ref
    if (certificate) frida_unref(certificate);
    frida_unref(opt);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::remote_remove(const std::string& address, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    GError* e = nullptr;
    frida_device_manager_remove_remote_device_sync(impl_->manager, address.c_str(),
                                                   nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

// process / application enumeration

bool frida_service_t::enumerate_processes(const std::string& device_id,
                                          const std::string& scope,
                                          std::vector<process_info_t>* out,
                                          std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaProcessQueryOptions* opt = frida_process_query_options_new();
    frida_process_query_options_set_scope(opt, impl_t::parse_scope(scope));
    FridaProcessList* list = frida_device_enumerate_processes_sync(dev, opt, nullptr, &e);
    frida_unref(opt);
    if (!list) {
        frida_unref(dev);
        if (error) *error = take_gerror(e);
        return false;
    }
    std::vector<process_info_t> res;
    const gint n = frida_process_list_size(list);
    for (gint i = 0; i < n; i++) {
        FridaProcess* p = frida_process_list_get(list, i);
        if (!p) continue;
        process_info_t pi;
        pi.pid = frida_process_get_pid(p);
        const char* nm = frida_process_get_name(p);
        pi.name = nm ? nm : "";
        pi.parameters = impl_t::flatten_params(frida_process_get_parameters(p));
        res.push_back(std::move(pi));
        frida_unref(p);
    }
    frida_unref(list);
    frida_unref(dev);
    *out = std::move(res);
    return true;
}

bool frida_service_t::find_process(const std::string& device_id, const std::string& name,
                                    std::optional<process_info_t>* out, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaProcessMatchOptions* opt = frida_process_match_options_new();
    frida_process_match_options_set_timeout(opt, 0);
    FridaProcess* p =
        frida_device_find_process_by_name_sync(dev, name.c_str(), opt, nullptr, &e);
    frida_unref(opt);
    if (!p) {
        frida_unref(dev);
        if (e) {
            if (error) *error = take_gerror(e);
            return false;
        }
        *out = std::nullopt;   // genuinely not found
        return true;
    }
    process_info_t pi;
    pi.pid = frida_process_get_pid(p);
    const char* nm = frida_process_get_name(p);
    pi.name = nm ? nm : "";
    pi.parameters = impl_t::flatten_params(frida_process_get_parameters(p));
    frida_unref(p);
    frida_unref(dev);
    *out = std::move(pi);
    return true;
}

bool frida_service_t::enumerate_applications(const std::string& device_id,
                                             const std::string& scope,
                                             std::vector<application_info_t>* out,
                                             std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaApplicationQueryOptions* opt = frida_application_query_options_new();
    frida_application_query_options_set_scope(opt, impl_t::parse_scope(scope));
    FridaApplicationList* list =
        frida_device_enumerate_applications_sync(dev, opt, nullptr, &e);
    frida_unref(opt);
    if (!list) {
        frida_unref(dev);
        if (error) *error = take_gerror(e);
        return false;
    }
    std::vector<application_info_t> res;
    const gint n = frida_application_list_size(list);
    for (gint i = 0; i < n; i++) {
        FridaApplication* a = frida_application_list_get(list, i);
        if (!a) continue;
        application_info_t ai;
        const char* id = frida_application_get_identifier(a);
        const char* nm = frida_application_get_name(a);
        ai.identifier = id ? id : "";
        ai.name = nm ? nm : "";
        ai.pid = frida_application_get_pid(a);
        res.push_back(std::move(ai));
        frida_unref(a);
    }
    frida_unref(list);
    frida_unref(dev);
    *out = std::move(res);
    return true;
}

bool frida_service_t::frontmost_application(const std::string& device_id,
                                            std::optional<application_info_t>* out,
                                            std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaFrontmostQueryOptions* opt = frida_frontmost_query_options_new();
    FridaApplication* a =
        frida_device_get_frontmost_application_sync(dev, opt, nullptr, &e);
    frida_unref(opt);
    frida_unref(dev);
    if (!a) {
        if (e) {
            if (error) *error = take_gerror(e);
            return false;
        }
        *out = std::nullopt;
        return true;
    }
    application_info_t ai;
    const char* id = frida_application_get_identifier(a);
    const char* nm = frida_application_get_name(a);
    ai.identifier = id ? id : "";
    ai.name = nm ? nm : "";
    ai.pid = frida_application_get_pid(a);
    frida_unref(a);
    *out = std::move(ai);
    return true;
}

// spawn / lifecycle

bool frida_service_t::spawn(const std::string& device_id, const std::string& program,
                            const std::vector<std::string>& argv,
                             const std::vector<std::string>& env,
                             const std::string& cwd, uint32_t* pid, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    return spawn_impl_locked(device_id, program, argv, env, cwd, false, pid, error);
}

bool frida_service_t::spawn_impl_locked(const std::string& device_id,
                                        const std::string& program,
                                        const std::vector<std::string>& argv,
                                        const std::vector<std::string>& env,
                                        const std::string& cwd, bool piped,
                                        uint32_t* pid, std::string* error) {
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    if (piped) impl_->ensure_output_device(device_id, dev);
    FridaSpawnOptions* opt = frida_spawn_options_new();
    std::vector<char*> argv_buf;
    argv_buf.reserve(argv.size());
    for (const auto& a : argv) argv_buf.push_back(const_cast<char*>(a.c_str()));
    if (!argv_buf.empty())
        frida_spawn_options_set_argv(opt, argv_buf.data(), static_cast<gint>(argv_buf.size()));
    std::vector<char*> env_buf;
    env_buf.reserve(env.size());
    for (const auto& v : env) env_buf.push_back(const_cast<char*>(v.c_str()));
    if (!env_buf.empty())
        frida_spawn_options_set_env(opt, env_buf.data(), static_cast<gint>(env_buf.size()));
    if (!cwd.empty()) frida_spawn_options_set_cwd(opt, cwd.c_str());
    frida_spawn_options_set_stdio(opt, piped ? FRIDA_STDIO_PIPE : FRIDA_STDIO_INHERIT);
    GError* e = nullptr;
    const guint spawned = frida_device_spawn_sync(dev, program.c_str(), opt, nullptr, &e);
    frida_unref(opt);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    if (pid) *pid = spawned;
    return true;
}

bool frida_service_t::spawn_piped(const std::string& device_id,
                                  const std::string& program,
                                  const std::vector<std::string>& argv,
                                  const std::vector<std::string>& env,
                                  const std::string& cwd, uint32_t* pid,
                                  std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    return spawn_impl_locked(device_id, program, argv, env, cwd, true, pid, error);
}

bool frida_service_t::read_spawn_output(const std::string& device_id, uint32_t pid,
                                        size_t max, std::vector<spawn_output_t>* out,
                                        size_t* remaining, size_t* dropped,
                                        std::string* error) {
    if (!init(error)) return false;
    (void)device_id;
    std::lock_guard lk(impl_->output_mu);
    std::vector<spawn_output_t> result;
    auto& ring = impl_->output_rings[pid];
    while (!ring.empty() && result.size() < max) {
        result.push_back(std::move(ring.front()));
        ring.pop_front();
    }
    if (remaining) *remaining = ring.size();
    if (dropped) *dropped = std::exchange(impl_->output_dropped[pid], 0);
    *out = std::move(result);
    return true;
}

bool frida_service_t::input(const std::string& device_id, uint32_t pid,
                            const std::vector<uint8_t>& data, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GBytes* bytes = g_bytes_new(
        data.empty() ? static_cast<gconstpointer>("") : data.data(), data.size());
    GError* e = nullptr;
    frida_device_input_sync(dev, pid, bytes, nullptr, &e);
    g_bytes_unref(bytes);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::resume(const std::string& device_id, uint32_t pid,
                             std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    frida_device_resume_sync(dev, pid, nullptr, &e);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::kill(const std::string& device_id, uint32_t pid, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    frida_device_kill_sync(dev, pid, nullptr, &e);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::enable_spawn_gating(const std::string& device_id, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaSpawnGatingOptions* opt = frida_spawn_gating_options_new();
    frida_device_enable_spawn_gating_sync(dev, opt, nullptr, &e);
    frida_unref(opt);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::disable_spawn_gating(const std::string& device_id, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    frida_device_disable_spawn_gating_sync(dev, nullptr, &e);
    frida_unref(dev);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::pending_spawn(const std::string& device_id,
                                    std::vector<spawn_info_t>* out, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaSpawnList* list = frida_device_enumerate_pending_spawn_sync(dev, nullptr, &e);
    frida_unref(dev);
    if (!list) {
        if (error) *error = take_gerror(e);
        return false;
    }
    std::vector<spawn_info_t> res;
    const gint n = frida_spawn_list_size(list);
    for (gint i = 0; i < n; i++) {
        FridaSpawn* s = frida_spawn_list_get(list, i);
        if (!s) continue;
        spawn_info_t si;
        si.pid = frida_spawn_get_pid(s);
        const char* id = frida_spawn_get_identifier(s);
        si.identifier = id ? id : "";
        res.push_back(std::move(si));
        frida_unref(s);
    }
    frida_unref(list);
    *out = std::move(res);
    return true;
}

bool frida_service_t::pending_children(const std::string& device_id,
                                       std::vector<child_info_t>* out, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    GError* e = nullptr;
    FridaChildList* list = frida_device_enumerate_pending_children_sync(dev, nullptr, &e);
    frida_unref(dev);
    if (!list) {
        if (error) *error = take_gerror(e);
        return false;
    }
    std::vector<child_info_t> res;
    const gint n = frida_child_list_size(list);
    for (gint i = 0; i < n; i++) {
        FridaChild* c = frida_child_list_get(list, i);
        if (!c) continue;
        child_info_t ci;
        ci.pid = frida_child_get_pid(c);
        ci.parent_pid = frida_child_get_parent_pid(c);
        switch (frida_child_get_origin(c)) {
        case FRIDA_CHILD_ORIGIN_FORK:  ci.origin = "fork";  break;
        case FRIDA_CHILD_ORIGIN_EXEC:  ci.origin = "exec";  break;
        case FRIDA_CHILD_ORIGIN_SPAWN: ci.origin = "spawn"; break;
        }
        const char* id = frida_child_get_identifier(c);
        ci.identifier = id ? id : "";
        res.push_back(std::move(ci));
        frida_unref(c);
    }
    frida_unref(list);
    *out = std::move(res);
    return true;
}

// sessions

bool frida_service_t::attach(const std::string& device_id, uint32_t pid,
                             const std::string& realm, std::string* handle,
                             std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    FridaDevice* dev = impl_->resolve_device(device_id, error);
    if (!dev) return false;
    FridaSessionOptions* opt = frida_session_options_new();
    if (realm == "emulated") frida_session_options_set_realm(opt, FRIDA_REALM_EMULATED);
    GError* e = nullptr;
    FridaSession* s = frida_device_attach_sync(dev, pid, opt, nullptr, &e);
    frida_unref(opt);
    frida_unref(dev);
    if (!s) {
        if (error) *error = take_gerror(e);
        return false;
    }

    const std::string h = "s" + std::to_string(impl_->next_session++);
    auto& rec = impl_->sessions[h];
    rec.obj = s;
    rec.pid = pid;
    rec.device_id = device_id.empty() ? "local" : device_id;
    rec.detach_handler = g_signal_connect(
        s, "detached", G_CALLBACK(&impl_t::on_session_detached), &rec);
    if (handle) *handle = h;
    return true;
}

bool frida_service_t::detach_session(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->sessions.find(handle);
    if (it == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + handle;
        return false;
    }
    destroy_session_scripts_locked(it->second.scripts);
    if (it->second.obj) {
        if (!it->second.detached.load(std::memory_order_acquire))
            frida_session_detach_sync(it->second.obj, nullptr, nullptr);
        if (it->second.detach_handler)
            g_signal_handler_disconnect(it->second.obj, it->second.detach_handler);
        frida_unref(it->second.obj);
    }
    impl_->sessions.erase(it);
    return true;
}

// Unload + release every script in `handles` and drop them from the tables
// call_mu held
void frida_service_t::destroy_session_scripts_locked(const std::vector<std::string>& handles) {
    for (const std::string& sh : handles) {
        auto sit = impl_->scripts.find(sh);
        if (sit == impl_->scripts.end()) continue;
        auto& rec = *sit->second;
        std::lock_guard olk(rec.obj_mu);
        impl_t::cancel_waits(rec, "session detached");
        if (rec.obj && rec.loaded)
            frida_script_unload_sync(rec.obj, nullptr, nullptr);
        if (rec.obj) {
            if (rec.message_handler)
                g_signal_handler_disconnect(rec.obj, rec.message_handler);
            frida_unref(rec.obj);
        }
        impl_->scripts.erase(sit);
    }
}

bool frida_service_t::resume_session(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->sessions.find(handle);
    if (it == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + handle;
        return false;
    }
    if (!it->second.obj) {
        if (error) *error = "session object gone";
        return false;
    }
    GError* e = nullptr;
    frida_session_resume_sync(it->second.obj, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::enable_child_gating(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->sessions.find(handle);
    if (it == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + handle;
        return false;
    }
    GError* e = nullptr;
    frida_session_enable_child_gating_sync(it->second.obj, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    it->second.child_gating = true;
    return true;
}

bool frida_service_t::disable_child_gating(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->sessions.find(handle);
    if (it == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + handle;
        return false;
    }
    GError* e = nullptr;
    frida_session_disable_child_gating_sync(it->second.obj, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    it->second.child_gating = false;
    return true;
}

bool frida_service_t::list_sessions(std::vector<session_info_t>* out) const {
    if (!impl_) {
        *out = {};
        return true;
    }
    std::lock_guard lk(impl_->call_mu);
    std::vector<session_info_t> res;
    res.reserve(impl_->sessions.size());
    for (const auto& [h, rec] : impl_->sessions) {
        session_info_t si;
        si.handle = h;
        si.pid = rec.pid;
        si.device = rec.device_id;
        si.detached = rec.detached.load(std::memory_order_acquire);
        {
            std::lock_guard dlk(rec.detach_mu);
            si.detach_reason = rec.detach_reason;
            si.crash_pid = rec.crash_pid;
            si.crash_process = rec.crash_process;
            si.crash_summary = rec.crash_summary;
            si.crash_report = rec.crash_report;
            si.crash_parameters = rec.crash_parameters;
        }
        si.scripts = rec.scripts.size();
        res.push_back(std::move(si));
    }
    *out = std::move(res);
    return true;
}

// scripts

bool frida_service_t::create_script(const std::string& session, const std::string& name,
                                    const std::string& source, const std::string& runtime,
                                    std::string* handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto sit = impl_->sessions.find(session);
    if (sit == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + session;
        return false;
    }
    FridaScriptOptions* opt = frida_script_options_new();
    const std::string nm = name.empty() ? "slop" : name;
    frida_script_options_set_name(opt, nm.c_str());
    frida_script_options_set_runtime(opt, impl_t::parse_runtime(runtime));
    GError* e = nullptr;
    FridaScript* s =
        frida_session_create_script_sync(sit->second.obj, source.c_str(), opt, nullptr, &e);
    frida_unref(opt);
    if (!s) {
        if (error) *error = take_gerror(e);
        return false;
    }

    const std::string h = "sc" + std::to_string(impl_->next_script++);
    auto rec = std::make_shared<impl_t::script_rec_t>();
    rec->obj = s;
    rec->name = nm;
    rec->session = session;
    rec->runtime = runtime.empty() ? "default" : runtime;
    rec->message_handler = g_signal_connect(
        s, "message", G_CALLBACK(&impl_t::on_script_message), rec.get());
    impl_->scripts.emplace(h, std::move(rec));
    sit->second.scripts.push_back(h);
    if (handle) *handle = h;
    return true;
}

bool frida_service_t::create_script_from_bytes(const std::string& session,
                                                const std::string& name,
                                                const std::string& bytecode_b64,
                                                const std::string& runtime,
                                                std::string* handle,
                                                std::string* error) {
    if (!init(error)) return false;
    bool valid = false;
    const std::vector<uint8_t> bytecode = decode_base64(bytecode_b64, &valid);
    if (!valid || bytecode.empty()) {
        if (error) *error = "invalid or empty Frida bytecode base64";
        return false;
    }

    std::lock_guard lk(impl_->call_mu);
    auto sit = impl_->sessions.find(session);
    if (sit == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + session;
        return false;
    }
    FridaScriptOptions* opt = frida_script_options_new();
    const std::string nm = name.empty() ? "slop" : name;
    frida_script_options_set_name(opt, nm.c_str());
    frida_script_options_set_runtime(opt, impl_t::parse_runtime(runtime));
    GBytes* bytes = g_bytes_new(bytecode.data(), bytecode.size());
    GError* e = nullptr;
    FridaScript* script = frida_session_create_script_from_bytes_sync(
        sit->second.obj, bytes, opt, nullptr, &e);
    g_bytes_unref(bytes);
    frida_unref(opt);
    if (!script) {
        if (error) *error = take_gerror(e);
        return false;
    }

    const std::string h = "sc" + std::to_string(impl_->next_script++);
    auto rec = std::make_shared<impl_t::script_rec_t>();
    rec->obj = script;
    rec->name = nm;
    rec->session = session;
    rec->runtime = runtime.empty() ? "default" : runtime;
    rec->message_handler = g_signal_connect(
        script, "message", G_CALLBACK(&impl_t::on_script_message), rec.get());
    impl_->scripts.emplace(h, std::move(rec));
    sit->second.scripts.push_back(h);
    if (handle) *handle = h;
    return true;
}

bool frida_service_t::create_script_with_snapshot(const std::string& session,
                                                   const std::string& name,
                                                   const std::string& source,
                                                   const std::string& snapshot_b64,
                                                   const std::string& runtime,
                                                   std::string* handle,
                                                   std::string* error) {
    if (!init(error)) return false;
    bool valid = false;
    const std::vector<uint8_t> snapshot = decode_base64(snapshot_b64, &valid);
    if (!valid || snapshot.empty()) {
        if (error) *error = "invalid or empty Frida snapshot base64";
        return false;
    }
    std::lock_guard lk(impl_->call_mu);
    auto sit = impl_->sessions.find(session);
    if (sit == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + session;
        return false;
    }
    FridaScriptOptions* opt = frida_script_options_new();
    const std::string nm = name.empty() ? "slop" : name;
    frida_script_options_set_name(opt, nm.c_str());
    frida_script_options_set_runtime(opt, impl_t::parse_runtime(runtime));
    GBytes* bytes = g_bytes_new(snapshot.data(), snapshot.size());
    frida_script_options_set_snapshot(opt, bytes);
    frida_script_options_set_snapshot_transport(opt, FRIDA_SNAPSHOT_TRANSPORT_INLINE);
    GError* e = nullptr;
    FridaScript* script = frida_session_create_script_sync(
        sit->second.obj, source.c_str(), opt, nullptr, &e);
    g_bytes_unref(bytes);
    frida_unref(opt);
    if (!script) {
        if (error) *error = take_gerror(e);
        return false;
    }
    const std::string h = "sc" + std::to_string(impl_->next_script++);
    auto rec = std::make_shared<impl_t::script_rec_t>();
    rec->obj = script;
    rec->name = nm;
    rec->session = session;
    rec->runtime = runtime.empty() ? "default" : runtime;
    rec->message_handler = g_signal_connect(
        script, "message", G_CALLBACK(&impl_t::on_script_message), rec.get());
    impl_->scripts.emplace(h, std::move(rec));
    sit->second.scripts.push_back(h);
    if (handle) *handle = h;
    return true;
}

bool frida_service_t::load_script(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    GError* e = nullptr;
    frida_script_load_sync(it->second->obj, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    it->second->loaded = true;
    return true;
}

bool frida_service_t::unload_script(const std::string& handle, std::string* error) {
    // Frida unload destroys the script object; remove the handle as terminal
    return destroy_script(handle, error);
}

bool frida_service_t::post_message(const std::string& handle,
                                   const std::string& message_json, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    frida_script_post(it->second->obj, message_json.c_str(), nullptr);
    return true;
}

bool frida_service_t::destroy_script(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    auto rec = it->second;
    std::lock_guard olk(rec->obj_mu);
    impl_t::cancel_waits(*rec, "script destroyed");
    if (rec->obj && rec->loaded)
        frida_script_unload_sync(rec->obj, nullptr, nullptr);
    if (rec->obj) {
        if (rec->message_handler)
            g_signal_handler_disconnect(rec->obj, rec->message_handler);
        frida_unref(rec->obj);
        rec->obj = nullptr;
    }
    auto sess = impl_->sessions.find(rec->session);
    if (sess != impl_->sessions.end()) {
        auto& v = sess->second.scripts;
        v.erase(std::remove(v.begin(), v.end(), handle), v.end());
    }
    impl_->scripts.erase(it);
    return true;
}

bool frida_service_t::enable_script_debugger(const std::string& handle, uint16_t port,
                                             std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    GError* e = nullptr;
    frida_script_enable_debugger_sync(it->second->obj, port, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::disable_script_debugger(const std::string& handle, std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    GError* e = nullptr;
    frida_script_disable_debugger_sync(it->second->obj, nullptr, &e);
    if (e) {
        if (error) *error = take_gerror(e);
        return false;
    }
    return true;
}

bool frida_service_t::list_scripts(std::vector<script_info_t>* out) const {
    if (!impl_) {
        *out = {};
        return true;
    }
    std::lock_guard lk(impl_->call_mu);
    std::vector<script_info_t> res;
    res.reserve(impl_->scripts.size());
    for (const auto& [h, rec] : impl_->scripts) {
        script_info_t si;
        si.handle = h;
        si.name = rec->name;
        si.session = rec->session;
        si.runtime = rec->runtime;
        si.loaded = rec->loaded;
        {
            std::lock_guard rlk(rec->ring_mu);
            si.dropped = rec->dropped;
        }
        res.push_back(std::move(si));
    }
    *out = std::move(res);
    return true;
}

bool frida_service_t::read_messages(const std::string& handle, size_t max,
                                    std::vector<script_message_t>* out, size_t* dropped,
                                    std::string* error) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto it = impl_->scripts.find(handle);
    if (it == impl_->scripts.end()) {
        if (error) *error = "unknown script handle: " + handle;
        return false;
    }
    std::vector<script_message_t> res;
    {
        std::lock_guard rlk(it->second->ring_mu);
        while (!it->second->ring.empty() && res.size() < max) {
            res.push_back(std::move(it->second->ring.front()));
            it->second->ring.pop_front();
        }
        if (dropped) *dropped = it->second->dropped;
        it->second->dropped = 0;
    }
    *out = std::move(res);
    return true;
}

// RPC

bool frida_service_t::rpc_call(const std::string& script, const std::string& method,
                               const std::string& args_json, int timeout_ms,
                               std::string* result_json, std::string* error,
                               std::function<bool()> cancelled) {
    if (cancelled && cancelled()) {
        if (error) *error = "rpc: cancelled";
        return false;
    }
    if (!init(error)) return false;
    std::shared_ptr<impl_t::script_rec_t> rec;
    {
        std::lock_guard lk(impl_->call_mu);
        auto it = impl_->scripts.find(script);
        if (it == impl_->scripts.end()) {
            if (error) *error = "unknown script handle: " + script;
            return false;
        }
        rec = it->second;
    }

    auto wait = std::make_shared<impl_t::rpc_wait_t>();
    uint64_t id = 0;
    {
        std::lock_guard olk(rec->obj_mu);
        if (!rec->obj) {
            if (error) *error = "script destroyed";
            return false;
        }
        std::lock_guard rlk(rec->ring_mu);
        id = rec->next_rpc_id++;
        rec->waits[id] = wait;
        // Host->agent request: ["frida:rpc", id, "call", method, args]
        const std::string req =
            "[\"frida:rpc\", " + std::to_string(id) + ", \"call\", " +
            json_string_literal(method) + ", " +
            (args_json.empty() ? "[]" : args_json) + "]";
        frida_script_post(rec->obj, req.c_str(), nullptr);
    }

    const auto deadline = clock::now() + std::chrono::milliseconds(timeout_ms);
    bool done = false;
    bool request_cancelled = false;
    {
        std::unique_lock wl(wait->mu);
        while (!wait->done) {
            if (cancelled && cancelled()) {
                request_cancelled = true;
                break;
            }
            const auto now = clock::now();
            if (now >= deadline) break;
            wait->cv.wait_until(wl, std::min(deadline, now + std::chrono::milliseconds(20)),
                                [&] { return wait->done; });
        }
        done = wait->done;
    }

    {
        std::lock_guard rlk(rec->ring_mu);
        rec->waits.erase(id);
    }
    if (request_cancelled && !done) {
        if (error) *error = "rpc: cancelled";
        return false;
    }
    if (!done) {
        if (error) *error = "rpc: timeout after " + std::to_string(timeout_ms) +
                            " ms (id " + std::to_string(id) + ")";
        return false;
    }
    if (!wait->error.empty()) {
        if (error) *error = "rpc: " + wait->error;
        return false;
    }
    if (result_json) *result_json = wait->reply_json;
    return true;
}

// compiler

bool frida_service_t::compile_project(const std::string& entrypoint,
                                       const std::string& project_root,
                                      std::string* output, std::string* error,
                                      std::function<bool()> cancelled) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    GError* e = nullptr;
    FridaCompiler* c = frida_compiler_new(impl_->manager);
    FridaBuildOptions* opt = frida_build_options_new();
    if (!project_root.empty())
        frida_compiler_options_set_project_root(FRIDA_COMPILER_OPTIONS(opt),
                                                project_root.c_str());
    cancellable_monitor_t monitor(std::move(cancelled));
    gchar* built = frida_compiler_build_sync(
        c, entrypoint.c_str(), opt, monitor.get(), &e);
    frida_unref(opt);
    frida_unref(c);
    if (!built) {
        if (error) *error = take_gerror(e);
        return false;
    }
    if (output) *output = built;
    g_free(built);
    return true;
}

bool frida_service_t::compile_script(const std::string& session, const std::string& source,
                                      const std::string& runtime, std::string* b64,
                                     std::string* error,
                                     std::function<bool()> cancelled) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto sit = impl_->sessions.find(session);
    if (sit == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + session;
        return false;
    }
    FridaScriptOptions* opt = frida_script_options_new();
    frida_script_options_set_runtime(opt, impl_t::parse_runtime(runtime));
    GError* e = nullptr;
    cancellable_monitor_t monitor(std::move(cancelled));
    GBytes* bytes = frida_session_compile_script_sync(sit->second.obj, source.c_str(),
                                                      opt, monitor.get(), &e);
    frida_unref(opt);
    if (!bytes) {
        if (error) *error = take_gerror(e);
        return false;
    }
    gsize len = 0;
    gconstpointer p = g_bytes_get_data(bytes, &len);
    if (b64) *b64 = base64(p, len);
    g_bytes_unref(bytes);
    return true;
}

bool frida_service_t::snapshot_script(const std::string& session,
                                       const std::string& embed_script,
                                       const std::string& runtime, std::string* b64,
                                      std::string* error,
                                      std::function<bool()> cancelled) {
    if (!init(error)) return false;
    std::lock_guard lk(impl_->call_mu);
    auto sit = impl_->sessions.find(session);
    if (sit == impl_->sessions.end()) {
        if (error) *error = "unknown session handle: " + session;
        return false;
    }
    FridaSnapshotOptions* opt = frida_snapshot_options_new();
    frida_snapshot_options_set_runtime(opt, impl_t::parse_runtime(runtime));
    GError* e = nullptr;
    cancellable_monitor_t monitor(std::move(cancelled));
    GBytes* bytes = frida_session_snapshot_script_sync(sit->second.obj,
                                                        embed_script.c_str(), opt,
                                                       monitor.get(), &e);
    frida_unref(opt);
    if (!bytes) {
        if (error) *error = take_gerror(e);
        return false;
    }
    gsize len = 0;
    gconstpointer p = g_bytes_get_data(bytes, &len);
    if (b64) *b64 = base64(p, len);
    g_bytes_unref(bytes);
    return true;
}

} // namespace slop::core::frida
