// src/core/mcp/mcp_tools.cpp
// every tool handler lives here, all under one mutex and response capped

#include "core/mcp/mcp_tools.hpp"
#include "core/mcp/mcp_server.hpp"

#include <windows.h>
#include <ws2tcpip.h>

#include "core/infra/app_control.hpp"
#include "core/infra/cancel.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/deferred.hpp"
#include "core/infra/diag.hpp"
#include "core/infra/event_bus.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/settings.hpp"
#include "core/infra/text_format.hpp"
#include "core/analysis/danger.hpp"
#include "core/analysis/libsig.hpp"
#include "core/analysis/packer.hpp"
#include "core/analysis/signatures.hpp"
#include "core/analysis/xray.hpp"
#include "core/analysis/imgpatch.hpp"
#include "core/analysis/recover.hpp"
#include "core/analysis/devirt.hpp"
#include "core/analysis/magicmida.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/re/type_catalog.hpp"

#include "core/analysis/bindiff.h"
#include "core/analysis/packer_detect.h"
#include "core/database/database.h"
#include "core/detect/security.hpp"
#include "core/emu/session.hpp"
#include "core/frida/frida_service.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/pointer_scan.hpp"
#include "core/memory/reader.hpp"
#include "core/memory/snapshot.hpp"
#include "core/memory/watch_service.hpp"
#include "core/network/capture_service.hpp"
#include "core/network/http_proxy.hpp"
#include "core/network/mitm_pki.hpp"
#include "core/network/traffic_store.hpp"
#include "core/persist/session_store.hpp"
#include "core/process/heap_list.hpp"
#include "core/process/module_dump.hpp"
#include "core/process/process_icon.hpp"
#include "core/re/rtti.hpp"
#include "core/runtime/kernel_service.hpp"
#include "core/runtime/kernel_symbols.hpp"
#include "core/runtime/voyager_comm.h"
#include "core/script/lua_engine.hpp"
#include "core/util/fs_tools.hpp"
#include "core/network/web_fetch.hpp"
#include "core/debugger/debugger.hpp"
#include "core/debugger/callstack.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/disasm/strings.hpp"
#include "core/disasm/xrefs.hpp"
#include "core/runtime/backend.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/scan_bridge.hpp"
#include "core/runtime/session.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

namespace slop::core::mcp {

namespace infra = slop::core::infra;
namespace ds = slop::core::disasm::binary_state;
namespace hs = slop::core::disasm::hyperion_session;
namespace xray = slop::core::analysis::xray;
namespace imgpatch = slop::core::analysis::imgpatch;
namespace recover = slop::core::analysis::recover;
namespace devirt = slop::core::analysis::devirt;
namespace magicmida = slop::core::analysis::magicmida;
namespace unwind = slop::core::debugger::unwind;

namespace {

using json = nlohmann::json;

std::mutex g_tool_mu;

// mcp side state

// the cheat engine style scan state, one per target
struct scan_state_t {
    memory::memscan_t         engine;  // hits plus the region stash
    bool                      used = false; // a first scan happened
    uint32_t                  pid = 0; // scan state never leaks across targets
    std::string               width = "i32";
    std::string               kind = "exact";
};
scan_state_t g_scan;

std::unique_ptr<debugger::debugger_t> g_dbg;

struct image_cache_t {
    std::string                     path;
    std::vector<uint8_t>            file;
    disasm::pe_image_t              pe;
    disasm::function_index_t        fidx;
    disasm::xref_index_t            xidx;
    bool                            fidx_ok = false;
    bool                            xidx_ok = false;
};
image_cache_t g_image;

// captured memory snapshots for the diff action
struct mcp_snapshot_t {
    uint64_t                  id = 0;
    memory::region_snapshot_t snap;
};
std::vector<mcp_snapshot_t> g_snaps;
uint64_t                    g_snap_next_id = 1;
constexpr size_t            kMaxMcpSnapshots = 8;

// capture sink and proxy instance
network::traffic_store_t g_traffic;
network::http_proxy_t    g_proxy;

// helpers

[[noreturn]] void fail(std::string msg) { throw std::runtime_error(std::move(msg)); }

const char* debugger_state_name(debugger::dbg_state_t s) {
    switch (s) {
    case debugger::dbg_state_t::idle:    return "idle";
    case debugger::dbg_state_t::running: return "running";
    case debugger::dbg_state_t::paused:  return "paused";
    }
    return "unknown";
}

const char* disasm_flow_name(disasm::flow_t f) {
    switch (f) {
    case disasm::flow_t::none: return "none";
    case disasm::flow_t::call: return "call";
    case disasm::flow_t::jmp:  return "jmp";
    case disasm::flow_t::jcc:  return "jcc";
    case disasm::flow_t::ret:  return "ret";
    }
    return "unknown";
}

const char* xref_kind_name(disasm::xref_kind_t k) {
    switch (k) {
    case disasm::xref_kind_t::call: return "call";
    case disasm::xref_kind_t::jmp:  return "jmp";
    case disasm::xref_kind_t::data: return "data";
    }
    return "unknown";
}

const char* arch_name(runtime::arch_t a) {
    switch (a) {
    case runtime::arch_t::x64:    return "x64";
    case runtime::arch_t::x86:    return "x86";
    case runtime::arch_t::arm64:  return "arm64";
    case runtime::arch_t::unknown: break;
    }
    return "unknown";
}

const char* elevation_name(runtime::elevation_t e) {
    switch (e) {
    case runtime::elevation_t::standard: return "user";
    case runtime::elevation_t::elevated: return "admin";
    case runtime::elevation_t::system:   return "system";
    case runtime::elevation_t::unknown:  break;
    }
    return "unknown";
}

runtime::session_t& need_session() {
    auto s = process::active_session();
    if (!s || !s->valid()) fail("no target attached (use target.attach first)");
    return *s;
}

uint64_t parse_addr(const json& args, const char* key) {
    if (!args.contains(key)) fail("missing numeric argument");
    const json& v = args.at(key);
    if (v.is_string()) {
        const std::string s = v.get<std::string>();
        return std::stoull(s, nullptr, 0);
    }
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer()) {
        const int64_t sv = v.get<int64_t>();
        if (sv < 0) fail("negative address");
        return static_cast<uint64_t>(sv);
    }
    fail("bad numeric argument");
}

std::string require_action(const json& args) {
    if (!args.contains("action") || !args.at("action").is_string())
        fail("missing 'action' string");
    return args.at("action").get<std::string>();
}

class session_reader_t final : public memory::reader_t {
public:
    explicit session_reader_t(runtime::session_t& s) : s_(s) {}
    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto io = s_.read(addr, dst, len);
        return io.ok && io.bytes == len;
    }
private:
    runtime::session_t& s_;
};

std::vector<uintptr_t> committed_ranges(runtime::session_t& s) {
    std::vector<uintptr_t> out;
    auto res = runtime::active().enum_regions(s.handle());
    if (!res.ok) return out;
    out.reserve(res.items.size() * 2);
    for (const auto& r : res.items) {
        const bool commit = (r.state & 0x1000) != 0;   // MEM_COMMIT
        if (!commit || r.size == 0) continue;
        const bool guard = (r.protect & 0x100) != 0;   // PAGE_GUARD
        if (guard) continue;
        out.push_back(r.base);
        out.push_back(r.base + r.size);
    }
    return out;
}

memory::value_width_t parse_width(const json& args) {
    const std::string w = args.value("width", std::string{"i32"});
    if (w == "i8")  return memory::value_width_t::i8;
    if (w == "u8")  return memory::value_width_t::u8;
    if (w == "i16") return memory::value_width_t::i16;
    if (w == "u16") return memory::value_width_t::u16;
    if (w == "i32") return memory::value_width_t::i32;
    if (w == "u32") return memory::value_width_t::u32;
    if (w == "i64") return memory::value_width_t::i64;
    if (w == "u64") return memory::value_width_t::u64;
    if (w == "f32") return memory::value_width_t::f32;
    if (w == "f64") return memory::value_width_t::f64;
    if (w == "all") return memory::value_width_t::u32; // handled via scan_all_types
    fail("bad width");
}

memory::scan_type_t parse_scan_kind(const json& args) {
    const std::string k = args.value("kind", std::string{"exact"});
    if (k == "exact")        return memory::scan_type_t::exact_value;
    if (k == "between")      return memory::scan_type_t::between;
    if (k == "bigger")       return memory::scan_type_t::bigger_than;
    if (k == "smaller")      return memory::scan_type_t::smaller_than;
    if (k == "unknown")      return memory::scan_type_t::unknown_initial;
    if (k == "increased")    return memory::scan_type_t::increased;
    if (k == "increased_by") return memory::scan_type_t::increased_by;
    if (k == "increased_percent") return memory::scan_type_t::increased_percent;
    if (k == "decreased")    return memory::scan_type_t::decreased;
    if (k == "decreased_by") return memory::scan_type_t::decreased_by;
    if (k == "decreased_percent") return memory::scan_type_t::decreased_percent;
    if (k == "changed")      return memory::scan_type_t::changed;
    if (k == "unchanged")    return memory::scan_type_t::unchanged;
    fail("bad scan kind");
}

memory::rounding_t parse_rounding(const json& args) {
    const std::string r = args.value("rounding", std::string{"exact"});
    if (r == "exact")     return memory::rounding_t::exact;
    if (r == "rounded")   return memory::rounding_t::rounded;
    if (r == "truncated") return memory::rounding_t::truncated;
    if (r == "extreme")   return memory::rounding_t::extreme;
    fail("bad rounding (exact|rounded|truncated|extreme)");
}

memory::region_pref_t parse_region_pref(const json& args, const char* key) {
    if (args.contains(key) && args.at(key).is_boolean()) return memory::region_pref_t::any;
    const std::string pref = args.value(key, std::string{"any"});
    if (pref == "any")     return memory::region_pref_t::any;
    if (pref == "include") return memory::region_pref_t::include;
    if (pref == "exclude") return memory::region_pref_t::exclude;
    fail(std::string("bad ") + key + " preference (any|include|exclude)");
}

const char* width_name(memory::value_width_t w) noexcept {
    switch (w) {
    case memory::value_width_t::i8:  return "i8";
    case memory::value_width_t::u8:  return "u8";
    case memory::value_width_t::i16: return "i16";
    case memory::value_width_t::u16: return "u16";
    case memory::value_width_t::i32: return "i32";
    case memory::value_width_t::u32: return "u32";
    case memory::value_width_t::i64: return "i64";
    case memory::value_width_t::u64: return "u64";
    case memory::value_width_t::f32: return "f32";
    case memory::value_width_t::f64: return "f64";
    }
    return "unknown";
}

std::vector<uint8_t> hex_decode(const std::string& hex) {
    std::vector<uint8_t> out;
    std::string clean;
    clean.reserve(hex.size());
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
        else if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ',') {}
        else fail("non-hex byte in payload");
    }
    if (clean.size() % 2 != 0) fail("hex payload has odd length");
    out.reserve(clean.size() / 2);
    for (size_t i = 0; i < clean.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* d = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = d[data[i] >> 4];
        out[i * 2 + 1] = d[data[i] & 0xF];
    }
    return out;
}

std::string hex64(uint64_t v) {
    char buf[32] = "";
    std::snprintf(buf, sizeof(buf), "%llX", static_cast<unsigned long long>(v));
    return buf;
}

const char* arch_from_hype(hype::Arch a) {
    switch (a) {
    case hype::Arch::X86:   return "x86";
    case hype::Arch::X64:   return "x64";
    case hype::Arch::ARM:   return "arm";
    case hype::Arch::ARM64: return "arm64";
    case hype::Arch::MIPS:  return "mips";
    case hype::Arch::PPC:   return "ppc";
    default:                return "unknown";
    }
}

const char* xref_kind_name_hype(hype::XrefType t) {
    switch (t) {
    case hype::XrefType::CodeCall:  return "call";
    case hype::XrefType::CodeJump:  return "jump";
    case hype::XrefType::DataRead:  return "read";
    case hype::XrefType::DataWrite: return "write";
    case hype::XrefType::DataOffset: return "offset";
    default:                         return "other";
    }
}

const char* callconv_name(hype::CallConv c) {
    switch (c) {
    case hype::CallConv::Cdecl:   return "cdecl";
    case hype::CallConv::Stdcall: return "stdcall";
    case hype::CallConv::Fastcall: return "fastcall";
    case hype::CallConv::Thiscall: return "thiscall";
    case hype::CallConv::X64:     return "x64";
    default:                      return "unknown";
    }
}

bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return true;
    const size_t n = needle.size(), h = haystack.size();
    if (n > h) return false;
    for (size_t i = 0; i + n <= h; ++i)
        if (_strnicmp(haystack.c_str() + i, needle.c_str(), n) == 0)
            return true;
    return false;
}

json hits_json(const std::vector<memory::scan_result_t>& hits, size_t limit) {
    json arr = json::array();
    const size_t n = std::min(hits.size(), limit);
    for (size_t i = 0; i < n; ++i) {
        arr.push_back({
            {"addr", static_cast<uint64_t>(hits[i].address)},
            {"bits", hits[i].bits},
            {"value", hits[i].bits},
            {"formatted", memory::format_value_text(hits[i].matched, hits[i].bits)},
            {"type", width_name(hits[i].matched)}
        });
    }
    return arr;
}

// image cache

image_cache_t& load_image(const std::string& path) {
    if (g_image.path == path && !g_image.file.empty()) return g_image;

    std::FILE* f = nullptr;
    fopen_s(&f, path.c_str(), "rb");
    if (!f) fail("cannot open image file");
    fseek(f, 0, SEEK_END);
    const long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (size <= 0 || size > (256L << 20)) { fclose(f); fail("image file too large or empty"); }
    image_cache_t c;
    c.file.resize(static_cast<size_t>(size));
    const size_t rd = fread(c.file.data(), 1, c.file.size(), f);
    fclose(f);
    if (rd != c.file.size()) fail("short read on image file");

    c.pe = disasm::pe_parse(c.file.data(), c.file.size());
    if (!c.pe.ok) fail("not a valid PE image");

    g_image = std::move(c);
    g_image.path = path;
    return g_image;
}

disasm::engine_t& shared_engine() {
    static disasm::engine_t eng;   // guarded by g_tool_mu
    return eng;
}

// hw bp and snapshot helpers

mcp_snapshot_t* find_snapshot(uint64_t id) {
    for (auto& rec : g_snaps)
        if (rec.id == id) return &rec;
    return nullptr;
}

// app session context
// what the app has going right now, shown at initialize and in the status actions

json loaded_image_json() {
    std::lock_guard lk(ds::state_mutex());
    auto& bin = ds::get();
    json out = {{"ready", bin.ready}};
    if (!bin.ready) return out;
    out["name"]          = bin.name;
    out["path"]          = bin.path;
    out["base"]          = bin.base;
    out["entry_va"]      = bin.base + bin.pe.entry_rva;
    out["size_of_image"] = bin.pe.size_of_image;
    out["sections"]      = bin.pe.sections.size();
    out["functions"]     = bin.fns.functions().size();
    out["xrefs"]         = bin.xrefs.total();
    out["strings"]       = bin.strings.size();
    out["symbols"]       = bin.symbols.size();

    // hyperion is the decompiler plus the rich analysis db
    json hype = {{"available", static_cast<bool>(bin.hype)}};
    if (bin.hype) {
        const bool rdy    = bin.hype->ready();
        hype["ready"]     = rdy;
        hype["progress"]  = bin.hype->progress();
        hype["arch"]      = arch_from_hype(bin.hype->db().arch);
        if (rdy) {
            hype["functions"]       = bin.hype->db().funcs.size();
            hype["instructions"]    = bin.hype->db().insns.size();
            hype["xrefs"]           = bin.hype->db().xrefs.size();
            hype["vtables"]         = bin.hype->db().vtables.size();
            hype["globals"]         = bin.hype->db().globals.size();
            hype["rtti_classes"]    = bin.hype->rtti().classes().size();
        }
        const std::string herr = bin.hype->error();
        if (!herr.empty()) hype["error"] = herr;
    }
    out["hype"] = hype;
    return out;
}

json attached_target_json() {
    json out = {{"attached", false}};
    if (auto s = process::active_session(); s && s->valid()) {
        out["attached"] = true;
        out["pid"]      = s->pid();
        out["name"]     = s->name();
        out["arch"]     = arch_name(s->arch());
    }
    return out;
}

// caller holds the mutex
json app_state_unlocked() {
    json out;
    out["backend"] = runtime::active_badge();
    out["target"]  = attached_target_json();
    out["image"]   = loaded_image_json();
    // surfacing a live debug session keeps an agent from stomping it
    out["debugger"] = g_dbg ? debugger_state_name(g_dbg->state()) : "idle";
    return out;
}

// tool: target

json tool_target(const json& args) {
    const std::string action = require_action(args);

    if (action == "list") {
        auto res = runtime::active().enum_processes();
        if (!res.ok) fail("process enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{4096});
        for (size_t i = 0; i < cap; ++i) {
            const auto& p = res.items[i];
            // the process table wants path and elevation too
            arr.push_back({{"pid", p.pid},
                           {"name", p.name},
                           {"arch", arch_name(p.arch)},
                           {"path", p.path},
                           {"elevation", elevation_name(p.elevation)}});
        }
        return {{"processes", arr}, {"count", arr.size()}};
    }

    if (action == "icon") {
        // icons get cached since a busy machine is 200 processes sharing a handful of images
        static std::unordered_map<std::string, json> icon_cache;

        std::vector<std::string> paths;
        if (args.contains("paths") && args.at("paths").is_array()) {
            for (const auto& p : args.at("paths")) {
                if (p.is_string()) paths.push_back(p.get<std::string>());
                if (paths.size() >= 64) break;   // keep one requests shell work bounded
            }
        } else if (args.contains("path") && args.at("path").is_string()) {
            paths.push_back(args.at("path").get<std::string>());
        } else if (args.contains("pid")) {
            const uint32_t pid = args.at("pid").get<uint32_t>();
            auto res = runtime::active().enum_processes();
            if (res.ok) {
                for (const auto& p : res.items)
                    if (p.pid == pid) {
                        paths.push_back(p.path);
                        break;
                    }
            }
        } else {
            fail("target.icon: need path, paths, or pid");
        }

        json icons = json::object();
        for (const auto& path : paths) {
            if (path.empty()) continue;
            auto hit = icon_cache.find(path);
            if (hit == icon_cache.end()) {
                const auto bits = process::icon_for_path(path, true);
                json entry = {{"width", bits.width}, {"height", bits.height}};
                if (!bits.empty()) entry["bgra_b64"] = infra::fmt::base64(bits.bgra);
                hit = icon_cache.emplace(path, std::move(entry)).first;
            }
            icons[path] = hit->second;
        }
        // grab the size before the move eats it
        const size_t resolved = icons.size();
        return {{"icons", std::move(icons)}, {"count", resolved}};
    }

    if (action == "attach") {
        const uint64_t pid = parse_addr(args, "pid");
        if (pid == 0 || pid > 0xFFFFFFFFull) fail("bad pid");
        if (!process::target_attach(static_cast<uint32_t>(pid)))
            fail("attach failed (process gone, access denied, or kernel DTB resolve failed)");
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        auto s = process::active_session();

        // pull the targets main module into the shared session so static tools see what actually runs, a ui loaded binary never gets clobbered
        bool image_auto_loaded = false;
        if (!ds::has_binary()) image_auto_loaded = ds::load_from_target();

        json out = {{"attached", true},
                    {"pid", pid},
                    {"name", s ? s->name() : ""},
                    {"arch", s ? arch_name(s->arch()) : ""},
                    {"backend", runtime::active_badge()},
                    {"image_auto_loaded", image_auto_loaded},
                    {"image", loaded_image_json()}};
        if (!image_auto_loaded && !ds::has_binary())
            out["hint"] = "main module could not be read from disk; pass an explicit "
                          "'path' to static tools or open a binary in reverse-slop";
        return out;
    }

    if (action == "detach") {
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        process::target_detach();
        return {{"attached", false}};
    }

    if (action == "status") {
        json out;
        out["backend"]  = runtime::active_badge();
        out["kernel"]   = runtime::active_kind() == runtime::backend_kind_t::kernel;
        auto s = process::active_session();
        if (s && s->valid()) {
            out["attached"] = true;
            out["pid"]      = s->pid();
            out["name"]     = s->name();
            out["arch"]     = arch_name(s->arch());
        } else {
            out["attached"] = false;
        }
        if (auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active())) {
            out["hwbp_supported"] = k->hwbp_supported();
        }
        out["debugger_state"] = g_dbg ? debugger_state_name(g_dbg->state()) : "idle";
        out["image"]          = loaded_image_json();
        return out;
    }

    if (action == "modules") {
        auto& s = need_session();
        auto res = runtime::active().enum_modules(s.handle());
        if (!res.ok) fail("module enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{2048});
        for (size_t i = 0; i < cap; ++i) {
            const auto& m = res.items[i];
            arr.push_back({{"base", static_cast<uint64_t>(m.base)},
                           {"size", m.size},
                           {"name", m.name},
                           {"path", m.path}});
        }
        return {{"modules", arr}, {"count", arr.size()}};
    }

    if (action == "dump_module") {
        auto& session = need_session();
        if (!args.contains("path") || !args.at("path").is_string())
            fail("dump_module requires output 'path'");
        const std::string output_path = args.at("path").get<std::string>();
        if (output_path.empty()) fail("dump_module output path is empty");

        const uint64_t requested_base = args.contains("base")
            ? parse_addr(args, "base") : 0;
        const std::string requested_name = args.value("name", std::string{});
        if (requested_base == 0 && requested_name.empty())
            fail("dump_module requires module 'base' or 'name'");

        auto modules = runtime::active().enum_modules(session.handle());
        if (!modules.ok) fail("module enumeration failed");

        const runtime::module_info_t* selected = nullptr;
        for (const auto& module : modules.items) {
            if ((requested_base != 0 && module.base == requested_base) ||
                (requested_base == 0 &&
                 _stricmp(module.name.c_str(), requested_name.c_str()) == 0)) {
                selected = &module;
                break;
            }
        }
        if (!selected) fail("requested module is not loaded in the target");

        process::module_dump_options_t options;
        options.strict_reads = args.value("strict", true);
        auto result = process::dump_module_pe(session, *selected, output_path, options);
        if (!result.ok) fail("module dump failed: " + result.error);

        bool loaded = false;
        if (args.value("load", false))
            loaded = ds::load_file(output_path, selected->base);

        return {{"dumped", true},
                {"complete", result.complete},
                {"path", result.output_path},
                {"bytes_written", result.bytes_written},
                {"sections", result.section_count},
                {"module", {{"base", static_cast<uint64_t>(selected->base)},
                             {"size", selected->size},
                             {"name", selected->name},
                             {"path", selected->path}}},
                {"loaded", loaded},
                {"warnings", result.warnings}};
    }

    if (action == "threads") {
        uint32_t pid = 0;
        if (args.contains("pid")) pid = static_cast<uint32_t>(parse_addr(args, "pid"));
        if (pid == 0) pid = need_session().pid();
        auto res = runtime::active().enum_threads(pid);
        if (!res.ok) fail("thread enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{4096});
        for (size_t i = 0; i < cap; ++i) {
            const auto& t = res.items[i];
            arr.push_back({{"tid", t.tid},
                           {"start", static_cast<uint64_t>(t.start_address)},
                           {"priority", t.priority}});
        }
        return {{"threads", arr}, {"count", arr.size()}};
    }

    if (action == "regions") {
        auto& s = need_session();
        auto res = runtime::active().enum_regions(s.handle());
        if (!res.ok) fail("region enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{8192});
        for (size_t i = 0; i < cap; ++i) {
            const auto& r = res.items[i];
            arr.push_back({{"base", static_cast<uint64_t>(r.base)},
                           {"size", r.size},
                           {"protect", r.protect},
                           {"state", r.state},
                           {"type", r.type}});
        }
        return {{"regions", arr}, {"count", arr.size()}};
    }

    if (action == "handles") {
        auto& s = need_session();
        auto res = runtime::active().enum_handles(s.pid());
        if (!res.ok) fail("handle enumeration failed");
        json arr = json::array();
        const size_t cap = std::min(res.items.size(), size_t{2048});
        for (size_t i = 0; i < cap; ++i) {
            const auto& h = res.items[i];
            json o = {{"handle", static_cast<uint64_t>(h.handle_value)},
                      {"type", h.type_name},
                      {"granted_access", h.granted_access}};
            if (!h.object_name.empty()) o["object"] = h.object_name;
            arr.push_back(std::move(o));
        }
        return {{"handles", arr}, {"count", arr.size()}, {"total", res.items.size()}};
    }

    fail("target: unknown action (list|attach|detach|status|modules|"
         "dump_module|threads|regions|handles|icon)");
}

// tool: memory

json tool_memory(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no target attached, a typo isnt a missing target
    {
        static const char* kKnown[] = {
            "read", "write", "scan", "rescan", "scan_state", "scan_reset",
            "aob", "pointerscan", "snapshot", "snapshots", "diff",
            "snapshot_free", "protect", "alloc", "free", "siggen",
            "live_crypto", "watch_list", "watch_add", "watch_remove",
            "watch_clear", "watch_set",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("memory: unknown action (read|write|scan|rescan|scan_state|scan_reset|"
                 "aob|pointerscan|snapshot|snapshots|diff|snapshot_free|protect|alloc|"
                 "free|siggen|live_crypto|watch_list|watch_add|watch_remove|watch_clear|"
                 "watch_set)");
    }

    // watchlist
    // the app tick services these at 10hz so the ui never polls
    if (action.rfind("watch", 0) == 0) {
        auto entries_json = [] {
            json arr = json::array();
            for (const auto& e : memory::watch::list())
                arr.push_back({{"id", e.id},
                               {"addr", e.addr},
                               {"width", width_name(e.width)},
                               {"label", e.label},
                               {"freeze", e.freeze},
                               {"frozen_bits", e.frozen_bits}});
            return arr;
        };

        if (action == "watch_list") {
            json vals = json::array();
            for (const auto& v : memory::watch::values())
                vals.push_back({{"id", v.id},
                                {"addr", v.addr},
                                {"ok", v.ok},
                                {"held", v.held},
                                {"bits", v.bits},
                                {"text", v.text}});
            return {{"entries", entries_json()}, {"values", std::move(vals)}};
        }

        if (action == "watch_add") {
            if (!args.contains("addr")) fail("memory.watch_add: missing addr");
            const uint64_t addr = args.at("addr").get<uint64_t>();
            const auto width = parse_width(args);
            std::string label = args.value("label", std::string{});
            if (label.empty()) label = infra::fmt::format_address(addr);
            const uint64_t id = memory::watch::add(addr, width, std::move(label));
            if (id == 0) fail("memory.watch_add: watch list is full");
            return {{"id", id}, {"entries", entries_json()}};
        }

        if (action == "watch_remove") {
            if (!args.contains("id")) fail("memory.watch_remove: missing id");
            const bool ok = memory::watch::remove(args.at("id").get<uint64_t>());
            if (!ok) fail("memory.watch_remove: no such id");
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_clear") {
            memory::watch::clear();
            return {{"ok", true}, {"entries", entries_json()}};
        }

        if (action == "watch_set") {
            if (!args.contains("id")) fail("memory.watch_set: missing id");
            const uint64_t id = args.at("id").get<uint64_t>();
            bool touched = false;
            if (args.contains("freeze") && args.at("freeze").is_boolean()) {
                if (!memory::watch::set_freeze(id, args.at("freeze").get<bool>()))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("width")) {
                if (!memory::watch::set_width(id, parse_width(args)))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("label") && args.at("label").is_string()) {
                if (!memory::watch::set_label(id, args.at("label").get<std::string>()))
                    fail("memory.watch_set: no such id");
                touched = true;
            }
            if (args.contains("value")) {
                // text form so floats and signed widths round trip like the value box
                const auto entries = memory::watch::list();
                auto it = std::find_if(entries.begin(), entries.end(),
                                       [id](const memory::watch::entry_t& e) {
                                           return e.id == id;
                                       });
                if (it == entries.end()) fail("memory.watch_set: no such id");
                uint64_t bits = 0;
                const auto& v = args.at("value");
                if (v.is_string()) {
                    if (!memory::parse_value_text(it->width, v.get<std::string>(), bits))
                        fail("memory.watch_set: cannot parse value for width");
                } else if (v.is_number_float()) {
                    bits = memory::value_from_double(it->width, v.get<double>());
                } else if (v.is_number()) {
                    bits = v.get<uint64_t>();
                } else {
                    fail("memory.watch_set: value must be string or number");
                }
                std::string err;
                if (!memory::watch::poke(id, bits, &err))
                    fail("memory.watch_set: " + err);
                touched = true;
            }
            if (!touched) fail("memory.watch_set: nothing to change");
            return {{"ok", true}, {"entries", entries_json()}};
        }

        fail("memory: unknown watch action");
    }

    if (action == "scan_reset") {
        g_scan.engine.reset();
        g_scan.used = false;
        g_scan.pid = 0;
        return {{"reset", true}};
    }

    if (action == "scan_state") {
        const auto stats = g_scan.engine.stats();
        return {{"active", g_scan.used},
                {"pid", g_scan.pid},
                {"width", g_scan.width},
                {"kind", g_scan.kind},
                {"total", g_scan.engine.results().size()},
                {"region_scan_active", g_scan.engine.region_scan_active()},
                {"regions", stats.regions},
                {"regions_scanned", stats.regions_scanned},
                {"bytes_scanned", stats.bytes_scanned},
                {"slots_scanned", stats.slots_scanned},
                {"slots_tracked", stats.slots_tracked},
                {"truncated", stats.truncated},
                {"cancelled", stats.cancelled}};
    }

    // snapshot actions work without a target, everything below needs one
    if (action == "snapshots") {
        json arr = json::array();
        for (const auto& rec : g_snaps) {
            arr.push_back({{"id", rec.id},
                           {"addr", static_cast<uint64_t>(rec.snap.base)},
                           {"size", rec.snap.size},
                           {"bytes", rec.snap.bytes.size()},
                           {"complete", rec.snap.complete}});
        }
        return {{"snapshots", arr}, {"count", arr.size()}};
    }

    if (action == "snapshot_free") {
        if (args.value("all", false)) {
            g_snaps.clear();
            return {{"freed", "all"}};
        }
        if (!args.contains("id")) fail("missing id (or all:true)");
        const uint64_t id = parse_addr(args, "id");
        for (auto it = g_snaps.begin(); it != g_snaps.end(); ++it) {
            if (it->id == id) {
                g_snaps.erase(it);
                return {{"freed", id}};
            }
        }
        fail("unknown snapshot id");
    }

    // reads fall back to the loaded image when no target is attached
    if (action == "read") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = parse_addr(args.contains("len") ? args : json{{"len", 256}}, "len");
        if (len == 0) len = 256;
        if (len > (1ull << 20)) fail("read len capped at 1 MiB");
        std::vector<uint8_t> buf(static_cast<size_t>(len));
        size_t got = 0;

        // live target first, a failed live read is a real error worth seeing
        if (auto sess = process::active_session(); sess && sess->valid()) {
            auto io = sess->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (io.ok) got = io.bytes;
            else fail(std::string("live read failed (error ") +
                      std::to_string(io.error) + ")");
        }
        // fall back to the file image only when nothing is attached
        if (got == 0) {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (!bin.ready) fail("no target attached and no image loaded");
            auto off = bin.pe.va_to_offset(addr);
            if (!off) fail("address not mapped in loaded image");
            got = std::min(buf.size(), bin.file.size() - *off);
            std::memcpy(buf.data(), bin.file.data() + *off, got);
        }

        json out = {{"addr", addr}, {"len", got}};
        const std::string fmt = args.value("format", std::string{"hex"});
        if (fmt == "hex") {
            out["hex"] = to_hex(buf.data(), got);
        } else if (fmt == "utf8") {
            std::string text(reinterpret_cast<const char*>(buf.data()), got);
            text.erase(std::find(text.begin(), text.end(), '\0'), text.end());
            out["text"] = text;
        } else if (fmt == "u8" || fmt == "u32" || fmt == "u64" || fmt == "f32" || fmt == "f64") {
            json arr = json::array();
            const size_t w = fmt == "u8" ? 1 : fmt == "u32" ? 4 : fmt == "f32" ? 4 : fmt == "f64" ? 8 : 8;
            for (size_t off = 0; off + w <= got; off += w) {
                if (fmt == "u8")  arr.push_back(buf[off]);
                if (fmt == "u32") { uint32_t v; memcpy(&v, buf.data() + off, 4); arr.push_back(v); }
                if (fmt == "u64") { uint64_t v; memcpy(&v, buf.data() + off, 8); arr.push_back(v); }
                if (fmt == "f32") { float v;    memcpy(&v, buf.data() + off, 4); arr.push_back(v); }
                if (fmt == "f64") { double v;   memcpy(&v, buf.data() + off, 8); arr.push_back(v); }
            }
            out["values"] = arr;
        } else {
            fail("bad format (hex|utf8|u8|u32|u64|f32|f64)");
        }
        return out;
    }

    auto& s = need_session();

    if (action == "write") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("hex") || !args.at("hex").is_string()) fail("missing hex payload");
        auto bytes = hex_decode(args.at("hex").get<std::string>());
        if (bytes.empty()) fail("empty payload");
        if (bytes.size() > (1ull << 20)) fail("write capped at 1 MiB");
        auto io = s.write(static_cast<uintptr_t>(addr), bytes.data(), bytes.size());
        if (!io.ok) fail("write failed at requested range");
        return {{"addr", addr}, {"written", io.bytes}};
    }

    if (action == "scan" || action == "rescan") {
        session_reader_t reader(s);

        // scan config straight from the request
        memory::scan_config_t cfg;
        cfg.type  = parse_scan_kind(args);
        cfg.width = parse_width(args);
        cfg.scan_all_types = args.value("width", std::string{"i32"}) == "all";
        cfg.rounding = parse_rounding(args);
        cfg.max_results = std::min<size_t>(
            args.value("max_results", infra::limits::max_scan_hits),
            infra::limits::max_scan_hits);
        cfg.threads = std::min<uint32_t>(args.value("threads", 0u), 64u);
        cfg.chunk_bytes = std::min<size_t>(
            args.value("chunk_bytes", infra::limits::scan_chunk_bytes),
            64u << 20);
        if (args.contains("begin") && args.contains("end")) {
            cfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            cfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        // fastscan is alignment or the ends with hex digits mode
        if (args.contains("tail")) {
            std::string tail = args.at("tail").get<std::string>();
            if (tail.rfind("0x", 0) == 0 || tail.rfind("0X", 0) == 0)
                tail.erase(0, 2);
            if (tail.empty() || tail.size() > 8 ||
                tail.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                fail("bad tail (1..8 hex digits)");
            uint64_t tv = 0;
            if (!memory::parse_value_text(memory::value_width_t::u64, "0x" + tail, tv))
                fail("bad tail (hex digits)");
            cfg.fast = memory::fastscan_method_t::ends_with;
            cfg.fast_digits = static_cast<uint32_t>(tail.size());
            cfg.fast_tail   = tv;
        } else {
            cfg.fast = memory::fastscan_method_t::alignment;
            cfg.fast_alignment = static_cast<uint32_t>(args.value("alignment", 4u));
            if (cfg.fast_alignment == 0) cfg.fast = memory::fastscan_method_t::off;
        }
        // region prefs, the old boolean flags still work
        cfg.writable = parse_region_pref(args, "writable");
        cfg.executable = parse_region_pref(args, "executable");
        cfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            cfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        if (args.value("read_only", false)) cfg.writable = memory::region_pref_t::exclude;
        if (args.value("no_exec", false)) cfg.executable = memory::region_pref_t::exclude;
        cfg.mem_private = args.value("mem_private", true);
        cfg.mem_image = args.value("mem_image", true);
        cfg.mem_mapped = args.value("mem_mapped", true);

        const auto needs_value1 = [](memory::scan_type_t type) {
            return type == memory::scan_type_t::exact_value ||
                   type == memory::scan_type_t::between ||
                   type == memory::scan_type_t::bigger_than ||
                   type == memory::scan_type_t::smaller_than ||
                   type == memory::scan_type_t::increased_by ||
                   type == memory::scan_type_t::decreased_by ||
                   type == memory::scan_type_t::increased_percent ||
                   type == memory::scan_type_t::decreased_percent;
        };
        const auto needs_value2 = [](memory::scan_type_t type) {
            return type == memory::scan_type_t::between ||
                   type == memory::scan_type_t::increased_percent ||
                   type == memory::scan_type_t::decreased_percent;
        };
        if (needs_value1(cfg.type) && !args.contains("value"))
            fail("scan kind requires value");
        if (needs_value2(cfg.type) && !args.contains("value2"))
            fail("scan kind requires value2");

        // text values keep the float accuracy
        std::string v1_text, v2_text;
        if (args.contains("value")) {
            const json& v = args.at("value");
            v1_text = v.is_string() ? v.get<std::string>() : v.dump();
            uint64_t bits = 0;
            if (!memory::parse_value_text(cfg.width, v1_text, bits))
                fail("bad value for width");
            cfg.value1 = memory::value_to_double(cfg.width, bits);
            cfg.float_accuracy = memory::float_accuracy_from_text(v1_text);
        }
        if (args.contains("value2")) {
            const json& v = args.at("value2");
            v2_text = v.is_string() ? v.get<std::string>() : v.dump();
            uint64_t bits = 0;
            if (!memory::parse_value_text(cfg.width, v2_text, bits))
                fail("bad value2 for width");
            cfg.value2 = memory::value_to_double(cfg.width, bits);
        }
        if (cfg.type == memory::scan_type_t::increased_percent ||
            cfg.type == memory::scan_type_t::decreased_percent) {
            // 5 means five percent, same as the cheat engine ui
            cfg.value1 /= 100.0;
            cfg.value2 /= 100.0;
        }

        // region set comes from the active backend
        auto regions = runtime::target_scan_regions(s.handle());

        infra::cancel_token_t tok;
        std::string err;

        if (action == "scan") {
            // scan starts fresh, rescan refines what the last one found
            g_scan.engine.reset();
            if (!g_scan.engine.first_scan(reader, std::move(regions), cfg, tok, &err))
                fail(err.empty() ? "first scan failed" : err);
            g_scan.used = true;
            g_scan.pid = s.pid();
        } else {
            if (!g_scan.used)
                fail("no previous scan to rescan (run memory.scan first)");
            if (g_scan.pid != s.pid())
                fail("scan belongs to another target (run memory.scan first)");
            if (!g_scan.engine.next_scan(reader, cfg, tok, &err))
                fail(err.empty() ? "rescan failed" : err);
        }
        g_scan.width = args.value("width", std::string{"i32"});
        g_scan.kind = args.value("kind", std::string{"exact"});

        const auto& out = g_scan.engine.results();
        const auto stats = g_scan.engine.stats();
        const size_t limit = std::min<size_t>(args.value("limit", 100u), 10000u);
        return {
            {"hits", hits_json(out, limit)},
            {"total", out.size()},
            {"truncated", stats.truncated},
            {"cancelled", stats.cancelled},
            {"bytes_scanned", stats.bytes_scanned},
            {"slots_scanned", stats.slots_scanned},
            {"regions_scanned", stats.regions_scanned},
            {"region_scan_active", g_scan.engine.region_scan_active()},
            {"slots_tracked", stats.slots_tracked},
            {"width", args.value("width", std::string{"i32"})}
        };
    }

    if (action == "aob") {
        if (!args.contains("pattern") || !args.at("pattern").is_string()) fail("missing pattern");
        std::string err;
        auto pat = memory::aob_compile(args.at("pattern").get<std::string>(), err);
        if (!pat) fail("bad pattern: " + err);
        session_reader_t reader(s);

        memory::scan_config_t rcfg; // region preference carrier
        if (args.contains("begin") && args.contains("end")) {
            rcfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            rcfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        rcfg.writable = parse_region_pref(args, "writable");
        rcfg.executable = parse_region_pref(args, "executable");
        rcfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            rcfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        rcfg.mem_private = args.value("mem_private", true);
        rcfg.mem_image = args.value("mem_image", true);
        rcfg.mem_mapped = args.value("mem_mapped", true);
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), rcfg);
        if (regions.empty()) fail("no committed ranges");

        memory::aob_scan_options_t opt;
        opt.alignment = static_cast<uint32_t>(args.value("alignment", 1u));
        opt.max_results = std::min<size_t>(
            args.value("max_results", infra::limits::max_aob_matches),
            infra::limits::max_aob_matches);
        opt.chunk_bytes = std::min<size_t>(
            args.value("chunk_bytes", infra::limits::scan_chunk_bytes),
            64u << 20);
        opt.threads = std::min<uint32_t>(args.value("threads", 0u), 64u);
        infra::cancel_token_t tok;
        memory::aob_stats_t stats{};
        auto matches = memory::aob_scan(reader, regions, *pat, opt, tok, &stats);
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 10000u);
        json arr = json::array();
        for (size_t i = 0; i < matches.size() && i < limit; ++i)
            arr.push_back(static_cast<uint64_t>(matches[i]));
        return {{"matches", arr}, {"total", matches.size()},
                {"truncated", stats.truncated}, {"cancelled", stats.cancelled},
                {"bytes_scanned", stats.bytes_scanned}};
    }

    if (action == "protect") {
        const uint64_t addr = parse_addr(args, "addr");
        const uint64_t len  = parse_addr(args.contains("len") ? args : json{{"len", 4096}}, "len");
        const uint32_t prot = static_cast<uint32_t>(parse_addr(args, "prot"));
        uint32_t old = 0;
        auto io = runtime::active().protect_memory(s.handle(), static_cast<uintptr_t>(addr),
                                                   static_cast<size_t>(len), prot, &old);
        if (!io.ok) fail("protect failed (kernel backend required for cross-process protect)");
        return {{"addr", addr}, {"len", len}, {"old_protect", old}};
    }

    if (action == "alloc") {
        const uint64_t len = parse_addr(args, "len");
        if (len == 0 || len > (64ull << 20)) fail("alloc len out of range (1 byte .. 64 MiB)");
        uintptr_t out = 0;
        auto io = runtime::active().allocate_memory(s.handle(), 0, static_cast<size_t>(len),
                                                    0x40 /*PAGE_EXECUTE_READWRITE*/, &out);
        if (!io.ok) fail("alloc failed (kernel backend required for cross-process alloc)");
        return {{"addr", static_cast<uint64_t>(out)}, {"len", len}};
    }

    if (action == "free") {
        const uint64_t addr = parse_addr(args, "addr");
        auto io = runtime::active().free_memory(s.handle(), static_cast<uintptr_t>(addr));
        if (!io.ok) fail("free failed (kernel backend required for cross-process free)");
        return {{"freed", true}};
    }

    if (action == "pointerscan") {
        if (!args.contains("target")) fail("missing target address");
        memory::pointer_scan_options_t opt;
        opt.target = static_cast<uintptr_t>(parse_addr(args, "target"));
        opt.depth  = std::min<uint32_t>(
            static_cast<uint32_t>(args.value("depth", 3u)),
            static_cast<uint32_t>(infra::limits::max_pointer_depth));
        opt.min_offset = args.value("min_offset", -4096);
        opt.max_offset = args.value("max_offset",  4096);
        opt.alignment  = static_cast<uint32_t>(args.value("alignment", 4u));
        opt.only_module_backed = args.value("static_roots", false);
        opt.frontier_cap = std::min<size_t>(
            args.value("frontier_cap", size_t{100'000}),
            infra::limits::max_pointer_chains);

        // region set is explicit bounds or committed memory, capped since pointer sweeps scale with range
        bool range_truncated = false;
        memory::scan_config_t rcfg;
        if (args.contains("begin") && args.contains("end")) {
            rcfg.begin = static_cast<uintptr_t>(parse_addr(args, "begin"));
            rcfg.end   = static_cast<uintptr_t>(parse_addr(args, "end"));
        }
        rcfg.writable = parse_region_pref(args, "writable");
        rcfg.executable = parse_region_pref(args, "executable");
        rcfg.copy_on_write = parse_region_pref(args, "copy_on_write");
        if (args.contains("writable") && args.at("writable").is_boolean())
            rcfg.writable = args.at("writable").get<bool>()
                ? memory::region_pref_t::include : memory::region_pref_t::any;
        rcfg.mem_private = args.value("mem_private", true);
        rcfg.mem_image = args.value("mem_image", true);
        rcfg.mem_mapped = args.value("mem_mapped", true);
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), rcfg);
        if (regions.empty()) fail("no committed ranges");

        if (!args.contains("begin") || !args.contains("end")) {
            const uint64_t lo = regions.front().base;
            uint64_t hi = regions.back().base + regions.back().size;
            const uint64_t span_cap = std::min<uint64_t>(
                args.contains("max_bytes") ? parse_addr(args, "max_bytes")
                                           : (256ull << 20),
                infra::limits::max_region_scan_bytes);
            if (hi - lo > span_cap) {
                hi = lo + span_cap;
                range_truncated = true;
                // clip regions to the window
                for (auto it = regions.begin(); it != regions.end();) {
                    if (it->base >= hi) it = regions.erase(it);
                    else {
                        if (it->base + it->size > hi)
                            it->size = static_cast<size_t>(hi - it->base);
                        ++it;
                    }
                }
            }
        }

        session_reader_t reader(s);
        infra::cancel_token_t tok;
        memory::pointer_scan_stats_t stats{};
        auto chains = memory::pointer_scan(reader, regions, opt, tok, &stats);

        const size_t limit = std::min<size_t>(args.value("limit", 100u), 1000u);
        json arr = json::array();
        for (size_t i = 0; i < chains.size() && i < limit; ++i) {
            json addrs = json::array();
            json offs  = json::array();
            for (uintptr_t a : chains[i].addresses) addrs.push_back(static_cast<uint64_t>(a));
            for (int64_t o : chains[i].offsets)     offs.push_back(o);
            arr.push_back({{"addresses", addrs}, {"offsets", offs},
                           {"depth", chains[i].depth()}});
        }
        return {{"chains", arr}, {"total", chains.size()},
                {"truncated", stats.truncated}, {"range_truncated", range_truncated},
                {"edges_explored", stats.edges_explored}};
    }

    if (action == "snapshot") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = parse_addr(args.contains("len") ? args : json{{"len", 4096}}, "len");
        if (len == 0 || len > infra::limits::max_snapshot_region_bytes)
            fail("bad snapshot len");
        const uint64_t max_bytes = std::min<uint64_t>(
            args.contains("max_bytes") ? parse_addr(args, "max_bytes") : (16ull << 20),
            infra::limits::max_snapshot_region_bytes);

        session_reader_t reader(s);
        infra::cancel_token_t tok;
        mcp_snapshot_t rec;
        rec.id  = g_snap_next_id++;
        rec.snap = memory::snapshot_capture(reader, static_cast<uintptr_t>(addr),
                                            static_cast<size_t>(len), tok, max_bytes);
        json out = {{"id", rec.id}, {"addr", addr}, {"len", len},
                    {"complete", rec.snap.complete}, {"bytes", rec.snap.bytes.size()}};
        if (g_snaps.size() >= kMaxMcpSnapshots) g_snaps.erase(g_snaps.begin());
        g_snaps.push_back(std::move(rec));
        return out;
    }

    if (action == "diff") {
        if (!args.contains("a") || !args.contains("b")) fail("missing snapshot ids a/b");
        mcp_snapshot_t* ra = find_snapshot(parse_addr(args, "a"));
        mcp_snapshot_t* rb = find_snapshot(parse_addr(args, "b"));
        if (!ra || !rb) fail("unknown snapshot id (run memory.snapshots)");
        auto d = memory::snapshot_diff(ra->snap, rb->snap);
        if (!d.valid) fail("snapshots cover different regions (base/size mismatch)");
        const size_t limit = std::min<size_t>(args.value("limit", 512u),
                                              infra::limits::max_diff_ranges);
        json arr = json::array();
        for (size_t i = 0; i < d.changed.size() && i < limit; ++i)
            arr.push_back({{"offset", d.changed[i].offset},
                           {"length", d.changed[i].length}});
        return {{"changed", arr}, {"count", d.changed.size()},
                {"truncated", d.changed.size() > limit}};
    }

    if (action == "siggen") {
        // wildcard the relocatable bytes so the pattern survives a rebase
        const uint64_t addr = parse_addr(args, "addr");
        size_t len = args.contains("len")
            ? static_cast<size_t>(parse_addr(args, "len")) : 32;
        if (len == 0 || len > 256) fail("siggen len must be 1..256");
        auto& eng = shared_engine();
        if (!eng.ok() && !eng.init()) fail("zydis engine init failed");

        std::vector<uint8_t> buf(len);
        auto io = s.read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
        if (!io.ok || io.bytes < len) fail("cannot read signature region");

        std::string pat;
        std::string mask;
        size_t off = 0, insns = 0;
        while (off < len) {
            auto in = eng.decode(addr + off, buf.data() + off, len - off);
            if (!in || in->length == 0) break;
            ++insns;
            for (size_t b = 0; b < in->length; ++b) {
                bool wild = false;
                // rip relative and rel32 bytes move on a rebase
                const bool is_branch =
                    in->flow != disasm::flow_t::none &&
                    in->flow != disasm::flow_t::ret;
                if (in->has_rip_rel && in->length >= 6 && b >= in->length - 4 &&
                    !is_branch)
                    wild = true;
                else if (is_branch && in->length == 5 && b >= 1)
                    wild = true;
                else if (is_branch && in->length == 6 && in->bytes[0] == 0x0F &&
                         b >= 2)
                    wild = true;

                char hex[4];
                std::snprintf(hex, sizeof(hex), "%02X ", buf[off + b]);
                if (!wild) { pat += hex; mask += 'x'; }
                else       { pat += "?? "; mask += '?'; }
            }
            off += in->length;
        }
        while (!pat.empty() && pat.back() == ' ') pat.pop_back();
        if (pat.empty()) fail("nothing decodable at that address");

        // check the pattern is unique across memory
        session_reader_t reader(s);
        infra::cancel_token_t tok;
        memory::aob_stats_t stats{};
        uint64_t hits_total = 0;
        auto regions = memory::filter_regions(
            runtime::target_scan_regions(s.handle()), memory::scan_config_t{});
        if (!regions.empty()) {
            constexpr uint64_t kSpanCap = 512ull << 20;
            const uint64_t lo = regions.front().base;
            uint64_t hi = regions.back().base + regions.back().size;
            if (hi - lo > kSpanCap) {
                hi = lo + kSpanCap;
                for (auto it = regions.begin(); it != regions.end();) {
                    if (it->base >= hi) it = regions.erase(it);
                    else {
                        if (it->base + it->size > hi)
                            it->size = static_cast<size_t>(hi - it->base);
                        ++it;
                    }
                }
            }
            std::string compile_err;
            auto pat2 = memory::aob_compile(pat, compile_err);
            if (pat2) {
                auto matches = memory::aob_scan(reader, regions, *pat2,
                                                memory::aob_scan_options_t{},
                                                tok, &stats);
                hits_total = matches.size();
            }
        }

        json out = {{"addr", addr}, {"pattern", pat}, {"mask", mask},
                    {"length", off}, {"instructions", insns},
                    {"unique", hits_total == 1},
                    {"occurrences", hits_total}};
        out["yara"] = "$a = { " + pat + " }\ncondition: $a";
        return out;
    }

    if (action == "live_crypto") {
        // defaults to the loaded image since thats what youre reversing
        uint64_t begin = args.contains("begin") ? parse_addr(args, "begin") : 0;
        uint64_t end   = args.contains("end")   ? parse_addr(args, "end")   : 0;
        if (!begin) {
            {
                std::lock_guard lk(ds::state_mutex());
                auto& bin = ds::get();
                if (bin.ready && bin.pe.size_of_image) {
                    begin = bin.base;
                    end   = bin.base + bin.pe.size_of_image;
                }
            }
            if (!begin) {
                auto ranges = committed_ranges(s);
                if (ranges.empty()) fail("no committed ranges and no loaded image");
                begin = ranges.front();
                end   = ranges.back();
                constexpr uint64_t kDefault = 1u << 20;
                end = std::min<uint64_t>(begin + kDefault, end);
            }
        }
        const uint64_t cap = std::min<uint64_t>(
            end <= begin ? 4096 : end - begin, 1ull << 20);

        auto& eng = shared_engine();
        std::vector<uint8_t> buf(static_cast<size_t>(cap));
        auto io = s.read(static_cast<uintptr_t>(begin), buf.data(), buf.size());
        if (!io.ok || io.bytes == 0) fail("cannot read target range");
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);
        auto hits = xray::crypto_range_bytes(begin, buf.data(), io.bytes,
                                             eng.ok() ? &eng : nullptr, limit);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"va", h.va}, {"algorithm", h.algorithm},
                           {"constant", h.constant_name}, {"value", h.value},
                           {"source", h.source}});
        return {{"range_begin", begin}, {"bytes", io.bytes},
                {"matches", arr}, {"count", arr.size()}};
    }

    fail("memory: unknown action (read|write|scan|rescan|scan_state|scan_reset|"
         "aob|pointerscan|snapshot|snapshots|diff|snapshot_free|protect|alloc|"
         "free|siggen|live_crypto|watch_list|watch_add|watch_remove|watch_clear|"
         "watch_set)");
}

// tool: disasm

json insn_to_json(const disasm::insn_t& in) {
    json o = {{"va", in.va}, {"len", in.length}, {"text", in.text},
              {"flow", disasm_flow_name(in.flow)}};
    if (in.has_rel_target) o["target"] = in.rel_target;
    if (in.has_rip_rel)    o["rip_rel"] = in.rip_rel_target;
    return o;
}

std::string assemble_one(const std::string& text, uint64_t addr,
                         ZydisEncoderRequest& out);

json tool_disasm(const json& args) {
    const std::string action = require_action(args);
    // say unknown action before no image loaded, a typo isnt a missing binary
    {
        static const char* kKnown[] = {
            "assemble", "disassemble", "loaded", "pe", "functions", "xrefs",
            "strings", "symbols", "symbol_set", "blocks", "globals", "vtables",
            "load", "unload", "analyze_stop",
        };
        const bool known = std::any_of(std::begin(kKnown), std::end(kKnown),
                                        [&](const char* k) { return action == k; });
        if (!known)
            fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
                 "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|unload|"
                 "analyze_stop)");
    }
    auto& eng = shared_engine();
    if (!eng.ok() && !eng.init()) fail("zydis engine init failed");

    if (action == "disassemble") {
        const uint64_t addr = parse_addr(args, "addr");
        const size_t count = std::min<size_t>(args.value("count", 32u), 512u);
        std::vector<uint8_t> buf(count * 16 + 16);
        size_t have = 0;

        // live target first, else the loaded file so you can read with nothing attached
        if (auto s = process::active_session(); s && s->valid()) {
            auto io = s->read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
            if (!io.ok) fail("cannot read code range");
            have = io.bytes;
        } else {
            std::lock_guard lk(ds::state_mutex());
            auto& bin = ds::get();
            if (!bin.ready) fail("no target attached and no image loaded in reverse-slop");
            auto off = bin.pe.va_to_offset(addr);
            if (!off) fail("address not mapped in loaded image (base may differ)");
            have = std::min(buf.size(), bin.file.size() - *off);
            std::memcpy(buf.data(), bin.file.data() + *off, have);
        }

        // hyperion decode is the same zydis core with richer operand records
        json arr = json::array();
        size_t off = 0;
        size_t resync_skip = 0;
        disasm::insn_t insn;
        for (size_t i = 0; i < count && off + 1 < have; ++i) {
            if (!hs::session_t::decode(addr + off, buf.data() + off,
                                       have - off, insn)) {
                ++off;
                ++resync_skip;
                if (resync_skip >= 64) break;  // too much garbage, bail
                --i;  // resync bytes arent instructions
                continue;
            }
            resync_skip = 0;
            arr.push_back(insn_to_json(insn));
            off += insn.length ? insn.length : 1;
        }
        return {{"instructions", arr}, {"count", arr.size()},
                {"engine", "hyperion"}};
    }

    if (action == "assemble") {
        // one instruction at a time, like mov rax, rbx
        if (!args.contains("text") || !args.at("text").is_string())
            fail("missing text (instruction mnemonic + operands)");

        ZydisEncoderRequest req{};
        std::string parse_err = assemble_one(
            args.at("text").get<std::string>(), 0x400000, req);
        if (!parse_err.empty()) fail(parse_err);

        uint8_t buf[16];
        ZyanUSize encoded_len = sizeof(buf);
        if (ZYAN_FAILED(ZydisEncoderEncodeInstruction(&req, buf,
                                                      &encoded_len)))
            fail("encode failed");
        return {{"bytes", to_hex(buf, static_cast<size_t>(encoded_len))},
                {"length", static_cast<uint64_t>(encoded_len)}};
    }

    if (action == "loaded") {
        json out = loaded_image_json();
        if (!out.value("ready", false)) {
            out["hint"] = "open a binary in the Disassembly view, attach a target and "
                          "use target.modules to find one, or pass an explicit 'path'";
        }
        out["target"] = attached_target_json();
        return out;
    }

    if (action == "symbols") {
        auto snaps = ds::symbols_snapshot();
        std::sort(snaps.begin(), snaps.end());
        json arr = json::array();
        for (const auto& [va, name] : snaps)
            arr.push_back({{"va", va}, {"name", name}});
        return {{"symbols", arr}, {"count", arr.size()}};
    }

    if (action == "symbol_set") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("name") || !args.at("name").is_string())
            fail("missing 'name' string (empty clears)");
        const std::string name = args.at("name").get<std::string>();
        if (!ds::has_binary()) fail("no image loaded in reverse-slop");
        ds::set_symbol(addr, name);   // saved, the ui sees it instantly
        return {{"va", addr}, {"name", name}, {"cleared", name.empty()}};
    }

    if (action == "load") {
        // same as opening a file in the ui, kicks off the background analysis
        if (!args.contains("path") || !args.at("path").is_string())
            fail("missing path");
        const std::string path = args.at("path").get<std::string>();
        if (!ds::load_file(path)) fail("failed to load: " + path);
        json out                = loaded_image_json();
        out["ok"]               = true;
        out["hype_wait_hint"]   = "poll disasm.loaded -> hype.ready for the "
                                  "decompiler/analyzer DB";
        return out;
    }
    if (action == "unload") {
        ds::unload();
        return {{"ok", true}, {"ready", false}};
    }

    if (action == "analyze_stop") {
        // cooperative cancel, the analyzer checks between phases so this returns fast
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded (see disasm.loaded)");
        if (!bin.hype)  fail("hyperion engine unavailable for this image");
        if (bin.hype->ready())
            return {{"stopped", false}, {"ready", true},
                    {"note", "analysis already complete"}};
        const std::string herr = bin.hype->error();
        if (!herr.empty())
            return {{"stopped", false}, {"ready", false},
                    {"reason", herr},
                    {"note", "analysis is not running, " + herr +
                     " (re-run disasm.load to restart)"}};
        const float at = bin.hype->progress();
        bin.hype->stop();
        return {{"stopped", true}, {"progress_at_stop", at},
                {"note", "analysis cancelled, decompiler/analyzer actions "
                 "report not-ready; re-run disasm.load to restart analysis"}};
    }

    // static actions over an image file

    // explicit path parses into the private cache, otherwise the app session
    const bool have_path = args.contains("path") && args.at("path").is_string();

    // keep the session pinned while we poke the indexes
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*       pe      = nullptr;
    const std::vector<uint8_t>*     file    = nullptr;
    disasm::function_index_t*       fidx    = nullptr;
    disasm::xref_index_t*           xidx    = nullptr;
    bool*                           fidx_ok = nullptr;   // null => always built
    bool*                           xidx_ok = nullptr;
    const std::unordered_map<uint64_t, std::string>* syms = nullptr;
    uint64_t default_base = 0;
    std::string                     img_name, img_path;

    if (have_path) {
        auto& img = load_image(args.at("path").get<std::string>());
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        fidx_ok = &img.fidx_ok; xidx_ok = &img.xidx_ok;
        img_path = img.path;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
        default_base = img.pe.image_base;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready) fail("no image: pass 'path' or load a binary in reverse-slop "
                             "(see disasm.loaded)");
        // patches dirty the indexes so rebuild them lazily
        if (bin.indexes_dirty &&
            (action == "functions" || action == "xrefs" || action == "strings")) {
            if (!bin.eng.init()) fail("zydis engine init failed");
            bin.fns.build(bin.pe, bin.file, bin.eng, bin.base);
            bin.xrefs.build(bin.pe, bin.file, bin.eng, bin.base);
            bin.strings.clear();
            for (const auto& sec : bin.pe.sections) {
                if (sec.is_executable() || sec.raw_size == 0) continue;
                auto soff = bin.pe.rva_to_offset(sec.rva);
                if (!soff || static_cast<size_t>(sec.raw_offset) + sec.raw_size > bin.file.size())
                    continue;
                auto part = disasm::extract_strings(
                    bin.file.data() + sec.raw_offset, sec.raw_size,
                    bin.base + sec.rva, 4, 200'000);
                bin.strings.insert(bin.strings.end(),
                                   std::make_move_iterator(part.begin()),
                                   std::make_move_iterator(part.end()));
            }
            bin.indexes_dirty = false;

            // reanalyze the patched bytes in the background
            if (bin.hype) bin.hype->reanalyze(bin.file);
        }
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        syms = &bin.symbols;
        img_name = bin.name; img_path = bin.path;
        default_base = bin.base;   // VA base the whole session was built with
    }

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : default_base;

    if (action == "pe") {
        json secs = json::array();
        for (const auto& sec : pe->sections) {
            // raw characteristics too so it matches the packer output
            secs.push_back({{"name", sec.name}, {"rva", sec.rva},
                            {"vsize", sec.virtual_size}, {"raw_size", sec.raw_size},
                            {"exec", sec.is_executable()},
                            {"writable", (sec.characteristics & 0x80000000u) != 0},
                            {"characteristics", sec.characteristics}});
        }
        json imps = json::array();
        for (const auto& dll : pe->imports) {
            json fns = json::array();
            for (const auto& fn : dll.functions) fns.push_back(fn.name);
            imps.push_back({{"dll", dll.dll}, {"functions", fns}});
        }
        json exps = json::array();
        for (const auto& e : pe->exports)
            exps.push_back({{"name", e.name}, {"rva", e.rva}, {"ordinal", e.ordinal}});
        return {{"ok", true}, {"image", img_name}, {"pe32plus", pe->pe32plus},
                {"image_base", pe->image_base}, {"entry_rva", pe->entry_rva},
                {"size_of_image", pe->size_of_image},
                {"sections", secs}, {"imports", imps}, {"exports", exps}};
    }

    if (action == "functions") {
        if (fidx_ok && !*fidx_ok) {
            if (!fidx->build(*pe, *file, eng, base)) fail("function index build failed");
            *fidx_ok = true;
        }
        const size_t limit = std::min<size_t>(args.value("limit", 1000u), 10000u);
        json arr = json::array();
        const auto& fns = fidx->functions();

        // hyperion adds names and cfg stats on the same rows
        const hype::AnalysisDB* hdb = nullptr;
        if (!have_path) {
            auto& bin = ds::get();
            if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
        }

        for (size_t i = 0; i < fns.size() && i < limit; ++i) {
            json o = {{"va", fns[i].va}, {"size", fns[i].size}};
            if (syms) {
                const auto it = syms->find(fns[i].va);
                if (it != syms->end()) o["symbol"] = it->second;
            }
            if (hdb) {
                const auto fit = hdb->funcs.find(fns[i].va);
                if (fit != hdb->funcs.end()) {
                    const auto& hf = fit->second;
                    if (!o.contains("symbol")) {
                        const auto nit = hdb->names.find(fns[i].va);
                        if (nit != hdb->names.end()) o["name"] = nit->second;
                    }
                    o["blocks"]    = hf.blocks.size();
                    o["callconv"]  = callconv_name(hf.callconv);
                    if (!hf.loops.empty()) o["loops"] = hf.loops.size();
                    if (hf.noreturn) o["noreturn"] = true;
                }
            }
            arr.push_back(std::move(o));
        }
        json out = {{"image", img_name}, {"functions", arr},
                    {"total", fns.size()},
                    {"stats", {{"seeds", fidx->stats().seeds},
                               {"recursive_descent", fidx->stats().rd_functions},
                               {"heuristic", fidx->stats().heuristic_fns}}}};
        if (hdb) {
            out["hype"] = {{"engine", "hyperion"},
                           {"functions", hdb->funcs.size()},
                           {"rtti_classes", [&] {
                               auto& bin = ds::get();
                               return bin.hype ? bin.hype->rtti().classes().size() : 0;
                           }()}};
        }
        return out;
    }

    if (action == "xrefs") {
        const uint64_t addr = parse_addr(args, "addr");

        // hyperion xrefs are richer so use them when we can
        if (!have_path) {
            auto& bin = ds::get();
            if (bin.hype && bin.hype->ready()) {
                const auto& db = bin.hype->db();
                const auto  it = db.xrefs_to.find(addr);
                json arr = json::array();
                if (it != db.xrefs_to.end()) {
                    // a call emits two records for one instruction, keep the strongest kind
                    auto kind_rank = [](hype::XrefType t) {
                        switch (t) {
                        case hype::XrefType::CodeCall:  return 5;
                        case hype::XrefType::CodeJump:  return 4;
                        case hype::XrefType::DataWrite: return 3;
                        case hype::XrefType::DataRead:  return 2;
                        default:                        return 1;
                        }
                    };
                    std::map<uint64_t, std::pair<int, const char*>> best;
                    for (const auto& x : it->second) {
                        const char* k = xref_kind_name_hype(x.type);
                        const int   r = kind_rank(x.type);
                        const auto  b = best.find(x.from);
                        if (b == best.end() || b->second.first < r)
                            best[x.from] = {r, k};
                    }
                    for (const auto& [from, p] : best)
                        arr.push_back({{"from", from}, {"kind", p.second}});
                }
                return {{"image", img_name}, {"engine", "hyperion"},
                        {"refs_to", arr}, {"count", arr.size()}};
            }
        }

        if (xidx_ok && !*xidx_ok) {
            if (!xidx->build(*pe, *file, eng, base)) fail("xref index build failed");
            *xidx_ok = true;
        }
        json arr = json::array();
        for (const auto& r : xidx->refs_to(addr))
            arr.push_back({{"from", r.from}, {"kind", xref_kind_name(r.kind)}});
        return {{"image", img_name}, {"refs_to", arr}, {"count", arr.size()}};
    }

    if (action == "strings") {
        const size_t min_chars = std::min<size_t>(args.value("min_chars", 4u), 256u);
        const size_t limit = std::min<size_t>(args.value("limit", 1000u), 10000u);
        // exec sections are garbage on packed code so theyre skipped unless asked for
        const bool include_exec = args.value("include_exec", false);
        json arr = json::array();
        disasm::string_stats_t stats{};
        for (const auto& sec : pe->sections) {
            if (sec.virtual_size == 0) continue;
            if (!include_exec && sec.is_executable()) continue;
            auto soff = pe->rva_to_offset(sec.rva);
            if (!soff) continue;
            const size_t len = std::min<uint32_t>(sec.raw_size, sec.virtual_size);
            if (*soff + len > file->size()) continue;
            auto hits = disasm::extract_strings(file->data() + *soff, len,
                                                base + sec.rva, min_chars, limit, &stats);
            for (const auto& h : hits) {
                if (arr.size() >= limit) break;
                arr.push_back({{"va", static_cast<uint64_t>(h.va)},
                               {"text", h.text}, {"utf16", h.utf16}});
            }
            if (arr.size() >= limit) break;
        }
        return {{"image", img_name}, {"strings", arr},
                {"total_scanned", stats.scanned}, {"truncated", stats.truncated}};
    }

    // hyperion backed actions, shared session only
    // these read the analyzer db which only exists for the app loaded image

    if (action == "blocks" || action == "globals" || action == "vtables") {
        if (have_path)
            fail(action + " requires the app-loaded image (no 'path' support, "
                 "load the binary in reverse-slop first)");
        // the lock above still guards the session
        auto& bin = ds::get();
        if (!bin.hype) fail("hyperion engine unavailable for this image");
        if (!bin.hype->ready()) {
            const std::string herr = bin.hype->error();
            if (!herr.empty())
                fail("hyperion analysis not running, " + herr +
                     " (re-run disasm.load to restart)");
            fail("hyperion analysis in progress (" +
                 std::to_string(static_cast<int>(bin.hype->progress() * 100)) +
                 "%), retry shortly");
        }
        const auto& db = bin.hype->db();

        if (action == "blocks") {
            const uint64_t addr = parse_addr(args, "addr");
            const hype::Function* f = bin.hype->function_at(addr);
            if (!f) fail("no hyperion function contains address " + hex64(addr));
            json arr = json::array();
            for (const auto& [start, bb] : f->blocks) {
                json succs = json::array(), preds = json::array();
                for (auto s : bb.succs) succs.push_back(s);
                for (auto p : bb.preds) preds.push_back(p);
                arr.push_back({{"start", start}, {"end", bb.end},
                               {"size", bb.end - start},
                               {"insn_count", bb.insns.size()},
                               {"succs", succs}, {"preds", preds}});
            }
            json loops = json::array();
            for (const auto& lp : f->loops)
                loops.push_back({{"header", lp.header},
                                 {"back_edge_src", lp.back_edge_src}});
            return {{"ok", true}, {"entry", f->entry},
                    {"name", bin.hype->db().names.count(f->entry)
                                  ? bin.hype->db().names.at(f->entry)
                                  : "sub_" + hex64(f->entry)},
                    {"blocks", arr}, {"count", arr.size()},
                    {"loops", loops}};
        }

        if (action == "vtables") {
            json arr = json::array();
            for (const auto& vt : db.vtables) {
                json entries = json::array();
                for (auto e : vt.entries) entries.push_back(e);
                arr.push_back({{"va", vt.addr}, {"entries", entries},
                               {"count", vt.entries.size()}});
            }
            return {{"ok", true}, {"vtables", arr}, {"count", arr.size()}};
        }

        // globals
        json arr = json::array();
        for (const auto& [va, g] : db.globals)
            arr.push_back({{"va", va}, {"size", g.size}, {"name", g.name}});
        return {{"ok", true}, {"globals", arr}, {"count", arr.size()}};
    }

    fail("disasm: unknown action (assemble|disassemble|loaded|pe|functions|"
         "xrefs|strings|symbols|symbol_set|blocks|globals|vtables|load|unload|"
         "analyze_stop)");
}

// tool: debugger

json tool_debugger(const json& args) {
    const std::string action = require_action(args);
    if (!g_dbg) g_dbg = std::make_unique<debugger::debugger_t>();
    auto& dbg = *g_dbg;

    if (action == "attach") {
        const uint64_t pid = parse_addr(args, "pid");
        if (dbg.state() != debugger::dbg_state_t::idle) {
            dbg.detach();   // never re-attach over a live loop
        }
        if (!dbg.attach(static_cast<uint32_t>(pid))) fail("debugger attach failed");
        return {{"attached", true}, {"pid", pid},
                {"state", debugger_state_name(dbg.state())},
                {"mode", debugger::dbg_mode_name(dbg.mode())}};
    }
    if (action == "detach") {
        dbg.detach();   // DR slots die with the session (debugger clears them)
        return {{"attached", false}};
    }
    if (action == "status") {
        json out = {{"state", debugger_state_name(dbg.state())},
                    {"pid", dbg.pid()},
                    {"mode", debugger::dbg_mode_name(dbg.mode())},
                    {"veh_page", dbg.veh_page()},
                    {"backend", runtime::active_badge()},
                    {"stealth_peb_spoof", infra::settings::stealth_peb_spoof()},
                    {"stealth_kernel_debug", infra::settings::stealth_kernel_debug()}};
        if (auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active())) {
            out["hwbp_supported"] = k->hwbp_supported();
        } else {
            out["hwbp_supported"] = false;
        }
        json bps = json::array();
        json hws = json::array();
        for (const auto& bp : dbg.breakpoints()) {
            const json rec = {{"addr", static_cast<uint64_t>(bp.addr)},
                              {"enabled", bp.enabled}, {"hardware", bp.hardware},
                              {"hits", bp.hits}, {"slot", bp.hw_slot},
                              {"type", bp.hw_type}, {"len", bp.hw_len}};
            bps.push_back(rec);
            if (bp.hardware) hws.push_back(rec);
        }
        out["breakpoints"] = bps;
        out["hw_breakpoints"] = hws;
        return out;
    }
    if (action == "suspend_all") {
        // freeze every thread through the driver, kernel backend only
        if (dbg.state() == debugger::dbg_state_t::idle)
            fail("debugger not attached");
        if (!dbg.suspend_all())
            fail("suspend_all failed (kernel driver required)");
        return {{"suspended", true}, {"pid", dbg.pid()}};
    }
    if (action == "resume_all") {
        if (dbg.state() == debugger::dbg_state_t::idle)
            fail("debugger not attached");
        if (!dbg.resume_all())
            fail("resume_all failed (kernel driver required)");
        return {{"resumed", true}, {"pid", dbg.pid()}};
    }
    if (action == "bp_set") {
        const uint64_t addr = parse_addr(args, "addr");
        const bool hw = args.value("hw", false);
        if (hw) {
            // the debugger owns the dr slots so theres no split brain with the engine
            if (dbg.state() == debugger::dbg_state_t::idle)
                fail("hardware breakpoints require the debugger attached first");
            const uint32_t type = static_cast<uint32_t>(args.value("type", 0u));
            uint32_t len = static_cast<uint32_t>(args.value("len", 1u));
            if (type != 0 && len > 4) len = 4;   // exec is fixed length, write caps at 4 on some cpus
            if (len != 1 && len != 2 && len != 4 && len != 8)
                fail("hw bp len must be 1, 2, 4 or 8");

            if (!dbg.set_hw_breakpoint(static_cast<uintptr_t>(addr), len, type))
                fail("hw bp programming failed (kernel driver + free DR slot required)");

            // report which slot it landed on
            int slot = -1;
            for (const auto& bp : dbg.breakpoints()) {
                if (bp.addr == static_cast<uintptr_t>(addr)) {
                    slot = bp.hw_slot;
                    break;
                }
            }
            return {{"set", true}, {"addr", addr}, {"hw", true},
                    {"slot", slot}, {"type", type}, {"len", len}};
        }
        const bool ok = dbg.set_sw_breakpoint(static_cast<uintptr_t>(addr));
        if (!ok) fail("bp_set failed");

        // tracepoint and conditional extras, software breakpoints only
        bool configured = false;
        if ((args.contains("condition") && args.at("condition").is_string() &&
             !args.at("condition").get<std::string>().empty()) ||
            args.value("auto_continue", false) || args.value("one_shot", false) ||
            (args.contains("log") && args.at("log").is_string())) {
            configured = dbg.configure_breakpoint(
                static_cast<uintptr_t>(addr),
                args.value("condition", std::string{}),
                args.value("log", std::string{}),
                args.value("auto_continue", false),
                args.value("one_shot", false));
            if (!configured) fail("bp configure failed");
        }
        return {{"set", true}, {"addr", addr}, {"hw", false},
                {"configured", configured}};
    }
    if (action == "callstack") {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached");
        uint32_t tid = 0;
        auto ctx = dbg.paused_context(&tid);
        if (!ctx) fail("debugger not paused (bp hit or wait_halt first)");

        auto& eng = shared_engine();
        if (!eng.ok() && !eng.init()) fail("zydis engine init failed");

        struct sess_reader final : unwind::reader_t {
            runtime::session_t& s;
            explicit sess_reader(runtime::session_t& s_) : s(s_) {}
            bool read(uint64_t addr, void* dst, size_t len) override {
                auto io = s.read(static_cast<uintptr_t>(addr), dst, len);
                return io.ok && io.bytes == len;
            }
        } rdr{*s};

        const size_t max_frames =
            std::min<size_t>(args.value("max_frames", 32u), 256u);
        auto frames = unwind::walk_stack(eng, rdr, ctx->rip, ctx->rsp,
                                         ctx->rbp, max_frames);
        json arr = json::array();
        for (const auto& f : frames)
            arr.push_back({{"ret_addr", f.ret_addr},
                           {"frame_ptr", f.frame_ptr},
                           {"snippet", f.snippet},
                           {"scanned", f.scanned}});
        return {{"tid", tid}, {"frames", arr}, {"count", arr.size()}};
    }
    if (action == "seh") {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached");
        // teb base through the driver in kernel mode, else the nt call
        uint32_t tid = 0;
        auto ctx = dbg.paused_context(&tid);
        if (!ctx) fail("debugger not paused (bp hit or wait_halt first)");

        uint64_t teb = 0;
        bool teb_ok = false;
        if (auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
            k && k->device()) {
            voyager::detail::thread_query_information_request tqi{};
            if (k->device()->query_thread_basic_information(tid, tqi) &&
                tqi.teb_base != 0) {
                teb = tqi.teb_base;
                teb_ok = true;
            }
        }
        if (!teb_ok) {
            using NtQIT_t = LONG(WINAPI*)(HANDLE, ULONG, void*, ULONG, ULONG*);
            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            auto ntqit = ntdll
                ? reinterpret_cast<NtQIT_t>(GetProcAddress(ntdll, "NtQueryInformationThread"))
                : nullptr;
            HANDLE th = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
            if (!ntqit || !th) {
                if (th) CloseHandle(th);
                fail("cannot query TEB for tid " + std::to_string(tid));
            }
#pragma pack(push, 1)
            struct tbi_t { void* exit_status; void* teb; void* client_id; };
#pragma pack(pop)
            tbi_t tbi{};
            LONG st = ntqit(th, 0 /*ThreadBasicInformation*/, &tbi, sizeof(tbi), nullptr);
            CloseHandle(th);
            if (st < 0) fail("NtQueryInformationThread failed");
            teb = reinterpret_cast<uint64_t>(tbi.teb);
        }

        struct sess_reader final : unwind::reader_t {
            runtime::session_t& s;
            explicit sess_reader(runtime::session_t& s_) : s(s_) {}
            bool read(uint64_t addr, void* dst, size_t len) override {
                auto io = s.read(static_cast<uintptr_t>(addr), dst, len);
                return io.ok && io.bytes == len;
            }
        } rdr{*s};

        auto r = unwind::seh_chain(rdr, teb);
        json chain = json::array();
        for (const auto& e : r.chain)
            chain.push_back({{"handler", e.handler}, {"frame", e.frame}});
        return {{"teb", teb}, {"chain", chain}, {"count", chain.size()},
                {"empty_proven", r.chain_empty_proven}, {"note", r.note}};
    }
    if (action == "set_register") {
        if (!args.contains("name") || !args.contains("value"))
            fail("missing name/value");
        const std::string name = args.at("name").get<std::string>();
        const uint64_t value = parse_addr(args, "value");
        if (!dbg.set_register(name, value))
            fail("set_register failed (paused? valid register name?)");
        return {{"set", true}, {"register", name}, {"value", value}};
    }
    if (action == "watchpoint_set") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = args.contains("len") ? parse_addr(args, "len") : 8;
        if (len == 0) fail("bad watchpoint len");
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k) fail("page-guard watchpoints require the kernel driver");
        if (!dbg.set_watchpoint(static_cast<uintptr_t>(addr),
                                static_cast<size_t>(len), true))
            fail("watchpoint arm failed (region already watched?)");
        return {{"armed", true}, {"addr", addr}, {"len", len}};
    }
    if (action == "watchpoint_clear") {
        if (!dbg.clear_watchpoint(static_cast<uintptr_t>(parse_addr(args, "addr"))))
            fail("unknown watchpoint address");
        return {{"cleared", true}};
    }
    if (action == "watchpoints") {
        json arr = json::array();
        for (const auto& w : dbg.watchpoints())
            arr.push_back({{"addr", w.addr}, {"len", w.len},
                           {"orig_prot", w.orig_prot}, {"hits", w.hits}});
        return {{"watchpoints", arr}, {"count", arr.size()}};
    }
    if (action == "trace_run") {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached");
        if (dbg.state() != debugger::dbg_state_t::paused)
            fail("debugger not paused (trace_run steps from a pause)");
        const size_t count = std::min<size_t>(args.value("count", 16u), 256u);

        auto& eng = shared_engine();
        if (!eng.ok() && !eng.init()) fail("zydis engine init failed");

        json arr = json::array();
        for (size_t i = 0; i < count; ++i) {
            dbg.step_into();
            bool halted = false;
            for (int spin = 0; spin < 400; ++spin) {           // ~6 s cap/step
                if (dbg.state() == debugger::dbg_state_t::paused) { halted = true; break; }
                std::this_thread::sleep_for(std::chrono::milliseconds(15));
            }
            if (!halted) break;

            uint32_t tid = 0;
            auto ctx = dbg.paused_context(&tid);
            if (!ctx) break;
            json rec = {{"index", i}, {"rip", ctx->rip}};
            uint8_t buf[16]{};
            auto io = s->read(static_cast<uintptr_t>(ctx->rip), buf, sizeof(buf));
            if (io.ok) {
                if (auto in = eng.decode(ctx->rip, buf, sizeof(buf)))
                    rec["text"] = in->text;
            }
            arr.push_back(std::move(rec));
        }
        return {{"trace", arr}, {"steps", arr.size()},
                {"state", debugger_state_name(dbg.state())}};
    }
    if (action == "bp_clear") {
        const uint64_t addr = parse_addr(args, "addr");
        const bool was_hw = std::any_of(
            dbg.breakpoints().begin(), dbg.breakpoints().end(),
            [addr](const debugger::breakpoint_t& b) {
                return b.addr == static_cast<uintptr_t>(addr) && b.hardware;
            });
        if (!dbg.clear_breakpoint(static_cast<uintptr_t>(addr))) fail("bp_clear failed");
        return {{"cleared", true}, {"addr", addr}, {"hw", was_hw}};
    }
    if (action == "continue") { dbg.go();       return {{"state", debugger_state_name(dbg.state())}}; }
    if (action == "step_into") { dbg.step_into(); return {{"state", debugger_state_name(dbg.state())}}; }
    if (action == "step_over") { dbg.step_over(); return {{"state", debugger_state_name(dbg.state())}}; }
    if (action == "step_out") { dbg.step_out();  return {{"state", debugger_state_name(dbg.state())}}; }

    if (action == "wait_halt") {
        const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
        while (dbg.state() != debugger::dbg_state_t::paused) {
            if (std::chrono::steady_clock::now() > deadline)
                return {{"halted", false}, {"state", debugger_state_name(dbg.state())}};
            std::this_thread::sleep_for(std::chrono::milliseconds(15));
        }
        return {{"halted", true}, {"state", "paused"}};
    }

    if (action == "regs") {
        uint32_t tid = 0;
        auto ctx = dbg.paused_context(&tid);
        if (!ctx) fail("debugger not paused (bp hit or wait_halt first)");
        json o = {{"tid", tid}, {"rip", ctx->rip}, {"rsp", ctx->rsp}, {"rbp", ctx->rbp},
                  {"rax", ctx->rax}, {"rbx", ctx->rbx}, {"rcx", ctx->rcx}, {"rdx", ctx->rdx},
                  {"rsi", ctx->rsi}, {"rdi", ctx->rdi},
                  {"r8", ctx->r8}, {"r9", ctx->r9}, {"r10", ctx->r10}, {"r11", ctx->r11},
                  {"r12", ctx->r12}, {"r13", ctx->r13}, {"r14", ctx->r14}, {"r15", ctx->r15},
                  {"flags", ctx->flags}};
        return o;
    }

    if (action == "events") {
        json arr = json::array();
        for (const auto& e : dbg.events_snapshot(64)) {
            arr.push_back({{"kind", e.kind}, {"tid", e.tid},
                           {"address", static_cast<uint64_t>(e.address)},
                           {"exc_code", e.exc_code}, {"text", e.text}});
        }
        return {{"events", arr}, {"count", arr.size()}};
    }

    fail("debugger: unknown action (attach|detach|status|suspend_all|"
         "resume_all|bp_set|bp_clear|continue|step_into|step_over|step_out|"
         "wait_halt|regs|events|callstack|seh|set_register|watchpoint_set|"
         "watchpoint_clear|watchpoints|trace_run)");
}

// tool: driver

// resolves a kernel export by walking its export table through raw kernel reads
std::optional<uint64_t> resolve_kernel_export(
    voyager::device_t& dev, uint64_t module_base, const std::string& name) {
    if (!module_base || name.empty()) return std::nullopt;
    auto kread = [&](uint64_t va, void* buf, size_t len) {
        return dev.read_kernel_raw(va, buf, len) == len;
    };
    uint8_t dos[64] = {};
    if (!kread(module_base, dos, sizeof(dos)) ||
        std::memcmp(dos, "MZ", 2) != 0)
        return std::nullopt;
    uint32_t pe_off = 0;
    std::memcpy(&pe_off, dos + 0x3C, 4);
    if (pe_off > 0x1000) return std::nullopt;
    uint8_t pe[0x200] = {};
    if (!kread(module_base + pe_off, pe, sizeof(pe)) ||
        std::memcmp(pe, "PE\0\0", 4) != 0)
        return std::nullopt;
    uint16_t opt_magic = 0;
    std::memcpy(&opt_magic, pe + 0x18, 2);
    const size_t dir_off = opt_magic == 0x020B ? 0x18 + 0x70   // PE32+
                                                  : 0x18 + 0x60; // PE32
    uint32_t export_rva = 0;
    std::memcpy(&export_rva, pe + dir_off, 4);
    if (!export_rva) return std::nullopt;
    uint8_t exp_dir[40] = {};
    if (!kread(module_base + export_rva, exp_dir, sizeof(exp_dir)))
        return std::nullopt;
    uint32_t num_names = 0, funcs_rva = 0, names_rva = 0, ords_rva = 0;
    std::memcpy(&num_names, exp_dir + 24, 4);
    std::memcpy(&funcs_rva, exp_dir + 28, 4);
    std::memcpy(&names_rva, exp_dir + 32, 4);
    std::memcpy(&ords_rva,  exp_dir + 36, 4);
    if (!num_names) return std::nullopt;
    // names are sorted so binary search works
    uint32_t lo = 0, hi = num_names - 1;
    while (lo <= hi && hi < num_names) {
        const uint32_t mid = lo + (hi - lo) / 2;
        uint32_t name_rva = 0;
        if (!kread(module_base + names_rva + uint64_t(mid) * 4,
                   &name_rva, 4))
            return std::nullopt;
        char candidate[128] = {};
        if (!kread(module_base + name_rva, candidate, sizeof(candidate) - 1))
            return std::nullopt;
        const int cmp = strcmp(candidate, name.c_str());
        if (cmp == 0) {
            uint16_t ord = 0;
            if (!kread(module_base + ords_rva + uint64_t(mid) * 2,
                       &ord, 2))
                return std::nullopt;
            uint32_t fn_rva = 0;
            if (!kread(module_base + funcs_rva + uint64_t(ord) * 4,
                       &fn_rva, 4))
                return std::nullopt;
            if (!fn_rva) return std::nullopt;
            return module_base + fn_rva;
        }
        if (cmp < 0) {
            if (mid == hi) break;
            lo = mid + 1;
        } else {
            if (mid == lo) break;
            hi = mid - 1;
        }
    }
    return std::nullopt;
}

// point the kernel device at a pid for cross process reads
bool ensure_context(voyager::device_t& dev, uint32_t pid) {
    if (!pid) return false;
    if (dev.get_process_id() != pid) dev.set_process_id(pid);
    if (dev.get_dtb() == 0) {
        const uint64_t dtb = dev.solve_dtb_for_pid(pid);
        if (dtb == 0) return false;
        dev.set_dtb(dtb);
    }
    return true;
}

const char* backend_pref_name(runtime::backend_pref_t p) {
    switch (p) {
    case runtime::backend_pref_t::auto_detect: return "auto";
    case runtime::backend_pref_t::force_user:  return "user";
    case runtime::backend_pref_t::force_kernel: return "kernel";
    }
    return "auto";
}

json tool_driver(const json& args) {
    const std::string action = require_action(args);
    if (action == "status") {
        json out;
        out["kernel_active"] = runtime::active_kind() == runtime::backend_kind_t::kernel;
        if (auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active())) {
            out["hwbp_supported"] = k->hwbp_supported();
        } else {
            out["hwbp_supported"] = false;
        }
        out["device"] = "\\\\.\\slopdrvr";
        out["preference"] = backend_pref_name(runtime::current_preference());
        out["load_hint"] = "slop_mapper.exe load build\\driver\\slopdrvr.sys  (admin; closes of reverse-slop unload the driver cleanly)";
        return out;
    }

    if (action == "backend") {
        // get or set the backend pref, refuse while a session is live since switching tears it down
        const std::string pref = args.value("pref", std::string{});
        if (!pref.empty()) {
            if (g_dbg && g_dbg->state() != debugger::dbg_state_t::idle)
                fail("detach the debugger before switching backends");
            if (auto s = process::active_session(); s && s->valid())
                fail("detach the target (target.detach) before switching backends");

            runtime::backend_pref_t p;
            if (pref == "auto")        p = runtime::backend_pref_t::auto_detect;
            else if (pref == "kernel") p = runtime::backend_pref_t::force_kernel;
            else if (pref == "user")   p = runtime::backend_pref_t::force_user;
            else fail("pref must be 'auto', 'kernel' or 'user'");
            runtime::set_backend_preference(p);
        }
        return {{"preference", backend_pref_name(runtime::current_preference())},
                {"active", runtime::active_badge()},
                {"kernel_active",
                 runtime::active_kind() == runtime::backend_kind_t::kernel}};
    }

    // kernel domain actions

    if (action == "kernel_modules") {
        std::string err;
        auto mods = runtime::kernel_svc::enumerate_modules(&err);
        if (!err.empty()) fail(err);
        json arr = json::array();
        for (const auto& m : mods)
            arr.push_back({{"name", m.name}, {"base", m.base},
                           {"size", m.size}});
        return {{"modules", arr}, {"count", arr.size()}};
    }

    if (action == "dump_driver") {
        if (!args.contains("path")) fail("missing path");
        uint64_t base = args.contains("base") ? parse_addr(args, "base") : 0;
        uint32_t size = static_cast<uint32_t>(
            args.value("size", 0));
        // resolve by name when no base is given
        if (!base || !size) {
            if (!args.contains("name"))
                fail("provide 'name' or both 'base' and 'size'");
            std::string err;
            auto mods = runtime::kernel_svc::enumerate_modules(&err);
            if (!err.empty()) fail(err);
            const std::string want = args.at("name").get<std::string>();
            bool found = false;
            for (const auto& m : mods) {
                if (_stricmp(m.name.c_str(), want.c_str()) == 0 ||
                    _stricmp((m.name + ".sys").c_str(), want.c_str()) == 0) {
                    base = m.base; size = m.size; found = true; break;
                }
            }
            if (!found) fail("no loaded driver named '" + want + "'");
        }
        auto err = runtime::kernel_svc::dump_module(
            base, size, args.at("path").get<std::string>());
        if (!err.empty()) fail(err);
        return {{"dumped", true}, {"path", args.at("path")},
                {"base", base}, {"size", size}};
    }

    if (action == "kernel_read") {
        const uint64_t addr = parse_addr(args, "addr");
        uint64_t len = args.contains("len") ? parse_addr(args, "len") : 64;
        if (len == 0 || len > (1ull << 20)) fail("bad len");
        std::vector<uint8_t> bytes;
        auto err = runtime::kernel_svc::kernel_read(
            addr, static_cast<size_t>(len), &bytes);
        if (!err.empty()) fail(err);
        return {{"addr", addr}, {"bytes", bytes.size()},
                {"hex", to_hex(bytes.data(), bytes.size())}};
    }
    if (action == "kernel_write") {
        const uint64_t addr = parse_addr(args, "addr");
        if (!args.contains("hex")) fail("missing hex payload");
        auto bytes = hex_decode(args.at("hex").get<std::string>());
        if (bytes.empty()) fail("empty payload");
        auto err = runtime::kernel_svc::kernel_write(addr, bytes);
        if (!err.empty()) fail(err);
        return {{"written", bytes.size()}};
    }
    if (action == "kernel_search") {
        if (!args.contains("pattern") || !args.contains("begin") ||
            !args.contains("end"))
            fail("missing pattern/begin/end");
        auto pat = hex_decode(args.at("pattern").get<std::string>());
        if (pat.empty()) fail("empty pattern");
        auto hits = runtime::kernel_svc::kernel_search(
            parse_addr(args, "begin"), parse_addr(args, "end"), pat,
            std::min<size_t>(args.value("limit", 100u), 1000u));
        json arr = json::array();
        for (auto h : hits) arr.push_back(h);
        return {{"hits", arr}, {"count", arr.size()}};
    }

    if (action == "call") {
        if (!args.contains("addr")) fail("missing addr");
        const uint64_t addr = parse_addr(args, "addr");
        auto r = runtime::kernel_svc::call_function(
            addr,
            args.contains("a1") ? parse_addr(args, "a1") : 0,
            args.contains("a2") ? parse_addr(args, "a2") : 0,
            args.contains("a3") ? parse_addr(args, "a3") : 0,
            args.contains("a4") ? parse_addr(args, "a4") : 0);
        if (!r) fail("call failed (driver required)");
        return {{"returned", *r}};
    }

    if (action == "v2p") {
        auto pa = runtime::kernel_svc::virtual_to_physical(
            parse_addr(args, "addr"));
        if (!pa) fail("translation failed (driver required)");
        return {{"virtual", parse_addr(args, "addr")},
                {"physical", *pa}};
    }

    if (action == "ssdt") {
        auto s = runtime::kernel_svc::query_ssdt();
        if (!s.ok) fail(s.error);
        json arr = json::array();
        for (auto h : s.handlers) arr.push_back(h);
        return {{"lstar", s.lstar}, {"service_table", s.service_table},
                {"service_limit", s.service_limit}, {"handlers", arr},
                {"count", arr.size()}};
    }

    if (action == "peb") {
        auto p = runtime::kernel_svc::read_peb();
        if (!p.ok) fail(p.error);
        return {{"peb_address", p.peb_address}, {"image_base", p.image_base},
                {"ldr_address", p.ldr_address},
                {"process_heap", p.process_heap},
                {"being_debugged", p.being_debugged}};
    }

    if (action == "resolve_export") {
        if (!args.contains("module_base") || !args.contains("name"))
            fail("missing module_base/name");
        auto va = runtime::kernel_svc::resolve_export(
            parse_addr(args, "module_base"),
            args.at("name").get<std::string>());
        if (!va) fail("export not found");
        return {{"resolved", true}, {"va", *va}};
    }

    if (action == "windows") {
        auto wins = runtime::kernel_svc::enumerate_windows(
            static_cast<uint32_t>(args.value("pid", 0u)));
        json arr = json::array();
        for (const auto& w : wins) {
            arr.push_back({{"pid", w.pid}, {"title", w.title},
                           {"class", w.klass}});
        }
        return {{"windows", arr}, {"count", arr.size()}};
    }

    if (action == "find_references") {
        // scan for qwords equal to the value
        auto& s = need_session();
        if (!args.contains("value")) fail("missing value");
        const uint64_t needle = parse_addr(args, "value");
        uint64_t begin = args.contains("begin") ? parse_addr(args, "begin") : 0;
        uint64_t end   = args.contains("end") ? parse_addr(args, "end") : 0;
        if (!begin || !end) {
            auto ranges = committed_ranges(s);
            if (ranges.empty()) fail("no committed ranges");
            begin = ranges.front();
            end = ranges.back();
        }
        end = std::min<uint64_t>(end, begin + (256ull << 20));
        json hits = json::array();
        const size_t limit = std::min<size_t>(args.value("limit", 200u), 1000u);
        uint8_t pat[8];
        std::memcpy(pat, &needle, 8);

        infra::cancel_token_t tok;
        uint64_t cursor = begin;
        constexpr uint64_t kWindow = 0x100000;
        std::vector<uint8_t> buf;
        while (cursor < end && hits.size() < limit) {
            const size_t span = static_cast<size_t>(
                std::min<uint64_t>(kWindow, end - cursor));
            buf.resize(span);
            auto io = s.read(static_cast<uintptr_t>(cursor), buf.data(),
                             buf.size());
            if (!io.ok) { cursor += kWindow; continue; }
            for (size_t i = 0; i + 8 <= buf.size(); i += 4) {
                if (std::memcmp(buf.data() + i, pat, 8) == 0) {
                    hits.push_back(cursor + i);
                    if (hits.size() >= limit) break;
                }
            }
            cursor += kWindow;
        }
        return {{"value", needle}, {"references", hits},
                {"count", hits.size()}};
    }

    if (action == "heap_walk") {
        auto& s = need_session();
        auto heaps = process::list_heaps(s.pid());
        json arr = json::array();
        for (const auto& h : heaps)
            arr.push_back({{"base", h.base}, {"size", h.size},
                           {"flags", h.flags}});
        return {{"heaps", arr}, {"count", arr.size()}};
    }

    if (action == "heap_blocks") {
        auto& s = need_session();
        if (!args.contains("base")) fail("missing heap base");
        auto blocks = process::walk_heap_blocks(
            s.pid(), parse_addr(args, "base"), nullptr,
            std::min<size_t>(args.value("limit", 4096u), 100000u));
        json arr = json::array();
        for (const auto& b : blocks)
            arr.push_back({{"address", b.address}, {"size", b.size},
                           {"flags", b.flags}});
        return {{"blocks", arr}, {"count", arr.size()}};
    }

    // deferred actions

    if (action == "defer_call") {
        if (!args.contains("addr")) fail("missing addr");
        json params = {{"addr", parse_addr(args, "addr")},
                       {"a1", args.contains("a1") ? parse_addr(args, "a1") : 0},
                       {"a2", args.contains("a2") ? parse_addr(args, "a2") : 0}};
        auto id = infra::deferred_manager_t::get().submit("call",
                                                          params.dump());
        return {{"deferred", true}, {"id", id}};
    }
    if (action == "defer_list") {
        auto all = infra::deferred_manager_t::get().list();
        json arr = json::array();
        for (const auto& a : all)
            arr.push_back({{"id", a.id}, {"kind", a.kind},
                           {"status", a.status}, {"params", a.params_json}});
        return {{"actions", arr}, {"count", arr.size()}};
    }
    if (action == "defer_execute") {
        size_t ran = infra::deferred_manager_t::get().execute_pending(
            args.value("kind", std::string{}));
        return {{"executed", ran}};
    }
    if (action == "defer_results") {
        const uint64_t id = parse_addr(args, "id");
        auto a = infra::deferred_manager_t::get().get(id);
        if (!a) fail("unknown deferred id");
        return {{"id", a->id}, {"status", a->status}, {"result", a->result_json}};
    }
    if (action == "defer_cancel") {
        if (!infra::deferred_manager_t::get().cancel(
                parse_addr(args, "id")))
            fail("cannot cancel (unknown or already finished)");
        return {{"cancelled", true}};
    }

    // kernel symbols

    if (action == "symbols_load") {
        auto st = runtime::kernel_symbols::ensure_loaded();
        json out = {{"loaded", st.loaded}, {"pdb_path", st.pdb_path},
                    {"module_name", st.module_name}, {"ntos_base", st.ntos_base},
                    {"guid_age", st.guid_text}};
        if (!st.error.empty()) out["error"] = st.error;
        return out;
    }
    if (action == "symbols_lookup") {
        if (!args.contains("name")) fail("missing name");
        auto sym = runtime::kernel_symbols::lookup(
            args.at("name").get<std::string>());
        if (!sym) fail("symbol not found (load the PDB first?)");
        return {{"name", sym->name}, {"address", sym->address}};
    }
    if (action == "symbols_nearest") {
        if (!args.contains("addr")) fail("missing addr");
        int64_t disp = 0;
        auto sym = runtime::kernel_symbols::nearest(parse_addr(args, "addr"),
                                                    &disp);
        if (!sym) fail("no nearby symbol (load the PDB first?)");
        return {{"name", sym->name}, {"address", sym->address},
                {"offset_from_start", disp}};
    }

    if (action == "anti_debug_spoof") {
        // clear the debug flags in the targets peb through the driver
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        auto s = process::active_session();
        if (!k || !s || !s->valid()) fail("kernel driver + attached target required");
        uint32_t flags = 0;
        auto& dev = *k->device();
        if (!dev.is_connected()) fail("driver device not connected");
        // it works on the current process context
        dev.set_process_id(s->pid());
        if (!dev.spoof_debug_flags(&flags)) fail("spoof failed");
        return {{"spoofed", true}, {"flags", flags}};
    }
    if (action == "sandbox_protect" || action == "sandbox_unprotect") {
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        const uint32_t pid = static_cast<uint32_t>(parse_addr(args, "pid"));
        std::uint64_t denials = 0;
        bool ok = false;
        if (action == "sandbox_protect") {
            ok = dev.protect_sandbox_pid(pid,
                                         static_cast<uint32_t>(args.value("flags", 0u)),
                                         &denials);
        } else {
            ok = dev.unprotect_sandbox_pid(pid, &denials);
        }
        if (!ok) fail("sandbox op failed");
        return {{action == "sandbox_protect" ? "protected" : "unprotected", true},
                {"pid", pid}, {"deny_events", denials}};
    }

    if (action == "log_config") {
        // driver log level and size cap, level 1 is default and the file trims itself when full
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        voyager::device_t::log_config cfg{};
        const bool apply = args.contains("level") || args.contains("cap_mb");
        if (apply) {
            cfg.level = static_cast<uint32_t>(args.value("level", 1u));
            cfg.cap_mb = static_cast<uint32_t>(args.value("cap_mb", 64u));
            if (cfg.level > 4) fail("level must be 0..4");
            if (cfg.cap_mb < 1 || cfg.cap_mb > 512) fail("cap_mb must be 1..512");
        }
        if (!dev.log_config_op(cfg, apply)) fail("log config op failed");
        return {{"level", cfg.level}, {"cap_mb", cfg.cap_mb},
                {"applied", apply}};
    }

    if (action == "read_teb") {
        // teb base through the kernel then the whole thing read cross process
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        if (!args.contains("tid")) fail("missing tid");
        const uint32_t tid = static_cast<uint32_t>(parse_addr(args, "tid"));
        auto s = process::active_session();
        const uint32_t pid = args.contains("pid")
            ? static_cast<uint32_t>(parse_addr(args, "pid"))
            : (s && s->valid() ? s->pid() : 0u);
        if (!pid) fail("no target pid (attach first or pass pid)");
        if (!ensure_context(dev, pid))
            fail("kernel context unavailable for pid " + std::to_string(pid));
        voyager::detail::thread_query_information_request tqif{};
        if (!dev.query_thread_basic_information(tid, tqif) ||
            tqif.teb_base == 0)
            fail("TEB base unavailable for tid " + std::to_string(tid));
        const uint64_t teb = tqif.teb_base;
        constexpr size_t kTebReadSize = 0x1680;
        std::vector<uint8_t> buf(kTebReadSize, 0);
        if (dev.read_raw(teb, buf.data(), buf.size()) != kTebReadSize)
            fail("TEB read failed at 0x" + hex64(teb));
        auto u64 = [&buf](size_t off) {
            uint64_t v = 0;
            std::memcpy(&v, buf.data() + off, sizeof(v));
            return v;
        };
        auto u32 = [&buf](size_t off) {
            uint32_t v = 0;
            std::memcpy(&v, buf.data() + off, sizeof(v));
            return v;
        };
        json teb_json = {{"teb_address", teb}, {"tid", tid},
                         {"exception_list", u64(0x00)},
                         {"stack_base", u64(0x08)},
                         {"stack_limit", u64(0x10)},
                         {"self", u64(0x30)},
                         {"environment_pointer", u64(0x38)},
                         {"client_id_process", u64(0x40)},
                         {"client_id_thread", u64(0x48)},
                         {"tls_pointer", u64(0x58)},
                         {"peb_address", u64(0x60)},
                         {"last_error_value", u32(0x68)},
                         {"count_of_owned_critical_sections", u32(0x6C)},
                         {"deallocation_stack", u64(0x1478)}};
        const uint64_t stack_base = u64(0x08), stack_limit = u64(0x10);
        if (stack_base > stack_limit)
            teb_json["stack_size"] = stack_base - stack_limit;
        json tls_slots = json::array();
        for (size_t i = 0; i < 64; ++i) {
            const uint64_t slot = u64(0x1480 + i * 8);
            if (slot) tls_slots.push_back({{"index", i}, {"value", slot}});
        }
        teb_json["active_tls_slots"] = std::move(tls_slots);
        return teb_json;
    }

    if (action == "peb_modules") {
        // walk the peb loader lists so hidden modules show up
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        auto s = process::active_session();
        const uint32_t pid = args.contains("pid")
            ? static_cast<uint32_t>(parse_addr(args, "pid"))
            : (s && s->valid() ? s->pid() : 0u);
        if (!pid) fail("no target pid (attach first or pass pid)");
        if (!ensure_context(dev, pid))
            fail("kernel context unavailable for pid " + std::to_string(pid));
        voyager::device_t::peb_info peb{};
        if (!dev.read_peb(peb) || peb.ldr_address == 0)
            fail("failed to read PEB (LDR address null)");
        const std::string order = args.value("order", std::string("all"));
        const std::string filter = args.value("filter", std::string{});
        struct ldr_list_t { uint64_t head_off; const char* name; };
        std::vector<ldr_list_t> lists;
        if (order == "load" || order == "all")   lists.push_back({0x10, "InLoadOrder"});
        if (order == "memory" || order == "all") lists.push_back({0x20, "InMemoryOrder"});
        if (order == "init" || order == "all")   lists.push_back({0x30, "InInitializationOrder"});
        if (lists.empty()) fail("order must be all|load|memory|init");
        auto read_remote_utf16 = [&](uint64_t addr, uint16_t wlen) {
            std::string out;
            if (!addr || !wlen) return out;
            wlen = static_cast<uint16_t>(std::min<uint32_t>(wlen, 512));
            std::vector<uint8_t> raw(size_t(wlen) * 2, 0);
            if (dev.read_raw(addr, raw.data(), raw.size()) != raw.size())
                return out;
            int n = WideCharToMultiByte(CP_UTF8, 0,
                                        reinterpret_cast<LPCWCH>(raw.data()),
                                        wlen, nullptr, 0, nullptr, nullptr);
            if (n <= 0) return out;
            out.resize(size_t(n));
            WideCharToMultiByte(CP_UTF8, 0,
                                reinterpret_cast<LPCWCH>(raw.data()), wlen,
                                out.data(), n, nullptr, nullptr);
            return out;
        };
        json out;
        for (const auto& list : lists) {
            const uint64_t head = peb.ldr_address + list.head_off;
            uint64_t cur = dev.read<uint64_t>(head);
            json mods = json::array();
            int iter = 0;
            constexpr int kMaxIter = 1024;
            while (cur && cur != head && iter++ < kMaxIter) {
                const uint64_t entry =
                    list.head_off == 0x10 ? cur
                    : list.head_off == 0x20 ? cur - 0x10
                                            : cur - 0x20;
                const uint64_t base = dev.read<uint64_t>(entry + 0x30);
                const uint64_t entry_point = dev.read<uint64_t>(entry + 0x38);
                const uint32_t size = dev.read<uint32_t>(entry + 0x40);
                const std::string name = read_remote_utf16(
                    dev.read<uint64_t>(entry + 0x60),
                    static_cast<uint16_t>(dev.read<uint16_t>(entry + 0x58) / 2));
                const std::string path = read_remote_utf16(
                    dev.read<uint64_t>(entry + 0x50),
                    static_cast<uint16_t>(dev.read<uint16_t>(entry + 0x48) / 2));
                const uint32_t flags = dev.read<uint32_t>(entry + 0x68);
                const uint64_t next = dev.read<uint64_t>(cur);
                if (base == 0 && name.empty()) {
                    if (next == cur) break;
                    cur = next;
                    continue;
                }
                if (!filter.empty() &&
                    !icontains(name, filter) && !icontains(path, filter)) {
                    if (next == cur) break;
                    cur = next;
                    continue;
                }
                json m = {{"base", base}, {"entry_point", entry_point},
                          {"size", size}, {"name", name}, {"path", path},
                          {"flags", flags},
                          {"flag_details", {{"packed_redirected", (flags & 0x2) != 0},
                                            {"image_dll", (flags & 0x4) != 0},
                                            {"static_import", (flags & 0x20) != 0},
                                            {"load_in_progress", (flags & 0x1000) != 0},
                                            {"entry_processed", (flags & 0x4000) != 0},
                                            {"process_attach_called", (flags & 0x80000) != 0}}}};
                mods.push_back(std::move(m));
                if (next == cur) break;
                cur = next;
            }
            out[list.name] = {{"modules", std::move(mods)}};
        }
        return {{"ldr_address", peb.ldr_address}, {"lists", out}};
    }

    if (action == "integrity_checks") {
        // scan the big ntoskrnl exports for inline hooks and map them back to their drivers
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        if (dev.get_kernel_dtb() == 0) dev.solve_kernel_dtb();
        std::string err;
        auto mods = runtime::kernel_svc::enumerate_modules(&err);
        if (!err.empty()) fail(err);
        uint64_t ntos_base = 0;
        for (const auto& m : mods) {
            if (icontains(m.name, "ntoskrnl") || icontains(m.name, "ntkrnlmp")) {
                ntos_base = m.base;
                break;
            }
        }
        if (!ntos_base) fail("could not locate ntoskrnl base");
        static const char* const kCriticalExports[] = {
            "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtOpenProcess",
            "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
            "NtQueryVirtualMemory", "NtCreateThreadEx",
            "NtDeviceIoControlFile", "NtQuerySystemInformation",
            "NtSetInformationThread", "NtClose", "NtDuplicateObject",
            "MmCopyVirtualMemory", "KeStackAttachProcess",
            "KeUnstackDetachProcess", "PsLookupProcessByProcessId",
            "PsLookupThreadByThreadId", "ObOpenObjectByPointer",
            "MmProbeAndLockPages",
        };
        json hooks = json::array(), clean = json::array();
        uint32_t checked = 0;
        for (const char* name : kCriticalExports) {
            const uint64_t fn = resolve_kernel_export(dev, ntos_base, name)
                                    .value_or(0);
            if (!fn) continue;
            ++checked;
            uint8_t bytes[16] = {};
            if (dev.read_kernel_raw(fn, bytes, sizeof(bytes)) != sizeof(bytes))
                continue;
            std::string hook_type;
            uint64_t target = 0;
            if (bytes[0] == 0xE9) {
                int32_t rel = 0;
                std::memcpy(&rel, &bytes[1], 4);
                target = fn + 5 + rel;
                hook_type = "jmp_rel32";
            } else if (bytes[0] == 0xFF && bytes[1] == 0x25) {
                int32_t disp = 0;
                std::memcpy(&disp, &bytes[2], 4);
                const uint64_t ptr = fn + 6 + disp;
                dev.read_kernel_raw(ptr, &target, 8);
                hook_type = "jmp_indirect_rip";
            } else if (bytes[0] == 0x48 && bytes[1] == 0xB8 &&
                       bytes[10] == 0xFF && bytes[11] == 0xE0) {
                std::memcpy(&target, &bytes[2], 8);
                hook_type = "mov_rax_jmp_rax";
            } else if (bytes[0] == 0xCC) {
                hook_type = "int3_breakpoint";
            }
            if (hook_type.empty()) {
                clean.push_back({{"function", name}, {"address", fn},
                                 {"status", "clean"}});
                continue;
            }
            json h = {{"function", name}, {"address", fn},
                      {"hook_type", hook_type},
                      {"prologue_bytes", to_hex(bytes, sizeof(bytes))}};
            if (target) {
                h["target"] = target;
                for (const auto& m : mods) {
                    if (target >= m.base && target < m.base + m.size) {
                        h["hook_owner"] = m.name;
                        break;
                    }
                }
            }
            hooks.push_back(std::move(h));
        }
        return {{"ntoskrnl_base", ntos_base},
                {"checked", checked},
                {"hooks", hooks}, {"hook_count", hooks.size()},
                {"clean", clean}, {"clean_count", clean.size()},
                {"scan_ran", checked > 0}};
    }

    if (action == "sniff_buffers") {
        // arm a sniff session at a network function and read buffers off breakpoint hits
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        auto& dev = *k->device();
        const std::string op = args.value("op", std::string("get"));
        if (op == "stop") {
            if (!dev.sniff_net_buffers_stop()) fail("sniff stop failed");
            return {{"stopped", true}};
        }
        if (op == "store") {
            if (!args.contains("hex")) fail("missing hex payload");
            auto bytes = hex_decode(args.at("hex").get<std::string>());
            if (bytes.empty()) fail("empty payload");
            if (!dev.sniff_net_buffers_store(
                    args.value("timestamp", uint64_t(0)),
                    args.value("thread_id", uint64_t(0)),
                    bytes.data(), static_cast<uint32_t>(bytes.size())))
                fail("sniff store failed");
            bool active = false;
            auto caps = dev.sniff_net_buffers_get(active);
            return {{"stored", true}, {"active", active},
                    {"capture_count", caps.size()}};
        }
        if (op == "get") {
            bool active = false;
            auto caps = dev.sniff_net_buffers_get(active);
            json arr = json::array();
            for (const auto& c : caps) {
                const size_t show = std::min<size_t>(c.buffer.size(), 256);
                json o = {{"timestamp", c.timestamp}, {"tid", c.thread_id},
                          {"size", c.buffer.size()},
                          {"hex", to_hex(c.buffer.data(), show)}};
                std::string ascii;
                for (size_t i = 0; i < show; ++i) {
                    const char ch = static_cast<char>(c.buffer[i]);
                    ascii += (ch >= 0x20 && ch < 0x7F) ? ch : '.';
                }
                o["ascii"] = std::move(ascii);
                arr.push_back(std::move(o));
            }
            return {{"active", active}, {"captures", arr},
                    {"count", arr.size()}};
        }
        // start
        if (!args.contains("addr")) fail("missing addr (send/recv fn)");
        const uint64_t address = parse_addr(args, "addr");
        auto reg_index = [](const std::string& name) -> uint32_t {
            static const std::pair<const char*, uint32_t> regs[] = {
                {"rax", 0}, {"rcx", 1}, {"rdx", 2}, {"rbx", 3},
                {"rsp", 4}, {"rbp", 5}, {"rsi", 6}, {"rdi", 7},
                {"r8", 8}, {"r9", 9}, {"r10", 10}, {"r11", 11},
                {"r12", 12}, {"r13", 13}, {"r14", 14}, {"r15", 15}};
            for (const auto& r : regs)
                if (name == r.first) return r.second;
            return 0;
        };
        const uint32_t buf_reg = reg_index(
            args.value("buffer_register", std::string("rcx")));
        const uint32_t size_reg = reg_index(
            args.value("size_register", std::string("rdx")));
        uint32_t max_caps = static_cast<uint32_t>(args.value("max_captures", 1u));
        max_caps = std::min<uint32_t>(max_caps, 16);
        const uint32_t tid = static_cast<uint32_t>(args.value("tid", 0u));
        uint32_t bp_index = static_cast<uint32_t>(args.value("bp_index", 0u));
        if (bp_index > 3) bp_index = 0;
        if (!dev.sniff_net_buffers_start(address, buf_reg, size_reg, max_caps,
                                         tid, bp_index))
            fail("sniff start failed");
        return {{"started", true}, {"addr", address},
                {"buffer_register", buf_reg}, {"size_register", size_reg},
                {"max_captures", max_caps}, {"bp_index", bp_index}};
    }

    fail("driver: unknown action (status|backend|kernel_modules|dump_driver|"
         "kernel_read|kernel_write|kernel_search|call|v2p|ssdt|peb|"
         "resolve_export|windows|find_references|heap_walk|heap_blocks|"
         "defer_call|defer_list|defer_execute|defer_results|defer_cancel|"
         "symbols_load|symbols_lookup|symbols_nearest|anti_debug_spoof|"
         "sandbox_protect|sandbox_unprotect|log_config|read_teb|peb_modules|"
         "integrity_checks|sniff_buffers)");
}




// tool: emulate

json tool_emulate(const json& args) {
    const std::string action = require_action(args);
    if (action != "run") fail("emulate: unknown action");

    emu::run_request_t req;

    // hex wins over file_addr wins over target_addr, code runs at its real va unless base says otherwise
    bool have_code = false;
    if (args.contains("hex") && args.at("hex").is_string()) {
        req.code = hex_decode(args.at("hex").get<std::string>());
        have_code = !req.code.empty();
    }
    if (!have_code && args.contains("file_addr")) {
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
        const uint64_t addr = parse_addr(args, "file_addr");
        uint64_t len = args.contains("code_len") ? parse_addr(args, "code_len") : 64;
        if (len == 0 || len > (1ull << 20)) fail("bad code_len");
        auto off = bin.pe.va_to_offset(addr);
        if (!off) fail("file_addr not mapped in the loaded image");
        len = std::min<uint64_t>(len, bin.file.size() - *off);
        req.code.assign(bin.file.data() + *off, bin.file.data() + *off + len);
        req.code_base = addr;
        have_code = true;
    }
    if (!have_code && args.contains("target_addr")) {
        auto s = process::active_session();
        if (!s || !s->valid()) fail("no target attached for target_addr");
        const uint64_t addr = parse_addr(args, "target_addr");
        uint64_t len = args.contains("code_len") ? parse_addr(args, "code_len") : 64;
        if (len == 0 || len > (1ull << 20)) fail("bad code_len");
        req.code.resize(static_cast<size_t>(len));
        auto io = s->read(static_cast<uintptr_t>(addr), req.code.data(),
                          req.code.size());
        if (!io.ok || io.bytes == 0) fail("cannot read target memory");
        req.code.resize(io.bytes);
        req.code_base = addr;
        have_code = true;
    }
    if (!have_code)
        fail("no code source: pass 'hex', 'file_addr' or 'target_addr'");

    if (args.contains("base")) req.code_base = parse_addr(args, "base");
    const uint64_t start_va = args.contains("entry")
        ? parse_addr(args, "entry")
        : req.code_base;
    if (start_va < req.code_base || start_va >= req.code_base + req.code.size())
        fail("entry outside code range");
    req.entry_absolute = true;
    req.entry          = start_va;

    if (args.contains("stack_base")) req.stack_base = parse_addr(args, "stack_base");
    if (args.contains("stack_size")) req.stack_size = static_cast<size_t>(parse_addr(args, "stack_size"));
    if (args.contains("sp")) { req.sp_set = true; req.sp = parse_addr(args, "sp"); }

    if (auto it = args.find("regs"); it != args.end() && it->is_object()) {
        for (auto r = it->begin(); r != it->end(); ++r) {
            const json& v = r.value();
            uint64_t value = 0;
            if (v.is_number_unsigned()) value = v.get<uint64_t>();
            else if (v.is_number_integer() && v.get<int64_t>() >= 0) value = static_cast<uint64_t>(v.get<int64_t>());
            else if (v.is_string()) value = std::stoull(v.get<std::string>(), nullptr, 0);
            else fail("regs values must be non-negative integers or hex strings");
            req.regs[r.key()] = value;
        }
    }

    if (auto it = args.find("maps"); it != args.end() && it->is_array()) {
        for (const auto& m : *it) {
            if (!m.contains("addr") || !m.contains("hex"))
                fail("maps entries need addr + hex");
            emu::emu_mem_region_t reg;
            reg.addr = parse_addr(m, "addr");
            reg.bytes = hex_decode(m.at("hex").is_string()
                                       ? m.at("hex").get<std::string>()
                                       : std::string{});
            if (reg.bytes.empty()) fail("empty map region");
            req.maps.push_back(std::move(reg));
        }
    }

    if (args.contains("until"))       req.until_addr       = parse_addr(args, "until");
    if (args.contains("count"))       req.max_instructions = parse_addr(args, "count");
    if (args.contains("timeout_ms"))  req.timeout_ms       = static_cast<uint32_t>(parse_addr(args, "timeout_ms"));
    if (args.contains("trace"))       req.trace            = args.value("trace", false);
    if (args.contains("trace_max"))   req.trace_max        = static_cast<size_t>(parse_addr(args, "trace_max"));

    if (auto it = args.find("taint"); it != args.end() && it->is_array()) {
        for (const auto& t : *it) {
            if (!t.contains("addr") || !t.contains("len"))
                fail("taint entries need addr + len");
            emu::run_request_t::taint_source_t s;
            s.addr = parse_addr(t, "addr");
            s.len  = static_cast<size_t>(parse_addr(t, "len"));
            if (s.len == 0) fail("taint len must be > 0");
            req.taint_sources.push_back(s);
        }
    }
    if (args.contains("watch_addr") && args.contains("watch_len")) {
        req.watch_addr = parse_addr(args, "watch_addr");
        req.watch_len  = static_cast<size_t>(parse_addr(args, "watch_len"));
    }

    auto r = emu::emulate_run(req);
    if (!r.ok && !r.error.empty()) fail(r.error);

    json out = {{"ok", r.ok},
                {"stopped_reason", r.stopped_reason},
                {"instructions", r.instructions}};
    if (!r.error.empty()) out["error"] = r.error;

    json regs = json::object();
    for (const auto& [name, value] : r.regs) regs[name] = value;
    out["regs"] = regs;

    if (!r.trace.empty()) {
        json arr = json::array();
        for (const auto& t : r.trace)
            arr.push_back({{"ip", t.ip}, {"text", t.text}});
        out["trace"] = arr;
    }
    {
        json arr = json::array();
        for (const auto& w : r.writes)
            arr.push_back({{"ip", w.ip}, {"addr", w.addr}, {"len", w.len}});
        out["writes"] = arr;
        out["total_writes"] = r.total_writes;
    }
    if (r.fault)
        out["fault"] = {{"ip", r.fault->ip}, {"addr", r.fault->addr},
                        {"access", r.fault->access}};

    if (!req.taint_sources.empty()) {
        json ranges = json::array();
        for (const auto& rg : r.taint_ranges)
            ranges.push_back({{"addr", rg.addr}, {"len", rg.len}});
        json events = json::array();
        for (const auto& e : r.taint_events)
            events.push_back({{"ip", e.ip}, {"insn", e.insn},
                              {"kind", e.kind}, {"target", e.target}});
        out["taint_ranges"]   = ranges;
        out["taint_events"]   = events;
        out["output_tainted"] = r.output_tainted;
    }
    return out;
}

// tool: analyze

json tool_analyze(const json& args) {
    const std::string action = require_action(args);
    if (action != "packer" && action != "signatures" && action != "diff")
        fail("analyze: unknown action (packer|signatures|diff)");

    // diff runs two full analyses synchronously so it takes a while
    if (action == "diff") {
        if (!args.contains("path_a") || !args.contains("path_b"))
            fail("missing path_a/path_b");
        const std::string pa = args.at("path_a").get<std::string>();
        const std::string pb = args.at("path_b").get<std::string>();

        auto load_and_analyze = [](const std::string& path) {
            std::ifstream f(path, std::ios::binary);
            if (!f) fail("cannot open " + path);
            std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)),
                                       std::istreambuf_iterator<char>{});
            auto sess = std::make_unique<hs::session_t>();
            if (!sess->start_sync(bytes.data(), bytes.size(), 0))
                fail("hyperion analysis failed for " + path + ": " +
                     sess->error());
            return sess;
        };

        auto sa = load_and_analyze(pa);
        auto sb = load_and_analyze(pb);

        hype::BinDiff differ;
        const auto results = differ.compare(sa->db(), sb->db());

        json arr = json::array();
        const size_t limit = std::min<size_t>(args.value("limit", 500u), 5000u);
        const char* status_name[] = {"added", "removed", "modified", "identical"};
        for (size_t i = 0; i < results.size() && i < limit; ++i) {
            const auto& r = results[i];
            json o = {{"addr_a", r.addr_a}, {"addr_b", r.addr_b},
                      {"name", r.name},
                      {"similarity", r.similarity},
                      {"status", status_name[r.status]}};
            if (r.status == hype::DiffResult::Identical) continue;  // noise
            arr.push_back(std::move(o));
        }
        size_t counts[4] = {0, 0, 0, 0};
        for (const auto& r : results) ++counts[r.status];
        return {{"ok", true}, {"diffs", arr}, {"count", arr.size()},
                {"totals", {{"added", counts[0]}, {"removed", counts[1]},
                            {"modified", counts[2]},
                            {"identical", counts[3]}}}};
    }

    // explicit path into the private cache, else the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& img = load_image(args.at("path").get<std::string>());
        pe = &img.pe; file = &img.file;
        const size_t slash = img.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? img.path : img.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop "
                 "(see disasm.loaded)");
        pe = &bin.pe; file = &bin.file;
        img_name = bin.name;
    }

    if (action == "packer") {
        auto v = analysis::packer_analyze(*pe, *file);
        json dets = json::array();
        for (const auto& d : v.detections)
            dets.push_back({{"type", d.type}, {"protector", d.protector},
                            {"detail", d.detail}, {"location", d.location}});
        json secs = json::array();
        for (const auto& s : v.sections)
            secs.push_back({{"name", s.name}, {"rva", s.rva},
                            {"raw_size", s.raw_size}, {"virtual_size", s.virtual_size},
                            {"entropy", s.entropy}, {"writable_exec", s.writable_exec},
                            // raw characteristics here too for consistency
                            {"exec", (s.characteristics & 0x20000000u) != 0},
                            {"writable", (s.characteristics & 0x80000000u) != 0},
                            {"characteristics", s.characteristics}});
        json out = {{"image", img_name}, {"packed", v.packed}, {"family", v.family},
                    {"confidence", v.confidence}, {"file_entropy", v.file_entropy},
                    {"detections", dets}, {"sections", secs}};

        // the hyperion packer verdict rides along when the session is analyzed
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype) {
                hype::PackerDetector det;
                auto infos = det.detect(bin.hype->image());
                json harr = json::array();
                for (const auto& i : infos)
                    harr.push_back({{"name", i.name},
                                    {"confidence", i.confidence},
                                    {"details", i.details}});
                out["hype_packer"] = harr;
            }
        }
        return out;
    }

    const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);

    // flirt style matches from the analyzer, about a hundred msvc crt patterns
    if (!args.contains("path")) {
        auto& bin = ds::get();
        if (bin.ready && bin.hype && bin.hype->ready()) {
            auto hits = analysis::crypto_hunt(*pe, *file, limit);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"name", h.name}, {"offset", h.offset},
                          {"in_overlay", h.in_overlay}};
                if (h.va) o["va"] = h.va;
                arr.push_back(std::move(o));
            }

            // analyzer derived names, nothing here is flirt verified
            json named = json::array();
            for (const auto& [va, name] : bin.hype->db().names) {
                if (name.find("j_") == 0 || name.find("__imp_") == 0) continue;
                if (named.size() >= limit) break;
                named.push_back({{"va", va}, {"name", name}});
            }
            return {{"image", img_name}, {"signatures", arr},
                    {"count", arr.size()}, {"named_functions", named},
                    {"named_count", named.size()}};
        }
    }

    auto hits = analysis::crypto_hunt(*pe, *file, limit);
    json arr = json::array();
    for (const auto& h : hits) {
        json o = {{"name", h.name}, {"offset", h.offset},
                  {"in_overlay", h.in_overlay}};
        if (h.va) o["va"] = h.va;
        arr.push_back(std::move(o));
    }
    return {{"image", img_name}, {"signatures", arr}, {"count", arr.size()}};
}

// tool: network

json packet_to_json(const network::packet_record_t& p) {
    json o = {{"id", p.id}, {"at_ms", p.at_ms}, {"pid", p.pid},
              {"protocol", p.protocol}, {"direction", p.direction},
              {"local", p.local_addr + ":" + std::to_string(p.local_port)},
              {"remote", p.remote_addr + ":" + std::to_string(p.remote_port)},
              {"payload_bytes", p.payload.size()}};
    const size_t preview = std::min<size_t>(p.payload.size(), 96);
    if (preview)
        o["payload_hex"] = to_hex(p.payload.data(), preview);
    return o;
}

// kernel network helpers

std::string ip_to_string(const uint8_t* addr, uint32_t af) {
    char buf[64] = "";
    if (af == 23) InetNtopA(AF_INET6, addr, buf, sizeof(buf));
    else          InetNtopA(AF_INET, addr, buf, sizeof(buf));
    return buf;
}

std::string ip_port_to_string(const uint8_t* addr, uint32_t af, uint32_t port) {
    return ip_to_string(addr, af) + ":" + std::to_string(port);
}

const char* http_method_name(uint32_t m) {
    switch (m) {
        case 1: return "GET";     case 2: return "POST";
        case 3: return "PUT";     case 4: return "DELETE";
        case 5: return "HEAD";    case 6: return "OPTIONS";
        case 7: return "PATCH";   case 8: return "CONNECT";
        case 9: return "TRACE";   default: return "UNKNOWN";
    }
}

const char* tls_version_name(uint32_t ver) {
    switch (ver) {
        case 0x0300: return "SSL 3.0"; case 0x0301: return "TLS 1.0";
        case 0x0302: return "TLS 1.1"; case 0x0303: return "TLS 1.2";
        case 0x0304: return "TLS 1.3"; default: return "unknown";
    }
}

const char* tls_content_type_name(uint32_t ct) {
    switch (ct) {
        case 20: return "ChangeCipherSpec"; case 21: return "Alert";
        case 22: return "Handshake";        case 23: return "ApplicationData";
        default: return "other";
    }
}

json tool_network(const json& args) {
    const std::string action = require_action(args);

    if (action == "status") {
        json out;
        out["kernel_available"] = network::capture::kernel_available();
        out["store_packets"]    = g_traffic.size();
        out["proxy_running"]    = g_proxy.running();
        out["proxy_port"]       = g_proxy.port();
        return out;
    }

    if (action == "capture_start") {
        auto err = network::capture::start(
            static_cast<uint32_t>(args.value("pid", 0u)),
            static_cast<uint32_t>(args.value("port", 0u)),
            static_cast<uint32_t>(args.value("protocol", 0u)));
        if (!err.empty()) fail(err);
        return {{"capture", true}};
    }
    if (action == "capture_stop") {
        auto err = network::capture::stop();
        if (!err.empty()) fail(err);
        return {{"capture", false}};
    }
    if (action == "packets") {
        // pull fresh packets first then serve from the store
        network::capture::poll(g_traffic, 512);
        const uint64_t from = args.contains("from")
                                  ? parse_addr(args, "from") : 0;
        auto page = args.contains("filter")
                        ? g_traffic.packets_filtered(
                              from,
                              std::min<size_t>(args.value("limit", 100u), 1000u),
                              args.at("filter").get<std::string>())
                        : g_traffic.packets(
                              from,
                              std::min<size_t>(args.value("limit", 100u), 1000u));
        json arr = json::array();
        for (const auto& p : page.items) arr.push_back(packet_to_json(p));
        return {{"packets", arr}, {"count", arr.size()},
                {"truncated", page.truncated},
                {"last_id", page.items.empty() ? from
                                               : page.items.back().id}};
    }
    if (action == "dns") {
        auto rows = network::capture::dns_queries(
            static_cast<uint32_t>(args.value("pid", 0u)));
        json arr = json::array();
        for (const auto& d : rows)
            arr.push_back({{"timestamp", d.timestamp}, {"pid", d.pid},
                           {"query_type", d.query_type}, {"domain", d.domain},
                           {"resolved", d.resolved_addr},
                           {"response_code", d.response_code}, {"ttl", d.ttl}});
        return {{"dns", arr}, {"count", arr.size()}};
    }
    if (action == "rules_add") {
        network::filter_rule_t rule;
        rule.action    = static_cast<uint32_t>(args.value("action_rule", 0u));
        rule.direction = static_cast<uint32_t>(args.value("direction", 0u));
        rule.protocol  = static_cast<uint32_t>(args.value("protocol", 0u));
        rule.pid       = static_cast<uint32_t>(args.value("pid", 0u));
        rule.port      = static_cast<uint32_t>(args.value("port", 0u));
        uint32_t id = 0;
        auto err = network::capture::add_filter_rule(rule, &id);
        if (!err.empty()) fail(err);
        return {{"added", true}, {"rule_id", id}};
    }
    if (action == "rules_remove") {
        auto err = network::capture::remove_filter_rule(
            static_cast<uint32_t>(parse_addr(args, "rule_id")));
        if (!err.empty()) fail(err);
        return {{"removed", true}};
    }
    if (action == "rules_clear") {
        auto err = network::capture::clear_filter_rules();
        if (!err.empty()) fail(err);
        return {{"cleared", true}};
    }
    if (action == "stats") {
        auto s = network::capture::stats();
        if (!s) fail("kernel driver not active");
        return json{{"bytes_sent", s->bytes_sent},
                    {"bytes_received", s->bytes_received},
                    {"packets_sent", s->packets_sent},
                    {"packets_received", s->packets_received},
                    {"active_connections", s->active_connections},
                    {"capture_active", s->capture_active},
                    {"total_captured", s->total_captured},
                    {"total_dropped", s->total_dropped},
                    {"total_dns_logged", s->total_dns_logged},
                    {"active_filter_rules", s->active_filter_rules}};
    }
    if (action == "export_pcap") {
        if (!args.contains("path")) fail("missing path");
        auto err = network::capture::export_pcap(
            args.at("path").get<std::string>(),
            static_cast<uint32_t>(args.value("pid", 0u)),
            static_cast<uint32_t>(
                std::min<uint64_t>(args.contains("max_packets")
                                       ? parse_addr(args, "max_packets")
                                       : 4096,
                                   65536ull)));
        if (!err.empty()) fail(err);
        return {{"exported", true}, {"path", args.at("path")}};
    }
    if (action == "streams") {
        auto all = g_traffic.streams();
        json arr = json::array();
        for (const auto& s : all) {
            arr.push_back({{"id", s.id}, {"key", s.key}, {"bytes", s.bytes},
                           {"packets", s.packets}, {"first_ms", s.first_ms},
                           {"last_ms", s.last_ms}});
        }
        return {{"streams", arr}, {"count", arr.size()}};
    }
    if (action == "stream_data") {
        const uint64_t id = parse_addr(args, "id");
        const uint64_t off =
            args.contains("offset") ? parse_addr(args, "offset") : 0;
        uint64_t len = args.contains("len") ? parse_addr(args, "len") : 4096;
        len = std::min<uint64_t>(len, 1 << 20);
        auto bytes = g_traffic.stream_bytes(
            id, static_cast<size_t>(off), static_cast<size_t>(len));
        if (!bytes) fail("unknown stream id");
        json out = {{"id", id}, {"offset", off}, {"bytes", bytes->size()}};
        const size_t text_len = std::min<size_t>(bytes->size(), 4096);
        std::string text(reinterpret_cast<const char*>(bytes->data()), text_len);
        for (char& ch : text)
            if (static_cast<unsigned char>(ch) < 0x20 &&
                ch != '\n' && ch != '\r' && ch != '\t')
                ch = '.';
        out["text"] = text;
        out["hex"]  = to_hex(bytes->data(), text_len);
        return out;
    }

    // kernel network manipulation through wfp
    // everything bails with a structured error when the driver is down
    // op 0 adds or starts, op 1 removes or stops

    auto need_device = []() -> voyager::device_t& {
        auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
        if (!k || !k->device()) fail("kernel driver not active");
        return *k->device();
    };
    auto parse_ip = [&](const json& a, const char* key,
                        std::array<uint8_t, 16>& out, uint32_t* af) {
        const std::string s2 = a.value(key, std::string{});
        if (s2.empty()) { *af = 2; return; }                 // AF_INET wildcard
        IN_ADDR v4{};
        if (InetPtonA(AF_INET, s2.c_str(), &v4) == 1) {
            std::memcpy(out.data(), &v4, 4);
            *af = 2;
            return;
        }
        IN6_ADDR v6{};
        if (InetPtonA(AF_INET6, s2.c_str(), &v6) == 1) {
            std::memcpy(out.data(), &v6, 16);
            *af = 23;                                        // AF_INET6
            return;
        }
        fail("bad ip in '" + std::string(key) + "'");
    };

    if (action == "inject") {
        auto& dev = need_device();
        if (!args.contains("payload_hex")) fail("missing payload_hex");
        auto bytes = hex_decode(args.at("payload_hex").get<std::string>());
        if (bytes.empty() || bytes.size() > 1500)
            fail("payload must be 1..1500 bytes");
        std::array<uint8_t, 16> src{}, dst{};
        uint32_t af_src = 2, af_dst = 2;
        parse_ip(args, "src_ip", src, &af_src);
        parse_ip(args, "dst_ip", dst, &af_dst);
        const bool ok = dev.inject_packet(
            static_cast<uint32_t>(args.value("direction", 1u)),
            static_cast<uint32_t>(args.value("protocol", 17u)),   // UDP default
            args.contains("dst_ip") ? af_dst : 2,
            static_cast<uint32_t>(args.value("src_port", 0u)),
            static_cast<uint32_t>(args.value("dst_port", 0u)),
            src.data(), dst.data(), bytes.data(),
            static_cast<uint32_t>(bytes.size()));
        if (!ok) fail("inject failed");
        return {{"injected", true}, {"bytes", bytes.size()}};
    }
    if (action == "mod_rule_add" || action == "mod_rule_remove") {
        auto& dev = need_device();
        const uint32_t op = action == "mod_rule_add" ? 0 : 1;
        std::vector<uint8_t> pat, rep;
        if (args.contains("pattern_hex"))
            pat = hex_decode(args.at("pattern_hex").get<std::string>());
        if (args.contains("replacement_hex"))
            rep = hex_decode(args.at("replacement_hex").get<std::string>());
        if (action == "mod_rule_add" &&
            (pat.empty() || pat.size() > 256 || rep.size() > 256))
            fail("bad pattern/replacement (1..256 bytes each)");
        uint32_t rule_id = 0;
        const bool ok = dev.packet_mod_rule_op(
            op,
            args.contains("rule_id")
                ? static_cast<uint32_t>(parse_addr(args, "rule_id")) : 0,
            static_cast<uint32_t>(args.value("direction", 2u)),
            static_cast<uint32_t>(args.value("protocol", 0u)),
            static_cast<uint32_t>(args.value("port", 0u)),
            static_cast<uint32_t>(args.value("pid", 0u)),
            action == "mod_rule_add" ? pat.data() : nullptr,
            action == "mod_rule_add"
                ? static_cast<uint32_t>(pat.size()) : 0,
            action == "mod_rule_add" ? rep.data() : nullptr,
            action == "mod_rule_add"
                ? static_cast<uint32_t>(rep.size()) : 0,
            &rule_id);
        if (!ok) fail("packet mod rule op failed");
        return {{"op", action}, {"rule_id", rule_id}};
    }
    if (action == "redirect_add" || action == "redirect_remove") {
        auto& dev = need_device();
        const uint32_t op = action == "redirect_add" ? 0 : 1;
        std::array<uint8_t, 16> match{}, redir{};
        uint32_t af_m = 2, af_r = 2;
        parse_ip(args, "match_ip", match, &af_m);
        parse_ip(args, "redirect_ip", redir, &af_r);
        uint32_t rule_id = 0;
        const bool ok = dev.traffic_redirect_op(
            op,
            args.contains("rule_id")
                ? static_cast<uint32_t>(parse_addr(args, "rule_id")) : 0,
            static_cast<uint32_t>(args.value("protocol", 0u)),
            static_cast<uint32_t>(args.value("match_port", 0u)),
            match.data(),
            static_cast<uint32_t>(args.value("redirect_port", 0u)),
            redir.data(),
            args.contains("redirect_ip") ? af_r : af_m,
            &rule_id,
            static_cast<uint32_t>(args.value("exclude_pid", 0u)));
        if (!ok) fail("traffic redirect op failed");
        return {{"op", action}, {"rule_id", rule_id}};
    }
    if (action == "dns_spoof_add" || action == "dns_spoof_remove") {
        auto& dev = need_device();
        const uint32_t op = action == "dns_spoof_add" ? 0 : 1;
        std::array<uint8_t, 16> addr{};
        uint32_t af = 2;
        parse_ip(args, "ip", addr, &af);
        uint32_t rule_id = 0;
        const bool ok = dev.dns_spoof_op(
            op,
            args.contains("rule_id")
                ? static_cast<uint32_t>(parse_addr(args, "rule_id")) : 0,
            action == "dns_spoof_add"
                ? args.at("domain").get<std::string>().c_str() : nullptr,
            addr.data(), af,
            static_cast<uint32_t>(args.value("ttl", 300u)),
            &rule_id);
        if (!ok) fail("dns spoof op failed");
        return {{"op", action}, {"rule_id", rule_id}};
    }
    if (action == "kill_conn") {
        auto& dev = need_device();
        std::array<uint8_t, 16> src{}, dst{};
        uint32_t af_s = 2, af_d = 2;
        parse_ip(args, "src_ip", src, &af_s);
        parse_ip(args, "dst_ip", dst, &af_d);
        const bool ok = dev.kill_connection(
            static_cast<uint32_t>(args.value("protocol", 6u)),
            args.contains("dst_ip") ? af_d : 2,
            static_cast<uint32_t>(args.value("src_port", 0u)),
            static_cast<uint32_t>(args.value("dst_port", 0u)),
            src.data(), dst.data(),
            static_cast<uint32_t>(args.value("pid", 0u)));
        if (!ok) fail("kill_connection failed");
        return {{"killed", true}};
    }
    if (action == "intercept_start" || action == "intercept_stop") {
        auto& dev = need_device();
        uint32_t held_count = 0;
        bool active = false;
        const bool ok = dev.intercept_op(
            action == "intercept_start" ? 0 : 1,
            static_cast<uint32_t>(args.value("pid", 0u)),
            static_cast<uint32_t>(args.value("port", 0u)),
            static_cast<uint32_t>(args.value("protocol", 0u)),
            0, nullptr, 0,
            &held_count, &active);
        if (!ok) fail("intercept op failed");
        return {{action == "intercept_start" ? "intercepting" : "stopped", true},
                {"held_count", held_count}, {"active", active}};
    }
    if (action == "intercept_list") {
        auto& dev = need_device();
        uint32_t held_count = 0;
        bool active = false;
        const bool ok = dev.intercept_op(2, 0, 0, 0, 0, nullptr, 0,
                                         &held_count, &active);
        if (!ok) fail("intercept list failed");
        json arr = json::array();
        for (const auto& h : dev.get_held_packets()) {
            char sip[64] = "", dip[64] = "";
            if (h.af == 2) {
                InetNtopA(AF_INET, h.src_addr, sip, sizeof(sip));
                InetNtopA(AF_INET, h.dst_addr, dip, sizeof(dip));
            } else {
                InetNtopA(AF_INET6, h.src_addr, sip, sizeof(sip));
                InetNtopA(AF_INET6, h.dst_addr, dip, sizeof(dip));
            }
            arr.push_back({{"hold_id", h.hold_id}, {"direction", h.direction},
                           {"protocol", h.protocol},
                           {"src", std::string(sip) + ":" + std::to_string(h.src_port)},
                           {"dst", std::string(dip) + ":" + std::to_string(h.dst_port)},
                           {"pid", h.pid}, {"payload_hex",
                                           to_hex(h.payload.data(),
                                                  std::min<size_t>(h.payload.size(), 96))}});
        }
        return {{"held", arr}, {"count", arr.size()}, {"active", active}};
    }
    if (action == "intercept_release") {
        auto& dev = need_device();
        if (!args.contains("hold_id")) fail("missing hold_id");
        std::vector<uint8_t> mod;
        if (args.contains("payload_hex"))
            mod = hex_decode(args.at("payload_hex").get<std::string>());
        uint32_t held_count = 0;
        bool active = false;
        const bool ok = dev.intercept_op(
            3, 0, 0, 0, parse_addr(args, "hold_id"),
            mod.empty() ? nullptr : mod.data(),
            static_cast<uint32_t>(mod.size()),
            &held_count, &active);
        if (!ok) fail("release failed (unknown hold_id?)");
        return {{"released", true}};
    }
    if (action == "bw_start" || action == "bw_stop" || action == "bw_stats" ||
        action == "bw_processes") {
        auto& dev = need_device();
        if (action == "bw_processes") {
            json arr = json::array();
            for (const auto& p : dev.get_bw_per_process(
                     static_cast<uint32_t>(args.value("pid", 0u))))
                arr.push_back({{"pid", p.pid},
                               {"bytes_sent", p.bytes_sent},
                               {"bytes_recv", p.bytes_recv},
                               {"packets_sent", p.packets_sent},
                               {"packets_recv", p.packets_recv}});
            return {{"processes", arr}, {"count", arr.size()}};
        }
        voyager::device_t::bw_stats stats{};
        const uint32_t op =
            action == "bw_start" ? 0 : action == "bw_stop" ? 1 : 2;
        const bool ok = dev.bw_monitor_op(
            op, static_cast<uint32_t>(args.value("pid", 0u)), &stats);
        if (!ok) fail("bandwidth monitor op failed");
        return json{{"active", stats.active},
                    {"total_bytes_sent", stats.total_bytes_sent},
                    {"total_bytes_recv", stats.total_bytes_recv},
                    {"packets_sent", stats.total_packets_sent},
                    {"packets_recv", stats.total_packets_recv},
                    {"bytes_per_sec_in", stats.bps_in},
                    {"bytes_per_sec_out", stats.bps_out}};
    }
    if (action == "fingerprint_run" || action == "fingerprint_results") {
        auto& dev = need_device();
        if (action == "fingerprint_run") {
            if (!dev.fingerprint_op(0)) fail("fingerprint start failed");
            std::this_thread::sleep_for(std::chrono::milliseconds(
                std::min<int>(args.value("window_ms", 4000), 20000)));
            if (!dev.fingerprint_op(1)) fail("fingerprint stop failed");
        }
        json arr = json::array();
        for (const auto& f : dev.get_fingerprints()) {
            char rip[64] = "";
            if (f.af == 2) InetNtopA(AF_INET, f.remote_addr, rip, sizeof(rip));
            else           InetNtopA(AF_INET6, f.remote_addr, rip, sizeof(rip));
            arr.push_back({{"remote_ip", rip}, {"ttl", f.ttl},
                           {"window", f.window_size}, {"mss", f.mss},
                           {"window_scale", f.window_scale},
                           {"df_flag", f.df_flag},
                           {"sack_permitted", f.sack_permitted},
                           {"guess", f.os_guess}});
        }
        return {{"fingerprints", arr}, {"count", arr.size()}};
    }
    if (action == "mod_rules_list" || action == "redirect_rules_list") {
        auto& dev = need_device();
        json arr = json::array();
        if (action == "mod_rules_list") {
            for (const auto& r : dev.list_packet_mod_rules())
                arr.push_back({{"rule_id", r.rule_id}, {"direction", r.direction},
                               {"protocol", r.protocol}, {"port", r.port},
                               {"pid", r.pid}, {"matches", r.match_count},
                               {"active", r.active}});
        } else {
            for (const auto& r : dev.list_redirect_rules())
                arr.push_back({{"rule_id", r.rule_id}, {"protocol", r.protocol},
                               {"match_port", r.match_port},
                               {"redirect_port", r.redirect_port},
                               {"af", r.af}, {"matches", r.match_count},
                               {"active", r.active}});
        }
        return {{"rules", arr}, {"count", arr.size()}};
    }
    if (action == "reassemble_stream") {
        auto& dev = need_device();
        std::vector<uint8_t> data;
        uint32_t packets = 0, truncated = 0;
        const bool ok = dev.stream_reassemble_op(
            static_cast<uint32_t>(args.value("op", 0u)),
            static_cast<uint32_t>(args.value("src_port", 0u)),
            static_cast<uint32_t>(args.value("dst_port", 0u)),
            static_cast<uint32_t>(args.value("pid", 0u)),
            nullptr, nullptr, &data, &packets, &truncated);
        if (!ok) fail("stream reassemble failed");
        const size_t text_len = std::min<size_t>(data.size(), 4096);
        std::string text(reinterpret_cast<const char*>(data.data()), text_len);
        for (char& ch : text)
            if (static_cast<unsigned char>(ch) < 0x20 && ch != '\n' &&
                ch != '\r' && ch != '\t')
                ch = '.';
        return {{"bytes", data.size()}, {"packets", packets},
                {"truncated", truncated != 0},
                {"hex", to_hex(data.data(), text_len)}, {"text", text}};
    }

    // system wide network views over the driver
    // connections, dpi, callouts, socket handles, tcpip internals

    if (action == "connections") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& c : dev.enumerate_connections(
                 static_cast<uint32_t>(args.value("pid", 0u)),
                 static_cast<uint32_t>(args.value("protocol", 0u)))) {
            arr.push_back({{"pid", c.pid},
                           {"protocol", c.protocol},
                           {"state", c.state},
                           {"local", ip_port_to_string(c.local_addr,
                                                       c.address_family,
                                                       c.local_port)},
                           {"remote", ip_port_to_string(c.remote_addr,
                                                        c.address_family,
                                                        c.remote_port)},
                           {"path", c.process_path}});
        }
        return {{"connections", arr}, {"count", arr.size()}};
    }
    if (action == "deep_inspect") {
        // dpi results straight from the kernel classifier
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& d : dev.get_dpi_results(
                 static_cast<uint32_t>(args.value("pid", 0u)),
                 static_cast<uint32_t>(args.value("protocol", 0u)),
                 static_cast<uint32_t>(args.value("port", 0u)))) {
            json o = {{"timestamp", d.timestamp},
                      {"direction", d.direction},
                      {"protocol", d.protocol},
                      {"src", ip_port_to_string(d.src_addr, d.af, d.src_port)},
                      {"dst", ip_port_to_string(d.dst_addr, d.af, d.dst_port)},
                      {"pid", d.pid},
                      {"payload_size", d.payload_size}};
            if (d.protocol == 6) {
                o["tcp_flags"] = d.tcp_flags;
                o["tcp_window"] = d.tcp_window;
            }
            if (d.is_http) {
                o["app_protocol"] = "HTTP";
                o["http_method"] = http_method_name(d.http_method);
                if (!d.http_host.empty()) o["http_host"] = d.http_host;
                if (!d.http_path.empty()) o["http_path"] = d.http_path;
            }
            if (d.is_tls) {
                o["app_protocol"] = "TLS";
                o["tls_version"] = tls_version_name(d.tls_version);
                o["tls_content_type"] = tls_content_type_name(d.tls_content_type);
                if (!d.tls_sni.empty()) o["tls_sni"] = d.tls_sni;
            }
            if (d.is_dns) o["app_protocol"] = "DNS";
            arr.push_back(std::move(o));
        }
        return {{"results", arr}, {"count", arr.size()}};
    }
    if (action == "wfp_callouts") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& c : dev.enumerate_wfp_callouts(
                 args.value("module", std::string{})))
            arr.push_back({{"filter_id", c.filter_id},
                           {"callout_id", c.callout_id},
                           {"layer_id", c.layer_id},
                           {"classify_fn", c.classify_fn},
                           {"notify_fn", c.notify_fn},
                           {"flow_delete_fn", c.flow_delete_fn},
                           {"owning_module", c.owning_module},
                           {"owning_module_base", c.owning_module_base},
                           {"action_type", c.action_type},
                           {"entry_type", c.entry_type},
                           {"provider_present", c.provider_present},
                           {"flags", c.flags}});
        return {{"callouts", arr}, {"count", arr.size()}};
    }
    if (action == "socket_handles") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& s : dev.get_socket_handles(
                 static_cast<uint32_t>(args.value("pid", 0u))))
            arr.push_back({{"pid", s.pid},
                           {"handle", s.handle_value},
                           {"afd_endpoint", s.afd_endpoint_addr},
                           {"protocol", s.protocol},
                           {"state", s.state},
                           {"local", ip_port_to_string(s.local_addr,
                                                       s.address_family,
                                                       s.local_port)},
                           {"remote", ip_port_to_string(s.remote_addr,
                                                        s.address_family,
                                                        s.remote_port)}});
        return {{"sockets", arr}, {"count", arr.size()}};
    }
    if (action == "tcpip_dump") {
        // the tcb table is richer than the socket view
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& c : dev.dump_tcpip_connections(
                 static_cast<uint32_t>(args.value("pid", 0u)),
                 static_cast<uint32_t>(args.value("protocol", 0u))))
            arr.push_back({{"pid", c.pid},
                           {"protocol", c.protocol},
                           {"state", c.state},
                           {"tcb", c.tcb_address},
                           {"owning_module", c.owning_module_base},
                           {"local", ip_port_to_string(c.local_addr,
                                                       c.address_family,
                                                       c.local_port)},
                           {"remote", ip_port_to_string(c.remote_addr,
                                                        c.address_family,
                                                        c.remote_port)},
                           {"create_time", c.create_time},
                           {"bytes_in", c.bytes_in},
                           {"bytes_out", c.bytes_out}});
        return {{"connections", arr}, {"count", arr.size()}};
    }
    if (action == "interfaces") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& i : dev.enumerate_interfaces()) {
            char mac[24] = "";
            std::snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                          i.mac_addr[0], i.mac_addr[1], i.mac_addr[2],
                          i.mac_addr[3], i.mac_addr[4], i.mac_addr[5]);
            arr.push_back({{"index", i.if_index},
                           {"name", i.name},
                           {"description", i.description},
                           {"type", i.if_type},
                           {"mtu", i.mtu},
                           {"operational", i.oper_status},
                           {"speed", i.speed},
                           {"mac", mac},
                           {"ipv4", ip_to_string(i.ipv4_addr, 2)},
                           {"ipv4_mask", ip_to_string(i.ipv4_mask, 2)},
                           {"ipv6", ip_to_string(i.ipv6_addr, 23)},
                           {"in_octets", i.in_octets},
                           {"out_octets", i.out_octets}});
        }
        return {{"interfaces", arr}, {"count", arr.size()}};
    }
    if (action == "dns_spoof_list") {
        auto& dev = need_device();
        json arr = json::array();
        for (const auto& r : dev.list_dns_spoof_rules())
            arr.push_back({{"rule_id", r.rule_id}, {"domain", r.domain},
                           {"ttl", r.ttl}, {"af", r.af},
                           {"matches", r.match_count}, {"active", r.active}});
        return {{"rules", arr}, {"count", arr.size()}};
    }
    if (action == "block_ip" || action == "block_port" ||
        action == "block_process") {
        // thin wrapper over the wfp filter rules, action 1 means block
        auto& dev = need_device();
        uint32_t direction = 2;                       // 0=in 1=out 2=both
        if (args.contains("direction")) {
            // take the int or the friendlier string form
            const json& dv = args.at("direction");
            if (dv.is_string()) {
                const std::string d = dv.get<std::string>();
                if (d == "in" || d == "inbound")         direction = 0;
                else if (d == "out" || d == "outbound")  direction = 1;
                else if (d == "both")                    direction = 2;
                else fail("direction must be in|out|both");
            } else if (dv.is_number_integer()) {
                direction = static_cast<uint32_t>(dv.get<int64_t>());
            } else {
                fail("direction must be in|out|both or 0|1|2");
            }
        }
        uint32_t pid = 0, port = 0, protocol = 0;
        const uint8_t* ip = nullptr;
        uint8_t ip_buf[16] = {};
        uint8_t mask[16] = {};
        if (action == "block_ip") {
            if (!args.contains("ip")) fail("missing ip");
            if (InetPtonA(AF_INET, args.at("ip").get<std::string>().c_str(),
                          ip_buf) != 1)
                fail("invalid IPv4 address");
            std::memset(mask, 0xFF, 4);               // /32
            ip = ip_buf;
        } else if (action == "block_port") {
            if (!args.contains("port")) fail("missing port");
            port = static_cast<uint32_t>(parse_addr(args, "port"));
            protocol = static_cast<uint32_t>(args.value("protocol", 0u));
        } else {
            if (!args.contains("pid")) fail("missing pid");
            pid = static_cast<uint32_t>(parse_addr(args, "pid"));
        }
        uint32_t id = 0;
        if (!dev.add_filter_rule(1, direction, protocol, pid, port, ip, mask,
                                 &id))
            fail("block rule rejected by driver");
        json out = {{"blocked", true}, {"rule_id", id}, {"direction", direction}};
        if (action == "block_ip")   out["ip"] = args.at("ip");
        if (action == "block_port") out["port"] = port;
        if (action == "block_process") out["pid"] = pid;
        return out;
    }

    fail("network: unknown action (status|capture_start|capture_stop|packets|"
         "dns|rules_add|rules_remove|rules_clear|stats|export_pcap|streams|"
         "stream_data|inject|mod_rule_add|mod_rule_remove|mod_rules_list|"
         "redirect_add|redirect_remove|redirect_rules_list|dns_spoof_add|"
         "dns_spoof_remove|dns_spoof_list|kill_conn|intercept_start|"
         "intercept_stop|intercept_list|intercept_release|bw_start|bw_stop|"
         "bw_stats|bw_processes|fingerprint_run|fingerprint_results|"
         "reassemble_stream|connections|deep_inspect|wfp_callouts|"
         "socket_handles|tcpip_dump|interfaces|block_ip|block_port|"
         "block_process)");
}

// tool: proxy

json tool_proxy(const json& args) {
    const std::string action = require_action(args);

    if (action == "start") {
        std::string err;
        const uint16_t port = static_cast<uint16_t>(args.value("port", 8888));
        if (!g_proxy.start(port, &g_traffic, &err)) fail(err);
        return {{"running", true}, {"port", g_proxy.port()}};
    }
    if (action == "stop") {
        g_proxy.stop();
        return {{"running", false}};
    }
    if (action == "status") {
        return json{{"running", g_proxy.running()}, {"port", g_proxy.port()}};
    }
    if (action == "entries") {
        auto entries = g_proxy.recent(
            std::min<size_t>(args.value("limit", 100u), 512u));
        json arr = json::array();
        for (const auto& e : entries) {
            json o = {{"id", e.id}, {"at_ms", e.at_ms}, {"kind", e.kind},
                      {"method", e.method}, {"host", e.host}, {"port", e.port},
                      {"path", e.path}, {"status", e.status},
                      {"req_bytes", e.req_bytes}, {"resp_bytes", e.resp_bytes}};
            if (!e.sni.empty()) o["sni"] = e.sni;
            arr.push_back(std::move(o));
        }
        return {{"entries", arr}, {"count", arr.size()}};
    }
    if (action == "entry") {
        const uint64_t id = parse_addr(args, "id");
        auto e = g_proxy.entry(id);
        if (!e) fail("unknown entry id");
        json o = {{"id", e->id}, {"kind", e->kind}, {"method", e->method},
                  {"host", e->host}, {"port", e->port}, {"path", e->path},
                  {"status", e->status}, {"req_bytes", e->req_bytes},
                  {"resp_bytes", e->resp_bytes}};
        if (!e->response_head.empty()) {
            const size_t n = std::min<size_t>(e->response_head.size(), 2048);
            o["response_head_text"] = std::string(
                reinterpret_cast<const char*>(e->response_head.data()), n);
        }
        if (!e->raw_request.empty())
            o["replayable"] = true;
        return o;
    }
    if (action == "replay") {
        std::string err;
        auto resp = g_proxy.replay(parse_addr(args, "id"), &err);
        if (!resp) fail(err);
        const size_t n = std::min<size_t>(resp->size(), 16384);
        return {{"bytes", resp->size()},
                {"text", std::string(reinterpret_cast<const char*>(resp->data()),
                                     n)}};
    }

    fail("proxy: unknown action (start|stop|status|entries|entry|replay)");
}

// tool: detect

json tool_detect(const json& args) {
    const std::string action = require_action(args);

    if (action == "hidden_modules") {
        std::string err;
        auto r = detect::detect_hidden_modules(&err);
        if (!err.empty()) fail(err);
        auto to_arr = [](const std::vector<detect::module_entry_t>& v) {
            json a = json::array();
            for (const auto& m : v)
                a.push_back({{"name", m.name}, {"base", m.base},
                             {"size", m.size}});
            return a;
        };
        return {{"psapi_only", to_arr(r.psapi_only)},
                {"sysinfo_only", to_arr(r.sysinfo_only)},
                {"suspicious",
                 !r.psapi_only.empty() || !r.sysinfo_only.empty()}};
    }
    if (action == "minifilters") {
        std::string err;
        auto filters = detect::enumerate_minifilters(&err);
        if (!err.empty()) fail(err);
        json arr = json::array();
        for (const auto& f : filters)
            arr.push_back({{"name", f.name}, {"altitude", f.altitude},
                           {"frame_id", f.frame_id}});
        return {{"minifilters", arr}, {"count", arr.size()}};
    }
    if (action == "etw_sessions") {
        std::string err;
        auto sessions = detect::enumerate_etw_sessions(&err);
        if (!err.empty()) fail(err);
        json arr = json::array();
        for (const auto& s : sessions)
            arr.push_back({{"handle", s.handle},
                           {"logger_name", s.logger_name},
                           {"buffers_written", s.buffers_written},
                           {"events_lost", s.events_lost}});
        return {{"sessions", arr}, {"count", arr.size()}};
    }
    if (action == "kernel_callbacks") {
        auto r = detect::enumerate_kernel_callbacks();
        if (!r.ok) fail(r.error);
        json arr = json::array();
        for (const auto& e : r.entries)
            arr.push_back({{"kind", e.kind}, {"slot", e.slot},
                           {"handler", e.handler}});
        return {{"callbacks", arr}, {"count", arr.size()}};
    }

    fail("detect: unknown action (hidden_modules|minifilters|etw_sessions|"
         "kernel_callbacks)");
}

// tool: fs

json tool_fs(const json& args) {
    const std::string action = require_action(args);

    if (action == "read_file") {
        if (!args.contains("path")) fail("missing path");
        std::vector<uint8_t> bytes;
        std::string err;
        const size_t cap =
            std::min<size_t>(args.value("max_bytes", 262144u), 4u << 20);
        if (!util::read_file(args.at("path").get<std::string>(), &bytes,
                             cap, &err))
            fail(err);
        json out = {{"path", args.at("path")},
                    {"bytes", bytes.size()},
                    {"hex", to_hex(bytes.data(),
                                   std::min<size_t>(bytes.size(), 8192))}};
        // text preview when it looks printable
        std::string text(reinterpret_cast<const char*>(bytes.data()),
                         std::min<size_t>(bytes.size(), 4096));
        out["text"] = text;
        return out;
    }
    if (action == "write_file") {
        if (!args.contains("path")) fail("missing path");
        std::vector<uint8_t> bytes;
        if (args.contains("hex"))
            bytes = hex_decode(args.at("hex").get<std::string>());
        else if (args.contains("text")) {
            // bind once, two get calls make two different strings and thats ub
            const std::string text = args.at("text").get<std::string>();
            bytes.assign(text.begin(), text.end());
        }
        std::string err;
        if (!util::write_file(args.at("path").get<std::string>(), bytes,
                              args.value("append", false), &err))
            fail(err);
        return {{"written", bytes.size()}, {"path", args.at("path")}};
    }
    if (action == "list_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        auto items = util::list_directory(
            args.at("path").get<std::string>(), &err);
        if (!items.empty() || err.empty()) {
            json arr = json::array();
            for (const auto& e : items)
                arr.push_back({{"name", e.name}, {"size", e.size},
                               {"directory", e.directory}});
            return {{"entries", arr}, {"count", arr.size()}};
        }
        fail(err);
    }
    if (action == "create_directory") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::create_directory(args.at("path").get<std::string>(),
                                    &err))
            fail(err);
        return {{"created", true}};
    }
    if (action == "delete_path") {
        if (!args.contains("path")) fail("missing path");
        std::string err;
        if (!util::delete_path(args.at("path").get<std::string>(), &err))
            fail(err);
        return {{"deleted", true}};
    }
    if (action == "search_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::search_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            std::min<size_t>(args.value("limit", 200u), 2000u));
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"size", h.size},
                           {"directory", h.directory}});
        return {{"matches", arr}, {"count", arr.size()}};
    }
    if (action == "grep_in_files") {
        if (!args.contains("root") || !args.contains("needle"))
            fail("missing root/needle");
        auto hits = util::grep_in_files(
            args.at("root").get<std::string>(),
            args.at("needle").get<std::string>(),
            args.value("suffix", std::string{}),
            std::min<size_t>(args.value("limit", 200u), 2000u));
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"path", h.path}, {"line", h.line},
                           {"text", h.text}});
        return {{"hits", arr}, {"count", arr.size()}};
    }

    fail("fs: unknown action (read_file|write_file|list_directory|"
         "create_directory|delete_path|search_files|grep_in_files)");
}

// tool: web

json tool_web(const json& args) {
    const std::string action = require_action(args);

    if (action == "fetch" || action == "post") {
        if (!args.contains("url")) fail("missing url");
        std::string err;
        const int timeout =
            std::min(args.value("timeout_ms", 15000), 60000);
        std::optional<util::http_response_t> resp;
        if (action == "fetch")
            resp = util::http_get(args.at("url").get<std::string>(), timeout,
                                  &err);
        else {
            if (!args.contains("body")) fail("missing body");
            resp = util::http_post(
                args.at("url").get<std::string>(),
                args.at("body").get<std::string>(),
                args.value("content_type", std::string{"application/json"}),
                timeout, &err);
        }
        if (!resp) fail(err);
        const size_t body_cap =
            std::min<size_t>(resp->body.size(), 65536);
        return {{"status", resp->status},
                {"content_type", resp->content_type},
                {"bytes", resp->body.size()},
                {"text", resp->body.substr(0, body_cap)}};
    }

    fail("web: unknown action (use fetch or post)");
}

// tool: decomp

// turns text like mov rax, [rbx+8] into an encoder request
std::string assemble_one(const std::string& text, uint64_t addr,
                         ZydisEncoderRequest& out) {
    out = {};
    out.machine_mode = ZYDIS_MACHINE_MODE_LONG_64;
    out.allowed_encodings = ZYDIS_ENCODABLE_ENCODING_DEFAULT;

    // split on spaces and commas
    std::vector<std::string> tokens;
    std::string cur;
    for (char ch : text + ",") {
        if (ch == ' ' || ch == ',' || ch == '\t') {
            if (!cur.empty()) tokens.push_back(cur);
            cur.clear();
        } else if (ch == '[' || ch == ']') {
            if (!cur.empty()) tokens.push_back(cur);
            cur.clear();
            tokens.push_back(std::string(1, ch));
        } else {
            cur += static_cast<char>(std::tolower(
                static_cast<unsigned char>(ch)));
        }
    }
    if (tokens.empty()) return "empty instruction";

    // mnemonic lookup
    bool mn_found = false;
    for (int m = 1; m < ZYDIS_MNEMONIC_MAX_VALUE; ++m) {
        const auto mm = static_cast<ZydisMnemonic>(m);
        const char* s = ZydisMnemonicGetString(mm);
        if (s && _stricmp(s, tokens[0].c_str()) == 0) {
            out.mnemonic = mm;
            mn_found = true;
            break;
        }
    }
    if (!mn_found) return "unknown mnemonic '" + tokens[0] + "'";

    // register lookup
    auto find_reg = [](const std::string& n, ZydisRegister* r) {
        for (int i = 1; i < ZYDIS_REGISTER_MAX_VALUE; ++i) {
            const auto rr = static_cast<ZydisRegister>(i);
            const char* s = ZydisRegisterGetString(rr);
            if (s && _stricmp(s, n.c_str()) == 0) { *r = rr; return true; }
        }
        return false;
    };

    size_t ti = 1;
    while (ti < tokens.size() &&
           out.operand_count < ZYDIS_MAX_OPERAND_COUNT) {
        const std::string& t = tokens[ti];
        if (t == "[") {
            // memory operand like [base + index*scale + disp]
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_MEMORY;
            op.mem.base = ZYDIS_REGISTER_NONE;
            op.mem.index = ZYDIS_REGISTER_NONE;
            op.mem.scale = 1;
            op.mem.displacement = 0;
            ++ti;
            while (ti < tokens.size() && tokens[ti] != "]") {
                ZydisRegister r = ZYDIS_REGISTER_NONE;
                int64_t sign = 1;
                bool handled = false;
                if (tokens[ti] == "+") { sign = 1; ti++; handled = true; }
                else if (tokens[ti] == "-") { sign = -1; ti++; handled = true; }
                if (!handled && find_reg(tokens[ti], &r)) {
                    if (r == ZYDIS_REGISTER_RIP) {
                        op.mem.base = ZYDIS_REGISTER_RIP;
                        op.mem.displacement =
                            static_cast<int64_t>(addr);
                    } else if (op.mem.base == ZYDIS_REGISTER_NONE)
                        op.mem.base = r;
                    else {
                        op.mem.index = r;
                    }
                    ti++;
                } else {
                    const uint64_t v =
                        std::strtoull(tokens[ti].c_str(), nullptr, 0);
                    op.mem.displacement +=
                        sign * static_cast<int64_t>(v);
                    ti++;
                }
                if (ti < tokens.size() && tokens[ti] == "*") {
                    ti++;
                    if (ti < tokens.size())
                        op.mem.scale = static_cast<uint32_t>(
                            std::strtoul(tokens[ti++].c_str(), nullptr, 0));
                }
            }
            if (ti < tokens.size()) ++ti;   // consume ']'
            continue;
        }

        ZydisRegister r = ZYDIS_REGISTER_NONE;
        if (find_reg(t, &r)) {
            ZydisEncoderOperand& op =
                out.operands[out.operand_count++];
            op.type = ZYDIS_OPERAND_TYPE_REGISTER;
            op.reg.value = r;
            ++ti;
            continue;
        }

        // immediate
        ZydisEncoderOperand& op = out.operands[out.operand_count++];
        op.type = ZYDIS_OPERAND_TYPE_IMMEDIATE;

        op.imm.u = std::strtoull(t.c_str(), nullptr, 0);
        op.imm.s = static_cast<int64_t>(op.imm.u);
        ++ti;
    }

    // the encoder picks the visibility defaults

    return "";
}

json tool_decomp(const json& args) {
    const std::string action = require_action(args);
    if (action != "function") fail("decomp: unknown action");

    const uint64_t va = parse_addr(args, "addr");

    // wait for analysis without holding the lock, fail soft so the agent can poll
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::seconds(10);
        for (;;) {
            {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                if (!bin0.ready)
                    fail("no image loaded in reverse-slop (see disasm.loaded)");
                if (!bin0.hype) fail("hyperion engine unavailable for this image");
                if (bin0.hype->ready()) break;
                // cancelled or failed means waiting is pointless
                const std::string herr = bin0.hype->error();
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                std::lock_guard lk(ds::state_mutex());
                auto& bin0 = ds::get();
                const std::string herr =
                    bin0.hype ? bin0.hype->error() : std::string{};
                if (!herr.empty())
                    fail("hyperion analysis not running, " + herr +
                         " (re-run disasm.load to restart)");
                fail("hyperion analysis in progress (" +
                     std::to_string(static_cast<int>(bin0.hype
                         ? bin0.hype->progress() * 100 : 0)) +
                     "%), retry shortly");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    std::lock_guard lk(ds::state_mutex());
    auto& bin = ds::get();
    if (!bin.ready) fail("no image loaded in reverse-slop (see disasm.loaded)");
    if (!bin.hype) fail("hyperion engine unavailable for this image");

    const bool annotate_bytes = args.value("annotate_bytes", false);

    const hype::Function* f = bin.hype->function_at(va);
    if (!f) fail("no hyperion function contains address " + hex64(va));
    const uint64_t entry = f->entry;

    std::vector<hype::PseudoLine> lines;
    std::string err;
    if (!bin.hype->decompile(va, lines, err)) fail(err);

    // rebuild the stack var table since the emitter inlines them into expressions
    struct var_rec { int64_t off; std::string name; uint32_t width; };
    std::map<int64_t, var_rec> vars;
    for (const auto& [bstart, bb] : f->blocks) {
        (void)bstart;
        for (const auto& in : bb.insns) {
            for (uint8_t i = 0; i < in.op_count; ++i) {
                const auto& op = in.ops[i];
                if (op.type != hype::OpType::Mem) continue;
                const auto base = static_cast<ZydisRegister>(op.mem.base);
                if (base != ZYDIS_REGISTER_RSP && base != ZYDIS_REGISTER_RBP)
                    continue;
                const auto it = vars.find(op.mem.disp);
                if (it == vars.end()) {
                    const bool arg = (base == ZYDIS_REGISTER_RSP &&
                                      op.mem.disp > 0);
                    vars.emplace(op.mem.disp, var_rec{
                        op.mem.disp,
                        (arg ? "arg_" : "var_") +
                            std::to_string(std::abs(op.mem.disp)),
                        op.size});
                }
            }
        }
    }

    json jvars = json::array();
    for (const auto& [off, v] : vars)
        jvars.push_back({{"name", v.name}, {"stack_offset", off},
                         {"width", v.width}});

    // name precedence is user symbol, hyperion name, then sub_rva
    std::string fname;
    if (const auto* sym = ds::symbol_for(entry); sym && *sym)
        fname = sym;
    else {
        const auto nit = bin.hype->db().names.find(entry);
        if (nit != bin.hype->db().names.end()) fname = nit->second;
    }
    const uint64_t img_base = bin.hype->db().image_base
                                  ? bin.hype->db().image_base
                                  : bin.base;
    if (fname.empty())
        fname = "sub_" + hex64(entry - img_base);

    // rename the body to match the signature so they agree
    const std::string sub_name = "sub_" + hex64(entry - img_base);
    const std::string emitter_name = [&] {
        const auto nit = bin.hype->db().names.find(entry);
        return nit != bin.hype->db().names.end() ? nit->second : sub_name;
    }();
    auto rename_fn = [&](const std::string& text) {
        if (emitter_name.size() < 3 || sub_name.size() < 3)
            return text;
        std::string out = text;
        const auto idch = [](char c) {
            return std::isalnum(static_cast<unsigned char>(c)) || c == '_';
        };
        for (const std::string& from : {emitter_name, sub_name}) {
            if (from == fname || from.size() < 3) continue;
            size_t pos = 0;
            while ((pos = out.find(from, pos)) != std::string::npos) {
                const size_t end = pos + from.size();
                const bool word = (pos == 0 || !idch(out[pos - 1])) &&
                                  (end >= out.size() || !idch(out[end]));
                if (word) {
                    out.replace(pos, from.size(), fname);
                    pos += fname.size();
                } else {
                    pos = end;
                }
            }
        }
        return out;
    };

    json jlines = json::array();
    size_t insn_count = 0;
    for (const auto& l : lines) {
        if (l.addr) ++insn_count;
        if (annotate_bytes && l.addr) {
            // prefix each line with its va
            std::ostringstream text;
            text << std::hex << std::uppercase << l.addr << std::dec << ": "
                 << rename_fn(l.text);
            jlines.push_back({{"va", l.addr}, {"text", text.str()}});
        } else {
            jlines.push_back({{"va", l.addr},
                              {"text", std::string(l.indent * 2, ' ') +
                                           rename_fn(l.text)}});
        }
    }

    std::string signature;
    {
        const auto it = bin.hype->db().signatures.find(entry);
        if (it != bin.hype->db().signatures.end()) {
            const auto& s = it->second;
            signature = s.return_type + " " + fname + "(";
            for (size_t i = 0; i < s.param_names.size(); ++i) {
                if (i) signature += ", ";
                signature += s.param_types[i] + " " + s.param_names[i];
            }
            signature += ")";
        } else {
            signature = "void " + fname + "()";
        }
    }

    return {{"ok", true},
            {"engine", "hyperion"},
            {"signature", signature},
            {"function_va", entry},
            {"insn_count", insn_count},
            {"vars", jvars},
            {"lines", jlines}};
}

// tool: persist

json tool_persist(const json& args) {
    const std::string action = require_action(args);

    // one store per process, opened on first use
    static persist::session_store_t store;
    static bool store_open = false;
    if (!store_open) {
        std::string err;
        if (!store.open(persist::default_store_path(), &err))
            fail("store open failed: " + err);
        store_open = true;
    }

    if (action == "save") {
        if (!args.contains("name") || !args.contains("data"))
            fail("missing name/data");
        auto id = store.save_session(args.at("name").get<std::string>(),
                                     args.at("data").dump());
        if (!id) fail("save failed");
        return {{"saved", true}, {"id", *id}};
    }
    if (action == "list") {
        json arr = json::array();
        for (const auto& m : store.list_sessions())
            arr.push_back({{"id", m.id}, {"name", m.name},
                           {"created_at", m.created_at}});
        return {{"sessions", arr}, {"count", arr.size()}};
    }
    if (action == "load") {
        auto row = store.load_session(parse_addr(args, "id"));
        if (!row) fail("unknown session id");
        json data = json::parse(row->data, nullptr, false);
        return {{"id", row->id}, {"name", row->name},
                {"created_at", row->created_at},
                {"data", data.is_discarded() ? json(row->data) : data}};
    }
    if (action == "delete") {
        if (!store.delete_session(parse_addr(args, "id")))
            fail("unknown session id");
        return {{"deleted", true}};
    }
    if (action == "kv_set") {
        if (!args.contains("key") || !args.contains("value"))
            fail("missing key/value");
        const json& v = args.at("value");
        const std::string text =
            v.is_string() ? v.get<std::string>() : v.dump();
        if (!store.kv_set(args.at("key").get<std::string>(), text))
            fail("kv_set failed");
        return {{"set", true}};
    }
    if (action == "kv_get") {
        auto v = store.kv_get(args.value("key", ""));
        if (!v) fail("no value for key");
        json parsed = json::parse(*v, nullptr, false);
        return {{"value", parsed.is_discarded() ? json(*v) : parsed}};
    }

    // hyperion project files
    // the format keeps names comments xrefs and types, load merges the names and comments back

    if (action == "hype_save") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to write)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded (see disasm.loaded)");
        hype::Database dbio;
        const std::string dir = args.at("dir").get<std::string>();
        if (!dbio.save(dir, bin.hype->image(), bin.hype->db()))
            fail("save failed (writable dir?)");
        return {{"ok", true}, {"dir", dir},
                {"names", bin.hype->db().names.size()},
                {"comments", bin.hype->db().comments.size()},
                {"xrefs", bin.hype->db().xrefs.size()}};
    }
    if (action == "hype_load") {
        if (!args.contains("dir") || !args.at("dir").is_string())
            fail("missing dir (project directory to read)");
        std::lock_guard lk(ds::state_mutex());
        auto& bin = ds::get();
        if (!bin.ready || !bin.hype || !bin.hype->ready())
            fail("no analyzed image loaded to merge into (see disasm.loaded)");
        const std::string dir = args.at("dir").get<std::string>();
        hype::PEImage  img;
        hype::AnalysisDB loaded;
        hype::Database dbio;
        if (!dbio.load(dir, img, loaded)) fail("load failed (missing meta.bin?)");
        auto& db = bin.hype->db_mut();
        size_t names = 0, comments = 0;
        for (const auto& [va, n] : loaded.names) {
            db.names[va] = n;
            ++names;
        }
        for (const auto& [va, c] : loaded.comments) {
            db.comments[va] = c;
            ++comments;
        }
        return {{"ok", true}, {"dir", dir},
                {"merged_names", names}, {"merged_comments", comments}};
    }

    fail("persist: unknown action (save|list|load|delete|kv_set|kv_get|"
         "hype_save|hype_load)");
}

// tool: re

json tool_re(const json& args) {
    const std::string action = require_action(args);

    // app loaded binary unless a path is given
    std::optional<ds::binary_lock_t> shared_lock;
    disasm::pe_image_t const*   pe   = nullptr;
    std::vector<uint8_t> const* file = nullptr;
    disasm::function_index_t*   fidx = nullptr;
    disasm::xref_index_t*       xidx = nullptr;
    uint64_t                    session_base = 0;   // VA base of the source
    const hype::AnalysisDB*     hdb  = nullptr;     // hyperion DB when analyzed

    if (args.contains("path") && args.at("path").is_string()) {
        auto& img = load_image(args.at("path").get<std::string>());
        pe = &img.pe; file = &img.file; fidx = &img.fidx; xidx = &img.xidx;
        session_base = pe->image_base;
        // build the indexes lazily for explicit paths
        if (action == "danger" || action == "libsig") {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!img.fidx_ok) {
                if (!fidx->build(*pe, *file, eng, session_base))
                    fail("function index build failed");
                img.fidx_ok = true;
            }
            if (!img.xidx_ok) {
                if (!xidx->build(*pe, *file, eng, session_base))
                    fail("xref index build failed");
                img.xidx_ok = true;
            }
        }
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        pe = &bin.pe; file = &bin.file; fidx = &bin.fns; xidx = &bin.xrefs;
        session_base = bin.base;
        if (bin.hype && bin.hype->ready()) hdb = &bin.hype->db();
        // legacy indexes go stale after patches until rebuilt, hyperion is fine
    }
    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base")
        : session_base;
    (void)base;

    if (action == "rtti_scan") {
        // hyperion rtti beats the quick scanner when its ready
        // the lock above already pins the session
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                const auto& classes = bin.hype->rtti().classes();
                json arr = json::array();
                for (const auto& c : classes) {
                    json methods = json::array();
                    for (auto m : c.methods) methods.push_back(m);
                    arr.push_back({{"name", c.demangled_name.empty()
                                                ? c.mangled_name
                                                : c.demangled_name},
                                   {"mangled", c.mangled_name},
                                   {"td_va", c.type_descriptor},
                                   {"vtable_va", c.vtable},
                                   {"methods", methods},
                                   {"method_count", c.methods.size()}});
                }
                return {{"engine", "hyperion"}, {"classes", arr},
                        {"count", arr.size()}};
            }
        }
        auto r = re::rtti_scan(*pe, *file);
        json arr = json::array();
        for (const auto& c : r.classes) {
            json vfs = json::array();
            for (auto v : c.vftables) vfs.push_back(v);
            arr.push_back({{"name", c.name}, {"td_va", c.td_va},
                           {"vftables", vfs}});
        }
        return {{"classes", arr}, {"count", arr.size()},
                {"scanned_bytes", r.scanned_bytes}};
    }
    if (action == "vftable") {
        if (!args.contains("path")) {
            auto& bin = ds::get();
            if (bin.ready && bin.hype && bin.hype->ready()) {
                // serve from the db when the address is indexed
                const uint64_t vva = parse_addr(args, "addr");
                for (const auto& vt : bin.hype->db().vtables) {
                    if (vt.addr != vva) continue;
                    json arr = json::array();
                    for (auto e : vt.entries) arr.push_back(e);
                    return {{"engine", "hyperion"}, {"vftable_va", vva},
                            {"targets", arr}, {"count", arr.size()}};
                }
                // raw read for everything else
            }
        }
        if (!args.contains("addr")) fail("missing addr");
        const uint64_t va = parse_addr(args, "addr");
        auto slots = re::read_vftable(
            *pe, *file, va,
            static_cast<size_t>(std::min<uint64_t>(
                args.contains("slots") ? parse_addr(args, "slots") : 32,
                256)));
        if (!slots) fail("vftable not readable in image");
        json arr = json::array();
        for (auto v : *slots) arr.push_back(v);
        return {{"vftable_va", va}, {"targets", arr},
                {"count", arr.size()}};
    }
    if (action == "danger") {
        // hyperion knows the iat refs, the legacy index covers explicit paths
        auto hits = analysis::danger_scan(
            *pe,
            [xidx, hdb](uint64_t target_va) {
                std::vector<uint64_t> out;
                if (hdb) {
                    // one instruction can emit two records, dedupe by from
                    std::set<uint64_t> seen;
                    const auto it = hdb->xrefs_to.find(target_va);
                    if (it != hdb->xrefs_to.end())
                        for (const auto& x : it->second)
                            if (seen.insert(x.from).second)
                                out.push_back(x.from);
                    return out;
                }
                for (const auto& r : xidx->refs_to(target_va))
                    out.push_back(r.from);
                return out;
            },
            session_base);
        json arr = json::array();
        for (const auto& h : hits) {
            json cs = json::array();
            for (auto c : h.callsites) cs.push_back(c);
            arr.push_back({{"function", h.function},
                           {"category", h.category},
                           {"iat_va", h.iat_va},
                           {"callsites", cs},
                           {"count", cs.size()}});
        }
        return {{"hits", arr}, {"count", arr.size()}};
    }
    if (action == "libsig") {
        if (!args.contains("sigset")) fail("missing sigset JSON");
        std::string sig_err;
        auto sigs = analysis::parse_sig_set(
            args.at("sigset").get<std::string>(), &sig_err);
        if (!sigs) fail(sig_err.empty() ? "bad sigset" : sig_err);
        auto hits = analysis::libsig_scan(*pe, *file, *fidx, *sigs);
        json arr = json::array();
        for (const auto& h : hits) {
            json o = {{"name", h.sig_name}, {"va", h.va}};
            if (h.function_va) o["function_va"] = *h.function_va;
            arr.push_back(std::move(o));
        }
        return {{"hits", arr}, {"count", arr.size()},
                {"requested", sigs->size()}};
    }

    fail("re: unknown action (rtti_scan|vftable|danger|libsig)");
}

// tool: xray

json tool_xray(const json& args) {
    const std::string action = require_action(args);

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;
    const disasm::pe_image_t*   pe   = nullptr;
    const std::vector<uint8_t>* file = nullptr;
    uint64_t default_base = 0;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        pe = &cache.pe; file = &cache.file;
        default_base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
        // path images get a function index too since the per function analyses need bounds
        static disasm::function_index_t path_fns;   // guarded by g_tool_mu
        static std::string             path_fns_for;
        if (path_fns_for != cache.path) {
            auto& eng = shared_engine();
            if (!eng.ok() && !eng.init()) fail("zydis engine init failed");
            if (!path_fns.build(cache.pe, cache.file, eng, default_base))
                fail("function index build failed");
            path_fns_for = cache.path;
        }
        img.fns = &path_fns;
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        pe = &bin.pe; file = &bin.file;
        default_base = bin.base;
        img_name = bin.name;
        img.fns = &bin.fns;
    }
    img.pe = pe; img.file = file; img.base = default_base;

    auto& engine = shared_engine();
    if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
    img.eng = &engine;

    const uint64_t base = args.contains("base")
        ? parse_addr(args, "base") : default_base;
    (void)base;

    json out;
    out["image"] = img_name;

    if (action == "cfg" || action == "complexity" || action == "cff" ||
        action == "obfuscation" || action == "strings_recon" ||
        action == "indirect_calls" || action == "anti_analysis") {
        const uint64_t fn_va = parse_addr(args, "addr");

        if (action == "cfg" || action == "complexity") {
            auto r = xray::build_cfg(img, fn_va);
            if (!r.ok) fail(r.error);
            if (action == "cfg") {
                json blocks = json::array();
                for (const auto& b : r.blocks)
                    blocks.push_back({{"start", b.start}, {"end", b.end},
                                      {"instructions", b.instructions},
                                      {"successors", b.successors}});
                out["blocks"] = blocks;
                out["block_count"] = r.blocks.size();
            } else {
                auto c = xray::function_complexity(img, fn_va);
                out["instruction_count"]  = c.instruction_count;
                out["basic_block_count"]  = c.basic_block_count;
                out["edge_count"]         = c.edge_count;
                out["cyclomatic_complexity"] = c.cyclomatic;
                out["call_count"]      = c.call_count;
                out["branch_count"]    = c.branch_count;
                out["return_count"]    = c.return_count;
                out["arithmetic_ops"]  = c.arithmetic_ops;
                out["memory_accesses"] = c.memory_accesses;
                out["string_operations"] = c.string_operations;
                out["unique_operators"] = c.unique_operators;
                out["unique_operands"]  = c.unique_operands;
                out["complexity_rating"] = c.rating;
            }
            out["edge_count"] = r.edge_count;
            out["back_edges"] = r.back_edges;
            out["cyclomatic_complexity"] = r.cyclomatic;
            return out;
        }

        if (action == "cff") {
            auto r = xray::detect_cff(img, fn_va);
            out["flattened"] = r.flattened;
            out["block_count"] = r.block_count;
            if (r.flattened) {
                out["dispatcher"] = r.dispatcher;
                out["dispatcher_backedges"] = r.dispatcher_backedges;
                out["state_variable"] = r.state_var_desc;
                json sbs = json::array();
                for (const auto& sb : r.state_blocks)
                    sbs.push_back({{"start", sb.start}, {"end", sb.end},
                                   {"next_state", sb.has_next ? json(sb.next_state) : json()},
                                   {"assign_addr", sb.assign_addr}});
                out["state_blocks"] = sbs;
                out["state_block_count"] = r.state_blocks.size();
            }
            return out;
        }

        if (action == "obfuscation") {
            // report a diagnostic when nothing decodes instead of a wall of zeros
            auto r = xray::detect_obfuscation(img, fn_va);
            json pats = json::array();
            for (const auto& p : r.patterns)
                pats.push_back({{"type", p.type}, {"address", p.address},
                                {"detail", p.detail}});
            out["patterns"] = pats;
            out["opaque_predicates"] = r.opaque_predicates;
            out["dead_heads"] = r.dead_heads;
            out["junk_sequences"] = r.junk_sequences;
            out["indirect_jumps"] = r.indirect_jumps;
            out["push_ret"] = r.push_ret;
            out["obfuscation_score_pct"] = r.score_pct;
            // check it actually decoded
            auto probe = xray::decode_range(img, fn_va, 4);
            if (probe.empty()) {
                out["warning"] = "no instructions decoded at addr, region may be "
                                 "compressed/encrypted data; obfuscation analysis "
                                 "requires decodable code";
            }
            return out;
        }

        if (action == "strings_recon") {
            auto hits = xray::string_decrypt_recon(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"type", h.type}, {"address", h.address}};
                if (!h.reconstructed.empty()) o["reconstructed"] = h.reconstructed;
                if (h.xor_key) o["xor_key"] = h.xor_key;
                o["length"] = h.length;
                arr.push_back(std::move(o));
            }
            out["candidates"] = arr;
            out["count"] = arr.size();
            return out;
        }

        if (action == "indirect_calls") {
            auto hits = xray::indirect_calls(img, fn_va);
            json arr = json::array();
            for (const auto& h : hits) {
                json o = {{"address", h.address}, {"text", h.text},
                          {"classification", h.classification}};
                if (!h.base_register.empty()) {
                    o["base_register"] = h.base_register;
                    o["offset"] = h.offset;
                }
                if (h.target) o["target"] = h.target;
                arr.push_back(std::move(o));
            }
            out["indirect_calls"] = arr;
            out["total"] = arr.size();
            return out;
        }

        // anti_analysis
        auto r = xray::detect_anti_analysis(img, fn_va);
        json dets = json::array();
        for (const auto& d : r.detections)
            dets.push_back({{"type", d.type}, {"address", d.address},
                            {"detail", d.detail}});
        out["detections"] = dets;
        out["anti_debug"] = r.anti_debug;
        out["anti_vm"] = r.anti_vm;
        out["timing_checks"] = r.timing_checks;
        out["traps"] = r.traps;
        out["anti_analysis_score_pct"] = r.score_pct;
        return out;
    }

    if (action == "hooks") {
        const size_t maxf = std::min<size_t>(args.value("max_functions", 500u), 10000u);
        auto hits = xray::detect_hooks(img, maxf);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"address", h.address}, {"hook_type", h.hook_type},
                           {"target", h.target}, {"prologue_bytes", h.prologue_hex}});
        out["functions_checked"] = std::min<size_t>(img.fns ? img.fns->functions().size() : 0, maxf);
        out["hooks_found"] = hits.size();
        out["hooks"] = arr;
        return out;
    }

    if (action == "syscalls") {
        uint64_t va = args.contains("addr") ? parse_addr(args, "addr") : 0;
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size")) : 0;
        auto hits = xray::detect_syscalls(img, va, size);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"address", h.address}, {"syscall_number", h.ssn},
                           {"pattern", h.pattern}});
        out["syscalls_found"] = hits.size();
        out["syscalls"] = arr;
        return out;
    }

    if (action == "apihash") {
        std::vector<uint64_t> hashes;
        auto push_hash = [](std::vector<uint64_t>& v, const json& h) {
            if (h.is_string()) v.push_back(std::stoull(h.get<std::string>(), nullptr, 0));
            else if (h.is_number_unsigned()) v.push_back(h.get<uint64_t>());
            else if (h.is_number_integer() && h.get<int64_t>() >= 0)
                v.push_back(static_cast<uint64_t>(h.get<int64_t>()));
            else fail("bad hash value");
        };
        if (args.contains("hashes") && args.at("hashes").is_array())
            for (const auto& h : args.at("hashes")) push_hash(hashes, h);
        else {
            if (!args.contains("hash")) fail("missing hash/hashes");
            push_hash(hashes, args.at("hash"));
        }
        std::string algo = args.value("algorithm", std::string{"ror13"});
        auto hits = xray::resolve_api_hashes(img, hashes, algo);
        if (algo != "ror13" && algo != "djb2" && algo != "crc32" &&
            algo != "fnv1a" && algo != "sdbm")
            fail("bad algorithm (ror13|djb2|crc32|fnv1a|sdbm)");
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"hash", h.hash}, {"api", h.api}, {"dll", h.dll}});
        out["algorithm"] = algo;
        out["total_queried"] = hashes.size();
        out["resolved_count"] = arr.size();
        out["resolved"] = arr;
        return out;
    }

    if (action == "entropy" || action == "pages" || action == "crypto_range") {
        const uint64_t va = parse_addr(args, "addr");
        const size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size")) : 4096;

        if (action == "entropy") {
            const size_t window = args.contains("window_size")
                ? static_cast<size_t>(parse_addr(args, "window_size")) : 256;
            // honor a limit, zero means summary only
            const size_t win_limit = args.value("window_limit", size_t{64});
            auto r = xray::entropy_scan(img, va, size, window);
            out["overall_entropy"] = r.overall;
            out["min_window_entropy"] = r.min_window;
            out["max_window_entropy"] = r.max_window;
            out["window_size"] = window;
            out["verdict"] = r.verdict;
            out["truncated"] = r.truncated;
            out["total_windows"] = r.windows.size();
            json wins = json::array();
            if (win_limit > 0) {
                for (size_t i = 0; i < r.windows.size() && i < win_limit; ++i) {
                    const auto& w = r.windows[i];
                    wins.push_back({{"offset", w.offset}, {"entropy", w.entropy},
                                    {"verdict", w.verdict}});
                }
            }
            out["windows"] = wins;
            return out;
        }
        if (action == "pages") {
            const size_t ps = args.contains("page_size")
                ? static_cast<size_t>(parse_addr(args, "page_size")) : 4096;
            auto pages = xray::classify_pages(img, va, size, ps);
            json arr = json::array();
            json summary = {{"code", 0}, {"data", 0}, {"encrypted", 0},
                            {"padding", 0}, {"mixed", 0}};
            auto bump = [&summary](const char* k) {
                summary[k] = summary[k].get<int>() + 1;
            };
            for (const auto& p : pages) {
                arr.push_back({{"address", p.address}, {"size", p.size},
                               {"class", p.klass}, {"entropy", p.entropy},
                               {"insn_ratio", p.insn_ratio},
                               {"zero_ratio", p.zero_ratio},
                               {"string_ratio", p.string_ratio}});
                const std::string k = p.klass;
                if (k == "code") bump("code");
                else if (k == "padding") bump("padding");
                else if (k == "encrypted_or_compressed" ||
                         k == "single_byte_encrypted") bump("encrypted");
                else if (k == "mixed") bump("mixed");
                else bump("data");
            }
            out["total_pages"] = pages.size();
            out["summary"] = summary;
            out["pages"] = arr;
            return out;
        }
        // crypto_range
        const size_t limit = std::min<size_t>(args.value("limit", 256u), 1000u);
        auto hits = xray::crypto_range(img, va, size, limit);
        json arr = json::array();
        for (const auto& h : hits)
            arr.push_back({{"va", h.va}, {"algorithm", h.algorithm},
                           {"constant", h.constant_name}, {"value", h.value},
                           {"source", h.source}});
        out["matches"] = arr;
        out["count"] = arr.size();
        return out;
    }

    if (action == "gadgets") {
        const size_t limit = std::min<size_t>(args.value("limit", 200u), 2000u);
        auto hits = xray::rop_gadgets(img, limit);
        json arr = json::array();
        for (const auto& g : hits)
            arr.push_back({{"address", g.address}, {"text", g.text}});
        out["gadgets"] = arr;
        out["count"] = arr.size();
        return out;
    }

    fail("xray: unknown action (cfg|complexity|cff|obfuscation|strings_recon|"
         "indirect_calls|anti_analysis|hooks|syscalls|apihash|entropy|pages|"
         "crypto_range|gadgets)");
}

// tool: patch

json tool_patch(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    ds::binary_lock_t lk;
    auto& bin = ds::get();

    imgpatch::op_result_t r;

    if (action == "nop_junk") {
        const uint64_t fn_va = parse_addr(args, "addr");
        r = imgpatch::nop_junk(bin, fn_va,
                               args.value("aggressive", false),
                               static_cast<size_t>(args.value("nop_threshold", 4u)));
    } else if (action == "resolve_opaque") {
        r = imgpatch::resolve_opaque_predicates(bin, parse_addr(args, "addr"),
                                                args.value("dry_run", false));
    } else if (action == "patch_antidebug") {
        imgpatch::anti_debug_opts_t opts;
        opts.patch_api_calls = args.value("patch_api_calls", true);
        opts.patch_int_traps = args.value("patch_int_traps", true);
        opts.patch_timing    = args.value("patch_timing", true);
        r = imgpatch::patch_anti_debug(bin, parse_addr(args, "addr"), opts,
                                       args.value("dry_run", false));
    } else if (action == "unpack_xor") {
        const uint64_t va = parse_addr(args, "addr");
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size"))
            : 4096;
        r = imgpatch::unpack_xor(bin, va, size,
                                 args.value("method", std::string{"auto"}),
                                 args.value("key_hex", std::string{}));
    } else if (action == "decode_strings") {
        r = imgpatch::decode_strings(bin, parse_addr(args, "addr"));
    } else if (action == "write_bytes") {
        if (!args.contains("hex")) fail("missing hex payload");
        r = imgpatch::write_bytes(bin, parse_addr(args, "addr"),
                                  hex_decode(args.at("hex").get<std::string>()));
    } else if (action == "revert_all") {
        r = imgpatch::revert_all(bin);
    } else if (action == "journal") {
        json arr = json::array();
        const size_t cap = std::min<size_t>(args.value("limit", 100u), bin.patches.size());
        for (size_t i = 0; i < cap; ++i) {
            const auto& p = bin.patches[i];
            arr.push_back({{"va", p.va}, {"before", p.before}, {"after", p.after}});
        }
        return {{"patches", arr}, {"total", bin.patches.size()},
                {"indexes_dirty", bin.indexes_dirty}};
    } else if (action == "full_pass") {
        auto r = imgpatch::full_pass(bin, parse_addr(args, "addr"),
                                     args.value("dry_run", false));
        if (!r.ok) fail(r.error);
        json steps = json::array();
        for (const auto& s : r.steps)
            steps.push_back({{"step", s.name}, {"success", s.success},
                             {"note", s.note}});
        return {{"ok", true},
                {"dry_run", r.dry_run},
                {"steps", steps},
                {"pre_obfuscation_score", r.pre_score},
                {"post_obfuscation_score", r.post_score},
                {"score_reduction", r.pre_score - r.post_score},
                {"strings_found", r.strings_found},
                {"bytes_changed", r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    } else if (action == "rebuild") {
        auto r = imgpatch::rebuild(bin, parse_addr(args, "addr"));
        if (!r.ok) fail(r.error);
        json insns = json::array();
        for (const auto& [va, text] : r.insns)
            insns.push_back({{"va", va}, {"text", text}});
        return {{"ok", true},
                {"instruction_count", r.instruction_count},
                {"insns", insns},
                {"indexes_dirty", bin.indexes_dirty}};
    } else {
        fail("patch: unknown action (nop_junk|resolve_opaque|patch_antidebug|"
             "unpack_xor|decode_strings|write_bytes|revert_all|journal|"
             "full_pass|rebuild)");
    }

    if (!r.ok) fail(r.error);
    json pats = json::array();
    for (const auto& p : r.patches) {
        json o = {{"va", p.va}, {"action", p.action}};
        if (!p.detail.empty()) o["detail"] = p.detail;
        pats.push_back(std::move(o));
    }
    json out = {{"ok", true},
                {"dry_run", r.dry_run},
                {"patches", pats},
                {"bytes_changed", r.bytes_changed},
                {"journal_total", bin.patches.size()}};
    if (r.detected_key) {
        out["detected_key"] = r.detected_key;
        out["key_confidence"] = r.key_confidence;
    }
    if (r.strings_found) out["strings_found"] = r.strings_found;
    return out;
}

// tool: types

json struct_to_json(const re::type_catalog::struct_def_t& s) {
    json fields = json::array();
    for (const auto& f : s.fields)
        fields.push_back({{"name", f.name}, {"type", f.type},
                          {"offset", f.offset}, {"size", f.size},
                          {"array_count", f.array_count}});
    return {{"name", s.name}, {"size", s.size}, {"packed", s.packed},
            {"fields", fields}};
}

json enum_to_json(const re::type_catalog::enum_def_t& e) {
    json vals = json::array();
    for (const auto& [n, v] : e.values)
        vals.push_back({{"name", n}, {"value", v}});
    return {{"name", e.name}, {"underlying", e.underlying}, {"values", vals}};
}

json tool_types(const json& args) {
    namespace tc = re::type_catalog;
    const std::string action = require_action(args);

    if (action == "create_struct" || action == "declare") {
        std::string decl_text;
        if (args.contains("decl") && args.at("decl").is_string())
            decl_text = args.at("decl").get<std::string>();
        else if (args.contains("name") && args.at("name").is_string())
            decl_text = "struct " + args.at("name").get<std::string>() + " {};";

        tc::decl_parse_result_t pr = tc::parse_decls(decl_text);
        if (!pr.error.empty()) fail(pr.error);
        size_t n = 0;
        std::string errs;
        for (auto& s : pr.structs)
            if (tc::create_struct(std::move(s), &errs)) ++n;
        for (auto& e : pr.enums)
            if (tc::create_enum(std::move(e), &errs)) ++n;
        if (n == 0) fail(errs.empty() ? "nothing declared" : errs);
        return {{"declared", n}};
    }

    if (action == "get_struct") {
        auto s = tc::get_struct(args.at("name").get<std::string>());
        if (!s) fail("unknown struct");
        return struct_to_json(*s);
    }
    if (action == "list_structs") {
        auto all = tc::list_structs(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& s : all) arr.push_back(struct_to_json(s));
        return {{"structs", arr}, {"count", arr.size()}};
    }
    if (action == "add_member") {
        tc::field_t f;
        f.name  = args.at("field").get<std::string>();
        f.type  = args.at("type").get<std::string>();
        f.array_count = static_cast<uint32_t>(args.value("array_count", 0u));
        std::string err;
        if (!tc::add_member(args.at("name").get<std::string>(), f, &err)) fail(err);
        auto s = tc::get_struct(args.at("name").get<std::string>());
        return struct_to_json(*s);
    }
    if (action == "remove_struct")
        return {{"removed", tc::remove_struct(args.at("name").get<std::string>())}};

    if (action == "create_enum") {
        tc::enum_def_t e;
        e.name = args.at("name").get<std::string>();
        e.underlying = args.value("underlying", std::string{"u32"});
        for (const auto& v : args.at("values")) {
            int64_t val = 0;
            const json& jv = v.contains("value") ? v.at("value") : json();
            if (jv.is_number_integer()) val = jv.get<int64_t>();
            else if (jv.is_string())    val = static_cast<int64_t>(std::stoull(jv.get<std::string>(), nullptr, 0));
            e.values.emplace_back(v.at("name").get<std::string>(), val);
        }
        std::string err;
        if (!tc::create_enum(std::move(e), &err)) fail(err);
        return {{"created", true}};
    }
    if (action == "get_enum") {
        auto e = tc::get_enum(args.at("name").get<std::string>());
        if (!e) fail("unknown enum");
        return enum_to_json(*e);
    }
    if (action == "list_enums") {
        auto all = tc::list_enums(args.value("filter", std::string{}));
        json arr = json::array();
        for (const auto& e : all) arr.push_back(enum_to_json(e));
        return {{"enums", arr}, {"count", arr.size()}};
    }
    if (action == "remove_enum")
        return {{"removed", tc::remove_enum(args.at("name").get<std::string>())}};

    if (action == "format_at") {
        // pretty print typed memory like MYSTRUCT @ 140001234
        if (!args.contains("addr")) fail("missing addr");
        if (!args.contains("type") && !args.contains("struct"))
            fail("missing type (struct or enum name)");
        const std::string type_name =
            args.value("type", args.value("struct", std::string{}));
        const uint64_t base = parse_addr(args, "addr");
        const size_t   want =
            static_cast<size_t>(args.value("size", 256u)) & 0xFFFF;

        // sync the catalog into a hyperion type system per call, theyre small
        hype::TypeSystem ts;
        std::unordered_map<std::string, uint32_t> ids;
        for (const auto& e : tc::list_enums()) {
            const uint32_t id = ts.add_enum(e.name);
            for (const auto& [n, v] : e.values) ts.add_member(id, n, v);
            ids[e.name] = id;
        }
        for (const auto& s : tc::list_structs()) {
            const uint32_t id = ts.add_struct(s.name,
                static_cast<uint32_t>(s.size ? s.size : 1));
            ids[s.name] = id;
        }
        // second pass so struct to struct references resolve
        for (const auto& s : tc::list_structs()) {
            for (const auto& f : s.fields) {
                uint32_t tid = 0;
                auto it = ids.find(f.type);
                if (it != ids.end()) {
                    tid = it->second;
                } else {
                    // map catalog names to hyperion builtins
                    static const std::unordered_map<std::string, const char*> prim = {
                        {"u8", "u8"}, {"u16", "u16"}, {"u32", "u32"}, {"u64", "u64"},
                        {"i8", "i8"}, {"i16", "i16"}, {"i32", "i32"}, {"i64", "i64"},
                        {"f32", "float"}, {"f64", "double"},
                        {"ptr", "ptr64"}, {"char", "char"},
                    };
                    auto pit = prim.find(f.type);
                    const char* pname = pit != prim.end() ? pit->second : "u8";
                    if (const auto* td = ts.find_by_name(pname)) tid = td->id;
                }
                ts.add_field(ids[s.name], f.name, tid,
                             static_cast<uint32_t>(f.offset));
            }
        }
        const auto* td = ts.find_by_name(type_name);
        if (!td) fail("unknown type: " + type_name);

        // live target when asked, else the file image
        std::vector<uint8_t> buf(want);
        std::string source = "file";
        bool got = false;
        if (args.value("live", false)) {
            if (auto sess = process::active_session(); sess && sess->valid()) {
                auto io = sess->read(static_cast<uintptr_t>(base), buf.data(),
                                     buf.size());
                if (io.ok && io.bytes) {
                    buf.resize(io.bytes);
                    got = true;
                    source = "live";
                }
            }
            if (!got) fail("live read failed (target attached?)");
        } else {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                if (auto off = bin.offset_of(base)) {
                    const size_t n = std::min(want, bin.file.size() - *off);
                    std::memcpy(buf.data(), bin.file.data() + *off, n);
                    buf.resize(n);
                    got = true;
                }
            }
            if (!got)
                fail("address not mapped in loaded image (load a binary or "
                     "pass live=true with a target attached)");
        }

        return {{"ok", true}, {"addr", base}, {"type", type_name},
                {"source", source},
                {"rendered", ts.format_at(base, td->id, buf.data(),
                                          buf.size())}};
    }

    if (action == "read_field") {
        auto s = tc::get_struct(args.at("struct").get<std::string>());
        if (!s) fail("unknown struct");
        const uint64_t base = parse_addr(args, "addr");

        // file image first, live memory when asked
        bool live = args.value("live", false);
        if (!live) {
            ds::binary_lock_t lk;
            auto& bin = ds::get();
            if (bin.ready) {
                auto off = bin.offset_of(base);
                if (off) {
                    auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                            0 /*offset already translated*/,
                                            bin.file.data() + *off,
                                            bin.file.size() - *off,
                                            nullptr, nullptr);
                    if (v.ok) return {{"ok", true}, {"hex", v.hex},
                                      {"uint", v.uint_val}, {"int", v.int_val},
                                      {"double", v.dbl_val}, {"source", "file"}};
                }
            }
        }
        auto sess = process::active_session();
        if (!live || !sess || !sess->valid())
            fail("no image data for that address (attach a target or use a mapped VA)");

        struct cb_ctx { runtime::session_t* s; } ctx{sess.get()};
        auto cb = [](uint64_t addr, void* dst, size_t len, void* user) -> bool {
            auto* c = static_cast<cb_ctx*>(user);
            auto io = c->s->read(static_cast<uintptr_t>(addr), dst, len);
            return io.ok && io.bytes == len;
        };
        auto v = tc::read_field(*s, args.at("field").get<std::string>(),
                                base, nullptr, 0, cb, &ctx);
        if (!v.ok) fail(v.error);
        return {{"ok", true}, {"hex", v.hex}, {"uint", v.uint_val},
                {"int", v.int_val}, {"double", v.dbl_val}, {"source", "target"}};
    }

    fail("types: unknown action (declare|create_struct|get_struct|list_structs|"
         "add_member|remove_struct|create_enum|get_enum|list_enums|remove_enum|"
         "read_field|format_at)");
}

// tool: notes

json tool_notes(const json& args) {
    const std::string action = require_action(args);
    if (!ds::has_binary()) fail("no image loaded in reverse-slop (see disasm.loaded)");

    if (action == "set_comment") {
        const uint64_t va = parse_addr(args, "addr");
        const std::string text = args.value("text", std::string{});
        ds::set_comment(va, text);          // saved, empty clears
        return {{"va", va}, {"cleared", text.empty()}};
    }
    if (action == "get_comment") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"comment", ds::comment_for(va)}};
    }
    if (action == "comments") {
        auto snaps = ds::comments_snapshot();
        std::sort(snaps.begin(), snaps.end());
        json arr = json::array();
        for (const auto& [va, text] : snaps)
            arr.push_back({{"va", va}, {"comment", text}});
        return {{"comments", arr}, {"count", arr.size()}};
    }
    if (action == "bookmark_toggle") {
        const uint64_t va = parse_addr(args, "addr");
        return {{"va", va}, {"bookmarked", ds::toggle_bookmark(va)}};
    }
    if (action == "bookmarks") {
        auto marks = ds::bookmarks_snapshot();
        std::sort(marks.begin(), marks.end());
        return {{"bookmarks", marks}, {"count", marks.size()}};
    }
    fail("notes: unknown action (set_comment|get_comment|comments|"
         "bookmark_toggle|bookmarks)");
}

// tool: devirt

json tool_devirt(const json& args) {
    const std::string action = require_action(args);

    const auto pe_json = [](const magicmida::pe_info_t& pe) {
        return json{{"ok", pe.ok}, {"arch", magicmida::arch_name(pe.arch)},
                    {"entry_rva", pe.entry_rva}, {"size_of_image", pe.size_of_image},
                    {"sections", pe.sections}, {"file_size", pe.file_size},
                    {"error", pe.error}};
    };
    const auto job_json = [&pe_json](const magicmida::job_t& job) {
        json out = {{"id", job.id}, {"state", magicmida::state_name(job.state)},
                    {"input_path", job.request.input_path},
                    {"requested_output_path", job.request.output_path}};
        if (job.state == magicmida::state_t::succeeded ||
            job.state == magicmida::state_t::failed ||
            job.state == magicmida::state_t::cancelled) {
            out["result"] = {{"ok", job.result.ok},
                             {"cancelled", job.result.cancelled},
                             {"timed_out", job.result.timed_out},
                             {"exit_code", job.result.exit_code},
                             {"duration_ms", job.result.duration_ms},
                             {"arch", magicmida::arch_name(job.result.arch)},
                             {"generated_path", job.result.generated_path},
                             {"output_path", job.result.output_path},
                             {"output", pe_json(job.result.output)},
                             {"warnings", job.result.warnings},
                             {"error", job.result.error}};
        }
        return out;
    };

    if (action == "themida_status") {
        const auto install = magicmida::installation();
        json running = json::array();
        for (const auto& job : magicmida::jobs()) running.push_back(job_json(job));
        return {{"engine", "Magicmida"}, {"version", "2026-05-14"},
                {"root", install.root}, {"x86_exe", install.x86_exe},
                {"x64_exe", install.x64_exe},
                {"x86_available", install.x86_available},
                {"x64_available", install.x64_available},
                {"x64_scyllahide_available", install.x64_scyllahide_available},
                {"jobs", std::move(running)}};
    }
    if (action == "themida_start") {
        const std::string path = args.value("path", std::string{});
        if (path.empty()) fail("themida_start requires 'path'");
        magicmida::request_t request;
        request.input_path = path;
        request.output_path = args.value("output_path", std::string{});
        request.timeout_ms = static_cast<uint32_t>(
            std::clamp(args.value("timeout_ms", 300000), 1000, 1800000));
        request.overwrite = args.value("overwrite", false);
        request.load_result = args.value("load", true);
        std::string error;
        const uint64_t id = magicmida::start(std::move(request), error);
        if (id == 0) fail(error);
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job was not registered");
        return job_json(job);
    }
    if (action == "themida_job") {
        const uint64_t id = parse_addr(args, "id");
        magicmida::job_t job;
        if (!magicmida::get_job(id, job)) fail("Themida job not found");
        return job_json(job);
    }
    if (action == "themida_cancel") {
        const uint64_t id = parse_addr(args, "id");
        return {{"id", id}, {"cancelled", magicmida::cancel(id)}};
    }

    // explicit path or the app loaded binary
    std::optional<ds::binary_lock_t> shared_lock;
    xray::image_ref_t img;
    std::string img_name;

    if (args.contains("path") && args.at("path").is_string()) {
        auto& cache = load_image(args.at("path").get<std::string>());
        img.pe = &cache.pe; img.file = &cache.file;
        img.base = cache.pe.image_base;
        const size_t slash = cache.path.find_last_of("\\/");
        img_name = (slash == std::string::npos) ? cache.path : cache.path.substr(slash + 1);
    } else {
        shared_lock.emplace();
        auto& bin = ds::get();
        if (!bin.ready)
            fail("no image: pass 'path' or load a binary in reverse-slop");
        img.pe = &bin.pe; img.file = &bin.file;
        img.base = bin.base;
        img_name = bin.name;
    }

    auto& engine = shared_engine();
    if (!engine.ok() && !engine.init()) fail("zydis engine init failed");
    img.eng = &engine;

    json out;
    out["image"] = img_name;

    // read only deobfuscation analysis

    if (action == "recover_cfg") {
        const uint64_t fn_va = parse_addr(args, "addr");
        const size_t runs = static_cast<size_t>(args.value("runs", 4));
        auto r = recover::recover_flattened(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["flattened"] = r.flattened;
        out["dispatcher"] = r.dispatcher;
        out["mode"] = r.mode;
        json edges = json::array();
        for (const auto& e : r.dispatch_map)
            edges.push_back({{"state", e.state}, {"target", e.target}});
        out["dispatch_map"] = edges;
        out["real_edges_recovered"] = r.real_edges_recovered;
        out["fake_edges"] = r.fake_edges;
        out["blocks"] = r.blocks;
        out["corroborated"] = r.corroborated;
        out["runs"] = r.runs;
        out["dispatcher_entries_observed"] = r.dispatcher_entries_observed;
        if (!r.note.empty()) out["note"] = r.note;
        return out;
    }

    if (action == "prove_predicates") {
        const uint64_t fn_va = parse_addr(args, "addr");
        const size_t runs = static_cast<size_t>(args.value("runs", 4));
        auto proofs = recover::prove_predicates(img, fn_va, runs);
        json arr = json::array();
        for (const auto& p : proofs)
            arr.push_back({{"jcc_va", p.jcc_va}, {"text", p.text},
                           {"static_idiom", p.static_idiom},
                           {"seen_runs", p.seen_runs},
                           {"taken_runs", p.taken_runs},
                           {"total_runs", p.total_runs},
                           {"proven_always_taken", p.proven_always_taken},
                           {"proven_never_taken", p.proven_never_taken}});
        out["predicates"] = arr;
        out["count"] = arr.size();
        return out;
    }

    if (action == "invariants") {
        const uint64_t fn_va = parse_addr(args, "addr");
        const size_t runs = static_cast<size_t>(args.value("runs", 4));
        auto r = recover::observe_invariants(img, fn_va, runs);
        if (!r.ok) fail(r.error);
        out["instructions_executed"] = r.instructions_executed;
        out["stopped_reason"] = r.stopped_reason;
        json inv = json::array();
        for (const auto& i : r.invariants)
            inv.push_back({{"reg", i.reg}, {"value", i.value}});
        out["invariants"] = inv;
        return out;
    }

    if (action == "iat_audit") {
        uint64_t va = args.contains("addr")
            ? parse_addr(args, "addr") : 0;
        size_t size = args.contains("size")
            ? static_cast<size_t>(parse_addr(args, "size")) : (1u << 20);
        auto r = recover::iat_audit(img, va, size);
        if (!r.ok) fail(r.error);
        out["slots_scanned"] = r.slots_scanned;
        out["named"] = r.named;
        out["unnamed_valid"] = r.unnamed_valid;
        out["invalid"] = r.invalid;
        json slots = json::array();
        for (const auto& s : r.unnamed)
            slots.push_back({{"slot_va", s.slot_va}, {"target", s.target}});
        out["unnamed_candidates"] = slots;
        return out;
    }

    // devirtualization chain

    if (action == "identify") {
        auto r = devirt::identify(img, parse_addr(args, "addr"));
        if (!r.ok) fail(r.error);
        out["likely_vm"] = r.likely_vm;
        out["confidence_pct"] = r.confidence_pct;
        out["fn_va"] = r.fn_va;
        out["dispatcher"] = r.dispatcher;
        out["handler_table"] = r.handler_table;
        out["table_entry_size"] = r.table_entry_size;
        out["indirect_jumps"] = r.indirect_jumps;
        out["cmp_chain_len"] = r.cmp_chain_len;
        return out;
    }

    if (action == "handlers" || action == "opcode_map") {
        const uint64_t table = parse_addr(args, "table");
        uint32_t es = args.contains("entry_size")
            ? static_cast<uint32_t>(parse_addr(args, "entry_size")) : 0;
        const size_t maxh = std::min<size_t>(args.value("max_handlers", 256u), 4096u);
        auto r = devirt::classify_handlers(img, table, es, maxh);
        if (!r.ok) fail(r.error);
        out["handler_table"] = r.handler_table;
        out["entry_size"] = r.entry_size;
        out["valid_entries"] = r.valid_entries;
        json hs = json::array();
        for (const auto& h : r.handlers) {
            json o = {{"opcode", h.opcode}, {"va", h.va},
                      {"classification", h.classification},
                      {"instruction_count", h.instruction_count}};
            if (action == "handlers") {
                json texts = json::array();
                for (const auto& t : h.insns) texts.push_back(t);
                o["insns"] = texts;
            }
            hs.push_back(std::move(o));
        }
        out["handlers"] = hs;
        return out;
    }

    if (action == "trace" || action == "lift" || action == "pseudocode") {
        const uint64_t entry = parse_addr(args, "addr");          // VM entry
        const uint64_t dispatcher = args.contains("dispatcher")
            ? parse_addr(args, "dispatcher") : 0;
        const size_t max_ops = std::min<size_t>(args.value("max_ops", 512u), 4096u);

        // handlers come from a table walk or a caller supplied list
        std::vector<uint64_t> handler_vas;
        if (args.contains("handler_table")) {
            uint64_t table = parse_addr(args, "handler_table");
            uint32_t es = args.contains("entry_size")
                ? static_cast<uint32_t>(parse_addr(args, "entry_size")) : 8;
            auto cls = devirt::classify_handlers(img, table, es, 256);
            if (!cls.ok) fail(cls.error);
            for (const auto& h : cls.handlers) handler_vas.push_back(h.va);
            out["entry_size"] = cls.entry_size;
            out["valid_entries"] = cls.valid_entries;
        } else if (args.contains("handlers") && args.at("handlers").is_array()) {
            for (const auto& v : args.at("handlers"))
                handler_vas.push_back(std::stoull(v.get<std::string>(), nullptr, 0));
        } else {
            fail("missing handler_table or handlers list");
        }
        if (handler_vas.empty()) fail("no handlers to trace");

        auto tr = devirt::trace_bytecode(img, entry, dispatcher,
                                         handler_vas, max_ops);
        if (!tr.ok && tr.bytecode.empty()) fail(tr.error);
        out["dispatcher_hits"] = tr.dispatcher_hits;
        out["stopped_reason"] = tr.stopped_reason;
        if (!tr.note.empty()) out["note"] = tr.note;

        if (action == "trace") {
            out["bytecode"] = tr.bytecode;
            out["handler_order"] = tr.handler_order;
            return out;
        }

        devirt::classify_result_t cls;
        cls.ok = true;
        for (size_t i = 0; i < handler_vas.size(); ++i) {
            devirt::handler_t h;
            h.opcode = static_cast<uint32_t>(i);
            h.va     = handler_vas[i];
            // classify by decoding each handler
            std::vector<disasm::insn_t> insns;
            uint64_t cur = h.va;
            for (size_t k = 0; k < 128; ++k) {
                uint8_t buf[16];
                if (cur < img.base) break;
                auto off = img.pe->rva_to_offset(
                    static_cast<uint32_t>(cur - img.base));
                if (!off || *off + sizeof(buf) > img.file->size()) break;
                std::memcpy(buf, img.file->data() + *off, sizeof(buf));
                auto in = img.eng->decode(cur, buf, sizeof(buf));
                if (!in || in->length == 0) break;
                insns.push_back(std::move(*in));
                cur += insns.back().length;
            }
            h.instruction_count = insns.size();
            h.classification = devirt::classify_handler_insns(insns);
            cls.handlers.push_back(std::move(h));
        }

        auto lifted = devirt::lift(tr, cls);
        if (!lifted.ok) fail(lifted.error);

        if (action == "lift") {
            json lines = json::array();
            for (const auto& l : lifted.lines)
                lines.push_back({{"opcode", l.opcode},
                                 {"handler_va", l.handler_va},
                                 {"il", l.il}});
            out["lines"] = lines;
            out["covered"] = lifted.covered;
            return out;
        }

        out["pseudocode"] = devirt::pseudocode(lifted);
        return out;
    }

    fail("devirt: unknown action (themida_status|themida_start|themida_job|"
         "themida_cancel|identify|handlers|opcode_map|trace|lift|"
         "pseudocode|recover_cfg|prove_predicates|invariants|iat_audit)");
}

// tool: frida

json tool_frida(const json& args, const infra::cancel_token_t& cancel) {
    const std::string action = require_action(args);
    auto& svc = frida::frida_service_t::get();
    std::string err;

    const std::string dev_id = args.value("device", std::string{});

    if (action == "status") {
        const bool available = svc.init(&err);
        json out = {{"available", available},
                    {"version", svc.version()},
                    {"initialized", svc.initialized()}};
        if (!available) out["error"] = err;
        std::vector<frida::device_info_t> devices;
        if (available && svc.list_devices(&devices, &err)) {
            json dv = json::array();
            for (auto& d : devices)
                dv.push_back({{"id", d.id}, {"name", d.name}, {"type", d.dtype}});
            out["devices"] = std::move(dv);
        } else {
            out["devices_error"] = err;
        }
        std::vector<frida::session_info_t> sessions;
        svc.list_sessions(&sessions);
        json sv = json::array();
        for (auto& s : sessions)
        {
            json item = {{"handle", s.handle}, {"pid", s.pid}, {"device", s.device},
                         {"detached", s.detached}, {"scripts", s.scripts}};
            if (!s.detach_reason.empty()) item["detach_reason"] = s.detach_reason;
            if (!s.crash_summary.empty()) {
                item["crash"] = {{"pid", s.crash_pid},
                                  {"process", s.crash_process},
                                  {"summary", s.crash_summary},
                                  {"report", s.crash_report},
                                  {"parameters", s.crash_parameters}};
            }
            sv.push_back(std::move(item));
        }
        out["sessions"] = std::move(sv);
        std::vector<frida::script_info_t> scripts;
        svc.list_scripts(&scripts);
        json sc = json::array();
        for (auto& s : scripts)
            sc.push_back({{"handle", s.handle}, {"name", s.name},
                          {"session", s.session}, {"runtime", s.runtime},
                          {"loaded", s.loaded}, {"dropped", s.dropped}});
        out["scripts"] = std::move(sc);
        return out;
    }

    if (action == "devices") {
        std::vector<frida::device_info_t> devices;
        if (!svc.list_devices(&devices, &err)) fail(err);
        json dv = json::array();
        for (auto& d : devices)
            dv.push_back({{"id", d.id}, {"name", d.name}, {"type", d.dtype}});
        return {{"devices", std::move(dv)}};
    }

    if (action == "remote_add" || action == "remote_remove") {
        const std::string address = args.value("address", std::string{});
        if (address.empty()) fail("missing 'address'");
        frida::remote_options_t options;
        options.certificate_path = args.value("certificate_path", std::string{});
        options.certificate_pem = args.value("certificate_pem", std::string{});
        options.origin = args.value("origin", std::string{});
        options.token = args.value("token", std::string{});
        options.keepalive_interval = args.value("keepalive_interval", -1);
        if (!options.certificate_path.empty() && !options.certificate_pem.empty())
            fail("provide only one of 'certificate_path' or 'certificate_pem'");
        if (options.keepalive_interval < -1)
            fail("'keepalive_interval' must be -1 or greater");
        const bool ok = action == "remote_add" ? svc.remote_add(address, options, &err)
                                               : svc.remote_remove(address, &err);
        if (!ok) fail(err);
        return {{"ok", true}, {"address", address}};
    }

    if (action == "ps" || action == "find_process") {
        if (action == "find_process") {
            const std::string name = args.value("name", std::string{});
            if (name.empty()) fail("missing 'name'");
            std::optional<frida::process_info_t> p;
            if (!svc.find_process(dev_id, name, &p, &err)) fail(err);
            if (!p) return {{"found", false}};
            return {{"found", true}, {"pid", p->pid}, {"name", p->name},
                    {"parameters", p->parameters}};
        }
        std::vector<frida::process_info_t> ps;
        if (!svc.enumerate_processes(dev_id, args.value("scope", std::string{}), &ps, &err))
            fail(err);
        json arr = json::array();
        const size_t limit = std::min<size_t>(args.value("limit", 500), 5000);
        size_t n = 0;
        for (auto& p : ps) {
            if (n++ >= limit) break;
            arr.push_back({{"pid", p.pid}, {"name", p.name},
                           {"parameters", p.parameters}});
        }
        return {{"processes", std::move(arr)}, {"total", ps.size()},
                {"returned", std::min(limit, ps.size())},
                {"truncated", ps.size() > limit}};
    }

    if (action == "applications" || action == "frontmost") {
        if (action == "frontmost") {
            std::optional<frida::application_info_t> a;
            if (!svc.frontmost_application(dev_id, &a, &err)) fail(err);
            if (!a) return {{"found", false}};
            return {{"found", true}, {"identifier", a->identifier},
                    {"name", a->name}, {"pid", a->pid}};
        }
        std::vector<frida::application_info_t> apps;
        if (!svc.enumerate_applications(dev_id, args.value("scope", std::string{}),
                                        &apps, &err))
            fail(err);
        json arr = json::array();
        for (auto& a : apps)
            arr.push_back({{"identifier", a.identifier}, {"name", a.name},
                           {"pid", a.pid}});
        return {{"applications", std::move(arr)}};
    }

    if (action == "spawn") {
        const std::string program = args.value("program", std::string{});
        if (program.empty()) fail("missing 'program'");
        std::vector<std::string> argv;
        if (args.contains("argv") && args.at("argv").is_array())
            for (const auto& v : args.at("argv")) argv.push_back(v.get<std::string>());
        std::vector<std::string> env;
        if (args.contains("env") && args.at("env").is_array())
            for (const auto& v : args.at("env")) env.push_back(v.get<std::string>());
        uint32_t pid = 0;
        const std::string stdio = args.value("stdio", std::string{"inherit"});
        const bool piped = stdio == "pipe";
        if (!piped && stdio != "inherit") fail("'stdio' must be 'inherit' or 'pipe'");
        const bool spawned = piped
            ? svc.spawn_piped(dev_id, program, argv, env,
                              args.value("cwd", std::string{}), &pid, &err)
            : svc.spawn(dev_id, program, argv, env,
                        args.value("cwd", std::string{}), &pid, &err);
        if (!spawned)
            fail(err);
        return {{"ok", true}, {"pid", pid}, {"stdio", stdio}};
    }

    if (action == "spawn_output") {
        const uint64_t raw_pid = parse_addr(args, "pid");
        if (raw_pid == 0 || raw_pid > UINT32_MAX)
            fail("'pid' must be in 1..4294967295");
        std::vector<frida::spawn_output_t> events;
        size_t remaining = 0;
        size_t dropped = 0;
        const size_t limit = std::min<size_t>(args.value("limit", 256), 1024);
        if (!svc.read_spawn_output(dev_id, static_cast<uint32_t>(raw_pid), limit,
                                   &events, &remaining, &dropped, &err))
            fail(err);
        json out = json::array();
        for (auto& event : events) {
            json item = {{"at_ms", event.at_ms}, {"pid", event.pid},
                         {"fd", event.fd}, {"eof", event.eof},
                         {"data_len", event.data.size()}};
            if (!event.data.empty()) {
                static constexpr char table[] =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
                std::string b64;
                b64.reserve(((event.data.size() + 2) / 3) * 4);
                for (size_t i = 0; i < event.data.size(); i += 3) {
                    uint32_t v = uint32_t(event.data[i]) << 16;
                    if (i + 1 < event.data.size()) v |= uint32_t(event.data[i + 1]) << 8;
                    if (i + 2 < event.data.size()) v |= uint32_t(event.data[i + 2]);
                    b64 += table[(v >> 18) & 63];
                    b64 += table[(v >> 12) & 63];
                    b64 += i + 1 < event.data.size() ? table[(v >> 6) & 63] : '=';
                    b64 += i + 2 < event.data.size() ? table[v & 63] : '=';
                }
                item["data_b64"] = std::move(b64);
                if (std::find(event.data.begin(), event.data.end(), uint8_t{0}) ==
                    event.data.end())
                    item["text"] = std::string(event.data.begin(), event.data.end());
            }
            out.push_back(std::move(item));
        }
        return {{"output", std::move(out)}, {"remaining", remaining},
                {"dropped", dropped}, {"drained", true}};
    }

    if (action == "resume" || action == "kill" || action == "input") {
        const uint64_t pid = parse_addr(args, "pid");
        if (pid == 0 || pid > UINT32_MAX) fail("'pid' must be in 1..4294967295");
        if (action == "resume") {
            if (!svc.resume(dev_id, (uint32_t)pid, &err)) fail(err);
            return {{"ok", true}, {"pid", pid}};
        }
        if (action == "kill") {
            if (!svc.kill(dev_id, (uint32_t)pid, &err)) fail(err);
            return {{"ok", true}, {"pid", pid}};
        }
        std::vector<uint8_t> data;
        if (args.contains("hex") && args.at("hex").is_string()) {
            const std::string hex = args.at("hex").get<std::string>();
            if (args.contains("text")) fail("provide exactly one of 'hex' or 'text'");
            if (hex.empty() || hex.size() % 2 != 0 ||
                hex.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos)
                fail("'hex' must contain a non-empty even number of hex digits");
            data.reserve(hex.size() / 2);
            for (size_t i = 0; i + 1 < hex.size(); i += 2)
                data.push_back((uint8_t)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
        } else if (args.contains("text") && args.at("text").is_string()) {
            const std::string t = args.at("text").get<std::string>();
            data.assign(t.begin(), t.end());
        } else fail("missing 'hex' or 'text' input data");
        if (!svc.input(dev_id, (uint32_t)pid, data, &err)) fail(err);
        return {{"ok", true}, {"pid", pid}, {"bytes", data.size()}};
    }

    if (action == "spawn_gating") {
        const bool enable = args.value("enable", true);
        const bool ok = enable ? svc.enable_spawn_gating(dev_id, &err)
                               : svc.disable_spawn_gating(dev_id, &err);
        if (!ok) fail(err);
        return {{"ok", true}, {"enabled", enable}};
    }

    if (action == "pending_spawn" || action == "pending_children") {
        if (action == "pending_spawn") {
            std::vector<frida::spawn_info_t> sp;
            if (!svc.pending_spawn(dev_id, &sp, &err)) fail(err);
            json arr = json::array();
            for (auto& s : sp)
                arr.push_back({{"pid", s.pid}, {"identifier", s.identifier}});
            return {{"pending", std::move(arr)}};
        }
        std::vector<frida::child_info_t> ch;
        if (!svc.pending_children(dev_id, &ch, &err)) fail(err);
        json arr = json::array();
        for (auto& c : ch)
            arr.push_back({{"pid", c.pid}, {"parent_pid", c.parent_pid},
                           {"origin", c.origin}, {"identifier", c.identifier}});
        return {{"children", std::move(arr)}};
    }

    if (action == "attach") {
        const uint64_t pid = parse_addr(args, "pid");
        if (pid == 0 || pid > UINT32_MAX) fail("'pid' must be in 1..4294967295");
        std::string handle;
        if (!svc.attach(dev_id, (uint32_t)pid, args.value("realm", std::string{}),
                        &handle, &err))
            fail(err);
        return {{"ok", true}, {"session", handle}, {"pid", pid}};
    }

    if (action == "detach") {
        const std::string session = args.value("session", std::string{});
        if (session.empty()) fail("missing 'session' handle");
        if (!svc.detach_session(session, &err)) fail(err);
        return {{"ok", true}};
    }

    if (action == "session_resume" || action == "child_gating") {
        const std::string session = args.value("session", std::string{});
        if (session.empty()) fail("missing 'session' handle");
        if (action == "session_resume") {
            if (!svc.resume_session(session, &err)) fail(err);
            return {{"ok", true}};
        }
        const bool enable = args.value("enable", true);
        const bool ok = enable ? svc.enable_child_gating(session, &err)
                               : svc.disable_child_gating(session, &err);
        if (!ok) fail(err);
        return {{"ok", true}, {"enabled", enable}};
    }

    if (action == "script_create") {
        const std::string session = args.value("session", std::string{});
        const std::string source = args.value("source", std::string{});
        const std::string bytecode = args.value("bytecode_b64", std::string{});
        const std::string snapshot = args.value("snapshot_b64", std::string{});
        if (session.empty()) fail("missing 'session' handle");
        if (source.empty() == bytecode.empty())
            fail("provide exactly one of 'source' or 'bytecode_b64'");
        if (!snapshot.empty() && source.empty())
            fail("'snapshot_b64' requires source code");
        std::string handle;
        const bool created = source.empty()
            ? svc.create_script_from_bytes(session, args.value("name", std::string{}),
                                           bytecode, args.value("runtime", std::string{}),
                                           &handle, &err)
            : snapshot.empty()
                ? svc.create_script(session, args.value("name", std::string{}), source,
                                    args.value("runtime", std::string{}), &handle, &err)
                : svc.create_script_with_snapshot(
                      session, args.value("name", std::string{}), source, snapshot,
                      args.value("runtime", std::string{}), &handle, &err);
        if (!created)
            fail(err);
        json out = {{"ok", true}, {"script", handle}};
        if (args.value("load", true)) {
            if (!svc.load_script(handle, &err)) {
                const std::string load_error = err;
                std::string cleanup_error;
                svc.destroy_script(handle, &cleanup_error);
                fail(cleanup_error.empty() ? load_error
                                           : load_error + "; cleanup: " + cleanup_error);
            }
            out["loaded"] = true;
        }
        return out;
    }

    if (action == "script_load" || action == "script_unload" ||
        action == "script_destroy" || action == "script_post") {
        const std::string script = args.value("script", std::string{});
        if (script.empty()) fail("missing 'script' handle");
        if (action == "script_load") {
            if (!svc.load_script(script, &err)) fail(err);
            return {{"ok", true}, {"script", script}, {"loaded", true}};
        }
        if (action == "script_unload") {
            if (!svc.unload_script(script, &err)) fail(err);
            return {{"ok", true}, {"script", script}, {"destroyed", true}};
        }
        if (action == "script_destroy") {
            if (!svc.destroy_script(script, &err)) fail(err);
            return {{"ok", true}};
        }
        const std::string msg = args.value("message", std::string{});
        if (msg.empty()) fail("missing 'message' JSON string");
        if (!svc.post_message(script, msg, &err)) fail(err);
        return {{"ok", true}};
    }

    if (action == "script_debugger") {
        const std::string script = args.value("script", std::string{});
        if (script.empty()) fail("missing 'script' handle");
        const bool enable = args.value("enable", true);
        const uint64_t port = args.value("port", uint64_t{9229});
        if (enable && (port == 0 || port > UINT16_MAX))
            fail("'port' must be in 1..65535");
        const bool ok = enable
            ? svc.enable_script_debugger(script,
                                         static_cast<uint16_t>(port),
                                         &err)
            : svc.disable_script_debugger(script, &err);
        if (!ok) fail(err);
        return {{"ok", true}, {"enabled", enable}};
    }

    if (action == "messages") {
        const std::string script = args.value("script", std::string{});
        if (script.empty()) fail("missing 'script' handle");
        std::vector<frida::script_message_t> msgs;
        size_t dropped = 0;
        if (!svc.read_messages(script, std::min<size_t>(args.value("limit", 256), 1024),
                               &msgs, &dropped, &err))
            fail(err);
        json arr = json::array();
        for (auto& m : msgs) {
            json mi = {{"at_ms", m.at_ms}};
            mi["message"] = json::parse(m.json, nullptr, false);
            if (!mi["message"].is_discarded()) {
                // keep as parsed object
            } else {
                mi["message"] = m.json;   // unparsable, keep the raw text
            }
            if (!m.data.empty()) {
                static const char* tbl = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                         "abcdefghijklmnopqrstuvwxyz0123456789+/";
                std::string b64;
                b64.reserve(((m.data.size() + 2) / 3) * 4);
                for (size_t i = 0; i < m.data.size(); i += 3) {
                    uint32_t v = (uint32_t(m.data[i]) << 16);
                    if (i + 1 < m.data.size()) v |= (uint32_t(m.data[i + 1]) << 8);
                    if (i + 2 < m.data.size()) v |= uint32_t(m.data[i + 2]);
                    b64 += tbl[(v >> 18) & 63];
                    b64 += tbl[(v >> 12) & 63];
                    b64 += (i + 1 < m.data.size()) ? tbl[(v >> 6) & 63] : '=';
                    b64 += (i + 2 < m.data.size()) ? tbl[v & 63] : '=';
                }
                mi["data_b64"] = b64;
                mi["data_len"] = m.data.size();
            }
            arr.push_back(std::move(mi));
        }
        return {{"messages", std::move(arr)}, {"dropped", dropped}};
    }

    if (action == "rpc") {
        const std::string script = args.value("script", std::string{});
        const std::string method = args.value("method", std::string{});
        if (script.empty()) fail("missing 'script' handle");
        if (method.empty()) fail("missing 'method'");
        std::string args_json = "[]";
        if (args.contains("args")) {
            if (!args.at("args").is_array()) fail("'args' must be a JSON array");
            args_json = args.at("args").dump();
        }
        std::string reply;
        const int timeout_ms = args.value("timeout_ms", 25000);
        if (timeout_ms <= 0 || timeout_ms > 25000)
            fail("'timeout_ms' must be in 1..25000");
        if (!svc.rpc_call(script, method, args_json, timeout_ms,
                          &reply, &err, [cancel] { return cancel.cancelled(); }))
            fail(err);
        // reply shape is frida:rpc with ok or error
        const json r = json::parse(reply, nullptr, false);
        if (!r.is_discarded() && r.is_array() && r.size() >= 4) {
            const std::string kind = r.at(2).get<std::string>();
            if (kind == "ok") return {{"ok", true}, {"result", r.at(3)}};
            return {{"ok", false},
                    {"error", r.at(3).is_string() ? r.at(3).get<std::string>()
                                                  : r.at(3).dump()}};
        }
        return {{"ok", true}, {"reply", reply}};
    }

    if (action == "compile") {
        const std::string entrypoint = args.value("entrypoint", std::string{});
        if (entrypoint.empty()) fail("missing 'entrypoint'");
        std::string output;
        if (!svc.compile_project(entrypoint, args.value("project_root", std::string{}),
                                 &output, &err,
                                 [cancel] { return cancel.cancelled(); }))
            fail(err);
        const size_t limit = std::min<size_t>(args.value("limit", 65536), 1 << 20);
        json out = {{"ok", true}, {"size", output.size()}};
        out["code"] = output.size() <= limit ? output
                                             : output.substr(0, limit) + "...[truncated]";
        return out;
    }

    if (action == "compile_script" || action == "snapshot_script") {
        const std::string session = args.value("session", std::string{});
        const std::string source = args.value("source", std::string{});
        if (session.empty()) fail("missing 'session' handle");
        if (source.empty()) fail("missing 'source' JS code");
        std::string b64;
        const bool ok = action == "compile_script"
            ? svc.compile_script(session, source, args.value("runtime", std::string{}),
                                 &b64, &err,
                                 [cancel] { return cancel.cancelled(); })
            : svc.snapshot_script(session, source, args.value("runtime", std::string{}),
                                  &b64, &err,
                                  [cancel] { return cancel.cancelled(); });
        if (!ok) fail(err);
        size_t byte_count = (b64.size() / 4) * 3;
        if (!b64.empty() && b64.back() == '=') --byte_count;
        if (b64.size() > 1 && b64[b64.size() - 2] == '=') --byte_count;
        json out = {{"ok", true}, {"byte_count", byte_count},
                    {"base64_char_count", b64.size()}};
        if (args.value("include", false) || b64.size() <= 4096) out["b64"] = b64;
        return out;
    }

    fail("frida: unknown action (status|devices|remote_add|remote_remove|ps|"
         "find_process|applications|frontmost|spawn|spawn_output|resume|kill|input|"
         "spawn_gating|pending_spawn|pending_children|attach|detach|"
         "session_resume|child_gating|script_create|script_load|script_unload|"
         "script_destroy|script_post|script_debugger|messages|rpc|compile|"
         "compile_script|snapshot_script)");
}

// tool: script

json tool_script(const json& args) {
    const std::string action = require_action(args);
    if (action != "run") fail("script: unknown action");

    size_t code_len = 0;
    const char* code_ptr = nullptr;
    std::string code;
    if (args.contains("code") && args.at("code").is_string())
        code = args.at("code").get<std::string>();
    if (code.empty()) fail("missing code string");
    code_ptr = code.c_str();
    code_len = code.size();

    const int timeout_ms = std::min(args.value("timeout_ms", 5000), 60000);
    auto r = script::lua_run(code, timeout_ms);
    json out = {{"ok", r.ok}, {"output", r.output}};
    if (!r.error.empty()) out["error"] = r.error;
    return out;
}

// tool: app
// app plumbing for the ui, stays off tools/list and lives on /api only

const int64_t g_app_start_ms = infra::steady_ms();

const char* diag_level_name(infra::diag::level_t l) noexcept {
    switch (l) {
    case infra::diag::level_t::trace: return "trace";
    case infra::diag::level_t::info:  return "info";
    case infra::diag::level_t::warn:  return "warn";
    case infra::diag::level_t::error: return "error";
    }
    return "?";
}

json tool_app(const json& args) {
    const std::string action = require_action(args);

    if (action == "status" || action == "ping") {
        json out = app_state_unlocked();
        out["uptime_ms"]   = infra::steady_ms() - g_app_start_ms;
        out["mcp"]         = {{"running", running()}, {"port", port()}};
        out["subscribers"] = infra::event_bus::subscriber_count();
        out["output_revision"] = infra::event_bus::output_revision();
        out["diag_revision"]   = infra::diag::revision();
        out["watch_entries"]   = memory::watch::size();
        out["quit_requested"]  = infra::app_control::quit_requested();
        return out;
    }

    if (action == "output") {
        const uint64_t since = args.value("since", uint64_t{0});
        auto lines = infra::event_bus::output_since(since);
        json arr = json::array();
        for (const auto& l : lines)
            arr.push_back({{"seq", l.seq}, {"ms", l.ms}, {"text", l.text}});
        return {{"revision", infra::event_bus::output_revision()},
                {"count", arr.size()},
                {"lines", std::move(arr)}};
    }

    if (action == "output_clear") {
        infra::event_bus::output_clear();
        return {{"ok", true}};
    }

    if (action == "log") {
        const std::string text = args.value("text", std::string{});
        if (text.empty()) fail("app.log: missing text");
        infra::event_bus::output(text);
        return {{"ok", true}, {"revision", infra::event_bus::output_revision()}};
    }

    if (action == "diag") {
        const uint64_t since = args.value("since_revision", uint64_t{0});
        const size_t   limit = std::min<size_t>(args.value("limit", size_t{2000}), 8192);
        auto snap = infra::diag::snapshot(since);
        json arr = json::array();
        const size_t begin = snap.entries.size() > limit ? snap.entries.size() - limit : 0;
        for (size_t i = begin; i < snap.entries.size(); ++i) {
            const auto& e = snap.entries[i];
            arr.push_back({{"ms", e.timestamp_ms},
                           {"level", diag_level_name(e.level)},
                           {"tag", e.tag},
                           {"message", e.message}});
        }
        return {{"revision", snap.revision},
                {"count", arr.size()},
                {"entries", std::move(arr)}};
    }

    if (action == "shutdown") {
        infra::app_control::request_quit(
            args.value("reason", std::string{"front end requested shutdown"}));
        return {{"ok", true}, {"reason", infra::app_control::quit_reason()}};
    }

    fail("app: unknown action");
    return {};
}

} // namespace

void list_tools(json& out) {
    const char* target_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["list","attach","detach","status","modules","dump_module","threads","regions","handles","icon"]},"pid":{"type":"integer"},"base":{"type":"integer"},"name":{"type":"string"},"path":{"type":"string"},"paths":{"type":"array","items":{"type":"string"}},"load":{"type":"boolean"},"strict":{"type":"boolean"}},"required":["action"]})";
    const char* memory_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["read","write","scan","rescan","scan_state","scan_reset","aob","pointerscan","snapshot","snapshots","diff","snapshot_free","protect","alloc","free","siggen","live_crypto","watch_list","watch_add","watch_remove","watch_clear","watch_set"]},"addr":{"type":"integer"},"len":{"type":"integer"},"format":{"type":"string","enum":["hex","utf8","u8","u32","u64","f32","f64"]},"hex":{"type":"string"},"kind":{"type":"string","enum":["exact","between","bigger","smaller","unknown","increased","increased_by","increased_percent","decreased","decreased_by","decreased_percent","changed","unchanged"]},"width":{"type":"string","enum":["i8","u8","i16","u16","i32","u32","i64","u64","f32","f64","all"]},"rounding":{"type":"string","enum":["exact","rounded","truncated","extreme"]},"value":{},"value2":{},"begin":{"type":"integer"},"end":{"type":"integer"},"pattern":{"type":"string"},"tail":{"type":"string"},"writable":{"oneOf":[{"type":"string","enum":["any","include","exclude"]},{"type":"boolean"}]},"executable":{"type":"string","enum":["any","include","exclude"]},"copy_on_write":{"type":"string","enum":["any","include","exclude"]},"mem_private":{"type":"boolean"},"mem_image":{"type":"boolean"},"mem_mapped":{"type":"boolean"},"read_only":{"type":"boolean"},"no_exec":{"type":"boolean"},"threads":{"type":"integer","minimum":0,"maximum":64},"chunk_bytes":{"type":"integer","minimum":1},"max_results":{"type":"integer","minimum":1},"prot":{"type":"integer"},"target":{"type":"integer"},"depth":{"type":"integer"},"min_offset":{"type":"integer"},"max_offset":{"type":"integer"},"alignment":{"type":"integer"},"static_roots":{"type":"boolean"},"frontier_cap":{"type":"integer","minimum":1},"max_bytes":{"type":"integer"},"a":{"type":"integer"},"b":{"type":"integer"},"id":{"type":"integer"},"all":{"type":"boolean"},"limit":{"type":"integer"},"label":{"type":"string"},"freeze":{"type":"boolean"}},"required":["action"]})";
    const char* disasm_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["assemble","disassemble","loaded","pe","functions","xrefs","strings","symbols","symbol_set","blocks","globals","vtables","load","unload","analyze_stop"]},"addr":{"type":"integer"},"count":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer"},"name":{"type":"string"},"text":{"type":"string"},"limit":{"type":"integer"},"min_chars":{"type":"integer"},"include_exec":{"type":"boolean"}},"required":["action"]})";
    const char* debugger_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["attach","detach","status","suspend_all","resume_all","bp_set","bp_clear","continue","step_into","step_over","step_out","wait_halt","regs","events","callstack","seh","set_register","watchpoint_set","watchpoint_clear","watchpoints","trace_run"]},"pid":{"type":"integer"},"addr":{"type":"integer"},"hw":{"type":"boolean"},"type":{"type":"integer"},"len":{"type":"integer"},"timeout_ms":{"type":"integer"},"condition":{"type":"string"},"log":{"type":"string"},"auto_continue":{"type":"boolean"},"one_shot":{"type":"boolean"},"max_frames":{"type":"integer"},"name":{"type":"string"},"value":{"type":"integer"},"count":{"type":"integer"}},"required":["action"]})";
    const char* driver_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["status","backend","kernel_modules","dump_driver","kernel_read","kernel_write","kernel_search","call","v2p","ssdt","peb","resolve_export","windows","find_references","heap_walk","heap_blocks","defer_call","defer_list","defer_execute","defer_results","defer_cancel","symbols_load","symbols_lookup","symbols_nearest","anti_debug_spoof","sandbox_protect","sandbox_unprotect","log_config","read_teb","peb_modules","integrity_checks","sniff_buffers"]},"pref":{"type":"string","enum":["auto","kernel","user"]},"pid":{"type":"integer"},"addr":{"type":"integer"},"len":{"type":"integer"},"hex":{"type":"string"},"pattern":{"type":"string"},"begin":{"type":"integer"},"end":{"type":"integer"},"a1":{"type":"integer"},"a2":{"type":"integer"},"a3":{"type":"integer"},"a4":{"type":"integer"},"name":{"type":"string"},"path":{"type":"string"},"base":{"type":"integer"},"size":{"type":"integer"},"module_base":{"type":"integer"},"value":{"type":"integer"},"kind":{"type":"string"},"id":{"type":"integer"},"limit":{"type":"integer"},"flags":{"type":"integer"},"tid":{"type":"integer"},"order":{"type":"string"},"filter":{"type":"string"},"op":{"type":"string"},"timestamp":{"type":"integer"},"thread_id":{"type":"integer"},"buffer_register":{"type":"string"},"size_register":{"type":"string"},"max_captures":{"type":"integer"},"bp_index":{"type":"integer"},"level":{"type":"integer"},"cap_mb":{"type":"integer"}},"required":["action"]})";
    const char* xray_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["cfg","complexity","cff","obfuscation","strings_recon","indirect_calls","anti_analysis","hooks","syscalls","apihash","entropy","pages","crypto_range","gadgets"]},"addr":{"type":"integer"},"size":{"type":"integer"},"path":{"type":"string"},"base":{"type":"integer"},"window_size":{"type":"integer"},"window_limit":{"type":"integer"},"page_size":{"type":"integer"},"max_functions":{"type":"integer"},"hash":{"type":"integer"},"hashes":{"type":"array"},"algorithm":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* patch_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["nop_junk","resolve_opaque","patch_antidebug","unpack_xor","decode_strings","write_bytes","revert_all","journal","full_pass","rebuild"]},"addr":{"type":"integer"},"size":{"type":"integer"},"hex":{"type":"string"},"aggressive":{"type":"boolean"},"nop_threshold":{"type":"integer"},"dry_run":{"type":"boolean"},"method":{"type":"string"},"key_hex":{"type":"string"},"patch_api_calls":{"type":"boolean"},"patch_int_traps":{"type":"boolean"},"patch_timing":{"type":"boolean"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* devirt_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["themida_status","themida_start","themida_job","themida_cancel","identify","handlers","opcode_map","trace","lift","pseudocode","recover_cfg","prove_predicates","invariants","iat_audit"]},"addr":{"type":"integer"},"path":{"type":"string"},"output_path":{"type":"string"},"timeout_ms":{"type":"integer","minimum":1000,"maximum":1800000},"overwrite":{"type":"boolean"},"load":{"type":"boolean"},"id":{"type":"integer","minimum":1},"runs":{"type":"integer"},"size":{"type":"integer"},"table":{"type":"integer"},"entry_size":{"type":"integer"},"max_handlers":{"type":"integer"},"dispatcher":{"type":"integer"},"handler_table":{"type":"integer"},"handlers":{"type":"array"},"max_ops":{"type":"integer"}},"required":["action"]})";
    const char* types_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["declare","create_struct","get_struct","list_structs","add_member","remove_struct","create_enum","get_enum","list_enums","remove_enum","read_field","format_at"]},"name":{"type":"string"},"decl":{"type":"string"},"filter":{"type":"string"},"field":{"type":"string"},"type":{"type":"string"},"underlying":{"type":"string"},"values":{"type":"array"},"array_count":{"type":"integer"},"addr":{"type":"integer"},"live":{"type":"boolean"},"struct":{"type":"string"},"size":{"type":"integer"}},"required":["action"]})";
    const char* notes_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["set_comment","get_comment","comments","bookmark_toggle","bookmarks"]},"addr":{"type":"integer"},"text":{"type":"string"}},"required":["action"]})";
    const char* emulate_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"hex":{"type":"string"},"file_addr":{"type":"integer"},"target_addr":{"type":"integer"},"code_len":{"type":"integer"},"base":{"type":"integer"},"entry":{"type":"integer"},"stack_base":{"type":"integer"},"stack_size":{"type":"integer"},"sp":{"type":"integer"},"regs":{"type":"object"},"maps":{"type":"array"},"until":{"type":"integer"},"count":{"type":"integer"},"timeout_ms":{"type":"integer"},"trace":{"type":"boolean"},"trace_max":{"type":"integer"},"taint":{"type":"array"},"watch_addr":{"type":"integer"},"watch_len":{"type":"integer"}},"required":["action"]})";
    const char* analyze_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["packer","signatures","diff"]},"path":{"type":"string"},"path_a":{"type":"string"},"path_b":{"type":"string"},"limit":{"type":"integer"}},"required":["action"]})";
    const char* network_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["status","capture_start","capture_stop","packets","dns","rules_add","rules_remove","rules_clear","stats","export_pcap","streams","stream_data","inject","mod_rule_add","mod_rule_remove","mod_rules_list","redirect_add","redirect_remove","redirect_rules_list","dns_spoof_add","dns_spoof_remove","dns_spoof_list","kill_conn","intercept_start","intercept_stop","intercept_list","intercept_release","bw_start","bw_stop","bw_stats","bw_processes","fingerprint_run","fingerprint_results","reassemble_stream","connections","deep_inspect","wfp_callouts","socket_handles","tcpip_dump","interfaces","block_ip","block_port","block_process"]},"pid":{"type":"integer"},"port":{"type":"integer"},"protocol":{"type":"integer"},"from":{"type":"integer"},"filter":{"type":"string"},"limit":{"type":"integer"},"rule_id":{"type":"integer"},"direction":{"type":["integer","string"]},"path":{"type":"string"},"max_packets":{"type":"integer"},"id":{"type":"integer"},"offset":{"type":"integer"},"len":{"type":"integer"},"payload_hex":{"type":"string"},"pattern_hex":{"type":"string"},"replacement_hex":{"type":"string"},"src_ip":{"type":"string"},"dst_ip":{"type":"string"},"match_ip":{"type":"string"},"redirect_ip":{"type":"string"},"ip":{"type":"string"},"domain":{"type":"string"},"ttl":{"type":"integer"},"hold_id":{"type":"integer"},"exclude_pid":{"type":"integer"},"window_ms":{"type":"integer"},"src_port":{"type":"integer"},"dst_port":{"type":"integer"},"module":{"type":"string"}},"required":["action"]})";
    const char* proxy_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["start","stop","status","entries","entry","replay"]},"port":{"type":"integer"},"limit":{"type":"integer"},"id":{"type":"integer"}},"required":["action"]})";
    const char* persist_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["save","list","load","delete","kv_set","kv_get","hype_save","hype_load"]},"name":{"type":"string"},"data":{},"id":{"type":"integer"},"key":{"type":"string"},"value":{},"dir":{"type":"string"}},"required":["action"]})";
    const char* re_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["rtti_scan","vftable","danger","libsig"]},"path":{"type":"string"},"base":{"type":"integer"},"addr":{"type":"integer"},"slots":{"type":"integer"},"sigset":{"type":"string"}},"required":["action"]})";
    const char* script_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["run"]},"code":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["action"]})";
    const char* frida_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["status","devices","remote_add","remote_remove","ps","find_process","applications","frontmost","spawn","spawn_output","resume","kill","input","spawn_gating","pending_spawn","pending_children","attach","detach","session_resume","child_gating","script_create","script_load","script_unload","script_destroy","script_post","script_debugger","messages","rpc","compile","compile_script","snapshot_script"]},"device":{"type":"string"},"address":{"type":"string"},"certificate_path":{"type":"string"},"certificate_pem":{"type":"string"},"origin":{"type":"string"},"token":{"type":"string"},"keepalive_interval":{"type":"integer","minimum":-1},"scope":{"type":"string","enum":["minimal","metadata","full"]},"limit":{"type":"integer","minimum":1},"name":{"type":"string"},"program":{"type":"string"},"argv":{"type":"array","items":{"type":"string"}},"env":{"type":"array","items":{"type":"string"}},"cwd":{"type":"string"},"stdio":{"type":"string","enum":["inherit","pipe"]},"pid":{"type":"integer","minimum":1,"maximum":4294967295},"hex":{"type":"string"},"text":{"type":"string"},"enable":{"type":"boolean"},"realm":{"type":"string","enum":["native","emulated"]},"session":{"type":"string"},"source":{"type":"string"},"bytecode_b64":{"type":"string"},"snapshot_b64":{"type":"string"},"runtime":{"type":"string","enum":["default","qjs","v8"]},"load":{"type":"boolean"},"script":{"type":"string"},"message":{"type":"string"},"port":{"type":"integer","minimum":1,"maximum":65535},"method":{"type":"string"},"args":{"type":"array"},"timeout_ms":{"type":"integer","minimum":1,"maximum":25000},"entrypoint":{"type":"string"},"project_root":{"type":"string"},"include":{"type":"boolean"}},"required":["action"],"allOf":[{"if":{"properties":{"action":{"const":"remote_add"}}},"then":{"required":["address"]}},{"if":{"properties":{"action":{"const":"remote_remove"}}},"then":{"required":["address"]}},{"if":{"properties":{"action":{"const":"find_process"}}},"then":{"required":["name"]}},{"if":{"properties":{"action":{"const":"spawn"}}},"then":{"required":["program"]}},{"if":{"properties":{"action":{"enum":["spawn_output","resume","kill","input","attach"]}}},"then":{"required":["pid"]}},{"if":{"properties":{"action":{"enum":["detach","session_resume","child_gating","script_create","compile_script","snapshot_script"]}}},"then":{"required":["session"]}},{"if":{"properties":{"action":{"enum":["script_load","script_unload","script_destroy","script_post","script_debugger","messages","rpc"]}}},"then":{"required":["script"]}},{"if":{"properties":{"action":{"const":"rpc"}}},"then":{"required":["method"]}},{"if":{"properties":{"action":{"const":"compile"}}},"then":{"required":["entrypoint"]}},{"if":{"properties":{"action":{"enum":["compile_script","snapshot_script"]}}},"then":{"required":["source"]}}]})";
    const char* decomp_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["function"]},"addr":{"type":"integer"},"annotate_bytes":{"type":"boolean"}},"required":["action"]})";
    const char* detect_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["hidden_modules","minifilters","etw_sessions","kernel_callbacks"]}},"required":["action"]})";
    const char* fs_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["read_file","write_file","list_directory","create_directory","delete_path","search_files","grep_in_files"]},"path":{"type":"string"},"hex":{"type":"string"},"text":{"type":"string"},"append":{"type":"boolean"},"root":{"type":"string"},"needle":{"type":"string"},"suffix":{"type":"string"},"limit":{"type":"integer"},"max_bytes":{"type":"integer"}},"required":["action"]})";
    const char* web_schema =
        R"({"type":"object","properties":{"action":{"type":"string","enum":["fetch","post"]},"url":{"type":"string"},"body":{"type":"string"},"content_type":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["action"]})";

    out.push_back({{"name", "target"},
                   {"description", "Select and inspect the live process used by memory, debugger, and other runtime tools. Start with action='status' to read the active backend plus attached-target and shared-image context; use action='list' to find a pid, then action='attach' with pid. Attach uses the kernel DTB path when slopdrvr is active and best-effort loads the process's main module from disk at its runtime base, unless the UI already has a binary loaded. dump_module selects a loaded module by base or exact name, reconstructs a conventional PE from its mapped bytes to output path, and optionally load=true opens it in the shared Hyperion analysis session. strict defaults true; false zero-fills unreadable section spans and reports complete=false. Actions modules, dump_module, threads, regions, and handles require an attached target. Detach clears the live target but does not unload a separately UI-loaded image."},
                   {"inputSchema", json::parse(target_schema)}, {"read_only", false}});
    out.push_back({{"name", "memory"},
                   {"description", "Read, search, compare, and modify memory in the process attached by target. Most actions require target.status attached=true; the active user/kernel backend is chosen automatically. Core actions: read/write bytes, protect/alloc/free pages, AOB pattern search, pointer scan, signature generation, and live crypto-constant search. CE-style scan creates per-PID scan state; follow it with rescan, inspect it with scan_state, and release it with scan_reset. snapshot returns an id; compare two ids with diff using a and b, list with snapshots, and release with snapshot_free. Scan filters cover numeric width/comparison/rounding, region type and protection, address bounds, alignment/tail, workers, chunks, and result caps. Kernel mode uses slopdrvr DTB reads and driver region enumeration."},
                   {"inputSchema", json::parse(memory_schema)}, {"read_only", false}});
    out.push_back({{"name", "disasm"},
                   {"description", "Primary static-analysis and instruction tool for the shared binary session. Call action='loaded' first: image.ready means a PE is loaded; image.hype.ready means background Hyperion analysis is complete; image.hype.progress/error explain pending or failed analysis. Use load(path) and unload to manage the same session as the UI, and analyze_stop to cancel analysis. pe/functions/xrefs/strings/symbols use the shared image or an explicit path; blocks/globals/vtables require hype.ready. disassemble reads attached-process memory first and otherwise the loaded file image. assemble converts x86/x64 text to bytes. symbol_set renames a VA persistently (empty name clears) and updates the UI. Strings paginate with limit and omit executable sections unless include_exec=true. Runtime-base loads make static and live VAs directly comparable."},
                   {"inputSchema", json::parse(disasm_schema)}, {"read_only", false}});
    out.push_back({{"name", "debugger"},
                   {"description", "Control a live debugging session. Call status first; attach(pid) starts kernel-stealth VEH debugging when slopdrvr is available, otherwise the classic Win32 debug loop. Set software or hardware breakpoints with bp_set(addr, hw); optional condition, log, auto_continue, and one_shot fields create conditional stops or tracepoints. After continue or a step action, use wait_halt(timeout_ms), then inspect regs, events, callstack, or seh; set_register mutates paused state. watchpoint_set/clear/list manage page-guard access watches, and trace_run records a bounded instruction trace. suspend_all/resume_all freeze or thaw target threads. Hardware DR0-DR3 breakpoints and handle-free thread control require the driver."},
                   {"inputSchema", json::parse(debugger_schema)}, {"read_only", false}});
    out.push_back({{"name", "driver"},
                   {"description", "Inspect and control the optional slopdrvr kernel bridge. Start with status to discover connection, capabilities, and active backend. backend reads or sets pref='auto'|'kernel'|'user', but cannot switch while a target or debugger session is live. Kernel actions include modules, memory read/write/search, driver dump, calls, virtual-to-physical translation, SSDT/PEB/TEB/loader views, exports, windows, heaps, references, symbols, deferred calls, integrity checks, anti-debug spoofing, sandboxing, logs, and network-buffer sniffing. Kernel-address operations lazily resolve the kernel DTB and return structured errors when unavailable; a symbols_load response with ntos_base=0 means the kernel context was not established and symbol lookups will fail. sniff_buffers uses op to start/get/store/stop capture. Use status rather than assuming the driver is installed."},
                   {"inputSchema", json::parse(driver_schema)}, {"read_only", false}});
    out.push_back({{"name", "xray"},
                   {"description", "Run focused read-only static-analysis queries on the shared image or an explicit path. For cfg, complexity, cff, obfuscation, strings_recon, indirect_calls, and anti_analysis, pass addr as a function-start VA; known functions use indexed bounds and unknown addresses fall back to linear decode. Whole-image actions detect hooks, direct syscalls and SSNs, imported-API hashes, entropy windows, page classes, crypto constants, and ROP gadgets. apihash only searches imports of this image, including bare API and 'DLL!API' forms; it is not a global hash dictionary. Use disasm.loaded/functions first to establish image state and valid function VAs."},
                   {"inputSchema", json::parse(xray_schema)}, {"read_only", true}});
    out.push_back({{"name", "patch"},
                   {"description", "Mutate the currently loaded file-image analysis session; this does not patch live target memory. Use journal to inspect recorded edits and revert_all to undo them. write_bytes performs an explicit VA/hex edit. nop_junk, resolve_opaque, patch_antidebug, unpack_xor, and decode_strings apply focused deobfuscation; dry_run previews opaque-predicate changes. full_pass orchestrates multiple passes and reports before/after scores. rebuild(addr) re-decodes a patched function and invalidates affected indexes so later disasm/decomp results reflect changes. Requires disasm.loaded image.ready=true; use memory.write for live-process bytes."},
                   {"inputSchema", json::parse(patch_schema)}, {"read_only", false}});
    out.push_back({{"name", "devirt"},
                    {"description", "Deobfuscation, VM recovery, and Themida unpacking. Themida actions supervise the separate Magicmida debugger engine: call themida_status to discover x86/x64 sidecars, themida_start(path,output_path,timeout_ms,overwrite,load) to launch a cancellable job, then poll themida_job(id) or stop it with themida_cancel(id). Successful output is architecture-validated and can load into the shared analysis session. Static actions identify/handlers/trace/lift/pseudocode recover VM structure; recover_cfg, prove_predicates, invariants, and iat_audit inspect the shared image without mutation."},
                    {"inputSchema", json::parse(devirt_schema)}, {"read_only", false}});
    out.push_back({{"name", "types"},
                   {"description", "Define and apply structs/enums for the current binary; the catalog persists by binary hash. declare parses C-like struct or enum declarations, while create/get/list/remove and add_member provide structured CRUD with computed natural or packed layouts. read_field reads one named field; format_at renders a complete struct or enum at addr. Reads use the mapped file image by default and attached-process memory when live=true. Accepted packed struct forms include 'struct Name { ... } packed;' and 'packed struct Name { ... };'. Load the intended binary before changing the catalog."},
                   {"inputSchema", json::parse(types_schema)}, {"read_only", false}});
    out.push_back({{"name", "notes"},
                   {"description", "Read and edit analyst annotations for the currently loaded binary. set_comment(addr,text), get_comment(addr), and comments manage per-VA comments; bookmark_toggle(addr) and bookmarks manage navigation marks. Data persists by binary hash alongside user symbols and is immediately shared with the UI. Requires a loaded image. set_comment with empty text clears the comment (response cleared=true)."},
                   {"inputSchema", json::parse(notes_schema)}, {"read_only", false}});
    out.push_back({{"name", "emulate"},
                   {"description", "Emulate x86-64 code in an isolated Unicorn VM. action='run' accepts exactly one practical code source: hex bytes, file_addr from the shared image, or target_addr from attached-process memory; code_len bounds file/live reads. Set base/entry, registers, stack, and extra maps as needed. Stop with until, count, or timeout_ms. trace enables bounded instruction history; taint entries mark source byte ranges, and watch_addr/watch_len selects the output window for byte-granular propagation results. Emulation does not modify the loaded image or live target."},
                   {"inputSchema", json::parse(emulate_schema)}, {"read_only", true}});
    out.push_back({{"name", "analyze"},
                   {"description", "Run whole-binary read-only analysis. packer uses the shared image or path and reports protector names, entry signatures, entropy, import anomalies, W+X sections, TLS, overlay, crypto constants, and the shared Hyperion verdict when available. signatures requires the analyzed shared session and returns analyzer-derived names in named_functions; names may come from RTTI, vtables, thunks, or signature candidates and are not provenance-verified as FLIRT. diff(path_a,path_b) performs two full Hyperion analyses and reports added, removed, and modified functions with similarity scores, so expect a longer call. Check disasm.loaded before shared-session actions."},
                   {"inputSchema", json::parse(analyze_schema)}, {"read_only", true}});
    out.push_back({{"name", "network"},
                   {"description", "Capture, query, and manipulate Windows network traffic through slopdrvr/WFP. Call status first. A common read flow is capture_start -> packets/dns/streams/stats -> capture_stop; packets filter syntax includes port=80;host:1.2.3.4;text:foo;pid:1234;proto:tcp, and stream_data reads payload by id/offset/len. Mutation actions cover WFP rules, injection, pattern replacement, redirects, DNS spoofing, connection kill, hold/modify/release interception, bandwidth controls, and block_ip/block_port/block_process (direction in|out|both, default both). System inspection includes connections, DPI, callouts, socket handles, TCB dump, interfaces, fingerprints, and reassembly. Driver-dependent actions return structured errors when slopdrvr is unavailable."},
                   {"inputSchema", json::parse(network_schema)}, {"read_only", false}});
    out.push_back({{"name", "proxy"},
                   {"description", "Run the built-in localhost HTTP/1.1 inspection proxy. Use start(port) -> status -> entries(limit); fetch one captured exchange with entry(id), and replay a logged plain-HTTP request with replay(id). CONNECT tunnels record SNI and metadata but encrypted tunnel bodies are not decrypted, so replay applies only to captured plain HTTP. stop releases the listener. This proxy is independent of the kernel network capture tool."},
                   {"inputSchema", json::parse(proxy_schema)}, {"read_only", false}});
    out.push_back({{"name", "persist"},
                   {"description", "Persist agent or analysis state in the app database. save(name,data) stores an arbitrary JSON session snapshot and returns an id; list discovers snapshots, load(id) retrieves one, and delete(id) removes it. kv_set/kv_get store small named values such as layouts. hype_save(dir) writes the current Hyperion project as a .hdb directory; hype_load(dir) merges names and comments into the live shared image, but does not merge xrefs or types. Persistence does not automatically restore a process attachment or debugger session."},
                   {"inputSchema", json::parse(persist_schema)}, {"read_only", false}});
    out.push_back({{"name", "re"},
                   {"description", "Run read-only reverse-engineering reconnaissance on the shared image or an explicit path. rtti_scan prefers completed Hyperion analysis and returns demangled MSVC classes, vtables, and methods; otherwise it falls back to a quick TypeDescriptor scan. vftable(addr,slots) reads virtual-function entries and uses Hyperion metadata when addr is an indexed vtable. danger finds callsites to security-sensitive imports using Hyperion xrefs for the shared session or the legacy index for explicit paths. libsig(path,sigset) identifies libraries from a JSON byte-signature set. Check disasm.loaded and wait for hype.ready for richest results."},
                   {"inputSchema", json::parse(re_schema)}, {"read_only", true}});
    out.push_back({{"name", "decomp"},
                   {"description", "Decompile one function from the shared image. Prerequisite: call disasm.loaded and wait for image.hype.ready=true, then obtain a function-start addr from disasm.functions. action='function' returns structured C, per-line VA mappings, reconstructed stack variables, and a recovered signature after p-code lifting, SSA, optimization, type inference, and control-flow structuring. Naming priority is user symbol, Hyperion name, then sub_<rva>; RTTI and recognized STL types may appear in output. Set annotate_bytes=true to prefix emitted lines with source VAs. This tool does not accept an explicit path; load the binary first."},
                   {"inputSchema", json::parse(decomp_schema)}, {"read_only", true}});
    out.push_back({{"name", "detect"},
                   {"description", "Inspect local Windows security and kernel artifacts without changing them. hidden_modules cross-checks EnumDeviceDrivers against SystemModuleInformation; minifilters enumerates filesystem filters through fltlib; etw_sessions lists active trace sessions; kernel_callbacks walks notify routines through slopdrvr using build-specific anchors. The first three actions can operate without an attached target; kernel_callbacks requires a working driver and returns a structured error when unavailable."},
                   {"inputSchema", json::parse(detect_schema)}, {"read_only", true}});
    out.push_back({{"name", "fs"},
                   {"description", "Access the Windows host filesystem, not target-process memory. read_file(path,max_bytes) returns file content; write_file(path,text|hex,append) creates or updates a file. list_directory and create_directory operate on path, while delete_path removes a file or directory. search_files(root,needle,suffix,limit) finds names and grep_in_files(root,needle,suffix,limit) searches text content. Use absolute paths when context matters and apply max_bytes/limit to bound large results."},
                   {"inputSchema", json::parse(fs_schema)}, {"read_only", false}});
    out.push_back({{"name", "web"},
                   {"description", "Make outbound HTTP(S) requests from the host through WinHTTP. fetch(url,timeout_ms) performs GET; post(url,body,content_type,timeout_ms) performs POST. Results include response status/body or a structured transport error. Use this for symbol downloads, API queries, and target-related lookups; it is unrelated to captured traffic in network or proxy and does not inherit browser cookies."},
                   {"inputSchema", json::parse(web_schema)}, {"read_only", false}});
    out.push_back({{"name", "script"},
                   {"description", "Run a Lua 5.4 automation script inside reverse-slop, the scripting layer over static analysis, like IDAPython for IDA. action='run' requires code; timeout_ms defaults to 5000 and is capped at 60000 (pass a higher timeout_ms when waiting for analysis). print() output is captured and returned values are serialized as 'return: <value>'. Scripts operate on the SAME shared binary session as the UI and every other MCP tool, so loads, renames, and comments are visible everywhere. Static-analysis API: slop.image.{load(path[,base]),load_from_target,unload,status,wait_ready([ms])}; slop.disasm.{decode(addr[,n]),functions([limit]),function_at(va),xrefs_to(va),strings([min[,limit]]),pe(),bytes(addr[,len]),name(va),set_name(va,name),comment(va),set_comment(va,text),bookmark_toggle(va),bookmarks()}; slop.decomp.{decompile(va),blocks(va),vtables(),globals(),rtti()} (decomp.* needs slop.image.wait_ready first). Live analysis: slop.target.{list,attach,status}, slop.mem.{read_hex,write_hex,scan}, slop.disasm.disassemble(addr,count), slop.analyze.packer. Typical flow: image.load(path) -> image.wait_ready() -> disasm.functions() -> decomp.decompile(va). Use direct MCP tools when one operation is sufficient."},
                   {"inputSchema", json::parse(script_schema)}, {"read_only", false}});
    out.push_back({{"name", "frida"},
                   {"description", "Instrument live processes with embedded frida-core 17.x. Start with status/devices; choose device, enumerate with ps/applications/find_process, then attach(pid) to obtain a session handle. Create and optionally auto-load JavaScript with script_create(session,source,runtime,load), or compile source with compile_script and pass its b64 back as script_create bytecode_b64. drain send()/console output with messages(script,limit), call rpc.exports with rpc(script,method,args,timeout_ms), and destroy scripts/detach sessions when finished. script_unload is terminal and removes its handle. spawn returns a suspended pid unless resumed; spawn/resume/kill/input and spawn/child gating support launch workflows. remote_add connects frida-server devices. Handles are returned by prior calls; do not substitute OS pids for session or script handles."},
                   {"inputSchema", json::parse(frida_schema)}, {"read_only", false}});
}

nlohmann::json call_tool(const std::string& name, const nlohmann::json& args,
                         bool& is_error, infra::cancel_token_t cancel) {
    is_error = false;
    try {
        // frida and magicmida have their own locks so dont hold ours
        if (name == "frida") return tool_frida(args, cancel);
        if (name == "devirt") {
            const std::string action = args.value("action", std::string{});
            if (action.rfind("themida_", 0) == 0) return tool_devirt(args);
        }
        std::lock_guard lk(g_tool_mu);
        if (name == "app")      return tool_app(args);
        if (name == "target")   return tool_target(args);
        if (name == "memory")   return tool_memory(args);
        if (name == "disasm")   return tool_disasm(args);
        if (name == "debugger") return tool_debugger(args);
        if (name == "driver")   return tool_driver(args);
        if (name == "emulate")  return tool_emulate(args);
        if (name == "analyze")  return tool_analyze(args);
        if (name == "network")  return tool_network(args);
        if (name == "proxy")    return tool_proxy(args);
        if (name == "persist")  return tool_persist(args);
        if (name == "re")       return tool_re(args);
        if (name == "script")   return tool_script(args);
        if (name == "decomp")   return tool_decomp(args);
        if (name == "detect")   return tool_detect(args);
        if (name == "fs")       return tool_fs(args);
        if (name == "web")      return tool_web(args);
        if (name == "xray")     return tool_xray(args);
        if (name == "patch")    return tool_patch(args);
        if (name == "types")    return tool_types(args);
        if (name == "notes")    return tool_notes(args);
        if (name == "devirt")   return tool_devirt(args);
        is_error = true;
        return {{"error", "unknown tool: " + name}};
    } catch (const std::exception& e) {
        is_error = true;
        return {{"error", e.what()}};
    } catch (...) {
        is_error = true;
        return {{"error", "unknown tool failure"}};
    }
}

void shutdown_tools() {
    std::lock_guard lk(g_tool_mu);
    if (g_dbg) {
        g_dbg->detach();
        g_dbg.reset();
    }
    g_proxy.stop();
    frida::frida_service_t::get().shutdown();
    g_scan.engine.reset();
    g_scan.used = false;
    g_snaps.clear();
    g_traffic.clear();
    g_image = {};
    magicmida::shutdown();
    memory::watch::shutdown();
}

json session_state() {
    std::lock_guard lk(g_tool_mu);
    return app_state_unlocked();
}

} // namespace slop::core::mcp








