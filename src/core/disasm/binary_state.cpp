// src/core/disasm/binary_state.cpp

#include <windows.h>

#include "core/disasm/binary_state.hpp"

#include "core/disasm/hyperion_session.hpp"
#include "core/infra/diag.hpp"
#include "core/process/target_service.hpp"
#include "core/re/type_catalog.hpp"
#include "core/runtime/backend_registry.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cctype>
#include <fstream>
#include <iterator>
#include <unordered_set>

namespace slop::core::disasm::binary_state {

namespace {

using json = nlohmann::json;

binary_t g_bin;

// guards load unload and the symbol map against ui vs mcp worker races, only mutators take it
std::mutex g_mu;

uint64_t fnv1a(const uint8_t* d, size_t n) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < n; ++i) {
        h ^= d[i];
        h *= 1099511628211ull;
    }
    return h;
}

std::string symbols_dir() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    const std::string dir = std::string(base, n) + "\\reverse-slop\\symbols";
    CreateDirectoryA((std::string(base, n) + "\\reverse-slop").c_str(), nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

std::string symbols_path_for(uint64_t hash) {
    const std::string dir = symbols_dir();
    if (dir.empty()) return {};
    char name[32];
    std::snprintf(name, sizeof(name), "%016llX.json",
                  static_cast<unsigned long long>(hash));
    return dir + "\\" + name;
}

struct session_meta_t {
    std::unordered_map<uint64_t, std::string> comments;
    std::vector<uint64_t>                     bookmarks;
};

void load_meta(binary_t& b, session_meta_t& out) {
    out.comments.clear();
    out.bookmarks.clear();
    const std::string path = symbols_path_for(b.file_hash);
    if (path.empty()) return;

    std::ifstream f(path);
    if (!f) return;
    try {
        json j;
        f >> j;
        // annotations save at the base they were made under, remap when the session loads elsewhere
        const uint64_t saved_base =
            j.contains("base") && j["base"].is_number_unsigned()
                ? j["base"].get<uint64_t>()
                : b.pe.image_base;
        const int64_t delta =
            saved_base && saved_base != b.base
                ? static_cast<int64_t>(b.base) - static_cast<int64_t>(saved_base)
                : 0;
        auto remap = [delta](uint64_t va) -> uint64_t {
            if (delta == 0) return va;
            return delta > 0 ? va + static_cast<uint64_t>(delta)
                             : va - static_cast<uint64_t>(-delta);
        };
        if (j.contains("symbols") && j["symbols"].is_object()) {
            for (auto it = j["symbols"].begin(); it != j["symbols"].end(); ++it) {
                const uint64_t va = std::strtoull(it.key().c_str(), nullptr, 16);
                if (va && it.value().is_string())
                    b.symbols[remap(va)] = it.value().get<std::string>();
            }
        }
        // legacy flat hexva to name form
        if (j.contains("name") == false && j.is_object()) {
            for (auto it = j.begin(); it != j.end(); ++it) {
                if (!it.key().empty() && std::isxdigit(static_cast<unsigned char>(it.key()[0])) &&
                    it.value().is_string()) {
                    const uint64_t va = std::strtoull(it.key().c_str(), nullptr, 16);
                    if (va && !b.symbols.count(remap(va))) b.symbols[remap(va)] = it.value().get<std::string>();
                }
            }
        }
        if (j.contains("comments") && j["comments"].is_object()) {
            for (auto it = j["comments"].begin(); it != j["comments"].end(); ++it) {
                const uint64_t va = std::strtoull(it.key().c_str(), nullptr, 16);
                if (va && it.value().is_string())
                    out.comments[remap(va)] = it.value().get<std::string>();
            }
        }
        if (j.contains("bookmarks") && j["bookmarks"].is_array()) {
            for (const auto& v : j["bookmarks"])
                if (v.is_number_unsigned()) out.bookmarks.push_back(remap(v.get<uint64_t>()));
        }
    } catch (...) {
        // corrupt store, start clean
        b.symbols.clear();
        out.comments.clear();
        out.bookmarks.clear();
    }
}

void save_meta(const binary_t& b) {
    const std::string path = symbols_path_for(b.file_hash);
    if (path.empty()) return;

    json hex_j = json::object();
    json cmts  = json::object();
    json marks = json::array();
    char key[24];
    for (const auto& [va, name] : b.symbols) {
        std::snprintf(key, sizeof(key), "%llX", static_cast<unsigned long long>(va));
        hex_j[key] = name;
    }
    for (const auto& [va, text] : b.comments) {
        std::snprintf(key, sizeof(key), "%llX", static_cast<unsigned long long>(va));
        cmts[key] = text;
    }
    for (uint64_t va : b.bookmarks)
        marks.push_back(static_cast<uint64_t>(va));

    json root = json::object();
    root["base"]      = b.base;      // rebase key for the remap on load
    root["symbols"]   = hex_j;
    root["comments"]  = cmts;
    root["bookmarks"] = marks;

    std::ofstream f(path, std::ios::trunc);
    if (f) f << root.dump(2);
}

// field wise reset since the engine is not movable, caller holds the lock
void unload_locked() {
    // tear hyperion down first, its destructor joins the analysis thread
    g_bin.hype.reset();
    g_bin.file.clear();
    g_bin.file.shrink_to_fit();
    g_bin.file_hash = 0;
    g_bin.pe = {};
    g_bin.base = 0;
    g_bin.name.clear();
    g_bin.path.clear();
    g_bin.fns = {};
    g_bin.xrefs = {};
    g_bin.strings.clear();
    g_bin.strings.shrink_to_fit();
    g_bin.symbols.clear();
    g_bin.comments.clear();
    g_bin.bookmarks.clear();
    g_bin.patches.clear();
    g_bin.indexes_dirty = false;
    g_bin.ready = false;
}

} // namespace

std::optional<size_t> binary_t::offset_of(uint64_t va) const {
    if (!ready || va < base || va - base > 0xFFFFFFFFull) return std::nullopt;
    return pe.rva_to_offset(static_cast<uint32_t>(va - base));
}

// defined here so the unique_ptr destructor sees the full type
binary_t::~binary_t() = default;

binary_t& get() { return g_bin; }

bool has_binary() { return g_bin.ready; }

void unload() {
    std::lock_guard lk(g_mu);
    unload_locked();
}

bool load_file(const std::string& path, uint64_t base_override) {
    // cheap check outside the lock before we tear down the current session
    {
        std::ifstream probe(path, std::ios::binary);
        if (!probe) return false;
        probe.seekg(0, std::ios::end);
        if (probe.tellg() < 1024) return false;
    }

    std::lock_guard lk(g_mu);
    unload_locked();

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    // one sized read, not a byte-at-a-time streambuf iterator pair: on a few
    // hundred megabytes the iterator form costs seconds on its own
    f.seekg(0, std::ios::end);
    const std::streamoff size = f.tellg();
    if (size < 1024) { unload_locked(); return false; }
    f.seekg(0, std::ios::beg);
    g_bin.file.resize(static_cast<size_t>(size));
    f.read(reinterpret_cast<char*>(g_bin.file.data()), size);
    if (!f) { unload_locked(); return false; }
    g_bin.file.resize(static_cast<size_t>(f.gcount()));
    if (g_bin.file.size() < 1024) { unload_locked(); return false; }
    g_bin.file_hash = fnv1a(g_bin.file.data(), g_bin.file.size());

    g_bin.pe = disasm::pe_parse(g_bin.file.data(), g_bin.file.size());
    if (!g_bin.pe.ok || !g_bin.eng.init(g_bin.pe.pe32plus)) { unload_locked(); return false; }

    // runtime base override so session vas match what the live process maps
    g_bin.base = base_override ? base_override : g_bin.pe.image_base;
    g_bin.path = path;

    const size_t slash = path.find_last_of("\\/");
    g_bin.name = (slash == std::string::npos) ? path : path.substr(slash + 1);

    // stage timings: a slow open should name the index that is slow
    using clock_t_ = std::chrono::steady_clock;
    auto stage = clock_t_::now();
    const auto stage_ms = [&stage] {
        const auto now = clock_t_::now();
        const double ms = std::chrono::duration<double, std::milli>(now - stage).count();
        stage = now;
        return ms;
    };

    if (!g_bin.fns.build(g_bin.pe, g_bin.file, g_bin.eng, g_bin.base))   { unload_locked(); return false; }
    const double fns_ms = stage_ms();
    if (!g_bin.xrefs.build(g_bin.pe, g_bin.file, g_bin.eng, g_bin.base)) { unload_locked(); return false; }
    const double xrefs_ms = stage_ms();

    // strings from the data sections, exec sections are skipped
    for (const auto& s : g_bin.pe.sections) {
        if (s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > g_bin.file.size()) continue;
        auto part = disasm::extract_strings(
            g_bin.file.data() + s.raw_offset, s.raw_size,
            g_bin.base + s.rva, 4, 200'000);
        g_bin.strings.insert(g_bin.strings.end(),
                             std::make_move_iterator(part.begin()),
                             std::make_move_iterator(part.end()));
    }

    session_meta_t meta;
    load_meta(g_bin, meta);
    g_bin.comments  = std::move(meta.comments);
    g_bin.bookmarks = std::move(meta.bookmarks);
    g_bin.ready = true;

    // the type catalog rides the same per hash store, rebind on load
    slop::core::re::type_catalog::bind_binary(g_bin.file.data(), g_bin.file.size());

    const double strings_ms = stage_ms();

    char timing[160];
    std::snprintf(timing, sizeof(timing),
                  " (functions %.0f ms, xrefs %.0f ms, strings %.0f ms)",
                  fns_ms, xrefs_ms, strings_ms);
    slop::core::infra::diag::info("disasm", "loaded " + g_bin.name + ", " +
        std::to_string(g_bin.fns.functions().size()) + " functions, " +
        std::to_string(g_bin.xrefs.total()) + " xrefs, " +
        std::to_string(g_bin.strings.size()) + " strings" + timing);

    // hyperion analysis in the background, small binaries finish in under a second and big ones stay responsive through the ready flag
    g_bin.hype = std::make_unique<hyperion_session::session_t>();
    if (!g_bin.hype->start(g_bin.file.data(), g_bin.file.size(), g_bin.base)) {
        slop::core::infra::diag::warn("hyperion", g_bin.hype->error());
        g_bin.hype.reset();
    } else {
        g_bin.hype->queue_names(g_bin.symbols);
    }
    return true;
}

bool load_from_target() {
    const auto session = slop::core::process::active_session();
    if (!session || !session->valid()) return false;

    auto mods = slop::core::runtime::active().enum_modules(session->handle());
    if (!mods.ok || mods.items.empty()) return false;

    // main module is the exact name match with a readable path, runtime base comes along
    for (const auto& m : mods.items) {
        if (!m.path.empty() &&
            _stricmp(m.name.c_str(), session->name().c_str()) == 0)
            return load_file(m.path, m.base);
    }
    // fall back to the biggest module with a path, usually the main image
    size_t best = SIZE_MAX;
    for (size_t i = 0; i < mods.items.size(); ++i) {
        const auto& m = mods.items[i];
        if (m.path.empty()) continue;
        if (best == SIZE_MAX || m.size > mods.items[best].size) best = i;
    }
    if (best != SIZE_MAX)
        return load_file(mods.items[best].path, mods.items[best].base);
    for (const auto& m : mods.items)
        if (!m.path.empty()) return load_file(m.path, m.base);
    return false;
}

void set_symbol(uint64_t va, const std::string& name) {
    std::lock_guard lk(g_mu);
    if (!g_bin.ready) return;
    if (name.empty()) g_bin.symbols.erase(va);
    else              g_bin.symbols[va] = name;
    save_meta(g_bin);

    // mirror renames into the hyperion db, queued if a reanalysis is still running
    if (g_bin.hype) {
        if (g_bin.hype->ready()) {
            auto& names = g_bin.hype->db_mut().names;
            if (name.empty()) names.erase(va);
            else              names[va] = name;
        } else {
            g_bin.hype->queue_names({{va, name}});
        }
    }
}

std::string symbol_name(uint64_t va) {
    std::lock_guard lk(g_mu);
    const auto it = g_bin.symbols.find(va);
    return it != g_bin.symbols.end() ? it->second : std::string{};
}

std::vector<std::pair<uint64_t, std::string>> symbols_snapshot() {
    std::lock_guard lk(g_mu);
    return {g_bin.symbols.begin(), g_bin.symbols.end()};
}

void set_comment(uint64_t va, const std::string& text) {
    std::lock_guard lk(g_mu);
    if (!g_bin.ready) return;
    if (text.empty()) g_bin.comments.erase(va);
    else              g_bin.comments[va] = text;
    save_meta(g_bin);
}

std::string comment_for(uint64_t va) {
    std::lock_guard lk(g_mu);
    const auto it = g_bin.comments.find(va);
    return it != g_bin.comments.end() ? it->second : std::string{};
}

std::vector<std::pair<uint64_t, std::string>> comments_snapshot() {
    std::lock_guard lk(g_mu);
    return {g_bin.comments.begin(), g_bin.comments.end()};
}

bool toggle_bookmark(uint64_t va) {
    std::lock_guard lk(g_mu);
    if (!g_bin.ready) return false;
    const auto it = std::find(g_bin.bookmarks.begin(), g_bin.bookmarks.end(), va);
    if (it != g_bin.bookmarks.end()) {
        g_bin.bookmarks.erase(it);
        save_meta(g_bin);
        return false;
    }
    g_bin.bookmarks.push_back(va);
    save_meta(g_bin);
    return true;
}

bool is_bookmarked(uint64_t va) {
    std::lock_guard lk(g_mu);
    return std::find(g_bin.bookmarks.begin(), g_bin.bookmarks.end(), va)
           != g_bin.bookmarks.end();
}

std::vector<uint64_t> bookmarks_snapshot() {
    std::lock_guard lk(g_mu);
    return g_bin.bookmarks;
}

const char* symbol_for(uint64_t va) {
    const auto& s = g_bin.symbols;
    const auto it = s.find(va);
    return it != s.end() ? it->second.c_str() : nullptr;
}

std::mutex& state_mutex() { return g_mu; }

bool hype_ready() {
    std::lock_guard lk(g_mu);
    return g_bin.ready && g_bin.hype && g_bin.hype->ready();
}

float hype_progress() {
    std::lock_guard lk(g_mu);
    if (!g_bin.ready || !g_bin.hype) return 0.f;
    return g_bin.hype->progress();
}

hype_status_t hype_status() {
    std::lock_guard lk(g_mu);
    hype_status_t st;
    st.has_image = g_bin.ready;
    if (!g_bin.ready) return st;
    st.image         = g_bin.name;
    st.engine_present = g_bin.hype != nullptr;
    if (!g_bin.hype) return st;
    st.ready        = g_bin.hype->ready();
    st.truncated    = st.ready && g_bin.hype->truncated();
    st.running      = !st.ready && g_bin.hype->running();
    st.progress     = st.ready ? 1.f : g_bin.hype->progress();
    if (!st.ready) st.engine_error = g_bin.hype->error();
    return st;
}

void hype_stop() {
    std::lock_guard lk(g_mu);
    if (g_bin.ready && g_bin.hype) g_bin.hype->stop();
}

} // namespace slop::core::disasm::binary_state
