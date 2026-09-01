// src/core/script/lua_engine.cpp

#include "core/script/lua_engine.hpp"

#include "core/analysis/packer.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/engine.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/memory/memscan.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/scan_bridge.hpp"

#include <lua.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <thread>

namespace slop::core::script {

namespace {

namespace infra = slop::core::infra;
namespace memory = slop::core::memory;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace disasm = slop::core::disasm;
namespace analysis = slop::core::analysis;
namespace hs = slop::core::disasm::hyperion_session;
namespace ds = slop::core::disasm::binary_state;

constexpr const char* kOutputKey = "__slop_output";
constexpr const char* kDeadlineKey = "__slop_deadline";

thread_local int64_t t_deadline_ms = 0;

void out_append(lua_State* L, const std::string& s) {
    lua_getfield(L, LUA_REGISTRYINDEX, kOutputKey);
    auto* buf = static_cast<std::string*>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (buf) *buf += s;
}

uint64_t to_addr(lua_State* L, int idx) {
    if (lua_isstring(L, idx)) {
        const char* s = lua_tostring(L, idx);
        return std::strtoull(s, nullptr, 0);
    }
    return static_cast<uint64_t>(lua_tointegerx(L, idx, nullptr));
}

int l_log(lua_State* L) {
    const int n = lua_gettop(L);
    for (int i = 1; i <= n; ++i) {
        size_t len = 0;
        const char* s = luaL_tolstring(L, i, &len);
        out_append(L, s ? std::string(s, len) : std::string("nil"));
        lua_pop(L, 1);
        if (i < n) out_append(L, "\t");
    }
    out_append(L, "\n");
    return 0;
}

int l_version(lua_State* L) {
    lua_pushstring(L, "reverse-slop script engine (Lua 5.4)");
    return 1;
}

// helpers

// raise lua errors from a dedicated noinline frame, longjmp on x64 walks
// every frame and an inlined raise with c++ locals can crash the unwinder
// the message goes through %s so dynamic content is never a format string
__declspec(noinline) int lua_fail(lua_State* L, const char* msg) {
    return luaL_error(L, "%s", msg);
}

// Push a table of strings (array part)
void push_str_array(lua_State* L, const std::vector<std::string>& v) {
    lua_createtable(L, static_cast<int>(std::min<size_t>(v.size(), 65536)), 0);
    int i = 1;
    for (const auto& s : v) {
        if (i > 65536) break;
        lua_pushstring(L, s.c_str());
        lua_rawseti(L, -2, i++);
    }
}

// Shared-image helpers: pin the session against concurrent load/unload for
// the duration of one binding call (same contract the MCP tools use)

// Requires a loaded image; errors (Lua-level) otherwise. Returns nothing on
// failure (longjmp out of the binding)
__declspec(noinline) bool need_image(lua_State* L) {
    if (ds::has_binary()) return true;
    lua_fail(L, "no image loaded in reverse-slop (slop.image.load a binary first)");
    return false;   // unreachable
}

const char* xref_kind_name_lua(hype::XrefType t) {
    switch (t) {
    case hype::XrefType::CodeCall:   return "call";
    case hype::XrefType::CodeJump:   return "jump";
    case hype::XrefType::DataRead:   return "read";
    case hype::XrefType::DataWrite:  return "write";
    case hype::XrefType::DataOffset: return "offset";
    default:                         return "other";
    }
}

// lua errors longjmp past c++ destructors so never raise while a binary
// lock is alive, capture the error, drop the lock, then raise
// and while the lock is held read bin fields directly since the helpers
// re take the same mutex
hs::session_t* pinned_hype(std::string& err) {
    auto& bin = ds::get();
    if (!bin.ready) {
        err = "no image loaded in reverse-slop (slop.image.load a binary first)";
        return nullptr;
    }
    if (!bin.hype) {
        err = "hyperion engine unavailable for this image";
        return nullptr;
    }
    if (!bin.hype->ready()) {
        const std::string herr = bin.hype->error();
        if (!herr.empty()) err = "hyperion analysis failed, " + herr;
        else err = "hyperion analysis in progress, call slop.image.wait_ready() first";
        return nullptr;
    }
    return bin.hype.get();
}

// target

bool session_valid() {
    auto s = process::active_session();
    return s && s->valid();
}

const char* arch_name(runtime::arch_t a) {
    switch (a) {
    case runtime::arch_t::x64: return "x64";
    case runtime::arch_t::x86: return "x86";
    default: return "unknown";
    }
}

int l_target_list(lua_State* L) {
    auto res = runtime::active().enum_processes();
    lua_createtable(L, 0, 64);
    if (!res.ok) return 1;
    int i = 1;
    for (const auto& p : res.items) {
        if (i > 4096) break;
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, p.pid);            lua_setfield(L, -2, "pid");
        lua_pushstring(L, p.name.c_str());    lua_setfield(L, -2, "name");
        lua_pushstring(L, arch_name(p.arch)); lua_setfield(L, -2, "arch");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_target_attach(lua_State* L) {
    const uint64_t pid = to_addr(L, 1);
    if (pid == 0 || pid > 0xFFFFFFFFull)
        return lua_fail(L, "bad pid");
    const bool ok = process::target_attach(static_cast<uint32_t>(pid));
    lua_pushboolean(L, ok);
    if (!ok) { lua_pushstring(L, "attach failed"); return 2; }
    auto s = process::active_session();
    lua_pushstring(L, s ? s->name().c_str() : "");
    return 2;
}

int l_target_status(lua_State* L) {
    lua_createtable(L, 0, 4);
    lua_pushstring(L, runtime::active_badge());
    lua_setfield(L, -2, "backend");
    auto s = process::active_session();
    lua_pushboolean(L, session_valid());
    lua_setfield(L, -2, "attached");
    if (session_valid()) {
        auto s2 = process::active_session();
        lua_pushinteger(L, s2->pid());         lua_setfield(L, -2, "pid");
        lua_pushstring(L, s2->name().c_str()); lua_setfield(L, -2, "name");
    }
    return 1;
}

// memory

runtime::session_t& need_session_lua(lua_State* L) {
    auto s = process::active_session();
    if (!s || !s->valid()) lua_fail(L, "no target attached");
    return *s;
}

std::vector<uint8_t> hex_decode_str(const std::string& hex, bool* ok) {
    std::vector<uint8_t> out;
    std::string clean;
    for (char c : hex) {
        if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
        else if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {}
        else { *ok = false; return out; }
    }
    if (clean.size() % 2) { *ok = false; return out; }
    for (size_t i = 0; i < clean.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(
            std::strtoul(clean.substr(i, 2).c_str(), nullptr, 16)));
    }
    *ok = true;
    return out;
}

int l_mem_read(lua_State* L) {
    auto& s = need_session_lua(L);
    const uint64_t addr = to_addr(L, 1);
    const uint64_t len = to_addr(L, 2);
    if (len == 0 || len > (1ull << 20)) return lua_fail(L, "bad length");
    std::vector<uint8_t> buf(static_cast<size_t>(len));
    auto io = s.read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
    if (!io.ok) return lua_fail(L, "read failed");
    lua_pushlstring(L, reinterpret_cast<const char*>(buf.data()), buf.size());
    return 1;
}

int l_mem_write(lua_State* L) {
    auto& s = need_session_lua(L);
    const uint64_t addr = to_addr(L, 1);
    size_t hex_len = 0;
    const char* hex = luaL_checklstring(L, 2, &hex_len);
    bool ok = false;
    auto bytes = hex_decode_str(std::string(hex, hex_len), &ok);
    if (!ok || bytes.empty()) return lua_fail(L, "bad hex payload");
    auto io = s.write(static_cast<uintptr_t>(addr), bytes.data(), bytes.size());
    if (!io.ok) return lua_fail(L, "write failed");
    lua_pushinteger(L, static_cast<lua_Integer>(io.bytes));
    return 1;
}

memory::value_width_t parse_width(const std::string& w) {
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
    return memory::value_width_t::i32;
}

struct lua_reader_t final : memory::reader_t {
    runtime::session_t& s;
    explicit lua_reader_t(runtime::session_t& sess) : s(sess) {}
    bool read(uintptr_t addr, void* dst, size_t len) override {
        auto io = s.read(addr, dst, len);
        return io.ok && io.bytes == len;
    }
};

int l_mem_scan(lua_State* L) {
    auto& sess = need_session_lua(L);
    luaL_checktype(L, 1, LUA_TTABLE);

    auto field_s = [&](const char* k) -> std::optional<std::string> {
        lua_getfield(L, 1, k);
        const char* v = lua_tostring(L, -1);
        const std::string out = v ? v : "";
        lua_pop(L, 1);
        if (!v) return std::nullopt;
        return out;
    };
    auto field_n = [&](const char* k) -> std::optional<uint64_t> {
        lua_getfield(L, 1, k);
        const bool is_num = lua_isnumber(L, -1) != 0;
        const uint64_t v =
            is_num ? static_cast<uint64_t>(lua_tointeger(L, -1)) : 0;
        lua_pop(L, 1);
        if (!is_num) return std::nullopt;
        return v;
    };

    memory::scan_config_t cfg;
    const auto kind  = field_s("kind").value_or("exact");
    const auto width = parse_width(field_s("width").value_or("i32"));
    cfg.width = width;
    if (auto b = field_n("begin")) cfg.begin = static_cast<uintptr_t>(*b);
    if (auto e = field_n("end"))   cfg.end   = static_cast<uintptr_t>(*e);
    cfg.fast = memory::fastscan_method_t::alignment;
    cfg.fast_alignment = static_cast<uint32_t>(field_n("alignment").value_or(4));
    if (cfg.fast_alignment == 0) cfg.fast = memory::fastscan_method_t::off;

    if      (kind == "unknown")        cfg.type = memory::scan_type_t::unknown_initial;
    else if (kind == "between")        cfg.type = memory::scan_type_t::between;
    else if (kind == "bigger")         cfg.type = memory::scan_type_t::bigger_than;
    else if (kind == "smaller")        cfg.type = memory::scan_type_t::smaller_than;
    else if (kind == "increased")      cfg.type = memory::scan_type_t::increased;
    else if (kind == "increased_by")   cfg.type = memory::scan_type_t::increased_by;
    else if (kind == "decreased")      cfg.type = memory::scan_type_t::decreased;
    else if (kind == "decreased_by")   cfg.type = memory::scan_type_t::decreased_by;
    else if (kind == "changed")        cfg.type = memory::scan_type_t::changed;
    else if (kind == "unchanged")      cfg.type = memory::scan_type_t::unchanged;
    else                               cfg.type = memory::scan_type_t::exact_value;

    if (auto v = field_n("value")) {
        cfg.value1 = memory::value_to_double(width, *v);
    }
    if (auto v2 = field_n("value2")) {
        cfg.value2 = memory::value_to_double(width, *v2);
    }

    infra::cancel_token_t tok;
    lua_reader_t reader(sess);

    // Region set from the active backend (driver ER path under slopdrvr)
    auto regions = runtime::target_scan_regions(sess.handle());

    memory::memscan_t engine;
    std::string err;
    engine.first_scan(reader, std::move(regions), cfg, tok, &err);
    if (!err.empty()) return lua_fail(L, err.c_str());

    const auto& hits = engine.results();
    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(hits.size(), 10000)));
    int i = 1;
    for (const auto& h : hits) {
        if (i > 10000) break;
        lua_pushinteger(L, static_cast<lua_Integer>(h.address));
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// live disasm

disasm::engine_t& shared_engine() {
    static disasm::engine_t eng;
    return eng;
}

int l_disasm_disassemble(lua_State* L) {
    auto& s = need_session_lua(L);
    const uint64_t addr = to_addr(L, 1);
    const uint64_t count_req = to_addr(L, 2);
    const int count = static_cast<int>(
        std::min<uint64_t>(count_req ? count_req : 32, 512));
    auto& eng = shared_engine();
    if (!eng.ok() && !eng.init()) return lua_fail(L, "zydis init failed");

    std::vector<uint8_t> buf(static_cast<size_t>(count) * 16 + 16);
    auto io = s.read(static_cast<uintptr_t>(addr), buf.data(), buf.size());
    if (!io.ok) return lua_fail(L, "cannot read code range");

    lua_createtable(L, 0, count);
    size_t off = 0;
    for (int i = 1; i <= count; ++i) {
        auto insn = eng.decode(addr + off, buf.data() + off, buf.size() - off);
        if (!insn) break;
        lua_pushstring(L, insn->text.c_str());
        lua_rawseti(L, -2, i);
        off += insn->length;
    }
    return 1;
}

// analyze (loaded binary)

int l_analyze_packer(lua_State* L) {
    if (!need_image(L)) return 0;
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    auto v = analysis::packer_analyze(bin.pe, bin.file);
    lua_createtable(L, 0, 4);
    lua_pushboolean(L, v.packed);          lua_setfield(L, -2, "packed");
    lua_pushstring(L, v.family.c_str());   lua_setfield(L, -2, "family");
    lua_pushnumber(L, v.confidence);       lua_setfield(L, -2, "confidence");
    lua_pushnumber(L, v.file_entropy);     lua_setfield(L, -2, "file_entropy");
    return 1;
}

// static analysis over the shared session, the ida style surface
// renames and comments made here show up everywhere

int l_image_status(lua_State* L);

int l_image_load(lua_State* L) {
    size_t plen = 0;
    const char* path = luaL_checklstring(L, 1, &plen);
    const uint64_t base = lua_gettop(L) >= 2 ? to_addr(L, 2) : 0;
    if (!ds::load_file(std::string(path, plen), base))
        return lua_fail(L, ("failed to load: " + std::string(path, plen)).c_str());
    return l_image_status(L);
}

int l_image_load_from_target(lua_State* L) {
    if (!ds::load_from_target())
        return lua_fail(L, "no attached target or readable main module");
    return l_image_status(L);
}

int l_image_unload(lua_State* L) {
    ds::unload();
    lua_pushboolean(L, true);
    return 1;
}

int l_image_status(lua_State* L) {
    lua_createtable(L, 0, 12);
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    lua_pushboolean(L, bin.ready);          lua_setfield(L, -2, "ready");
    lua_pushstring(L, bin.name.c_str());    lua_setfield(L, -2, "name");
    lua_pushstring(L, bin.path.c_str());    lua_setfield(L, -2, "path");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.base));
    lua_setfield(L, -2, "base");
    if (!bin.ready) return 1;

    lua_pushinteger(L, static_cast<lua_Integer>(bin.base + bin.pe.entry_rva));
    lua_setfield(L, -2, "entry");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.image_base));
    lua_setfield(L, -2, "preferred_base");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.size_of_image));
    lua_setfield(L, -2, "size_of_image");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.fns.functions().size()));
    lua_setfield(L, -2, "functions");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.xrefs.total()));
    lua_setfield(L, -2, "xrefs");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.strings.size()));
    lua_setfield(L, -2, "strings");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.symbols.size()));
    lua_setfield(L, -2, "symbols");

    // Hyperion sub-table
    lua_createtable(L, 0, 8);
    const bool has_hype = bin.hype != nullptr;
    lua_pushboolean(L, has_hype);          lua_setfield(L, -2, "available");
    if (has_hype) {
        const bool rdy = bin.hype->ready();
        lua_pushboolean(L, rdy);           lua_setfield(L, -2, "ready");
        lua_pushnumber(L, bin.hype->progress());
        lua_setfield(L, -2, "progress");
        if (rdy) {
            const auto& db = bin.hype->db();
            lua_pushinteger(L, static_cast<lua_Integer>(db.funcs.size()));
            lua_setfield(L, -2, "functions");
            lua_pushinteger(L, static_cast<lua_Integer>(db.insns.size()));
            lua_setfield(L, -2, "instructions");
            lua_pushinteger(L, static_cast<lua_Integer>(db.xrefs.size()));
            lua_setfield(L, -2, "xrefs");
            lua_pushinteger(L, static_cast<lua_Integer>(db.vtables.size()));
            lua_setfield(L, -2, "vtables");
            lua_pushinteger(L, static_cast<lua_Integer>(db.globals.size()));
            lua_setfield(L, -2, "globals");
            lua_pushinteger(L, static_cast<lua_Integer>(bin.hype->rtti().classes().size()));
            lua_setfield(L, -2, "rtti_classes");
        }
        const std::string herr = bin.hype->error();
        if (!herr.empty()) {
            lua_pushstring(L, herr.c_str());
            lua_setfield(L, -2, "error");
        }
    }
    lua_setfield(L, -2, "hype");
    return 1;
}

int l_image_wait_ready(lua_State* L) {
    const uint64_t timeout_ms = lua_gettop(L) >= 1 ? to_addr(L, 1) : 30000;
    const auto deadline =
        std::chrono::steady_clock::now() +
        std::chrono::milliseconds(std::clamp<uint64_t>(timeout_ms, 0, 300000));
    for (;;) {
        std::string err;
        bool ready = false;
        {
            ds::binary_lock_t lock;
            auto& bin = ds::get();
            if (!bin.ready)
                err = "no image loaded in reverse-slop";
            else if (!bin.hype)
                err = "hyperion engine unavailable for this image";
            else if (bin.hype->ready())
                ready = true;
            else {
                const std::string herr = bin.hype->error();
                if (!herr.empty()) err = "hyperion analysis failed, " + herr;
            }
        }
        if (!err.empty()) return lua_fail(L, err.c_str());
        if (ready) { lua_pushboolean(L, true); return 1; }
        if (std::chrono::steady_clock::now() >= deadline) {
            lua_pushboolean(L, false);
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

// slop.disasm: static disassembly over the loaded image

int l_disasm_decode(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t addr = to_addr(L, 1);
    const uint64_t count_req = lua_gettop(L) >= 2 ? to_addr(L, 2) : 32;
    const size_t count = static_cast<size_t>(
        std::min<uint64_t>(count_req ? count_req : 32, 512));

    std::string err;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        auto off = bin.offset_of(addr);
        if (!off) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "address %llx is outside the loaded image",
                          static_cast<unsigned long long>(addr));
            err = buf;
        } else {
            const size_t avail =
                bin.file.size() > *off ? bin.file.size() - *off : 0;
            if (avail == 0)
                err = "no bytes at address";
            else {
                lua_createtable(L, 0, static_cast<int>(count));
                size_t consumed = 0;
                size_t made = 0;
                disasm::insn_t insn;
                for (size_t i = 0; i < count && consumed < avail;) {
                    if (!hs::session_t::decode(
                            addr + consumed, bin.file.data() + *off + consumed,
                            avail - consumed, insn)) {
                        // 1-byte resync (same contract as the MCP path)
                        ++consumed;
                        continue;
                    }
                    ++made;
                    lua_createtable(L, 0, 7);
                    lua_pushinteger(L, static_cast<lua_Integer>(insn.va));
                    lua_setfield(L, -2, "addr");
                    lua_pushinteger(L, insn.length);
                    lua_setfield(L, -2, "len");
                    lua_pushstring(L, insn.text.c_str());
                    lua_setfield(L, -2, "text");
                    lua_pushlstring(L, reinterpret_cast<const char*>(insn.bytes),
                                    insn.length);
                    lua_setfield(L, -2, "bytes");
                    if (insn.has_rel_target) {
                        lua_pushinteger(L, static_cast<lua_Integer>(insn.rel_target));
                        lua_setfield(L, -2, "target");
                    }
                    if (insn.has_rip_rel) {
                        lua_pushinteger(L, static_cast<lua_Integer>(insn.rip_rel_target));
                        lua_setfield(L, -2, "rip_target");
                    }
                    lua_rawseti(L, -2, static_cast<lua_Integer>(made));
                    consumed += insn.length ? insn.length : 1;
                }
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_disasm_functions(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t limit_req = lua_gettop(L) >= 1 ? to_addr(L, 1) : 0;
    const size_t limit = static_cast<size_t>(
        std::min<uint64_t>(limit_req ? limit_req : 10000, 100000));

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    const auto& fns = bin.fns.functions();
    const bool hready = bin.hype && bin.hype->ready();
    const hype::AnalysisDB* hdb = hready ? &bin.hype->db() : nullptr;

    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(fns.size(), limit)));
    size_t i = 0;
    for (const auto& f : fns) {
        if (i >= limit) break;
        lua_createtable(L, 0, 6);
        lua_pushinteger(L, static_cast<lua_Integer>(f.va));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(f.size));
        lua_setfield(L, -2, "size");
        // Name: user symbol > hyperion name > sub_<rva>
        std::string name;
        const auto sit = bin.symbols.find(f.va);
        if (sit != bin.symbols.end()) {
            name = sit->second;
        } else if (hdb) {
            const auto nit = hdb->names.find(f.va);
            if (nit != hdb->names.end()) name = nit->second;
        }
        if (name.empty() && hdb) {
            const auto fit = hdb->funcs.find(f.va);
            if (fit != hdb->funcs.end() && !fit->second.name.empty())
                name = fit->second.name;
        }
        if (name.empty()) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "sub_%llX",
                          static_cast<unsigned long long>(f.va - bin.base));
            name = buf;
        }
        lua_pushstring(L, name.c_str());
        lua_setfield(L, -2, "name");
        if (hdb) {
            const auto fit = hdb->funcs.find(f.va);
            if (fit != hdb->funcs.end()) {
                const auto& hf = fit->second;
                lua_pushinteger(L, static_cast<lua_Integer>(hf.blocks.size()));
                lua_setfield(L, -2, "blocks");
                if (!hf.loops.empty()) {
                    lua_pushinteger(L, static_cast<lua_Integer>(hf.loops.size()));
                    lua_setfield(L, -2, "loops");
                }
                if (hf.noreturn) {
                    lua_pushboolean(L, true);
                    lua_setfield(L, -2, "noreturn");
                }
            }
        }
        lua_rawseti(L, -2, static_cast<lua_Integer>(++i));
    }
    return 1;
}

int l_disasm_function_at(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    if (bin.hype && bin.hype->ready()) {
        if (const hype::Function* f = bin.hype->function_at(va); f) {
            const uint64_t img_base =
                bin.hype->db().image_base ? bin.hype->db().image_base
                                          : bin.base;
            std::string name;
            const auto sit = bin.symbols.find(f->entry);
            if (sit != bin.symbols.end()) name = sit->second;
            if (name.empty()) {
                const auto nit = bin.hype->db().names.find(f->entry);
                if (nit != bin.hype->db().names.end()) name = nit->second;
            }
            if (name.empty() && !f->name.empty()) name = f->name;
            if (name.empty()) {
                char buf[32];
                std::snprintf(buf, sizeof(buf), "sub_%llX",
                              static_cast<unsigned long long>(f->entry - img_base));
                name = buf;
            }
            lua_createtable(L, 0, 4);
            lua_pushinteger(L, static_cast<lua_Integer>(f->entry));
            lua_setfield(L, -2, "va");
            lua_pushstring(L, name.c_str());
            lua_setfield(L, -2, "name");
            if (!f->ranges.empty()) {
                const uint64_t lo = f->ranges.front().first;
                const uint64_t hi = f->ranges.back().second;
                lua_pushinteger(L, static_cast<lua_Integer>(hi - lo));
                lua_setfield(L, -2, "size");
            }
            lua_pushboolean(L, true);
            lua_setfield(L, -2, "hype");
            return 1;
        }
    }
    if (auto owner = bin.fns.containing(va); owner) {
        const uint64_t f = *owner;
        // Find the size from the index
        size_t size = 0;
        for (const auto& fn : bin.fns.functions())
            if (fn.va == f) { size = fn.size; break; }
        // Read the symbol directly, ds::symbol_name() re-takes this mutex
        // Fall back to sub_<rva> so a function entry is never nameless
        std::string name;
        const auto sit = bin.symbols.find(f);
        if (sit != bin.symbols.end()) name = sit->second;
        if (name.empty()) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "sub_%llX",
                          static_cast<unsigned long long>(f - bin.base));
            name = buf;
        }
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(f));
        lua_setfield(L, -2, "va");
        lua_pushstring(L, name.c_str());
        lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(size));
        lua_setfield(L, -2, "size");
        return 1;
    }
    lua_pushnil(L);
    return 1;
}

int l_disasm_xrefs_to(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    if (bin.hype && bin.hype->ready()) {
        const auto& db = bin.hype->db();
        const auto  it = db.xrefs_to.find(va);
        lua_createtable(L, 0, 8);
        int i = 1;
        if (it != db.xrefs_to.end()) {
            // Dedup by from-address keeping the strongest kind (a direct
            // call/jmp emits both a Code* and a DataOffset record)
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
                const char* k = xref_kind_name_lua(x.type);
                const int   r = kind_rank(x.type);
                const auto  b = best.find(x.from);
                if (b == best.end() || b->second.first < r)
                    best[x.from] = {r, k};
            }
            for (const auto& [from, p] : best) {
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(from));
                lua_setfield(L, -2, "from");
                lua_pushstring(L, p.second);
                lua_setfield(L, -2, "kind");
                lua_rawseti(L, -2, i++);
            }
        }
        return 1;
    }
    const auto& refs = bin.xrefs.refs_to(va);
    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(refs.size(), 10000)));
    int i = 1;
    for (const auto& r : refs) {
        if (i > 10000) break;
        lua_createtable(L, 0, 2);
        lua_pushinteger(L, static_cast<lua_Integer>(r.from));
        lua_setfield(L, -2, "from");
        lua_pushstring(L, r.kind == disasm::xref_kind_t::call ? "call"
                       : r.kind == disasm::xref_kind_t::jmp ? "jmp"
                                                            : "data");
        lua_setfield(L, -2, "kind");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_disasm_strings(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t min_req = lua_gettop(L) >= 1 ? to_addr(L, 1) : 4;
    const size_t min_chars = static_cast<size_t>(std::min<uint64_t>(min_req, 256));
    const uint64_t limit_req = lua_gettop(L) >= 2 ? to_addr(L, 2) : 10000;
    const size_t limit = static_cast<size_t>(
        std::min<uint64_t>(limit_req ? limit_req : 10000, 100000));

    ds::binary_lock_t lock;
    auto& bin = ds::get();
    // Pre-scanned strings (built at load) are filtered by min_chars >= 4;
    // smaller thresholds re-extract from the file image
    std::vector<disasm::string_hit_t> hits;
    if (min_chars <= 4) {
        hits = bin.strings;
    } else {
        for (const auto& sec : bin.pe.sections) {
            if (sec.is_executable() || sec.raw_size == 0) continue;
            if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bin.file.size())
                continue;
            auto part = disasm::extract_strings(
                bin.file.data() + sec.raw_offset, sec.raw_size,
                bin.base + sec.rva, min_chars, 200'000);
            hits.insert(hits.end(),
                        std::make_move_iterator(part.begin()),
                        std::make_move_iterator(part.end()));
        }
    }

    lua_createtable(L, 0, static_cast<int>(std::min<size_t>(hits.size(), limit)));
    int i = 1;
    for (const auto& h : hits) {
        if (static_cast<size_t>(i) > limit) break;
        lua_createtable(L, 0, 3);
        lua_pushinteger(L, static_cast<lua_Integer>(h.va));
        lua_setfield(L, -2, "va");
        lua_pushstring(L, h.text.c_str());
        lua_setfield(L, -2, "text");
        lua_pushboolean(L, h.utf16);
        lua_setfield(L, -2, "utf16");
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

int l_disasm_pe(lua_State* L) {
    if (!need_image(L)) return 0;
    ds::binary_lock_t lock;
    auto& bin = ds::get();
    lua_createtable(L, 0, 8);
    lua_pushboolean(L, bin.pe.pe32plus);      lua_setfield(L, -2, "pe32plus");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.image_base));
    lua_setfield(L, -2, "image_base");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.entry_rva));
    lua_setfield(L, -2, "entry_rva");
    lua_pushinteger(L, static_cast<lua_Integer>(bin.pe.size_of_image));
    lua_setfield(L, -2, "size_of_image");
    lua_pushinteger(L, bin.pe.machine);       lua_setfield(L, -2, "machine");
    lua_pushinteger(L, bin.pe.subsystem);     lua_setfield(L, -2, "subsystem");

    // sections
    lua_createtable(L, 0, static_cast<int>(bin.pe.sections.size()));
    int i = 1;
    for (const auto& sec : bin.pe.sections) {
        lua_createtable(L, 0, 6);
        lua_pushstring(L, sec.name);          lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(bin.base + sec.rva));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, static_cast<lua_Integer>(sec.virtual_size));
        lua_setfield(L, -2, "vsize");
        lua_pushinteger(L, static_cast<lua_Integer>(sec.raw_size));
        lua_setfield(L, -2, "raw_size");
        lua_pushboolean(L, sec.is_executable());
        lua_setfield(L, -2, "exec");
        lua_pushboolean(L, (sec.characteristics & 0x80000000u) != 0);
        lua_setfield(L, -2, "writable");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "sections");

    // imports
    lua_createtable(L, 0, static_cast<int>(bin.pe.imports.size()));
    i = 1;
    for (const auto& dll : bin.pe.imports) {
        lua_createtable(L, 0, 2);
        lua_pushstring(L, dll.dll.c_str());   lua_setfield(L, -2, "dll");
        push_str_array(L, [&] {
            std::vector<std::string> names;
            names.reserve(dll.functions.size());
            for (const auto& fn : dll.functions) names.push_back(fn.name);
            return names;
        }());
        lua_setfield(L, -2, "functions");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "imports");

    // exports
    lua_createtable(L, 0, static_cast<int>(bin.pe.exports.size()));
    i = 1;
    for (const auto& e : bin.pe.exports) {
        lua_createtable(L, 0, 3);
        lua_pushstring(L, e.name.c_str());    lua_setfield(L, -2, "name");
        lua_pushinteger(L, static_cast<lua_Integer>(bin.base + e.rva));
        lua_setfield(L, -2, "va");
        lua_pushinteger(L, e.ordinal);        lua_setfield(L, -2, "ordinal");
        lua_rawseti(L, -2, i++);
    }
    lua_setfield(L, -2, "exports");
    return 1;
}

// slop.disasm: names / comments / bookmarks (persisted, shared with UI)

int l_name_get(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    std::string name;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        // user symbol > hyperion name > sub_<rva> (same precedence as decomp)
        // bin.symbols is read directly, symbol_name() re-takes this mutex
        const auto sit = bin.symbols.find(va);
        if (sit != bin.symbols.end()) name = sit->second;
        else if (bin.hype && bin.hype->ready()) {
            const auto nit = bin.hype->db().names.find(va);
            if (nit != bin.hype->db().names.end()) name = nit->second;
        }
        if (name.empty()) {
            // If a legacy-index function starts here, fall back to sub_<rva>
            for (const auto& f : bin.fns.functions())
                if (f.va == va) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "sub_%llX",
                                  static_cast<unsigned long long>(va - bin.base));
                    name = buf;
                    break;
                }
        }
    }
    if (name.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, name.c_str());
    return 1;
}

int l_name_set(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    size_t nlen = 0;
    const char* name = luaL_checklstring(L, 2, &nlen);
    ds::set_symbol(va, std::string(name, nlen));   // persisted; UI sees it
    lua_pushboolean(L, true);
    return 1;
}

int l_comment_get(lua_State* L) {
    if (!need_image(L)) return 0;
    const auto text = ds::comment_for(to_addr(L, 1));
    if (text.empty()) { lua_pushnil(L); return 1; }
    lua_pushstring(L, text.c_str());
    return 1;
}

int l_comment_set(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);
    size_t tlen = 0;
    const char* text = luaL_checklstring(L, 2, &tlen);
    ds::set_comment(va, std::string(text, tlen));
    lua_pushboolean(L, true);
    return 1;
}

int l_bookmark_toggle(lua_State* L) {
    if (!need_image(L)) return 0;
    lua_pushboolean(L, ds::toggle_bookmark(to_addr(L, 1)));
    return 1;
}

int l_bookmarks(lua_State* L) {
    if (!need_image(L)) return 0;
    const auto marks = ds::bookmarks_snapshot();
    lua_createtable(L, static_cast<int>(std::min<size_t>(marks.size(), 10000)), 0);
    int i = 1;
    for (uint64_t va : marks) {
        if (i > 10000) break;
        lua_pushinteger(L, static_cast<lua_Integer>(va));
        lua_rawseti(L, -2, i++);
    }
    return 1;
}

// slop.disasm: raw image bytes

int l_image_bytes(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t addr = to_addr(L, 1);
    const uint64_t len = lua_gettop(L) >= 2 ? to_addr(L, 2) : 16;
    if (len == 0 || len > (1ull << 20))
        return lua_fail(L, "bad length (1..1048576)");
    std::string err;
    {
        ds::binary_lock_t lock;
        auto& bin = ds::get();
        auto off = bin.offset_of(addr);
        if (!off) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "address %llx is outside the loaded image",
                          static_cast<unsigned long long>(addr));
            err = buf;
        } else {
            const size_t avail =
                bin.file.size() > *off ? bin.file.size() - *off : 0;
            const size_t take = std::min<size_t>(avail, static_cast<size_t>(len));
            if (take == 0)
                err = "no bytes at address";
            else
                lua_pushlstring(L,
                                reinterpret_cast<const char*>(bin.file.data() + *off),
                                take);
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// slop.decomp: hyperion decompiler + rich analysis

int l_decomp_function(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        const hype::Function* f =
            hype ? hype->function_at(va) : nullptr;
        if (hype && !f) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "no hyperion function contains address %llx",
                          static_cast<unsigned long long>(va));
            err = buf;
        }
        if (err.empty()) {
            const uint64_t entry = f->entry;

            std::vector<hype::PseudoLine> lines;
            std::string derr;
            if (!hype->decompile(va, lines, derr)) {
                err = derr.empty() ? "decompile failed" : derr;
            } else {
                auto& bin = ds::get();
                const auto& db = hype->db();

                // display name precedence, user symbol then hyperion name then sub rva,
                // read directly since the helper re takes the mutex
                std::string fname;
                const auto sit = bin.symbols.find(entry);
                if (sit != bin.symbols.end()) fname = sit->second;
                if (fname.empty()) {
                    const auto nit = db.names.find(entry);
                    if (nit != db.names.end()) fname = nit->second;
                }
                const uint64_t img_base =
                    db.image_base ? db.image_base : bin.base;
                if (fname.empty()) {
                    char buf[32];
                    std::snprintf(buf, sizeof(buf), "sub_%llX",
                                  static_cast<unsigned long long>(entry - img_base));
                    fname = buf;
                }

                lua_createtable(L, 0, 5);
                lua_pushinteger(L, static_cast<lua_Integer>(entry));
                lua_setfield(L, -2, "va");
                lua_pushstring(L, fname.c_str());
                lua_setfield(L, -2, "name");

                // signature
                std::string signature;
                {
                    const auto it = db.signatures.find(entry);
                    if (it != db.signatures.end()) {
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
                lua_pushstring(L, signature.c_str());
                lua_setfield(L, -2, "signature");

                // lines: {addr, indent, text}
                lua_createtable(L, 0,
                                static_cast<int>(std::min<size_t>(lines.size(), 20000)));
                int i = 1;
                for (const auto& l : lines) {
                    if (i > 20000) break;
                    lua_createtable(L, 0, 3);
                    if (l.addr) {
                        lua_pushinteger(L, static_cast<lua_Integer>(l.addr));
                        lua_setfield(L, -2, "addr");
                    }
                    lua_pushinteger(L, l.indent);
                    lua_setfield(L, -2, "indent");
                    lua_pushstring(L, l.text.c_str());
                    lua_setfield(L, -2, "text");
                    lua_rawseti(L, -2, i++);
                }
                lua_setfield(L, -2, "lines");
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_blocks(lua_State* L) {
    if (!need_image(L)) return 0;
    const uint64_t va = to_addr(L, 1);

    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        const hype::Function* f = hype ? hype->function_at(va) : nullptr;
        if (hype && !f) {
            char buf[96];
            std::snprintf(buf, sizeof(buf),
                          "no hyperion function contains address %llx",
                          static_cast<unsigned long long>(va));
            err = buf;
        }
        if (err.empty()) {
            lua_createtable(L, 0, 4);
            lua_pushinteger(L, static_cast<lua_Integer>(f->entry));
            lua_setfield(L, -2, "entry");

            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(f->blocks.size(), 20000)));
            int i = 1;
            for (const auto& [start, bb] : f->blocks) {
                if (i > 20000) break;
                lua_createtable(L, 0, 6);
                lua_pushinteger(L, static_cast<lua_Integer>(start));
                lua_setfield(L, -2, "start");
                lua_pushinteger(L, static_cast<lua_Integer>(bb.end));
                lua_setfield(L, -2, "end_va");
                lua_pushinteger(L, static_cast<lua_Integer>(bb.insns.size()));
                lua_setfield(L, -2, "insns");
                lua_createtable(L, 0, 4);
                int j = 1;
                for (auto s : bb.succs) {
                    lua_pushinteger(L, static_cast<lua_Integer>(s));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "succs");
                lua_createtable(L, 0, 4);
                j = 1;
                for (auto p : bb.preds) {
                    lua_pushinteger(L, static_cast<lua_Integer>(p));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "preds");
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "blocks");

            lua_createtable(L, 0, 4);
            i = 1;
            for (const auto& lp : f->loops) {
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(lp.header));
                lua_setfield(L, -2, "header");
                lua_pushinteger(L, static_cast<lua_Integer>(lp.back_edge_src));
                lua_setfield(L, -2, "back_edge_src");
                lua_rawseti(L, -2, i++);
            }
            lua_setfield(L, -2, "loops");
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_vtables(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& vts = hype->db().vtables;
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(vts.size(), 10000)));
            int i = 1;
            for (const auto& vt : vts) {
                if (i > 10000) break;
                lua_createtable(L, 0, 2);
                lua_pushinteger(L, static_cast<lua_Integer>(vt.addr));
                lua_setfield(L, -2, "va");
                lua_createtable(L, 0,
                                static_cast<int>(std::min<size_t>(vt.entries.size(), 512)));
                int j = 1;
                for (auto e : vt.entries) {
                    if (j > 512) break;
                    lua_pushinteger(L, static_cast<lua_Integer>(e));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "entries");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_globals(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& globs = hype->db().globals;
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(globs.size(), 20000)));
            int i = 1;
            for (const auto& [va, g] : globs) {
                if (i > 20000) break;
                lua_createtable(L, 0, 3);
                lua_pushinteger(L, static_cast<lua_Integer>(va));
                lua_setfield(L, -2, "va");
                lua_pushinteger(L, static_cast<lua_Integer>(g.size));
                lua_setfield(L, -2, "size");
                lua_pushstring(L, g.name.c_str());
                lua_setfield(L, -2, "name");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

int l_decomp_rtti(lua_State* L) {
    if (!need_image(L)) return 0;
    std::string err;
    {
        ds::binary_lock_t lock;
        hs::session_t* hype = pinned_hype(err);
        if (err.empty()) {
            const auto& classes = hype->rtti().classes();
            lua_createtable(L, 0,
                            static_cast<int>(std::min<size_t>(classes.size(), 10000)));
            int i = 1;
            for (const auto& c : classes) {
                if (i > 10000) break;
                lua_createtable(L, 0, 5);
                lua_pushstring(L, c.demangled_name.empty() ? c.mangled_name.c_str()
                                                           : c.demangled_name.c_str());
                lua_setfield(L, -2, "name");
                lua_pushinteger(L, static_cast<lua_Integer>(c.type_descriptor));
                lua_setfield(L, -2, "type_descriptor");
                lua_pushinteger(L, static_cast<lua_Integer>(c.complete_locator));
                lua_setfield(L, -2, "locator");
                lua_pushinteger(L, static_cast<lua_Integer>(c.vtable));
                lua_setfield(L, -2, "vtable");
                lua_createtable(L, 0, 8);
                int j = 1;
                for (auto m : c.methods) {
                    if (j > 512) break;
                    lua_pushinteger(L, static_cast<lua_Integer>(m));
                    lua_rawseti(L, -2, j++);
                }
                lua_setfield(L, -2, "methods");
                lua_rawseti(L, -2, i++);
            }
        }
    }
    if (!err.empty()) return lua_fail(L, err.c_str());
    return 1;
}

// timeout hook

// Serialize a Lua return value into the captured output (lua-style summary;
// depth-capped so a huge table can't flood the output buffer)
void append_value(lua_State* L, int idx, int depth) {
    if (depth > 4) { out_append(L, "..."); return; }
    // normalize to an absolute index, pushes below would shift a negative
    // idx onto the wrong slots
    const int at = lua_absindex(L, idx);
    const int t = lua_type(L, at);
    switch (t) {
    case LUA_TNIL:
        out_append(L, "nil");
        break;
    case LUA_TBOOLEAN:
        out_append(L, lua_toboolean(L, at) ? "true" : "false");
        break;
    case LUA_TNUMBER:
        if (lua_isinteger(L, at))
            out_append(L, std::to_string(lua_tointeger(L, at)));
        else
            out_append(L, std::to_string(lua_tonumber(L, at)));
        break;
    case LUA_TSTRING: {
        size_t len = 0;
        const char* s = lua_tolstring(L, at, &len);
        out_append(L, "\"");
        out_append(L, std::string(s ? s : "", std::min<size_t>(len, 4096)));
        out_append(L, "\"");
        break;
    }
    case LUA_TTABLE: {
        // Render as {v1, v2, ...} over the array part first, then string
        // key/value pairs
        out_append(L, "{");
        bool first = true;
        lua_Integer n = 0;
        lua_len(L, at);
        n = lua_tointeger(L, -1);
        lua_pop(L, 1);
        int shown = 0;
        for (lua_Integer i = 1; i <= n && shown < 32; ++i, ++shown) {
            if (!first) out_append(L, ", ");
            first = false;
            lua_geti(L, at, i);
            append_value(L, -1, depth + 1);
            lua_pop(L, 1);
        }
        if (shown >= 32 && n > shown) out_append(L, ", ...");
        // String-keyed fields after the array part
        lua_pushnil(L);
        int pairs_shown = 0;
        while (lua_next(L, at) != 0) {
            if (lua_type(L, -2) == LUA_TSTRING && pairs_shown < 32) {
                if (!first) out_append(L, ", ");
                first = false;
                size_t klen = 0;
                const char* k = lua_tolstring(L, -2, &klen);
                out_append(L, std::string(k ? k : "", klen));
                out_append(L, "=");
                append_value(L, -1, depth + 1);
                ++pairs_shown;
            } else if (pairs_shown >= 32) {
                // stop scanning, enough
            }
            lua_pop(L, 1);
        }
        out_append(L, "}");
        break;
    }
    default:
        out_append(L, lua_typename(L, t));
        break;
    }
}

void timeout_hook(lua_State* L, lua_Debug*) {
    if (std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() >
        t_deadline_ms) {
        luaL_where(L, 1);
        lua_pushstring(L, "script execution timed out");
        lua_concat(L, 2);
        lua_error(L);
    }
}

} // namespace

lua_run_result_t lua_run(const std::string& code, int timeout_ms) {
    lua_run_result_t res;

    lua_State* L = luaL_newstate();
    if (!L) {
        res.error = "lua_newstate failed";
        return res;
    }

    std::string output;
    t_deadline_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count() +
        std::clamp<int64_t>(timeout_ms, 500, 60000);

    luaL_openlibs(L);

    lua_pushlightuserdata(L, &output);
    lua_setfield(L, LUA_REGISTRYINDEX, kOutputKey);
    lua_pushlightuserdata(L, &t_deadline_ms);
    lua_setfield(L, LUA_REGISTRYINDEX, kDeadlineKey);
    lua_sethook(L, timeout_hook, LUA_MASKCOUNT, 5'000'000);

    lua_pushcfunction(L, l_log);
    lua_setglobal(L, "print");

    lua_createtable(L, 0, 8);
    lua_pushcfunction(L, l_version); lua_setfield(L, -2, "version");
    lua_pushcfunction(L, l_log);     lua_setfield(L, -2, "log");

    lua_createtable(L, 0, 3);
    lua_pushcfunction(L, l_target_list);   lua_setfield(L, -2, "list");
    lua_pushcfunction(L, l_target_attach); lua_setfield(L, -2, "attach");
    lua_pushcfunction(L, l_target_status); lua_setfield(L, -2, "status");
    lua_setfield(L, -2, "target");

    lua_createtable(L, 0, 3);
    lua_pushcfunction(L, l_mem_read);  lua_setfield(L, -2, "read_hex");
    lua_pushcfunction(L, l_mem_write); lua_setfield(L, -2, "write_hex");
    lua_pushcfunction(L, l_mem_scan);  lua_setfield(L, -2, "scan");
    lua_setfield(L, -2, "mem");

    lua_createtable(L, 0, 14);
    // Live-target disassembly (attached process memory)
    lua_pushcfunction(L, l_disasm_disassemble);
    lua_setfield(L, -2, "disassemble");
    // Static analysis over the loaded image, the IDA-style surface
    lua_pushcfunction(L, l_disasm_decode);        lua_setfield(L, -2, "decode");
    lua_pushcfunction(L, l_disasm_functions);     lua_setfield(L, -2, "functions");
    lua_pushcfunction(L, l_disasm_function_at);   lua_setfield(L, -2, "function_at");
    lua_pushcfunction(L, l_disasm_xrefs_to);      lua_setfield(L, -2, "xrefs_to");
    lua_pushcfunction(L, l_disasm_strings);       lua_setfield(L, -2, "strings");
    lua_pushcfunction(L, l_disasm_pe);            lua_setfield(L, -2, "pe");
    lua_pushcfunction(L, l_image_bytes);          lua_setfield(L, -2, "bytes");
    // Names/comments/bookmarks, persisted per binary hash, shared with the
    // UI and the MCP tools
    lua_pushcfunction(L, l_name_get);             lua_setfield(L, -2, "name");
    lua_pushcfunction(L, l_name_set);             lua_setfield(L, -2, "set_name");
    lua_pushcfunction(L, l_comment_get);          lua_setfield(L, -2, "comment");
    lua_pushcfunction(L, l_comment_set);          lua_setfield(L, -2, "set_comment");
    lua_pushcfunction(L, l_bookmark_toggle);      lua_setfield(L, -2, "bookmark_toggle");
    lua_pushcfunction(L, l_bookmarks);            lua_setfield(L, -2, "bookmarks");
    lua_setfield(L, -2, "disasm");

    lua_createtable(L, 0, 1);
    lua_pushcfunction(L, l_analyze_packer);
    lua_setfield(L, -2, "packer");
    lua_setfield(L, -2, "analyze");

    // the image session surface, load, load from target, unload, status,
    // wait ready
    lua_createtable(L, 0, 5);
    lua_pushcfunction(L, l_image_load);           lua_setfield(L, -2, "load");
    lua_pushcfunction(L, l_image_load_from_target);
    lua_setfield(L, -2, "load_from_target");
    lua_pushcfunction(L, l_image_unload);         lua_setfield(L, -2, "unload");
    lua_pushcfunction(L, l_image_status);         lua_setfield(L, -2, "status");
    lua_pushcfunction(L, l_image_wait_ready);     lua_setfield(L, -2, "wait_ready");
    lua_setfield(L, -2, "image");

    // Decompiler + hyperion-rich analysis (requires analysis-ready session)

    // Decompiler + hyperion-rich analysis (requires analysis-ready session)
    lua_createtable(L, 0, 5);
    lua_pushcfunction(L, l_decomp_function);      lua_setfield(L, -2, "decompile");
    lua_pushcfunction(L, l_decomp_blocks);        lua_setfield(L, -2, "blocks");
    lua_pushcfunction(L, l_decomp_vtables);       lua_setfield(L, -2, "vtables");
    lua_pushcfunction(L, l_decomp_globals);       lua_setfield(L, -2, "globals");
    lua_pushcfunction(L, l_decomp_rtti);          lua_setfield(L, -2, "rtti");
    lua_setfield(L, -2, "decomp");

    lua_setglobal(L, "slop");

    if (luaL_loadbuffer(L, code.c_str(), code.size(), "=slop_script")
        != LUA_OK) {
        res.error = lua_tostring(L, -1) ? lua_tostring(L, -1) : "load failed";
        lua_close(L);
        res.output = output;
        return res;
    }
    // one result slot, the return value is serialized into the output so
    // return x is not lost
    if (lua_pcall(L, 0, 1, 0) != LUA_OK) {
        res.error = lua_tostring(L, -1) ? lua_tostring(L, -1) : "runtime error";
    } else {
        res.ok = true;
        out_append(L, "return: ");
        append_value(L, -1, 0);
        out_append(L, "\n");
    }

    res.output = output;
    lua_close(L);
    return res;
}

} // namespace slop::core::script
