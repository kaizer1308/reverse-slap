// src/core/re/type_catalog.cpp

#include "core/re/type_catalog.hpp"

#include <nlohmann/json.hpp>

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>

namespace slop::core::re::type_catalog {

namespace {

using json = nlohmann::json;

struct catalog_t {
    std::mutex mu;
    std::map<std::string, struct_def_t> structs;
    std::map<std::string, enum_def_t>   enums;
    uint64_t bound_hash = 0;             // binary hash this catalog mirrors
};

catalog_t g_cat;

std::string store_dir() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return {};
    const std::string dir = std::string(base, n) + "\\reverse-slop\\types";
    CreateDirectoryA((std::string(base, n) + "\\reverse-slop").c_str(), nullptr);
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

std::string store_path(uint64_t hash) {
    const std::string dir = store_dir();
    if (dir.empty()) return {};
    char name[32];
    std::snprintf(name, sizeof(name), "%016llX.json",
                  static_cast<unsigned long long>(hash));
    return dir + "\\" + name;
}

json to_json(const catalog_t& c) {
    json js = json::object();
    for (const auto& [name, s] : c.structs) {
        json fields = json::array();
        for (const auto& f : s.fields)
            fields.push_back({{"name", f.name}, {"type", f.type},
                              {"offset", f.offset}, {"size", f.size},
                              {"array_count", f.array_count}});
        js[name] = {{"size", s.size}, {"packed", s.packed}, {"fields", fields}};
    }
    json je = json::object();
    for (const auto& [name, e] : c.enums) {
        json vals = json::array();
        for (const auto& [vn, vv] : e.values)
            vals.push_back({{"name", vn}, {"value", vv}});
        je[name] = {{"underlying", e.underlying}, {"values", vals}};
    }
    json root = json::object();
    root["structs"] = js;
    root["enums"]   = je;
    return root;
}

void from_json(const json& root, catalog_t& c) {
    c.structs.clear();
    c.enums.clear();
    if (root.contains("structs")) {
        for (auto it = root["structs"].begin(); it != root["structs"].end(); ++it) {
            struct_def_t s;
            s.name   = it.key();
            s.size   = it.value().value("size", 0ull);
            s.packed = it.value().value("packed", false);
            if (it.value().contains("fields"))
                for (const auto& f : it.value()["fields"]) {
                    field_t fld;
                    fld.name = f.value("name", "");
                    fld.type = f.value("type", "");
                    fld.offset = f.value("offset", 0ull);
                    fld.size = f.value("size", 0ull);
                    fld.array_count = f.value("array_count", 0u);
                    s.fields.push_back(std::move(fld));
                }
            c.structs[s.name] = std::move(s);
        }
    }
    if (root.contains("enums")) {
        for (auto it = root["enums"].begin(); it != root["enums"].end(); ++it) {
            enum_def_t e;
            e.name = it.key();
            e.underlying = it.value().value("underlying", "u32");
            if (it.value().contains("values"))
                for (const auto& v : it.value()["values"])
                    e.values.emplace_back(v.value("name", ""),
                                          v.value("value", static_cast<int64_t>(0)));
            c.enums[e.name] = std::move(e);
        }
    }
}

bool save_locked(const catalog_t& c) {
    if (!c.bound_hash) return false;
    const std::string path = store_path(c.bound_hash);
    if (path.empty()) return false;
    std::ofstream f(path, std::ios::trunc);
    if (!f) return false;
    f << to_json(c).dump(2);
    return true;
}

// Bind to a binary's hash and load its persisted catalog (called from
// bind_binary on session open)
void load_locked(catalog_t& c) {
    if (!c.bound_hash) return;
    const std::string path = store_path(c.bound_hash);
    if (path.empty()) return;
    std::ifstream f(path);
    if (!f) return;
    try {
        json j;
        f >> j;
        from_json(j, c);
    } catch (...) {
        c.structs.clear();
        c.enums.clear();
    }
}

} // namespace

// the binding lives here since binary_state depends on this host layer

void bind_binary(const uint8_t* bytes, size_t len);

void bind_binary(const uint8_t* bytes, size_t len) {
    uint64_t h = 1469598103934665603ull;
    for (size_t i = 0; i < len; ++i) {
        h ^= bytes[i];
        h *= 1099511628211ull;
    }
    std::lock_guard lk(g_cat.mu);
    g_cat.structs.clear();
    g_cat.enums.clear();
    g_cat.bound_hash = h;
    load_locked(g_cat);
}

// mini parser

namespace {

bool ident_start(char c) {
    return isalpha(static_cast<unsigned char>(c)) || c == '_';
}
bool ident_char(char c) {
    return isalnum(static_cast<unsigned char>(c)) || c == '_';
}

struct tokenizer_t {
    explicit tokenizer_t(const std::string& src) : s(src) {}

    void skip_ws() {
        while (pos < s.size() && isspace(static_cast<unsigned char>(s[pos]))) ++pos;
    }

    std::string next() {
        skip_ws();
        if (pos >= s.size()) return {};
        const char c = s[pos];
        if (ident_start(c)) {
            const size_t start = pos;
            while (pos < s.size() && ident_char(s[pos])) ++pos;
            return s.substr(start, pos - start);
        }
        if (isdigit(static_cast<unsigned char>(c)) ||
            ((c == '-' || c == '+') && pos + 1 < s.size() &&
             isdigit(static_cast<unsigned char>(s[pos + 1])))) {
            const size_t start = pos;
            ++pos;
            while (pos < s.size() &&
                   (isxdigit(static_cast<unsigned char>(s[pos])) ||
                    s[pos] == 'x' || s[pos] == 'X'))
                ++pos;
            return s.substr(start, pos - start);
        }
        ++pos;
        return std::string(1, c);
    }

    std::string peek() {
        const size_t save = pos;
        const std::string t = next();
        pos = save;
        return t;
    }

    const std::string& s;
    size_t pos = 0;
};

} // namespace

uint64_t base_type_size(const std::string& type) {
    if (!type.empty() && type.back() == '*') return 8;
    if (type == "u8" || type == "i8" || type == "int8" || type == "uint8" ||
        type == "char" || type == "bool") return 1;
    if (type == "u16" || type == "i16" || type == "int16" || type == "uint16" ||
        type == "wchar_t") return 2;
    if (type == "u32" || type == "i32" || type == "int32" || type == "uint32" ||
        type == "float") return 4;
    if (type == "u64" || type == "i64" || type == "int64" || type == "uint64" ||
        type == "double" || type == "__int64") return 8;
    return 0;   // unknown -> named struct reference
}

void layout_struct(struct_def_t& def) {
    uint64_t off = 0, max_align = 1;
    for (auto& f : def.fields) {
        uint64_t sz = base_type_size(f.type);
        if (sz == 0) {
            // Named struct member (or pointer to one)
            std::string nm = f.type;
            bool ptr = !nm.empty() && nm.back() == '*';
            if (ptr) nm.pop_back();
            sz = 0;
            if (auto inner = get_struct(nm)) sz = inner->size;
            else if (auto en = get_enum(nm))
                sz = base_type_size(en->underlying);
            else sz = ptr ? 8 : 0;
            if (ptr) sz = 8;
        }
        if (f.array_count) sz *= f.array_count;
        if (sz == 0) { f.offset = off; continue; }

        const uint64_t align = def.packed ? 1 : std::min<uint64_t>(sz, 8);
        max_align = std::max(max_align, align);
        off = (off + align - 1) / align * align;
        f.offset = off;
        off += sz;
        f.size = sz;
    }
    def.size = def.packed ? off
                          : ((off + max_align - 1) / max_align) * max_align;
}

decl_parse_result_t parse_decls(const std::string& text) {
    decl_parse_result_t out;
    tokenizer_t tk(text);

    // Batch-local name resolution: members may reference types declared
    // earlier in the same declaration string (before the catalog knows them)
    std::map<std::string, uint64_t> batch_sizes;
    auto batch_lookup = [&batch_sizes](const std::string& n) -> uint64_t {
        const auto it = batch_sizes.find(n);
        return it != batch_sizes.end() ? it->second : 0;
    };
    auto layout_batch = [&](struct_def_t& def) {
        uint64_t off = 0, max_align = 1;
        for (auto& f : def.fields) {
            uint64_t sz = base_type_size(f.type);
            if (sz == 0) {
                std::string nm = f.type;
                const bool ptr = !nm.empty() && nm.back() == '*';
                if (ptr) nm.pop_back();
                sz = batch_lookup(nm);
                if (!sz && ptr) sz = 8;
            }
            if (f.array_count) sz *= f.array_count;
            if (sz == 0) { f.offset = off; continue; }
            const uint64_t align = def.packed ? 1 : std::min<uint64_t>(sz, 8);
            max_align = std::max(max_align, align);
            off = (off + align - 1) / align * align;
            f.offset = off;
            off += sz;
            f.size = sz;
        }
        def.size = def.packed ? off
                              : ((off + max_align - 1) / max_align) * max_align;
        batch_sizes[def.name] = def.size;
    };

    for (;;) {
        std::string kw = tk.next();
        if (kw.empty()) break;
        if (kw == ";") continue;   // stray terminators between definitions
        if (kw != "struct" && kw != "enum") {
            out.error = "expected 'struct' or 'enum', got '" + kw + "'";
            return out;
        }

        const std::string name = tk.next();
        if (name.empty() || name == "{") {
            out.error = "missing type name";
            return out;
        }

        if (kw == "enum") {
            enum_def_t e;
            e.name = name;
            if (tk.peek() == ":") { tk.next(); e.underlying = tk.next(); }
            if (tk.next() != "{") { out.error = "enum: expected '{'"; return out; }
            int64_t next_val = 0;
            for (;;) {
                std::string vn = tk.next();
                if (vn.empty()) { out.error = "enum: unexpected end"; return out; }
                if (vn == "}") break;
                if (vn == ",") continue;
                const std::string eq = tk.next();
                if (eq == "=") {
                    try {
                        next_val = static_cast<int64_t>(
                            std::stoull(tk.next(), nullptr, 0));
                    } catch (...) { out.error = "enum: bad value"; return out; }
                } else if (eq != "," && eq != "}") {
                    out.error = "enum: expected '=' after '" + vn + "'";
                    return out;
                }
                e.values.emplace_back(vn, next_val++);
                if (eq == "}") break;
            }
            out.enums.push_back(std::move(e));
        } else {
            struct_def_t s;
            s.name = name;
            if (tk.peek() == "packed") { tk.next(); s.packed = true; }
            if (tk.next() != "{") { out.error = "struct: expected '{'"; return out; }
            for (;;) {
                std::string ftype = tk.next();
                if (ftype == "}" || ftype.empty()) break;
                if (ftype == ";") continue;

                std::string tok = tk.peek();
                while (tok == "*") { tk.next(); ftype += "*"; tok = tk.peek(); }

                field_t f;
                f.type = ftype;
                f.name = tk.next();
                if (f.name.empty()) { out.error = "struct: missing member name"; return out; }

                std::string post = tk.next();
                if (post == "[") {
                    try {
                        f.array_count = static_cast<uint32_t>(
                            std::stoul(tk.next(), nullptr, 0));
                    } catch (...) { out.error = "struct: bad array count"; return out; }
                    if (tk.next() != "]") { out.error = "struct: expected ']'"; return out; }
                    post = tk.next();
                }
                if (post != ";" && post != "}") {
                    out.error = "struct: expected ';' after member";
                    return out;
                }
                s.fields.push_back(std::move(f));
                if (post == "}") break;
            }
            // trailing packed after the brace, the form the tool description documents
            if (tk.peek() == "packed") {
                tk.next();
                s.packed = true;
                if (tk.peek() == ";") tk.next();
            }
            layout_batch(s);
            out.structs.push_back(std::move(s));
        }
    }
    return out;
}

// queries

std::optional<struct_def_t> get_struct(const std::string& name) {
    std::lock_guard lk(g_cat.mu);
    const auto it = g_cat.structs.find(name);
    if (it == g_cat.structs.end()) return std::nullopt;
    return it->second;
}

std::optional<enum_def_t> get_enum(const std::string& name) {
    std::lock_guard lk(g_cat.mu);
    const auto it = g_cat.enums.find(name);
    if (it == g_cat.enums.end()) return std::nullopt;
    return it->second;
}

std::vector<struct_def_t> list_structs(const std::string& filter) {
    std::lock_guard lk(g_cat.mu);
    std::vector<struct_def_t> out;
    for (const auto& [name, s] : g_cat.structs)
        if (filter.empty() || name.find(filter) != std::string::npos)
            out.push_back(s);
    return out;
}

std::vector<enum_def_t> list_enums(const std::string& filter) {
    std::lock_guard lk(g_cat.mu);
    std::vector<enum_def_t> out;
    for (const auto& [name, e] : g_cat.enums)
        if (filter.empty() || name.find(filter) != std::string::npos)
            out.push_back(e);
    return out;
}

// mutations

bool create_struct(struct_def_t def, std::string* error) {
    if (def.name.empty()) { if (error) *error = "missing name"; return false; }
    layout_struct(def);
    std::lock_guard lk(g_cat.mu);
    g_cat.structs[def.name] = std::move(def);
    if (!save_locked(g_cat)) { if (error) *error = "persist failed"; return false; }
    return true;
}

bool add_member(const std::string& struct_name, const field_t& field,
                std::string* error) {
    std::lock_guard lk(g_cat.mu);
    const auto it = g_cat.structs.find(struct_name);
    if (it == g_cat.structs.end()) { if (error) *error = "unknown struct"; return false; }
    it->second.fields.push_back(field);
    layout_struct(it->second);
    if (!save_locked(g_cat)) { if (error) *error = "persist failed"; return false; }
    return true;
}

bool remove_struct(const std::string& name) {
    std::lock_guard lk(g_cat.mu);
    const size_t n = g_cat.structs.erase(name);
    if (n) save_locked(g_cat);
    return n != 0;
}

bool create_enum(enum_def_t def, std::string* error) {
    if (def.name.empty() || def.values.empty()) {
        if (error) *error = "missing name/values";
        return false;
    }
    std::lock_guard lk(g_cat.mu);
    g_cat.enums[def.name] = std::move(def);
    if (!save_locked(g_cat)) { if (error) *error = "persist failed"; return false; }
    return true;
}

bool remove_enum(const std::string& name) {
    std::lock_guard lk(g_cat.mu);
    const size_t n = g_cat.enums.erase(name);
    if (n) save_locked(g_cat);
    return n != 0;
}

// field reads

field_value_t read_field(const struct_def_t& strct, const std::string& field_name,
                         uint64_t base_va,
                         const uint8_t* file_bytes, size_t file_len,
                         read_cb_t reader, void* reader_user) {
    field_value_t out;
    const field_t* fld = nullptr;
    for (const auto& f : strct.fields)
        if (f.name == field_name) { fld = &f; break; }
    if (!fld) { out.error = "unknown field '" + field_name + "'"; return out; }

    // raw buffer view at base_va when provided, else the reader callback
    // fetches live memory
    const uint64_t rel_off = base_va + fld->offset;
    const size_t len = static_cast<size_t>(
        std::min<uint64_t>(fld->size ? fld->size : base_type_size(fld->type),
                           64));
    uint8_t buf[64]{};

    bool got = false;
    if (file_bytes && file_len && rel_off < file_len) {
        std::memcpy(buf, file_bytes + rel_off,
                    std::min<size_t>(len, file_len - rel_off));
        got = true;
    }
    if (!got && reader) got = reader(rel_off, buf, len, reader_user);
    if (!got) { out.error = "read failed at requested range"; return out; }

    out.ok = true;
    out.hex.resize(len * 2);
    static const char* d = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out.hex[i * 2]     = d[buf[i] >> 4];
        out.hex[i * 2 + 1] = d[buf[i] & 0xF];
    }

    if (len >= 8) {
        uint64_t v; std::memcpy(&v, buf, 8);
        out.uint_val = v; out.int_val = static_cast<int64_t>(v);
        if (fld->type == "double") std::memcpy(&out.dbl_val, buf, 8);
    } else if (len >= 4) {
        uint32_t v; std::memcpy(&v, buf, 4);
        out.uint_val = v; out.int_val = static_cast<int32_t>(v);
        if (fld->type == "float") { float f2; std::memcpy(&f2, buf, 4); out.dbl_val = f2; }
    } else if (len >= 2) {
        uint16_t v; std::memcpy(&v, buf, 2);
        out.uint_val = v; out.int_val = static_cast<int16_t>(v);
    } else if (len >= 1) {
        out.uint_val = buf[0]; out.int_val = static_cast<int8_t>(buf[0]);
    }
    return out;
}

} // namespace slop::core::re::type_catalog

