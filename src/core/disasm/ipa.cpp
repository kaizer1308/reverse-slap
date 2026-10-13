// src/core/disasm/ipa.cpp

#include "core/disasm/ipa.hpp"

#include "core/util/zip_reader.hpp"

#include <cstring>
#include <optional>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace slop::core::disasm::ipa {

namespace {

namespace zip = slop::core::util::zip;

// top-level dict string values only
using plist_map_t = std::unordered_map<std::string, std::string>;

constexpr uint64_t         kMaxInfoPlist = 16ull << 20;   // 16 MiB
constexpr std::string_view kPayload      = "Payload/";

void append_utf8(std::string& s, uint32_t cp) {
    if (cp < 0x80) {
        s += static_cast<char>(cp);
    } else if (cp < 0x800) {
        s += static_cast<char>(0xC0 | (cp >> 6));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        s += static_cast<char>(0xE0 | (cp >> 12));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        s += static_cast<char>(0xF0 | (cp >> 18));
        s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

// ---- binary plist (bplist00) ------------------------------------------------

uint64_t rd_be(const uint8_t* p, size_t n) noexcept {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | p[i];
    return v;
}

bool parse_bplist(const uint8_t* d, size_t len, plist_map_t& out) {
    constexpr size_t kHeader  = 8;
    constexpr size_t kTrailer = 32;
    if (len < kHeader + kTrailer || std::memcmp(d, "bplist00", kHeader) != 0) return false;

    const uint8_t* t        = d + len - kTrailer;
    const size_t   oint     = t[6];
    const size_t   ref      = t[7];
    const uint64_t num      = rd_be(t + 8, 8);
    const uint64_t top      = rd_be(t + 16, 8);
    const uint64_t table    = rd_be(t + 24, 8);
    const size_t   objs_end = len - kTrailer;
    if (oint < 1 || oint > 8 || ref < 1 || ref > 8) return false;
    if (num == 0 || top >= num) return false;
    if (table < kHeader || table > objs_end) return false;
    if (num > (objs_end - table) / oint) return false;

    auto obj_off = [&](uint64_t idx, size_t& off) {
        if (idx >= num) return false;
        const uint64_t o = rd_be(d + table + static_cast<size_t>(idx) * oint, oint);
        if (o < kHeader || o >= objs_end) return false;
        off = static_cast<size_t>(o);
        return true;
    };
    // marker nibbles + element count; `pos` lands on the payload
    auto obj_head = [&](size_t off, uint8_t& type, uint64_t& count, size_t& pos) {
        const uint8_t m = d[off];
        type  = static_cast<uint8_t>(m >> 4);
        count = m & 0x0F;
        pos   = off + 1;
        if (count == 0x0F) {
            if (pos >= objs_end) return false;
            const uint8_t im = d[pos++];
            if ((im >> 4) != 0x1 || (im & 0x0F) > 3) return false;
            const size_t n = size_t(1) << (im & 0x0F);
            if (n > objs_end - pos) return false;
            count = rd_be(d + pos, n);
            pos += n;
        }
        return true;
    };
    auto read_string = [&](uint64_t idx, std::string& s) {
        size_t   off = 0, pos = 0;
        uint8_t  type = 0;
        uint64_t count = 0;
        if (!obj_off(idx, off) || !obj_head(off, type, count, pos)) return false;
        const size_t avail = objs_end - pos;
        if (type == 0x5) {
            if (count > avail) return false;
            s.assign(reinterpret_cast<const char*>(d + pos), static_cast<size_t>(count));
            return true;
        }
        if (type == 0x6) {
            if (count > avail / 2) return false;
            s.clear();
            const uint8_t* p = d + pos;
            const size_t   n = static_cast<size_t>(count);
            for (size_t i = 0; i < n; ++i) {
                uint32_t u = (static_cast<uint32_t>(p[i * 2]) << 8) | p[i * 2 + 1];
                if (u >= 0xD800 && u <= 0xDBFF && i + 1 < n) {
                    const uint32_t lo = (static_cast<uint32_t>(p[i * 2 + 2]) << 8) | p[i * 2 + 3];
                    if (lo >= 0xDC00 && lo <= 0xDFFF) {
                        append_utf8(s, 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00));
                        ++i;
                        continue;
                    }
                }
                if (u >= 0xD800 && u <= 0xDFFF) u = 0xFFFD;   // unpaired surrogate
                append_utf8(s, u);
            }
            return true;
        }
        return false;
    };

    size_t   off = 0, pos = 0;
    uint8_t  type = 0;
    uint64_t count = 0;
    if (!obj_off(top, off) || !obj_head(off, type, count, pos) || type != 0xD) return false;
    if (count > (objs_end - pos) / ref / 2) return false;
    const size_t n = static_cast<size_t>(count);
    for (size_t i = 0; i < n; ++i) {
        const uint64_t kref = rd_be(d + pos + i * ref, ref);
        const uint64_t vref = rd_be(d + pos + (n + i) * ref, ref);
        if (kref >= num || vref >= num) return false;
        std::string key, value;
        if (!read_string(kref, key)) continue;     // non-string key
        if (!read_string(vref, value)) continue;   // non-string value
        out[std::move(key)] = std::move(value);
    }
    return true;
}

// ---- xml plist --------------------------------------------------------------

enum class tag_kind_t : uint8_t { open, close, empty };

struct tag_t {
    tag_kind_t       kind = tag_kind_t::open;
    std::string_view name;
};

bool is_space(char c) noexcept {
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

// position just past `term` searched from `from`
bool skip_past(std::string_view s, size_t from, std::string_view term, size_t& pos) {
    const size_t e = s.find(term, from);
    if (e == std::string_view::npos) return false;
    pos = e + term.size();
    return true;
}

// next element tag at or after `pos`, skipping text, comments, processing
// instructions, doctype and cdata
bool next_tag(std::string_view s, size_t& pos, tag_t& tag) {
    for (;;) {
        const size_t lt = s.find('<', pos);
        if (lt == std::string_view::npos) return false;
        const std::string_view rest = s.substr(lt);
        if (rest.starts_with("<!--")) {
            if (!skip_past(s, lt + 4, "-->", pos)) return false;
            continue;
        }
        if (rest.starts_with("<![CDATA[")) {
            if (!skip_past(s, lt + 9, "]]>", pos)) return false;
            continue;
        }
        if (rest.starts_with("<?")) {
            if (!skip_past(s, lt + 2, "?>", pos)) return false;
            continue;
        }
        if (rest.starts_with("<!")) {
            if (!skip_past(s, lt + 2, ">", pos)) return false;
            continue;
        }

        size_t p       = lt + 1;
        bool   closing = false;
        if (p < s.size() && s[p] == '/') { closing = true; ++p; }
        const size_t name_start = p;
        while (p < s.size() && !is_space(s[p]) && s[p] != '/' && s[p] != '>') ++p;
        if (p == name_start) return false;
        tag.name = s.substr(name_start, p - name_start);

        char quote = 0;
        for (; p < s.size(); ++p) {
            const char c = s[p];
            if (quote) {
                if (c == quote) quote = 0;
            } else if (c == '"' || c == '\'') {
                quote = c;
            } else if (c == '>') {
                break;
            }
        }
        if (p >= s.size()) return false;
        tag.kind = closing ? tag_kind_t::close
                 : s[p - 1] == '/' ? tag_kind_t::empty
                 : tag_kind_t::open;
        pos = p + 1;
        return true;
    }
}

void decode_entities(std::string_view t, std::string& out) {
    for (size_t i = 0; i < t.size();) {
        if (t[i] != '&') { out += t[i++]; continue; }
        const size_t semi = t.find(';', i);
        if (semi == std::string_view::npos || semi - i > 12) { out += t[i++]; continue; }
        const std::string_view ent = t.substr(i + 1, semi - i - 1);
        if      (ent == "amp")  out += '&';
        else if (ent == "lt")   out += '<';
        else if (ent == "gt")   out += '>';
        else if (ent == "quot") out += '"';
        else if (ent == "apos") out += '\'';
        else if (ent.size() >= 2 && ent[0] == '#') {
            const bool hex   = ent[1] == 'x' || ent[1] == 'X';
            size_t     k     = hex ? 2 : 1;
            uint32_t   cp    = 0;
            bool       valid = k < ent.size();
            for (; valid && k < ent.size(); ++k) {
                const char c = ent[k];
                uint32_t   digit = 0;
                if (c >= '0' && c <= '9')             digit = static_cast<uint32_t>(c - '0');
                else if (hex && c >= 'a' && c <= 'f') digit = static_cast<uint32_t>(c - 'a' + 10);
                else if (hex && c >= 'A' && c <= 'F') digit = static_cast<uint32_t>(c - 'A' + 10);
                else { valid = false; break; }
                cp = cp * (hex ? 16 : 10) + digit;
                if (cp > 0x10FFFF) valid = false;
            }
            if (!valid || cp == 0 || (cp >= 0xD800 && cp <= 0xDFFF)) { out += t[i++]; continue; }
            append_utf8(out, cp);
        } else {
            out += t[i++];
            continue;
        }
        i = semi + 1;
    }
}

// character content up to the matching `</name>` (pos is just past the open tag)
bool read_text(std::string_view s, size_t& pos, std::string_view name, std::string& out) {
    out.clear();
    for (;;) {
        const size_t lt = s.find('<', pos);
        if (lt == std::string_view::npos) return false;
        decode_entities(s.substr(pos, lt - pos), out);
        const std::string_view rest = s.substr(lt);
        if (rest.starts_with("<![CDATA[")) {
            const size_t e = s.find("]]>", lt + 9);
            if (e == std::string_view::npos) return false;
            out.append(s.substr(lt + 9, e - lt - 9));
            pos = e + 3;
            continue;
        }
        if (rest.starts_with("<!--")) {
            if (!skip_past(s, lt + 4, "-->", pos)) return false;
            continue;
        }
        pos = lt;
        tag_t t;
        if (!next_tag(s, pos, t)) return false;
        return t.kind == tag_kind_t::close && t.name == name;
    }
}

// skip the rest of an element whose open tag was just consumed
bool skip_element(std::string_view s, size_t& pos) {
    size_t depth = 1;
    tag_t  t;
    while (depth) {
        if (!next_tag(s, pos, t)) return false;
        if (t.kind == tag_kind_t::open)       ++depth;
        else if (t.kind == tag_kind_t::close) --depth;
    }
    return true;
}

bool parse_xml_plist(std::string_view s, plist_map_t& out) {
    size_t pos = 0;
    tag_t  t;
    // root: optional <plist>, then the top-level <dict>
    for (;;) {
        if (!next_tag(s, pos, t)) return false;
        if (t.kind == tag_kind_t::open && t.name == "plist") continue;
        if (t.name == "dict" && t.kind == tag_kind_t::empty) return true;
        if (t.name == "dict" && t.kind == tag_kind_t::open) break;
        return false;
    }

    // inside the top dict: only depth-1 <key> elements count
    bool pending = false;   // `t` already holds the next tag
    for (;;) {
        if (!pending && !next_tag(s, pos, t)) return false;
        pending = false;
        if (t.kind == tag_kind_t::close) return t.name == "dict";
        if (t.kind == tag_kind_t::empty) continue;
        if (t.name != "key") {
            if (!skip_element(s, pos)) return false;
            continue;
        }

        std::string key;
        if (!read_text(s, pos, "key", key)) return false;
        if (!next_tag(s, pos, t)) return false;
        if (t.kind == tag_kind_t::close) return t.name == "dict";   // key without value
        if (t.kind == tag_kind_t::open && t.name == "key") { pending = true; continue; }
        if (t.name == "string") {
            std::string value;
            if (t.kind == tag_kind_t::open && !read_text(s, pos, "string", value)) return false;
            out[std::move(key)] = std::move(value);
            continue;
        }
        if (t.kind == tag_kind_t::open && !skip_element(s, pos)) return false;
    }
}

bool parse_plist(const std::vector<uint8_t>& bytes, plist_map_t& out) {
    if (bytes.size() >= 8 && std::memcmp(bytes.data(), "bplist00", 8) == 0)
        return parse_bplist(bytes.data(), bytes.size(), out);
    return parse_xml_plist(std::string_view(reinterpret_cast<const char*>(bytes.data()),
                                            bytes.size()), out);
}

// ---- bundle layout ----------------------------------------------------------

// "Payload/<X>.app/" when `name` lives under a top-level app bundle
std::optional<std::string_view> top_app_dir(std::string_view name) {
    if (!name.starts_with(kPayload)) return std::nullopt;
    const std::string_view rest  = name.substr(kPayload.size());
    const size_t           slash = rest.find('/');
    if (slash == std::string_view::npos) return std::nullopt;
    const std::string_view comp = rest.substr(0, slash);
    if (comp.size() <= 4 || !comp.ends_with(".app")) return std::nullopt;
    return name.substr(0, kPayload.size() + slash + 1);
}

std::optional<std::string> find_app_dir(const zip::archive_t& ar) {
    std::optional<std::string_view> best;
    for (const auto& e : ar.entries()) {
        const auto dir = top_app_dir(e.name);
        if (dir && (!best || *dir < *best)) best = dir;
    }
    if (!best) return std::nullopt;
    return std::string(*best);
}

std::string plist_value(const plist_map_t& m, const char* key) {
    const auto it = m.find(key);
    return it == m.end() ? std::string() : it->second;
}

} // namespace

bool looks_like_ipa(const uint8_t* data, size_t len) {
    if (!zip::has_zip_magic(data, len)) return false;
    zip::archive_t ar;
    if (!ar.open(data, len)) return false;
    for (const auto& e : ar.entries())
        if (top_app_dir(e.name)) return true;
    return false;
}

extract_result_t extract_main_binary(const uint8_t* data, size_t len) {
    extract_result_t r;
    if (!zip::has_zip_magic(data, len)) {
        r.error = "ipa: not a zip archive";
        return r;
    }
    zip::archive_t ar;
    std::string    err;
    if (!ar.open(data, len, &err)) {
        r.error = "ipa: " + err;
        return r;
    }
    const auto app_dir = find_app_dir(ar);
    if (!app_dir) {
        r.error = "ipa: no Payload/<name>.app/ bundle found";
        return r;
    }

    bundle_t& b = r.bundle;
    b.app_dir   = *app_dir;
    const std::string stem =
        b.app_dir.substr(kPayload.size(), b.app_dir.size() - kPayload.size() - 5);   // drop ".app/"

    plist_map_t info;
    if (const zip::entry_t* pe = ar.find(b.app_dir + "Info.plist")) {
        std::vector<uint8_t> bytes;
        if (!ar.extract(*pe, bytes, nullptr, kMaxInfoPlist) || !parse_plist(bytes, info))
            info.clear();
    }
    b.executable = plist_value(info, "CFBundleExecutable");
    if (b.executable.empty()) b.executable = stem;
    b.bundle_id = plist_value(info, "CFBundleIdentifier");
    b.version   = plist_value(info, "CFBundleShortVersionString");
    b.build     = plist_value(info, "CFBundleVersion");
    b.min_os    = plist_value(info, "MinimumOSVersion");
    b.executable_path = b.app_dir + b.executable;

    const zip::entry_t* exe = ar.find(b.executable_path);
    if (!exe || exe->is_directory()) {
        r.error = "ipa: main executable '" + b.executable_path + "' not found";
        return r;
    }
    if (!ar.extract(*exe, r.binary, &err)) {
        r.error = "ipa: cannot extract '" + b.executable_path + "': " + err;
        r.binary.clear();
        return r;
    }
    r.ok = true;
    return r;
}

} // namespace slop::core::disasm::ipa
