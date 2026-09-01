// src/core/analysis/libsig.cpp

#include "core/analysis/libsig.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace slop::core::analysis {

namespace {

struct compiled_sig_t {
    std::string name;
    std::vector<uint8_t> bytes;
    std::vector<uint8_t> mask;    // 1 = must match
    uint32_t anchor_offset = 0;
};

compiled_sig_t compile(const libsig_t& sig, bool* ok) {
    compiled_sig_t out;
    out.name = sig.name;
    out.anchor_offset = sig.offset;
    *ok = false;

    const std::string& s = sig.pattern;
    auto is_hex = [](char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
               (c >= 'A' && c <= 'F');
    };
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] == ' ') { ++i; continue; }
        if (s[i] == '?') {
            if (i + 1 >= s.size() || s[i+1] != '?') return out;
            out.bytes.push_back(0);
            out.mask.push_back(0);
            i += 2;
            continue;
        }
        if (!is_hex(s[i]) || i + 1 >= s.size() || !is_hex(s[i+1])) return out;
        out.bytes.push_back(static_cast<uint8_t>(
            std::stoul(s.substr(i, 2), nullptr, 16)));
        out.mask.push_back(1);
        i += 2;
    }
    *ok = !out.bytes.empty();
    return out;
}

const disasm::function_t* enclosing_function(
    const disasm::function_index_t& fidx, uint64_t va) {
    const auto& fns = fidx.functions();
    // Function list is sorted by VA; binary search for the last start <= va
    auto it = std::upper_bound(
        fns.begin(), fns.end(), va,
        [](uint64_t v, const disasm::function_t& f) { return v < f.va; });
    if (it == fns.begin()) return nullptr;
    --it;
    if (va >= it->va && va < it->va + it->size) return &*it;
    return nullptr;
}

} // namespace

std::vector<libsig_hit_t> libsig_scan(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    const disasm::function_index_t& fidx,
    const std::vector<libsig_t>& sigs) {
    std::vector<libsig_hit_t> hits;
    if (!pe.ok) return hits;

    std::vector<compiled_sig_t> compiled;
    for (const auto& s : sigs) {
        bool ok = false;
        compiled_sig_t c = compile(s, &ok);
        if (ok) compiled.push_back(std::move(c));
    }
    if (compiled.empty()) return hits;

    for (const auto& sec : pe.sections) {
        if (!sec.is_executable() || sec.raw_size == 0) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > file.size())
            continue;

        const uint8_t* base = file.data() + sec.raw_offset;
        const size_t span = std::min<uint32_t>(sec.raw_size, sec.virtual_size);

        for (const auto& cs : compiled) {
            if (span < cs.bytes.size()) continue;
            for (size_t i = 0; i + cs.bytes.size() <= span; ++i) {
                bool m = true;
                for (size_t b = 0; b < cs.bytes.size(); ++b) {
                    if ((base[i + b] & 0xFF & cs.mask[b]) !=
                        (cs.bytes[b] & cs.mask[b])) {
                        m = false;
                        break;
                    }
                }
                if (!m) continue;

                libsig_hit_t hit;
                hit.sig_name = cs.name;
                const size_t rel =
                    i >= cs.anchor_offset ? i - cs.anchor_offset : 0;
                hit.va = pe.image_base + sec.rva + static_cast<uint32_t>(rel);
                if (auto* fn = enclosing_function(fidx, hit.va))
                    hit.function_va = fn->va;
                hits.push_back(std::move(hit));
                break;   // one hit per signature per section
            }
        }
    }
    return hits;
}

std::optional<std::vector<libsig_t>> parse_sig_set(const std::string& json_text,
                                                   std::string* error) {
    using json = nlohmann::json;
    json j = json::parse(json_text, nullptr, false);
    if (j.is_discarded() || !j.is_array()) {
        if (error) *error = "signature set must be a JSON array";
        return std::nullopt;
    }
    std::vector<libsig_t> out;
    for (const auto& e : j) {
        if (!e.contains("name") || !e.contains("pattern") ||
            !e.at("name").is_string() || !e.at("pattern").is_string()) {
            if (error) *error = "entries need string name + pattern";
            return std::nullopt;
        }
        libsig_t s;
        s.name    = e.at("name").get<std::string>();
        s.pattern = e.at("pattern").get<std::string>();
        if (e.contains("offset")) {
            const auto& o = e.at("offset");
            s.offset = o.is_number_unsigned()
                           ? static_cast<uint32_t>(o.get<uint64_t>())
                           : static_cast<uint32_t>(
                                 std::strtoul(o.get<std::string>().c_str(),
                                              nullptr, 0));
        }
        out.push_back(std::move(s));
    }
    return out;
}

} // namespace slop::core::analysis
