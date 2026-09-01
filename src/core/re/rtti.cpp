// src/core/re/rtti.cpp
// msvc x64 rtti layouts kept here as a reference while parsing

#include "core/re/rtti.hpp"

#include <algorithm>
#include <cstring>

namespace slop::core::re {

namespace {

struct section_span_t {
    uint64_t va = 0;
    size_t   file_off = 0;
    size_t   raw_size = 0;
    bool     writable = false;
};

std::vector<section_span_t> data_spans(const disasm::pe_image_t& pe,
                                       const std::vector<uint8_t>& file) {
    std::vector<section_span_t> out;
    for (const auto& s : pe.sections) {
        if (s.raw_size == 0 || s.virtual_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > file.size())
            continue;
        // Skip obviously code-only sections for speed; RTTI lives in data
        if (!s.is_executable() || true) {
            out.push_back({pe.image_base + s.rva,
                           s.raw_offset, std::min<uint32_t>(s.raw_size, s.virtual_size),
                           (s.characteristics & 0x80000000) != 0});
        }
    }
    return out;
}

std::string demangle_msvc_name(const std::string& raw) {
    // ".?AVMyClass@@" -> "MyClass"; ".?AVns@Inner@@" -> "ns::Inner"
    const std::string prefix = ".?AV";
    if (raw.rfind(prefix, 0) != 0) return raw;
    std::string body = raw.substr(prefix.size());
    while (!body.empty() && (body.back() == '@')) body.pop_back();
    for (char& ch : body)
        if (ch == '@') ch = ':';
    return body;
}

} // namespace

rtti_result_t rtti_scan(const disasm::pe_image_t& pe,
                        const std::vector<uint8_t>& file) {
    rtti_result_t res;
    if (!pe.ok || pe.image_base == 0) return res;

    const auto spans = data_spans(pe, file);
    for (const auto& sp : spans)
        res.scanned_bytes += sp.raw_size;

    // pass 1: type descriptors
    struct td_hit_t { uint64_t va; uint32_t rva; std::string name; };
    std::map<uint32_t, td_hit_t> tds_by_rva;   // image-relative offset

    for (const auto& sp : spans) {
        if (sp.raw_size < 20) continue;
        const uint8_t* base = file.data() + sp.file_off;
        for (size_t i = 16; i + 4 <= sp.raw_size; ++i) {
            if (!(base[i] == '.' && base[i+1] == '?' &&
                  (base[i+2] == 'A' || base[i+2] == 'W')))
                continue;
            // Name must be NUL-terminated within the span
            size_t end = i;
            while (end < sp.raw_size && base[end] != 0) ++end;
            if (end >= sp.raw_size || end == i) continue;
            const std::string name(reinterpret_cast<const char*>(base + i),
                                   end - i);

            td_hit_t hit;
            hit.va   = sp.va + (i - 16);       // name starts after vfptr+spare
            hit.rva  = static_cast<uint32_t>(hit.va - pe.image_base);
            hit.name = demangle_msvc_name(name);
            tds_by_rva[hit.rva] = hit;
            i = end;                            // skip past this name
        }
    }

    // pass 2: complete object locators
    struct col_hit_t {
        uint64_t va;
        uint32_t td_rva;
    };
    std::map<uint32_t, col_hit_t> cols_by_rva;

    for (const auto& sp : spans) {
        if (sp.raw_size < 24) continue;
        const uint8_t* base = file.data() + sp.file_off;
        for (size_t i = 0; i + 24 <= sp.raw_size; i += 4) {
            const auto rd32 = [base](size_t o) {
                uint32_t v;
                std::memcpy(&v, base + o, 4);
                return v;
            };
            if (rd32(i) != 0) continue;                       // signature x64
            const uint32_t td_rva = rd32(i + 12);
            const uint32_t self_rva = rd32(i + 20);
            const uint32_t self_calc =
                static_cast<uint32_t>(sp.va + i - pe.image_base);
            if (self_rva != self_calc) continue;              // self must match
            if (!tds_by_rva.count(td_rva)) continue;          // must hit a TD

            col_hit_t hit;
            hit.va     = sp.va + i;
            hit.td_rva = td_rva;
            cols_by_rva[self_calc] = hit;
        }
    }

    // pass 3: vftables whose [-1] slot points at a COL
    for (const auto& sp : spans) {
        if (sp.raw_size < 8) continue;
        const uint8_t* base = file.data() + sp.file_off;
        for (size_t i = 0; i + 8 <= sp.raw_size; i += 8) {
            uint64_t ptr;
            std::memcpy(&ptr, base + i, 8);
            if (ptr < pe.image_base || ptr < pe.image_base + 0x1000) continue;
            const uint64_t target_rva = ptr - pe.image_base;
            const auto it = cols_by_rva.find(
                static_cast<uint32_t>(target_rva));
            if (it == cols_by_rva.end()) continue;

            const uint64_t vftable_va = sp.va + i + 8;   // [-1] slot
            const auto& td = tds_by_rva[it->second.td_rva];
            auto& cls = [&]() -> rtti_class_t& {
                for (auto& c : res.classes)
                    if (c.td_va == td.va) return c;
                rtti_class_t nc;
                nc.name = td.name;
                nc.td_va = td.va;
                res.classes.push_back(nc);
                return res.classes.back();
            }();
            cls.col_vas.push_back(it->second.va);
            cls.vftables.push_back(vftable_va);
        }
    }

    std::sort(res.classes.begin(), res.classes.end(),
              [](const rtti_class_t& a, const rtti_class_t& b) {
                  return a.name < b.name;
              });
    return res;
}

std::optional<std::vector<uint64_t>> read_vftable(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    uint64_t vftable_va, size_t max_slots) {
    auto off = pe.va_to_offset(vftable_va);
    if (!off || *off + max_slots * 8 > file.size()) return std::nullopt;
    std::vector<uint64_t> out;
    out.reserve(max_slots);
    for (size_t i = 0; i < max_slots; ++i) {
        uint64_t ptr;
        std::memcpy(&ptr, file.data() + *off + i * 8, 8);
        if (ptr == 0) break;
        // Stop at the first entry that leaves the image, end of table
        if (ptr < pe.image_base ||
            ptr >= pe.image_base + pe.size_of_image)
            break;
        out.push_back(ptr);
    }
    return out;
}

} // namespace slop::core::re
