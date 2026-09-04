// src/core/disasm/pe_parser.cpp

#include "core/disasm/pe_parser.hpp"

#include <cstring>

namespace slop::core::disasm {

namespace {

template <typename T>
bool read_at(const uint8_t* d, size_t len, size_t off, T& out) {
    if (off + sizeof(T) > len) return false;
    std::memcpy(&out, d + off, sizeof(T));
    return true;
}

uint16_t rd16(const uint8_t* p) { uint16_t v; std::memcpy(&v, p, 2); return v; }
uint32_t rd32(const uint8_t* p) { uint32_t v; std::memcpy(&v, p, 4); return v; }
uint64_t rd64(const uint8_t* p) { uint64_t v; std::memcpy(&v, p, 8); return v; }

std::string read_cstring_at(const uint8_t* d, size_t len, size_t off) {
    std::string s;
    if (off >= len) return s;
    const size_t cap = std::min<size_t>(len - off, 4096);
    s.reserve(64);
    for (size_t i = 0; i < cap; ++i) {
        const char c = static_cast<char>(d[off + i]);
        if (c == '\0') break;
        s.push_back(c);
    }
    return s;
}

} // namespace

std::optional<size_t> pe_image_t::rva_to_offset(uint32_t rva) const {
    for (const auto& s : sections) {
        if (!s.contains_rva(rva)) continue;
        if (rva - s.rva >= s.raw_size) break; // BSS-like tail: no file backing
        return static_cast<size_t>(s.raw_offset) + (rva - s.rva);
    }
    // Headers region
    if (rva < 0x400) return static_cast<size_t>(rva);
    return std::nullopt;
}

std::optional<size_t> pe_image_t::va_to_offset(uint64_t va) const {
    if (image_base == 0) return std::nullopt;
    if (va < image_base || va - image_base > 0xFFFFFFFFull) return std::nullopt;
    return rva_to_offset(static_cast<uint32_t>(va - image_base));
}

std::optional<uintptr_t> pe_image_t::offset_to_va(size_t off) const {
    for (const auto& s : sections) {
        if (off < s.raw_offset || off >= s.raw_offset + s.raw_size) continue;
        return image_base + s.rva + static_cast<uint32_t>(off - s.raw_offset);
    }
    return std::nullopt;
}

const pe_section_t* pe_image_t::section_for_rva(uint32_t rva) const {
    for (const auto& s : sections)
        if (s.contains_rva(rva)) return &s;
    return nullptr;
}

pe_image_t pe_parse(const uint8_t* d, size_t len) {
    pe_image_t img;

    // DOS header
    if (len < 0x40 || d[0] != 'M' || d[1] != 'Z') return img;
    uint32_t e_lfanew = 0;
    if (!read_at(d, len, 0x3C, e_lfanew)) return img;
    if (e_lfanew == 0 || e_lfanew + 0x18 > len) return img;

    // PE signature + COFF
    if (std::memcmp(d + e_lfanew, "PE\0\0", 4) != 0) return img;
    const size_t coff = e_lfanew + 4;
    if (coff + 20 > len) return img;
    img.machine = rd16(d + coff);

    const uint16_t num_sections   = rd16(d + coff + 2);
    const uint16_t opt_header_off = static_cast<uint16_t>(e_lfanew + 24);
    const uint16_t opt_size       = rd16(d + coff + 16);
    if (opt_size == 0 || opt_header_off + opt_size > len) return img;

    // Optional header
    const uint16_t magic = rd16(d + opt_header_off);
    if (magic != 0x10B && magic != 0x20B) return img;
    img.pe32plus = (magic == 0x20B);

    if (img.pe32plus) {
        if (opt_size < 112) return img;
        img.image_base = rd64(d + opt_header_off + 24);
        img.entry_rva  = rd32(d + opt_header_off + 16);
    } else {
        if (opt_size < 96) return img;
        img.image_base = rd32(d + opt_header_off + 28);
        img.entry_rva  = rd32(d + opt_header_off + 16);
    }
    img.subsystem     = rd16(d + opt_header_off + (img.pe32plus ? 68 : 68));
    img.size_of_image = rd32(d + opt_header_off + 56);

    // Data directories: PE32+ at offset 112, PE32 at 96
    const uint16_t dd_off = opt_header_off + (img.pe32plus ? 112 : 96);
    if (opt_size >= (img.pe32plus ? 120 : 104)) {
        for (int i = 0; i < 16; ++i) {
            const size_t o = dd_off + static_cast<size_t>(i) * 8;
            if (o + 8 > len) break;
            img.data_dirs[i].rva  = rd32(d + o);
            img.data_dirs[i].size = rd32(d + o + 4);
        }
    }

    // Sections
    const size_t sec_table = opt_header_off + opt_size;
    const size_t sec_entry = img.pe32plus ? 40 : 40;
    if (sec_table + static_cast<size_t>(num_sections) * sec_entry > len) return img;

    for (uint16_t i = 0; i < num_sections; ++i) {
        const size_t o = sec_table + static_cast<size_t>(i) * sec_entry;
        pe_section_t s;
        std::memcpy(s.name, d + o, 8);
        s.virtual_size    = rd32(d + o + 8);
        s.rva             = rd32(d + o + 12);
        s.raw_size        = rd32(d + o + 16);
        s.raw_offset      = rd32(d + o + 20);
        s.characteristics = rd32(d + o + 36);
        img.sections.push_back(s);
    }

    img.ok = true;

    // Imports (directory index 1)
    {
        const uint32_t imp_rva  = img.data_dirs[1].rva;
        const uint32_t imp_size = img.data_dirs[1].size;
        if (imp_rva && imp_size) {
            auto off_opt = img.rva_to_offset(imp_rva);
            if (off_opt) {
                size_t desc = *off_opt;
                while (desc + 20 <= len) {
                    const uint32_t oft_rva = rd32(d + desc);
                    const uint32_t name_rva = rd32(d + desc + 12);
                    if (oft_rva == 0 && name_rva == 0) break;

                    pe_import_dll_t dll;
                    dll.dll = read_cstring_at(d, len,
                        img.rva_to_offset(name_rva).value_or(0));

                    const uint32_t thunk_rva = oft_rva ? oft_rva : rd32(d + desc + 16);
                    const uint32_t iat_rva  = rd32(d + desc + 16);   // FirstThunk
                    auto thunk_off = img.rva_to_offset(thunk_rva);
                    auto iat_off   = img.rva_to_offset(iat_rva);
                    if (thunk_off && !dll.dll.empty()) {
                        size_t t = *thunk_off;
                        size_t it = iat_off.value_or(0);
                        const size_t thunk_size = img.pe32plus ? 8 : 4;
                        constexpr int kMaxFuncs = 4096;
                        for (int f = 0; f < kMaxFuncs && t + thunk_size <= len;
                             ++f, t += thunk_size, it += thunk_size) {
                            const uint64_t thunk = img.pe32plus ? rd64(d + t) : rd32(d + t);
                            if (thunk == 0) break;
                            pe_import_func_t fn;
                            const uint64_t ordinal_flag = img.pe32plus
                                ? (1ull << 63) : (1ull << 31);
                            if (thunk & ordinal_flag) { // import by ordinal
                                fn.by_ordinal = true;
                                fn.ordinal    = static_cast<uint16_t>(thunk & 0xFFFF);
                            } else {
                                auto noff = img.rva_to_offset(static_cast<uint32_t>(thunk));
                                if (!noff) break;
                                fn.name = read_cstring_at(d, len, *noff + 2); // skip hint
                                if (fn.name.empty()) { if (!iat_off) continue; else break; }
                            }
                            // the iat slot is first thunk plus index times thunk size, consumers want
                            // the slot address not its content
                            fn.iat_rva = iat_rva + static_cast<uint32_t>(f) *
                                static_cast<uint32_t>(thunk_size);
                            dll.functions.push_back(std::move(fn));
                        }
                    }
                    img.imports.push_back(std::move(dll));

                    if (img.imports.size() >= 256) break; // sanity
                    desc += 20;
                }
            }
        }
    }

    // Exports (directory index 0)
    {
        const uint32_t exp_rva = img.data_dirs[0].rva;
        if (exp_rva) {
            auto dir_off = img.rva_to_offset(exp_rva);
            if (dir_off && *dir_off + 40 <= len) {
                const uint32_t ordinal_base = rd32(d + *dir_off + 16);
                const uint32_t num_funcs     = std::min<uint32_t>(rd32(d + *dir_off + 20), 65536);
                const uint32_t num_names     = std::min<uint32_t>(rd32(d + *dir_off + 24), 65536);
                const uint32_t funcs_rva     = rd32(d + *dir_off + 28);
                const uint32_t names_rva     = rd32(d + *dir_off + 32);
                const uint32_t ordinals_rva  = rd32(d + *dir_off + 36);

                auto funcs_off = img.rva_to_offset(funcs_rva);
                auto names_off = img.rva_to_offset(names_rva);
                auto ords_off  = img.rva_to_offset(ordinals_rva);
                if (funcs_off) {
                    std::vector<std::string> names(num_funcs);
                    if (names_off && ords_off) {
                        for (uint32_t i = 0; i < num_names; ++i) {
                            const size_t no = *names_off + static_cast<size_t>(i) * 4;
                            const size_t oo = *ords_off + static_cast<size_t>(i) * 2;
                            if (no + 4 > len || oo + 2 > len) break;
                            const uint16_t index = rd16(d + oo);
                            const auto str_off = img.rva_to_offset(rd32(d + no));
                            if (index < names.size() && str_off)
                                names[index] = read_cstring_at(d, len, *str_off);
                        }
                    }
                    const uint64_t exp_end = static_cast<uint64_t>(exp_rva) + img.data_dirs[0].size;
                    for (uint32_t index = 0; index < num_funcs; ++index) {
                        const size_t fo = *funcs_off + static_cast<size_t>(index) * 4;
                        if (fo + 4 > len) break;
                        const uint32_t func_rva = rd32(d + fo);
                        if (!func_rva) continue;
                        pe_export_t e;
                        e.name = names[index];
                        e.ordinal = static_cast<uint16_t>(ordinal_base + index);
                        e.rva = func_rva;
                        if (func_rva >= exp_rva && static_cast<uint64_t>(func_rva) < exp_end) {
                            e.forwarded = true;
                            const auto forwarder_off = img.rva_to_offset(func_rva);
                            if (forwarder_off) e.forwarder = read_cstring_at(d, len, *forwarder_off);
                        }
                        img.exports.push_back(std::move(e));
                    }
                }
            }
        }
    }

    // Exception directory (index 3): RUNTIME_FUNCTION entries give exact
    // function bounds on x64. Parsed structurally (no decode), so the
    // function index can seed from the compiler's own data instead of
    // validating every prologue by decoding toward a ret.
    {
        const uint32_t exc_rva  = img.data_dirs[3].rva;
        const uint32_t exc_size = img.data_dirs[3].size;
        if (exc_rva && exc_size >= 12) {
            auto dir_off = img.rva_to_offset(exc_rva);
            if (dir_off && *dir_off + 12 <= len) {
                // Clamp the entry count the same way the table size does:
                // a corrupt size must not turn into millions of entries.
                size_t count = exc_size / 12;
                constexpr size_t kMaxEntries = 500'000;
                if (count > kMaxEntries) count = kMaxEntries;
                const size_t avail = (len - *dir_off) / 12;
                if (count > avail) count = avail;
                for (size_t i = 0; i < count; ++i) {
                    const size_t o = *dir_off + i * 12;
                    const uint32_t begin = rd32(d + o);
                    const uint32_t end   = rd32(d + o + 4);
                    if (begin == 0 || end <= begin) continue;
                    img.runtime_funcs.push_back({begin, end});
                }
            }
        }
    }

    return img;
}

} // namespace slop::core::disasm
