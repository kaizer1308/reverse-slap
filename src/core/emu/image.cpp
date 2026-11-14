// src/core/emu/image.cpp

#include "core/emu/image.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>

namespace slop::core::emu {

namespace {

constexpr size_t   kDirBaseReloc = 5;
constexpr size_t   kDirTls       = 9;
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint16_t kSubsystemNative = 1;
constexpr size_t   kMaxTlsTemplate  = 1u << 20;

std::string lower_ascii(std::string s) {
    for (char& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    return s;
}

} // namespace

void image_view_t::copy_mapped(const image_bytes_t& img, uint64_t rva, size_t len,
                               uint8_t* out) {
    std::memset(out, 0, len);
    const uint64_t end = rva + len;
    const auto& pe = *img.pe;
    if (img.is_pe) {
        uint64_t headers = kPageSize;
        for (const auto& s : pe.sections)
            if (s.raw_size) headers = std::min<uint64_t>(headers, s.raw_offset);
        headers = std::min<uint64_t>(headers, img.size);
        if (rva < headers)
            std::memcpy(out, img.file + rva,
                        static_cast<size_t>(std::min(end, headers) - rva));
    }
    for (const auto& s : pe.sections) {
        // file bytes past VirtualSize are not mapped by the loader
        const uint64_t backed = std::min<uint64_t>(
            s.virtual_size ? s.virtual_size : s.raw_size, s.raw_size);
        const uint64_t lo = std::max<uint64_t>(rva, s.rva);
        const uint64_t hi = std::min<uint64_t>(end, s.rva + backed);
        if (lo >= hi) continue;
        const uint64_t off = uint64_t{s.raw_offset} + (lo - s.rva);
        if (off >= img.size) continue;
        const uint64_t n = std::min<uint64_t>(hi - lo, img.size - off);
        std::memcpy(out + (lo - rva), img.file + off, static_cast<size_t>(n));
    }
}

std::shared_ptr<const image_view_t> image_view_t::make(const image_bytes_t& img,
                                                       uint64_t base) {
    auto v = std::make_shared<image_view_t>();
    const auto& pe = *img.pe;
    v->extent = pe.size_of_image;
    if (!v->extent)
        for (const auto& s : pe.sections)
            v->extent = std::max<uint64_t>(
                v->extent, uint64_t{s.rva} + (s.virtual_size ? s.virtual_size : s.raw_size));
    v->delta = base - pe.image_base;

    // IMAGE_DIRECTORY_ENTRY_BASERELOC: blocks of {page rva, size, u16
    // entries}, type in the top 4 bits (3 HIGHLOW, 10 DIR64)
    const auto& dir = pe.data_dirs[kDirBaseReloc];
    if (v->delta == 0 || !img.is_pe || !dir.rva || !dir.size || dir.size > (64u << 20))
        return v;
    std::vector<uint8_t> raw(dir.size);
    copy_mapped(img, dir.rva, raw.size(), raw.data());
    for (size_t pos = 0; pos + 8 <= raw.size();) {
        uint32_t page = 0, block = 0;
        std::memcpy(&page, raw.data() + pos, 4);
        std::memcpy(&block, raw.data() + pos + 4, 4);
        if (block < 8 || block > raw.size() - pos) break;
        for (size_t e = pos + 8; e + 2 <= pos + block; e += 2) {
            uint16_t entry = 0;
            std::memcpy(&entry, raw.data() + e, 2);
            const uint32_t at = page + (entry & 0xFFFu);
            if ((entry >> 12) == 10)     v->relocs.push_back({at, 8});
            else if ((entry >> 12) == 3) v->relocs.push_back({at, 4});
        }
        pos += block;
    }
    std::sort(v->relocs.begin(), v->relocs.end(),
              [](const reloc_t& a, const reloc_t& b) { return a.rva < b.rva; });
    return v;
}

void image_view_t::read(const image_bytes_t& img, uint64_t rva, size_t len,
                        uint8_t* out) const {
    copy_mapped(img, rva, len, out);
    if (relocs.empty()) return;
    // a fixup starting up to 7 bytes before the range still reaches into it
    const uint64_t from = rva >= 7 ? rva - 7 : 0;
    auto it = std::lower_bound(relocs.begin(), relocs.end(), from,
                               [](const reloc_t& r, uint64_t a) { return r.rva < a; });
    for (; it != relocs.end() && it->rva < rva + len; ++it) {
        uint8_t v[8] = {};
        copy_mapped(img, it->rva, it->width, v);
        if (it->width == 8) {
            uint64_t x = 0;
            std::memcpy(&x, v, 8);
            x += delta;
            std::memcpy(v, &x, 8);
        } else {
            uint32_t x = 0;
            std::memcpy(&x, v, 4);
            x += static_cast<uint32_t>(delta);
            std::memcpy(v, &x, 4);
        }
        for (uint8_t i = 0; i < it->width; ++i) {
            const uint64_t at = uint64_t{it->rva} + i;
            if (at >= rva && at < rva + len) out[at - rva] = v[i];
        }
    }
}

page_source_t image_page_source(std::shared_ptr<const image_view_t> view,
                                image_bytes_t img, uint64_t base) {
    return [view = std::move(view), img, base](uint64_t page, uint8_t* out) {
        if (page < base) return false;
        const uint64_t rva = page - base;
        if (rva >= view->extent) return false;
        view->read(img, rva, kPageSize, out);
        return true;
    };
}

std::vector<import_slot_t> image_import_slots(const disasm::pe_image_t& pe, uint64_t base,
                                              std::map<std::string, uint64_t>* returns) {
    std::vector<import_slot_t> out;
    if (!pe.pe32plus) return out;
    std::vector<std::string> used;
    for (const auto& dll : pe.imports) {
        for (const auto& fn : dll.functions) {
            if (!fn.iat_rva) continue;
            if (out.size() >= kMaxImports) break;
            import_slot_t slot;
            slot.slot = base + fn.iat_rva;
            const std::string func = fn.by_ordinal ? "#" + std::to_string(fn.ordinal) : fn.name;
            slot.name = dll.dll + "!" + func;
            if (returns) {
                for (const std::string& key : {lower_ascii(slot.name), lower_ascii(func)}) {
                    if (auto it = returns->find(key); it != returns->end()) {
                        slot.has_ret = true;
                        slot.ret = it->second;
                        used.push_back(key);
                        break;
                    }
                }
            }
            out.push_back(std::move(slot));
        }
    }
    if (returns)
        for (const auto& key : used) returns->erase(key);
    return out;
}

void image_tls(const image_view_t& view, const image_bytes_t& img, uint64_t base,
               run_request_t* req) {
    const auto& pe = *img.pe;
    const auto& dir = pe.data_dirs[kDirTls];
    if (!img.is_pe || !pe.pe32plus || !dir.rva || dir.size < 40) return;

    // IMAGE_TLS_DIRECTORY64: StartAddressOfRawData, EndAddressOfRawData,
    // AddressOfIndex, AddressOfCallBacks (all vas), SizeOfZeroFill,
    // Characteristics. Read relocated, so the vas are session vas
    uint8_t raw[40] = {};
    view.read(img, dir.rva, sizeof(raw), raw);
    uint64_t start = 0, end = 0, index_va = 0;
    uint32_t zero_fill = 0;
    std::memcpy(&start, raw, 8);
    std::memcpy(&end, raw + 8, 8);
    std::memcpy(&index_va, raw + 16, 8);
    std::memcpy(&zero_fill, raw + 32, 4);

    auto to_rva = [&](uint64_t va, uint64_t* rva) {
        if (va < base || va - base >= view.extent) return false;
        *rva = va - base;
        return true;
    };
    uint64_t start_rva = 0, index_rva = 0;
    if (end < start || !to_rva(start, &start_rva)) return;
    const uint64_t data = end - start;
    if (data > view.extent - start_rva || data + zero_fill > kMaxTlsTemplate) return;

    req->has_tls = true;
    req->tls_block.assign(static_cast<size_t>(data + zero_fill), 0);
    if (data) view.read(img, start_rva, static_cast<size_t>(data), req->tls_block.data());
    // the loader stores the module's index here; on disk it is the linker's 0
    req->tls_index = 0;
    if (to_rva(index_va, &index_rva)) {
        uint8_t idx[4] = {};
        view.read(img, index_rva, sizeof(idx), idx);
        std::memcpy(&req->tls_index, idx, 4);
    }
}

bool image_is_kernel(const disasm::pe_image_t& pe) {
    if (pe.subsystem != kSubsystemNative) return false;
    for (const auto& dll : pe.imports)
        if (lower_ascii(dll.dll) == "ntdll.dll") return false;
    return true;
}

bool attach_image(run_request_t* req, const image_bytes_t& img, uint64_t base) {
    const auto& pe = *img.pe;
    if (!pe.pe32plus || pe.machine != kMachineAmd64) return false;
    auto view = image_view_t::make(img, base);
    req->image_base = base;
    if (img.is_pe) {
        req->kernel_mode = image_is_kernel(pe);
        req->imports     = image_import_slots(pe, base);
        image_tls(*view, img, base, req);
    }
    req->page_in = image_page_source(std::move(view), img, base);
    return true;
}

bool is_pe_file(const uint8_t* file, size_t size) {
    return size >= 2 && file[0] == 'M' && file[1] == 'Z';
}

} // namespace slop::core::emu
