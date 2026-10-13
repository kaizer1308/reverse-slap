// src/core/disasm/image_open.cpp

#include "core/disasm/image_open.hpp"

#include "core/loader/macho_loader.h"
#include "core/util/zip_reader.hpp"

#include <algorithm>
#include <cstring>
#include <limits>
#include <unordered_map>

namespace slop::core::disasm {

namespace {

constexpr uint16_t kMachineX86   = 0x014C;
constexpr uint16_t kMachineX64   = 0x8664;
constexpr uint16_t kMachineArmNt = 0x01C4;
constexpr uint16_t kMachineArm64 = 0xAA64;

constexpr uint64_t kMaxRva = std::numeric_limits<uint32_t>::max();

bool arch_from_hype(hype::Arch a, image_arch_t& out) {
    switch (a) {
    case hype::Arch::X86:   out = image_arch_t::x86;   return true;
    case hype::Arch::X64:   out = image_arch_t::x64;   return true;
    case hype::Arch::ARM:   out = image_arch_t::arm;   return true;
    case hype::Arch::ARM64: out = image_arch_t::arm64; return true;
    default:                return false;
    }
}

uint16_t machine_for(image_arch_t a) {
    switch (a) {
    case image_arch_t::x86:   return kMachineX86;
    case image_arch_t::x64:   return kMachineX64;
    case image_arch_t::arm:   return kMachineArmNt;
    case image_arch_t::arm64: return kMachineArm64;
    }
    return 0;
}

// the hyperion loader parses, the legacy stack gets the same facts as a
// pe_image_t so rva/offset/section/string consumers need no Mach-O branch
void synthesize_section_map(const hype::PEImage& img, image_arch_t arch,
                            size_t file_size, pe_image_t& pe) {
    pe.ok         = true;
    pe.pe32plus   = arch == image_arch_t::x64 || arch == image_arch_t::arm64;
    pe.machine    = machine_for(arch);
    pe.image_base = img.base;
    if (img.entry >= img.base && img.entry - img.base <= kMaxRva)
        pe.entry_rva = static_cast<uint32_t>(img.entry - img.base);

    uint64_t image_end = 0;
    for (const auto& seg : img.segments) {
        if (seg.va < img.base || seg.va - img.base > kMaxRva) continue;
        pe_section_t s;
        const size_t n = std::min(seg.name.size(), sizeof(s.name) - 1);
        std::memcpy(s.name, seg.name.data(), n);
        s.rva          = static_cast<uint32_t>(seg.va - img.base);
        s.virtual_size = static_cast<uint32_t>(std::min<uint64_t>(seg.size, kMaxRva - s.rva));
        if (seg.file_sz && seg.file_off < file_size) {
            s.raw_offset = static_cast<uint32_t>(std::min<uint64_t>(seg.file_off, kMaxRva));
            s.raw_size   = static_cast<uint32_t>(std::min<uint64_t>(
                {seg.file_sz, file_size - seg.file_off, kMaxRva}));
        }
        s.characteristics = seg.flags;
        image_end = std::max<uint64_t>(image_end, uint64_t{s.rva} + s.virtual_size);
        pe.sections.push_back(s);
    }
    pe.size_of_image = static_cast<uint32_t>(std::min(image_end, kMaxRva));

    // group slots per dylib in first-seen order, like a PE import directory
    std::unordered_map<std::string, size_t> dll_index;
    for (const auto& imp : img.imports) {
        if (imp.iat_addr < img.base || imp.iat_addr - img.base > kMaxRva) continue;
        const std::string dll = imp.dll.empty() ? "(flat namespace)" : imp.dll;
        auto [it, fresh] = dll_index.try_emplace(dll, pe.imports.size());
        if (fresh) pe.imports.push_back({dll, {}});
        pe_import_func_t fn;
        fn.name    = imp.name;
        fn.iat_rva = static_cast<uint32_t>(imp.iat_addr - img.base);
        pe.imports[it->second].functions.push_back(std::move(fn));
    }

    for (const auto& ex : img.exports) {
        if (ex.addr < img.base || ex.addr - img.base > kMaxRva) continue;
        pe_export_t e;
        e.name = ex.name;
        e.rva  = static_cast<uint32_t>(ex.addr - img.base);
        pe.exports.push_back(std::move(e));
    }

    for (const auto& rf : img.runtime_funcs) {
        if (rf.start < img.base || rf.end <= rf.start || rf.end - img.base > kMaxRva) continue;
        pe.runtime_funcs.push_back({static_cast<uint32_t>(rf.start - img.base),
                                    static_cast<uint32_t>(rf.end - img.base)});
    }
}

void open_macho(std::vector<uint8_t> raw, opened_image_t& out) {
    const auto slice = hype::MachOLoader::select_slice(raw.data(), raw.size());
    if (!slice) {
        out.error = "macho: no supported architecture slice (arm64, x86_64, arm, x86)";
        return;
    }
    // analyze one thin slice so file offsets, patches and the annotation
    // hash all refer to the bytes the section map describes
    if (slice->offset == 0 && slice->size == raw.size()) {
        out.file = std::move(raw);
    } else {
        const auto first = raw.begin() + static_cast<std::ptrdiff_t>(slice->offset);
        out.file.assign(first, first + static_cast<std::ptrdiff_t>(slice->size));
    }

    hype::MachOLoader loader;
    const auto img = loader.load_buffer(out.file.data(), out.file.size());
    if (!img) {
        out.error = "macho: load commands could not be parsed";
        return;
    }
    if (!arch_from_hype(img->arch, out.arch)) {
        out.error = "macho: unsupported cpu type";
        return;
    }
    out.format    = image_format_t::macho;
    out.encrypted = img->encrypted;
    synthesize_section_map(*img, out.arch, out.file.size(), out.pe);
    if (out.pe.sections.empty()) {
        out.error = "macho: no mapped sections";
        return;
    }
    out.ok = true;
}

} // namespace

const char* image_format_name(image_format_t f) noexcept {
    switch (f) {
    case image_format_t::pe:    return "pe";
    case image_format_t::macho: return "macho";
    }
    return "unknown";
}

const char* image_arch_name(image_arch_t a) noexcept {
    switch (a) {
    case image_arch_t::x86:   return "x86";
    case image_arch_t::x64:   return "x64";
    case image_arch_t::arm:   return "arm";
    case image_arch_t::arm64: return "arm64";
    }
    return "unknown";
}

hype::Arch hype_arch(image_arch_t a) noexcept {
    switch (a) {
    case image_arch_t::x86:   return hype::Arch::X86;
    case image_arch_t::x64:   return hype::Arch::X64;
    case image_arch_t::arm:   return hype::Arch::ARM;
    case image_arch_t::arm64: return hype::Arch::ARM64;
    }
    return hype::Arch::X64;
}

opened_image_t open_image(std::vector<uint8_t> raw) {
    opened_image_t out;

    if (util::zip::has_zip_magic(raw.data(), raw.size())) {
        if (!ipa::looks_like_ipa(raw.data(), raw.size())) {
            out.error = "zip archive without a Payload/<name>.app bundle (not an .ipa)";
            return out;
        }
        auto ex = ipa::extract_main_binary(raw.data(), raw.size());
        if (!ex.ok) {
            out.error = ex.error;
            return out;
        }
        if (!hype::MachOLoader::is_macho(ex.binary.data(), ex.binary.size())) {
            out.error = "ipa: main executable '" + ex.bundle.executable_path +
                        "' is not a Mach-O";
            return out;
        }
        out.bundle = std::move(ex.bundle);
        raw = std::move(ex.binary);
    }

    if (hype::MachOLoader::is_macho(raw.data(), raw.size())) {
        open_macho(std::move(raw), out);
        return out;
    }

    out.pe = pe_parse(raw.data(), raw.size());
    if (!out.pe.ok) {
        out.error = "unrecognized image format (expected PE, Mach-O or .ipa)";
        return out;
    }
    // same rule the hyperion PE loader applies: the optional header picks
    // the decoder
    out.format = image_format_t::pe;
    out.arch   = out.pe.pe32plus ? image_arch_t::x64 : image_arch_t::x86;
    out.file   = std::move(raw);
    out.ok     = true;
    return out;
}

} // namespace slop::core::disasm
