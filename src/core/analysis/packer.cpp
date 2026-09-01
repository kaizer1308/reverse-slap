// src/core/analysis/packer.cpp

#include "core/analysis/packer.hpp"

#include <algorithm>
#include <array>
#include <cmath>
#include <cctype>
#include <cstring>

namespace slop::core::analysis {

namespace {

constexpr size_t kEntropySampleBytes = 256 * 1024;

double entropy_sampled(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    if (len <= kEntropySampleBytes) return shannon_entropy(data, len);
    // Stride sampling keeps large sections cheap without biasing the result
    // for the uniform-density distributions packers produce
    const size_t stride = len / kEntropySampleBytes;
    std::array<uint32_t, 256> freq{};
    size_t n = 0;
    for (size_t i = 0; i < len; i += stride) {
        ++freq[data[i]];
        ++n;
    }
    double e = 0.0;
    for (uint32_t f : freq) {
        if (!f) continue;
        const double p = static_cast<double>(f) / static_cast<double>(n);
        e -= p * std::log2(p);
    }
    return e;
}

struct family_sig_t {
    const char* section;     // lower-cased compare target
    const char* family;
};

constexpr family_sig_t kSectionFamilies[] = {
    {"upx0", "UPX"},        {"upx1", "UPX"},       {"upx2", "UPX"},
    {".upx", "UPX"},
    {".vmp", "VMProtect"},  {".vmp0", "VMProtect"},{".vmp1", "VMProtect"},
    {".vmp2", "VMProtect"},{".vmprotect", "VMProtect"},
    {"themida", "Themida/WinLicense"}, {".themida", "Themida/WinLicense"},
    {"winlice", "Themida/WinLicense"},
    {".aspack", "ASPack"},  {".adata", "ASPack"},
    {"asprotect", "ASProtect"}, {".aspack", "ASPack"},
    {".nsp0", "NSPack"},    {".nsp1", "NSPack"},   {".nsp2", "NSPack"},
    {".enigma1", "Enigma Protector"}, {".enigma2", "Enigma Protector"},
    {"mpress1", "MPRESS"},  {"mpress2", "MPRESS"},
    {".pec", "PECompact"},  {".pec2", "PECompact"},{".pecompact", "PECompact"},
    {".petite", "Petite"},
    {".upk", "UPack"},
    {".y0da", "Y0da Crypter"},
    {".sforce", "StarForce"},
    {"_winzip_", "WinZip SFX"},
    {".ndata", "NSIS Installer"},
    {".rlpack", "RLPack"},
    {".maskpe", "MaskPE"},
    {".shrink", "Shrinker"},
    {".obsidium", "Obsidium"},
    {".packed", "Generic packed section"},
};

std::string lower_ascii(std::string s) {
    for (char& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

const char* family_for_section(const std::string& raw_name) {
    const std::string name = lower_ascii(raw_name);
    for (const auto& sig : kSectionFamilies)
        if (name == sig.section) return sig.family;
    // Prefix match catches .vmp1-style variants with numeric suffixes
    for (const auto& sig : kSectionFamilies) {
        const std::string pfx = sig.section;
        if (pfx.size() >= 3 && name.rfind(pfx, 0) == 0 &&
            (std::isdigit(static_cast<unsigned char>(name[pfx.size()]))))
            return sig.family;
    }
    return nullptr;
}

struct byte_sig_t {
    const char* family;
    const char* detail;
    std::array<uint8_t, 10> pattern;
    std::array<uint8_t, 10> mask;
    uint8_t length;
};

// Classic unpacking-stub prologues at/around the entry point
constexpr byte_sig_t kEntrySigs[] = {
    {"UPX", "UPX decompression stub (pushad/mov esi/lea edi)",
     {0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE, 0x00, 0x00},
     {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00}, 8},
    {"VMProtect", "VMProtect entry stub (push imm32/call rel32)",
     {0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00},
     {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x00}, 10},
    {"Themida/WinLicense", "Themida stolen-code entry (mov eax,imm/pushad/rdtsc)",
     {0xB8, 0x00, 0x00, 0x00, 0x00, 0x60, 0x0F, 0x31, 0x00, 0x00},
     {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0x00, 0x00}, 8},
};

constexpr const char* kProtectorStrings[] = {
    "VMProtect", "Themida", "WinLicense", "Oreans Technologies",
    "ASProtect", "Enigma protector", "PECompact", "Obsidium",
    ".NET Reactor", "ConfuserEx", nullptr,
};

bool find_bytes(const std::vector<uint8_t>& hay, const uint8_t* needle, size_t n,
                size_t begin, size_t end, size_t* out_off) {
    if (n == 0 || hay.size() < n) return false;
    const size_t stop = std::min(end, hay.size()) - (n - 1);
    for (size_t i = begin; i <= stop; ++i) {
        if (std::equal(needle, needle + n, hay.data() + i)) {
            *out_off = i;
            return true;
        }
    }
    return false;
}

} // namespace

double shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    std::array<uint32_t, 256> freq{};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    double e = 0.0;
    for (uint32_t f : freq) {
        if (!f) continue;
        const double p = static_cast<double>(f) / static_cast<double>(len);
        e -= p * std::log2(p);
    }
    return e;
}

packer_verdict_t packer_analyze(const disasm::pe_image_t& pe,
                                const std::vector<uint8_t>& file) {
    packer_verdict_t out;
    if (!pe.ok) return out;

    double score = 0.0;
    std::string best_family;
    double best_family_score = 0.0;
    auto bump = [&](double w, const char* family) {
        score += w;
        if (family && w > best_family_score) {
            best_family_score = w;
            best_family = family;
        }
    };

    // per-section profile
    int exec_sections = 0;
    int first_exec_idx = -1;
    int writable_exec = 0;
    const disasm::pe_section_t* entry_sec = nullptr;
    int entry_sec_idx = -1;

    for (size_t i = 0; i < pe.sections.size(); ++i) {
        const auto& sec = pe.sections[i];
        packer_section_report_t rep;
        rep.name         = sec.name;
        rep.rva          = sec.rva;
        rep.raw_size     = sec.raw_size;
        rep.virtual_size = sec.virtual_size;
        rep.characteristics = sec.characteristics;
        rep.writable_exec = sec.is_executable() && (sec.characteristics & 0x80000000) != 0;
        if (sec.is_executable()) {
            if (first_exec_idx < 0) first_exec_idx = static_cast<int>(i);
            ++exec_sections;
        }
        if (rep.writable_exec) ++writable_exec;
        if (sec.contains_rva(pe.entry_rva)) {
            entry_sec     = &sec;
            entry_sec_idx = static_cast<int>(i);
        }

        if (sec.raw_size > 0 &&
            static_cast<size_t>(sec.raw_offset) + sec.raw_size <= file.size()) {
            rep.entropy = entropy_sampled(file.data() + sec.raw_offset, sec.raw_size);
        }
        out.sections.push_back(std::move(rep));

        if (const char* fam = family_for_section(sec.name)) {
            packer_detection_t d;
            d.type      = "section_name";
            d.protector = fam;
            d.detail    = "section '" + std::string(sec.name) + "' matches known packer naming";
            d.location  = sec.rva;
            out.detections.push_back(std::move(d));
            bump(fam == std::string("Generic packed section") ? 0.35 : 0.55, fam);
        }
        if (rep.entropy >= 7.5 && sec.is_executable()) {
            packer_detection_t d;
            d.type   = "high_entropy";
            d.detail = "executable section '" + std::string(sec.name) + "' entropy " +
                       std::to_string(rep.entropy).substr(0, 5);
            d.location = sec.rva;
            out.detections.push_back(std::move(d));
            bump(0.45, nullptr);
        } else if (rep.entropy >= 7.0 && !sec.is_executable() && sec.raw_size > 4096) {
            packer_detection_t d;
            d.type   = "high_entropy";
            d.detail = "data section '" + std::string(sec.name) + "' entropy " +
                       std::to_string(rep.entropy).substr(0, 5);
            d.location = sec.rva;
            out.detections.push_back(std::move(d));
            bump(0.20, nullptr);
        }
        if (rep.writable_exec && sec.raw_size > 0) {
            packer_detection_t d;
            d.type   = "wx_section";
            d.detail = "section '" + std::string(sec.name) + "' is writable+executable";
            d.location = sec.rva;
            out.detections.push_back(std::move(d));
            bump(0.15, nullptr);
        }
    }

    // entry-point placement
    if (entry_sec && first_exec_idx >= 0 && entry_sec_idx > first_exec_idx) {
        const bool bloated = entry_sec->virtual_size >
                             entry_sec->raw_size * 4 && entry_sec->raw_size > 0;
        if (bloated || entropy_sampled(
               file.data() + entry_sec->raw_offset,
               std::min<size_t>(entry_sec->raw_size, kEntropySampleBytes)) > 6.8 ||
           family_for_section(entry_sec->name)) {
            packer_detection_t d;
            d.type   = "layout";
            d.detail = "entry point inside '" + std::string(entry_sec->name) +
                       "' (not the first executable section)";
            d.location = pe.image_base + pe.entry_rva;
            out.detections.push_back(std::move(d));
            bump(0.30, nullptr);
        }
    }

    // entry-stub byte signatures
    if (auto ep_off = pe.va_to_offset(pe.image_base + pe.entry_rva)) {
        const size_t scan_begin = *ep_off > 0x100 ? *ep_off - 0x100 : 0;
        const size_t scan_end   = std::min(file.size(), *ep_off + 0x1000);
        for (const auto& sig : kEntrySigs) {
            size_t hit = 0;
            bool found = false;
            for (size_t i = scan_begin; i + sig.length <= scan_end; ++i) {
                bool m = true;
                for (int b = 0; b < sig.length; ++b) {
                    if ((file[i + b] & sig.mask[b]) != (sig.pattern[b] & sig.mask[b])) {
                        m = false;
                        break;
                    }
                }
                if (m) { found = true; hit = i; break; }
            }
            if (found) {
                packer_detection_t d;
                d.type      = "byte_signature";
                d.protector = sig.family;
                d.detail    = sig.detail;
                d.location  = hit;
                out.detections.push_back(std::move(d));
                bump(0.50, sig.family);
                break;
            }
        }
    }

    // protector marker strings
    {
        size_t cursor = 0;
        for (const char* const* s = kProtectorStrings; *s; ++s) {
            size_t off = 0;
            if (find_bytes(file, reinterpret_cast<const uint8_t*>(*s),
                           std::strlen(*s), cursor, file.size(), &off)) {
                packer_detection_t d;
                d.type      = "string_reference";
                d.protector = *s;
                d.detail    = std::string("marker string \"") + *s + "\"";
                d.location  = off;
                out.detections.push_back(std::move(d));
                bump(0.35, *s);
                cursor = off + 1;
            }
        }
    }

    // UPX end-of-file magic
    {
        size_t off = 0;
        if (find_bytes(file, reinterpret_cast<const uint8_t*>("UPX!"), 4, 0,
                       file.size(), &off)) {
            packer_detection_t d;
            d.type      = "byte_signature";
            d.protector = "UPX";
            d.detail    = "\"UPX!\" trailer magic";
            d.location  = off;
            out.detections.push_back(std::move(d));
            bump(0.50, "UPX");
        }
    }

    // import table anomalies
    {
        size_t total_imports = 0;
        bool has_ldl_gpa = false;
        for (const auto& dll : pe.imports) {
            total_imports += dll.functions.size();
            for (const auto& fn : dll.functions) {
                if (_stricmp(fn.name.c_str(), "LoadLibraryA") == 0 ||
                    _stricmp(fn.name.c_str(), "GetProcAddress") == 0)
                    has_ldl_gpa = true;
            }
        }
        if (total_imports < 10 && has_ldl_gpa) {
            packer_detection_t d;
            d.type   = "imports";
            d.detail = "tiny import table (" + std::to_string(total_imports) +
                       ") centered on LoadLibraryA/GetProcAddress";
            out.detections.push_back(std::move(d));
            bump(0.35, nullptr);
        } else if (total_imports == 0 && pe.sections.size() > 0) {
            packer_detection_t d;
            d.type   = "imports";
            d.detail = "no imports resolved";
            out.detections.push_back(std::move(d));
            bump(0.25, nullptr);
        }
    }

    // TLS callbacks + overlay
    if (pe.data_dirs[9].size > 0) {   // IMAGE_DIRECTORY_ENTRY_TLS
        packer_detection_t d;
        d.type   = "tls";
        d.detail = "TLS directory present (callback execution before entry)";
        out.detections.push_back(std::move(d));
        bump(0.10, nullptr);
    }
    {
        uint64_t end_of_raw = 0;
        for (const auto& sec : pe.sections)
            end_of_raw = std::max<uint64_t>(
                end_of_raw, static_cast<uint64_t>(sec.raw_offset) + sec.raw_size);
        if (end_of_raw > 0 && file.size() > end_of_raw + 512) {
            packer_detection_t d;
            d.type   = "overlay";
            d.detail = std::to_string(file.size() - end_of_raw) +
                       " bytes of appended overlay data";
            d.location = end_of_raw;
            out.detections.push_back(std::move(d));
            bump(0.05, nullptr);
        }
    }

    out.file_entropy = entropy_sampled(file.data(),
                                       std::min<size_t>(file.size(), 1024 * 1024));
    out.confidence = std::min(1.0, score);
    out.family     = best_family;
    out.packed     = out.confidence >= 0.50 || !best_family.empty();
    if (out.packed && out.family.empty()) out.family = "Unknown packer";
    return out;
}

} // namespace slop::core::analysis
