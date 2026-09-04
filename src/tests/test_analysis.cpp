// src/tests/test_analysis.cpp
// Packer/protector heuristics + crypto signature hunt against the real
// SlopTarget.exe fixture and patched variants of it

#include "harness.hpp"

#include "core/analysis/packer.hpp"
#include "core/analysis/signatures.hpp"
#include "core/disasm/pe_parser.hpp"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iterator>
#include <random>
#include <vector>

using namespace slop::core::analysis;
namespace disasm = slop::core::disasm;

namespace {

std::vector<uint8_t>& slop_target_bytes() {
    static std::vector<uint8_t> bytes = [] {
        std::ifstream f(SLOP_TARGET_EXE_PATH, std::ios::binary);
        return std::vector<uint8_t>(std::istreambuf_iterator<char>(f),
                                    std::istreambuf_iterator<char>{});
    }();
    return bytes;
}

// Patch section name #index in a PE copy (headers only, layout untouched)
bool patch_section_name(std::vector<uint8_t>& img, size_t index,
                        const char* name) {
    if (img.size() < 0x400) return false;
    const uint32_t e_lfanew =
        *reinterpret_cast<const uint32_t*>(img.data() + 0x3C);
    const uint16_t opt_size = *reinterpret_cast<const uint16_t*>(
        img.data() + e_lfanew + 4 + 16);
    const size_t first_hdr = e_lfanew + 4 + 20 + opt_size;
    const size_t off = first_hdr + index * 40;
    if (off + 8 > img.size()) return false;
    std::memset(img.data() + off, 0, 8);
    std::memcpy(img.data() + off, name, std::min<size_t>(strlen(name), 8));
    return true;
}

} // namespace

TEST_CASE(entropy_basics) {
    std::vector<uint8_t> zeros(4096, 0x00);
    REQUIRE(shannon_entropy(zeros.data(), zeros.size()) < 0.01);

    std::mt19937 rng(1234);
    std::vector<uint8_t> noise(65536);
    for (auto& b : noise) b = static_cast<uint8_t>(rng());
    REQUIRE(shannon_entropy(noise.data(), noise.size()) > 7.9);
}

TEST_CASE(packer_clean_binary_not_flagged) {
    const auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(!v.packed);
    REQUIRE(v.confidence < 0.5);
    REQUIRE(v.family.empty());
}

TEST_CASE(packer_upx_section_names_identify_family) {
    auto bytes = slop_target_bytes();
    REQUIRE(patch_section_name(bytes, 0, "UPX0"));
    REQUIRE(patch_section_name(bytes, 1, "UPX1"));

    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(v.packed);
    REQUIRE_STR_EQ(v.family.c_str(), "UPX");

    bool named_hit = false;
    for (const auto& d : v.detections)
        if (d.type == "section_name" && d.protector == "UPX") named_hit = true;
    REQUIRE(named_hit);
}

TEST_CASE(packer_vmp_names_identify_family) {
    auto bytes = slop_target_bytes();
    REQUIRE(patch_section_name(bytes, 0, ".vmp0"));
    REQUIRE(patch_section_name(bytes, 1, ".vmp1"));

    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    auto v = packer_analyze(pe, bytes);
    REQUIRE(v.packed);
    REQUIRE_STR_EQ(v.family.c_str(), "VMProtect");
}

TEST_CASE(packer_high_entropy_exec_section_flagged) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE(pe.sections.size() > 0);

    // Fill the first executable section's raw payload with PRNG noise
    bool filled = false;
    for (const auto& sec : pe.sections) {
        if (!sec.is_executable() || sec.raw_size < 4096) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bytes.size())
            continue;
        std::mt19937 rng(99);
        for (uint32_t i = 0; i < sec.raw_size; ++i)
            bytes[sec.raw_offset + i] = static_cast<uint8_t>(rng());
        filled = true;
        break;
    }
    REQUIRE(filled);

    auto repacked = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(repacked.ok);
    auto v = packer_analyze(repacked, bytes);

    bool entropy_hit = false;
    for (const auto& d : v.detections)
        if (d.type == "high_entropy") entropy_hit = true;
    REQUIRE(entropy_hit);
}

TEST_CASE(packer_noisy_data_sections_plus_tls_stays_clean) {
    // Regression: clean Rust-style image (.rdata/.rsrc ~7.8 entropy + TLS
    // directory) used to score 0.2+0.2+0.1=0.50 -> packed:Unknown. Weak
    // signals alone must not tip the verdict without a strong indicator.
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Fill from the end so the import table (.rdata, early) survives and no
    // spurious "no imports" signal pollutes the score.
    int filled = 0;
    for (auto it = pe.sections.rbegin(); it != pe.sections.rend(); ++it) {
        const auto& sec = *it;
        if (sec.is_executable() || sec.raw_size < 4096) continue;
        if (static_cast<size_t>(sec.raw_offset) + sec.raw_size > bytes.size())
            continue;
        std::mt19937 rng(0xC0FFEE + filled);
        for (uint32_t i = 0; i < sec.raw_size; ++i)
            bytes[sec.raw_offset + i] = static_cast<uint8_t>(rng());
        if (++filled == 2) break;
    }
    REQUIRE_EQ(filled, 2);

    // Set a TLS directory size (weak signal, normal in Rust/MSVC CRT)
    {
        const uint32_t e_lfanew =
            *reinterpret_cast<const uint32_t*>(bytes.data() + 0x3C);
        const size_t oh = e_lfanew + 4 + 20;
        const size_t tls_size_off = oh + 112 + 9 * 8 + 4;
        REQUIRE_LT(tls_size_off + 4, bytes.size());
        const uint32_t tls_size = 0x18;
        std::memcpy(bytes.data() + tls_size_off, &tls_size, 4);
    }

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(reparsed.ok);
    auto v = packer_analyze(reparsed, bytes);
    REQUIRE(!v.packed);
    REQUIRE(v.family.empty());
}

TEST_CASE(crypto_hunt_finds_planted_aes_sbox) {
    auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);

    // Plant the AES forward S-box prefix into the last raw section
    const uint8_t sbox[16] = {0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5,
                              0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76};
    size_t plant_off = 0;
    bool planted = false;
    for (auto it = pe.sections.rbegin(); it != pe.sections.rend(); ++it) {
        if (it->raw_size < 64) continue;
        if (static_cast<size_t>(it->raw_offset) + it->raw_size > bytes.size())
            continue;
        plant_off = it->raw_offset + it->raw_size - 32;
        std::memcpy(bytes.data() + plant_off, sbox, sizeof(sbox));
        planted = true;
        break;
    }
    REQUIRE(planted);

    auto reparsed = disasm::pe_parse(bytes.data(), bytes.size());
    auto hits = crypto_hunt(reparsed, bytes);
    bool found = false;
    for (const auto& h : hits) {
        if (h.name == "AES S-box (forward)" && h.offset == plant_off &&
            !h.in_overlay)
            found = true;
    }
    REQUIRE(found);
}

TEST_CASE(crypto_hunt_clean_image_no_false_sbox) {
    const auto bytes = slop_target_bytes();
    auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    auto hits = crypto_hunt(pe, bytes);
    // SlopTarget is a plain MSVC build, no AES tables expected. Base64 may
    // legitimately appear in CRT data; only assert on absence of crypto-core
    // constants here
    for (const auto& h : hits) {
        REQUIRE(h.name.find("AES") == std::string::npos);
        REQUIRE(h.name.find("SHA") == std::string::npos);
    }
}
