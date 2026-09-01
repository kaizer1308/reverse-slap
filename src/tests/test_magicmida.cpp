#include "harness.hpp"

#include "core/analysis/magicmida.hpp"

#include <windows.h>

#include <filesystem>
#include <fstream>
#include <cstring>
#include <string>
#include <vector>

namespace magicmida = slop::core::analysis::magicmida;
namespace fs = std::filesystem;

namespace {

std::vector<uint8_t> make_pe(bool x64) {
    std::vector<uint8_t> bytes(0x400, 0);
    auto put16 = [&bytes](size_t at, uint16_t value) {
        std::memcpy(bytes.data() + at, &value, sizeof(value));
    };
    auto put32 = [&bytes](size_t at, uint32_t value) {
        std::memcpy(bytes.data() + at, &value, sizeof(value));
    };
    bytes[0] = 'M';
    bytes[1] = 'Z';
    put32(0x3c, 0x80);
    bytes[0x80] = 'P';
    bytes[0x81] = 'E';
    put16(0x84, x64 ? 0x8664 : 0x014c);
    put16(0x86, 1);
    put16(0x94, x64 ? 0xf0 : 0xe0);
    const size_t optional = 0x98;
    put16(optional, x64 ? 0x20b : 0x10b);
    put32(optional + 16, 0x1000);
    put32(optional + 56, 0x2000);
    put32(optional + 60, 0x200);
    put32(optional + (x64 ? 108 : 92), 16);
    const size_t section = optional + (x64 ? 0xf0 : 0xe0);
    std::memcpy(bytes.data() + section, ".text", 5);
    put32(section + 8, 0x100);
    put32(section + 12, 0x1000);
    put32(section + 16, 0x200);
    put32(section + 20, 0x200);
    put32(section + 36, 0x60000020);
    bytes[0x200] = 0xc3;
    return bytes;
}

fs::path temp_file(const char* name, const std::vector<uint8_t>& bytes) {
    const fs::path path = fs::temp_directory_path() / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return path;
}

} // namespace

TEST_CASE(magicmida_inspects_x86_and_x64_pe) {
    const fs::path x86 = temp_file("slop_magicmida_x86.exe", make_pe(false));
    const fs::path x64 = temp_file("slop_magicmida_x64.exe", make_pe(true));
    const auto x86_info = magicmida::inspect_pe(x86.string());
    const auto x64_info = magicmida::inspect_pe(x64.string());
    REQUIRE(x86_info.ok);
    REQUIRE(x64_info.ok);
    REQUIRE(x86_info.arch == magicmida::arch_t::x86);
    REQUIRE(x64_info.arch == magicmida::arch_t::x64);
    REQUIRE_EQ(x64_info.entry_rva, 0x1000u);
    std::error_code ec;
    fs::remove(x86, ec);
    fs::remove(x64, ec);
}

TEST_CASE(magicmida_predicts_adjacent_output) {
    const std::string output = magicmida::generated_output_path("C:\\samples\\packed.exe");
    REQUIRE(output.ends_with("packedU.exe"));
}
