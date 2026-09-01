#include "harness.hpp"

#include "core/disasm/pe_parser.hpp"
#include "core/process/module_dump.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/session.hpp"

#include <windows.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

namespace {

constexpr uintptr_t kImageBase = 0x140000000ull;

std::vector<uint8_t> make_mapped_image() {
    std::vector<uint8_t> image(0x3000, 0);

    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(image.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    auto* nt = reinterpret_cast<IMAGE_NT_HEADERS64*>(image.data() + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 2;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.BaseOfCode = 0x1000;
    nt->OptionalHeader.ImageBase = kImageBase;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.SizeOfImage = 0x3000;
    nt->OptionalHeader.SizeOfHeaders = 0x200;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    auto* sections = IMAGE_FIRST_SECTION(nt);
    std::memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = 0x180;
    sections[0].VirtualAddress = 0x1000;
    sections[0].SizeOfRawData = 0x200;
    sections[0].PointerToRawData = 0x200;
    sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;

    std::memcpy(sections[1].Name, ".data", 5);
    sections[1].Misc.VirtualSize = 0x100;
    sections[1].VirtualAddress = 0x2000;
    sections[1].SizeOfRawData = 0x200;
    sections[1].PointerToRawData = 0x400;
    sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    std::fill_n(image.begin() + 0x1000, 0x200, uint8_t{0x90});
    image[0x1000] = 0xCC;
    std::fill_n(image.begin() + 0x2000, 0x200, uint8_t{0x42});
    image[0x2000] = 0x7A;
    return image;
}

slop::core::process::module_read_fn_t reader_for(
    const std::vector<uint8_t>& image, uintptr_t fail_begin = 0,
    uintptr_t fail_end = 0) {
    return [&image, fail_begin, fail_end](uintptr_t address, void* output,
                                          size_t size) {
        slop::core::runtime::io_result_t result;
        if (address < kImageBase || size > image.size() ||
            address - kImageBase > image.size() - size ||
            (fail_begin < fail_end && address < fail_end &&
             address + size > fail_begin)) {
            result.error = ERROR_PARTIAL_COPY;
            return result;
        }
        std::memcpy(output, image.data() + (address - kImageBase), size);
        result.ok = true;
        result.bytes = size;
        return result;
    };
}

} // namespace

TEST_CASE(module_dump_reconstructs_file_layout) {
    const auto mapped = make_mapped_image();
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);

    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE_EQ(result.section_count, size_t{2});
    REQUIRE_EQ(output.size(), size_t{0x600});
    REQUIRE_EQ(output[0x200], uint8_t{0xCC});
    REQUIRE_EQ(output[0x201], uint8_t{0x90});
    REQUIRE_EQ(output[0x400], uint8_t{0x7A});
    REQUIRE_EQ(output[0x401], uint8_t{0x42});

    const auto pe = slop::core::disasm::pe_parse(output.data(), output.size());
    REQUIRE(pe.ok);
    REQUIRE_EQ(pe.sections.size(), size_t{2});
    REQUIRE_EQ(pe.sections[0].raw_offset, uint32_t{0x200});
    REQUIRE_EQ(pe.sections[1].raw_offset, uint32_t{0x400});
}

TEST_CASE(module_dump_rejects_invalid_headers) {
    auto mapped = make_mapped_image();
    mapped[0] = 0;
    std::vector<uint8_t> output;
    const auto result = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), reader_for(mapped), output);
    REQUIRE_FALSE(result.ok);
    REQUIRE(output.empty());
    REQUIRE_FALSE(result.error.empty());
}

TEST_CASE(module_dump_strict_and_best_effort_reads) {
    const auto mapped = make_mapped_image();
    const auto failing_reader = reader_for(mapped, kImageBase + 0x2000,
                                           kImageBase + 0x2200);
    std::vector<uint8_t> output;

    auto strict = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output);
    REQUIRE_FALSE(strict.ok);
    REQUIRE(output.empty());

    slop::core::process::module_dump_options_t options;
    options.strict_reads = false;
    auto best_effort = slop::core::process::reconstruct_mapped_pe(
        kImageBase, static_cast<uint32_t>(mapped.size()), failing_reader, output,
        options);
    REQUIRE(best_effort.ok);
    REQUIRE_FALSE(best_effort.complete);
    REQUIRE_EQ(output[0x400], uint8_t{0});
    REQUIRE_EQ(output[0x5FF], uint8_t{0});
}

TEST_CASE(module_dump_captures_live_test_process) {
    using namespace slop::core;
    if (runtime::active_kind() != runtime::backend_kind_t::user_mode) {
        std::printf("  [skip] live self-dump requires user-mode backend\n");
        return;
    }

    runtime::session_t session;
    REQUIRE(session.open(GetCurrentProcessId()));
    auto modules = runtime::active().enum_modules(session.handle());
    REQUIRE(modules.ok);
    REQUIRE_FALSE(modules.items.empty());
    if (!modules.ok || modules.items.empty()) return;

    const auto module = modules.items.front();
    const auto path = std::filesystem::temp_directory_path() /
                      L"reverse_slop_live_module_dump.exe";
    const auto result = process::dump_module_pe(session, module, path.string());
    REQUIRE(result.ok);
    REQUIRE(result.complete);
    REQUIRE(result.bytes_written >= 1024);

    std::ifstream file(path, std::ios::binary);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                     std::istreambuf_iterator<char>{}};
    REQUIRE_EQ(bytes.size(), result.bytes_written);
    const auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    REQUIRE(pe.ok);
    REQUIRE_FALSE(pe.sections.empty());

    std::error_code ec;
    std::filesystem::remove(path, ec);
    session.close();
}
