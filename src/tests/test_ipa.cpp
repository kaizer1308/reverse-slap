// src/tests/test_ipa.cpp
// .ipa support: ZIP container, Info.plist executable resolution, Mach-O
// (thin/FAT) loading into hyperion, the format-neutral image open, and the
// shared binary session driving an arm64 executable end to end. Every input
// is built in memory by macho_fixture.hpp

#include "harness.hpp"
#include "macho_fixture.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/disasm/hyperion_session.hpp"
#include "core/disasm/image_open.hpp"
#include "core/disasm/ipa.hpp"
#include "core/loader/macho_loader.h"
#include "core/util/zip_reader.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace mf     = slop_test::macho;
namespace zip    = slop::core::util::zip;
namespace ipa    = slop::core::disasm::ipa;
namespace disasm = slop::core::disasm;
namespace ds     = slop::core::disasm::binary_state;
namespace hs     = slop::core::disasm::hyperion_session;

namespace {

const mf::exe_layout_t& L = mf::exe_layout;

// the main app's Info.plist values shared by the bundle tests
const std::map<std::string, std::string>& shop_plist_values() {
    static const std::map<std::string, std::string> kv = {
        {"CFBundleExecutable",         "ShopCore"},
        {"CFBundleIdentifier",         "com.example.shop"},
        {"CFBundleShortVersionString", "2.4.1"},
        {"CFBundleVersion",            "241"},
        {"MinimumOSVersion",           "15.0"},
    };
    return kv;
}

// Payload/Shop.app/ with a plugin bundle whose own Info.plist and binary come
// first in archive order, a decoy named after the .app stem, then the real
// Info.plist and executable
std::vector<mf::zip_entry_t> shop_entries(std::vector<uint8_t> info_plist,
                                          std::vector<uint8_t> main_binary,
                                          bool with_main_plist = true) {
    std::vector<mf::zip_entry_t> e = {
        {"Payload/", {}, std::nullopt},
        {"Payload/Shop.app/", {}, std::nullopt},
        {"Payload/Shop.app/PlugIns/", {}, std::nullopt},
        {"Payload/Shop.app/PlugIns/W.appex/", {}, std::nullopt},
        {"Payload/Shop.app/PlugIns/W.appex/Info.plist",
         mf::build_bplist({{"CFBundleExecutable", "W"},
                           {"CFBundleIdentifier", "com.example.shop.widget"}}),
         std::nullopt},
        {"Payload/Shop.app/PlugIns/W.appex/W", mf::bytes_of("plugin executable"), std::nullopt},
        {"Payload/Shop.app/Shop", mf::bytes_of("decoy named after the bundle"), std::nullopt},
    };
    if (with_main_plist)
        e.push_back({"Payload/Shop.app/Info.plist", std::move(info_plist), std::nullopt});
    e.push_back({"Payload/Shop.app/ShopCore", std::move(main_binary), std::nullopt});
    e.push_back({"iTunesMetadata.plist", mf::bytes_of("<plist/>"), std::nullopt});
    return e;
}

std::vector<uint8_t> shop_ipa(const std::vector<uint8_t>& main_binary, bool deflate = true) {
    return mf::build_zip(shop_entries(mf::build_bplist(shop_plist_values()), main_binary),
                         deflate);
}

std::vector<uint8_t> lcg_bytes(size_t n, uint32_t seed) {
    std::vector<uint8_t> out(n);
    for (auto& b : out) {
        seed = seed * 1664525u + 1013904223u;
        b = uint8_t(seed >> 24);
    }
    return out;
}

const hype::Segment* find_seg(const hype::PEImage& img, std::string_view name) {
    for (const auto& s : img.segments)
        if (s.name == name) return &s;
    return nullptr;
}

const hype::Import* find_import(const hype::PEImage& img, std::string_view name) {
    for (const auto& i : img.imports)
        if (i.name == name) return &i;
    return nullptr;
}

const hype::Symbol* find_symbol(const hype::PEImage& img, std::string_view name) {
    for (const auto& s : img.symbols)
        if (s.name == name) return &s;
    return nullptr;
}

std::string lower(std::string s) {
    for (auto& c : s) c = char(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool wait_hype_ready(int timeout_ms = 30000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (std::chrono::steady_clock::now() < deadline) {
        if (ds::hype_ready()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return ds::hype_ready();
}

// one arm64 instruction through the session's Capstone path
bool decode_a64(uint64_t va, uint32_t word, disasm::insn_t& out) {
    uint8_t buf[4];
    for (int i = 0; i < 4; ++i) buf[i] = uint8_t(word >> (8 * i));
    return hs::session_t::decode(va, buf, sizeof(buf), out, hype::Arch::ARM64);
}

} // namespace

TEST_CASE(ipa_zip_roundtrip_and_crc) {
    // compressible but not trivially so: forces real (dynamic) deflate blocks
    std::vector<uint8_t> big;
    const char* pattern = "lorem ipsum dolor sit amet ";
    const size_t plen = std::strlen(pattern);
    for (size_t i = 0; i < 8192; ++i)
        big.push_back(uint8_t(pattern[i % plen] ^ uint8_t(i / 512)));

    const std::vector<mf::zip_entry_t> entries = {
        {"dir/", {}, std::nullopt},
        {"dir/stored.txt", mf::bytes_of("stored payload, kept verbatim\n"), false},
        {"dir/deflated.bin", big, true},
        {"empty.bin", {}, true},
    };
    mf::zip_layout_t lay;
    const auto z = mf::build_zip(entries, true, &lay);
    REQUIRE(zip::has_zip_magic(z.data(), z.size()));
    REQUIRE_FALSE(zip::has_zip_magic(big.data(), big.size()));

    zip::archive_t ar;
    std::string err;
    REQUIRE(ar.open(z.data(), z.size(), &err));
    REQUIRE_EQ(ar.entries().size(), entries.size());

    for (size_t i = 0; i < entries.size(); ++i) {
        const auto* e = ar.find(entries[i].name);
        REQUIRE(e != nullptr);
        REQUIRE_EQ(e->method, lay.method[i]);
        REQUIRE_EQ(e->uncompressed_size, entries[i].data.size());
        REQUIRE_EQ(e->compressed_size, lay.data_size[i]);
        std::vector<uint8_t> out{0xEE};   // extract must replace, not append
        std::string xerr;
        CHECK(ar.extract(*e, out, &xerr));
        CHECK(out == entries[i].data);
    }
    const auto* deflated = ar.find("dir/deflated.bin");
    REQUIRE(deflated != nullptr);
    REQUIRE_EQ(deflated->method, 8);
    REQUIRE_LT(deflated->compressed_size, deflated->uncompressed_size);
    CHECK(ar.find("dir/")->is_directory());
    CHECK(!ar.find("dir/stored.txt")->is_directory());

    // exact-match lookups only
    CHECK(ar.find("missing") == nullptr);
    CHECK(ar.find("dir") == nullptr);
    CHECK(ar.find("DIR/STORED.TXT") == nullptr);
    CHECK(ar.find("dir/stored.tx") == nullptr);
    CHECK(ar.find("stored.txt") == nullptr);

    // size cap rejects instead of truncating
    {
        std::vector<uint8_t> out;
        std::string xerr;
        REQUIRE_FALSE(ar.extract(*deflated, out, &xerr, big.size() - 1));
        CHECK(!xerr.empty());
    }

    // a flipped payload byte fails the CRC (stored) or inflate/CRC (deflate)
    for (size_t idx : {size_t(1), size_t(2)}) {
        auto bad = z;
        mf::corrupt_entry_payload(bad, lay, idx);
        zip::archive_t a2;
        std::string oerr;
        REQUIRE(a2.open(bad.data(), bad.size(), &oerr));
        const auto* e = a2.find(entries[idx].name);
        REQUIRE(e != nullptr);
        std::vector<uint8_t> out;
        std::string xerr;
        REQUIRE_FALSE(a2.extract(*e, out, &xerr));
        CHECK(!xerr.empty());
    }

    // EOCD cut short: open refuses rather than reading past the buffer
    {
        auto cut = z;
        cut.resize(cut.size() - 10);
        zip::archive_t a3;
        std::string oerr;
        REQUIRE_FALSE(a3.open(cut.data(), cut.size(), &oerr));
        CHECK(!oerr.empty());
    }
}

TEST_CASE(ipa_resolves_executable_from_binary_plist) {
    const auto core = mf::build_arm64_exe();
    for (bool deflate : {true, false}) {
        const auto z = shop_ipa(core, deflate);
        REQUIRE(ipa::looks_like_ipa(z.data(), z.size()));

        const auto r = ipa::extract_main_binary(z.data(), z.size());
        REQUIRE(r.ok);
        CHECK(r.error.empty());
        REQUIRE_STR_EQ(r.bundle.app_dir, "Payload/Shop.app/");
        REQUIRE_STR_EQ(r.bundle.executable, "ShopCore");
        REQUIRE_STR_EQ(r.bundle.executable_path, "Payload/Shop.app/ShopCore");
        REQUIRE_STR_EQ(r.bundle.bundle_id, "com.example.shop");
        REQUIRE_STR_EQ(r.bundle.version, "2.4.1");
        REQUIRE_STR_EQ(r.bundle.build, "241");
        REQUIRE_STR_EQ(r.bundle.min_os, "15.0");
        CHECK(r.binary == core);
    }
}

TEST_CASE(ipa_resolves_executable_from_xml_plist_and_stem_fallback) {
    const auto core = mf::build_arm64_exe();

    // XML plist, with non-string values ahead of the keys we read
    {
        const std::string extra =
            "\t<key>UIRequiredDeviceCapabilities</key>\n"
            "\t<array>\n\t\t<string>arm64</string>\n\t</array>\n"
            "\t<key>LSRequiresIPhoneOS</key>\n\t<true/>\n";
        const auto plist = mf::build_xml_plist(shop_plist_values(), extra);
        const auto z = mf::build_zip(shop_entries(plist, core), true);
        const auto r = ipa::extract_main_binary(z.data(), z.size());
        REQUIRE(r.ok);
        REQUIRE_STR_EQ(r.bundle.executable, "ShopCore");
        REQUIRE_STR_EQ(r.bundle.executable_path, "Payload/Shop.app/ShopCore");
        REQUIRE_STR_EQ(r.bundle.bundle_id, "com.example.shop");
        REQUIRE_STR_EQ(r.bundle.version, "2.4.1");
        CHECK(r.binary == core);
    }

    // no main Info.plist: the .app stem names the executable, and the
    // plugin's Info.plist must not be mistaken for the app's
    {
        std::vector<mf::zip_entry_t> e = {
            {"Payload/Shop.app/PlugIns/W.appex/Info.plist",
             mf::build_bplist({{"CFBundleExecutable", "W"}}), std::nullopt},
            {"Payload/Shop.app/PlugIns/W.appex/W", mf::bytes_of("plugin executable"), std::nullopt},
            {"Payload/Shop.app/Shop", core, std::nullopt},
        };
        const auto z = mf::build_zip(e, true);
        REQUIRE(ipa::looks_like_ipa(z.data(), z.size()));
        const auto r = ipa::extract_main_binary(z.data(), z.size());
        REQUIRE(r.ok);
        REQUIRE_STR_EQ(r.bundle.app_dir, "Payload/Shop.app/");
        REQUIRE_STR_EQ(r.bundle.executable, "Shop");
        REQUIRE_STR_EQ(r.bundle.executable_path, "Payload/Shop.app/Shop");
        CHECK(r.bundle.bundle_id.empty());
        CHECK(r.binary == core);
    }
}

TEST_CASE(ipa_macho_fat_selects_arm64) {
    const auto exe = mf::build_arm64_exe();
    std::vector<size_t> offs;
    const auto fat = mf::build_fat({
        {mf::kCpuX86_64, mf::kSubX86_64All, mf::build_x86_64_stub()},
        {mf::kCpuArm64,  mf::kSubArm64All,  exe},
    }, &offs);
    REQUIRE_EQ(offs.size(), 2u);

    REQUIRE(hype::MachOLoader::is_macho(fat.data(), fat.size()));
    REQUIRE(hype::MachOLoader::is_macho(exe.data(), exe.size()));
    const auto junk = lcg_bytes(64, 7);
    REQUIRE_FALSE(hype::MachOLoader::is_macho(junk.data(), junk.size()));

    const auto slice = hype::MachOLoader::select_slice(fat.data(), fat.size());
    REQUIRE(slice.has_value());
    REQUIRE_EQ(slice->offset, offs[1]);
    REQUIRE_EQ(slice->size, exe.size());

    const auto thin = hype::MachOLoader::select_slice(exe.data(), exe.size());
    REQUIRE(thin.has_value());
    REQUIRE_EQ(thin->offset, 0u);
    REQUIRE_EQ(thin->size, exe.size());

    REQUIRE_FALSE(hype::MachOLoader::select_slice(junk.data(), junk.size()).has_value());

    hype::MachOLoader ld;
    const auto img = ld.load_buffer(fat.data(), fat.size());
    REQUIRE(img.has_value());
    REQUIRE(img->arch == hype::Arch::ARM64);
    REQUIRE_EQ(img->base, L.base);
    REQUIRE_EQ(img->entry, L.entry_va);
    // segment views point into the arm64 slice, not the FAT container start
    const auto* cs = find_seg(*img, "__TEXT.__cstring");
    REQUIRE(cs != nullptr);
    REQUIRE_GE(cs->data.size(), std::strlen(L.cstring));
    CHECK(std::memcmp(cs->data.data(), L.cstring, std::strlen(L.cstring)) == 0);
}

TEST_CASE(ipa_macho_loader_layout) {
    const auto exe = mf::build_arm64_exe();
    hype::MachOLoader ld;
    const auto img = ld.load_buffer(exe.data(), exe.size());
    REQUIRE(img.has_value());
    REQUIRE(img->arch == hype::Arch::ARM64);
    REQUIRE_EQ(img->base, L.base);
    REQUIRE_EQ(img->entry, L.entry_va);
    REQUIRE_FALSE(img->encrypted);

    const auto* text = find_seg(*img, "__TEXT.__text");
    REQUIRE(text != nullptr);
    REQUIRE_EQ(text->va, L.text_va);
    REQUIRE_EQ(text->size, L.text_size);
    REQUIRE_EQ(text->file_off, L.text_off);
    CHECK(text->executable());
    CHECK(text->readable());
    CHECK(!text->writable());

    const auto* stubs = find_seg(*img, "__TEXT.__stubs");
    REQUIRE(stubs != nullptr);
    CHECK(stubs->executable());

    const auto* cs = find_seg(*img, "__TEXT.__cstring");
    REQUIRE(cs != nullptr);
    REQUIRE_EQ(cs->va, L.cstring_va);
    CHECK(!cs->executable());
    CHECK(cs->readable());

    const auto* got = find_seg(*img, "__DATA_CONST.__got");
    REQUIRE(got != nullptr);
    REQUIRE_EQ(got->va, L.got0_va);
    CHECK(got->writable());
    CHECK(!got->executable());

    for (const auto& s : img->segments) {
        CHECK(s.name.rfind("__PAGEZERO", 0) != 0);
        CHECK(s.name.rfind("__LINKEDIT", 0) != 0);
    }

    // one import per pointer slot, bound through the two-level namespace
    REQUIRE_EQ(img->imports.size(), 2u);
    const auto* objc = find_import(*img, "objc_msgSend");
    REQUIRE(objc != nullptr);
    REQUIRE_STR_EQ(objc->dll, "libobjc.A.dylib");
    REQUIRE_EQ(objc->iat_addr, L.got0_va);
    const auto* puts_imp = find_import(*img, "puts");
    REQUIRE(puts_imp != nullptr);
    REQUIRE_STR_EQ(puts_imp->dll, "libSystem.B.dylib");
    REQUIRE_EQ(puts_imp->iat_addr, L.got1_va);

    // stub named after the import it binds, local symbol kept, external not
    const auto* stub = find_symbol(*img, "puts");
    REQUIRE(stub != nullptr);
    REQUIRE_EQ(stub->addr, L.stub0_va);
    const auto* helper = find_symbol(*img, "helper");
    REQUIRE(helper != nullptr);
    REQUIRE_EQ(helper->addr, L.helper_va);
    CHECK(find_symbol(*img, "main") == nullptr);

    bool main_export = false;
    for (const auto& e : img->exports)
        if (e.name == "main" && e.addr == L.main_va) main_export = true;
    CHECK(main_export);

    // function starts, the last one clipped to the end of __text
    REQUIRE_EQ(img->runtime_funcs.size(), 2u);
    REQUIRE_EQ(img->runtime_funcs[0].start, L.main_va);
    REQUIRE_EQ(img->runtime_funcs[0].end,   L.helper_va);
    REQUIRE_EQ(img->runtime_funcs[1].start, L.helper_va);
    REQUIRE_EQ(img->runtime_funcs[1].end,   L.text_end);

    // LC_ENCRYPTION_INFO_64: present-but-zero is a decrypted dump
    {
        const auto plain = mf::build_arm64_exe({.cryptid = 0u});
        hype::MachOLoader l2;
        const auto i2 = l2.load_buffer(plain.data(), plain.size());
        REQUIRE(i2.has_value());
        CHECK(!i2->encrypted);
        REQUIRE_EQ(i2->entry, L.entry_va);
    }
    {
        const auto enc = mf::build_arm64_exe({.cryptid = 1u});
        hype::MachOLoader l3;
        const auto i3 = l3.load_buffer(enc.data(), enc.size());
        REQUIRE(i3.has_value());
        CHECK(i3->encrypted);
    }
}

TEST_CASE(ipa_open_image_synthesizes_section_map) {
    const auto exe = mf::build_arm64_exe();
    const auto fat = mf::build_fat({
        {mf::kCpuX86_64, mf::kSubX86_64All, mf::build_x86_64_stub()},
        {mf::kCpuArm64,  mf::kSubArm64All,  exe},
    });
    const auto z = shop_ipa(fat);

    const auto img = disasm::open_image(z);
    REQUIRE(img.ok);
    CHECK(img.error.empty());
    REQUIRE(img.format == disasm::image_format_t::macho);
    REQUIRE(img.arch == disasm::image_arch_t::arm64);
    REQUIRE_FALSE(img.is_x86());
    CHECK(!img.encrypted);
    REQUIRE(img.bundle.has_value());
    REQUIRE_STR_EQ(img.bundle->executable, "ShopCore");
    REQUIRE_STR_EQ(img.bundle->bundle_id, "com.example.shop");

    // the analyzed bytes are the thin arm64 slice, not the FAT wrapper
    REQUIRE_EQ(img.file.size(), exe.size());
    CHECK(img.file == exe);

    REQUIRE(img.pe.ok);
    REQUIRE(img.pe.pe32plus);
    REQUIRE_EQ(img.pe.machine, 0xAA64);
    REQUIRE_EQ(img.pe.image_base, L.base);
    REQUIRE_EQ(img.pe.entry_rva, uint32_t(L.entry_va - L.base));

    const auto off = img.pe.va_to_offset(L.cstring_va);
    REQUIRE(off.has_value());
    REQUIRE_EQ(*off, L.cstring_off);
    REQUIRE_LE(*off + std::strlen(L.cstring), img.file.size());
    CHECK(std::memcmp(img.file.data() + *off, L.cstring, std::strlen(L.cstring)) == 0);

    const disasm::pe_section_t* text = nullptr;
    const disasm::pe_section_t* cstr = nullptr;
    for (const auto& s : img.pe.sections) {
        if (std::strcmp(s.name, "__TEXT.__text") == 0)    text = &s;
        if (std::strcmp(s.name, "__TEXT.__cstring") == 0) cstr = &s;
    }
    REQUIRE(text != nullptr);
    REQUIRE(cstr != nullptr);
    CHECK(text->is_executable());
    CHECK(!cstr->is_executable());
    REQUIRE_EQ(text->rva, uint32_t(L.text_va - L.base));

    bool objc = false;
    for (const auto& d : img.pe.imports)
        if (d.dll == "libobjc.A.dylib")
            for (const auto& f : d.functions)
                if (f.name == "objc_msgSend" && f.iat_rva == uint32_t(L.got0_va - L.base))
                    objc = true;
    CHECK(objc);

    REQUIRE_EQ(img.pe.runtime_funcs.size(), 2u);
    REQUIRE_EQ(img.pe.runtime_funcs[0].begin_rva, uint32_t(L.main_va - L.base));
    REQUIRE_EQ(img.pe.runtime_funcs[1].begin_rva, uint32_t(L.helper_va - L.base));

    // a bare thin Mach-O opens the same way, without a bundle
    const auto bare = disasm::open_image(exe);
    REQUIRE(bare.ok);
    REQUIRE(bare.arch == disasm::image_arch_t::arm64);
    CHECK(!bare.bundle.has_value());
    CHECK(bare.file == exe);
}

TEST_CASE(ipa_open_image_rejects_garbage) {
    {
        const auto r = disasm::open_image(lcg_bytes(4096, 1234));
        CHECK(!r.ok);
        CHECK(!r.error.empty());
    }
    {
        const auto r = disasm::open_image({});
        CHECK(!r.ok);
        CHECK(!r.error.empty());
    }
    // a valid ZIP that is not an iOS app
    {
        const auto z = mf::build_zip({{"readme.txt", mf::bytes_of("just a zip"), std::nullopt},
                                      {"lib/thing.bin", lcg_bytes(256, 9), std::nullopt}}, true);
        CHECK(!ipa::looks_like_ipa(z.data(), z.size()));
        const auto r = disasm::open_image(z);
        CHECK(!r.ok);
        CHECK(!r.error.empty());
    }
    // an app bundle whose executable is not Mach-O
    {
        const auto z = shop_ipa(mf::bytes_of("#!/bin/sh\necho not a mach-o binary\n"));
        REQUIRE(ipa::looks_like_ipa(z.data(), z.size()));
        const auto r = disasm::open_image(z);
        CHECK(!r.ok);
        CHECK(!r.error.empty());
    }
    // the executable named by Info.plist is missing from the archive
    {
        auto e = shop_entries(mf::build_bplist(shop_plist_values()), {});
        e.erase(std::remove_if(e.begin(), e.end(), [](const mf::zip_entry_t& x) {
            return x.name == "Payload/Shop.app/ShopCore";
        }), e.end());
        const auto z = mf::build_zip(e, true);
        const auto r = ipa::extract_main_binary(z.data(), z.size());
        CHECK(!r.ok);
        CHECK(!r.error.empty());
    }
}

TEST_CASE(ipa_binary_state_loads_ipa_end_to_end) {
    // stored entries: the mostly-zero executable deflates to a few hundred
    // bytes, below load_file's minimum image size
    const auto z = shop_ipa(mf::build_arm64_exe(), false);

    const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
    const std::string fname = "slop_ipa_test_" + std::to_string(stamp) + ".ipa";
    const auto path = std::filesystem::temp_directory_path() / fname;
    {
        std::ofstream f(path, std::ios::binary);
        f.write(reinterpret_cast<const char*>(z.data()), std::streamsize(z.size()));
        REQUIRE(f.good());
    }
    // unload and delete even when a REQUIRE throws
    struct cleanup_t {
        std::filesystem::path p;
        ~cleanup_t() {
            ds::unload();
            std::error_code ec;
            std::filesystem::remove(p, ec);
        }
    } cleanup{path};

    REQUIRE(ds::load_file(path.string()));

    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        REQUIRE(bin.ready);
        REQUIRE_FALSE(bin.is_x86());
        REQUIRE(bin.format == disasm::image_format_t::macho);
        REQUIRE(bin.arch == disasm::image_arch_t::arm64);
        CHECK(!bin.encrypted);
        REQUIRE(bin.bundle.has_value());
        REQUIRE_STR_EQ(bin.bundle->executable, "ShopCore");
        REQUIRE_STR_EQ(bin.name, fname + "!ShopCore");
        REQUIRE_EQ(bin.base, L.base);

        CHECK(bin.fns.containing(L.main_va) == std::optional<uint64_t>(L.main_va));
        CHECK(bin.fns.containing(L.bl_helper_va) == std::optional<uint64_t>(L.main_va));
        CHECK(bin.fns.containing(L.helper_va) == std::optional<uint64_t>(L.helper_va));

        bool hello = false;
        for (const auto& s : bin.strings)
            if (s.text == L.cstring && s.va == L.cstring_va) hello = true;
        CHECK(hello);

        const auto main_off = bin.offset_of(L.main_va);
        REQUIRE(main_off.has_value());
        REQUIRE_EQ(*main_off, L.text_off);
        const uint8_t* p   = bin.file.data() + *main_off;
        const size_t   len = bin.file.size() - *main_off;

        const auto first = ds::decode_insn(bin, L.main_va, p, len);
        REQUIRE(first.has_value());
        REQUIRE_EQ(first->length, 4);
        CHECK(lower(first->text).rfind("stp", 0) == 0);

        const size_t bl_rel = size_t(L.bl_stub_va - L.main_va);
        const auto bl = ds::decode_insn(bin, L.bl_stub_va, p + bl_rel, len - bl_rel);
        REQUIRE(bl.has_value());
        CHECK(bl->flow == disasm::flow_t::call);
        REQUIRE(bl->has_rel_target);
        REQUIRE_EQ(bl->rel_target, L.stub0_va);
    }

    if (!wait_hype_ready()) {
        const auto st = ds::hype_status();
        std::printf("  hyperion not ready: error='%s' running=%d progress=%.2f\n",
                    st.engine_error.c_str(), int(st.running), double(st.progress));
        REQUIRE(false);
    }

    {
        ds::binary_lock_t lk;
        auto& bin = ds::get();
        REQUIRE(bin.hype != nullptr);
        REQUIRE(bin.hype->arch() == hype::Arch::ARM64);

        const auto& db = bin.hype->db();
        const auto stub_name = db.names.find(L.stub0_va);
        REQUIRE(stub_name != db.names.end());
        CHECK(stub_name->second.find("puts") != std::string::npos);
        CHECK(db.funcs.count(L.main_va) == 1);
        CHECK(db.funcs.count(L.helper_va) == 1);

        std::vector<hype::PseudoLine> lines;
        std::string derr;
        REQUIRE(bin.hype->decompile(L.main_va, lines, derr));
        CHECK(!lines.empty());
    }
}

TEST_CASE(ipa_session_decode_arm64) {
    const uint64_t va = 0x100002000;
    disasm::insn_t in;

    REQUIRE(decode_a64(va, mf::a64::kRet, in));
    REQUIRE_EQ(in.length, 4);
    CHECK(in.flow == disasm::flow_t::ret);
    CHECK(!in.has_rel_target);

    // b.ne forward
    REQUIRE(decode_a64(va, mf::a64::b_cond(mf::a64::kCondNe, va, va + 0x40), in));
    CHECK(in.flow == disasm::flow_t::jcc);
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, va + 0x40);

    // cbz backward: the register is not the target
    REQUIRE(decode_a64(va, mf::a64::cbz_x(3, va, va - 0x20), in));
    CHECK(in.flow == disasm::flow_t::jcc);
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, va - 0x20);

    // tbz x5, #35: the bit number is an immediate too, the target is the last
    REQUIRE(decode_a64(va, mf::a64::tbz(5, 35, va, va + 0x100), in));
    CHECK(in.flow == disasm::flow_t::jcc);
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, va + 0x100);

    REQUIRE(decode_a64(va, mf::a64::bl(va, va + 0x1000), in));
    CHECK(in.flow == disasm::flow_t::call);
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, va + 0x1000);

    REQUIRE(decode_a64(va, mf::a64::b(va, va - 0x400), in));
    CHECK(in.flow == disasm::flow_t::jmp);
    REQUIRE(in.has_rel_target);
    REQUIRE_EQ(in.rel_target, va - 0x400);

    // indirect branch through a register has no direct target
    REQUIRE(decode_a64(va, mf::a64::kBrX16, in));
    CHECK(in.flow == disasm::flow_t::jmp);
    CHECK(!in.has_rel_target);

    // plain data op: no flow, and the immediate is not a branch target
    REQUIRE(decode_a64(va, mf::a64::movz_w(0, 42), in));
    CHECK(in.flow == disasm::flow_t::none);
    CHECK(!in.has_rel_target);
}
