// src/core/runtime/kernel_symbols.cpp

#include "core/runtime/kernel_symbols.hpp"

#include "core/network/web_fetch.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"

#include <core/runtime/voyager_comm.h>

#include <windows.h>
#include <psapi.h>
#include <dbghelp.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <mutex>

#pragma comment(lib, "dbghelp.lib")

namespace slop::core::runtime {

namespace {

struct pdb_ref_t {
    std::string pdb_name;     // ntkrnlmp.pdb
    std::string guid_age;     // concatenated GUID+age hex, symbol-server key
    uint64_t ntos_base = 0;
};

pdb_ref_t find_rsds(std::string* error) {
    pdb_ref_t out;
    auto* k = dynamic_cast<backend_kernel_t*>(&active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) {
        if (error) *error = "kernel driver not active";
        return out;
    }

    LPVOID drivers[64] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed) || !needed ||
        drivers[0] == nullptr) {
        if (error) *error = "cannot locate ntoskrnl base";
        return out;
    }
    out.ntos_base = reinterpret_cast<uint64_t>(drivers[0]);

    // solve the dtb lazily instead of depending on another tool
    if (dev->get_kernel_dtb() == 0) dev->solve_kernel_dtb();

    // read a generous 4mb, the debug directory lives in the header region
    constexpr size_t kHead = 4ull << 20;
    std::vector<uint8_t> img(kHead);
    const size_t got = dev->read_kernel_raw(out.ntos_base, img.data(),
                                            img.size());
    if (got < 0x1000 || img[0] != 'M' || img[1] != 'Z') {
        if (error) *error = "kernel header read failed";
        out.ntos_base = 0;   // don't leak a half-verified base
        return out;
    }

    const uint32_t e_lfanew =
        *reinterpret_cast<const uint32_t*>(img.data() + 0x3C);
    // PE32+ optional header: data dir offset = e_lfanew + 4 + 20 + 112
    const uint32_t dd_rva_off =
        e_lfanew + 4 + 20 + 112 + 6 * 8;   // 7th directory = Debug
    uint32_t dbg_rva = 0, dbg_size = 0;
    std::memcpy(&dbg_rva, img.data() + dd_rva_off, 4);
    std::memcpy(&dbg_size, img.data() + dd_rva_off + 4, 4);
    if (!dbg_rva || !dbg_size) {
        if (error) *error = "no debug directory in kernel image";
        return out;
    }
    // rva is the va offset directly for an in memory image
    if (dbg_rva + dbg_size > got) {
        if (error) *error = "debug directory outside readable window";
        return out;
    }

    struct image_debug_directory_t {
        uint32_t characteristics;
        uint32_t timestamp;
        uint16_t major, minor;
        uint32_t type;
        uint32_t size_of_data;
        uint32_t address_of_raw_data;
        uint32_t pointer_to_raw_data;
    };
    const auto* dirs =
        reinterpret_cast<const image_debug_directory_t*>(img.data() +
                                                         dbg_rva);
    const size_t entries = dbg_size / sizeof(image_debug_directory_t);
    for (size_t i = 0; i < entries; ++i) {
        if (dirs[i].type != 2 /*IMAGE_DEBUG_TYPE_CODEVIEW*/) continue;
        // In-memory images store RVA in address_of_raw_data when not
        // stripped; fall back to pointer_to_raw_data (mapped equivalence)
        const uint32_t off = dirs[i].address_of_raw_data
                                 ? dirs[i].address_of_raw_data
                                 : dirs[i].pointer_to_raw_data;
        if (off == 0 || off + 24 > got) continue;
        const char* sig = reinterpret_cast<const char*>(img.data() + off);
        if (std::memcmp(sig, "RSDS", 4) != 0) continue;

        // CV_INFO_PDB70: RSDS(4) GUID(16) Age(4) Name(...)
        const uint8_t* guid = img.data() + off + 4;
        uint32_t age = 0;
        std::memcpy(&age, img.data() + off + 20, 4);
        const char* name = reinterpret_cast<const char*>(img.data() + off + 24);

        // guid bytes go in swapped order for the symbol server key
        char key[64] = {};
        std::snprintf(key, sizeof(key),
                      "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%X",
                      guid[3], guid[2], guid[1], guid[0],
                      guid[5], guid[4], guid[7], guid[6],
                      guid[8], guid[9], guid[10], guid[11],
                      guid[12], guid[13], guid[14], guid[15], age);
        out.guid_age = key;
        out.pdb_name = name;
        return out;
    }
    if (error) *error = "no RSDS CodeView entry found";
    return out;
}

std::string cache_dir() {
    char base[MAX_PATH]{};
    const DWORD n = GetEnvironmentVariableA("LOCALAPPDATA", base, MAX_PATH);
    std::string dir = n ? std::string(base) + "\\reverse-slop\\symsrv"
                        : ".\\symsrv";
    CreateDirectoryA(dir.c_str(), nullptr);
    return dir;
}

std::mutex g_mu;
kernel_symbols::load_state_t g_state;

} // namespace

kernel_symbols::load_state_t kernel_symbols::ensure_loaded() {
    std::lock_guard lk(g_mu);
    if (g_state.loaded) return g_state;

    load_state_t st;
    std::string err;
    const pdb_ref_t ref = find_rsds(&err);
    if (ref.pdb_name.empty()) {
        st.error = err.empty() ? "no PDB reference" : err;
        // leave the base at 0, a half solved base is worse than none
        g_state = st;
        return st;
    }
    st.module_name = ref.pdb_name;
    st.guid_text   = ref.guid_age;
    st.ntos_base   = ref.ntos_base;

    // Download from the Microsoft symbol server into cache
    const std::string url =
        "https://msdl.microsoft.com/download/symbols/" + ref.pdb_name +
        "/" + ref.guid_age + "/" + ref.pdb_name;
    const std::string local =
        cache_dir() + "\\" + ref.guid_age + "\\" + ref.pdb_name;
    CreateDirectoryA((cache_dir() + "\\" + ref.guid_age).c_str(), nullptr);

    if (!std::filesystem::exists(local)) {
        std::string dl_err;
        auto resp = util::http_get(url, 30000, &dl_err);
        if (!resp || resp->status != 200) {
            st.error = "symbol download failed (" +
                       (resp ? std::to_string(resp->status) : dl_err) + ")";
            g_state = st;
            return st;
        }
        FILE* f = nullptr;
        fopen_s(&f, local.c_str(), "wb");
        if (!f) {
            st.error = "cannot write cached PDB";
            g_state = st;
            return st;
        }
        fwrite(resp->body.data(), 1, resp->body.size(), f);
        fclose(f);
    }
    st.pdb_path = local;

    // dbghelp: load module at the live base with our downloaded PDB
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS |
                  SYMOPT_EXACT_SYMBOLS);
    static bool syms_init = false;
    if (!syms_init) {
        SymInitializeW(GetCurrentProcess(), nullptr, FALSE);
        syms_init = true;
    }
    const uint64_t base = SymLoadModuleEx(
        GetCurrentProcess(), nullptr, local.c_str(), nullptr,
        ref.ntos_base, 0, nullptr, 0);
    if (!base) {
        st.error = "SymLoadModuleEx failed";
        g_state = st;
        return st;
    }
    st.loaded = true;
    g_state = st;
    return st;
}

std::optional<kernel_sym_t> kernel_symbols::lookup(const std::string& name) {
    auto st = ensure_loaded();
    if (!st.loaded) return std::nullopt;
    std::string bare = name;
    const size_t bang = bare.rfind('!');
    if (bang != std::string::npos) bare = bare.substr(bang + 1);

    char buffer[sizeof(SYMBOL_INFOW) + 256 * sizeof(wchar_t)] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFOW*>(buffer);
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = 256;
    std::wstring wide(bare.begin(), bare.end());
    if (!SymFromNameW(GetCurrentProcess(), wide.c_str(), sym))
        return std::nullopt;
    kernel_sym_t s;
    s.address = sym->Address;
    s.name.assign(sym->Name, sym->Name + sym->NameLen);
    return s;
}

std::optional<kernel_sym_t> kernel_symbols::nearest(uint64_t address,
                                                    int64_t* out_offset) {
    auto st = ensure_loaded();
    if (!st.loaded) return std::nullopt;

    char buffer[sizeof(SYMBOL_INFOW) + 256 * sizeof(wchar_t)] = {};
    auto* sym = reinterpret_cast<SYMBOL_INFOW*>(buffer);
    sym->SizeOfStruct = sizeof(SYMBOL_INFOW);
    sym->MaxNameLen = 256;
    uint64_t disp = 0;
    if (!SymFromAddrW(GetCurrentProcess(), address, &disp, sym))
        return std::nullopt;
    kernel_sym_t s;
    s.address = sym->Address;
    s.name.assign(sym->Name, sym->Name + sym->NameLen);
    if (out_offset) *out_offset = static_cast<int64_t>(disp);
    return s;
}

} // namespace slop::core::runtime

