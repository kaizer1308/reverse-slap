// src/core/runtime/investigation.cpp
#include "core/runtime/investigation.hpp"
#include "core/runtime/xorstr.hpp"
#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "advapi32.lib")
#endif

namespace slop::core::runtime::investigation {

static int64_t now_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ── findings database ────────────────────────────────────────────────────

std::string findings_db_t::add_finding(finding_t f) {
    char id[16];
    std::snprintf(id, sizeof(id), "F-%04u", next_finding_id_++);
    f.id = id;
    f.created_ms = now_ms();
    f.updated_ms = f.created_ms;
    if (f.status.empty()) f.status = "open";
    findings_.push_back(std::move(f));
    return id;
}

void findings_db_t::update_finding(const std::string& id, const finding_t& f) {
    for (auto& ex : findings_) {
        if (ex.id == id) {
            ex.title = f.title;
            ex.category = f.category;
            ex.confidence = f.confidence;
            ex.description = f.description;
            ex.evidence = f.evidence;
            ex.limitations = f.limitations;
            ex.status = f.status;
            ex.updated_ms = now_ms();
            return;
        }
    }
}

void findings_db_t::remove_finding(const std::string& id) {
    findings_.erase(std::remove_if(findings_.begin(), findings_.end(),
        [&](const finding_t& f) { return f.id == id; }), findings_.end());
}

const finding_t* findings_db_t::get(const std::string& id) const {
    for (const auto& f : findings_)
        if (f.id == id) return &f;
    return nullptr;
}

std::string findings_db_t::add_question(open_question_t q) {
    char id[16];
    std::snprintf(id, sizeof(id), "Q-%04u", next_question_id_++);
    q.id = id;
    q.created_ms = now_ms();
    if (q.status.empty()) q.status = "open";
    questions_.push_back(std::move(q));
    return id;
}

void findings_db_t::answer_question(const std::string& id, const std::string& answer) {
    for (auto& q : questions_) {
        if (q.id == id) {
            q.answer = answer;
            q.status = "answered";
            return;
        }
    }
}

bool findings_db_t::export_json(const std::string& path) const {
    std::ofstream f(path);
    if (!f) return false;
    f << "{\n  \"findings\": [\n";
    for (size_t i = 0; i < findings_.size(); ++i) {
        const auto& fi = findings_[i];
        f << "    {\"id\":\"" << fi.id << "\",\"title\":\"" << fi.title
          << "\",\"category\":\"" << fi.category
          << "\",\"confidence\":" << static_cast<int>(fi.confidence)
          << ",\"status\":\"" << fi.status
          << "\",\"description\":\"" << fi.description
          << "\",\"limitations\":\"" << fi.limitations
          << "\",\"evidence_count\":" << fi.evidence.size()
          << ",\"created\":" << fi.created_ms
          << "}";
        if (i + 1 < findings_.size()) f << ",";
        f << "\n";
    }
    f << "  ],\n  \"questions\": [\n";
    for (size_t i = 0; i < questions_.size(); ++i) {
        const auto& q = questions_[i];
        f << "    {\"id\":\"" << q.id << "\",\"question\":\"" << q.question
          << "\",\"status\":\"" << q.status << "\"}";
        if (i + 1 < questions_.size()) f << ",";
        f << "\n";
    }
    f << "  ]\n}\n";
    return true;
}

bool findings_db_t::import_json(const std::string& path) {
    // simplified: just read the file and count entries
    std::ifstream f(path);
    return f.good();
}

void findings_db_t::clear() {
    findings_.clear();
    questions_.clear();
}

// ── hash helpers ─────────────────────────────────────────────────────────

#ifdef _WIN32
static std::string hash_bytes(const uint8_t* data, size_t len, ALG_ID alg) {
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    if (!CryptAcquireContextW(&prov, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return {};
    if (!CryptCreateHash(prov, alg, 0, 0, &hash)) {
        CryptReleaseContext(prov, 0); return {};
    }
    CryptHashData(hash, data, static_cast<DWORD>(len), 0);
    DWORD hash_len = 0, dw_count = sizeof(hash_len);
    CryptGetHashParam(hash, HP_HASHSIZE, reinterpret_cast<BYTE*>(&hash_len), &dw_count, 0);
    std::vector<BYTE> buf(hash_len);
    CryptGetHashParam(hash, HP_HASHVAL, buf.data(), &hash_len, 0);
    CryptDestroyHash(hash);
    CryptReleaseContext(prov, 0);
    std::string hex;
    for (DWORD i = 0; i < hash_len; ++i) {
        char h[3]; std::snprintf(h, sizeof(h), "%02x", buf[i]);
        hex += h;
    }
    return hex;
}
#endif

static uint32_t crc32_calc(const uint8_t* data, size_t len) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j)
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
    return ~crc;
}

static float entropy(const uint8_t* data, size_t len) {
    if (!len) return 0.0f;
    uint32_t freq[256] = {};
    for (size_t i = 0; i < len; ++i) ++freq[data[i]];
    float ent = 0.0f;
    for (int i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        float p = static_cast<float>(freq[i]) / static_cast<float>(len);
        ent -= p * std::log2f(p);
    }
    return ent;
}

// ── security audit ───────────────────────────────────────────────────────

static const char* kDangerousApis[] = {
    "VirtualAlloc", "VirtualProtect", XORSTR("CreateRemoteThread"),
    XORSTR("WriteProcessMemory"), XORSTR("ReadProcessMemory"), XORSTR("OpenProcess"),
    XORSTR("NtWriteVirtualMemory"), XORSTR("NtReadVirtualMemory"),
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
    "CreateThread", "ResumeThread", "SuspendThread",
    "SetWindowsHookExA", "SetWindowsHookExW",
    "ShellExecuteA", "ShellExecuteW", "WinExec",
    "InternetOpenA", "InternetOpenW", "URLDownloadToFileA",
    "RegSetValueExA", "RegSetValueExW",
    "CryptEncrypt", "CryptDecrypt",
    nullptr
};

security_audit_t audit_file(const std::vector<uint8_t>& file,
                             const std::string& name) {
    security_audit_t audit;
    audit.module_name = name;
    if (file.size() < sizeof(IMAGE_DOS_HEADER)) return audit;

    // hashes
#ifdef _WIN32
    audit.md5 = hash_bytes(file.data(), file.size(), CALG_MD5);
    audit.sha1 = hash_bytes(file.data(), file.size(), CALG_SHA1);
    audit.sha256 = hash_bytes(file.data(), file.size(), CALG_SHA_256);
#endif
    {
        char hex[16];
        std::snprintf(hex, sizeof(hex), "%08X", crc32_calc(file.data(), file.size()));
        audit.crc32 = hex;
    }

    // entropy
    audit.overall_entropy = entropy(file.data(), file.size());
    audit.likely_packed = audit.overall_entropy > 7.0f;

    // parse PE
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return audit;
    if (static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS64) > file.size())
        return audit;
    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
        file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return audit;

    audit.base = nt->OptionalHeader.ImageBase;
    audit.size = nt->OptionalHeader.SizeOfImage;

    // security features from DllCharacteristics
    uint16_t dc = nt->OptionalHeader.DllCharacteristics;
    audit.features.push_back({"ASLR (DYNAMIC_BASE)",
        (dc & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) != 0, ""});
    audit.features.push_back({"DEP/NX (NX_COMPAT)",
        (dc & IMAGE_DLLCHARACTERISTICS_NX_COMPAT) != 0, ""});
    audit.features.push_back({"CFG (GUARD_CF)",
        (dc & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0, ""});
    audit.features.push_back({"High Entropy ASLR",
        (dc & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA) != 0, ""});
    audit.features.push_back({"Force Integrity",
        (dc & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) != 0, ""});
    audit.features.push_back({"No SEH",
        (dc & IMAGE_DLLCHARACTERISTICS_NO_SEH) != 0, ""});
    audit.features.push_back({"No Bind",
        (dc & IMAGE_DLLCHARACTERISTICS_NO_BIND) != 0, ""});
    audit.features.push_back({"App Container",
        (dc & IMAGE_DLLCHARACTERISTICS_APPCONTAINER) != 0, ""});
    audit.features.push_back({"Terminal Server Aware",
        (dc & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE) != 0, ""});

    // sections analysis
    const auto* sec = IMAGE_FIRST_SECTION(nt);
    audit.section_count = nt->FileHeader.NumberOfSections;
    for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        uint32_t ch = sec[i].Characteristics;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE)) {
            audit.has_writable_exec = true;
        }
    }

    // relocation directory
    const auto& reloc_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    audit.has_no_relocs = (reloc_dir.VirtualAddress == 0 || reloc_dir.Size == 0);

    // import analysis
    const auto& import_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_dir.VirtualAddress && import_dir.Size) {
        // count imports and check for dangerous APIs
        // (simplified: scan the file for import name strings)
        for (int d = 0; kDangerousApis[d]; ++d) {
            if (std::search(file.begin(), file.end(),
                    reinterpret_cast<const uint8_t*>(kDangerousApis[d]),
                    reinterpret_cast<const uint8_t*>(kDangerousApis[d]) +
                        std::strlen(kDangerousApis[d])) != file.end()) {
                audit.dangerous_apis.push_back(kDangerousApis[d]);
                ++audit.suspicious_imports;
            }
        }
    }

    return audit;
}

security_audit_t audit_module(backend_t& be, const target_handle_t& h,
                               std::uint64_t base, std::uint32_t size,
                               const std::string& name) {
    // read the module from memory and audit
    std::vector<uint8_t> image(std::min<size_t>(size, 64 * 1024 * 1024));
    be.read_memory(h, base, image.data(), image.size());
    auto audit = audit_file(image, name);
    audit.base = base;
    audit.size = size;
    return audit;
}

// ── investigation workflows ──────────────────────────────────────────────

std::vector<investigation_workflow_t> get_workflows() {
    return {
        {"Feature Trace", "Trace how a specific feature works from UI to code",
         {{"target.modules", "List loaded modules to find the main game binary", "Look for the main .exe or .dll"},
          {"disasm.strings", "Search for UI strings related to the feature", "Find string references that match the feature name"},
          {"disasm.xrefs", "Follow xrefs from the string to code", "Find the function that uses this string"},
          {"decomp.function", "Decompile the function", "Understand the logic"},
          {"disasm.functions", "List callers of this function", "Trace the call chain upward"}}},

        {"Vulnerability Hunt", "Systematic vulnerability pattern search",
         {{"game.crypto_scan", "Find crypto constants (potential encryption keys)", "AES S-boxes, SHA constants in unexpected locations"},
          {"game.find_code_caves", "Find executable slack space", "Potential injection targets or hidden code"},
          {"re.rtti_scan", "Scan for RTTI class hierarchies", "Map the object model"},
          {"xray.hooks", "Detect inline hooks", "Modified function prologues"},
          {"xray.syscalls", "Find direct syscalls", "Potential anti-debug or evasion"}}},

        {"Network Protocol RE", "Reverse engineer the game's network protocol",
         {{"network.capture_start", "Start capturing packets", "Filter by game PID"},
          {"network.packets", "Examine captured packets", "Look for patterns in payload structure"},
          {"game.tick_rate", "Analyze server tick rate", "Understand update frequency"},
          {"game.test_authority", "Test client authority on key values", "Find exploitable client-trusted values"},
          {"game.find_position", "Find position coordinates", "Map the world-space data structure"}}},

        {"Anti-Cheat Analysis", "Understand the game's anti-cheat implementation",
         {{"detect.hidden_modules", "Check for hidden kernel modules", "AC drivers that hide from module list"},
          {"detect.kernel_callbacks", "Enumerate kernel callbacks", "PsSetCreateProcessNotifyRoutine, etc."},
          {"detect.etw_sessions", "List ETW trace sessions", "AC telemetry channels"},
          {"xray.anti_analysis", "Detect anti-analysis patterns", "Timing checks, debugger detection"},
          {"detect.minifilters", "Enumerate filesystem filters", "File-access monitoring"}}},

        {"Memory Layout Mapping", "Map the game's memory structure",
         {{"target.regions", "Enumerate memory regions", "Identify heap, stack, and mapped regions"},
          {"game.binary_map", "Build entropy heatmap", "Visualize code vs data vs packed regions"},
          {"game.rtti", "Scan for RTTI classes", "Map the C++ object hierarchy"},
          {"re.vftable", "Analyze virtual function tables", "Find polymorphic dispatch points"},
          {"game.find_timers", "Detect active timers/cooldowns", "Find game state variables"}}},

        {"Exploit Development", "Systematic exploit discovery workflow",
         {{"game.find_exploit type=health", "Scan for health values", "Find godmode candidates"},
          {"game.find_exploit type=ammo", "Scan for ammo counters", "Find infinite ammo candidates"},
          {"game.find_exploit type=cooldown", "Scan for cooldown timers", "Find no-cooldown candidates"},
          {"game.find_speed", "Find movement speed values", "Speed hack candidates"},
          {"game.test_authority", "Test server validation", "Which values are client-authoritative"}}},
    };
}

} // namespace slop::core::runtime::investigation
