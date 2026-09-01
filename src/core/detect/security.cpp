// src/core/detect/security.cpp

#include "core/detect/security.hpp"

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/voyager_comm.h"

#include <windows.h>
#include <psapi.h>
#include <evntrace.h>

#include <algorithm>
#include <cstring>
#include <set>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "fltlib.lib")

namespace slop::core::detect {

namespace {

std::string base_name(const std::string& path) {
    const size_t slash = path.find_last_of("\\/");
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::vector<module_entry_t> psapi_drivers() {
    std::vector<module_entry_t> out;
    LPVOID bases[2048] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(bases, sizeof(bases), &needed)) return out;
    const size_t n = std::min<size_t>(needed / sizeof(LPVOID), 2048);
    for (size_t i = 0; i < n; ++i) {
        module_entry_t m;
        m.base = reinterpret_cast<uint64_t>(bases[i]);
        wchar_t path[MAX_PATH * 2] = L"";
        GetDeviceDriverFileNameW(bases[i], path, MAX_PATH * 2);
        std::string a;
        a.reserve(wcslen(path));
        for (const wchar_t* p = path; *p; ++p)
            a.push_back(static_cast<char>(*p));
        m.name = base_name(a);
        out.push_back(std::move(m));
    }
    return out;
}

std::vector<module_entry_t> sysinfo_modules() {
    std::vector<module_entry_t> out;
    using NtQSI = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return out;
    const auto qsi =
        reinterpret_cast<NtQSI>(GetProcAddress(ntdll,
                                               "NtQuerySystemInformation"));
    if (!qsi) return out;

    constexpr ULONG SystemModuleInformation = 11;
    struct mod_info_t {
        uint64_t section;
        uint64_t mapped_base;
        uint64_t image_base;
        uint32_t image_size;
        uint32_t flags;
        uint16_t load_count;
        uint16_t offset_to_file_name;
        char full_path_name[256];
    };
    struct hdr_t { uint32_t count; };

    ULONG need = 0;
    std::vector<uint8_t> buf(1 << 20);
    LONG st = qsi(SystemModuleInformation, buf.data(),
                  static_cast<ULONG>(buf.size()), &need);
    if (st == 0xC0000004) {
        buf.resize(need + 4096);
        st = qsi(SystemModuleInformation, buf.data(),
                 static_cast<ULONG>(buf.size()), &need);
    }
    if (st != 0 || buf.size() < sizeof(hdr_t)) return out;

    const uint32_t count =
        std::min<uint32_t>(*reinterpret_cast<const uint32_t*>(buf.data()),
                           2048);
    // On x64 the module array starts at offset 8 (pointer alignment after
    // the ULONG count)
    const auto* items =
        reinterpret_cast<const mod_info_t*>(buf.data() + 8);
    for (uint32_t i = 0; i < count; ++i) {
        module_entry_t m;
        m.base = items[i].image_base;
        m.size = items[i].image_size;
        m.name = items[i].full_path_name + items[i].offset_to_file_name;
        out.push_back(std::move(m));
    }
    return out;
}

} // namespace

hidden_module_report_t detect_hidden_modules(std::string* error) {
    hidden_module_report_t rep;
    auto psapi = psapi_drivers();
    auto sysinfo = sysinfo_modules();
    if (psapi.empty() && sysinfo.empty()) {
        if (error) *error = "enumeration failed (privilege?)";
        return rep;
    }

    std::set<uint64_t> psapi_bases;
    for (const auto& m : psapi) psapi_bases.insert(m.base);
    std::set<uint64_t> sysinfo_bases;
    for (const auto& m : sysinfo) sysinfo_bases.insert(m.base);

    for (const auto& m : psapi)
        if (!sysinfo_bases.count(m.base)) rep.psapi_only.push_back(m);
    for (const auto& m : sysinfo)
        if (!psapi_bases.count(m.base)) rep.sysinfo_only.push_back(m);
    return rep;
}

std::vector<minifilter_t> enumerate_minifilters(std::string* error) {
    // minifilters live under services with an altitude value, plain user mode enumeration
    std::vector<minifilter_t> out;
    HKEY services = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
                      "SYSTEM\\CurrentControlSet\\Services", 0,
                      KEY_READ, &services) != ERROR_SUCCESS) {
        if (error) *error = "cannot open Services key";
        return out;
    }
    DWORD idx = 0;
    char svc[256];
    DWORD svc_len = sizeof(svc);
    while (RegEnumKeyExA(services, idx++, svc, &svc_len, nullptr, nullptr,
                         nullptr, nullptr) == ERROR_SUCCESS) {
        svc_len = sizeof(svc);
        const std::string inst_path =
            std::string("SYSTEM\\CurrentControlSet\\Services\\") + svc +
            "\\Instances";
        HKEY inst = nullptr;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, inst_path.c_str(), 0, KEY_READ,
                          &inst) != ERROR_SUCCESS)
            continue;

        char instance[256] = {};
        DWORD instance_len = sizeof(instance);
        if (RegEnumKeyExA(inst, 0, instance, &instance_len, nullptr, nullptr,
                          nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY one = nullptr;
            if (RegOpenKeyExA(inst, instance, 0, KEY_READ, &one) ==
                ERROR_SUCCESS) {
                char altitude[64] = {};
                DWORD alt_len = sizeof(altitude), type = 0;
                RegQueryValueExA(one, "Altitude", nullptr, &type,
                                 reinterpret_cast<BYTE*>(altitude),
                                 &alt_len);
                minifilter_t f;
                f.name = svc;
                f.altitude = altitude;
                out.push_back(std::move(f));
                RegCloseKey(one);
            }
        }
        RegCloseKey(inst);
    }
    RegCloseKey(services);
    return out;
}

std::vector<etw_session_t> enumerate_etw_sessions(std::string* error) {
    std::vector<etw_session_t> out;
    // QueryAllTraces takes an array of POINTERS to property blobs
    struct props_blob_t {
        EVENT_TRACE_PROPERTIES props;
        wchar_t logger_name[128];
        wchar_t log_file[256];
    };
    static props_blob_t blobs[64];
    EVENT_TRACE_PROPERTIES* prop_ptrs[64] = {};
    for (ULONG i = 0; i < 64; ++i) {
        blobs[i].props.Wnode.BufferSize = sizeof(props_blob_t);
        prop_ptrs[i] = &blobs[i].props;
    }
    ULONG real = 0;
    if (!QueryAllTraces(prop_ptrs, 64, &real)) {
        if (error) *error = "QueryAllTraces failed";
        return out;
    }
    for (ULONG i = 0; i < real; ++i) {
        etw_session_t s;
        s.handle = static_cast<uint64_t>(prop_ptrs[i]->Wnode.HistoricalContext);
        s.logger_name.reserve(128);
        for (int ci = 0; ci < 128 && blobs[i].logger_name[ci]; ++ci)
            s.logger_name.push_back(
                static_cast<char>(blobs[i].logger_name[ci]));
        s.buffers_written = blobs[i].props.BuffersWritten;
        s.events_lost = blobs[i].props.EventsLost;
        out.push_back(std::move(s));
    }
    return out;
}

callback_report_t enumerate_kernel_callbacks() {
    callback_report_t res;
    auto* k = dynamic_cast<runtime::backend_kernel_t*>(&runtime::active());
    voyager::device_t* dev = k ? k->device() : nullptr;
    if (!dev) {
        res.error = "kernel driver not active";
        return res;
    }

    LPVOID drivers[512] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed) || !needed ||
        drivers[0] == nullptr) {
        res.error = "cannot locate ntoskrnl base";
        return res;
    }
    const uint64_t nt_base = reinterpret_cast<uint64_t>(drivers[0]);

    constexpr size_t kScanBytes = 24ull << 20;
    std::vector<uint8_t> img(kScanBytes);
    const size_t got = dev->read_kernel_raw(nt_base, img.data(), img.size());
    if (got < (1 << 20)) {
        res.error = "kernel read too short";
        return res;
    }

    // Walk a notify-routine array discovered via an RIP-relative LEA anchor
    // inside the corresponding PspSetCreate*NotifyRoutine function
    auto walk_kind = [&](const char* kind, const uint8_t sig[], size_t len,
                         int slot_count) -> bool {
        for (size_t i = 0; i + len <= got; ++i) {
            if (std::memcmp(img.data() + i, sig, len) != 0) continue;
            int32_t disp;
            std::memcpy(&disp, img.data() + i + 3, 4);
            const uint64_t array_va = nt_base + i + len + disp;

            bool any_valid = false;
            for (int slot = 0; slot < slot_count; ++slot) {
                uint64_t handler = 0;
                if (dev->read_kernel_raw(array_va + slot * 8, &handler,
                                         8) != 8)
                    break;
                // Slot validity: kernel-space pointer or NULL
                if (!handler) continue;
                if (handler < nt_base) break;
                res.entries.push_back(
                    {kind, static_cast<uint32_t>(slot), handler});
                any_valid = true;
            }
            if (any_valid) return true;
        }
        return false;
    };

    // Canonical LEA-with-RIP-relative anchors on current Win10/11 x64
    // builds. Signatures miss on some builds -> reported as partial
    static const uint8_t kProcSig[] = {0x4C, 0x8D, 0x35};   // lea r14,[x]
    static const uint8_t kThrdSig[] = {0x4C, 0x8D, 0x25};   // lea r12,[x]
    static const uint8_t kImgSig[]  = {0x48, 0x8D, 0x05};   // lea rax,[x]

    bool ok = false;
    if (walk_kind("process", kProcSig, sizeof(kProcSig), 64)) ok = true;
    if (walk_kind("thread", kThrdSig, sizeof(kThrdSig), 64)) ok = true;
    if (walk_kind("image", kImgSig, sizeof(kImgSig), 64)) ok = true;

    res.ok = ok;
    if (!ok)
        res.error = "notify-routine anchors not found on this build "
                    "(detection requires per-build signatures)";
    return res;
}

} // namespace slop::core::detect

