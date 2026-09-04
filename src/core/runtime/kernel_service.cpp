// src/core/runtime/kernel_service.cpp

#include "core/runtime/kernel_service.hpp"

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/voyager_comm.h"
#include "core/infra/limits.hpp"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cstring>

#pragma comment(lib, "psapi.lib")

namespace slop::core::runtime {

namespace {

voyager::device_t* active_device() {
    auto* k = dynamic_cast<backend_kernel_t*>(&active());
    return k ? k->device() : nullptr;
}

// kernel reads need the dtb solved on the device, the first caller solves
// it and a driver reload resets it
voyager::device_t* kernel_device_ready(std::string* error) {
    auto* dev = active_device();
    if (!dev) {
        if (error) *error = "kernel driver not active";
        return nullptr;
    }
    if (dev->get_kernel_dtb() == 0) {
        dev->solve_kernel_dtb();
        if (dev->get_kernel_dtb() == 0) {
            if (error) *error = "kernel DTB resolve failed (driver connected but kernel context not established)";
            return nullptr;
        }
    }
    return dev;
}

std::string module_name_from_path(const std::wstring& path) {
    // GetDeviceDriverBaseNameW already returns a bare name ("ntoskrnl.exe",
    // no slashes); the old code returned "" for exactly that case.
    const size_t slash = path.find_last_of(L"\\/");
    std::wstring leaf = (slash == std::wstring::npos)
        ? path : path.substr(slash + 1);
    std::string out;
    out.reserve(leaf.size());
    for (wchar_t c : leaf) out.push_back(static_cast<char>(c));
    return out;
}

} // namespace

bool kernel_svc::available() { return active_device() != nullptr; }

std::vector<kernel_module_t> kernel_svc::enumerate_modules(
    std::string* error) {
    std::vector<kernel_module_t> out;
    if (!available()) {
        if (error) *error = "kernel driver not active";
        return out;
    }

    // enumdevicedrivers works without version dependent pool walks
    LPVOID drivers[1024] = {};
    DWORD needed = 0;
    if (!EnumDeviceDrivers(drivers, sizeof(drivers), &needed)) {
        if (error) *error = "EnumDeviceDrivers failed";
        return out;
    }
    const size_t count = std::min<size_t>(needed / sizeof(LPVOID), 1024);

    std::vector<LPVOID> bases(drivers, drivers + count);
    std::vector<wchar_t> name_buf(MAX_PATH * 2);
    auto names = std::make_unique<std::wstring[]>(count);
    // GetModuleFileNameEx-style driver names need the array form
    for (size_t i = 0; i < count; ++i) {
        wchar_t path[MAX_PATH * 2] = L"";
        GetDeviceDriverBaseNameW(bases[i], path, MAX_PATH * 2);
        names[i] = path;
    }

    // sizes come from sorted base deltas, the last entry gets a 1mb guess
    std::sort(bases.begin(), bases.end());
    for (size_t i = 0; i < count; ++i) {
        kernel_module_t m;
        m.base = reinterpret_cast<uint64_t>(bases[i]);
        m.size = 0x100000;
        if (i + 1 < count) {
            const uint64_t next = reinterpret_cast<uint64_t>(bases[i + 1]);
            if (next > m.base && next - m.base < 0x2000000)
                m.size = static_cast<uint32_t>(
                    std::min<uint64_t>(next - m.base, 0x2000000));
        }
        // Recover the name for this base
        for (size_t j = 0; j < count; ++j) {
            if (reinterpret_cast<uint64_t>(drivers[j]) == m.base) {
                m.name = module_name_from_path(names[j]);
                break;
            }
        }
        out.push_back(std::move(m));
    }
    return out;
}

std::string kernel_svc::dump_module(uint64_t base, uint32_t size,
                                    const std::string& out_path) {
    std::string kerr;
    auto* dev = kernel_device_ready(&kerr);
    if (!dev) return kerr;
    if (!base || !size || size > infra::limits::max_snapshot_region_bytes)
        return "bad base/size";

    std::vector<uint8_t> image(size);
    size_t total = 0;
    constexpr size_t kChunk = 0x10000;
    while (total < size) {
        const size_t take = std::min(kChunk, size - total);
        const size_t got = dev->read_kernel_raw(base + total,
                                                image.data() + total, take);
        if (got != take)
            return "short read at offset " + std::to_string(total);
        total += take;
    }
    if (image[0] != 'M' || image[1] != 'Z')
        return "no MZ header at driver base (wrong base?)";

    HANDLE f = CreateFileA(out_path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return "cannot create output file";
    DWORD written = 0;
    WriteFile(f, image.data(), static_cast<DWORD>(image.size()), &written,
              nullptr);
    CloseHandle(f);
    return written == image.size() ? "" : "short write";
}

std::string kernel_svc::kernel_read(uint64_t addr, size_t len,
                                    std::vector<uint8_t>* out) {
    std::string kerr;
    auto* dev = kernel_device_ready(&kerr);
    if (!dev) return kerr;
    if (!len || len > infra::limits::max_snapshot_region_bytes)
        return "bad length";
    out->resize(len);
    const size_t got = dev->read_kernel_raw(addr, out->data(), len);
    if (got != len) {
        out->resize(got);
        return got == 0 ? "read failed" : "";
    }
    return "";
}

std::string kernel_svc::kernel_write(uint64_t addr,
                                     const std::vector<uint8_t>& bytes) {
    std::string kerr;
    auto* dev = kernel_device_ready(&kerr);
    if (!dev) return kerr;
    if (bytes.empty()) return "empty payload";
    const size_t put =
        dev->write_kernel_raw(addr, bytes.data(), bytes.size());
    return put == bytes.size() ? "" : "short write";
}

std::vector<uint64_t> kernel_svc::kernel_search(
    uint64_t begin, uint64_t end, const std::vector<uint8_t>& pattern,
    size_t max_hits) {
    std::vector<uint64_t> hits;
    auto* dev = kernel_device_ready(nullptr);
    if (!dev || pattern.empty() || end <= begin || end - begin > 0x4000000ull)
        return hits;

    constexpr size_t kWindow = 0x10000;
    std::vector<uint8_t> buf(kWindow + pattern.size());
    uint64_t cursor = begin;
    while (cursor + pattern.size() <= end &&
           hits.size() < max_hits) {
        const size_t span = static_cast<size_t>(
            std::min<uint64_t>(kWindow, end - cursor));
        const size_t got = dev->read_kernel_raw(cursor, buf.data(), span);
        if (got == 0) {
            cursor += kWindow;   // skip unreadable hole
            continue;
        }
        for (size_t i = 0; i + pattern.size() <= got; ++i) {
            bool m = true;
            for (size_t b = 0; b < pattern.size(); ++b) {
                if (buf[i + b] != pattern[b]) { m = false; break; }
            }
            if (m) {
                hits.push_back(cursor + i);
                if (hits.size() >= max_hits) break;
            }
        }
        cursor += kWindow;
    }
    return hits;
}

std::optional<uint64_t> kernel_svc::call_function(uint64_t addr, uint64_t a1,
                                                  uint64_t a2, uint64_t a3,
                                                  uint64_t a4) {
    auto* dev = kernel_device_ready(nullptr);
    if (!dev) return std::nullopt;
    const uint64_t r = dev->call_function(addr, a1, a2, a3, a4);
    return r;
}

std::optional<uint64_t> kernel_svc::virtual_to_physical(uint64_t va) {
    auto* dev = kernel_device_ready(nullptr);
    if (!dev) return std::nullopt;
    const uint64_t pa = dev->virtual_to_physical(va);
    return pa ? std::optional<uint64_t>(pa) : std::nullopt;
}

kernel_svc::ssdt_result_t kernel_svc::query_ssdt() {
    ssdt_result_t res;
    auto* dev = kernel_device_ready(&res.error);
    if (!dev) return res;
    voyager::device_t::ssdt_info info{};
    if (!dev->query_ssdt(info)) {
        res.error = "query_ssdt failed";
        return res;
    }
    res.ok = true;
    res.lstar = info.lstar;
    res.service_table = info.service_table;
    res.service_limit = info.service_limit;

    // x64 entries are 32 bit offsets, handler is table base plus entry
// shifted right 4
    const uint32_t limit = std::min<uint32_t>(info.service_limit, 512);
    if (info.service_table && limit) {
        std::vector<uint8_t> raw(static_cast<size_t>(limit) * 4);
        if (dev->read_kernel_raw(info.service_table, raw.data(),
                                 raw.size()) == raw.size()) {
            res.handlers.reserve(limit);
            for (uint32_t i = 0; i < limit; ++i) {
                uint32_t entry;
                std::memcpy(&entry, raw.data() + i * 4, 4);
                res.handlers.push_back(info.service_table +
                                       (entry >> 4));
            }
        }
    }
    return res;
}

kernel_svc::peb_result_t kernel_svc::read_peb() {
    peb_result_t res;
    auto* dev = kernel_device_ready(&res.error);
    if (!dev) return res;
    voyager::device_t::peb_info info{};
    if (!dev->read_peb(info)) {
        res.error = "read_peb failed";
        return res;
    }
    res.ok             = true;
    res.peb_address    = info.peb_address;
    res.image_base     = info.image_base;
    res.ldr_address    = info.ldr_address;
    res.process_heap   = info.process_heap;
    res.being_debugged = info.being_debugged;
    return res;
}

std::optional<uint64_t> kernel_svc::resolve_export(uint64_t module_base,
                                                   const std::string& name) {
    auto* dev = kernel_device_ready(nullptr);
    if (!dev || module_base == 0 || name.empty()) return std::nullopt;
    const uint64_t va = dev->resolve_export(module_base, name.c_str());
    return va ? std::optional<uint64_t>(va) : std::nullopt;
}

std::vector<window_info_t> kernel_svc::enumerate_windows(uint32_t filter_pid) {
    std::vector<window_info_t> out;
    struct ctx_t {
        uint32_t pid;
        std::vector<window_info_t>* out;
    } ctx{filter_pid, &out};

    EnumWindows(
        [](HWND hwnd, LPARAM lparam) -> BOOL {
            auto* c = reinterpret_cast<ctx_t*>(lparam);
            DWORD pid = 0;
            GetWindowThreadProcessId(hwnd, &pid);
            if (c->pid != 0 && c->pid != pid) return TRUE;
            if (!IsWindowVisible(hwnd)) return TRUE;

            window_info_t w;
            w.hwnd = hwnd;
            w.pid = pid;
            wchar_t title[256] = L"", klass[256] = L"";
            GetWindowTextW(hwnd, title, 256);
            GetClassNameW(hwnd, klass, 256);
            w.title.assign(title, title + wcslen(title));
            w.klass.assign(klass, klass + wcslen(klass));
            c->out->push_back(std::move(w));
            return TRUE;
        },
        reinterpret_cast<LPARAM>(&ctx));
    return out;
}

} // namespace slop::core::runtime

