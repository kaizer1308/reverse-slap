// src/core/runtime/winotify_driver.cpp
// NtLoadDriver staging + ioctl transport for the WHQL-signed WinNotify driver.
// the load path is the legit one: SeLoadDriverPrivilege, a random demand-start
// service key, a randomly named staged copy, no SCM and therefore no 7045 event.
// the driver registers its DeviceObject via IoCreateDriver and its unload
// routine is real, so unload is clean (no reboot).

#include "core/runtime/winotify_driver.hpp"
#include "core/runtime/xorstr.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <atomic>
#include <cwchar>
#include <ctime>
#include <vector>

namespace slop::core::runtime::winotify {

namespace {

const wchar_t* device_path() { return XORWSTR(L"\\\\.\\WinNotify"); }
constexpr wchar_t kRuntimeSubdir[] = L"\\SystemDevices";


using nt_open_key_fn   = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
using nt_create_key_fn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES,
                                      ULONG, PUNICODE_STRING, ULONG, PULONG);
using nt_set_value_fn  = LONG(NTAPI*)(HANDLE, PUNICODE_STRING, ULONG, ULONG, PVOID, ULONG);
using nt_delete_key_fn = LONG(NTAPI*)(POBJECT_ATTRIBUTES);
using nt_load_fn       = LONG(NTAPI*)(PUNICODE_STRING);
using rtl_init_us_fn   = VOID(NTAPI*)(PUNICODE_STRING, PCWSTR);

using ntstatus_t = LONG;
using nt_query_fn      = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
using rtl_adjust_fn    = LONG(NTAPI*)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);

void* ntdll_proc(const char* name) {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    return ntdll ? reinterpret_cast<void*>(GetProcAddress(ntdll, name)) : nullptr;
}

template <typename Fn>
Fn ntdll_fn(const char* name) {
    return reinterpret_cast<Fn>(ntdll_proc(name));
}

LONG enable_load_privilege() {
    static const rtl_adjust_fn fn = ntdll_fn<rtl_adjust_fn>("RtlAdjustPrivilege");
    if (!fn) return -1;
    BOOLEAN ignored = FALSE;
    return fn(10, TRUE, FALSE, &ignored);   // 10 == SeLoadDriverPrivilege
}

void init_attributes(OBJECT_ATTRIBUTES& oa, PUNICODE_STRING us) {
    InitializeObjectAttributes(&oa, us, OBJ_CASE_INSENSITIVE, nullptr, nullptr);
}

std::wstring staged_directory() {
    wchar_t override_dir[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"SLOP_DRIVER_STAGE_DIR", override_dir, MAX_PATH) != 0) {
        std::wstring dir(override_dir);
        CreateDirectoryW(dir.c_str(), nullptr);
        return dir;
    }
    wchar_t programdata[MAX_PATH] = {};
    if (GetEnvironmentVariableW(L"ProgramData", programdata, MAX_PATH) == 0)
        return {};
    std::wstring dir = std::wstring(programdata) + kRuntimeSubdir;
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

std::wstring random_leaf() {
    unsigned seed = static_cast<unsigned>(GetTickCount64()) ^
                    (static_cast<unsigned>(GetCurrentProcessId()) << 9) ^
                    static_cast<unsigned>(reinterpret_cast<uintptr_t>(&seed));
    wchar_t leaf[16] = {};
    for (int i = 0; i < 8; ++i) {
        seed = seed * 1103515245u + 12345u;
        leaf[i] = static_cast<wchar_t>(L'a' + (seed >> 16) % 26u);
    }
    return std::wstring(leaf) + L".sys";
}

std::wstring exe_directory() {
    wchar_t exe[MAX_PATH] = {};
    const DWORD len = GetModuleFileNameW(nullptr, exe, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) return {};
    std::wstring dir(exe);
    const size_t slash = dir.find_last_of(L"\\/");
    return slash == std::wstring::npos ? std::wstring() : dir.substr(0, slash);
}

bool find_source_driver(std::wstring& out) {
    const std::wstring dir = exe_directory();
    const wchar_t* candidates[] = {
        L"\\driver\\signeddrv.sys",
        L"\\signeddrv.sys",
        L"\\wn\\signeddrv.sys",
    };
    for (const wchar_t* rel : candidates) {
        std::wstring cand = dir + rel;
        if (GetFileAttributesW(cand.c_str()) != INVALID_FILE_ATTRIBUTES) {
            out = cand;
            return true;
        }
    }
    const wchar_t* store = L"E:\\Markus\\Drivers\\signeddrv.sys";
    if (GetFileAttributesW(store) != INVALID_FILE_ATTRIBUTES) {
        out = store;
        return true;
    }
    return false;
}

} // namespace

driver_t::~driver_t() { disconnect(); }

bool driver_t::device_present() const noexcept {
    HANDLE h = CreateFileW(device_path(), GENERIC_READ | GENERIC_WRITE,
                           FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    CloseHandle(h);
    return true;
}

bool driver_t::stage_and_load() {
    static const rtl_init_us_fn   rtl_init_us  = ntdll_fn<rtl_init_us_fn>("RtlInitUnicodeString");
    static const nt_load_fn       nt_load      = ntdll_fn<nt_load_fn>("NtLoadDriver");
    static const nt_create_key_fn nt_create    = ntdll_fn<nt_create_key_fn>("NtCreateKey");
    static const nt_set_value_fn  nt_set_value = ntdll_fn<nt_set_value_fn>("NtSetValueKey");
    static const nt_open_key_fn   nt_open      = ntdll_fn<nt_open_key_fn>("NtOpenKey");
    if (!nt_load || !nt_create || !nt_set_value || !nt_open) {
        last_error_ = "ntdll natives unavailable";
        return false;
    }
    if (enable_load_privilege() != 0) {
        last_error_ = "SeLoadDriverPrivilege unavailable (not elevated?)";
        return false;
    }

    const std::wstring dir = staged_directory();
    if (dir.empty()) { last_error_ = "no LOCALAPPDATA"; return false; }

    std::wstring source;
    if (!find_source_driver(source)) {
        last_error_ = "signed driver not found next to the exe (driver\\) or in the driver store";
        return false;
    }
    staged_path_ = dir + L"\\" + random_leaf();
    if (!CopyFileW(source.c_str(), staged_path_.c_str(), FALSE)) {
        last_error_ = "staging copy failed";
        return false;
    }
    const size_t leaf_at = staged_path_.find_last_of(L"\\/");
    wchar_t module_name[64] = {};
    lstrcpynW(module_name, staged_path_.c_str() + leaf_at + 1, 64);
    wchar_t wide_name[64] = {};
    lstrcpyW(wide_name, module_name);
    char narrow_name[64] = {};
    WideCharToMultiByte(CP_UTF8, 0, wide_name, -1, narrow_name, sizeof(narrow_name), nullptr, nullptr);
    staged_module_name_ = narrow_name;

    wchar_t key_path[256] = {};
    _snwprintf_s(key_path, _TRUNCATE,
                 L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\%s", module_name);
    service_key_ = key_path;

    wchar_t key_path_buf[256] = {};
    lstrcpynW(key_path_buf, service_key_.c_str(), 256);
    UNICODE_STRING key_us{};
    rtl_init_us(&key_us, key_path_buf);
    OBJECT_ATTRIBUTES oa{};
    init_attributes(oa, &key_us);
    HANDLE key = nullptr;
    ntstatus_t st = nt_create(&key, KEY_ALL_ACCESS, &oa, 0, nullptr, 0, nullptr);
    if (st < 0 || !key) {
        last_error_ = "service key create failed ntstatus=0x" +
                      std::to_string(static_cast<unsigned long>(st));
        DeleteFileW(staged_path_.c_str());
        staged_path_.clear();
        return false;
    }

    const std::wstring image_path = L"\\??\\" + staged_path_;
    wchar_t image_buf[512] = {};
    lstrcpynW(image_buf, image_path.c_str(), 512);
    UNICODE_STRING name_us{};
    rtl_init_us(&name_us, const_cast<PWSTR>(L"ImagePath"));
    UNICODE_STRING image_us{};
    rtl_init_us(&image_us, image_buf);
    nt_set_value(key, &name_us, 0, REG_SZ, image_us.Buffer, image_us.MaximumLength);

    const DWORD values[3] = { 1, 1, 3 };
    const wchar_t* names[3] = { L"Type", L"ErrorControl", L"Start" };
    for (int i = 0; i < 3; ++i) {
        UNICODE_STRING vs{};
        rtl_init_us(&vs, const_cast<PWSTR>(names[i]));
        nt_set_value(key, &vs, 0, REG_DWORD,
                     const_cast<DWORD*>(&values[i]), sizeof(DWORD));
    }
    CloseHandle(key);

    UNICODE_STRING load_us{};
    rtl_init_us(&load_us, key_path_buf);
    static const nt_delete_key_fn nt_delete_key_fn_impl =
        ntdll_fn<nt_delete_key_fn>("NtDeleteKey");
    st = nt_load(&load_us);
    if (st < 0) {
        last_error_ = "NtLoadDriver failed ntstatus=0x" +
                      std::to_string(static_cast<unsigned long>(st));
        DeleteFileW(staged_path_.c_str());
        staged_path_.clear();
        return false;
    }
    // the loaded image keeps its own registry identity in the driver object,
    // the key is only a loader hint: drop it immediately so a session long
    // registry sweep never sees a kernel service pointing into user land
    if (nt_delete_key_fn_impl) nt_delete_key_fn_impl(&oa);
    last_error_.clear();
    return true;
}

bool driver_t::connect() {
    if (dev_) return true;
    if (!device_present()) {
        if (!stage_and_load()) return false;
    }
    void* dev = CreateFileW(device_path(), GENERIC_READ | GENERIC_WRITE,
                            FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (dev == INVALID_HANDLE_VALUE) {
        dev_ = nullptr;
        last_error_ = "device open failed gle=" + std::to_string(GetLastError());
        return false;
    }
    dev_ = dev;
    last_error_.clear();
    return true;
}

void driver_t::disconnect() {
    if (dev_) { CloseHandle(static_cast<HANDLE>(dev_)); dev_ = nullptr; }
}

bool driver_t::kernel_write_checked(std::uint64_t va, const void* buf, std::size_t len,
                                     std::uint64_t expect_mask, std::uint64_t expect_value) {
    if (!dev_ || !buf || !len || len > 0x1000) return false;

    // pre-read the target: verify it is readable and the bits we expect to
    // see (masked) match, so we never write into a hole or a shifted offset
    std::vector<std::uint8_t> before(len);
    if (!kernel_read(va, before.data(), len)) return false;

    // validate expect_mask/expect_value against however many bytes are present
    {
        std::uint64_t cur = 0;
        const std::size_t n = len < 8 ? len : 8;
        std::memcpy(&cur, before.data(), n);
        // for reads shorter than 8 bytes the upper bits of cur are zero,
        // so the caller's mask must not set bits beyond the read width
        if ((cur & expect_mask) != expect_value) return false;
    }

    // write and verify the write landed
    if (!kernel_write(va, buf, len)) return false;
    std::vector<std::uint8_t> after(len);
    if (!kernel_read(va, after.data(), len)) return false;
    if (std::memcmp(after.data(), buf, len) != 0) return false;

    // snapshot the surrounding page twice in quick succession: if any byte
    // outside our write range changed between the two snapshots, a concurrent
    // modification is racing us and our offsets may be wrong
    const std::uint64_t page = va & ~0xFFFull;
    const std::uint64_t off = va & 0xFFF;
    std::vector<std::uint8_t> snap_a(0x1000);
    if (!kernel_read(page, snap_a.data(), 0x1000)) return true;
    std::vector<std::uint8_t> snap_b(0x1000);
    if (!kernel_read(page, snap_b.data(), 0x1000)) return true;
    for (std::size_t i = 0; i < 0x1000; ++i) {
        if (i >= off && i < off + len) continue;
        if (snap_a[i] != snap_b[i]) {
            // collateral damage: something else changed this page, which
            // means our offsets are wrong or a race hit. we cannot undo the
            // write, but we report failure so the caller stops immediately
            return false;
        }
    }
    return true;
}

void driver_t::park() {
    disconnect();
}

bool driver_t::resume() {
    return connect();
}

bool driver_t::unload() {
    static const rtl_init_us_fn   rtl_init_us   = ntdll_fn<rtl_init_us_fn>("RtlInitUnicodeString");
    static const nt_load_fn       nt_unload     = ntdll_fn<nt_load_fn>("NtUnloadDriver");
    static const nt_delete_key_fn nt_delete_key = ntdll_fn<nt_delete_key_fn>("NtDeleteKey");
    static const nt_open_key_fn   nt_open       = ntdll_fn<nt_open_key_fn>("NtOpenKey");
    if (!nt_unload || !nt_delete_key || !nt_open || !rtl_init_us) {
        last_error_ = "unload natives unavailable";
        return false;
    }
    disconnect();
    bool ok = true;
    if (!service_key_.empty()) {
        wchar_t key_path_buf[256] = {};
        lstrcpynW(key_path_buf, service_key_.c_str(), 256);
        UNICODE_STRING key_us{};
        rtl_init_us(&key_us, key_path_buf);
        OBJECT_ATTRIBUTES oa{};
        init_attributes(oa, &key_us);
        HANDLE key = nullptr;
        if (nt_open(&key, DELETE, &oa) >= 0 && key) {
            CloseHandle(key);
            const LONG ust = nt_unload(&key_us);
            if (ust < 0) {
                last_error_ = "NtUnloadDriver ntstatus=0x" +
                              std::to_string(static_cast<unsigned long>(ust));
                ok = false;
            }
        } else {
            last_error_ = "service key reopen failed";
            ok = false;
        }
        const LONG dst = nt_delete_key(&oa);
        if (dst < 0) {
            last_error_ += " NtDeleteKey ntstatus=0x" +
                           std::to_string(static_cast<unsigned long>(dst));
            ok = false;
        }
        if (ok) service_key_.clear();
    }
    if (!staged_path_.empty()) {
        if (!DeleteFileW(staged_path_.c_str())) {
            // loaded image keeps the file locked until unload completes, retry briefly
            bool deleted = false;
            for (int i = 0; i < 20 && !deleted; ++i) {
                Sleep(100);
                deleted = DeleteFileW(staged_path_.c_str()) != 0;
            }
            if (!deleted) {
                last_error_ += " staged file still locked";
                ok = false;
            }
        }
        if (ok) staged_path_.clear();
    }
    return ok;
}

bool driver_t::send(std::uint32_t code, void* buf, std::uint32_t size) noexcept {
    if (!dev_) return false;
    DWORD returned = 0;
    return DeviceIoControl(static_cast<HANDLE>(dev_), code, buf, size, buf, size,
                           &returned, nullptr) != 0;
}

std::uint64_t driver_t::solve_dtb(std::uint32_t pid) {
    dtb_request_t req{};
    req.pid = pid;
    req.strict = 0;
    if (!send(ioctl::DTB, &req, sizeof(req))) return 0;
    return req.out_dtb;
}

bool driver_t::phys_read(std::uint64_t dtb, std::uint64_t va, void* buf, std::size_t len) {
    if (!buf || !len || !dtb || !dev_) return false;
    if (len > 0x1000000 || va + len < va) return false;
    auto* dst = static_cast<std::uint8_t*>(buf);
    std::size_t done = 0;
    while (done < len) {
        const std::uint64_t cur = va + done;
        const std::size_t page_left = 0x1000 - static_cast<std::size_t>(cur & 0xFFF);
        const std::size_t chunk = page_left < (len - done) ? page_left : (len - done);
        phys_request_t req{};
        req.flag = 1;
        req.va = cur;
        req.buffer = reinterpret_cast<std::uint64_t>(dst + done);
        req.size = chunk;
        req.dtb = dtb;
        if (!send(ioctl::PHYS_READ, &req, sizeof(req))) return false;
        done += chunk;
    }
    return true;
}

bool driver_t::phys_write(std::uint64_t dtb, std::uint64_t va, const void* buf, std::size_t len) {
    if (!buf || !len || !dtb || !dev_) return false;
    if (len > 0x1000000 || va + len < va) return false;
    const auto* src = static_cast<const std::uint8_t*>(buf);
    std::size_t done = 0;
    while (done < len) {
        const std::uint64_t cur = va + done;
        const std::size_t page_left = 0x1000 - static_cast<std::size_t>(cur & 0xFFF);
        const std::size_t chunk = page_left < (len - done) ? page_left : (len - done);
        phys_request_t req{};
        req.flag = 1;
        req.va = cur;
        req.buffer = reinterpret_cast<std::uint64_t>(src + done);
        req.size = chunk;
        req.dtb = dtb;
        if (!send(ioctl::PHYS_WRITE, &req, sizeof(req))) return false;
        done += chunk;
    }
    return true;
}

namespace {

bool kernel_range_ok(std::uint64_t va, std::size_t len) {
    if (!len || len > 0x1000000) return false;
    if (va < 0xFFFF800000000000ull || (va >> 48) != 0xFFFF) return false;
    return va + len >= va;
}

std::uint64_t proven_kernel_dtb(driver_t& dev) {
    static std::atomic<std::uint64_t> cached{0};
    const std::uint64_t c = cached.load(std::memory_order_acquire);
    if (c) return c;
    const std::uint64_t dtb = dev.solve_dtb(4) & ~0xFFFull;
    if (!dtb) return 0;
    const std::uint64_t nt = dev.module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!nt) return 0;
    std::uint8_t mz[2] = {};
    if (!dev.phys_read(dtb, nt, mz, sizeof(mz)) || mz[0] != 'M' || mz[1] != 'Z')
        return 0;
    cached.store(dtb, std::memory_order_release);
    return dtb;
}

} // namespace

bool driver_t::kernel_write(std::uint64_t dst, const void* src, std::size_t len) {
    if (!src || !dev_ || !kernel_range_ok(dst, len)) return false;
    const std::uint64_t dtb = proven_kernel_dtb(*this);
    if (!dtb) return false;
    return phys_write(dtb, dst, src, len);
}

std::uint64_t driver_t::base_of(std::uint32_t pid) {
    base_request_t req{};
    req.pid = pid;
    if (!send(ioctl::BASE_OF, &req, sizeof(req))) return 0;
    return req.out_base;
}

std::uint64_t driver_t::peb_of(std::uint32_t pid) {
    base_request_t req{};
    req.pid = pid;
    if (!send(ioctl::PEB_OF, &req, sizeof(req))) return 0;
    return req.out_base;
}

std::uint64_t driver_t::module_base_user(std::uint32_t pid, const wchar_t* name, std::uint64_t dtb) {
    if (!name) return 0;
    umodbase_request_t req{};
    req.pid = pid;
    req.name = name;
    req.out_base = 0;
    req.dtb = dtb;
    if (!send(ioctl::UMODBASE, &req, sizeof(req))) return 0;
    return req.out_base;
}

std::uint64_t driver_t::module_base_kernel(const char* name) {
    if (!name) return 0;
    kmodbase_request_t req{};
    req.name = name;
    req.out_base = 0;
    if (!send(ioctl::KMODBASE, &req, sizeof(req))) return 0;
    return req.out_base;
}

bool driver_t::alloc(std::uint32_t pid, std::uint64_t* base, std::uint64_t* size,
                     std::uint32_t type, std::uint32_t protect) {
    if (!base || !size || !*size) return false;
    alloc_request_t req{};
    req.pid = pid;
    req.base = *base;
    req.size = *size;
    req.type = type;
    req.protect = protect;
    if (!send(ioctl::ALLOC, &req, sizeof(req))) return false;
    *base = req.base;
    *size = req.size;
    return true;
}

bool driver_t::protect_mem(std::uint32_t pid, std::uint64_t* base, std::uint64_t* size,
                           std::uint32_t protect, std::uint32_t* out_old) {
    if (!base || !size || !*size) return false;
    protect_request_t req{};
    req.pid = pid;
    req.base = *base;
    req.size = *size;
    req.protect = protect;
    if (!send(ioctl::PROTECT, &req, sizeof(req))) return false;
    *base = req.base;
    *size = req.size;
    if (out_old) *out_old = req.out_old;
    return true;
}

bool driver_t::cross_read(std::uint32_t pid, std::uint64_t src, void* dst, std::size_t len) {
    if (!dst || !len) return false;
    xread_request_t req{};
    req.pid = pid;
    req.src = src;
    req.dst = reinterpret_cast<std::uint64_t>(dst);
    req.size = len;
    return send(ioctl::XREAD, &req, sizeof(req));
}

bool driver_t::key_state(std::uint64_t vk, bool down) {
    keystate_request_t req{};
    req.vk = vk;
    req.down = down ? 1 : 0;
    return send(ioctl::KEYSTATE, &req, sizeof(req));
}

bool driver_t::mouse_relative(std::int32_t dx, std::int32_t dy,
                              std::uint16_t button_flags, std::uint16_t button_data) {
    mouse_request_t req{};
    req.dx = dx;
    req.dy = dy;
    req.button_flags = button_flags;
    req.button_data = button_data;
    return send(ioctl::MOUSE, &req, sizeof(req));
}
bool driver_t::kernel_read(std::uint64_t va, void* buf, std::size_t len) {
    if (!buf || !dev_ || !kernel_range_ok(va, len)) return false;
    const std::uint64_t dtb = proven_kernel_dtb(*this);
    if (!dtb) return false;
    return phys_read(dtb, va, buf, len);
}

bool driver_t::hide_from_module_list() {
    if (staged_module_name_.empty()) { last_error_ = "no staged module identity"; return false; }
    const std::uint64_t self_base = module_base_kernel(staged_module_name_.c_str());
    if (!self_base) { last_error_ = "own kernel base not found"; return false; }

    const std::uint64_t nt = module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!nt) { last_error_ = "ntoskrnl base not found"; return false; }

    // parse the export directory for PsLoadedModuleList, 40 bytes per kernel read
    std::uint8_t dos[0x40] = {};
    if (!kernel_read(nt, dos, sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z') {
        last_error_ = "nt header unreadable";
        return false;
    }
    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(dos + 0x3C);
    std::uint8_t opt[0x40] = {};
    if (!kernel_read(nt + e_lfanew + 0x18, opt, sizeof(opt))) {
        last_error_ = "optional header unreadable";
        return false;
    }
    const std::uint32_t export_rva = *reinterpret_cast<const std::uint32_t*>(opt + 0x70);
    if (!export_rva) { last_error_ = "no export directory"; return false; }

    std::uint8_t dir[0x28] = {};
    if (!kernel_read(nt + export_rva, dir, sizeof(dir))) {
        last_error_ = "export dir unreadable";
        return false;
    }
    const std::uint32_t num_names = *reinterpret_cast<const std::uint32_t*>(dir + 0x18);
    const std::uint32_t functions_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x1C);
    const std::uint32_t names_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x20);
    const std::uint32_t ordinals_rva = *reinterpret_cast<const std::uint32_t*>(dir + 0x24);

    std::uint64_t list_va = 0;
    for (std::uint32_t i = 0; i < num_names && !list_va; ++i) {
        std::uint8_t name_rva_buf[8] = {};
        if (!kernel_read(nt + names_rva + i * 4, name_rva_buf, 4)) break;
        const std::uint32_t name_rva = *reinterpret_cast<const std::uint32_t*>(name_rva_buf);
        char name[24] = {};
        if (!kernel_read(nt + name_rva, name, sizeof(name) - 1)) continue;
        if (std::strncmp(name, "PsLoadedModuleList", 18) != 0 || name[18] != '\0') continue;
        std::uint8_t ord_buf[4] = {};
        if (!kernel_read(nt + ordinals_rva + i * 2, ord_buf, 2)) break;
        const std::uint16_t ord = *reinterpret_cast<const std::uint16_t*>(ord_buf);
        std::uint8_t fn_buf[4] = {};
        if (!kernel_read(nt + functions_rva + ord * 4, fn_buf, 4)) break;
        const std::uint32_t fn_rva = *reinterpret_cast<const std::uint32_t*>(fn_buf);
        list_va = nt + fn_rva;
    }
    if (!list_va) { last_error_ = "PsLoadedModuleList not resolved"; return false; }

    // walk the load order list, find our entry by DllBase (+0x30)
    std::uint8_t head_buf[8] = {};
    if (!kernel_read(list_va, head_buf, 8)) { last_error_ = "list head unreadable"; return false; }
    std::uint64_t cur = *reinterpret_cast<const std::uint64_t*>(head_buf);
    auto is_canonical_kernel = [](std::uint64_t va) {
        return (va >> 48) == 0xFFFF && va > 0xFFFF800000000000ull;
    };
    for (int guard = 0; guard < 1024 && is_canonical_kernel(cur) && cur != list_va; ++guard) {
        std::uint8_t entry[0x38] = {};
        if (!kernel_read(cur, entry, sizeof(entry))) break;
        const std::uint64_t flink = *reinterpret_cast<const std::uint64_t*>(entry + 0x00);
        const std::uint64_t blink = *reinterpret_cast<const std::uint64_t*>(entry + 0x08);
        const std::uint64_t dll_base = *reinterpret_cast<const std::uint64_t*>(entry + 0x30);
        if (!is_canonical_kernel(flink) || !is_canonical_kernel(blink)) break;
        if (dll_base == self_base) {
            // harden: keep the entry in the list (no count mismatch for
            // bidirectional walk detection) but overwrite DllBase to point
            // at a legitimate module and zero the size, so scanners see a
            // duplicate entry referencing a real driver instead of ours
            const std::uint64_t legit_base = module_base_kernel("crashdmp.sys");
            const std::uint64_t replace_base = legit_base ? legit_base
                : module_base_kernel("intelpep.sys");
            if (!replace_base) {
                // no legit module found to mimic, fall back to unlink
                std::uint8_t pre[8] = {};
                std::uint64_t at_flink_blink = 0, at_blink_flink = 0;
                if (kernel_read(flink + 8, pre, 8)) {
                    std::memcpy(&at_flink_blink, pre, sizeof(at_flink_blink));
                }
                if (kernel_read(blink, pre, 8)) {
                    std::memcpy(&at_blink_flink, pre, sizeof(at_blink_flink));
                }
                if (at_flink_blink == cur && at_blink_flink == cur) {
                    if (kernel_write(flink + 8, &blink, sizeof(blink)) &&
                        kernel_write(blink, &flink, sizeof(flink))) {
                        last_error_.clear();
                        return true;
                    }
                }
                last_error_ = "no mimic target and unlink validation failed";
                return false;
            }

            // overwrite DllBase and zero SizeOfImage: validate that the
            // current DllBase is our known base (proves offset is right)
            if (dll_base != self_base) {
                last_error_ = "DllBase offset mismatch";
                return false;
            }
            if (!kernel_write(cur + 0x30, &replace_base, sizeof(replace_base))) {
                last_error_ = "DllBase overwrite failed";
                return false;
            }
            const std::uint32_t zero_size = 0;
            if (!kernel_write(cur + 0x40, &zero_size, sizeof(zero_size))) {
                // restore DllBase on partial failure
                kernel_write(cur + 0x30, &self_base, sizeof(self_base));
                last_error_ = "SizeOfImage zero failed";
                return false;
            }

            // verify the overwrite landed
            std::uint8_t verify[8] = {};
            if (kernel_read(cur + 0x30, verify, 8)) {
                if (*reinterpret_cast<const std::uint64_t*>(verify) == replace_base) {
                    last_error_.clear();
                    return true;
                }
            }
            last_error_ = "DllBase overwrite verification failed";
            return false;
        }
        cur = flink;
    }
    last_error_ = "own entry not found in module list";
    return false;
}

bool driver_t::rename_device(const wchar_t* new_name) {
    if (!new_name || !*new_name) return false;
    const std::size_t name_len = std::wcslen(new_name);
    if (name_len > 8) return false;

    // the device object name lives in OBJECT_HEADER_NAME_INFO (kernel pool,
    // rw). we cannot find the device object va from user mode without either
    // walking the irp stack (unreachable) or the driver object chain (the
    // driver object is unnamed, created via IoCreateDriver). instead we
    // take the practical path: zero the utf-16 string constants in the
    // driver's .rdata via phys write (maps physical as rw regardless of
    // the original page protection). this does not rename the live object
    // but ensures any code that reads the driver image for the device name
    // (including the driver itself if re-entered) finds zeros. combined
    // with dkom hardening and the scrub, the device name string is gone
    // from every location we can reach.
    const std::uint64_t drv_base = module_base_kernel(staged_module_name_.c_str());
    if (!drv_base) { last_error_ = "driver base not found for rename"; return false; }

    // resolve a dtb that can write kernel vas (same logic as scrub_driver)
    const std::uint64_t nt = module_base_kernel(XORSTR("ntoskrnl.exe"));
    if (!nt) { last_error_ = "ntoskrnl base not found"; return false; }
    auto maps_kernel = [&](std::uint64_t dtb) {
        std::uint8_t mz[2] = {};
        return dtb && phys_read(dtb, nt, mz, sizeof(mz)) &&
               mz[0] == 'M' && mz[1] == 'Z';
    };
    std::uint64_t kdtb = solve_dtb(4) & ~0xFFFull;
    if (!maps_kernel(kdtb)) {
        kdtb = solve_dtb(GetCurrentProcessId());
        if (!maps_kernel(kdtb)) kdtb = 0;
    }
    if (!kdtb) { last_error_ = "no kernel-capable dtb for rename"; return false; }

    // scan the driver image for the utf-16 strings and overwrite them
    const std::uint64_t drv_size = 0x8000;
    std::vector<std::uint8_t> image(drv_size);
    if (!kernel_read(drv_base, image.data(), drv_size)) {
        last_error_ = "driver image unreadable for rename";
        return false;
    }

    const wchar_t* device_needle = XORWSTR(L"\\Device\\WinNotify");
    const wchar_t* dos_needle = XORWSTR(L"\\DosDevices\\WinNotify");
    bool wiped_any = false;
    std::size_t device_leaf_off = 0;   // offset of the "WinNotify" leaf in the device string

    for (const auto& needle : {device_needle, dos_needle}) {
        const std::size_t needle_bytes = std::wcslen(needle) * sizeof(wchar_t);
        // the leaf starts after the last backslash in the needle
        const wchar_t* leaf = std::wcsrchr(needle, L'\\');
        const std::size_t leaf_off_in_needle = leaf ? (leaf + 1 - needle) * sizeof(wchar_t) : 0;
        for (std::size_t i = 0; i + needle_bytes <= image.size(); i += 2) {
            if (std::memcmp(image.data() + i, needle, needle_bytes) == 0) {
                std::vector<std::uint8_t> zeros(needle_bytes + 2, 0);
                if (phys_write(kdtb, drv_base + i, zeros.data(), zeros.size())) {
                    wiped_any = true;
                    // record the first device leaf for the replacement write
                    if (!device_leaf_off && needle == device_needle)
                        device_leaf_off = i + leaf_off_in_needle;
                }
            }
        }
    }

    // write the replacement name at the exact leaf offset found during the wipe
    if (wiped_any && name_len > 0 && device_leaf_off) {
        std::vector<std::uint8_t> name_bytes(name_len * sizeof(wchar_t) + 2, 0);
        std::memcpy(name_bytes.data(), new_name, name_len * sizeof(wchar_t));
        phys_write(kdtb, drv_base + device_leaf_off, name_bytes.data(), name_bytes.size());
    }

    if (wiped_any) {
        last_error_.clear();
        return true;
    }
    last_error_ = "device name strings not found in driver image";
    return false;
}

bool driver_t::wipe_own_headers() {
    if (staged_module_name_.empty()) return false;
    const std::uint64_t system_dtb = solve_dtb(4);
    if (!system_dtb) return false;
    const std::uint64_t base = module_base_kernel(staged_module_name_.c_str());
    if (!base) return false;

    std::uint8_t hdr[0x400] = {};
    if (!phys_read(system_dtb, base, hdr, sizeof(hdr))) return false;
    if (hdr[0] != 'M' || hdr[1] != 'Z') return false;
    const std::uint32_t e_lfanew = *reinterpret_cast<const std::uint32_t*>(hdr + 0x3C);
    if (e_lfanew == 0 || static_cast<std::size_t>(e_lfanew) + 0x18 > sizeof(hdr)) return false;
    const std::uint16_t opt_size = *reinterpret_cast<const std::uint16_t*>(hdr + e_lfanew + 20);
    const std::uint16_t nsec = *reinterpret_cast<const std::uint16_t*>(hdr + e_lfanew + 6);
    std::size_t end = static_cast<std::size_t>(e_lfanew) + 24 + opt_size +
                      static_cast<std::size_t>(nsec) * 40;
    if (end > sizeof(hdr)) end = sizeof(hdr);

    std::uint8_t zeros[0x400] = {};
    return phys_write(system_dtb, base, zeros, end);
}

std::uint32_t find_process_by_name(const wchar_t* image_name) {
    if (!image_name) return 0;
    static const nt_query_fn query = ntdll_fn<nt_query_fn>("NtQuerySystemInformation");
    if (!query) return 0;

    struct sys_process_entry_t {
        ULONG         next_entry_offset;
        ULONG         number_of_threads;
        std::uint8_t  pad[0x30];
        USHORT        name_length;
        USHORT        name_max;
        wchar_t*      name_buffer;
        std::uint8_t  tail[8];
        std::uint64_t pid;
    };
    static_assert(sizeof(sys_process_entry_t) == 0x58);

    ULONG size = 1u << 16;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::vector<std::uint8_t> buf(size);
        ULONG need = 0;
        const LONG st = query(5, buf.data(), size, &need);
        if (st >= 0) {
            const std::uint8_t* it = buf.data();
            const std::uint8_t* end = buf.data() + need;
            while (it + 0x58 <= end) {
                const auto* entry = reinterpret_cast<const sys_process_entry_t*>(it);
                if (entry->name_buffer && entry->name_length > 0 && entry->pid != 0) {
                    const std::wstring candidate(entry->name_buffer,
                                                 entry->name_length / sizeof(wchar_t));
                    if (_wcsicmp(candidate.c_str(), image_name) == 0)
                        return static_cast<std::uint32_t>(entry->pid);
                }
                if (entry->next_entry_offset == 0) break;
                it += entry->next_entry_offset;
            }
            return 0;
        }
        if (need > size) { size = need + (need >> 1); continue; }
        size *= 2;
    }
    return 0;
}

} // namespace slop::core::runtime::winotify
