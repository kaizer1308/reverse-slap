// src/core/runtime/winotify_driver.hpp
// client for the WHQL-signed WinNotify kernel driver (signeddrv.sys)
// loads through the legit NtLoadDriver path, no mapper, no unsigned load,
// every op rides ioctls so no handle ever lands in the target

#pragma once

#include <cstdint>
#include <string>

namespace slop::core::runtime::winotify {

// signeddrv.sys ioctl codes (METHOD_BUFFERED, FILE_ANY_ACCESS, base 0x222000)
namespace ioctl {
    constexpr std::uint32_t base = 0x222000u;
    constexpr std::uint32_t make(std::uint32_t function) noexcept {
        return (0x22u << 16) | (function << 2);
    }
    constexpr std::uint32_t KREAD40   = make(0x810);   // 0x222040 kernel va read, 40 bytes
    constexpr std::uint32_t PHYS_READ = make(0x800);   // 0x222000 phys read under supplied dtb
    constexpr std::uint32_t PHYS_WRITE= make(0x801);   // 0x222004 phys write under supplied dtb
    constexpr std::uint32_t UMODBASE  = make(0x802);   // 0x222008 user module base by name (peb walk via phys)
    constexpr std::uint32_t KMODBASE  = make(0x803);   // 0x22200C kernel module base by name
    constexpr std::uint32_t BIGPOOL   = make(0x804);   // 0x222010 big-pool marker scan
    constexpr std::uint32_t DTB       = make(0x805);   // 0x222014 pid -> dtb (kpti aware)
    constexpr std::uint32_t KWRITE    = make(0x811);   // 0x222044 kernel memmove
    constexpr std::uint32_t BASE_OF   = make(0x812);   // 0x222048 psGetProcessSectionBaseAddress
    constexpr std::uint32_t PEB_OF    = make(0x813);   // 0x22204C psGetProcessPeb
    constexpr std::uint32_t KEYSTATE  = make(0x814);   // 0x222050 win32k async key state
    constexpr std::uint32_t MOUSE     = make(0x815);   // 0x222054 mouclass queue mouse packet
    constexpr std::uint32_t ALLOC     = make(0x816);   // 0x222058 remote ZwAllocateVirtualMemory
    constexpr std::uint32_t PROTECT   = make(0x817);   // 0x22205C remote ZwProtectVirtualMemory
    constexpr std::uint32_t XREAD     = make(0x818);   // 0x222060 MmCopyVirtualMemory target -> caller
}

// ioctl request layouts (verified against the dispatch)
#pragma pack(push, 1)
struct phys_request_t {
    std::uint32_t flag;
    std::uint32_t pad0;
    std::uint64_t va;
    std::uint64_t buffer;
    std::uint64_t size;
    std::uint64_t dtb;
};
static_assert(sizeof(phys_request_t) == 40);

struct dtb_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    std::uint64_t out_dtb;
    std::uint8_t  strict;
    std::uint8_t  pad1[7];
};
static_assert(sizeof(dtb_request_t) == 24);

struct umodbase_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    const wchar_t* name;
    std::uint64_t out_base;
    std::uint64_t dtb;
};
static_assert(sizeof(umodbase_request_t) == 32);

struct kmodbase_request_t {
    const char* name;
    std::uint64_t pad0;
    std::uint64_t out_base;
};
static_assert(sizeof(kmodbase_request_t) == 24);

struct kwrite_request_t {
    std::uint64_t src;
    std::uint64_t len;
    std::uint64_t dst;
};
static_assert(sizeof(kwrite_request_t) == 24);

struct base_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    std::uint64_t out_base;
};
static_assert(sizeof(base_request_t) == 16);

struct keystate_request_t {
    std::uint64_t vk;
    std::uint8_t  down;
    std::uint8_t  pad0[7];
};
static_assert(sizeof(keystate_request_t) == 16);

struct mouse_request_t {
    std::int32_t  dx;
    std::int32_t  dy;
    std::uint16_t button_flags;
    std::uint16_t button_data;
};
static_assert(sizeof(mouse_request_t) == 12);

struct alloc_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    std::uint64_t base;
    std::uint64_t size;
    std::uint32_t type;
    std::uint32_t pad1;
    std::uint32_t protect;
    std::uint32_t pad2;
};
static_assert(sizeof(alloc_request_t) == 40);

struct protect_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    std::uint64_t base;
    std::uint64_t size;
    std::uint32_t protect;
    std::uint32_t out_old;
};
static_assert(sizeof(protect_request_t) == 32);

struct xread_request_t {
    std::uint32_t pid;
    std::uint32_t pad0;
    std::uint64_t src;
    std::uint64_t dst;
    std::uint64_t size;
};
static_assert(sizeof(xread_request_t) == 32);
#pragma pack(pop)

class driver_t {
public:
    driver_t() = default;
    ~driver_t();
    driver_t(const driver_t&)            = delete;
    driver_t& operator=(const driver_t&) = delete;

    // stage + NtLoadDriver + open device, idempotent
    bool connect();
    void disconnect();
    bool is_connected() const noexcept { return dev_ != nullptr; }

    // NtUnloadDriver + registry key + staged file cleanup
    bool unload();

    // primitives, all require connect()
    std::uint64_t solve_dtb(std::uint32_t pid);
    bool phys_read(std::uint64_t dtb, std::uint64_t va, void* buf, std::size_t len);
    bool phys_write(std::uint64_t dtb, std::uint64_t va, const void* buf, std::size_t len);
    bool kernel_write(std::uint64_t dst, const void* src, std::size_t len);
    std::uint64_t base_of(std::uint32_t pid);
    std::uint64_t peb_of(std::uint32_t pid);
    std::uint64_t module_base_user(std::uint32_t pid, const wchar_t* name, std::uint64_t dtb);
    std::uint64_t module_base_kernel(const char* name);
    bool alloc(std::uint32_t pid, std::uint64_t* base, std::uint64_t* size,
               std::uint32_t type, std::uint32_t protect);
    bool protect_mem(std::uint32_t pid, std::uint64_t* base, std::uint64_t* size,
                     std::uint32_t protect, std::uint32_t* out_old);
    bool cross_read(std::uint32_t pid, std::uint64_t src, void* dst, std::size_t len);
    bool key_state(std::uint64_t vk, bool down);
    bool mouse_relative(std::int32_t dx, std::int32_t dy,
                        std::uint16_t button_flags, std::uint16_t button_data);

    // kernel va read/write via the System DTB and the physical copy path.
    // the raw 0x222040/0x222044 handlers are not used: they memcpy a kernel
    // va with no exception handler.
    bool kernel_read(std::uint64_t va, void* buf, std::size_t len);

    // dkom unlink of the loaded image from PsLoadedModuleList; the driver
    // object and dispatch stay alive, module enumerations stop seeing it
    bool hide_from_module_list();



    // close the device handle while idle: no standing handle in our table,
    // no ioctl traffic possible until resume
    void park();
    bool resume();


    // validated kernel write: pre-reads the target, sanity-checks it looks
    // like the expected kind of memory, writes, reads back and verifies
    // only the intended bytes changed; aborts without writing on any
    // validation failure
    bool kernel_write_checked(std::uint64_t va, const void* buf, std::size_t len,
                              std::uint64_t expect_mask, std::uint64_t expect_value);
    const std::string& staged_module_name() const noexcept { return staged_module_name_; }

    // rename the device object from WinNotify to a shorter plausible name
    // by walking the driver object chain to find the OBJECT_HEADER_NAME_INFO
    // buffer in kernel pool and overwriting the string in place
    bool rename_device(const wchar_t* new_name);
    bool wipe_own_headers();
    // raw ioctl access for callers that need driver specific codes
    bool send(std::uint32_t code, void* buf, std::uint32_t size) noexcept;

    const std::wstring& staged_path() const noexcept { return staged_path_; }
    const std::string&  last_error() const noexcept { return last_error_; }

    void* native_handle() const noexcept { return dev_; }
private:
    bool stage_and_load();

    bool device_present() const noexcept;

    void*         dev_ = nullptr;
    std::wstring  service_key_;
    std::wstring  staged_path_;
    std::string   staged_module_name_;
    std::string   last_error_;
};

// process discovery without toolhelp handles to the target
std::uint32_t find_process_by_name(const wchar_t* image_name);

} // namespace slop::core::runtime::winotify
