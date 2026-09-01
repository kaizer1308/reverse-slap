// src/core/runtime/backend_kernel.cpp
// kernel backend over the driver, everything rides ioctls so no handles
// ever land in the target where a handle scan could spot them

#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/voyager_comm.h"
#include "core/infra/settings.hpp"
#include "core/infra/limits.hpp"

#include <windows.h>

namespace slop::core::runtime {

namespace {

constexpr uint32_t kMaxHwbpFanout = 64;

// a fake handle value so valid() is happy and detach knows not to close it
inline void* kernel_sentinel() noexcept { return reinterpret_cast<void*>(0x1); }

// tctx mask bits, we only carry gprs rip and flags so bits 0 to 17
constexpr uint64_t kGprMask = (1ULL << 18) - 1;

io_result_t full_or_partial(bool ok, size_t bytes) {
    if (ok && bytes > 0) return { true, bytes, 0 };
    return { false, bytes, ERROR_PARTIAL_COPY };
}

// read a utf16 counted string through the driver
std::string read_remote_utf16(voyager::device_t& dev, uint64_t addr, uint16_t wlen) {
    std::string out;
    if (!addr || !wlen) return out;
    wlen = static_cast<uint16_t>(std::min<uint32_t>(wlen, 512));
    std::vector<uint8_t> raw(size_t(wlen) * 2, 0);
    if (dev.read_raw(addr, raw.data(), raw.size()) != raw.size()) return out;
    int n = WideCharToMultiByte(CP_UTF8, 0,
                                reinterpret_cast<LPCWCH>(raw.data()),
                                wlen, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return out;
    out.resize(size_t(n));
    WideCharToMultiByte(CP_UTF8, 0,
                        reinterpret_cast<LPCWCH>(raw.data()), wlen,
                        out.data(), n, nullptr, nullptr);
    return out;
}

} // namespace

// peb module walk that catches modules hidden from toolhelp
std::vector<peb_module_info_t> kernel_peb_modules(voyager::device_t& dev) {
    std::vector<peb_module_info_t> out;
    voyager::device_t::peb_info peb{};
    if (!dev.read_peb(peb) || peb.ldr_address == 0) return out;

    const uint64_t head = peb.ldr_address + 0x10;   // InLoadOrderModuleList
    uint64_t cur = dev.read<uint64_t>(head);
    constexpr int kMaxIter = 1024;
    int iter = 0;
    while (cur && cur != head && iter++ < kMaxIter) {
        // InLoadOrder links sit at entry+0x00, so cur IS the entry base
        const uint64_t base        = dev.read<uint64_t>(cur + 0x30);
        const uint64_t entry_point = dev.read<uint64_t>(cur + 0x38);
        const uint32_t size        = dev.read<uint32_t>(cur + 0x40);
        const std::string name     = read_remote_utf16(
            dev,
            dev.read<uint64_t>(cur + 0x60),
            static_cast<uint16_t>(dev.read<uint16_t>(cur + 0x58) / 2));
        const std::string path     = read_remote_utf16(
            dev,
            dev.read<uint64_t>(cur + 0x50),
            static_cast<uint16_t>(dev.read<uint16_t>(cur + 0x48) / 2));
        const uint32_t flags       = dev.read<uint32_t>(cur + 0x68);
        const uint64_t next        = dev.read<uint64_t>(cur);

        if (base != 0 || !name.empty()) {
            peb_module_info_t m;
            m.base        = base;
            m.entry_point = entry_point;
            m.size        = size;
            m.name        = name;
            m.path        = path;
            m.flags       = flags;
            out.push_back(std::move(m));
        }
        if (next == cur) break;
        cur = next;
    }
    return out;
}

backend_kernel_t::backend_kernel_t() = default;

backend_kernel_t::~backend_kernel_t() {
    // release ownership at teardown, the os reclaims the handle anyway
    (void)dev_.release();
}

bool backend_kernel_t::connect() {
    if (dev_ && dev_->is_connected()) return true;
    if (!dev_) dev_ = std::make_unique<voyager::device_t>();
    if (!dev_->connect()) {
        hwbp_supported_ = false;
        return false;
    }
    hwbp_supported_ = true;
    // solve the kernel dtb up front so kernel reads work before any attach, non fatal when it fails
    if (dev_->get_kernel_dtb() == 0) dev_->solve_kernel_dtb();
    return true;
}

void backend_kernel_t::disconnect() {
    if (dev_) {
        if (dev_->is_connected()) dev_->clear_process_context();
        dev_->disconnect();
    }
    hwbp_supported_ = false;
}

// identity

backend_kind_t backend_kernel_t::kind() const noexcept {
    return backend_kind_t::kernel;
}

const char* backend_kernel_t::badge() const noexcept {
    return "kernel";
}

// attach and detach

bool backend_kernel_t::ready_for_pid(uint32_t pid) const noexcept {
    return dev_ && dev_->is_connected() && pid != 0 &&
           dev_->get_process_id() == pid && dev_->get_dtb() != 0;
}

target_handle_t& backend_kernel_t::ensure_user_handle(target_handle_t& h) {
    if (h.valid() && h.native != kernel_sentinel()) return h;   // real handle
    if (h.valid() && h.native == kernel_sentinel()) h.native = nullptr;
    h = user_.attach(h.pid);
    return h;
}

target_handle_t backend_kernel_t::attach(uint32_t pid) {
    if (!connect()) return {};

    dev_->clear_process_context();
    dev_->set_process_id(pid);
    const uint64_t dtb = dev_->solve_dtb_for_pid(pid);
    if (dtb != 0) {
        // solve_dtb_for_pid returns the raw value; caching is the caller's job
        dev_->set_dtb(dtb);
    }
    if (dtb == 0 || dev_->get_dtb() == 0) {
        // Driver could not resolve the target's DTB, kernel attach failed
        return {};
    }

    // No user-mode handle is opened: every op below routes through the
    // driver, so the target's handle table stays clean (nothing for
    // NtQuerySystemInformation handle scans / ObRegisterCallbacks to see)
    // Zero BeingDebugged / NtGlobalFlag unless the user opted out, belt and
    // braces against PEB-based checks even when nothing is being debugged
    if (infra::settings::stealth_peb_spoof()) dev_->spoof_debug_flags();

    return target_handle_t{ kernel_sentinel(), pid };
}

void backend_kernel_t::detach(target_handle_t& h) {
    if (h.valid() && dev_ && dev_->is_connected()) {
        dev_->clear_process_context();
    }
    if (h.native != nullptr && h.native != kernel_sentinel()) {
        // A lazy real handle (from ensure_user_handle), close it properly
        user_.detach(h);
    } else {
        h.native = nullptr;
        h.pid    = 0;
    }
}

// Memory

io_result_t backend_kernel_t::read_memory(const target_handle_t& h, uintptr_t addr,
                                          void* buf, size_t len) {
    if (!h.valid())          return { false, 0, ERROR_INVALID_HANDLE };
    if (!ready_for_pid(h.pid)) return { false, 0, ERROR_NOT_READY };
    const size_t got = dev_->read_raw(addr, buf, len);
    return full_or_partial(got == len, got);
}

io_result_t backend_kernel_t::write_memory(const target_handle_t& h, uintptr_t addr,
                                           const void* buf, size_t len) {
    if (!h.valid())          return { false, 0, ERROR_INVALID_HANDLE };
    if (!ready_for_pid(h.pid)) return { false, 0, ERROR_NOT_READY };
    const size_t put = dev_->write_raw(addr, buf, len);
    return full_or_partial(put == len, put);
}

io_result_t backend_kernel_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                             size_t len, uint32_t new_prot,
                                             uint32_t* old_prot) {
    if (!h.valid())          return { false, 0, ERROR_INVALID_HANDLE };
    if (!ready_for_pid(h.pid)) return { false, 0, ERROR_NOT_READY };
    uint32_t old = 0;
    if (!dev_->protect_memory(addr, len, new_prot, &old))
        return { false, 0, GetLastError() };
    if (old_prot) *old_prot = old;
    return { true, len, 0 };
}

io_result_t backend_kernel_t::allocate_memory(const target_handle_t& h, uintptr_t hint,
                                              size_t len, uint32_t prot,
                                              uintptr_t* out_addr) {
    (void)hint;   // driver picks the address
    (void)prot;   // driver default (rw/x per its allocation policy)
    if (!h.valid())            return { false, 0, ERROR_INVALID_HANDLE };
    if (!ready_for_pid(h.pid)) return { false, 0, ERROR_NOT_READY };
    const uint64_t allocated = dev_->allocate_memory(len);
    if (allocated == 0) return { false, 0, GetLastError() };
    if (out_addr) *out_addr = static_cast<uintptr_t>(allocated);
    return { true, len, 0 };
}

io_result_t backend_kernel_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    if (!h.valid())            return { false, 0, ERROR_INVALID_HANDLE };
    if (!ready_for_pid(h.pid)) return { false, 0, ERROR_NOT_READY };
    if (!dev_->free_memory(addr)) return { false, 0, GetLastError() };
    return { true, 0, 0 };
}

// Enumeration (driver)

enum_result_t<region_info_t> backend_kernel_t::enum_regions(const target_handle_t& h) {
    enum_result_t<region_info_t> r;
    if (!h.valid()) { r.error = ERROR_INVALID_HANDLE; return r; }
    if (!ready_for_pid(h.pid)) { r.error = ERROR_NOT_READY; return r; }

    r.ok = true;
    for (const auto& e : dev_->enumerate_memory_regions(0, 0, true)) {
        if (r.items.size() >= infra::limits::max_regions_enumerated) break;
        region_info_t ri;
        ri.base    = static_cast<uintptr_t>(e.base);
        ri.size    = static_cast<size_t>(e.size);
        ri.protect = e.protect;
        ri.state   = e.state;
        ri.type    = e.type;
        r.items.push_back(ri);
    }
    return r;
}

enum_result_t<thread_info_t> backend_kernel_t::enum_threads(uint32_t pid) {
    enum_result_t<thread_info_t> r;
    if (pid == 0) { r.error = ERROR_INVALID_PARAMETER; return r; }

    if (ready_for_pid(pid)) {
        // TENUM lists the threads of the device's current target context
        r.ok = true;
        for (const auto& t : dev_->enumerate_threads()) {
            thread_info_t ti;
            ti.tid      = t.tid;
            ti.owner_pid = pid;
            ti.start_address = 0;   // TENUM exposes tid/state/rip only
            r.items.push_back(ti);
        }
        return r;
    }

    // Foreign pid (no driver context): Toolhelp is a system-wide snapshot  
    // it never opens a handle in the target, so it stays stealth-safe
    return user_.enum_threads(pid);
}

enum_result_t<module_info_t> backend_kernel_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> r;
    if (!h.valid()) { r.error = ERROR_INVALID_HANDLE; return r; }
    if (!ready_for_pid(h.pid)) { r.error = ERROR_NOT_READY; return r; }

    r.ok = true;
    for (const auto& m : kernel_peb_modules(*dev_)) {
        module_info_t mi;
        mi.base = static_cast<uintptr_t>(m.base);
        mi.size = m.size;
        mi.name = m.name;
        mi.path = m.path;
        r.items.push_back(std::move(mi));
    }
    return r;
}

// Thread context: both directions through the kernel

io_result_t backend_kernel_t::get_thread_context(uint32_t tid, thread_context_t& ctx) {
    if (!dev_ || !dev_->is_connected()) return { false, 0, ERROR_NOT_READY };

    voyager::device_t::thread_context kctx{};
    if (!dev_->get_thread_context(tid, kctx)) return { false, 0, GetLastError() };

    ctx.rip = kctx.rip;   ctx.rsp = kctx.rsp;   ctx.rbp = kctx.rbp;
    ctx.rax = kctx.rax;   ctx.rbx = kctx.rbx;   ctx.rcx = kctx.rcx;
    ctx.rdx = kctx.rdx;   ctx.rsi = kctx.rsi;   ctx.rdi = kctx.rdi;
    ctx.r8  = kctx.r8;    ctx.r9  = kctx.r9;    ctx.r10 = kctx.r10;
    ctx.r11 = kctx.r11;   ctx.r12 = kctx.r12;   ctx.r13 = kctx.r13;
    ctx.r14 = kctx.r14;   ctx.r15 = kctx.r15;
    ctx.flags = kctx.rflags;
    return { true, 0, 0 };
}

io_result_t backend_kernel_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    if (!dev_ || !dev_->is_connected()) return { false, 0, ERROR_NOT_READY };

    voyager::device_t::thread_context kctx{};
    kctx.rax = ctx.rax;   kctx.rbx = ctx.rbx;   kctx.rcx = ctx.rcx;
    kctx.rdx = ctx.rdx;   kctx.rsi = ctx.rsi;   kctx.rdi = ctx.rdi;
    kctx.rbp = ctx.rbp;   kctx.rsp = ctx.rsp;
    kctx.r8  = ctx.r8;    kctx.r9  = ctx.r9;    kctx.r10 = ctx.r10;
    kctx.r11 = ctx.r11;   kctx.r12 = ctx.r12;   kctx.r13 = ctx.r13;
    kctx.r14 = ctx.r14;   kctx.r15 = ctx.r15;
    kctx.rip = ctx.rip;   kctx.rflags = ctx.flags;

    // System-thread worker route: no OpenThread handle, thread suspended in
    // the kernel while the CONTEXT is swapped
    if (!dev_->set_thread_context(tid, kctx, kGprMask))
        return { false, 0, GetLastError() };
    return { true, 0, 0 };
}

// Query

arch_t backend_kernel_t::query_arch(const target_handle_t& h) {
    if (h.valid() && ready_for_pid(h.pid)) {
        // Machine field from the target's on-disk-image NT headers, read
        // through the driver, no handle needed
        voyager::device_t::peb_info peb{};
        if (dev_->read_peb(peb) && peb.image_base != 0) {
            IMAGE_DOS_HEADER dos{};
            if (dev_->read_raw(peb.image_base, &dos, sizeof(dos)) == sizeof(dos) &&
                dos.e_magic == IMAGE_DOS_SIGNATURE) {
                IMAGE_NT_HEADERS64 nt{};
                if (dev_->read_raw(peb.image_base + dos.e_lfanew, &nt, sizeof(nt)) == sizeof(nt)) {
                    switch (nt.FileHeader.Machine) {
                    case IMAGE_FILE_MACHINE_AMD64: return arch_t::x64;
                    case IMAGE_FILE_MACHINE_I386:  return arch_t::x86;
                    case IMAGE_FILE_MACHINE_ARM64: return arch_t::arm64;
                    default: break;
                    }
                }
            }
        }
    }

    // Fallback: lazy user handle (only opens when the kernel probe failed)
    if (h.valid()) {
        target_handle_t copy = h;
        const auto& uh = ensure_user_handle(copy);
        if (uh.valid()) return user_.query_arch(uh);
    }
    return arch_t::unknown;
}

// Hardware breakpoints

bool backend_kernel_t::apply_hw_breakpoint(uint32_t tid, uint32_t slot,
                                           uint64_t address, uint32_t length_bytes,
                                           bool set, uint32_t type) {
    if (!dev_ || !dev_->is_connected() || !hwbp_supported_) return false;
    if (slot > 3) return false;

    // The driver's hwbp helper takes the raw DR7 fields, not byte counts:
    // type: 0=exec, 1=write, 3=read/write. len: 0=1, 1=2, 2=8, 3=4 bytes
    // Execute breakpoints must carry LEN=0 or the CPU treats the combination
    // as undefined
    int len_field = 0;
    switch (length_bytes) {
    case 1:  len_field = 0; break;
    case 2:  len_field = 1; break;
    case 4:  len_field = 3; break;
    case 8:  len_field = 2; break;
    default: return false;
    }
    const int type_field = static_cast<int>(type & 3);

    if (tid == 0) {
        auto threads = dev_->enumerate_threads();
        uint32_t applied = 0;
        for (const auto& th : threads) {
            if (applied >= kMaxHwbpFanout) break;
            const bool ok = set
                ? dev_->set_hardware_breakpoint(th.tid, static_cast<int>(slot), address, type_field, len_field)
                : dev_->clear_hardware_breakpoint(th.tid, static_cast<int>(slot));
            if (ok) ++applied;
        }
        return applied != 0;
    }
    return set
        ? dev_->set_hardware_breakpoint(tid, static_cast<int>(slot), address, type_field, len_field)
        : dev_->clear_hardware_breakpoint(tid, static_cast<int>(slot));
}

bool backend_kernel_t::set_hw_breakpoint(uint32_t pid, uint32_t slot, uint32_t tid,
                                         uint64_t address, uint32_t length_bytes,
                                         uint32_t type) {
    if (!hwbp_supported_)      return false;
    if (!ready_for_pid(pid))   return false;
    return apply_hw_breakpoint(tid, slot, address, length_bytes, true, type);
}

bool backend_kernel_t::clear_hw_breakpoint(uint32_t pid, uint32_t slot, uint32_t tid) {
    if (!hwbp_supported_)      return false;
    if (!ready_for_pid(pid))   return false;
    return apply_hw_breakpoint(tid, slot, 0, 0, false, 0);
}

} // namespace slop::core::runtime
