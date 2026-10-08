#include "core/runtime/xorstr.hpp"
#include "core/runtime/lazy_import.hpp"
// src/core/runtime/backend_winotify.cpp
// every memory op rides the signed driver's phys path with the target dtb,
// so ac handle strips, ObRegisterCallbacks and ReadProcessMemory hooks never
// see anything. module enumeration walks the peb over phys reads, also fully
// driver side. threads/regions/contexts degrade to the lazy user handle like
// backend_kernel_t does, memory stays kernel for the whole session

#include "core/runtime/backend_winotify.hpp"

#include <windows.h>
#include <cstdio>

namespace slop::core::runtime {

namespace {

target_handle_t make_kernel_handle(uint32_t pid, uint64_t dtb) {
    target_handle_t h;
    h.pid = pid;
    h.native = reinterpret_cast<void*>(static_cast<uintptr_t>(dtb));
    return h;
}

std::string read_remote_utf16_phys(winotify::driver_t& dev, uint64_t dtb,
                                   uint64_t addr, uint16_t wlen) {
    std::string out;
    if (!addr || !wlen) return out;
    wlen = static_cast<uint16_t>((wlen > 512) ? 512 : wlen);
    std::vector<uint8_t> raw(size_t(wlen) * 2, 0);
    if (!dev.phys_read(dtb, addr, raw.data(), raw.size())) return out;
    const int need = WideCharToMultiByte(CP_UTF8, 0,
                                         reinterpret_cast<const wchar_t*>(raw.data()), wlen,
                                         nullptr, 0, nullptr, nullptr);
    if (need <= 0) return out;
    out.resize(size_t(need));
    WideCharToMultiByte(CP_UTF8, 0, reinterpret_cast<const wchar_t*>(raw.data()), wlen,
                        out.data(), need, nullptr, nullptr);
    return out;
}

io_result_t not_ready() { return { false, 0, ERROR_NOT_READY }; }

} // namespace

backend_winotify_t::~backend_winotify_t() = default;

bool backend_winotify_t::connect() {
    if (dev_ && dev_->is_connected()) return true;
    if (!dev_) dev_ = std::make_unique<winotify::driver_t>();
    return dev_->connect();
}

void backend_winotify_t::disconnect() {
    if (dev_) dev_->disconnect();
}

bool backend_winotify_t::wipe_headers() {
    if (!connect()) return false;
    return dev_->wipe_own_headers();
}

backend_kind_t backend_winotify_t::kind() const noexcept { return backend_kind_t::kernel; }

const char* backend_winotify_t::badge() const noexcept {
    static const std::string b = XORSTR("kernel (signed winotify)");
    return b.c_str();
}

uint64_t backend_winotify_t::handle_dtb(const target_handle_t& h) const noexcept {
    if (!h.valid()) return 0;
    return reinterpret_cast<uintptr_t>(h.native);
}

target_handle_t backend_winotify_t::attach(uint32_t pid) {
    if (!connect()) return {};

    const std::uint64_t peb = dev_->peb_of(pid);
    std::uint64_t ldr_truth = 0;
    if (peb) dev_->cross_read(pid, peb + 0x18, &ldr_truth, sizeof(ldr_truth));

    // the dtb scan walks physical ranges and can latch onto a stale pml4 from a
    // dead process sharing the same image base; cross check the candidate against
    // the attach path truth before trusting it for phys writes
    auto dtb_valid = [&](std::uint64_t dtb) {
        if (!dtb || !peb) return false;
        std::uint64_t ldr_phys = 0;
        if (!dev_->phys_read(dtb, peb + 0x18, &ldr_phys, sizeof(ldr_phys))) return false;
        return ldr_phys == ldr_truth && ldr_truth != 0;
    };

    std::uint64_t dtb = dev_->solve_dtb(pid);
    if (!dtb_valid(dtb)) {
        // strict variant: same scan with the image size filter enabled
        winotify::dtb_request_t strict{};
        strict.pid = pid;
        strict.strict = 1;
        if (dev_->send(winotify::ioctl::DTB, &strict, sizeof(strict)) &&
            dtb_valid(strict.out_dtb)) {
            dtb = strict.out_dtb;
        } else {
            dtb = 0;   // reads still work via the attach path, writes are refused
        }
    }
    return make_kernel_handle(pid, dtb);
}

void backend_winotify_t::detach(target_handle_t& h) {
    h.native = nullptr;
    h.pid = 0;
}

io_result_t backend_winotify_t::read_memory(const target_handle_t& h,
                                            uintptr_t addr, void* buf, size_t len) {
    if (!dev_ || !dev_->is_connected()) return not_ready();
    const uint64_t dtb = handle_dtb(h);
    if (!dtb) return { false, 0, ERROR_INVALID_HANDLE };
    // attach based MmCopyVirtualMemory: dtb independent, works for every user
    // mapping even when the solved dtb turns out to be a partial shadow table
    if (!dev_->cross_read(h.pid, addr, buf, len))
        return { false, 0, ERROR_READ_FAULT };
    return { true, len, 0 };
}

io_result_t backend_winotify_t::write_memory(const target_handle_t& h,
                                             uintptr_t addr, const void* buf, size_t len) {
    if (!dev_ || !dev_->is_connected()) return not_ready();
    // NOTE: writes require a validated DTB (solved during attach) because the
    // driver has no cross_write IOCTL — only phys_write, which translates
    // through the DTB.  reads use the attach-based cross_read (MmCopyVirtualMemory)
    // which is DTB-independent.  if DTB solve failed at attach time, reads
    // still work but writes are refused here.
    const uint64_t dtb = handle_dtb(h);
    if (!dtb) return { false, 0, ERROR_WRITE_PROTECT };
    const size_t chunk_cap = 0x100000;
    size_t done = 0;
    const auto* src = static_cast<const uint8_t*>(buf);
    while (done < len) {
        const size_t chunk = (len - done) > chunk_cap ? chunk_cap : (len - done);
        if (!dev_->phys_write(dtb, addr + done, src + done, chunk))
            return { done != 0, done, ERROR_WRITE_FAULT };
        done += chunk;
    }
    return { true, done, 0 };
}

io_result_t backend_winotify_t::protect_memory(const target_handle_t& h, uintptr_t addr,
                                               size_t len, uint32_t new_prot,
                                               uint32_t* old_prot) {
    if (!dev_ || !dev_->is_connected()) return not_ready();
    uint64_t base = addr;
    uint64_t size = len;
    uint32_t old = 0;
    if (!dev_->protect_mem(h.pid, &base, &size, new_prot, &old))
        return { false, 0, GetLastError() };
    if (old_prot) *old_prot = old;
    return { true, len, 0 };
}

io_result_t backend_winotify_t::allocate_memory(const target_handle_t& h, uintptr_t hint,
                                                size_t len, uint32_t prot, uintptr_t* out_addr) {
    if (!dev_ || !dev_->is_connected()) return not_ready();
    uint64_t base = hint;
    uint64_t size = len;
    constexpr uint32_t mem_commit_reserve = 0x3000;
    if (!dev_->alloc(h.pid, &base, &size, mem_commit_reserve, prot))
        return { false, 0, GetLastError() };
    if (out_addr) *out_addr = static_cast<uintptr_t>(base);
    return { true, len, 0 };
}

io_result_t backend_winotify_t::free_memory(const target_handle_t& h, uintptr_t addr) {
    if (!dev_ || !dev_->is_connected()) return not_ready();
    // MEM_RELEASE rides the same ZwAllocateVirtualMemory ioctl, base must be the
    // allocation base and size must be zero
    uint64_t base = addr;
    uint64_t size = 0;
    constexpr uint32_t mem_release = 0x4000;
    if (!dev_->alloc(h.pid, &base, &size, mem_release, 0))
        return { false, 0, GetLastError() };
    return { true, 0, 0 };
}

enum_result_t<module_info_t> backend_winotify_t::enum_modules(const target_handle_t& h) {
    enum_result_t<module_info_t> out;
    if (!dev_ || !dev_->is_connected()) { out.error = ERROR_NOT_READY; return out; }

    // the dtb solve can hand back a partial shadow table that covers the image
    // slot but not every user mapping, so every read here rides the attach based
    // MmCopyVirtualMemory ioctl instead - fully dtb independent
    std::uint64_t peb = dev_->peb_of(h.pid);
    if (!peb) { out.error = ERROR_NOT_FOUND; return out; }

    uint64_t ldr = 0;
    if (!dev_->cross_read(h.pid, peb + 0x18, &ldr, sizeof(ldr)) || !ldr) {
        out.error = ERROR_NOT_FOUND;
        return out;
    }
    uint64_t head = 0;
    if (!dev_->cross_read(h.pid, ldr + 0x10, &head, sizeof(head)) || !head) {
        out.error = ERROR_NOT_FOUND;
        return out;
    }

    uint64_t cur = head;
    for (int i = 0; i < 1024 && cur; ++i) {
        std::uint8_t entry[0x68] = {};
        if (!dev_->cross_read(h.pid, cur, entry, sizeof(entry))) break;

        module_info_t mod;
        mod.base = *reinterpret_cast<std::uint64_t*>(entry + 0x30);
        mod.size = *reinterpret_cast<std::uint32_t*>(entry + 0x40);
        const std::uint16_t name_len = *reinterpret_cast<std::uint16_t*>(entry + 0x58);
        const std::uint64_t name_buf = *reinterpret_cast<std::uint64_t*>(entry + 0x60);

        // read the utf16 name through the same path; name_len is in bytes
        if (name_len && name_buf) {
            std::uint16_t wlen = static_cast<std::uint16_t>(name_len / 2);
            if (wlen > 512) wlen = 512;
            std::vector<std::uint8_t> raw(static_cast<std::size_t>(wlen) * 2, 0);
            if (dev_->cross_read(h.pid, name_buf, raw.data(), raw.size())) {
                const int need = WideCharToMultiByte(CP_UTF8, 0,
                    reinterpret_cast<const wchar_t*>(raw.data()), wlen,
                    nullptr, 0, nullptr, nullptr);
                if (need > 0) {
                    std::string conv(static_cast<std::size_t>(need), '\0');
                    WideCharToMultiByte(CP_UTF8, 0,
                        reinterpret_cast<const wchar_t*>(raw.data()), wlen,
                        conv.data(), need, nullptr, nullptr);
                    const std::size_t z = conv.find('\0');
                    if (z != std::string::npos) conv.resize(z);
                    if (!conv.empty()) {
                        out.items.emplace_back();
                        module_info_t& dst = out.items.back();
                        dst.base = mod.base;
                        dst.size = mod.size;
                        dst.name = std::move(conv);
                    }
                }
            }
        }

        const std::uint64_t next = *reinterpret_cast<std::uint64_t*>(entry);
        if (!next || next == head) break;
        cur = next;
    }
    out.ok = !out.items.empty();
    if (!out.ok) out.error = ERROR_NOT_FOUND;
    return out;
}

io_result_t backend_winotify_t::get_thread_context(uint32_t tid, thread_context_t& ctx) {
    // kernel-side: brief NtOpenThread + NtGetContextThread with immediate
    // close. the handle exists for <1ms, minimizing the ObRegisterCallbacks
    // detection window. fully kernel-side ETHREAD walk would be better but
    // requires build-dependent offsets for the TrapFrame.
    using nt_open_thread_fn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, void*, void*);
    static const nt_open_thread_fn nt_open = [] {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? reinterpret_cast<nt_open_thread_fn>(
            GetProcAddress(m, "NtOpenThread")) : nullptr;
    }();
    if (!nt_open) return user_.get_thread_context(tid, ctx);

    // CLIENT_ID: UniqueProcess=0 (don't care), UniqueThread=tid
    struct { void* pid; void* tid; } cid = { nullptr, reinterpret_cast<void*>(static_cast<uintptr_t>(tid)) };
    // OBJECT_ATTRIBUTES: minimal
    struct { ULONG len; void* root; void* name; ULONG attrs; void* sd; void* qos; }
        oa = { sizeof(oa), nullptr, nullptr, 0, nullptr, nullptr };

    HANDLE th = nullptr;
    LONG status = nt_open(&th, THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, &oa, &cid);
    if (status < 0 || !th) return { false, 0, static_cast<uint32_t>(status) };

    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    io_result_t result;
    if (GetThreadContext(th, &c)) {
        ctx.rip = c.Rip; ctx.rsp = c.Rsp; ctx.rbp = c.Rbp;
        ctx.rax = c.Rax; ctx.rbx = c.Rbx; ctx.rcx = c.Rcx;
        ctx.rdx = c.Rdx; ctx.rsi = c.Rsi; ctx.rdi = c.Rdi;
        ctx.r8  = c.R8;  ctx.r9  = c.R9;  ctx.r10 = c.R10;
        ctx.r11 = c.R11; ctx.r12 = c.R12; ctx.r13 = c.R13;
        ctx.r14 = c.R14; ctx.r15 = c.R15; ctx.flags = c.EFlags;
        result = { true, sizeof(ctx), 0 };
    } else {
        result = { false, 0, GetLastError() };
    }
    CloseHandle(th);
    return result;
}

io_result_t backend_winotify_t::set_thread_context(uint32_t tid, const thread_context_t& ctx) {
    // same brief-handle pattern as get_thread_context
    using nt_open_thread_fn = LONG(NTAPI*)(PHANDLE, ACCESS_MASK, void*, void*);
    static const nt_open_thread_fn nt_open = [] {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? reinterpret_cast<nt_open_thread_fn>(
            GetProcAddress(m, "NtOpenThread")) : nullptr;
    }();
    if (!nt_open) return user_.set_thread_context(tid, ctx);

    struct { void* pid; void* tid; } cid = { nullptr, reinterpret_cast<void*>(static_cast<uintptr_t>(tid)) };
    struct { ULONG len; void* root; void* name; ULONG attrs; void* sd; void* qos; }
        oa = { sizeof(oa), nullptr, nullptr, 0, nullptr, nullptr };

    HANDLE th = nullptr;
    LONG status = nt_open(&th, THREAD_SET_CONTEXT, &oa, &cid);
    if (status < 0 || !th) return { false, 0, static_cast<uint32_t>(status) };

    CONTEXT c{};
    c.ContextFlags = CONTEXT_FULL;
    c.Rip = ctx.rip; c.Rsp = ctx.rsp; c.Rbp = ctx.rbp;
    c.Rax = ctx.rax; c.Rbx = ctx.rbx; c.Rcx = ctx.rcx;
    c.Rdx = ctx.rdx; c.Rsi = ctx.rsi; c.Rdi = ctx.rdi;
    c.R8  = ctx.r8;  c.R9  = ctx.r9;  c.R10 = ctx.r10;
    c.R11 = ctx.r11; c.R12 = ctx.r12; c.R13 = ctx.r13;
    c.R14 = ctx.r14; c.R15 = ctx.r15; c.EFlags = static_cast<DWORD>(ctx.flags);

    io_result_t result;
    if (SetThreadContext(th, &c)) {
        result = { true, sizeof(ctx), 0 };
    } else {
        result = { false, 0, GetLastError() };
    }
    CloseHandle(th);
    return result;
}

enum_result_t<thread_info_t> backend_winotify_t::enum_threads(uint32_t pid) {
    // SystemProcessInformation walk: per-process thread arrays at +0x100,
    // SYSTEM_THREAD_INFORMATION stride 0x40 (offsets derived empirically on
    // this build), no OpenThread and no handle to the target anywhere
    enum_result_t<thread_info_t> out;
    if (!dev_ || !dev_->is_connected()) { out.error = ERROR_NOT_READY; return out; }

    using nt_query_fn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    static const nt_query_fn query = [] {
        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        return ntdll ? reinterpret_cast<nt_query_fn>(
                           GetProcAddress(ntdll, "NtQuerySystemInformation")) : nullptr;
    }();
    if (!query) { out.error = ERROR_PROC_NOT_FOUND; return out; }

    ULONG size = 1u << 18;
    for (int attempt = 0; attempt < 8; ++attempt) {
        std::vector<std::uint8_t> buf(size);
        ULONG need = 0;
        const LONG st = query(5, buf.data(), size, &need);
        if (st >= 0) {
            std::size_t off = 0;
            while (off + 0x58 <= buf.size()) {
                const std::uint32_t next = *reinterpret_cast<const std::uint32_t*>(buf.data() + off);
                const std::uint32_t num_threads = *reinterpret_cast<const std::uint32_t*>(buf.data() + off + 4);
                const std::uint64_t entry_pid = *reinterpret_cast<const std::uint64_t*>(buf.data() + off + 0x50);
                if (static_cast<std::uint32_t>(entry_pid) == pid && num_threads) {
                    const std::size_t threads_at = off + 0x100;
                    for (std::uint32_t t = 0; t < num_threads; ++t) {
                        const std::size_t rec = threads_at + t * 0x40;
                        if (rec + 0x40 > buf.size()) break;
                        thread_info_t info;
                        info.tid = *reinterpret_cast<const std::uint32_t*>(buf.data() + rec + 0x30);
                        info.owner_pid = pid;
                        info.start_address = reinterpret_cast<uintptr_t>(
                            *reinterpret_cast<const void* const*>(buf.data() + rec + 0x20));
                        info.priority = *reinterpret_cast<const std::int32_t*>(buf.data() + rec + 0x38);
                        out.items.push_back(info);
                    }
                    out.ok = true;
                    return out;
                }
                if (!next) break;
                off += next;
            }
            out.ok = true;
            return out;
        }
        if (need > size) { size = need + (need >> 1); continue; }
        size *= 2;
    }
    out.error = ERROR_INSUFFICIENT_BUFFER;
    return out;
}


enum_result_t<region_info_t> backend_winotify_t::enum_regions(const target_handle_t& h) {
    // brief-handle pattern: open the target with PROCESS_QUERY_INFORMATION
    // for NtQueryVirtualMemory, walk regions, close immediately. the handle
    // exists for the duration of the walk (~1-5ms) with minimal access rights
    enum_result_t<region_info_t> out;
    if (!dev_ || !dev_->is_connected()) { out.error = ERROR_NOT_READY; return out; }

    HANDLE ph = lazy::resolve_OpenProcess()(PROCESS_QUERY_INFORMATION, FALSE, h.pid);
    if (!ph) {
        // fallback to usermode if we can't open with limited rights
        return user_.enum_regions(h);
    }

    out.ok = true;
    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (addr < 0x7FFFFFFEFFFF) {
        if (!lazy::resolve_VirtualQueryEx()(ph, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)))
            break;
        if (mbi.RegionSize == 0) break;
        region_info_t r;
        r.base    = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        r.size    = mbi.RegionSize;
        r.protect = mbi.Protect;
        r.state   = mbi.State;
        r.type    = mbi.Type;
        out.items.push_back(r);
        addr = r.base + r.size;
        if (out.items.size() > 16384) break;
    }
    CloseHandle(ph);
    return out;
}

enum_result_t<handle_info_t> backend_winotify_t::enum_handles(uint32_t pid) {
    // NtQuerySystemInformation(SystemHandleInformation) - queries from our
    // own process context, no handle to the target needed, filter by pid
    enum_result_t<handle_info_t> out;
    if (!dev_ || !dev_->is_connected()) { out.error = ERROR_NOT_READY; return out; }

    using nt_query_fn = LONG(NTAPI*)(ULONG, PVOID, ULONG, PULONG);
    static const nt_query_fn query = [] {
        HMODULE m = GetModuleHandleW(L"ntdll.dll");
        return m ? reinterpret_cast<nt_query_fn>(
            GetProcAddress(m, "NtQuerySystemInformation")) : nullptr;
    }();
    if (!query) { out.error = ERROR_NOT_SUPPORTED; return out; }

    // SystemHandleInformation = 16
    ULONG buf_size = 1024 * 1024;
    std::vector<uint8_t> buf(buf_size);
    ULONG ret_len = 0;
    LONG status = query(16, buf.data(), buf_size, &ret_len);
    while (status == 0xC0000004L /* STATUS_INFO_LENGTH_MISMATCH */) {
        buf_size *= 2;
        if (buf_size > 128 * 1024 * 1024) { out.error = ERROR_OUTOFMEMORY; return out; }
        buf.resize(buf_size);
        status = query(16, buf.data(), buf_size, &ret_len);
    }
    if (status < 0) { out.error = static_cast<uint32_t>(status); return out; }

    // SYSTEM_HANDLE_INFORMATION: NumberOfHandles at +0, entries at +8
    // each entry: ProcessId(ULONG), ObjectTypeNumber(UCHAR), Flags(UCHAR),
    // Handle(USHORT), Object(PVOID), GrantedAccess(ACCESS_MASK) = 24 bytes on x64
    struct sys_handle_entry {
        uint32_t pid;
        uint8_t  type_num;
        uint8_t  flags;
        uint16_t handle;
        uint64_t object;
        uint32_t access;
        uint32_t pad;
    };

    uint32_t count = *reinterpret_cast<const uint32_t*>(buf.data());
    const auto* entries = reinterpret_cast<const sys_handle_entry*>(buf.data() + 8);

    out.ok = true;
    for (uint32_t i = 0; i < count && i < 100000; ++i) {
        if (entries[i].pid != pid) continue;
        handle_info_t hi;
        hi.handle_value   = entries[i].handle;
        hi.type_index     = entries[i].type_num;
        hi.granted_access = entries[i].access;
        // type_name from type index would need NtQueryObject which needs
        // a handle - skip for stealth, just show the index
        char tmp[16];
        std::snprintf(tmp, sizeof(tmp), "type_%u", entries[i].type_num);
        hi.type_name = tmp;
        out.items.push_back(std::move(hi));
    }
    return out;
}

arch_t backend_winotify_t::query_arch(const target_handle_t& h) {
    if (!dev_ || !dev_->is_connected()) return arch_t::unknown;
    const uint64_t dtb = handle_dtb(h);
    if (!dtb) return arch_t::unknown;

    uint64_t peb = dev_->peb_of(h.pid);
    if (!peb) return arch_t::unknown;
    uint64_t image_base = 0;
    if (!dev_->phys_read(dtb, peb + 0x10, &image_base, sizeof(image_base)) || !image_base)
        return arch_t::unknown;

    uint8_t dos[0x40] = {};
    if (!dev_->phys_read(dtb, image_base, dos, sizeof(dos)) || dos[0] != 'M' || dos[1] != 'Z')
        return arch_t::unknown;
    const uint32_t e_lfanew = *reinterpret_cast<const uint32_t*>(dos + 0x3C);
    if (e_lfanew == 0 || e_lfanew > 0x1000) return arch_t::unknown;
    uint16_t machine = 0;
    if (!dev_->phys_read(dtb, image_base + e_lfanew + 4, &machine, sizeof(machine)))
        return arch_t::unknown;
    if (machine == 0x8664) return arch_t::x64;
    if (machine == 0x14C) return arch_t::x86;
    if (machine == 0xAA64) return arch_t::arm64;
    return arch_t::unknown;
}

} // namespace slop::core::runtime
