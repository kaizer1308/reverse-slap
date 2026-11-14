// src/core/emu/session.cpp
// the run: cpu and Windows environment setup, the unicorn hooks, and the
// machine as import models see it. All the unicorn includes stay in here

#include "core/emu/session.hpp"

#include "core/disasm/engine.hpp"
#include "core/emu/insn.hpp"
#include "core/emu/unicorn.hpp"
#include "core/emu/winapi.hpp"

#include <unicorn/unicorn.h>

// Vendored header defines an unused static helper (usleep shim) that trips
// C4505 at TU end, kept suppressed for the rest of this file
#pragma warning(disable : 4505)
#include <Zydis/Zydis.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <unordered_set>

namespace slop::core::emu {

namespace {

constexpr uint64_t kPageMask   = kPageSize - 1;
constexpr uint64_t kReturnPage = 0x00110000;            // sentinel RET trampoline
constexpr uint64_t kBootStub   = kReturnPage + 0x800;   // iretq that drops to ring 3
constexpr uint64_t kBootLand   = kReturnPage + 0x810;   // where it lands, never run
constexpr uint64_t kBootFrame  = kReturnPage + 0x900;   // its rip/cs/rflags/rsp/ss frame
constexpr uint64_t kStubBase   = 0x00120000;            // one RET per import slot
constexpr uint64_t kStubStride = 8;
constexpr uint64_t kTebBase    = kStubBase + kMaxImports * kStubStride;
constexpr uint64_t kTebSize    = 0x2000;                // x64 TEB is 0x1838 bytes
constexpr uint64_t kPebBase    = kTebBase + kTebSize;
constexpr uint64_t kTlsArray   = kPebBase + kPageSize;  // TEB.ThreadLocalStoragePointer
constexpr uint64_t kTlsBlock   = kTlsArray + kPageSize; // this image's TLS data
constexpr size_t   kMaxTlsBlock = 1u << 20;
constexpr size_t   kMaxApiCalls = 1024;
constexpr size_t   kMaxWrites   = 2048;

// Private heap for the api models: a header page (the handle GetProcessHeap
// and PEB.ProcessHeap return), then the arena, mapped a chunk at a time
constexpr uint64_t kHeapBase   = 0x000001E000000000ull;
constexpr uint64_t kHeapChunk  = 1u << 20;

// Descriptor tables live where Windows keeps them, in the kernel half, so
// sgdt/sidt hand back plausible bases and no user mapping can collide
constexpr uint64_t kGdtBase    = 0xFFFFF8047A8DB000ull;
constexpr uint64_t kIdtBase    = 0xFFFFF8047A8D9000ull;

constexpr uint16_t kSelKernelCode = 0x10, kSelKernelData = 0x18;
constexpr uint16_t kSelUserData   = 0x2B, kSelUserCode   = 0x33, kSelUserTeb32 = 0x53;
constexpr uint64_t kInitialRflags = 0x202;              // IF + the always-one bit

// KUSER_SHARED_DATA, the same page at its user and kernel addresses
constexpr uint64_t kKuserUser   = 0x000000007FFE0000ull;
constexpr uint64_t kKuserKernel = 0xFFFFF78000000000ull;

// One instruction is one nanosecond of virtual time on a 3 GHz counter
constexpr uint64_t kTscPerNs   = 3;
constexpr uint64_t kTscBase    = kBootUptimeNs * kTscPerNs;
constexpr uint64_t kClockRefreshMask = 0xFFFF;          // KUSER times, in instructions

constexpr uint32_t kOsBuild    = 19045;                 // Windows 10 22H2
constexpr uint32_t kProcessors = 4;

struct reg_alias_t { const char* name; int uc_reg; };

constexpr reg_alias_t kRegAliases[] = {
    {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX},
    {"rdx", UC_X86_REG_RDX}, {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI},
    {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP},
    {"r8",  UC_X86_REG_R8},  {"r9",  UC_X86_REG_R9},  {"r10", UC_X86_REG_R10},
    {"r11", UC_X86_REG_R11}, {"r12", UC_X86_REG_R12}, {"r13", UC_X86_REG_R13},
    {"r14", UC_X86_REG_R14}, {"r15", UC_X86_REG_R15},
    {"rip", UC_X86_REG_RIP}, {"rflags", UC_X86_REG_EFLAGS},
    {"fs_base", UC_X86_REG_FS_BASE}, {"gs_base", UC_X86_REG_GS_BASE},
};

bool lookup_reg(const std::string& name, int* out) {
    for (const auto& a : kRegAliases) {
        if (name == a.name) { *out = a.uc_reg; return true; }
    }
    return false;
}

uc_engine* eng_of(unicorn_t& uc) { return reinterpret_cast<uc_engine*>(uc.handle()); }

uint64_t reg_read(uc_engine* uc, int id) {
    uint64_t v = 0;
    uc_reg_read(uc, id, &v);
    return v;
}

void reg_write(uc_engine* uc, int id, uint64_t v) { uc_reg_write(uc, id, &v); }

// The block scan remembers which translation blocks it has looked at, and
// in a one-bit-per-page hash filter which pages they came from, so a store
// into code (self-modifying or unpacking) makes it look again
struct scan_slot_t { uint64_t addr = ~0ull; uint32_t size = 0; };
constexpr size_t kScanSlots       = 1024;
constexpr size_t kCodeFilterWords = 1024;

constexpr size_t code_filter_bit(uint64_t page) {
    return static_cast<size_t>((page ^ (page >> 16)) & (kCodeFilterWords * 64 - 1));
}

struct run_ctx_t final : api_host_t {
    run_request_t const* req      = nullptr;
    unicorn_t*           uc       = nullptr;
    taint_tracker_t      taint;
    bool                 taint_on = false;

    disasm::engine_t     eng;        // trace/event text formatting
    ZydisDecoder         decoder{};  // operand classification

    uint64_t instructions = 0;
    bool     until_hit    = false;
    bool     return_hit   = false;
    bool     cancelled    = false;
    bool     unsupported_hit = false;
    bool     stop_now     = false;   // an api model ended the run

    std::vector<run_result_t::trace_entry_t> trace;
    std::vector<run_result_t::write_entry_t> writes;
    size_t total_writes = 0;
    uint64_t prev_ip    = 0;         // previous instruction, for rep collapsing
    bool     rep_open   = false;     // trace.back() is a rep still counting
    uint64_t rep_rcx    = 0;         // its count register when it started

    std::optional<run_result_t::fault_t>     fault;
    std::optional<run_result_t::exception_t> exception;
    std::optional<run_result_t::exit_t>      exit;

    uint64_t cur_ip        = 0;
    std::string cur_text;
    uint64_t last_event_ip = 0;

    std::map<uint64_t, uint64_t> slot_stubs;   // IAT slot va -> stub va
    uint64_t stub_end = kStubBase;             // kStubBase: no stubs
    std::vector<api_model_fn> models;          // per import, nullptr = plain stub
    std::vector<run_result_t::api_call_t> api_calls;
    size_t total_api_calls = 0;

    // the import being modeled
    const std::string* api_name = nullptr;
    uint64_t call_rsp       = 0;
    bool     result_tainted = false;

    size_t paged_in          = 0;
    bool   page_in_exhausted = false;
    std::vector<uint8_t> page_buf = std::vector<uint8_t>(kPageSize);

    uint64_t kuser_va = 0;                     // KUSER_SHARED_DATA once touched
    uint64_t slept_ns = 0;                     // virtual time spent in Sleep

    uint64_t heap_next   = kHeapBase + kPageSize;
    uint64_t heap_mapped = kHeapBase + kPageSize;
    uint64_t heap_used   = 0;
    uint64_t fixed_used  = 0;                  // map_fixed pages
    std::map<uint64_t, uint64_t> blocks;       // block -> size
    std::map<uint64_t, uint64_t> fls;
    uint64_t next_fls = 1;
    uint64_t next_tls = 4;                     // a real process has a few taken

    // cpuid runs first, then the next instruction boundary patches its output
    bool     cpuid_pending = false;
    uint32_t cpuid_leaf    = 0;

    // instructions the cpu core would run with the wrong result
    std::array<scan_slot_t, kScanSlots> scanned{};
    std::unordered_set<uint64_t> miscomputed;
    std::array<uint64_t, kCodeFilterWords> code_filter{};   // pages holding scanned code
    bool     scanned_any = false;
    std::vector<uint8_t> scan_buf;

    // api_host_t
    uint64_t arg(size_t index) override;
    bool     arg_tainted(size_t index) override;
    bool     read(uint64_t addr, void* out, size_t len) override;
    bool     write(uint64_t addr, const void* data, size_t len) override;
    bool     fill(uint64_t addr, uint8_t value, size_t len, bool tainted) override;
    bool     copy(uint64_t dst, uint64_t src, size_t len) override;
    bool     tainted(uint64_t addr, size_t len) override;
    void     taint_result(bool t) override { result_tainted = t; }
    uint64_t alloc(uint64_t size, uint64_t align) override;
    bool     alloc_size(uint64_t ptr, uint64_t* size) override;
    bool     map_fixed(uint64_t addr, uint64_t size) override;
    uint64_t gs_base() override { return reg_read(eng_of(*uc), UC_X86_REG_GS_BASE); }
    uint64_t image_base() override { return req->image_base; }
    uint64_t heap_handle() override { return kHeapBase; }
    uint64_t clock_ns() override { return kBootUptimeNs + slept_ns + instructions; }
    void     sleep_ns(uint64_t ns) override;
    uint64_t fls_get(uint64_t index) override;
    void     fls_set(uint64_t index, uint64_t value) override { fls[index] = value; }
    uint64_t fls_alloc() override { return next_fls < 4000 ? next_fls++ : 0xFFFFFFFFull; }
    uint64_t tls_alloc() override { return next_tls < 64 ? next_tls++ : ~0ull; }
    void     exit_process(uint64_t code) override;
    void     raise(uint32_t code, const char* name) override;

    void log_write(uint64_t addr, size_t len, uint64_t value);
    void set_fault(uint64_t addr, const char* access);

    bool is_code_page(uint64_t page) const {
        const size_t bit = code_filter_bit(page);
        return (code_filter[bit >> 6] >> (bit & 63)) & 1;
    }
    void mark_code(uint64_t addr, uint64_t len) {
        for (uint64_t page = addr >> 12; page <= (addr + len - 1) >> 12; ++page) {
            const size_t bit = code_filter_bit(page);
            code_filter[bit >> 6] |= 1ull << (bit & 63);
        }
        scanned_any = true;
    }
    // A store of len >= 1 bytes: forget the scan when it lands on code
    void code_written(uint64_t addr, uint64_t len) {
        if (!scanned_any) return;
        for (uint64_t page = addr >> 12; page <= (addr + len - 1) >> 12; ++page) {
            if (!is_code_page(page)) continue;
            scanned.fill({});
            miscomputed.clear();
            code_filter.fill(0);
            scanned_any = false;
            return;
        }
    }
};

// The source is caller code running under a C callback, nothing may unwind
// through unicorn
bool fetch_page(const run_request_t& req, uint64_t page, uint8_t* out) noexcept {
    if (!req.page_in) return false;
    try {
        return req.page_in(page, out);
    } catch (...) {
        return false;
    }
}

// Point every IAT slot in [lo, hi) at its stub. Unmapped slots fail quietly
// and get patched when their page comes in
void patch_slots(const run_ctx_t& c, uint64_t lo, uint64_t hi) {
    for (auto it = c.slot_stubs.lower_bound(lo);
         it != c.slot_stubs.end() && it->first < hi; ++it)
        c.uc->write(it->first, &it->second, sizeof(it->second));
}

// KUSER_SHARED_DATA

void put_ksystem_time(uint8_t* at, uint64_t v) {
    const uint32_t lo = static_cast<uint32_t>(v), hi = static_cast<uint32_t>(v >> 32);
    std::memcpy(at, &lo, 4);          // LowPart
    std::memcpy(at + 4, &hi, 4);      // High1Time
    std::memcpy(at + 8, &hi, 4);      // High2Time, equal when the read is stable
}

constexpr size_t kKuserInterruptTime = 0x08, kKuserSystemTime = 0x14, kKuserTickCount = 0x320;

// The three clocks a reader polls, at the current virtual time
void put_kuser_clocks(uint8_t* page, uint64_t now_ns) {
    put_ksystem_time(page + kKuserInterruptTime, now_ns / 100);
    put_ksystem_time(page + kKuserSystemTime,
                     kBootFileTime + (now_ns - kBootUptimeNs) / 100);
    // one tick is 15.625 ms: ms = TickCount * TickCountMultiplier >> 24
    put_ksystem_time(page + kKuserTickCount, now_ns / 15625000);
}

void fill_kuser(uint8_t* page, uint64_t now_ns) {
    std::memset(page, 0, kPageSize);
    auto put = [page](size_t off, uint64_t v, size_t n) { std::memcpy(page + off, &v, n); };
    put(0x004, 0x0FA00000, 4);            // TickCountMultiplier
    put(0x02C, 0x8664, 2);                // ImageNumberLow
    put(0x02E, 0x8664, 2);                // ImageNumberHigh
    static constexpr char16_t kRoot[] = u"C:\\Windows";
    std::memcpy(page + 0x030, kRoot, sizeof(kRoot));   // NtSystemRoot
    put(0x244, 0x200000, 4);              // LargePageMinimum
    put(0x260, kOsBuild, 4);              // NtBuildNumber
    put(0x264, 1, 4);                     // NtProductType: WinNt
    put(0x268, 1, 1);                     // ProductTypeIsValid
    put(0x26A, 9, 2);                     // NativeProcessorArchitecture: AMD64
    put(0x26C, 10, 4);                    // NtMajorVersion
    put(0x270, 0, 4);                     // NtMinorVersion
    for (size_t i = 0; i < 64; ++i)       // ProcessorFeatures
        page[0x274 + i] = processor_feature(i) ? 1 : 0;
    put(0x2D4, 0, 1);                     // KdDebuggerEnabled
    put(0x2D8, 1, 4);                     // ActiveConsoleId
    put(0x2E8, 0x400000, 4);              // NumberOfPhysicalPages: 16 GiB
    put(0x2F8, 0xC3, 8);                  // TestRetInstruction
    put(0x300, kQpcFrequency, 8);         // QpcFrequency
    put(0x330, 0x5A17C0DE, 4);            // Cookie
    put(0x3C0, kProcessors, 4);           // ActiveProcessorCount
    put(0x3C4, 1, 2);                     // ActiveGroupCount
    put_kuser_clocks(page, now_ns);
}

void refresh_kuser(run_ctx_t* c) {
    uint8_t clocks[kKuserTickCount + 12] = {};
    put_kuser_clocks(clocks, c->clock_ns());
    c->uc->write(c->kuser_va + kKuserInterruptTime, clocks + kKuserInterruptTime, 12);
    c->uc->write(c->kuser_va + kKuserSystemTime, clocks + kKuserSystemTime, 12);
    c->uc->write(c->kuser_va + kKuserTickCount, clocks + kKuserTickCount, 12);
}

void run_ctx_t::sleep_ns(uint64_t ns) {
    slept_ns += ns;
    if (kuser_va) refresh_kuser(this);
}

// Bring one unmapped page in: from the page source, or synthesized when it
// is the shared user data page nothing else supplies
bool materialize(run_ctx_t* c, uint64_t page) {
    const bool kuser = page == kKuserUser || page == kKuserKernel;
    bool have = false, from_source = false;
    if (c->req->page_in) {
        if (c->paged_in < c->req->page_in_max) {
            have = from_source = fetch_page(*c->req, page, c->page_buf.data());
        } else if (!kuser) {
            c->page_in_exhausted = true;
            return false;
        }
    }
    if (!have && kuser) {
        fill_kuser(c->page_buf.data(), c->clock_ns());
        have = true;
    }
    if (!have) return false;
    if (!c->uc->map(page, kPageSize) ||
        !c->uc->write(page, c->page_buf.data(), kPageSize))
        return false;
    if (from_source) {
        patch_slots(*c, page, page + kPageSize);
        ++c->paged_in;
    } else {
        c->kuser_va = page;
    }
    return true;
}

// Map every page of [address, address + size) that nothing mapped yet. False
// leaves the access faulting, *bad is the first address that stays unmapped
bool page_in_range(run_ctx_t* c, uint64_t address, uint64_t size, uint64_t* bad = nullptr) {
    const uint64_t first = address & ~kPageMask;
    uint64_t last = (address + (size > 1 ? size - 1 : 0)) & ~kPageMask;
    if (last < first) last = first;   // wrapped at the top of the address space
    for (uint64_t page = first;; page += kPageSize) {
        // a straddling access can fault with one of its pages already mapped
        uint8_t probe = 0;
        if (!c->uc->read(page, &probe, 1) && !materialize(c, page)) {
            if (bad) *bad = std::max(page, address);
            return false;
        }
        if (page == last) return true;
    }
}

// api_host_t: the machine as an import model sees it

uint64_t run_ctx_t::arg(size_t index) {
    static constexpr int kArgRegs[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX,
                                        UC_X86_REG_R8,  UC_X86_REG_R9};
    if (index < 4) return reg_read(eng_of(*uc), kArgRegs[index]);
    // above the return address and the four home slots
    uint64_t v = 0;
    read(call_rsp + 8 + 8 * index, &v, sizeof(v));
    return v;
}

bool run_ctx_t::arg_tainted(size_t index) {
    static constexpr uint32_t kArgRegs[4] = {ZYDIS_REGISTER_RCX, ZYDIS_REGISTER_RDX,
                                             ZYDIS_REGISTER_R8,  ZYDIS_REGISTER_R9};
    if (!taint_on) return false;
    if (index < 4) return taint.reg(kArgRegs[index]);
    return taint.memory_any(call_rsp + 8 + 8 * index, 8);
}

void run_ctx_t::set_fault(uint64_t addr, const char* access) {
    if (!fault) fault = {cur_ip, addr, access};   // keep the first fault
    stop_now = true;
}

void run_ctx_t::log_write(uint64_t addr, size_t len, uint64_t value) {
    ++total_writes;
    if (writes.size() < kMaxWrites) writes.push_back({cur_ip, addr, len, value});
}

bool run_ctx_t::read(uint64_t addr, void* out, size_t len) {
    if (len == 0) return true;
    uint64_t bad = addr;
    if (addr + len < addr || !page_in_range(this, addr, len, &bad) ||
        !uc->read(addr, out, len)) {
        set_fault(bad, "read");
        return false;
    }
    return true;
}

bool run_ctx_t::write(uint64_t addr, const void* data, size_t len) {
    if (len == 0) return true;
    uint64_t bad = addr;
    if (addr + len < addr || !page_in_range(this, addr, len, &bad) ||
        !uc->write(addr, data, len)) {
        set_fault(bad, "write");
        return false;
    }
    uint64_t value = 0;
    if (len <= 8) std::memcpy(&value, data, len);
    log_write(addr, len, value);
    if (taint_on) taint.clear_memory(addr, len);
    code_written(addr, len);
    return true;
}

constexpr size_t kModelChunk = 0x10000;

bool run_ctx_t::fill(uint64_t addr, uint8_t value, size_t len, bool tainted_value) {
    if (len == 0) return true;
    const std::vector<uint8_t> buf(std::min(len, kModelChunk), value);
    size_t done = 0;
    bool ok = true;
    while (done < len) {
        const size_t n = std::min(len - done, buf.size());
        uint64_t bad = addr + done;
        if (addr + done + n < addr + done ||
            !page_in_range(this, addr + done, n, &bad) ||
            !uc->write(addr + done, buf.data(), n)) {
            // the bytes below the bad page were stored before the fault
            const size_t head = static_cast<size_t>(bad - (addr + done));
            if (head && uc->write(addr + done, buf.data(), head)) done += head;
            set_fault(bad, "write");
            ok = false;
            break;
        }
        done += n;
    }
    if (done) {
        uint64_t logged = 0;
        if (done <= 8) std::memset(&logged, value, done);
        log_write(addr, done, logged);
        if (taint_on) {
            if (tainted_value) taint.mark_memory(addr, done);
            else               taint.clear_memory(addr, done);
        }
        code_written(addr, done);
    }
    return ok;
}

bool run_ctx_t::copy(uint64_t dst, uint64_t src, size_t len) {
    if (len == 0) return true;
    // overlapping with the destination ahead: copy from the top down
    const bool backward = dst > src && dst - src < len;
    std::vector<uint8_t> buf(std::min(len, kModelChunk));
    size_t done = 0;
    bool ok = true;
    while (done < len) {
        const size_t n = std::min(len - done, buf.size());
        const size_t off = backward ? len - done - n : done;
        uint64_t bad = 0;
        if (src + off + n < src + off || !page_in_range(this, src + off, n, &bad) ||
            !uc->read(src + off, buf.data(), n)) {
            set_fault(std::max(bad, src + off), "read");
            ok = false;
            break;
        }
        if (dst + off + n < dst + off || !page_in_range(this, dst + off, n, &bad) ||
            !uc->write(dst + off, buf.data(), n)) {
            set_fault(std::max(bad, dst + off), "write");
            ok = false;
            break;
        }
        if (taint_on) taint.copy_memory(dst + off, src + off, n);
        done += n;
    }
    if (done) {
        const uint64_t at = backward ? dst + (len - done) : dst;
        uint64_t logged = 0;
        if (done <= 8) uc->read(at, &logged, done);
        log_write(at, done, logged);
        code_written(at, done);
    }
    return ok;
}

bool run_ctx_t::tainted(uint64_t addr, size_t len) {
    return taint_on && taint.memory_any(addr, len);
}

uint64_t run_ctx_t::alloc(uint64_t size, uint64_t align) {
    if (align < 16) align = 16;
    const uint64_t want = size ? size : 1;   // malloc(0) is a unique pointer
    const uint64_t limit = kHeapBase + req->heap_max;
    const uint64_t at = (heap_next + align - 1) & ~(align - 1);
    if (want > req->heap_max || at >= limit || want > limit - at) return 0;
    const uint64_t end = at + want;
    if (end > heap_mapped) {
        const uint64_t grow =
            std::min((end + kHeapChunk - 1) & ~(kHeapChunk - 1), (limit + kPageMask) & ~kPageMask);
        if (!uc->map(heap_mapped, static_cast<size_t>(grow - heap_mapped))) return 0;
        heap_mapped = grow;
    }
    heap_next = end;
    heap_used += want;
    blocks[at] = size;
    return at;
}

bool run_ctx_t::alloc_size(uint64_t ptr, uint64_t* size) {
    const auto it = blocks.find(ptr);
    if (it == blocks.end()) return false;
    *size = it->second;
    return true;
}

bool run_ctx_t::map_fixed(uint64_t addr, uint64_t size) {
    const uint64_t first = addr & ~kPageMask;
    const uint64_t end = (addr + size + kPageMask) & ~kPageMask;
    if (end <= first || end - first > req->heap_max - std::min<uint64_t>(fixed_used, req->heap_max))
        return false;
    // map the runs of pages nothing holds yet, what is mapped stays as it is
    uint64_t run = 0;
    for (uint64_t page = first; page <= end; page += kPageSize) {
        uint8_t probe = 0;
        const bool free_page = page < end && !uc->read(page, &probe, 1);
        if (free_page) {
            if (!run) run = page;
            continue;
        }
        if (run) {
            if (!uc->map(run, static_cast<size_t>(page - run))) return false;
            fixed_used += page - run;
            run = 0;
        }
    }
    return true;
}

uint64_t run_ctx_t::fls_get(uint64_t index) {
    const auto it = fls.find(index);
    return it == fls.end() ? 0 : it->second;
}

void run_ctx_t::exit_process(uint64_t code) {
    if (!exit) exit = {api_name ? *api_name : std::string(), code};
    stop_now = true;
}

void run_ctx_t::raise(uint32_t code, const char* name) {
    if (!exception) {
        run_result_t::exception_t e;
        e.ip   = cur_ip;
        e.code = code;
        e.name = name;
        if (api_name) e.insn = "call " + *api_name;
        exception = std::move(e);
    }
    stop_now = true;
}

// imports and syscalls

void log_api_call(run_ctx_t* c, run_result_t::api_call_t call) {
    ++c->total_api_calls;
    if (c->api_calls.size() < kMaxApiCalls) c->api_calls.push_back(std::move(call));
}

// A call through a stubbed IAT slot landed here: run its model or hand back
// the configured value, log it, and let the stub's RET go back to the caller
void on_import(uc_engine* uc, run_ctx_t* c, uint64_t address) {
    const size_t idx = static_cast<size_t>((address - kStubBase) / kStubStride);
    const import_slot_t& slot = c->req->imports[idx];

    run_result_t::api_call_t call;
    call.ip   = c->cur_ip;   // still the instruction that got us here
    call.name = slot.name;
    c->call_rsp = reg_read(uc, UC_X86_REG_RSP);
    c->uc->read(c->call_rsp, &call.ret, sizeof(call.ret));
    for (size_t i = 0; i < 4; ++i) call.args[i] = c->arg(i);

    uint64_t rax = slot.has_ret ? slot.ret : c->req->api_ret;
    c->result_tainted = false;
    if (const api_model_fn model = c->models[idx]) {
        c->api_name = &slot.name;
        rax = model(*c);     // faults and exits are attributed to the call site
        c->api_name = nullptr;
        call.modeled = true;
    }
    call.rax = rax;
    reg_write(uc, UC_X86_REG_RAX, rax);
    log_api_call(c, std::move(call));

    ++c->instructions;
    c->cur_ip = address;
    c->cur_text = "api " + slot.name;
    c->prev_ip = address;
    if (c->req->trace && c->trace.size() < c->req->trace_max)
        c->trace.push_back({address, c->cur_text});
    if (c->taint_on) c->taint.set_reg(ZYDIS_REGISTER_RAX, c->result_tainted);
    if (c->stop_now) uc_emu_stop(uc);
}

// syscall and int 2Eh: there is no kernel behind them, so they are logged
// and answered like an import. args follow the syscall convention
void on_syscall(uc_engine* uc, run_ctx_t* c, const char* gate, uint64_t next_ip) {
    char name[40];
    std::snprintf(name, sizeof(name), "%s:0x%X", gate,
                  static_cast<unsigned>(reg_read(uc, UC_X86_REG_RAX) & 0xFFFFFFFFu));
    run_result_t::api_call_t call;
    call.ip   = c->cur_ip;
    call.ret  = next_ip;
    call.name = name;
    static constexpr int kArgRegs[4] = {UC_X86_REG_R10, UC_X86_REG_RDX,
                                        UC_X86_REG_R8,  UC_X86_REG_R9};
    for (size_t i = 0; i < 4; ++i) call.args[i] = reg_read(uc, kArgRegs[i]);
    call.rax = c->req->api_ret;
    reg_write(uc, UC_X86_REG_RAX, call.rax);
    log_api_call(c, std::move(call));
    if (c->taint_on) c->taint.set_reg(ZYDIS_REGISTER_RAX, false);
}

void hook_syscall(uc_engine* uc, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    const uint64_t next_ip = c->cur_ip + 2;
    on_syscall(uc, c, "syscall", next_ip);
    // the kernel's sysret leaves the return address and the flags behind
    reg_write(uc, UC_X86_REG_RCX, next_ip);
    reg_write(uc, UC_X86_REG_R11, reg_read(uc, UC_X86_REG_EFLAGS));
    if (c->taint_on) {
        c->taint.set_reg(ZYDIS_REGISTER_RCX, false);
        c->taint.set_reg(ZYDIS_REGISTER_R11, false);
    }
}

// cpu identity

// TCG always reports a hypervisor; a bare-metal machine does not
int hook_cpuid(uc_engine* uc, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    c->cpuid_pending = true;
    c->cpuid_leaf = static_cast<uint32_t>(reg_read(uc, UC_X86_REG_RAX));
    return 0;   // let the core answer, patch_cpuid fixes it up after
}

void patch_cpuid(uc_engine* uc, run_ctx_t* c) {
    c->cpuid_pending = false;
    if (c->cpuid_leaf == 1) {
        reg_write(uc, UC_X86_REG_RCX,
                  reg_read(uc, UC_X86_REG_RCX) & ~(1ull << 31));   // hypervisor present
    } else if ((c->cpuid_leaf & 0xF0000000u) == 0x40000000u) {
        // the hypervisor leaves: no vendor signature to find
        for (int r : {UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX})
            reg_write(uc, r, 0);
    }
}

// The time stamp counter follows the instruction count, so a run repeats
// exactly and two reads are never the same
int hook_rdtsc(uc_engine* uc, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    const uint64_t tsc = kTscBase + (c->slept_ns + c->instructions) * kTscPerNs;
    reg_write(uc, UC_X86_REG_RAX, tsc & 0xFFFFFFFFu);
    reg_write(uc, UC_X86_REG_RDX, tsc >> 32);
    return 1;   // skip the host clock
}

int hook_rdtscp(uc_engine* uc, void* user_data) {
    hook_rdtsc(uc, user_data);
    reg_write(uc, UC_X86_REG_RCX, 0);   // IA32_TSC_AUX: processor 0
    return 1;
}

// exceptions

// Up to 16 bytes at ip, fewer when the mapping ends first
size_t insn_bytes(run_ctx_t* c, uint64_t ip, uint8_t (&bytes)[16]) {
    std::memset(bytes, 0, sizeof(bytes));
    size_t n = sizeof(bytes);
    while (n && !c->uc->read(ip, bytes, n)) --n;
    return n;
}

std::string insn_text(run_ctx_t* c, uint64_t ip) {
    uint8_t bytes[16];
    if (!insn_bytes(c, ip, bytes)) return {};
    if (auto insn = c->eng.decode(ip, bytes, sizeof(bytes))) return insn->text;
    return {};
}

// #GP from a user-mode instruction that needs ring 0 or I/O privilege
bool is_privileged_insn(run_ctx_t* c, uint64_t ip) {
    uint8_t bytes[16];
    if (!insn_bytes(c, ip, bytes)) return false;
    ZydisDecodedInstruction zin{};
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&c->decoder, nullptr, bytes,
                                                    sizeof(bytes), &zin)))
        return false;
    if (zin.attributes & ZYDIS_ATTRIB_IS_PRIVILEGED) return true;
    switch (zin.mnemonic) {
    case ZYDIS_MNEMONIC_CLI: case ZYDIS_MNEMONIC_STI: case ZYDIS_MNEMONIC_HLT:
    case ZYDIS_MNEMONIC_IN:  case ZYDIS_MNEMONIC_OUT:
    case ZYDIS_MNEMONIC_INSB: case ZYDIS_MNEMONIC_INSW: case ZYDIS_MNEMONIC_INSD:
    case ZYDIS_MNEMONIC_OUTSB: case ZYDIS_MNEMONIC_OUTSW: case ZYDIS_MNEMONIC_OUTSD:
        return true;
    default:
        return false;
    }
}

// The NTSTATUS a Windows handler would be handed for an x86 vector
void name_exception(run_ctx_t* c, run_result_t::exception_t* e) {
    switch (e->vector) {
    case 0:  e->name = "divide_error";        e->code = 0xC0000094; break;
    case 1:  e->name = "single_step";         e->code = 0x80000004; break;
    case 3:  e->name = "breakpoint";          e->code = 0x80000003; break;
    case 4:  e->name = "overflow";            e->code = 0xC0000095; break;
    case 5:  e->name = "bound_range";         e->code = 0xC000008C; break;
    case 6:
    case 7:  e->name = "illegal_instruction"; e->code = 0xC000001D; break;
    case 13:
        if (is_privileged_insn(c, e->ip)) {
            e->name = "privileged_instruction";
            e->code = 0xC0000096;
            break;
        }
        [[fallthrough]];
    case 12: e->name = "access_violation";    e->code = 0xC0000005; break;
    case 16: e->name = "x87_floating_point";  e->code = 0xC0000090; break;
    case 17: e->name = "alignment_check";     e->code = 0x80000002; break;
    case 19: e->name = "simd_floating_point"; e->code = 0xC00002B5; break;
    case 0x29: e->name = "fail_fast";         e->code = 0xC0000409; break;
    case 0x2C: e->name = "assertion_failure"; e->code = 0xC0000420; break;
    case 0x2D: e->name = "debug_service";     e->code = 0x80000003; break;
    default:
        // int n through a gate user mode may not use
        e->name = "access_violation";
        e->code = 0xC0000005;
        break;
    }
}

void raise_cpu(uc_engine* uc, run_ctx_t* c, int vector) {
    if (!c->exception) {
        run_result_t::exception_t e;
        e.ip     = c->cur_ip;
        e.vector = vector;
        e.insn   = insn_text(c, e.ip);
        name_exception(c, &e);
        c->exception = std::move(e);
    }
    uc_emu_stop(uc);
}

void hook_intr(uc_engine* uc, uint32_t intno, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    if (intno == 0x2E && !c->req->kernel_mode) {   // the legacy system call gate
        on_syscall(uc, c, "int2e", c->cur_ip + 2);
        return;
    }
    raise_cpu(uc, c, static_cast<int>(intno));
}

// 64-bit Windows leaves the sysenter MSRs empty: the instruction faults
void hook_sysenter(uc_engine* uc, void* user_data) {
    raise_cpu(uc, static_cast<run_ctx_t*>(user_data), 13);
}

// Port I/O from user mode is a privileged instruction on Windows
uint32_t hook_in(uc_engine* uc, uint32_t, int, void* user_data) {
    raise_cpu(uc, static_cast<run_ctx_t*>(user_data), 13);
    return 0;
}

void hook_out(uc_engine* uc, uint32_t, int, uint32_t, void* user_data) {
    raise_cpu(uc, static_cast<run_ctx_t*>(user_data), 13);
}

// instructions the cpu core gets wrong

// Find the miscomputed instructions of a translation block the first time it
// runs. VEX needs a C4/C5 byte, so most blocks cost one memchr
void scan_block(run_ctx_t* c, uint64_t address, uint32_t size) {
    if (size == 0) return;
    c->scan_buf.resize(size);
    uint8_t* bytes = c->scan_buf.data();
    if (!c->uc->read(address, bytes, size)) return;
    c->mark_code(address, size);
    if (!std::memchr(bytes, 0xC4, size) && !std::memchr(bytes, 0xC5, size)) return;

    ZydisDecodedInstruction zin{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    for (uint32_t off = 0; off < size;) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&c->decoder, bytes + off, size - off,
                                                 &zin, ops)))
            break;   // the core raises #UD here on its own
        if (vex_miscomputed(zin, ops)) c->miscomputed.insert(address + off);
        off += zin.length;
    }
}

void hook_block(uc_engine*, uint64_t address, uint32_t size, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    auto& slot = c->scanned[(address ^ (address >> 10)) & (kScanSlots - 1)];
    if (slot.addr == address && slot.size == size) return;
    slot = {address, size};
    scan_block(c, address, size);
}

// The rep instruction on the last trace line is done: record its iterations
void close_rep(uc_engine* uc, run_ctx_t* c) {
    if (!c->rep_open) return;
    c->rep_open = false;
    c->trace.back().repeat = c->rep_rcx - reg_read(uc, UC_X86_REG_RCX);
}

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);

    if (c->taint_on) c->taint.boundary();
    if (c->cpuid_pending) patch_cpuid(uc, c);

    // Caller cancellation (MCP notifications/cancelled) must stop the run now,
    // not after the full timeout budget
    if (c->req->cancel.cancelled()) {
        c->cancelled = true;
        uc_emu_stop(uc);
        return;
    }

    if (c->req->until_addr && address == c->req->until_addr) {
        c->until_hit = true;
        uc_emu_stop(uc);
        return;
    }
    if (address >= kReturnPage && address < kReturnPage + 0x1000) {
        c->return_hit = true;
        uc_emu_stop(uc);
        return;
    }
    if (address >= kStubBase && address < c->stub_end) {
        on_import(uc, c, address);
        return;
    }
    if (!c->miscomputed.empty() && c->miscomputed.count(address)) {
        run_result_t::exception_t e;
        e.ip   = address;
        e.name = "unsupported_avx";
        e.insn = insn_text(c, address);
        c->exception = std::move(e);
        c->unsupported_hit = true;
        uc_emu_stop(uc);
        return;
    }

    ++c->instructions;
    c->cur_ip = address;
    if (c->kuser_va && (c->instructions & kClockRefreshMask) == 0) refresh_kuser(c);

    // Instruction text and operands only feed the trace and taint; skip the
    // per-instruction read + decode + format when neither wants them
    if (!c->req->trace && !c->taint_on) return;
    const uint64_t prev_ip = c->prev_ip;
    c->prev_ip = address;
    const bool want_trace = c->req->trace && c->trace.size() < c->req->trace_max;
    // the same instruction again right after its own trace line: an
    // iteration of a rep to fold into that line
    const bool maybe_rep = c->req->trace && prev_ip == address && !c->trace.empty() &&
                           c->trace.back().ip == address;
    if (!want_trace && !maybe_rep && !c->rep_open && !c->taint_on) return;

    // If the bytes are unreadable (unmapped callee after a CALL outside the
    // slice), do NOT decode zeros -- 00 00 decodes as "ADD [rax],al" and
    // poisons the trace with a fake fall-through. Record the gap instead.
    uint8_t bytes[16] = {};
    const size_t n = size <= sizeof(bytes) ? size : sizeof(bytes);
    const bool readable = n > 0 && c->uc->read(address, bytes, n);

    // One trace line per rep instruction. The hook fires for every iteration
    // (and once more to see the count reach zero), so the iterations are read
    // off the count register when the instruction is left
    const bool rep = readable && is_rep_string(bytes, n);
    if (maybe_rep && rep && c->rep_open) {
        if (!c->taint_on) return;
    } else {
        close_rep(uc, c);
        if (want_trace || c->taint_on) {
            c->cur_text.clear();
            if (!readable)
                c->cur_text = "<unmapped>";
            else if (auto insn = c->eng.decode(address, bytes, sizeof(bytes)))
                c->cur_text = insn->text;
        }
        if (want_trace) {
            c->trace.push_back({address, c->cur_text});
            if (rep) {
                c->rep_open = true;
                c->rep_rcx  = reg_read(uc, UC_X86_REG_RCX);
            }
        }
    }

    if (!c->taint_on || !readable) return;

    ZydisDecodedInstruction zin{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&c->decoder, bytes, n, &zin, ops)))
        return;
    c->taint.analyze(address, c->cur_text, taint_sources(c->taint, zin, ops));
}

// Memory hooks report the address the cpu core looked up, see fold_addr

void hook_mem_read(uc_engine*, uc_mem_type, uint64_t address, int size,
                   int64_t, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    if (c->taint_on)
        c->taint.note_mem_read(unfold_addr(address), static_cast<size_t>(size));
}

bool hook_mem_write(uc_engine*, uc_mem_type, uint64_t address, int size,
                    int64_t value, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    address = unfold_addr(address);
    const size_t len = static_cast<size_t>(size);
    ++c->total_writes;
    if (c->writes.size() < kMaxWrites) {
        uint64_t stored = 0;
        if (size == 8)                stored = static_cast<uint64_t>(value);
        else if (size > 0 && size < 8) stored = static_cast<uint64_t>(value) &
                                                ((1ull << (size * 8)) - 1);
        c->writes.push_back({c->cur_ip, address, len, stored});
    }
    if (len) c->code_written(address, len);
    if (!c->taint_on) return false;

    if (c->taint.note_mem_write(address, len)) {
        // Propagate: the stored bytes themselves become taint carriers
        c->taint.mark_memory(address, len);
        if (c->cur_ip != c->last_event_ip) {
            char addr_text[32];
            std::snprintf(addr_text, sizeof(addr_text), "mem %llX",
                          static_cast<unsigned long long>(address));
            c->taint.record_event({c->cur_ip, c->cur_text, "mem", addr_text});
            c->last_event_ip = c->cur_ip;
        }
    } else {
        // clean bytes over tainted ones: the old taint is gone
        c->taint.clear_memory(address, len);
    }
    return false;
}

// The cpu core reports a data fault at the 52-bit address it looked up. For a
// pointer with stray high bits that is far from the address the instruction
// formed, so work that one out from the operand and the registers
uint64_t effective_fault_addr(uc_engine* uc, run_ctx_t* c, uint64_t reported) {
    uint8_t bytes[16];
    ZydisDecodedInstruction zin{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!insn_bytes(c, c->cur_ip, bytes) ||
        !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&c->decoder, bytes, sizeof(bytes), &zin, ops)))
        return reported;
    static constexpr struct { ZydisRegister zy; int uc; } kGprs[] = {
        {ZYDIS_REGISTER_RAX, UC_X86_REG_RAX}, {ZYDIS_REGISTER_RCX, UC_X86_REG_RCX},
        {ZYDIS_REGISTER_RDX, UC_X86_REG_RDX}, {ZYDIS_REGISTER_RBX, UC_X86_REG_RBX},
        {ZYDIS_REGISTER_RSP, UC_X86_REG_RSP}, {ZYDIS_REGISTER_RBP, UC_X86_REG_RBP},
        {ZYDIS_REGISTER_RSI, UC_X86_REG_RSI}, {ZYDIS_REGISTER_RDI, UC_X86_REG_RDI},
        {ZYDIS_REGISTER_R8,  UC_X86_REG_R8},  {ZYDIS_REGISTER_R9,  UC_X86_REG_R9},
        {ZYDIS_REGISTER_R10, UC_X86_REG_R10}, {ZYDIS_REGISTER_R11, UC_X86_REG_R11},
        {ZYDIS_REGISTER_R12, UC_X86_REG_R12}, {ZYDIS_REGISTER_R13, UC_X86_REG_R13},
        {ZYDIS_REGISTER_R14, UC_X86_REG_R14}, {ZYDIS_REGISTER_R15, UC_X86_REG_R15},
    };
    auto reg_value = [uc](ZydisRegister r, uint64_t* out) {
        if (r == ZYDIS_REGISTER_NONE) { *out = 0; return true; }
        for (const auto& g : kGprs)
            if (g.zy == r) { *out = reg_read(uc, g.uc); return true; }
        return false;   // rip-relative or a 32-bit address form, never out of range
    };
    for (uint8_t i = 0; i < zin.operand_count; ++i) {
        const auto& op = ops[i];
        if (op.type != ZYDIS_OPERAND_TYPE_MEMORY || op.mem.type != ZYDIS_MEMOP_TYPE_MEM)
            continue;
        uint64_t base = 0, index = 0;
        if (!reg_value(op.mem.base, &base) || !reg_value(op.mem.index, &index)) continue;
        uint64_t ea = base + index * op.mem.scale +
                      static_cast<uint64_t>(op.mem.disp.has_displacement ? op.mem.disp.value : 0);
        if (op.mem.segment == ZYDIS_REGISTER_GS) ea += reg_read(uc, UC_X86_REG_GS_BASE);
        if (op.mem.segment == ZYDIS_REGISTER_FS) ea += reg_read(uc, UC_X86_REG_FS_BASE);
        // the access the core reported starts inside this operand
        if (fold_addr(reported) - fold_addr(ea) < 64) return ea + (fold_addr(reported) - fold_addr(ea));
    }
    return reported;
}

bool hook_mem_invalid(uc_engine* uc, uc_mem_type access, uint64_t address,
                      int size, int64_t value, void* user_data) {
    (void)value;
    auto* c = static_cast<run_ctx_t*>(user_data);
    address = unfold_addr(address);
    // unicorn 2 retries the access when the hook maps the page and returns true
    const bool unmapped = access == UC_MEM_READ_UNMAPPED ||
                          access == UC_MEM_WRITE_UNMAPPED ||
                          access == UC_MEM_FETCH_UNMAPPED;
    uint64_t bad = address;
    if (unmapped &&
        page_in_range(c, address, static_cast<uint64_t>(size > 0 ? size : 1), &bad))
        return true;
    if (!c->fault) {   // keep the first fault
        const char* what = access == UC_MEM_FETCH_UNMAPPED ? "fetch"
                         : access == UC_MEM_WRITE_UNMAPPED ? "write"
                         : access == UC_MEM_FETCH_PROT     ? "fetch_prot"
                         : access == UC_MEM_WRITE_PROT     ? "write_prot"
                                                           : "read";
        if (access != UC_MEM_FETCH_UNMAPPED && access != UC_MEM_FETCH_PROT)
            bad = effective_fault_addr(uc, c, bad);
        c->fault = {c->cur_ip, bad, what};
    }
    uc_emu_stop(uc);
    return false;
}

// environment

uint64_t gdt_descriptor(uint8_t access, uint8_t flags) {
    // base 0, limit 0xFFFFF
    return 0xFFFFull | (static_cast<uint64_t>(access) << 40) | (0xFull << 48) |
           (static_cast<uint64_t>(flags) << 52);
}

// Bring the CPU up the way Windows hands it to code: its GDT, the selectors
// for the chosen ring, interrupts on, and the x87/SSE control words every
// thread starts with. Unicorn itself starts in ring 0 with null selectors
// and all floating point exceptions unmasked
bool setup_cpu(unicorn_t& uc, const run_request_t& req) {
    uc_engine* e = eng_of(uc);

    uint64_t gdt[11] = {};
    gdt[kSelKernelCode >> 3] = gdt_descriptor(0x9B, 0xA);   // ring 0 code, long mode
    gdt[kSelKernelData >> 3] = gdt_descriptor(0x93, 0xC);   // ring 0 data
    gdt[0x20 >> 3]           = gdt_descriptor(0xFB, 0xC);   // ring 3 code, compatibility
    gdt[kSelUserData >> 3]   = gdt_descriptor(0xF3, 0xC);   // ring 3 data
    gdt[kSelUserCode >> 3]   = gdt_descriptor(0xFB, 0xA);   // ring 3 code, long mode
    gdt[kSelUserTeb32 >> 3]  = gdt_descriptor(0xF3, 0x4);   // ring 3 TEB32
    if (!uc.map(kGdtBase, kPageSize) || !uc.write(kGdtBase, gdt, sizeof(gdt))) return false;

    uc_x86_mmr table{};
    table.base  = kGdtBase;
    table.limit = static_cast<uint32_t>(sizeof(gdt) - 1);
    if (uc_reg_write(e, UC_X86_REG_GDTR, &table) != UC_ERR_OK) return false;
    table.base  = kIdtBase;
    table.limit = 0xFFF;
    uc_reg_write(e, UC_X86_REG_IDTR, &table);
    table.selector = 0x40;                 // str reads the task register
    table.base     = kGdtBase + kPageSize;
    table.limit    = 0x67;
    table.flags    = 0x8B00;               // present, busy 64-bit TSS
    uc_reg_write(e, UC_X86_REG_TR, &table);

    // fs and gs are loaded for real (that reads the GDT); the bases come after
    reg_write(e, UC_X86_REG_FS, kSelUserTeb32);
    reg_write(e, UC_X86_REG_GS, kSelUserData);

    if (req.kernel_mode) {
        reg_write(e, UC_X86_REG_CS, kSelKernelCode);
        reg_write(e, UC_X86_REG_SS, kSelKernelData);
        reg_write(e, UC_X86_REG_EFLAGS, kInitialRflags);
    } else {
        // The only way down to ring 3 is a real privilege return: one iretq
        // on the trampoline page. It lands on kBootLand, which is also the
        // stop address, so nothing after it runs
        static constexpr uint8_t kIretq[2] = {0x48, 0xCF};
        const uint64_t frame[5] = {kBootLand, kSelUserCode, kInitialRflags,
                                   kBootFrame, kSelUserData};
        if (!uc.write(kBootStub, kIretq, sizeof(kIretq)) ||
            !uc.write(kBootFrame, frame, sizeof(frame)))
            return false;
        reg_write(e, UC_X86_REG_RSP, kBootFrame);
        if (uc_emu_start(e, kBootStub, kBootLand, 0, 0) != UC_ERR_OK ||
            reg_read(e, UC_X86_REG_RIP) != kBootLand)
            return false;
        // blocks translated for the boot must not outlive it
        uc_ctl_flush_tb(e);
    }
    // plain selector values in long mode, and the return above cleared them
    reg_write(e, UC_X86_REG_DS, kSelUserData);
    reg_write(e, UC_X86_REG_ES, kSelUserData);

    uint16_t fpcw = 0x27F;     // 53-bit precision, all exceptions masked
    uint32_t mxcsr = 0x1F80;   // all exceptions masked, round to nearest
    uc_reg_write(e, UC_X86_REG_FPCW, &fpcw);
    uc_reg_write(e, UC_X86_REG_MXCSR, &mxcsr);
    return true;
}

// TEB + PEB with the fields code reads first: gs:[0x30] self, gs:[0x60] PEB,
// stack bounds, client ids, the TLS pointer, PEB.ImageBaseAddress, the
// process heap and the OS version. Everything else reads 0, so
// PEB.BeingDebugged / NtGlobalFlag checks see a clean process
bool map_teb(unicorn_t& uc, const run_request_t& req) {
    if (!uc.map(kTebBase, kTebSize + kPageSize)) return false;
    std::vector<uint8_t> blk(kTebSize + kPageSize, 0);
    auto put = [&blk](size_t off, uint64_t v, size_t n = 8) {
        std::memcpy(blk.data() + off, &v, n);
    };
    put(0x08, req.stack_base + req.stack_size);   // NtTib.StackBase
    put(0x10, req.stack_base);                    // NtTib.StackLimit
    put(0x30, kTebBase);                          // NtTib.Self
    put(0x40, 0x1000);                            // ClientId.UniqueProcess
    put(0x48, 0x1004);                            // ClientId.UniqueThread
    put(0x60, kPebBase);                          // ProcessEnvironmentBlock
    put(0x1478, req.stack_base);                  // DeallocationStack
    const size_t peb = kTebSize;
    put(peb + 0x10, req.image_base);              // ImageBaseAddress
    put(peb + 0x30, kHeapBase);                   // ProcessHeap
    put(peb + 0xB8, kProcessors, 4);              // NumberOfProcessors
    put(peb + 0x118, 10, 4);                      // OSMajorVersion
    put(peb + 0x11C, 0, 4);                       // OSMinorVersion
    put(peb + 0x120, kOsBuild, 2);                // OSBuildNumber
    put(peb + 0x124, 2, 4);                       // OSPlatformId: VER_PLATFORM_WIN32_NT
    put(peb + 0x2C0, 1, 4);                       // SessionId
    if (!uc.write(kTebBase, blk.data(), blk.size())) return false;
    uint64_t gs = kTebBase;
    if (uc_reg_write(eng_of(uc), UC_X86_REG_GS_BASE, &gs) != UC_ERR_OK) return false;

    // The process heap header: Flags is HEAP_GROWABLE and ForceFlags 0 in a
    // process no debugger started. Best effort, a caller map there wins
    if (uc.map(kHeapBase, kPageSize)) {
        const uint32_t growable = 2;
        uc.write(kHeapBase + 0x70, &growable, sizeof(growable));
    }
    return true;
}

// The thread's TLS: a slot array behind TEB+0x58 and this image's block in
// its slot, filled from the template. Best effort like the TEB
bool map_tls(unicorn_t& uc, const run_request_t& req) {
    constexpr uint32_t kSlots = static_cast<uint32_t>(kPageSize / 8);
    if (!req.has_tls || req.tls_index >= kSlots || req.tls_block.size() > kMaxTlsBlock)
        return false;
    // a thread with no TLS data still gets an (empty) block to point at
    const size_t len = std::max<size_t>(req.tls_block.size(), 1);
    if (!uc.map(kTlsArray, kPageSize) || !uc.map(kTlsBlock, len)) return false;
    const uint64_t block = kTlsBlock, array = kTlsArray;
    if (!req.tls_block.empty() &&
        !uc.write(kTlsBlock, req.tls_block.data(), req.tls_block.size()))
        return false;
    return uc.write(kTlsArray + uint64_t{req.tls_index} * 8, &block, sizeof(block)) &&
           uc.write(kTebBase + 0x58, &array, sizeof(array));
}

// Page by page so a dump running into unmapped memory keeps its readable
// head. Pages the run never touched still read from the page source
emu_mem_region_t read_back(const unicorn_t& uc, const run_request_t& req,
                           const run_request_t::dump_range_t& d) {
    emu_mem_region_t m;
    m.addr = d.addr;
    m.bytes.reserve(d.len);
    std::vector<uint8_t> page;
    uint64_t a = d.addr;
    size_t left = d.len;
    while (left) {
        const size_t chunk = std::min<size_t>(left, kPageSize - (a & kPageMask));
        const size_t at = m.bytes.size();
        m.bytes.resize(at + chunk);
        if (!uc.read(a, m.bytes.data() + at, chunk)) {
            if (page.empty()) page.resize(kPageSize);
            if (!fetch_page(req, a & ~kPageMask, page.data())) {
                m.bytes.resize(at);
                break;
            }
            std::memcpy(m.bytes.data() + at, page.data() + (a & kPageMask), chunk);
        }
        a += chunk;
        left -= chunk;
    }
    return m;
}

std::string_view import_function(const std::string& name) {
    const size_t bang = name.rfind('!');
    return bang == std::string::npos ? std::string_view(name)
                                     : std::string_view(name).substr(bang + 1);
}

} // namespace

run_result_t emulate_run(const run_request_t& req) {
    run_result_t res;
    if (req.code.empty()) { res.error = "no code bytes"; return res; }
    if (req.imports.size() > kMaxImports) {
        res.error = "too many imports (max 16384)";
        return res;
    }

    unicorn_t uc;
    if (!uc.ok()) { res.error = "unicorn init failed"; return res; }

    if (!uc.map(req.code_base, req.code.size())) {
        res.error = "code mapping failed (unmapped/overlap?)";
        return res;
    }
    // A slice ending mid-page has to run into the real next bytes, not zero
    // fill, so the pages it shares come from the source first
    if (req.page_in) {
        std::vector<uint8_t> page(kPageSize);
        const uint64_t lo = req.code_base & ~kPageMask;
        const uint64_t hi = (req.code_base + req.code.size() + kPageMask) & ~kPageMask;
        for (uint64_t p = lo; p < hi; p += kPageSize)
            if (fetch_page(req, p, page.data())) uc.write(p, page.data(), kPageSize);
    }
    if (!uc.write(req.code_base, req.code.data(), req.code.size())) {
        res.error = "code mapping failed (unmapped/overlap?)";
        return res;
    }
    if (req.stack_size < 0x1000 || !uc.map(req.stack_base, req.stack_size)) {
        res.error = "stack mapping failed";
        return res;
    }
    for (const auto& r : req.maps) {
        if (r.bytes.empty() || !uc.map(r.addr, r.bytes.size()) ||
            !uc.write(r.addr, r.bytes.data(), r.bytes.size())) {
            res.error = "data mapping failed";
            return res;
        }
    }

    static constexpr uint8_t kRet = 0xC3;
    if (!uc.map(kReturnPage, 0x1000) || !uc.write(kReturnPage, &kRet, 1)) {
        res.error = "trampoline mapping failed";
        return res;
    }
    if (!setup_cpu(uc, req)) {
        res.error = "cpu setup failed (descriptor table pages taken?)";
        return res;
    }

    run_ctx_t ctx{};
    ctx.req = &req;
    ctx.uc  = &uc;

    // One RET per import, int3 between them so a stray jump into a stub
    // stops instead of sliding into the next one
    if (!req.imports.empty()) {
        const size_t len = req.imports.size() * kStubStride;
        std::vector<uint8_t> stubs((len + kPageMask) & ~kPageMask, 0xCC);
        ctx.models.resize(req.imports.size(), nullptr);
        for (size_t i = 0; i < req.imports.size(); ++i) {
            const import_slot_t& slot = req.imports[i];
            stubs[i * kStubStride] = kRet;
            ctx.slot_stubs[slot.slot] = kStubBase + i * kStubStride;
            if (req.api_models && !slot.has_ret)
                ctx.models[i] = find_api_model(import_function(slot.name));
        }
        if (!uc.map(kStubBase, stubs.size()) ||
            !uc.write(kStubBase, stubs.data(), stubs.size())) {
            res.error = "import stub mapping failed";
            return res;
        }
        ctx.stub_end = kStubBase + len;
        patch_slots(ctx, 0, UINT64_MAX);
    }

    // Best effort: a caller map over the TEB pages or a caller gs_base wins
    if (!req.regs.count("gs_base")) {
        res.teb_mapped = map_teb(uc, req);
        if (res.teb_mapped) res.tls_mapped = map_tls(uc, req);
    }

    // Initial RSP with a return-address sentinel so clean leaf routines halt
    // deterministically with stopped_reason="return"
    uint64_t rsp = req.sp_set ? req.sp
                              : req.stack_base + req.stack_size - 0x1000;
    rsp &= ~0x7ull;
    rsp -= 8;
    uint64_t ret_sentinel = kReturnPage;
    if (!uc.write(rsp, &ret_sentinel, sizeof(ret_sentinel))) {
        res.error = "stack sentinel write failed";
        return res;
    }

    ctx.taint_on  = !req.taint_sources.empty();
    if (ctx.taint_on) {
        ctx.taint.reset();
        for (const auto& s : req.taint_sources)
            ctx.taint.mark_memory(s.addr, s.len);
    }
    if (!ctx.eng.init()) { res.error = "zydis engine init failed"; return res; }
    if (ZydisDecoderInit(&ctx.decoder, ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS) {
        res.error = "zydis decoder init failed";
        return res;
    }

    for (const auto& [name, value] : req.regs) {
        int id = 0;
        if (!lookup_reg(name, &id)) {
            res.error = "unknown register '" + name +
                        "' (use rax..r15, rip, rflags, fs_base, gs_base)";
            return res;
        }
        uint64_t v = value;
        uc_reg_write(uc.handle(), id, &v);
    }

    if (!req.entry_absolute && req.entry >= req.code.size()) {
        res.error = "entry offset outside code bytes";
        return res;
    }
    const uint64_t entry_va = req.entry_absolute ? req.entry
                                                 : req.code_base + req.entry;

    uc_engine* e = eng_of(uc);
    uc_hook h = 0;
    uc_hook_add(e, &h, UC_HOOK_CODE, reinterpret_cast<void*>(hook_code), &ctx, 1, 0);
    uc_hook_add(e, &h, UC_HOOK_BLOCK, reinterpret_cast<void*>(hook_block), &ctx, 1, 0);
    if (ctx.taint_on)   // the read hook only feeds taint; skip the per-access callback otherwise
        uc_hook_add(e, &h, UC_HOOK_MEM_READ, reinterpret_cast<void*>(hook_mem_read), &ctx, 1, 0);
    uc_hook_add(e, &h, UC_HOOK_MEM_WRITE, reinterpret_cast<void*>(hook_mem_write), &ctx, 1, 0);
    uc_hook_add(e, &h, UC_HOOK_MEM_INVALID, reinterpret_cast<void*>(hook_mem_invalid), &ctx, 1, 0);
    uc_hook_add(e, &h, UC_HOOK_INTR, reinterpret_cast<void*>(hook_intr), &ctx, 1, 0);
    uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_syscall), &ctx, 1, 0,
                UC_X86_INS_SYSCALL);
    uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_sysenter), &ctx, 1, 0,
                UC_X86_INS_SYSENTER);
    uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_cpuid), &ctx, 1, 0,
                UC_X86_INS_CPUID);
    uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_rdtsc), &ctx, 1, 0,
                UC_X86_INS_RDTSC);
    uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_rdtscp), &ctx, 1, 0,
                UC_X86_INS_RDTSCP);
    if (!req.kernel_mode) {
        uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_in), &ctx, 1, 0,
                    UC_X86_INS_IN);
        uc_hook_add(e, &h, UC_HOOK_INSN, reinterpret_cast<void*>(hook_out), &ctx, 1, 0,
                    UC_X86_INS_OUT);
    }

    uint64_t rip = entry_va, spv = rsp;
    uc_reg_write(uc.handle(), UC_X86_REG_RIP, &rip);
    uc_reg_write(uc.handle(), UC_X86_REG_RSP, &spv);

    const uint64_t until = req.until_addr ? req.until_addr : kReturnPage;
    const uint64_t count = req.max_instructions ? req.max_instructions : 100000;
    const uint32_t timeout_ms = std::min<uint32_t>(
        req.timeout_ms ? req.timeout_ms : 5000, kMaxTimeoutMs);
    const uc_err err = uc_emu_start(uc.handle(), entry_va, until,
                                    static_cast<uint64_t>(timeout_ms) * 1000ull,
                                    count);
    // unicorn returns OK on timeout; its timer thread records whether it fired
    size_t timed_out = 0;
    uc_query(uc.handle(), UC_QUERY_TIMEOUT, &timed_out);
    if (ctx.cpuid_pending) patch_cpuid(e, &ctx);   // cpuid was the last instruction
    if (ctx.rep_open) ctx.trace.back().repeat = ctx.rep_rcx - reg_read(e, UC_X86_REG_RCX);

    // Final register snapshot
    uint64_t final_rip = 0;
    for (const auto& a : kRegAliases) {
        uint64_t v = 0;
        if (uc_reg_read(uc.handle(), a.uc_reg, &v) == UC_ERR_OK) {
            res.regs[a.name] = v;
            if (a.uc_reg == UC_X86_REG_RIP) final_rip = v;
        }
    }

    const bool at_return = final_rip >= kReturnPage && final_rip < kReturnPage + 0x1000;
    if (ctx.cancelled)             res.stopped_reason = "cancelled";
    else if (ctx.exit)             res.stopped_reason = "exit";
    else if (ctx.fault)            res.stopped_reason = std::string("invalid_mem_") + ctx.fault->access;
    else if (ctx.unsupported_hit)  res.stopped_reason = "unsupported_insn";
    else if (ctx.exception)
        res.stopped_reason = ctx.exception->vector < 0 ? "api_exception" : "cpu_exception";
    else if (ctx.return_hit)       res.stopped_reason = "return";
    else if (ctx.until_hit)        res.stopped_reason = "until";
    else if (timed_out)            res.stopped_reason = "timeout";
    else if (err == UC_ERR_FETCH_UNMAPPED) res.stopped_reason = "invalid_mem_fetch";
    else if (err == UC_ERR_INSN_INVALID) {
        run_result_t::exception_t ex;
        ex.ip   = final_rip;
        ex.insn = insn_text(&ctx, final_rip);
        uint8_t opcode = 0;
        if (uc.read(final_rip, &opcode, 1) && opcode == 0xF1) {
            // int1 / icebp: the core has no such opcode, a real CPU traps
            ex.vector = 1;
            res.stopped_reason = "cpu_exception";
        } else {
            ex.vector = 6;
            res.stopped_reason = "invalid_insn";
        }
        name_exception(&ctx, &ex);
        ctx.exception = std::move(ex);
    } else if (err == UC_ERR_OK) {
        uint8_t last = 0;
        if (at_return)
            res.stopped_reason = "return";   // stopped at the sentinel via until
        else if (req.until_addr && final_rip == req.until_addr)
            res.stopped_reason = "until";    // ditto for an explicit until
        else if (ctx.instructions < count && uc.read(final_rip - 1, &last, 1) && last == 0xF4)
            res.stopped_reason = "halt";     // hlt in kernel mode parks the cpu
        else
            res.stopped_reason = "count";
    } else {
        res.stopped_reason = "cpu_exception";
        res.error = uc_strerror(err);
    }
    res.ok = true;

    res.instructions = ctx.instructions;
    res.trace  = std::move(ctx.trace);
    res.writes = std::move(ctx.writes);
    res.total_writes = ctx.total_writes;
    res.api_calls = std::move(ctx.api_calls);
    res.total_api_calls = ctx.total_api_calls;
    res.paged_in = ctx.paged_in;
    res.page_in_exhausted = ctx.page_in_exhausted;
    res.heap_used = static_cast<size_t>(ctx.heap_used + ctx.fixed_used);
    res.fault  = ctx.fault;
    res.exception = ctx.exception;
    res.exit   = ctx.exit;

    for (const auto& d : req.dumps) res.memory.push_back(read_back(uc, req, d));

    if (ctx.taint_on) {
        ctx.taint.boundary();   // flush the final instruction's deferred dests
        res.taint_ranges = ctx.taint.tainted_ranges();
        res.taint_events = ctx.taint.events();
        res.output_tainted = req.watch_len > 0 &&
                             ctx.taint.memory_any(req.watch_addr, req.watch_len);
    }
    return res;
}

} // namespace slop::core::emu
