// src/core/debugger/debugger.cpp

#include "core/debugger/debugger.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/settings.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/context.hpp"
#include "core/runtime/voyager_comm.h"
#include "core/debugger/veh_stub.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <string>

namespace slop::core::debugger {

namespace {

constexpr DWORD kStatusBreakpoint   = 0x80000003;
constexpr DWORD kStatusSingleStep   = 0x40000006;   // EXCEPTION_SINGLE_STEP
constexpr DWORD kStatusGuardPage    = 0x80000001;   // EXCEPTION_GUARD_PAGE
constexpr DWORD kPageGuardFlag      = 0x100;        // PAGE_GUARD

const char* dbg_mode_name_impl(dbg_mode_t m) noexcept {
    switch (m) {
    case dbg_mode_t::kernel_stealth:   return "kernel-stealth";
    case dbg_mode_t::user_debug_object: return "user-debug-object";
    default:                           return "idle";
    }
}

// tiny breakpoint condition evaluator
// grammar is reg op value, ops are == != < > <= >= & and values take 0x hex

using reg_ptr_t = uint64_t runtime::thread_context_t::*;

struct cond_eval_t {
    bool      valid = false;
    reg_ptr_t reg   = nullptr;
    enum op_t : uint8_t { eq, ne, lt, gt, le, ge, band } op = eq;
    uint64_t  value = 0;
};

reg_ptr_t lookup_reg(const std::string& name) {
    static const std::pair<const char*, reg_ptr_t> kRegs[] = {
        {"rip", &runtime::thread_context_t::rip}, {"rsp", &runtime::thread_context_t::rsp},
        {"rbp", &runtime::thread_context_t::rbp}, {"rax", &runtime::thread_context_t::rax},
        {"rbx", &runtime::thread_context_t::rbx}, {"rcx", &runtime::thread_context_t::rcx},
        {"rdx", &runtime::thread_context_t::rdx}, {"rsi", &runtime::thread_context_t::rsi},
        {"rdi", &runtime::thread_context_t::rdi}, {"r8",  &runtime::thread_context_t::r8 },
        {"r9",  &runtime::thread_context_t::r9 }, {"r10", &runtime::thread_context_t::r10},
        {"r11", &runtime::thread_context_t::r11}, {"r12", &runtime::thread_context_t::r12},
        {"r13", &runtime::thread_context_t::r13}, {"r14", &runtime::thread_context_t::r14},
        {"r15", &runtime::thread_context_t::r15}, {"flags", &runtime::thread_context_t::flags},
    };
    for (const auto& [n, p] : kRegs)
        if (_stricmp(n, name.c_str()) == 0) return p;
    return nullptr;
}

cond_eval_t parse_condition(const std::string& text) {
    cond_eval_t out;
    size_t i = 0;
    auto token = [&](const char* sep) {
        while (i < text.size() && isspace(static_cast<unsigned char>(text[i]))) ++i;
        const size_t start = i;
        while (i < text.size() && !strchr(sep, text[i])) ++i;
        while (i > start && isspace(static_cast<unsigned char>(text[i - 1]))) --i;
        return text.substr(start, i - start);
    };
    const std::string reg_name = token(" \t");
    if (reg_name.empty()) return out;
    out.reg = lookup_reg(reg_name);
    if (!out.reg) return out;

    const std::string op = token(" 0123456789xXabcdefABCDEF-");
    if      (op == "==") out.op = cond_eval_t::eq;
    else if (op == "!=") out.op = cond_eval_t::ne;
    else if (op == "<")  out.op = cond_eval_t::lt;
    else if (op == ">")  out.op = cond_eval_t::gt;
    else if (op == "<=") out.op = cond_eval_t::le;
    else if (op == ">=") out.op = cond_eval_t::ge;
    else if (op == "&")  out.op = cond_eval_t::band;
    else return out;

    const std::string val = token("");
    if (val.empty()) return out;
    try { out.value = std::stoull(val, nullptr, 0); }
    catch (...) { return out; }

    out.valid = true;
    return out;
}

bool eval_condition(const cond_eval_t& c, const runtime::thread_context_t& ctx) {
    if (!c.valid) return false;
    const uint64_t v = ctx.*(c.reg);
    switch (c.op) {
    case cond_eval_t::eq:   return v == c.value;
    case cond_eval_t::ne:   return v != c.value;
    case cond_eval_t::lt:   return v <  c.value;
    case cond_eval_t::gt:   return v >  c.value;
    case cond_eval_t::le:   return v <= c.value;
    case cond_eval_t::ge:   return v >= c.value;
    case cond_eval_t::band: return (v & c.value) != 0;
    }
    return false;
}

namespace {
void dbg_loop_trace(const char* /*what*/, DWORD /*code*/ = 0, uint32_t /*tid*/ = 0) {
    // kept as a no-op sink, the call sites document the failure points and a dev build can flip tracing back on here
}

} // namespace

} // namespace

// pure planners

step_action_t plan_step_over(const disasm::insn_t& at_rip) {
    step_action_t a;
    if (at_rip.flow == disasm::flow_t::call && at_rip.length > 0) {
        a.kind      = step_action_t::temp_breakpoint;
        a.temp_addr = at_rip.va + at_rip.length;
    } else {
        a.kind = step_action_t::trap_flag;
    }
    return a;
}

step_action_t plan_step_out(uint64_t /*rsp*/, uint64_t return_addr) {
    step_action_t a;
    a.kind      = step_action_t::temp_breakpoint;
    a.temp_addr = return_addr;   // [rsp] captured by caller
    return a;
}

// breakpoint store

bool bp_store_t::add(uintptr_t addr, uint8_t orig_byte, bool hw) {
    if (find(addr)) return false;
    breakpoint_t bp;
    bp.addr      = addr;
    bp.orig_byte = orig_byte;
    bp.hardware  = hw;
    bps_.push_back(bp);
    return true;
}

bool bp_store_t::remove(uintptr_t addr) {
    const auto it = std::remove_if(bps_.begin(), bps_.end(),
                                   [addr](const breakpoint_t& b) { return b.addr == addr; });
    if (it == bps_.end()) return false;
    bps_.erase(it, bps_.end());
    return true;
}

breakpoint_t* bp_store_t::find(uintptr_t addr) {
    for (auto& b : bps_)
        if (b.addr == addr) return &b;
    return nullptr;
}

// engine

const char* dbg_mode_name(dbg_mode_t m) noexcept {
    return dbg_mode_name_impl(m);
}

debugger_t::~debugger_t() { detach(); }

void debugger_t::push_event(const debug_event_t& e) {
    std::lock_guard<std::mutex> lk(mu_);
    events_.push_back(e);
    constexpr size_t kMaxEvents = 4096;
    if (events_.size() > kMaxEvents)
        events_.erase(events_.begin(), events_.begin() + static_cast<long>(events_.size() - kMaxEvents));
}

std::vector<debug_event_t> debugger_t::events_snapshot(size_t max) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (events_.size() <= max) return events_;
    return std::vector<debug_event_t>(events_.end() - static_cast<long>(max), events_.end());
}

std::vector<breakpoint_t> debugger_t::breakpoints() const {
    std::lock_guard<std::mutex> lk(mu_);
    return *bps_.all();
}

bool debugger_t::configure_breakpoint(uintptr_t va, const std::string& condition,
                                      const std::string& log_text,
                                      bool auto_continue, bool one_shot) {
    std::lock_guard<std::mutex> lk(mu_);
    breakpoint_t* bp = bps_.find(va);
    if (bp == nullptr) return false;
    if (!condition.empty()) bp->condition = condition;
    if (!log_text.empty())  bp->log_text  = log_text;
    bp->auto_continue = auto_continue || !log_text.empty();
    bp->one_shot      = one_shot;
    return true;
}

std::vector<watchpoint_t> debugger_t::watchpoints() const {
    std::lock_guard<std::mutex> lk(mu_);
    return watches_;
}

bool debugger_t::set_watchpoint(uintptr_t addr, size_t len, bool auto_continue) {
    (void)auto_continue;   // hits always stream into the event log
    std::lock_guard<std::mutex> lk(mu_);
    for (const auto& w : watches_)
        if (w.addr == addr) return false;

    // flip the page rw to learn the old protection, then guard goes back on top of it
    auto* kdev = kdev_.get();
    uint32_t prev = 0;
    if (kdev) {
        if (!kdev->protect_memory(addr, len, 0x04, &prev)) return false;
    } else if (!backend_->protect_memory(mem_handle_, addr, len, 0x04, &prev).ok) {
        return false;
    }
    const uint32_t cur = prev ? prev : 0x04;
    uint32_t ignored = 0;
    if (kdev) {
        if (!kdev->protect_memory(addr, len, cur | kPageGuardFlag, &ignored))
            return false;
    } else if (!backend_->protect_memory(mem_handle_, addr, len,
                                         cur | kPageGuardFlag, &ignored).ok) {
        return false;
    }

    watchpoint_t w;
    w.addr      = addr;
    w.len       = len;
    w.orig_prot = cur;
    w.hits      = 0;
    watches_.push_back(w);

    debug_event_t e;
    e.kind  = event_kind_t::note;
    e.at_ms = slop::core::infra::steady_ms();
    e.text  = "watchpoint armed @ " + std::to_string(addr) +
              " len " + std::to_string(len);
    push_event(e);
    return true;
}

bool debugger_t::clear_watchpoint(uintptr_t addr) {
    std::lock_guard<std::mutex> lk(mu_);
    for (auto it = watches_.begin(); it != watches_.end(); ++it) {
        if (it->addr == addr) {
            uint32_t ignored = 0;
            if (kdev_) {
                kdev_->protect_memory(it->addr, it->len, it->orig_prot, &ignored);
            } else {
                backend_->protect_memory(mem_handle_, it->addr, it->len,
                                         it->orig_prot, &ignored);
            }
            watches_.erase(it);
            return true;
        }
    }
    return false;
}

bool debugger_t::set_register(const std::string& name, uint64_t value) {
    std::lock_guard<std::mutex> lk(mu_);
    if (state_.load() != dbg_state_t::paused) return false;

    auto p = lookup_reg(name);
    if (!p) return false;
    paused_ctx_.*p = value;

    if (mode_ == dbg_mode_t::kernel_stealth) {
        // the parked thread gets its context applied on release, not through setthreadcontext which would hit the stubs own frame
        kparked_regs_ = paused_ctx_;
        runtime::context_to_win(kparked_win_, kparked_regs_);
        kparked_dirty_ = true;   // release must rewrite the slot CONTEXT
        return true;
    }
    return backend_->set_thread_context(paused_tid_, paused_ctx_).ok;
}

std::optional<runtime::thread_context_t> debugger_t::paused_context(uint32_t* out_tid) const {
    std::lock_guard<std::mutex> lk(mu_);
    if (state_.load() != dbg_state_t::paused) return std::nullopt;
    if (out_tid) *out_tid = paused_tid_;
    return paused_ctx_;
}

// write the byte by flipping the page rw first, the driver copy on writes shared image pages, then the protection goes back so the page looks normal
bool debugger_t::write_byte_stealth(voyager::device_t* dev, uintptr_t va, uint8_t val) {
    if (!dev && backend_ == nullptr) return false;
    const uintptr_t page = va & ~0xFFFull;

    auto protect = [&](uintptr_t addr, size_t len, uint32_t prot, uint32_t* old) {
        if (dev) return dev->protect_memory(addr, len, prot, old);
        return backend_->protect_memory(mem_handle_, addr, len, prot, old).ok;
    };

    uint32_t old_prot = 0;
    if (!protect(page, 0x1000, 0x04 /*PAGE_READWRITE*/, &old_prot))
        return false;

    const bool ok = dev
        ? dev->write_raw(va, &val, 1) == 1
        : backend_->write_memory(mem_handle_, va, &val, 1).ok;

    uint32_t ignored = 0;
    protect(page, 0x1000, old_prot ? old_prot : 0x04, &ignored);
    return ok;
}

bool debugger_t::arm_bp(breakpoint_t& bp) {
    if (bp.armed || bp.hardware) return true;
    auto* dev = kdev_.get();
    if (!dev) {
        uint8_t probe = 0xCC;
        if (!backend_->read_memory(mem_handle_, bp.addr, &probe, 1).ok) return false;
        if (!write_byte_stealth(nullptr, bp.addr, 0xCC)) return false;
        bp.orig_byte = probe;
        bp.armed     = true;
        return true;
    }
    uint8_t probe = 0xCC;
    if (dev->read_raw(bp.addr, &probe, 1) != 1) return false;
    if (!write_byte_stealth(dev, bp.addr, 0xCC)) return false;
    bp.orig_byte = probe;
    bp.armed     = true;
    return true;
}

bool debugger_t::disarm_bp(breakpoint_t& bp) {
    if (!bp.armed || bp.hardware) return true;
    if (kdev_) {
        if (!write_byte_stealth(kdev_.get(), bp.addr, bp.orig_byte)) return false;
    } else if (!write_byte_stealth(nullptr, bp.addr, bp.orig_byte)) {
        return false;
    }
    bp.armed = false;
    return true;
}

bool debugger_t::set_sw_breakpoint(uintptr_t va) {
    std::lock_guard<std::mutex> lk(mu_);
    if (bps_.find(va) != nullptr || backend_ == nullptr) return false;

    if (kdev_) {
        uint8_t probe = 0xCC;
        if (kdev_->read_raw(va, &probe, 1) != 1) return false;
        // the plant flips the code page rx rw rx so freeze the world for the window
        kfreeze_world();
        const bool ok = write_byte_stealth(kdev_.get(), va, 0xCC);
        kunfreeze_world();
        if (!ok) return false;
        breakpoint_t bp;
        bp.addr      = va;
        bp.orig_byte = probe;
        bp.armed     = true;
        bps_.all()->push_back(bp);
        return true;
    }

    uint8_t probe = 0xCC;
    if (!backend_->read_memory(mem_handle_, va, &probe, 1).ok) return false;
    if (!write_byte_stealth(nullptr, va, 0xCC)) return false;

    breakpoint_t bp;
    bp.addr      = va;
    bp.orig_byte = probe;
    bp.armed     = true;
    bps_.all()->push_back(bp);
    return true;
}

bool debugger_t::set_hw_breakpoint(uintptr_t va, uint32_t len, uint32_t type) {
    std::lock_guard<std::mutex> lk(mu_);
    if (bps_.find(va) != nullptr || backend_ == nullptr) return false;

    // dr slots need the driver, there is no honest user mode fallback
    auto* kernel = dynamic_cast<runtime::backend_kernel_t*>(backend_);
    if (!kernel) return false;

    // first free dr slot, exec breakpoints are one byte
    if (type == 0) len = 1;
    bool used[4] = { false, false, false, false };
    for (const auto& b : *bps_.all()) {
        if (b.hardware && b.hw_slot < 4) used[b.hw_slot] = true;
    }
    int slot = -1;
    for (int i = 0; i < 4; ++i) {
        if (!used[i]) { slot = i; break; }
    }
    if (slot < 0) return false;   // all DR0-3 occupied

    if (!kernel->set_hw_breakpoint(pid_, static_cast<uint32_t>(slot), 0, va, len, type))
        return false;

    breakpoint_t bp;
    bp.addr      = va;
    bp.hardware  = true;
    bp.hw_slot   = static_cast<uint8_t>(slot);
    bp.hw_type   = static_cast<uint8_t>(type & 3);
    bp.hw_len    = static_cast<uint8_t>(len);
    bp.armed     = false;
    bps_.all()->push_back(bp);
    return true;
}

bool debugger_t::clear_breakpoint(uintptr_t va) {
    std::lock_guard<std::mutex> lk(mu_);
    breakpoint_t* bp = bps_.find(va);
    if (bp == nullptr) return false;
    if (bp->hardware) {
        // release the dr slot through the driver before dropping the record
        auto* kernel = dynamic_cast<runtime::backend_kernel_t*>(backend_);
        if (kernel) kernel->clear_hw_breakpoint(pid_, bp->hw_slot, 0);
    } else {
        // the disarm flips the page too, freeze the world again
        kfreeze_world();
        disarm_bp(*bp);
        kunfreeze_world();
    }
    return bps_.remove(va);
}

bool debugger_t::set_tf(uint32_t tid, bool on) {
    runtime::thread_context_t ctx;
    if (!backend_->get_thread_context(tid, ctx).ok) return false;
    ctx.flags = on ? (ctx.flags | runtime::kTrapFlag)
                   : (ctx.flags & ~runtime::kTrapFlag);
    return backend_->set_thread_context(tid, ctx).ok;
}

std::optional<disasm::insn_t> debugger_t::decode_at(uint64_t va) {
    uint8_t buf[16]{};
    const bool ok = kdev_
        ? kdev_->read_raw(va, buf, sizeof(buf)) == sizeof(buf)
        : backend_->read_memory(mem_handle_, va, buf, sizeof(buf)).ok;
    if (!ok) return std::nullopt;
    return engine_.decode(va, buf, sizeof(buf));
}

// remote call by rewriting a threads context to call fn and land on the capture stub, threads stuck in waits get woken and the context always goes back
bool debugger_t::kcall(uint64_t fn, uint64_t a1, uint64_t a2, uint64_t* out) {
    auto* dev = kdev_.get();
    if (!dev || !kpage_ || !fn) return false;

    const uint64_t capture = kpage_ + veh::kCaptureOff;
    // capture stub, park the rax in the slot then spin
    const int32_t disp = static_cast<int32_t>(
        veh::kGlobalsOff + 8 - (veh::kCaptureOff + 7));
    const uint8_t cap_code[] = {0x48, 0x89, 0x05,
                                static_cast<uint8_t>(disp & 0xFF),
                                static_cast<uint8_t>((disp >> 8) & 0xFF),
                                static_cast<uint8_t>((disp >> 16) & 0xFF),
                                static_cast<uint8_t>((disp >> 24) & 0xFF),
                                0xEB, 0xFE};
    uint64_t zero = 0;
    dev->write_raw(kpage_ + veh::kGlobalsOff + 8, &zero, 8);
    if (dev->write_raw(capture, cap_code, sizeof(cap_code)) != sizeof(cap_code))
        return false;
    const uint64_t ret_slot = kpage_ + veh::kStackTop;
    if (dev->write_raw(ret_slot, &capture, 8) != 8) return false;

    // the shim builds the call frame itself since the context write only applies control registers
    {
        const uint64_t shim = kpage_ + veh::kShimOff;
        uint8_t shim_code[32];
        size_t o = 0;
        // mov rcx, a1
        shim_code[o++] = 0x48; shim_code[o++] = 0xB9;
        std::memcpy(shim_code + o, &a1, 8); o += 8;
        // mov rdx, a2
        shim_code[o++] = 0x48; shim_code[o++] = 0xBA;
        std::memcpy(shim_code + o, &a2, 8); o += 8;
        // mov rax, fn ; jmp rax
        shim_code[o++] = 0x48; shim_code[o++] = 0xB8;
        std::memcpy(shim_code + o, &fn, 8); o += 8;
        shim_code[o++] = 0xFF; shim_code[o++] = 0xE0;
        if (dev->write_raw(shim, shim_code, o) != o) return false;
    }

    constexpr uint64_t kGprMask = (1ull << 18) - 1;
    for (const auto& t : dev->enumerate_threads()) {
        const uint32_t tid = t.tid;
        if (tid == 0) continue;
        if (!dev->suspend_thread(tid)) continue;

        voyager::device_t::thread_context orig{};
        if (!dev->get_thread_context(tid, orig)) {
            dev->resume_thread(tid);
            continue;
        }

        voyager::device_t::thread_context call_ctx = orig;
        call_ctx.rip = kpage_ + veh::kShimOff;
        call_ctx.rcx = a1;
        call_ctx.rdx = a2;
        call_ctx.rsp = kpage_ + veh::kStackTop;
        if (!dev->set_thread_context(tid, call_ctx, kGprMask)) {
            dev->resume_thread(tid);
            continue;
        }
        dev->resume_thread(tid);

        // wake out of message waits
        PostThreadMessageW(tid, 0x0000 /*WM_NULL*/, 0, 0);

        uint64_t result = 0;
        for (int i = 0; i < 100 && result == 0; ++i) {   // ~0.5 s / thread
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            dev->read_raw(kpage_ + veh::kGlobalsOff + 8, &result, 8);
        }

        // put the thread back exactly where it was
        dev->suspend_thread(tid);
        dev->set_thread_context(tid, orig, kGprMask);
        dev->resume_thread(tid);

        if (result != 0) {
            if (out) *out = result;
            return true;
        }
    }
    return false;
}

bool debugger_t::kattach(uint32_t pid) {
    auto kdiag = [&](const char* what) {
        debug_event_t e;
        e.kind  = event_kind_t::note;
        e.at_ms = slop::core::infra::steady_ms();
        e.text  = std::string("kattach: ") + what;
        push_event(e);
    };

    // our own device keeps a stable pid binding, the shared one gets its context switched by random mcp actions
    kdev_ = std::make_unique<voyager::device_t>();
    if (!kdev_->connect()) { kdiag("device connect failed"); kdev_.reset(); return false; }
    kdev_->set_process_id(pid);
    const uint64_t dtb = kdev_->solve_dtb_for_pid(pid);
    if (!dtb) {
        kdiag("dtb solve failed");
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }
    kdev_->set_dtb(dtb);
    auto* dev = kdev_.get();

    // 1. allocate the stub page in the target, no handle, no debug object
    const uint64_t page = dev->allocate_memory(0x2000);
    if (!page) { kdiag("page alloc failed"); return false; }

    // 2. zero it then write the stub
    std::vector<uint8_t> zeros(0x2000, 0);
    if (dev->write_raw(page, zeros.data(), zeros.size()) != 0x2000 ||
        dev->write_raw(page, veh::kVehStub, veh::kStubSize) != veh::kStubSize) {
        kdiag("page write failed");
        dev->free_memory(page);
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }

    // 3. find ntdll and kernel32 in the target and resolve the imports
    uint64_t ntdll = 0, kernel32 = 0;
    for (const auto& m : runtime::kernel_peb_modules(*dev)) {
        if (_stricmp(m.name.c_str(), "ntdll.dll") == 0) ntdll = m.base;
        else if (_stricmp(m.name.c_str(), "kernel32.dll") == 0) kernel32 = m.base;
    }
    if (!ntdll || !kernel32) {
        kdiag((std::string("module walk: ntdll=") +
               std::to_string(ntdll) + " kernel32=" + std::to_string(kernel32)).c_str());
        dev->free_memory(page);
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }
    const uint64_t p_sleep   = dev->resolve_export(kernel32, "Sleep");
    const uint64_t p_add     = dev->resolve_export(ntdll, "RtlAddVectoredExceptionHandler");
    const uint64_t p_remove  = dev->resolve_export(ntdll, "RtlRemoveVectoredExceptionHandler");
    if (!p_sleep || !p_add || !p_remove) {
        kdiag((std::string("exports: sleep=") + std::to_string(p_sleep) +
               " add=" + std::to_string(p_add) +
               " remove=" + std::to_string(p_remove)).c_str());
        dev->free_memory(page);
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }

    // 4. publish sleep_fn for the stubs park loop
    if (dev->write_raw(page + veh::kGlobalsOff, &p_sleep, 8) != 8) {
        kdiag("sleep publish failed");
        dev->free_memory(page);
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }

    // 5. install the handler by hijacking a thread to call rtladdvectoredexceptionhandler
    kpage_ = page;   // kcall targets the capture stub in this page
    kntdll_base_ = ntdll;
    uint64_t handle = 0;
    if (!kcall(p_add, 1, page, &handle)) {
        kdiag("call did not produce a VEH handle (no runnable thread)");
        kpage_ = 0;
        dev->free_memory(page);
        kdev_->disconnect();
        kdev_.reset();
        return false;
    }
    kveh_handle_ = handle;
    kremove_veh_ = p_remove;
    return true;
}

void debugger_t::kdetach() {
    auto* dev = kdev_.get();
    if (!dev || !kpage_) return;

    // release parked slots with per exception rules, our bps continue from the site, guard pages re-execute the access, foreign int3 forwards to the targets own seh, single steps get tf cleared
    for (int i = 0; i < veh::kSlotCount; ++i) {
        const uint64_t slot = kpage_ + veh::kSlotsOff + i * veh::kSlotStride;
        uint64_t state = 0;
        if (dev->read_raw(slot, &state, 8) != 8 || state != 1) continue;

        uint64_t code = 0;
        dev->read_raw(slot + veh::kSlotCode, &code, 8);

        CONTEXT win{};
        const bool have_ctx =
            dev->read_raw(slot + veh::kContextOff, &win, sizeof(win)) == sizeof(win);

        bool forward = false;
        if (code == kStatusBreakpoint && have_ctx) {
            std::lock_guard<std::mutex> lk(mu_);
            // our bp sites park with rip rewound, foreign cc bytes park the same way, told apart by bookkeeping
            forward = bps_.find(static_cast<uintptr_t>(win.Rip)) == nullptr;
        }

        if (forward) {
            krelease_slot(slot, veh::kCmdForward, nullptr);
            continue;
        }

        if (have_ctx) {
            win.EFlags &= ~0x100u;              // TF off: no re-trap
            if (slot == kparked_slot_) win = kparked_win_;   // keep reg edits
            krelease_slot(slot, veh::kCmdContinue, &win);
        } else {
            krelease_slot(slot, veh::kCmdContinue, nullptr);
        }
    }
    kparked_slot_ = 0;

    // remove the veh the same way we installed it, after the join so nobody else touches kdev_
    if (kveh_handle_ && kremove_veh_) {
        uint64_t result = 0;
        kcall(kremove_veh_, kveh_handle_, 0, &result);
    }
    dev->free_memory(kpage_);
    kpage_       = 0;
    kveh_handle_ = 0;
    kremove_veh_ = 0;
    dev->disconnect();
    kdev_.reset();
}

void debugger_t::krelease_slot(uint64_t slot_va, uint64_t cmd, const CONTEXT* regs) {
    // always the private device, the shared one gets its context moved by unrelated actions
    auto* dev = kdev_.get();
    if (!dev || !slot_va) return;
    if (regs) {
        // context first command last, the parked thread only acts on the command
        dev->write_raw(slot_va + veh::kContextOff, regs, veh::kContextSize);
    }
    dev->write_raw(slot_va + veh::kCmdOff, &cmd, 8);
}

void debugger_t::ksuspend_all() {
    // private device, the stable pid binding matters here too
    auto* dev = kdev_.get();
    if (!dev) return;
    for (const auto& t : dev->enumerate_threads()) {
        if (t.tid != 0) dev->suspend_thread(t.tid);
    }
}

void debugger_t::kresume_all() {
    auto* dev = kdev_.get();
    if (!dev) return;
    for (const auto& t : dev->enumerate_threads()) {
        if (t.tid != 0) dev->resume_thread(t.tid);
    }
}

void debugger_t::kfreeze_world(uint32_t except_tid) {
    if (kworld_frozen_ || !kdev_) return;
    for (const auto& t : kdev_->enumerate_threads()) {
        if (t.tid != 0 && t.tid != except_tid) kdev_->suspend_thread(t.tid);
    }
    kworld_frozen_ = true;
}

void debugger_t::kunfreeze_world() {
    if (!kworld_frozen_) return;
    kresume_all();
    kworld_frozen_ = false;
}

bool debugger_t::suspend_all() {
    if (pid_ == 0 || backend_ == nullptr) return false;
    if (auto* dev = kdev_.get()) {          // kernel-stealth session
        for (const auto& t : dev->enumerate_threads())
            if (t.tid != 0) dev->suspend_thread(t.tid);
        return true;
    }
    // user mode session on a kernel backend, the shared device is bound by the attach
    auto* kernel = dynamic_cast<runtime::backend_kernel_t*>(backend_);
    auto* dev = kernel ? kernel->device() : nullptr;
    if (!dev || !kernel->hwbp_supported()) return false;
    for (const auto& t : dev->enumerate_threads())
        if (t.tid != 0) dev->suspend_thread(t.tid);
    return true;
}

bool debugger_t::resume_all() {
    if (pid_ == 0 || backend_ == nullptr) return false;
    if (auto* dev = kdev_.get()) {
        for (const auto& t : dev->enumerate_threads())
            if (t.tid != 0) dev->resume_thread(t.tid);
        return true;
    }
    auto* kernel = dynamic_cast<runtime::backend_kernel_t*>(backend_);
    auto* dev = kernel ? kernel->device() : nullptr;
    if (!dev || !kernel->hwbp_supported()) return false;
    for (const auto& t : dev->enumerate_threads())
        if (t.tid != 0) dev->resume_thread(t.tid);
    return true;
}

bool debugger_t::attach(uint32_t pid) {
    if (state_.load() != dbg_state_t::idle) return false;

    backend_ = &runtime::active();
    pid_     = pid;

    mem_handle_ = backend_->attach(pid);
    if (!mem_handle_.valid()) return false;

    engine_.init();

    // stealth mode means no debug object and no handles, picked when the driver is live and armed, else the classic win32 loop
    bool stealth = runtime::active_kind() == runtime::backend_kind_t::kernel &&
                   infra::settings::stealth_kernel_debug() &&
                   kattach(pid);

    quit_.store(false);
    attach_done_.store(false);
    attach_result_.store(false);
    state_.store(dbg_state_t::running);
    mode_ = stealth ? dbg_mode_t::kernel_stealth : dbg_mode_t::user_debug_object;

    debug_event_t e;
    e.kind  = event_kind_t::attached;
    e.at_ms = slop::core::infra::steady_ms();
    e.text  = "attaching to pid " + std::to_string(pid) +
              (stealth ? " (kernel-stealth, no debug object)" : "");
    push_event(e);

    if (stealth) {
        // the monitor is armed so the worker just polls
        attach_result_.store(true);
        attach_done_.store(true);
        worker_ = std::thread([this] { kloop(); });
    } else {
        // debugactiveprocess caches the handle in the calling threads teb so the loop thread does the attach itself
        worker_ = std::thread([this] {
            if (!DebugActiveProcess(pid_)) {
                dbg_loop_trace("DebugActiveProcess FAILED", GetLastError(), pid_);
                backend_->detach(mem_handle_);
                pid_ = 0;
                state_.store(dbg_state_t::idle);
                attach_result_.store(false);
                attach_done_.store(true);
                return;
            }
            dbg_loop_trace("DebugActiveProcess OK", 0, pid_);
            attach_result_.store(true);
            attach_done_.store(true);
            loop();
        });
    }

    // wait for the loop threads verdict
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!attach_done_.load()) {
        if (std::chrono::steady_clock::now() > deadline) {
            dbg_loop_trace("attach verdict timeout", 0, pid_);
            detach();
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    if (!attach_result_.load()) {
        if (worker_.joinable()) worker_.join();
        pid_ = 0;
        state_.store(dbg_state_t::idle);
        mode_ = dbg_mode_t::idle;
        return false;
    }

    debug_event_t ok;
    ok.kind  = event_kind_t::attached;
    ok.at_ms = slop::core::infra::steady_ms();
    ok.text  = "attached to pid " + std::to_string(pid) +
               (stealth ? " (kernel-stealth)" : "");
    push_event(ok);
    return true;
}

void debugger_t::detach() {
    if (state_.load() == dbg_state_t::idle && !worker_.joinable()) return;

    {
        std::lock_guard<std::mutex> lk(mu_);
        // stealth disarms flip code pages, freeze for the whole batch
        kfreeze_world();
        for (auto& bp : *bps_.all()) {
            if (bp.hardware) {
                auto* kernel = dynamic_cast<runtime::backend_kernel_t*>(backend_);
                if (kernel) kernel->clear_hw_breakpoint(pid_, bp.hw_slot, 0);
            } else {
                disarm_bp(bp);
            }
        }
        // restore the pre guard protection
        for (const auto& w : watches_) {
            uint32_t ignored = 0;
            if (kdev_) {
                kdev_->protect_memory(w.addr, w.len, w.orig_prot, &ignored);
            } else {
                backend_->protect_memory(mem_handle_, w.addr, w.len,
                                         w.orig_prot, &ignored);
            }
        }
        watches_.clear();
    }

    quit_.store(true);
    // wake both loop flavors or a stealth detach mid pause deadlocks on the join
    cv_.notify_all();

    if (worker_.joinable()) worker_.join();

    if (mode_ == dbg_mode_t::kernel_stealth) {
        // thaw frozen threads before kdetach, the veh removal needs runnable threads
        // threads (kcall hijacks a live one; a suspended thread never
        // executes the rewritten context)
        kunfreeze_world();
        kdetach();
    }

    if (pid_ != 0) backend_->detach(mem_handle_);

    // Drop every breakpoint record: they belonged to the session that just
    // ended. Stale entries block bp_set at the same address on the next
    // attach (bp_store_t::add rejects duplicates) and claim DR slots that
    // were never programmed in the new target
    {
        std::lock_guard<std::mutex> lk(mu_);
        bps_.all()->clear();
        hit_bp_     = nullptr;
        rearm_pause_ = false;
    }

    debug_event_t e;
    e.kind  = event_kind_t::detached;
    e.at_ms = slop::core::infra::steady_ms();
    push_event(e);

    state_.store(dbg_state_t::idle);
    mode_ = dbg_mode_t::idle;
    pid_ = 0;
}

void debugger_t::request_resume(step_action_t plan) {
    {
        std::lock_guard<std::mutex> lk(mu_);
        pending_plan_ = plan;
        resume_mode_  = resume_mode_t::apply_plan;
    }
    cv_.notify_one();
}

void debugger_t::go()        { request_resume({ step_action_t::none, 0 }); }
void debugger_t::step_into() { request_resume({ step_action_t::trap_flag, 0 }); }

void debugger_t::step_over() {
    runtime::thread_context_t ctx;
    {
        std::lock_guard<std::mutex> lk(mu_);
        ctx = paused_ctx_;
    }
    auto insn = decode_at(ctx.rip);
    request_resume(insn ? plan_step_over(*insn)
                        : step_action_t{ step_action_t::trap_flag, 0 });
}

void debugger_t::step_out() {
    runtime::thread_context_t ctx;
    {
        std::lock_guard<std::mutex> lk(mu_);
        ctx = paused_ctx_;
    }
    uint64_t ret = 0;
    if (kdev_) {
        (void)(kdev_->read_raw(ctx.rsp, &ret, 8) == 8);
    } else {
        (void)backend_->read_memory(mem_handle_, ctx.rsp, &ret, 8);
    }
    request_resume(plan_step_out(ctx.rsp, ret));
}

// Loop

void debugger_t::loop() {
    DEBUG_EVENT ev{};

    for (;;) {
        if (quit_.load()) break;
        if (!WaitForDebugEventEx(&ev, 100)) {
            const DWORD gle = GetLastError();
            if (gle != ERROR_SEM_TIMEOUT) {
                dbg_loop_trace("wait_failed", gle, 0);
            }
            continue;
        }
        dbg_loop_trace("event", ev.dwDebugEventCode, ev.dwThreadId);

        DWORD status = DBG_CONTINUE;
        bool   pause_after = false;
        bool   stop_all    = false;
        debug_event_t out;
        out.tid   = ev.dwThreadId;
        out.at_ms = slop::core::infra::steady_ms();

        switch (ev.dwDebugEventCode) {
        case CREATE_THREAD_DEBUG_EVENT:
            out.kind    = event_kind_t::thread_create;
            out.address = reinterpret_cast<uint64_t>(ev.u.CreateThread.lpStartAddress);
            push_event(out);
            break;

        case EXIT_THREAD_DEBUG_EVENT:
            out.kind = event_kind_t::thread_exit;
            push_event(out);
            break;

        case LOAD_DLL_DEBUG_EVENT: {
            out.kind = event_kind_t::dll_load;
            out.address = reinterpret_cast<uint64_t>(ev.u.LoadDll.lpBaseOfDll);
            if (ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
            push_event(out);
            break;
        }

        case UNLOAD_DLL_DEBUG_EVENT:
            out.kind    = event_kind_t::dll_unload;
            out.address = reinterpret_cast<uint64_t>(ev.u.UnloadDll.lpBaseOfDll);
            push_event(out);
            break;

        case EXIT_PROCESS_DEBUG_EVENT:
            out.kind = event_kind_t::process_exit;
            push_event(out);
            stop_all = true;
            break;

        case EXCEPTION_DEBUG_EVENT: {
            const auto& ei = ev.u.Exception.ExceptionRecord;
            out.exc_code = static_cast<uint32_t>(ei.ExceptionCode);
            out.address        = reinterpret_cast<uint64_t>(ei.ExceptionAddress);

            // Which continuation did the user queue while we were blocked?
            resume_mode_t mode;
            step_action_t plan;
            breakpoint_t* hit = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu_);
                mode = resume_mode_;
                plan = pending_plan_;
                hit  = hit_bp_;
            }

            if (ei.ExceptionCode == kStatusBreakpoint) {
                // Windows reports RIP past the one-byte int3
                const uintptr_t site = reinterpret_cast<uintptr_t>(ei.ExceptionAddress) - 1;

                breakpoint_t* bp = nullptr;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    bp = bps_.find(site);
                }

                if (bp != nullptr && bp->armed) {
                    disarm_bp(*bp);                       // reveal original byte
                    ++bp->hits;

                    backend_->get_thread_context(ev.dwThreadId, out.ctx);

                    // Conditional / tracepoint evaluation
                    bool stop_here = true;
                    if (!bp->condition.empty()) {
                        const cond_eval_t ce = parse_condition(bp->condition);
                        if (ce.valid && !eval_condition(ce, out.ctx)) {
                            debug_event_t skip = out;
                            skip.kind  = event_kind_t::note;
                            skip.text  = "bp @ " + std::to_string(site) +
                                         " skipped (condition '" +
                                         bp->condition + "' false)";
                            push_event(skip);
                            stop_here = false;
                        }
                    }
                    if (stop_here && bp->auto_continue) {
                        debug_event_t log = out;
                        log.kind  = event_kind_t::note;
                        log.text  = bp->log_text.empty()
                                        ? "bp @ " + std::to_string(site)
                                        : bp->log_text;
                        log.address = site;
                        push_event(log);
                        stop_here = false;
                    }

                    if (!stop_here) {
                        // Auto-resume: single-step over the disarmed site,
                        // the step_rearm pass replaces CC afterwards
                        hit_bp_ = bp;
                        set_tf(ev.dwThreadId, true);
                        std::lock_guard<std::mutex> lk2(mu_);
                        resume_mode_ = resume_mode_t::step_rearm;
                        status = DBG_CONTINUE;
                        break;
                    }

                    hit_bp_ = bp;
                    out.kind = event_kind_t::bp_hit;
                    out.address = site;
                    push_event(out);
                    pause_after = true;
                } else if (mode == resume_mode_t::apply_plan &&
                           plan.kind == step_action_t::temp_breakpoint &&
                           site == plan.temp_addr) {
                    // Temporary breakpoint landed: pause here
                    backend_->get_thread_context(ev.dwThreadId, out.ctx);
                    // Restore the byte we borrowed and drop the temp entry
                    breakpoint_t* tmp = nullptr;
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        tmp = bps_.find(site);
                        if (tmp) { disarm_bp(*tmp); }
                    }
                    if (tmp) {
                        std::lock_guard<std::mutex> lk(mu_);
                        bps_.remove(site);
                    }
                    out.kind = event_kind_t::single_step;
                    push_event(out);
                    pause_after = true;
                } else {
                    // System breakpoint from DebugActiveProcess (or foreign)
                    backend_->get_thread_context(ev.dwThreadId, out.ctx);
                    out.kind = event_kind_t::exception;
                    out.text = "system breakpoint";
                    push_event(out);
                    pause_after = true;
                }
            } else if (ei.ExceptionCode == kStatusGuardPage) {
                // Page-guard watchpoints: report the access, re-arm, keep
                // running. ExceptionInformation[0]: 0=read 1=write 2=exec;
                // [1]: touched address
                const uint64_t access_type =
                    ei.NumberParameters >= 1 ? ei.ExceptionInformation[0] : 0;
                const uint64_t fault =
                    ei.NumberParameters >= 2
                        ? static_cast<uint64_t>(ei.ExceptionInformation[1])
                        : reinterpret_cast<uint64_t>(ei.ExceptionAddress);

                watchpoint_t* wp = nullptr;
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    for (auto& w : watches_) {
                        const uint64_t page = fault & ~0xFFFull;
                        if ((fault >= w.addr && fault < w.addr + w.len) ||
                            (page >= w.addr && page < w.addr + w.len)) {
                            wp = &w;
                            break;
                        }
                    }
                }

                if (wp != nullptr) {
                    ++wp->hits;

                    backend_->get_thread_context(ev.dwThreadId, out.ctx);
                    out.kind    = event_kind_t::bp_hit;
                    out.address = fault;

                    char desc[128];
                    std::snprintf(desc, sizeof(desc),
                                  "watchpoint %s @ 0x%llX (hit #%llu)",
                                  access_type == 0 ? "READ"
                                  : access_type == 1 ? "WRITE"
                                                     : "EXEC",
                                  static_cast<unsigned long long>(fault),
                                  static_cast<unsigned long long>(wp->hits));
                    out.text = desc;
                    push_event(out);

                    // the guard bit gets consumed by the exception so re-arm it
                    uint32_t prot = 0, ignored = 0;
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        prot = wp->orig_prot;
                    }
                    backend_->protect_memory(mem_handle_, wp->addr, wp->len,
                                             prot | kPageGuardFlag, &ignored);

                    status = DBG_CONTINUE;   // free run; hits stream as events
                } else {
                    // Foreign guard page: hand it to the target's SEH
                    backend_->get_thread_context(ev.dwThreadId, out.ctx);
                    out.kind = event_kind_t::exception;
                    out.text = "guard page (foreign)";
                    push_event(out);
                    pause_after = true;
                    status = DBG_EXCEPTION_NOT_HANDLED;
                }
            } else if (ei.ExceptionCode == kStatusSingleStep) {
                const bool rearming = [&] {
                    std::lock_guard<std::mutex> lk(mu_);
                    return resume_mode_ == resume_mode_t::step_rearm;
                }();

                if (rearming) {
                    // We just stepped over an armed bp site to re-place it
                    bool pause_after_rearm = false;
                    {
                        std::lock_guard<std::mutex> lk(mu_);
                        if (hit_bp_) {
                            if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                            else arm_bp(*hit_bp_);
                            hit_bp_ = nullptr;
                        }
                        pause_after_rearm = rearm_pause_;
                        rearm_pause_      = false;
                    }
                    resume_mode_ = resume_mode_t::none;
                    if (pause_after_rearm) {
                        // Explicit user step off a bp site: the re-arm step
                        // doubles as the requested step, report + pause
                        out.kind = event_kind_t::single_step;
                        push_event(out);
                        pause_after = true;
                        break;
                    }
                } else {
                    backend_->get_thread_context(ev.dwThreadId, out.ctx);
                    out.kind = event_kind_t::single_step;
                    push_event(out);
                    pause_after = true;
                }
            } else {
                backend_->get_thread_context(ev.dwThreadId, out.ctx);
                out.kind = event_kind_t::exception;
                char code[16];
                std::snprintf(code, sizeof(code), "%08X", ei.ExceptionCode);
                out.text = "exception " + std::string(code) +
                           (ev.u.Exception.dwFirstChance ? " (first chance)" : "");
                push_event(out);
                pause_after = true;
                // Non-breakpoint exceptions pass through to the target's SEH
                status = DBG_EXCEPTION_NOT_HANDLED;
            }
            break;
        }

        default:
            break;
        }

        // Paused wait: hold the debuggee until the user resumes
        if (pause_after) {
            {
                std::lock_guard<std::mutex> lk(mu_);
                paused_tid_ = ev.dwThreadId;
                backend_->get_thread_context(ev.dwThreadId, paused_ctx_);
                state_.store(dbg_state_t::paused);
                resume_mode_ = resume_mode_t::none;
            }

            std::unique_lock<std::mutex> lk(mu_);
            cv_.wait(lk, [&] {
                return quit_.load() || resume_mode_ != resume_mode_t::none;
            });

            if (!quit_.load()) {
                const step_action_t plan   = pending_plan_;
                const bool     sitting_on_hit = (hit_bp_ != nullptr);

                switch (plan.kind) {
                case step_action_t::trap_flag:
                    // Stepping while parked on a disarmed bp site: do NOT
                    // re-place CC yet (instant re-trap). Re-arm after the
                    // single-step lands via the step_rearm pass, and since
                    // this is an explicit user step, pause after re-arming
                    set_tf(ev.dwThreadId, true);
                    rearm_pause_ = sitting_on_hit;
                    resume_mode_ = sitting_on_hit ? resume_mode_t::step_rearm
                                                  : resume_mode_t::none;
                    break;

                case step_action_t::temp_breakpoint: {
                    // Borrow the byte at the temp address and plant CC
                    uint8_t probe = 0xCC;
                    if (backend_->read_memory(mem_handle_, plan.temp_addr,
                                              &probe, 1).ok) {
                        const uint8_t cc = 0xCC;
                        if (backend_->write_memory(mem_handle_, plan.temp_addr,
                                                   &cc, 1).ok) {
                            bps_.add(plan.temp_addr, probe, false);
                        }
                    }
                    // Parked-on-hit bp is far from the temp site: safe now
                    if (sitting_on_hit && hit_bp_) {
                        if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                        else arm_bp(*hit_bp_);
                        hit_bp_ = nullptr;
                    }
                    resume_mode_ = resume_mode_t::none;
                    break;
                }

                case step_action_t::none:
                default:
                    // Free run: put the bp byte back before releasing
                    if (sitting_on_hit && hit_bp_) {
                        if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                        else arm_bp(*hit_bp_);
                        hit_bp_ = nullptr;
                    }
                    resume_mode_ = resume_mode_t::none;
                    break;
                }

                state_.store(dbg_state_t::running);
            } else {
                resume_mode_ = resume_mode_t::none;
            }
            lk.unlock();

            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
            if (quit_.load()) break;
            continue;
        }

        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);

        if (stop_all) {
            state_.store(dbg_state_t::idle);
            quit_.store(true);
            break;
        }
    }

    // The loop thread owns the debug-object handle in its TEB (see attach),
    // so the port teardown happens HERE, on this thread. Doing it from the
    // the detaching threads teb has no handle so it fails quietly
    if (pid_ != 0) {
        DebugActiveProcessStop(pid_);
    }
}

// Kernel-stealth loop
//
// Event source is the injected VEH stub (see veh_stub.hpp). The faulting
// thread parks inside its own exception dispatch (user-mode VEH) until we
// write a command into its slot, that parked thread IS the pause. State
// machine mirrors loop(): bp site match -> disarm -> condition/tracepoint ->
// pause or auto-continue (release + single-step rearm); DR hits classified
// from the CONTEXT's Dr6; guard pages re-armed through protect_memory

void debugger_t::kloop() {
    auto* dev = kdev_.get();
    if (!dev || !kpage_) return;

    std::vector<uint8_t> slot(veh::kSlotStride);
    int dead_polls = 0;
    constexpr int kMaxDeadPolls = 500;   // about a second of dead reads means the device is gone

    // Target-death watchdog: a dead target's DTB reads keep "succeeding"
    // against freed physical pages (all-zero slots, forever), so the
    // kloop would poll quietly until the end of time. TENUM through the
    // private device is the reliable signal, the driver looks the process
    // up by pid and returns an empty thread list once it is gone
    int  liveness_polls  = 0;
    int  empty_enums     = 0;
    auto target_dead = [&]() {
        if (++liveness_polls < 500) return false;   // check ~1x / second
        liveness_polls = 0;
        if (!dev->enumerate_threads().empty()) { empty_enums = 0; return false; }
        return ++empty_enums >= 3;                  // debounce: 3 s empty
    };

    for (;;) {
        if (quit_.load()) break;

        if (target_dead()) {
            debug_event_t e;
            e.kind  = event_kind_t::process_exit;
            e.at_ms = slop::core::infra::steady_ms();
            e.text  = "target exited (kernel-stealth)";
            push_event(e);
            state_.store(dbg_state_t::idle);
            break;
        }

        if (state_.load() != dbg_state_t::paused) {
            bool any_read_ok = false;
            for (int i = 0; i < veh::kSlotCount; ++i) {
                if (quit_.load()) break;
                const uint64_t slot_va =
                    kpage_ + veh::kSlotsOff + i * veh::kSlotStride;
                uint8_t hdr[0x40];
                if (dev->read_raw(slot_va, hdr, sizeof(hdr)) != sizeof(hdr))
                    continue;
                any_read_ok = true;
                if (hdr[0] != 1) continue;   // slot state != hit
                // Heartbeat: keep the parked thread's wait counter at 0 so
                // it never times out while this loop is alive
                const uint64_t zero = 0;
                dev->write_raw(slot_va + veh::kSlotWait, &zero, 8);
                if (dev->read_raw(slot_va, slot.data(), slot.size()) != slot.size())
                    continue;
                handle_veh_slot(slot_va, slot.data());
            }

            if (any_read_ok) {
                dead_polls = 0;
            } else if (++dead_polls >= kMaxDeadPolls) {
                // Driver unloaded / service stopped under us: stop polling
                // instead of spinning on a dead handle forever
                debug_event_t e;
                e.kind  = event_kind_t::note;
                e.at_ms = slop::core::infra::steady_ms();
                e.text  = "kernel-stealth: driver reads failing, event loop stopped";
                push_event(e);
                state_.store(dbg_state_t::idle);
                break;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
            continue;
        }

        // Parked on a pause? Wait for the user's resume command. The wait is
        // PERIODIC (not an open cv_.wait): while paused nothing else refreshes
        // the parked thread's heartbeat, and the stub self-releases after
        // ~30 s of stale wait counter, which would silently un-park the
        // thread mid-analysis and desynchronize the whole session
        std::unique_lock<std::mutex> lk(mu_);
        while (!quit_.load() && resume_mode_ == resume_mode_t::none) {
            const uint64_t parked = kparked_slot_;
            if (parked != 0) {
                lk.unlock();
                const uint64_t zero = 0;
                dev->write_raw(parked + veh::kSlotWait, &zero, 8);
                lk.lock();
            }
            cv_.wait_for(lk, std::chrono::milliseconds(500));
        }
        if (quit_.load()) break;

        const step_action_t plan = pending_plan_;
        const bool sitting_on_hit = (hit_bp_ != nullptr);

        switch (plan.kind) {
        case step_action_t::trap_flag: {
            // Single-step: set TF in the released CONTEXT; if we're sitting
            // on a disarmed bp site, re-arm via the step_rearm pass. An
            // EXPLICIT user step must pause again after the re-arm, the
            // same mechanism serves tracepoint auto-continue, which must
            // not pause; rearm_pause_ distinguishes the two. The TF makes
            // the released context differ from the stub's capture, mark
            // it dirty so the release actually rewrites it
            kparked_win_.EFlags |= 0x100;   // TF
            runtime::context_from_win(kparked_regs_, kparked_win_);
            kparked_dirty_ = true;
            rearm_pause_ = sitting_on_hit;
            resume_mode_ = sitting_on_hit ? resume_mode_t::step_rearm
                                          : resume_mode_t::none;
            break;
        }

        case step_action_t::temp_breakpoint: {
            // Borrow the byte at the temp address and plant CC
            uint8_t probe = 0xCC;
            if (dev->read_raw(plan.temp_addr, &probe, 1) == 1) {
                if (write_byte_stealth(dev, plan.temp_addr, 0xCC)) {
                    bps_.add(plan.temp_addr, probe, false);
                }
            }
            if (sitting_on_hit && hit_bp_) {
                if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                else arm_bp(*hit_bp_);
                hit_bp_ = nullptr;
            }
            resume_mode_ = resume_mode_t::none;
            break;
        }

        case step_action_t::none:
        default:
            // Free run: put the bp byte back before releasing
            if (sitting_on_hit && hit_bp_) {
                if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                else arm_bp(*hit_bp_);
                hit_bp_ = nullptr;
            }
            resume_mode_ = resume_mode_t::none;
            break;
        }

        // Release the parked faulting thread, then let everyone else run
        // again. The released thread may re-trap (TF step / temp bp) before
        // the thaw lands, it parks again while the world stays frozen,
        // which is exactly what the re-arm pass wants. The slot CONTEXT is
        // rewritten ONLY when the user modified registers: the stub's own
        // captured context is byte-identical otherwise, and a cmd-only
        // release is the path the standalone probe validated
        krelease_slot(kparked_slot_, veh::kCmdContinue,
                      kparked_dirty_ ? &kparked_win_ : nullptr);
        kparked_slot_ = 0;
        state_.store(dbg_state_t::running);
        lk.unlock();
        kunfreeze_world();
    }
}

void debugger_t::handle_veh_slot(uint64_t slot_va, const uint8_t* slot) {
    auto rd64 = [&](uint64_t off) {
        uint64_t v = 0;
        std::memcpy(&v, slot + off, 8);
        return v;
    };

    const uint32_t tid  = static_cast<uint32_t>(rd64(veh::kSlotTid));
    const uint32_t code = static_cast<uint32_t>(rd64(veh::kSlotCode));
    const uint64_t info0 = rd64(veh::kSlotInfo0);
    const uint64_t info1 = rd64(veh::kSlotInfo1);

    // Full OS context from the slot
    CONTEXT win{};
    std::memcpy(&win, slot + veh::kContextOff, sizeof(win));

    debug_event_t out;
    out.tid   = tid;
    out.at_ms = slop::core::infra::steady_ms();
    runtime::context_from_win(out.ctx, win);

    auto kpause = [&](const CONTEXT& w, const runtime::thread_context_t& ctx) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            paused_tid_    = tid;
            paused_ctx_    = ctx;
            kparked_slot_  = slot_va;
            kparked_win_   = w;
            kparked_regs_  = ctx;
            kparked_dirty_ = false;   // set_register flips this
            state_.store(dbg_state_t::paused);
            resume_mode_ = resume_mode_t::none;
        }
        // Freeze the rest of the process while we inspect (tracked so the
        // page flips below always run against a frozen world)
        kfreeze_world();
    };

    if (code == kStatusBreakpoint) {
        // KiDispatchException rewinds RIP past the int3 for user-mode
        // dispatch, so the CONTEXT's Rip IS the site (ExceptionAddress
        // still points past the CC)
        const uintptr_t site = static_cast<uintptr_t>(win.Rip);

        breakpoint_t* bp = nullptr;
        {
            std::lock_guard<std::mutex> lk(mu_);
            bp = bps_.find(site);
        }

        if (bp != nullptr && bp->armed) {
            ++bp->hits;

            // Conditional / tracepoint evaluation (same as the Win32 loop)
            // Runs BEFORE any page flip: the evaluator only touches the
            // captured context, so the breakpoint byte can stay armed
            // until we know which release path is taken
            bool stop_here = true;
            if (!bp->condition.empty()) {
                const cond_eval_t ce = parse_condition(bp->condition);
                if (ce.valid && !eval_condition(ce, out.ctx)) {
                    debug_event_t skip = out;
                    skip.kind  = event_kind_t::note;
                    skip.text  = "bp @ " + std::to_string(site) +
                                 " skipped (condition '" +
                                 bp->condition + "' false)";
                    push_event(skip);
                    stop_here = false;
                }
            }
            if (stop_here && bp->auto_continue) {
                debug_event_t log = out;
                log.kind  = event_kind_t::note;
                log.text  = bp->log_text.empty()
                                ? "bp @ " + std::to_string(site)
                                : bp->log_text;
                log.address = site;
                push_event(log);
                stop_here = false;
            }

            if (!stop_here) {
                // Auto-resume: single-step over the disarmed site, the
                // step_rearm pass replaces CC afterwards. Freeze everyone
                // EXCEPT this thread, it must run the step, then flip
                // the page for the disarm (the flip makes the page
                // non-executable; a running thread would die on NX)
                {
                    std::lock_guard<std::mutex> lk(mu_);
                    hit_bp_ = bp;
                    resume_mode_ = resume_mode_t::step_rearm;
                }
                kfreeze_world(tid);
                disarm_bp(*bp);
                win.EFlags |= 0x100;   // TF
                krelease_slot(slot_va, veh::kCmdContinue, &win);
                return;
            }

            // Pausing here: freeze everything (the parked thread is going
            // nowhere) so the disarm's page flip is safe
            kfreeze_world();
            disarm_bp(*bp);                       // reveal original byte
            {
                std::lock_guard<std::mutex> lk(mu_);
                hit_bp_ = bp;
            }
            out.kind = event_kind_t::bp_hit;
            out.address = site;
            push_event(out);
            kpause(win, out.ctx);
            return;
        }

        // Temp-breakpoint landing (step over/out)
        resume_mode_t mode;
        step_action_t plan;
        {
            std::lock_guard<std::mutex> lk(mu_);
            mode = resume_mode_;
            plan = pending_plan_;
        }
        if (mode == resume_mode_t::apply_plan &&
            plan.kind == step_action_t::temp_breakpoint &&
            site == plan.temp_addr) {
            breakpoint_t* tmp = nullptr;
            {
                std::lock_guard<std::mutex> lk(mu_);
                tmp = bps_.find(site);
            }
            kfreeze_world();   // disarm flips the page, frozen world
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (tmp) disarm_bp(*tmp);
                if (tmp) bps_.remove(site);
            }
            out.kind = event_kind_t::single_step;
            push_event(out);
            kpause(win, out.ctx);
            return;
        }

        // Foreign int3 (not ours): pause on it like the Win32 loop does  
        // the analyst decides (anti-debug int3 traps land here)
        out.kind = event_kind_t::exception;
        out.exc_code = code;
        out.text = "foreign breakpoint";
        push_event(out);
        kpause(win, out.ctx);
        return;
    }

    if (code == kStatusSingleStep) {
        const bool rearming = [&] {
            std::lock_guard<std::mutex> lk(mu_);
            return resume_mode_ == resume_mode_t::step_rearm;
        }();

        if (rearming) {
            // We just stepped over an armed bp site to re-place it. The
            // world may already be thawed (user-step path released and
            // unfroze before this trap landed), re-freeze everyone except
            // THIS thread (it is parked in its slot; the others must not
            // fetch code while the re-arm flips the page RX->RW->RX)
            kfreeze_world(tid);
            bool pause_after_rearm = false;
            {
                std::lock_guard<std::mutex> lk(mu_);
                if (hit_bp_) {
                    if (hit_bp_->one_shot) bps_.remove(hit_bp_->addr);
                    else arm_bp(*hit_bp_);
                    hit_bp_ = nullptr;
                }
                pause_after_rearm = rearm_pause_;
                rearm_pause_      = false;
                resume_mode_      = resume_mode_t::none;
            }
            if (pause_after_rearm) {
                // Explicit user step off a bp site: the re-arm step is also
                // the step the user asked for, report it and pause (the
                // others stay frozen; kpause's freeze is a tracked no-op)
                out.kind = event_kind_t::single_step;
                push_event(out);
                kpause(win, out.ctx);
                return;
            }
            // Tracepoint auto-continue: re-arm done, back to free running
            krelease_slot(slot_va, veh::kCmdContinue, nullptr);
            kunfreeze_world();
            return;
        }

        // DR hit on one of our HW breakpoints, or a TF step
        const uint64_t dr6 = win.Dr6;
        const uint64_t dr7 = win.Dr7;
        const bool dr_hit = (dr6 & 0xF) != 0 && (dr7 & 0xFF) != 0;
        out.kind = dr_hit ? event_kind_t::bp_hit : event_kind_t::single_step;
        if (dr_hit) {
            // Map the DR6 slot bits to the owning hardware bp. Snapshot the
            // store under mu_: MCP bp_set/bp_clear mutate it concurrently
            // and an unlocked scan dangles
            const uint64_t bits = dr6 & 0xF;
            std::optional<breakpoint_t> match;
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (const auto& b : *bps_.all()) {
                    if (b.hardware && (bits & (1ull << b.hw_slot))) {
                        match = b;
                        break;
                    }
                }
            }
            if (match) {
                out.address = match->addr;
                char desc[128];
                std::snprintf(desc, sizeof(desc),
                              "hw bp slot %u @ 0x%llX",
                              match->hw_slot,
                              static_cast<unsigned long long>(match->addr));
                out.text = desc;
            }
        }
        push_event(out);
        kpause(win, out.ctx);
        return;
    }

    if (code == kStatusGuardPage) {
        // Watchpoint hit: report, re-arm the guard, auto-continue
        const uint64_t access_type = info0;   // 0=read 1=write 2=exec
        const uint64_t fault = info1;         // touched address

        watchpoint_t* wp = nullptr;
        {
            std::lock_guard<std::mutex> lk(mu_);
            for (auto& w : watches_) {
                const uint64_t page = fault & ~0xFFFull;
                if ((fault >= w.addr && fault < w.addr + w.len) ||
                    (page >= w.addr && page < w.addr + w.len)) {
                    wp = &w;
                    break;
                }
            }
        }

        if (wp != nullptr) {
            ++wp->hits;
            out.kind    = event_kind_t::bp_hit;
            out.address = fault;
            char desc[128];
            std::snprintf(desc, sizeof(desc),
                          "watchpoint %s @ 0x%llX (hit #%llu)",
                          access_type == 0 ? "READ"
                          : access_type == 1 ? "WRITE"
                                             : "EXEC",
                          static_cast<unsigned long long>(fault),
                          static_cast<unsigned long long>(wp->hits));
            out.text = desc;
            push_event(out);

            // Guard bit consumed by the exception, re-arm and continue
            uint32_t prot = 0, ignored = 0;
            {
                std::lock_guard<std::mutex> lk(mu_);
                prot = wp->orig_prot;
            }
            if (kdev_) kdev_->protect_memory(wp->addr, wp->len,
                                             prot | kPageGuardFlag, &ignored);
            else backend_->protect_memory(mem_handle_, wp->addr, wp->len,
                                          prot | kPageGuardFlag, &ignored);
            krelease_slot(slot_va, veh::kCmdContinue, nullptr);
            return;
        }

        // Foreign guard page (stack growth, allocator tricks): forward so
        // the target's own handling proceeds unchanged
        krelease_slot(slot_va, veh::kCmdForward, nullptr);
        return;
    }

    // Anything else the stub filtered in: forward (should not happen)
    krelease_slot(slot_va, veh::kCmdForward, nullptr);
}

} // namespace slop::core::debugger
