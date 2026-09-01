#pragma once

// src/core/debugger/debugger.hpp
// the debug loop engine, memory writes ride the active backend so hw breakpoints and patching survive where user mode is blocked
// the pure planning helpers are split out so they test without the os loop

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/runtime/backend.hpp"

#include <windows.h>

#include <memory>

#include "core/runtime/voyager_comm.h"

namespace slop::core::debugger {

enum class dbg_state_t : uint8_t { idle, running, paused };

// Event channel the engine runs on
enum class dbg_mode_t : uint8_t {
    idle,             // not attached
    kernel_stealth,   // driver exception monitor: no debug object, no handles
    user_debug_object // classic Win32 loop (fallback when the driver is absent)
};

const char* dbg_mode_name(dbg_mode_t m) noexcept;

enum class event_kind_t : uint8_t {
    attached,
    detached,
    bp_hit,
    single_step,
    exception,
    thread_create,
    thread_exit,
    dll_load,
    dll_unload,
    process_exit,
    note
};

struct debug_event_t {
    event_kind_t     kind = event_kind_t::note;
    uint32_t         tid  = 0;
    uint64_t         address = 0;        // RIP / bp site / exception address
    uint32_t         exc_code = 0;
    std::string      text;
    runtime::thread_context_t ctx{};         // valid on pause events
    int64_t          at_ms = 0;
};

struct breakpoint_t {
    uintptr_t addr       = 0;
    bool      enabled    = true;
    bool      hardware   = false;          // DR0-3 via driver path
    uint8_t   hw_slot    = 0;              // DR0-3 slot (valid when hardware)
    uint8_t   hw_type    = 0;              // 0=exec 1=write 3=read/write
    uint8_t   hw_len     = 1;              // 1/2/4/8 bytes
    uint8_t   orig_byte  = 0xCC;           // stashed first byte
    bool      armed      = false;          // 0xCC currently written
    uint32_t  hits       = 0;

    // tracepoint and conditional extras, condition is a reg op value expression and empty means always stop
    std::string condition;
    std::string log_text;
    bool        auto_continue = false;
    bool        one_shot      = false;
};

struct watchpoint_t {
    uint64_t addr      = 0;
    size_t   len       = 0;              // region covered by the guard page(s)
    uint32_t orig_prot = 0;              // protection before PAGE_GUARD
    uint64_t hits      = 0;
};

// Pure planners

struct step_action_t {
    enum kind_t : uint8_t { none, trap_flag, temp_breakpoint };
    kind_t   kind = none;
    uint64_t temp_addr = 0;              // valid when temp_breakpoint
};

// step over plants a temp bp after calls and single steps everything else
step_action_t plan_step_over(const disasm::insn_t& at_rip);

// step out breaks on the return address
step_action_t plan_step_out(uint64_t rsp, uint64_t return_addr);

// breakpoint store, pure and mutex free

class bp_store_t {
public:
    bool        add(uintptr_t addr, uint8_t orig_byte, bool hw);
    bool        remove(uintptr_t addr);
    breakpoint_t* find(uintptr_t addr);
    std::vector<breakpoint_t>* all() noexcept { return &bps_; }
    const std::vector<breakpoint_t>* all() const noexcept { return &bps_; }
    size_t size() const noexcept { return bps_.size(); }

private:
    std::vector<breakpoint_t> bps_;
};

// Engine

class debugger_t {
public:
    debugger_t() = default;
    ~debugger_t();

    debugger_t(const debugger_t&)            = delete;
    debugger_t& operator=(const debugger_t&) = delete;

    bool        attach(uint32_t pid);
    void        detach();

    dbg_state_t state() const noexcept { return state_; }
    uint32_t    pid() const noexcept { return pid_; }
    dbg_mode_t  mode() const noexcept { return mode_; }
    uint64_t    veh_page() const noexcept { return kpage_; }   // injected page (0 = none)

    // Breakpoints, safe while paused or running
    bool set_sw_breakpoint(uintptr_t va);
    bool clear_breakpoint(uintptr_t va);
    // dr slots through the driver, first free slot wins, exec is forced to one byte, no user mode fallback
    bool set_hw_breakpoint(uintptr_t va, uint32_t len = 1, uint32_t type = 0);
    std::vector<breakpoint_t> breakpoints() const;   // snapshot

    // attach tracepoint or conditional info, empty values leave it alone
    bool configure_breakpoint(uintptr_t va, const std::string& condition,
                              const std::string& log_text, bool auto_continue,
                              bool one_shot);

    // page guard watchpoints report every access to a range, auto continue streams the hits into the log
    bool set_watchpoint(uintptr_t addr, size_t len, bool auto_continue);
    bool clear_watchpoint(uintptr_t addr);
    std::vector<watchpoint_t> watchpoints() const;

    // Write a register of the paused thread ("rax", "rip", ...)
    bool set_register(const std::string& name, uint64_t value);

    // Control (meaningful while paused)
    void go();
    void step_into();
    void step_over();
    void step_out();

    // Context of the paused thread
    std::optional<runtime::thread_context_t> paused_context(uint32_t* out_tid = nullptr) const;

    // Event ring snapshot for UI
    std::vector<debug_event_t> events_snapshot(size_t max = 512) const;

    // freeze and thaw every thread through the driver, no handles opened in the target
    bool suspend_all();
    bool resume_all();

private:
    void loop();
    void kloop();          // kernel-stealth event loop (injected VEH)
    void push_event(const debug_event_t& e);
    bool arm_bp(breakpoint_t& bp);
    bool disarm_bp(breakpoint_t& bp);
    // flip the page rw, write, restore, stealth passes the private device
    bool write_byte_stealth(voyager::device_t* dev, uintptr_t va, uint8_t val);
    bool set_tf(uint32_t tid, bool on);
    void request_resume(step_action_t plan);
    std::optional<disasm::insn_t> decode_at(uint64_t va);

    // Kernel-stealth helpers (injected-VEH engine)
    bool kcall(uint64_t fn, uint64_t a1, uint64_t a2, uint64_t* out);
    bool kattach(uint32_t pid);          // inject stub + install VEH
    void kdetach();                      // release parked threads, remove VEH, free page
    void krelease_slot(uint64_t slot_va, uint64_t cmd,
                       const CONTEXT* regs);   // wake a parked thread
    void ksuspend_all();
    void kresume_all();
    // page flips run against a frozen world since an rw code page is non executable, except_tid keeps one thread runnable
    void kfreeze_world(uint32_t except_tid = 0);
    void kunfreeze_world();
    void handle_veh_slot(uint64_t slot_va, const uint8_t* slot);

    enum class resume_mode_t : uint8_t { none, apply_plan, step_rearm };

    // true when a step must re-arm its breakpoint and pause after, false for silent tracepoint re-arms
    bool rearm_pause_ = false;

    runtime::backend_t* backend_ = nullptr;      // active backend at attach time
    runtime::target_handle_t mem_handle_{};      // memory ops route through backend
    disasm::engine_t    engine_;
    uint32_t            pid_     = 0;
    dbg_mode_t          mode_    = dbg_mode_t::idle;

    std::atomic<dbg_state_t> state_{dbg_state_t::idle};
    std::thread              worker_;
    std::atomic<bool>        quit_{false};
    std::atomic<bool>        attach_done_{false};
    std::atomic<bool>        attach_result_{false};

    mutable std::mutex       mu_;
    std::condition_variable  cv_;
    resume_mode_t            resume_mode_ = resume_mode_t::none;
    step_action_t            pending_plan_{};
    uint32_t                 paused_tid_ = 0;
    runtime::thread_context_t paused_ctx_{};
    breakpoint_t*            hit_bp_ = nullptr;

    bp_store_t               bps_;
    std::vector<watchpoint_t> watches_;
    std::vector<debug_event_t> events_;

    // Kernel-stealth state (valid while mode_ == kernel_stealth)
    // private device, the shared one gets its context switched by mcp actions
    std::unique_ptr<voyager::device_t> kdev_;
    uint64_t    kpage_        = 0;   // injected stub+slots page (target VA)
    uint64_t    kntdll_base_  = 0;   // target ntdll (diagnostics / MZ check)
    uint64_t    kveh_handle_  = 0;   // RtlAddVectoredExceptionHandler ret
    uint64_t    kremove_veh_  = 0;   // ntdll!RtlRemoveVectoredExceptionHandler
    uint64_t    kparked_slot_ = 0;   // slot VA of the thread paused on
    CONTEXT     kparked_win_{};      // its OS context (regs applied on release)
    runtime::thread_context_t kparked_regs_{};   // GPR view of kparked_win_
    // set_register dirties the win so the release rewrites the slot context
    bool        kparked_dirty_ = false;
    std::atomic<bool> kworld_frozen_{false};  // target threads kernel-suspended
};

} // namespace slop::core::debugger
