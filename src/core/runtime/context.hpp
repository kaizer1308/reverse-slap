#pragma once

// src/core/runtime/context.hpp
// context mapping helpers shared by the backend and the debugger

#include <windows.h>

#include "core/runtime/backend.hpp"

namespace slop::core::runtime {

inline void context_from_win(thread_context_t& out, const CONTEXT& c) {
    out.rip = c.Rip;   out.rsp = c.Rsp;   out.rbp = c.Rbp;
    out.rax = c.Rax;   out.rbx = c.Rbx;   out.rcx = c.Rcx;
    out.rdx = c.Rdx;   out.rsi = c.Rsi;   out.rdi = c.Rdi;
    out.r8  = c.R8;    out.r9  = c.R9;    out.r10 = c.R10;
    out.r11 = c.R11;   out.r12 = c.R12;   out.r13 = c.R13;
    out.r14 = c.R14;   out.r15 = c.R15;
    out.flags = c.EFlags;
}

inline void context_to_win(CONTEXT& c, const thread_context_t& in) {
    c.Rip = in.rip;   c.Rsp = in.rsp;   c.Rbp = in.rbp;
    c.Rax = in.rax;   c.Rbx = in.rbx;   c.Rcx = in.rcx;
    c.Rdx = in.rdx;   c.Rsi = in.rsi;   c.Rdi = in.rdi;
    c.R8  = in.r8;    c.R9  = in.r9;    c.R10 = in.r10;
    c.R11 = in.r11;   c.R12 = in.r12;   c.R13 = in.r13;
    c.R14 = in.r14;   c.R15 = in.r15;
    c.EFlags = static_cast<DWORD>(in.flags);
}

constexpr uint64_t kTrapFlag = 0x100;   // EFLAGS.TF

} // namespace slop::core::runtime
