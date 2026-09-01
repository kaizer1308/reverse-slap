// src/ui/view_debugger.cpp
// debugger workspace, controls, registers, breakpoints and the event log

#include "ui/views_core.hpp"

#include "core/debugger/debugger.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_kernel.hpp"
#include "core/runtime/backend_registry.hpp"
#include "ui/fonts.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <cstdio>
#include <string>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace dbg     = slop::core::debugger;

namespace {

dbg::debugger_t g_dbg;

const char* StateName(dbg::dbg_state_t s) noexcept {
    switch (s) {
    case dbg::dbg_state_t::running: return "running";
    case dbg::dbg_state_t::paused:  return "paused";
    default:                        return "idle";
    }
}

void DrawRegisters(const runtime::thread_context_t& c) {
    if (!ImGui::BeginTable("regs", 4,
                           ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingFixedFit))
        return;
    struct pair_t { const char* n; uint64_t v; };
    const pair_t rows[] = {
        {"rip", c.rip}, {"rsp", c.rsp}, {"rbp", c.rbp}, {"flags", c.flags},
        {"rax", c.rax}, {"rbx", c.rbx}, {"rcx", c.rcx}, {"rdx", c.rdx},
        {"rsi", c.rsi}, {"rdi", c.rdi},
        {"r8",  c.r8},  {"r9",  c.r9},  {"r10", c.r10}, {"r11", c.r11},
        {"r12", c.r12}, {"r13", c.r13}, {"r14", c.r14}, {"r15", c.r15},
    };
    for (size_t i = 0; i < std::size(rows); i += 2) {
        ImGui::TableNextRow();
        for (int k = 0; k < 2 && i + static_cast<size_t>(k) < std::size(rows); ++k) {
            const auto& r = rows[i + static_cast<size_t>(k)];
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%-5s", r.n);
            ImGui::TableNextColumn();
            char hex[24];
            std::snprintf(hex, sizeof(hex), "%016llX",
                          static_cast<unsigned long long>(r.v));
            ImGui::TextUnformatted(hex);
        }
    }
    ImGui::EndTable();
}

} // namespace

namespace debugger_view {

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    // Backend / driver status card
    {
        const bool kernel_live = runtime::active_kind() == runtime::backend_kind_t::kernel;
        ImGui::Text("backend:");
        ImGui::SameLine();
        if (kernel_live)
            ImGui::TextColored(ImVec4(0.95f, 0.65f, 0.25f, 1.0f), "KERNEL (slopdrvr)");
        else
            ImGui::TextDisabled("USER-MODE");
        ImGui::SameLine();

        if (ImGui::SmallButton(kernel_live ? "switch to USER" : "switch to KERNEL")) {
            const bool ok = kernel_live
                ? runtime::set_backend_preference(runtime::backend_pref_t::force_user)
                : runtime::set_backend_preference(runtime::backend_pref_t::auto_detect);
            panels::AppendBootLog(ok ? "backend switched"
                                     : "kernel backend unavailable (driver not loaded)");
        }
        if (!kernel_live) {
            ImGui::SameLine();
            ImGui::TextDisabled("load: slop_mapper.exe load build\\driver\\slopdrvr.sys");
        }
        ImGui::Separator();
    }

    // Attach / detach debugger
    const auto session = process::active_session();
    if (!session || !session->valid()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("attach a target first.");
        return;
    }

    const auto state = g_dbg.state();
    if (state == dbg::dbg_state_t::idle) {
        if (ImGui::Button("debug attach")) {
            if (!g_dbg.attach(session->pid()))
                panels::AppendBootLog("debugger: DebugActiveProcess failed (elevated required?)");
        }
    } else {
        if (ImGui::Button("debug detach")) g_dbg.detach();
        ImGui::SameLine();
        ImGui::Text("state: %s", StateName(state));

        // Controls
        if (state == dbg::dbg_state_t::paused) {
            ImGui::SameLine();
            if (ImGui::Button("Go"))          g_dbg.go();
            ImGui::SameLine();
            if (ImGui::Button("Step Into"))   g_dbg.step_into();
            ImGui::SameLine();
            if (ImGui::Button("Step Over"))   g_dbg.step_over();
            ImGui::SameLine();
            if (ImGui::Button("Step Out"))    g_dbg.step_out();
        }
    }
    ImGui::Separator();

    // Registers
    if (ImGui::CollapsingHeader("registers", ImGuiTreeNodeFlags_DefaultOpen)) {
        uint32_t tid = 0;
        if (auto ctx = g_dbg.paused_context(&tid)) {
            ImGui::Text("thread %u", tid);
            DrawRegisters(*ctx);
        } else {
            ImGui::TextDisabled("(paused context only)");
        }
    }

    // Breakpoints
    if (ImGui::CollapsingHeader("breakpoints", ImGuiTreeNodeFlags_DefaultOpen)) {
        static char bp_buf[24] = {};
        ImGui::SetNextItemWidth(160.0f);
        ImGui::InputTextWithHint("##bpaddr", "va (hex)", bp_buf, sizeof(bp_buf));
        ImGui::SameLine();
        if (ImGui::SmallButton("int3") && state != dbg::dbg_state_t::idle) {
            uint64_t addr = 0;
            sscanf_s(bp_buf, "%llX", &addr);
            if (addr && g_dbg.set_sw_breakpoint(addr))
                panels::AppendBootLog("bp armed @ " + std::to_string(addr));
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("hw (kernel)") &&
            runtime::active_kind() == runtime::backend_kind_t::kernel) {
            uint64_t addr = 0;
            sscanf_s(bp_buf, "%llX", &addr);
            if (addr) {
                // DR0 exec breakpoint on every thread of the target
                auto* k = static_cast<runtime::backend_kernel_t*>(&runtime::active());
                k->set_hw_breakpoint(session->pid(), 0, 0, addr, 1);
                panels::AppendBootLog("hw bp DR0 @ " + std::to_string(addr));
            }
        }

        for (const auto& bp : g_dbg.breakpoints()) {
            char line[96];
            std::snprintf(line, sizeof(line), "%011llX  %s  hits=%u",
                          static_cast<unsigned long long>(bp.addr),
                          bp.armed ? "armed" : "disarmed", bp.hits);
            ImGui::Selectable(line);
            ImGui::SameLine();
            ImGui::PushID(static_cast<int>(bp.addr & 0xFFFFFF));
            if (ImGui::SmallButton("del")) g_dbg.clear_breakpoint(bp.addr);
            ImGui::PopID();
        }
    }

    // Event log
    if (ImGui::CollapsingHeader("events", ImGuiTreeNodeFlags_DefaultOpen)) {
        for (const auto& e : g_dbg.events_snapshot(128)) {
            const char* tag = "?";
            switch (e.kind) {
            case dbg::event_kind_t::attached:     tag = "attached"; break;
            case dbg::event_kind_t::detached:     tag = "detached"; break;
            case dbg::event_kind_t::bp_hit:       tag = "BP HIT"; break;
            case dbg::event_kind_t::single_step:  tag = "step"; break;
            case dbg::event_kind_t::exception:    tag = "exception"; break;
            case dbg::event_kind_t::thread_create:tag = "thread+"; break;
            case dbg::event_kind_t::thread_exit:  tag = "thread-"; break;
            case dbg::event_kind_t::dll_load:     tag = "dll+"; break;
            case dbg::event_kind_t::dll_unload:   tag = "dll-"; break;
            case dbg::event_kind_t::process_exit: tag = "exit"; break;
            default:                              tag = "note"; break;
            }
            ImGui::Text("[%s] tid %u @ %011llX %s",
                        tag, e.tid,
                        static_cast<unsigned long long>(e.address),
                        e.text.c_str());
        }
    }

    if (pushed) ImGui::PopFont();
}

} // namespace debugger_view
} // namespace slop::ui
