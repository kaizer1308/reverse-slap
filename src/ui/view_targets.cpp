// src/ui/view_targets.cpp
// process list and the attach flow

#include "ui/views_core.hpp"

#include "core/infra/clock.hpp"
#include "core/process/target_service.hpp"
#include "core/process/module_dump.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/runtime/backend_registry.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <windows.h>
#include <commdlg.h>

#include <algorithm>
#include <string>
#include <vector>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace infra   = slop::core::infra;

namespace {

using runtime::process_info_t;
using runtime::module_info_t;

std::vector<process_info_t> g_procs;
char                        g_filter_buf[64] = {};
int64_t                     g_last_refresh_ms = 0;
bool                        g_dirty           = true;
uint32_t                    g_selected_pid    = 0;
std::vector<module_info_t>  g_modules;
uint32_t                    g_modules_pid = 0;
int64_t                     g_modules_refresh_ms = 0;

std::string DumpPath(const module_info_t& module) {
    OPENFILENAMEA dialog{};
    char file[MAX_PATH]{};
    std::snprintf(file, sizeof(file), "%s_%016llX.dump%s",
                  module.name.empty() ? "module" : module.name.c_str(),
                  static_cast<unsigned long long>(module.base),
                  module.name.ends_with(".dll") ? ".dll" : ".exe");
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = "PE images\0*.exe;*.dll;*.sys\0All files\0*.*\0";
    dialog.lpstrFile = file;
    dialog.nMaxFile = MAX_PATH;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    return GetSaveFileNameA(&dialog) ? std::string(file) : std::string{};
}

const char* ArchName(runtime::arch_t a) noexcept {
    switch (a) {
    case runtime::arch_t::x64:   return "x64";
    case runtime::arch_t::x86:   return "x86";
    case runtime::arch_t::arm64: return "arm64";
    default:                     return "?";
    }
}

const char* ElevName(runtime::elevation_t e) noexcept {
    switch (e) {
    case runtime::elevation_t::standard: return "user";
    case runtime::elevation_t::elevated: return "admin";
    case runtime::elevation_t::system:   return "system";
    default:                             return "?";
    }
}

bool NameFilterMatch(const process_info_t& p) {
    std::string g_filter(g_filter_buf);
    if (g_filter.empty()) return true;
    const std::string needle = [](std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return s;
    }(g_filter);

    auto hay = std::string(p.name);
    std::transform(hay.begin(), hay.end(), hay.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (hay.find(needle) != std::string::npos) return true;

    // PID match
    char pidbuf[16]{};
    std::snprintf(pidbuf, sizeof(pidbuf), "%u", p.pid);
    return needle == pidbuf;
}

} // namespace

namespace targets_view {

void Draw() {
    const auto session = process::active_session();
    const bool attached = session && session->valid();

    // Status header
    ImGui::Text("backend: %s", runtime::active_badge());
    ImGui::SameLine();
    if (attached) {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.5f, 1.0f), "target: %s (pid %u)",
                           session->name().c_str(), session->pid());
        ImGui::SameLine();
        if (ImGui::SmallButton("Detach")) {
            process::target_detach();
            panels::AppendBootLog("detached");
            g_dirty = true;
        }
    } else {
        ImGui::TextDisabled("no target attached");
    }
    ImGui::Separator();

    if (attached) {
        const int64_t now = infra::steady_ms();
        if (g_modules_pid != session->pid() || now - g_modules_refresh_ms > 3000) {
            auto modules = runtime::active().enum_modules(session->handle());
            if (modules.ok) g_modules = std::move(modules.items);
            g_modules_pid = session->pid();
            g_modules_refresh_ms = now;
        }

        if (ImGui::Button("Refresh modules")) g_modules_refresh_ms = 0;
        ImGui::SameLine();
        ImGui::TextDisabled("%d loaded modules", static_cast<int>(g_modules.size()));

        if (ImGui::BeginTable("target_modules", 5,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("module", ImGuiTableColumnFlags_WidthStretch, 2.0f);
            ImGui::TableSetupColumn("base", ImGuiTableColumnFlags_WidthFixed, 130.0f);
            ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, 85.0f);
            ImGui::TableSetupColumn("dump", ImGuiTableColumnFlags_WidthFixed, 58.0f);
            ImGui::TableSetupColumn("analyze", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableHeadersRow();
            for (const auto& module : g_modules) {
                ImGui::PushID(reinterpret_cast<const void*>(module.base));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(module.name.c_str());
                if (ImGui::IsItemHovered() && !module.path.empty())
                    ImGui::SetTooltip("%s", module.path.c_str());
                ImGui::TableNextColumn();
                ImGui::Text("%016llX", static_cast<unsigned long long>(module.base));
                ImGui::TableNextColumn();
                ImGui::Text("0x%X", module.size);
                ImGui::TableNextColumn();
                const bool dump = ImGui::SmallButton("dump");
                ImGui::TableNextColumn();
                const bool analyze = ImGui::SmallButton("dump+load");
                if (dump || analyze) {
                    const std::string path = DumpPath(module);
                    if (!path.empty()) {
                        auto result = process::dump_module_pe(*session, module, path);
                        if (!result.ok) {
                            panels::AppendBootLog("module dump failed: " + result.error);
                        } else if (analyze &&
                                   !slop::core::disasm::binary_state::load_file(path, module.base)) {
                            panels::AppendBootLog("module dumped but analysis load failed: " + path);
                        } else {
                            panels::AppendBootLog("dumped " + module.name + " to " + path);
                        }
                    }
                }
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        return;
    }

    // Refresh logic
    const int64_t now = infra::steady_ms();
    if (g_dirty || now - g_last_refresh_ms > 2000) {
        auto res = runtime::active().enum_processes();
        if (res.ok) {
            g_procs = std::move(res.items);
            std::sort(g_procs.begin(), g_procs.end(),
                      [](const process_info_t& a, const process_info_t& b) {
                          return _stricmp(a.name.c_str(), b.name.c_str()) < 0;
                      });
        }
        g_last_refresh_ms = now;
        g_dirty = false;
    }

    if (ImGui::Button("Refresh")) g_dirty = true;
    ImGui::SameLine();
    ImGui::SetNextItemWidth(220.0f);
    ImGui::InputTextWithHint("##procfilter", "filter name or pid",
                             g_filter_buf, sizeof(g_filter_buf));
    ImGui::SameLine();
    ImGui::TextDisabled("%d processes", static_cast<int>(g_procs.size()));

    if (ImGui::BeginTable("procs", 4,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("pid", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthStretch, 3.0f);
        ImGui::TableSetupColumn("arch", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("attach", ImGuiTableColumnFlags_WidthFixed, 70.0f);
        ImGui::TableHeadersRow();

        for (const auto& p : g_procs) {
            if (!NameFilterMatch(p)) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%u", p.pid);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(p.name.c_str());
            if (ImGui::IsItemHovered() && !p.path.empty())
                ImGui::SetTooltip("%s", p.path.c_str());
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", ArchName(p.arch));
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(p.pid));
            if (ImGui::SmallButton("attach")) {
                if (process::target_attach(p.pid))
                    panels::AppendBootLog("attached: " + p.name + " (pid " +
                                          std::to_string(p.pid) + ")");
                else
                    panels::AppendBootLog("attach FAILED: " + p.name + " (pid " +
                                          std::to_string(p.pid) + ")");
            }
            ImGui::PopID();
        }
        ImGui::EndTable();
    }
}

} // namespace targets_view
} // namespace slop::ui
