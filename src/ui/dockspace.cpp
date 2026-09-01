#include "ui/dockspace.hpp"

#include <windows.h>

#include <cstdio>

#include "imgui.h"
#include "imgui_internal.h"

#include "core/disasm/binary_state.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "ui/chrome.hpp"
#include "ui/command_palette.hpp"
#include "ui/theme.hpp"
#include "ui/view_registry.hpp"

namespace slop::ui::dockspace {

namespace {

namespace ds  = slop::core::disasm::binary_state;
namespace proc = slop::core::process;
namespace rt   = slop::core::runtime;

bool g_reset_requested = false;

void BuildDefaultLayout(ImGuiID dock_id, const ImVec2& size) {
    ImGui::DockBuilderRemoveNode(dock_id);
    ImGui::DockBuilderAddNode(dock_id, ImGuiDockNodeFlags_DockSpace);
    ImGui::DockBuilderSetNodeSize(dock_id, size);

    ImGuiID left = 0, center = 0, right = 0, bottom = 0;
    ImGui::DockBuilderSplitNode(dock_id, ImGuiDir_Left,  0.22f, &left,   &center);
    ImGui::DockBuilderSplitNode(center,  ImGuiDir_Right, 0.28f, &right,  &center);
    ImGui::DockBuilderSplitNode(center,  ImGuiDir_Down,  0.30f, &bottom, &center);

    ImGui::DockBuilderDockWindow("Targets",       left);
    ImGui::DockBuilderDockWindow("Inspector",     right);
    ImGui::DockBuilderDockWindow("Frame Metrics", right);
    ImGui::DockBuilderDockWindow("Output",        bottom);
    ImGui::DockBuilderDockWindow("Disassembly",   center);
    ImGui::DockBuilderDockWindow("Memory",        center);
    ImGui::DockBuilderFinish(dock_id);
}

// Menu block, drawn inside the custom titlebar's menu bar (see chrome.cpp)
void DrawMenus() {
    if (ImGui::BeginMenu("File")) {
        ImGui::MenuItem("Attach to process...", nullptr, nullptr, false);
        ImGui::Separator();
        if (ImGui::MenuItem("Exit", "Alt+F4"))
            PostQuitMessage(0);
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("View")) {
        views::DrawMenuItems();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Window")) {
        if (ImGui::MenuItem("Command Palette", "Ctrl+Shift+P"))
            palette::Open();
        ImGui::Separator();
        if (ImGui::MenuItem("Reset Layout"))
            RequestReset();
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Theme")) {
        const int cur = theme::CurrentIndex();
        for (int i = 0; i < theme::Count(); ++i) {
            if (ImGui::MenuItem(theme::Get(i).label, nullptr, i == cur)) {
                theme::SetCurrent(i);
                theme::Apply();
            }
        }
        ImGui::Separator();
        ImVec4 accent = theme::EffectiveAccent();
        if (ImGui::ColorEdit4("##accent", (float*)&accent,
                ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel | ImGuiColorEditFlags_AlphaBar)) {
            theme::OverrideAccent(accent);
            theme::Apply();
        }
        ImGui::SameLine();
        ImGui::TextDisabled("accent");
        if (theme::HasAccentOverride()) {
            if (ImGui::MenuItem("Clear accent override")) {
                theme::ClearAccentOverride();
                theme::Apply();
            }
        }
        ImGui::EndMenu();
    }

    if (ImGui::BeginMenu("Help")) {
        if (ImGui::MenuItem("About reverse-slop"))
            ImGui::OpenPopup("##about");
        ImGui::EndMenu();
    }
}

void DrawAboutModal() {
    const ImGuiViewport* vp = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(vp->GetCenter(), ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
    if (ImGui::BeginPopupModal("##about", nullptr,
            ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoTitleBar)) {
        ImGui::TextUnformatted("reverse-slop 0.1.0 (phase 1)");
        ImGui::Separator();
        ImGui::TextDisabled("windows reverse-engineering workbench");
        if (ImGui::Button("Close", ImVec2(120.0f, 0.0f)))
            ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}

// Live analysis indicator: progress + cancel while the hyperion background
// analysis runs, end-state otherwise. Sits left of the backend/target text
void DrawAnalysisStatus() {
    const ds::hype_status_t st = ds::hype_status();
    if (!st.has_image) return;

    if (st.running) {
        char label[96];
        std::snprintf(label, sizeof(label), "analysis: %s %d%%",
                      st.image.c_str(),
                      static_cast<int>(st.progress * 100.f));
        ImGui::TextUnformatted(label);
        ImGui::SameLine();
        ImGui::ProgressBar(st.progress, ImVec2(90.0f, ImGui::GetTextLineHeight() * 0.8f), "");
        ImGui::SameLine();
        if (ImGui::SmallButton("stop"))
            ds::hype_stop();
        if (ImGui::IsItemHovered())
            ImGui::SetTooltip("cancel the background hyperion analysis");
        ImGui::SameLine();
        ImGui::TextDisabled("|");
        ImGui::SameLine();
        return;
    }

    if (st.engine_present && st.ready) {
        ImGui::TextDisabled("analysis: ready");
    } else if (st.engine_present) {
        // failed or cancelled, surface the reason
        ImGui::TextColored(ImVec4(0.95f, 0.75f, 0.35f, 1.0f), "analysis: %s",
                           st.engine_error.empty() ? "stopped" : st.engine_error.c_str());
        if (ImGui::IsItemHovered() && !st.engine_error.empty())
            ImGui::SetTooltip("%s", st.engine_error.c_str());
    }
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
}

void DrawStatusBar() {
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoDocking;
    if (ImGui::BeginViewportSideBar("##statusbar", viewport, ImGuiDir_Down,
            ImGui::GetFrameHeight(), flags)) {
        if (ImGui::BeginMenuBar()) {
            DrawAnalysisStatus();

            const char* backend = rt::active_badge();
            char target[128] = "(none)";
            if (auto s = proc::active_session(); s && s->valid())
                std::snprintf(target, sizeof(target), "%s (%u)",
                              s->name().c_str(), s->pid());
            ImGui::TextDisabled("backend: %s", backend);
            ImGui::TextDisabled("|");
            ImGui::TextDisabled("target: %s", target);
            char fps_buf[48];
            const float fps = ImGui::GetIO().Framerate;
            std::snprintf(fps_buf, sizeof(fps_buf), "%.0f fps", fps);
            const float text_w = ImGui::CalcTextSize(fps_buf).x;
            ImGui::SameLine(ImGui::GetWindowWidth() - text_w - ImGui::GetStyle().FramePadding.x * 2.0f);
            ImGui::TextDisabled("%s", fps_buf);
            ImGui::EndMenuBar();
        }
    }
    ImGui::End();
}

} // namespace

void RequestReset() { g_reset_requested = true; }

void Render() {
    chrome::DrawTitleBar(DrawMenus);

    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);
    ImGui::SetNextWindowViewport(viewport->ID);

    const ImGuiWindowFlags host_flags = ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoTitleBar |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
        ImGuiWindowFlags_NoBackground;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0.0f, 0.0f));
    ImGui::Begin("##workbench", nullptr, host_flags);
    ImGui::PopStyleVar(3);

    const ImGuiID dock_id = ImGui::GetID("ReverseSlopDock");
    if (g_reset_requested || ImGui::DockBuilderGetNode(dock_id) == nullptr) {
        BuildDefaultLayout(dock_id, viewport->WorkSize);
        g_reset_requested = false;
    }
    ImGui::DockSpace(dock_id, ImVec2(0.0f, 0.0f),
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_AutoHideTabBar) |
        static_cast<ImGuiDockNodeFlags>(ImGuiDockNodeFlags_NoWindowMenuButton));

    DrawAboutModal();

    ImGui::End();

    views::DrawAll();
    DrawStatusBar();

    palette::Render();
}

} // namespace slop::ui::dockspace
