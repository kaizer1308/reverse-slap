#include "ui/views_core.hpp"

#include "core/analysis/magicmida.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <windows.h>
#include <commdlg.h>

#include <cstdio>
#include <string>

namespace slop::ui::unpacker_view {

namespace magicmida = slop::core::analysis::magicmida;

namespace {

char g_input[MAX_PATH]{};
char g_output[MAX_PATH]{};
int g_timeout_seconds = 300;
bool g_overwrite = false;
bool g_load = true;
uint64_t g_last_job = 0;

bool OpenPe(char* path, DWORD size) {
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = "PE images\0*.exe;*.dll\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = size;
    dialog.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;
    return GetOpenFileNameA(&dialog) != FALSE;
}

bool SavePe(char* path, DWORD size) {
    OPENFILENAMEA dialog{};
    dialog.lStructSize = sizeof(dialog);
    dialog.hwndOwner = GetActiveWindow();
    dialog.lpstrFilter = "PE images\0*.exe;*.dll\0All files\0*.*\0";
    dialog.lpstrFile = path;
    dialog.nMaxFile = size;
    dialog.Flags = OFN_OVERWRITEPROMPT | OFN_NOCHANGEDIR;
    return GetSaveFileNameA(&dialog) != FALSE;
}

void DrawJob(const magicmida::job_t& job) {
    ImGui::PushID(static_cast<int>(job.id));
    ImGui::Separator();
    ImGui::Text("job %llu", static_cast<unsigned long long>(job.id));
    ImGui::SameLine();
    const ImVec4 color = job.state == magicmida::state_t::succeeded
        ? ImVec4(0.35f, 0.9f, 0.5f, 1.0f)
        : job.state == magicmida::state_t::failed
            ? ImVec4(0.95f, 0.35f, 0.35f, 1.0f)
            : ImVec4(0.9f, 0.75f, 0.3f, 1.0f);
    ImGui::TextColored(color, "%s", magicmida::state_name(job.state));
    ImGui::TextWrapped("%s", job.request.input_path.c_str());
    if (job.state == magicmida::state_t::queued || job.state == magicmida::state_t::running) {
        if (ImGui::SmallButton("Cancel")) magicmida::cancel(job.id);
    } else {
        if (!job.result.output_path.empty())
            ImGui::TextWrapped("output: %s", job.result.output_path.c_str());
        if (job.result.ok) {
            ImGui::Text("%s, entry RVA %08X, %u sections, %llu ms",
                        magicmida::arch_name(job.result.arch), job.result.output.entry_rva,
                        job.result.output.sections,
                        static_cast<unsigned long long>(job.result.duration_ms));
        }
        if (!job.result.error.empty())
            ImGui::TextColored(ImVec4(0.95f, 0.35f, 0.35f, 1.0f), "%s",
                               job.result.error.c_str());
        for (const auto& warning : job.result.warnings)
            ImGui::TextColored(ImVec4(0.9f, 0.75f, 0.3f, 1.0f), "%s", warning.c_str());
    }
    ImGui::PopID();
}

} // namespace

void Draw() {
    const auto install = magicmida::installation();
    ImGui::TextUnformatted("Themida / WinLicense unpacker");
    ImGui::TextDisabled("Magicmida 2026-05-14 sidecar, debugger-driven x86/x64 unpacking");
    ImGui::Separator();
    ImGui::TextColored(install.x86_available ? ImVec4(0.35f, 0.9f, 0.5f, 1.0f)
                                               : ImVec4(0.95f, 0.35f, 0.35f, 1.0f),
                       "x86: %s", install.x86_available ? "ready" : "missing");
    ImGui::SameLine();
    const bool x64_ready = install.x64_available && install.x64_scyllahide_available;
    ImGui::TextColored(x64_ready ? ImVec4(0.35f, 0.9f, 0.5f, 1.0f)
                                 : ImVec4(0.95f, 0.35f, 0.35f, 1.0f),
                       "x64: %s", x64_ready ? "ready" : "missing dependencies");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", install.root.c_str());

    ImGui::SetNextItemWidth(-80.0f);
    ImGui::InputText("##themida_input", g_input, sizeof(g_input));
    ImGui::SameLine();
    if (ImGui::Button("Input...")) {
        if (OpenPe(g_input, static_cast<DWORD>(sizeof(g_input)))) {
            const std::string generated = magicmida::generated_output_path(g_input);
            std::snprintf(g_output, sizeof(g_output), "%s", generated.c_str());
        }
    }
    ImGui::SetNextItemWidth(-80.0f);
    ImGui::InputText("##themida_output", g_output, sizeof(g_output));
    ImGui::SameLine();
    if (ImGui::Button("Output...")) SavePe(g_output, static_cast<DWORD>(sizeof(g_output)));

    ImGui::SetNextItemWidth(140.0f);
    ImGui::InputInt("timeout (seconds)", &g_timeout_seconds);
    g_timeout_seconds = g_timeout_seconds < 1 ? 1 : (g_timeout_seconds > 1800 ? 1800 : g_timeout_seconds);
    ImGui::Checkbox("overwrite output", &g_overwrite);
    ImGui::SameLine();
    ImGui::Checkbox("load result", &g_load);

    const bool can_start = g_input[0] != '\0' && (install.x86_available || x64_ready);
    ImGui::BeginDisabled(!can_start);
    if (ImGui::Button("Unpack with Magicmida")) {
        magicmida::request_t request;
        request.input_path = g_input;
        request.output_path = g_output;
        request.timeout_ms = static_cast<uint32_t>(g_timeout_seconds * 1000);
        request.overwrite = g_overwrite;
        request.load_result = g_load;
        std::string error;
        g_last_job = magicmida::start(std::move(request), error);
        if (g_last_job == 0) panels::AppendBootLog("Themida unpack failed: " + error);
        else panels::AppendBootLog("Themida unpack job started: " + std::to_string(g_last_job));
    }
    ImGui::EndDisabled();

    for (const auto& job : magicmida::jobs()) DrawJob(job);
}

} // namespace slop::ui::unpacker_view
