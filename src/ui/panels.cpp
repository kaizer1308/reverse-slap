#include "ui/panels.hpp"

#include <string>

#include "imgui.h"

#include "core/infra/event_bus.hpp"
#include "ui/fonts.hpp"
#include "ui/view_registry.hpp"
#include "ui/views_core.hpp"

namespace slop::ui::panels {

namespace {

namespace bus = slop::core::infra::event_bus;

void EmptyStateCentered(const char* text) {
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const ImVec2 ts    = ImGui::CalcTextSize(text);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + (avail.y - ts.y) * 0.45f);
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + (avail.x - ts.x) * 0.5f);
    ImGui::TextDisabled("%s", text);
}

void DrawInspector() { EmptyStateCentered("Select a target to inspect."); }

void DrawOutput() {
    // the ring lives in core now so mcp and front ends see the same lines,
    // visit renders straight out of it
    bus::output_visit([](const bus::output_line_t& l) {
        ImGui::TextUnformatted(l.text.c_str());
    });
    if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
        ImGui::SetScrollHereY(1.0f);
}

void DrawFrameMetrics() {
    const ImGuiIO& io = ImGui::GetIO();
    ImGui::Text("%.1f fps", io.Framerate);
    ImGui::Text("%.3f ms/frame", io.Framerate > 0.0f ? 1000.0f / io.Framerate : 0.0f);
    ImGui::Separator();
    ImGui::Text("vertices : %d", io.MetricsRenderVertices);
    ImGui::Text("indices  : %d", io.MetricsRenderIndices);
    ImGui::Text("windows  : %d", io.MetricsRenderWindows);
    ImGui::Text("active   : %d", io.MetricsActiveWindows);
}

} // namespace

void AppendBootLog(std::string_view line) {
    bus::output(line);
}

void RegisterBuiltins() {
    using views::View;

    auto add = [](const char* id, const char* title, const char* cat,
                  const char* shortcut, std::function<void()> fn, bool open = true) {
        View v;
        v.id           = id;
        v.title        = title;
        v.category     = cat;
        v.shortcut     = shortcut ? shortcut : "";
        v.default_open = open;
        v.draw         = std::move(fn);
        views::Register(std::move(v));
    };

    add("targets",       "Targets",       "Workspace", "Ctrl+1", targets_view::Draw);
    add("inspector",     "Inspector",     "Workspace", "Ctrl+2", DrawInspector);
    add("disassembly",   "Disassembly",   "Workspace", "Ctrl+3", disasm_view::Draw);
    add("pseudocode",    "Pseudocode",    "Workspace", "Ctrl+0", pseudocode_view::Draw);
    add("memory",        "Memory",        "Workspace", "Ctrl+4", memory_view::Draw);
    add("strings",       "Strings",       "Workspace", "Ctrl+7", strings_view::Draw);
    add("pe_browser",    "PE Browser",    "Workspace", "Ctrl+8", pe_view::Draw);
    add("scanner",       "Scanner",       "Workspace", "Ctrl+6", scanner_view::Draw);
    add("debugger",      "Debugger",      "Workspace", "Ctrl+9", debugger_view::Draw);
    add("unpacker",      "Unpacker",      "Workspace", "",       unpacker_view::Draw, false);
    add("output",        "Output",        "Workspace", "Ctrl+5", DrawOutput);
    add("frame_metrics", "Frame Metrics", "Debug",     "F12",    DrawFrameMetrics, false);
}

} // namespace slop::ui::panels
