#include "ui/panels.hpp"

#include <string>

#include "imgui.h"

#include "core/infra/event_bus.hpp"
#include "ui/fonts.hpp"
#include "ui/view_registry.hpp"
#include "ui/views_core.hpp"

namespace slop::ui::panels {

namespace kt = ::slop::ui::kt;

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
    add("driver_status",  "Driver Status",  "Kernel",    "",       kt::DrawDriverStatus, false);
    add("memory_map",     "Memory Map",     "Kernel",    "",       kt::DrawMemoryMap,    false);
    add("modules",        "Modules",        "Kernel",    "",       kt::DrawModules,      false);
    add("handles",        "Handles",        "Kernel",    "",       kt::DrawHandles,      false);
    add("threads",        "Threads",        "Kernel",    "",       kt::DrawThreads,      false);
    add("runtime_dump",   "Runtime Dump",   "Kernel",    "",       kt::DrawRuntimeDump,  false);
    add("ptr_scanner",    "Pointer Scanner", "Game Tools", "",     gt::DrawPointerScanner, false);
    add("snapshot_diff",  "Snapshot Diff",   "Game Tools", "",     gt::DrawSnapshotDiff,   false);
    add("aob_gen",        "AOB Generator",   "Game Tools", "",     gt::DrawAobGenerator,   false);
    add("struct_dissect", "Struct Dissector", "Game Tools", "",     gt::DrawStructDissector, false);
    add("enc_ptr",        "Encrypted Ptrs",  "Game Tools", "",     gt::DrawEncPtrDecoder,  false);
    add("offset_db",      "Offset Database", "Game Tools", "",     gt::DrawOffsetDb,       false);
    add("crypto_scan",    "Crypto Scanner",  "Game Tools", "",     gt::DrawCryptoScanner,  false);
    add("rtti_walker",    "RTTI / VMT",      "Game Tools", "",     gt::DrawRttiWalker,     false);
    add("binary_map",     "Binary Map",      "Game Tools", "",     gt::DrawBinaryMap,      false);
    add("exploit_finder", "Exploit Finder", "Exploits",   "",     ex::DrawExploitFinder,  false);
    add("value_freezer",  "Value Freezer",  "Exploits",   "",     ex::DrawValueFreezer,   false);
    add("write_watcher",  "Write Watcher",  "Exploits",   "",     ex::DrawWriteWatcher,   false);
    add("cooldown_find",  "Cooldown Finder", "Exploits",  "",     ex::DrawCooldownFinder, false);
    add("code_patcher",   "Code Patcher",   "Exploits",   "",     ex::DrawCodePatcher,    false);
    add("code_caves",     "Code Caves",     "Exploits",   "",     ex::DrawCodeCaveFinder, false);
    add("insn_viewer",    "Instructions",   "Exploits",   "",     ex::DrawInsnViewer,     false);
    add("pkt_capture",    "Packet Capture",  "Server",   "",     sx::DrawPacketCapture,   false);
    add("authority_test", "Authority Test",  "Server",   "",     sx::DrawAuthorityTester, false);
    add("proto_analyze",  "Protocol Analyzer","Server",  "",     sx::DrawProtocolAnalyzer,false);
    add("position_find",  "Position Finder", "Server",   "",     sx::DrawPositionFinder,  false);
    add("speed_find",     "Speed Finder",    "Server",   "",     sx::DrawSpeedFinder,     false);
    add("tick_rate",      "Tick Rate",       "Server",   "",     sx::DrawTickRate,        false);
    add("xrefs_panel",    "Xrefs",          "Analysis",  "",      an::DrawXrefs,            false);
    add("process_info",   "Process Info",   "Analysis",  "",      an::DrawProcessInfo,      false);
    add("sym_resolver",   "Symbol Resolver","Analysis",  "",      an::DrawSymbolResolver,   false);
    add("call_graph",     "Call Graph",     "Analysis",  "",      an::DrawCallGraph,        false);
    add("src_recon",      "Source Reconstruct","Analysis","",     an::DrawSourceReconstruct,false);
    add("lua_script",     "Lua Script",     "Scripting", "",      sc::DrawLuaScript,        false);
    add("ai_chat",        "AI Chat",        "Scripting", "",      sc::DrawAiChat,           false);
    add("w2s_tester",    "World to Screen","Engine",    "",       eh::DrawW2STester,      false);
    add("tarray_view",   "TArray Viewer",  "Engine",    "",       eh::DrawTArrayViewer,   false);
    add("ue_camera",     "UE Camera Finder","Engine",   "",       eh::DrawUECameraFinder, false);
    add("overlay_panel", "Discord Overlay","Overlay",   "",       ov::DrawOverlay, false);
    add("ue_dumper",      "UE SDK Dumper",  "Engine",       "",   ed::DrawUEDumper,       false);
    add("il2cpp_dumper",  "Il2Cpp Dumper",  "Engine",       "",   ed::DrawIl2CppDumper,   false);
    add("telescope",     "Telescope",      "Game Tools",   "",   ed::DrawTelescope,      false);
    add("api_schema",    "API Schema",     "Server",       "",   ed::DrawApiSchema,      false);
    add("findings",       "Findings",       "Investigation","",   iv::DrawFindings,       false);
    add("questions",      "Open Questions", "Investigation","",   iv::DrawQuestions,      false);
    add("sec_audit",      "Security Audit", "Investigation","",   iv::DrawSecurityAudit,  false);
    add("workflows",      "Workflows",      "Investigation","",   iv::DrawWorkflows,      false);
    add("output",        "Output",        "Workspace", "Ctrl+5", DrawOutput);
    add("frame_metrics", "Frame Metrics", "Debug",     "F12",    DrawFrameMetrics, false);
}

} // namespace slop::ui::panels
