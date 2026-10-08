#pragma once

#include <string_view>

namespace slop::ui::kt {
// kernel-backed inspection panels (view_kernel_tools.cpp)
void DrawDriverStatus();
void DrawMemoryMap();
void DrawModules();
void DrawHandles();
void DrawThreads();
void DrawRuntimeDump();
}

namespace slop::ui::gt {
// game analysis tools (view_game_tools.cpp)
void DrawPointerScanner();
void DrawSnapshotDiff();
void DrawAobGenerator();
void DrawStructDissector();
void DrawEncPtrDecoder();
void DrawOffsetDb();
void DrawCryptoScanner();
void DrawRttiWalker();
void DrawBinaryMap();
}

namespace slop::ui::ex {
// exploit discovery tools (view_exploits.cpp)
void DrawValueFreezer();
void DrawWriteWatcher();
void DrawCooldownFinder();
void DrawCodePatcher();
void DrawExploitFinder();
void DrawCodeCaveFinder();
void DrawInsnViewer();
}

namespace slop::ui::sx {
// server-side exploit tools (view_server_exploits.cpp)
void DrawPacketCapture();
void DrawAuthorityTester();
void DrawProtocolAnalyzer();
void DrawPositionFinder();
void DrawSpeedFinder();
void DrawTickRate();
}

namespace slop::ui::an {
// analysis panels (view_analysis.cpp)
void DrawXrefs();
void DrawProcessInfo();
void DrawSymbolResolver();
void DrawCallGraph();
void DrawSourceReconstruct();
}

namespace slop::ui::sc {
// scripting panels (view_scripting.cpp)
void DrawLuaScript();
void DrawAiChat();
}

namespace slop::ui::eh {
void DrawW2STester();
void DrawTArrayViewer();
void DrawUECameraFinder();
}

namespace slop::ui::ov {
void DrawOverlay();
}

namespace slop::ui::ed {
void DrawUEDumper();
void DrawIl2CppDumper();
void DrawTelescope();
void DrawApiSchema();
}

namespace slop::ui::iv {
void DrawFindings();
void DrawQuestions();
void DrawSecurityAudit();
void DrawWorkflows();
}

namespace slop::ui::panels {

// Register the phase-1 placeholder panels with the view registry
// Call once, after ImGui context creation and font load
void RegisterBuiltins();

// Append a line to the Output panel's boot/log buffer
void AppendBootLog(std::string_view line);

} // namespace slop::ui::panels
