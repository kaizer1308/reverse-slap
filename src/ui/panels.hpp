#pragma once

#include <string_view>

namespace slop::ui::panels {

// Register the phase-1 placeholder panels with the view registry
// Call once, after ImGui context creation and font load
void RegisterBuiltins();

// Append a line to the Output panel's boot/log buffer
void AppendBootLog(std::string_view line);

} // namespace slop::ui::panels
