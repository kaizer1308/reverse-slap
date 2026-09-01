#pragma once

#include "imgui.h"

namespace slop::ui::fonts {

struct FontSet {
    ImFont* ui = nullptr;
    ImFont* ui_small = nullptr;
    ImFont* ui_header = nullptr;
    ImFont* mono = nullptr;
};

// fill the font atlas before backend init, dpi_scale is a multiplier,
// repeat calls need the texture recreated
void Load(float dpi_scale);

const FontSet& Get();

} // namespace slop::ui::fonts
