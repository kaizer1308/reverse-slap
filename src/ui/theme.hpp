#pragma once

#include <string_view>

#include "imgui.h"
#include "ui/tokens.hpp"

namespace slop::ui::theme {

struct Theme {
    const char* id;
    const char* label;
    Palette palette;
    Tokens tokens;
};

int Count();
const Theme& Get(int idx);
int FindByID(std::string_view id);

int CurrentIndex();
const Theme& Current();
void SetCurrent(int idx);

void OverrideAccent(ImVec4 accent);
void ClearAccentOverride();
bool HasAccentOverride();
ImVec4 EffectiveAccent();

// (re)apply the current theme + tokens + any accent override to ImGuiStyle
void Apply();

// RAII scope: push accent-related color slots for a widget subtree
struct ScopedAccent {
    explicit ScopedAccent(ImVec4 accent);
    ~ScopedAccent();
    ScopedAccent(const ScopedAccent&) = delete;
    ScopedAccent& operator=(const ScopedAccent&) = delete;
};

} // namespace slop::ui::theme
