#pragma once

#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "imgui.h"

namespace slop::ui::views {

struct View {
    std::string id;            // stable id, e.g. "targets"
    std::string title;         // window title
    std::string category;      // menu group, e.g. "Workspace" or "Debug"
    std::string shortcut;      // chord string, e.g. "Ctrl+1", "F12", "" for none
    const char* icon = nullptr;
    bool default_open = true;
    bool singleton = true;
    std::function<void()> draw;
};

// Lightweight, copyable view of a registered panel (for the command palette)
struct ViewInfo {
    std::string id;
    std::string title;
    std::string category;
    std::string shortcut;
    bool open;
};

// Add or replace a view by id
void Register(View v);

// Called once per frame, inside NewFrame/Render, AFTER the dockspace host
// window has ended. Handles global shortcuts + draws each open view
void DrawAll();

// Emit checkable menu items for every registered view (grouped by category)
void DrawMenuItems();

void Toggle(std::string_view id);
void SetOpen(std::string_view id, bool open);
bool IsOpen(std::string_view id);

// Snapshot of all registered views, in registration order
std::vector<ViewInfo> Snapshot();

} // namespace slop::ui::views
