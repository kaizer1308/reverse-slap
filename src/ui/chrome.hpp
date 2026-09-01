#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <functional>

namespace slop::ui::chrome {

// Store the window handle + dpi and prime the borderless-frame state
// Call once, after the HWND exists
void Init(HWND hwnd, float dpi_scale);

// frameless window messages, returns true when it owns the message,
// call before the default switch
bool HandleMessage(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, LRESULT& out);

// Draw the custom titlebar: app label, the passed menu block, and the
// minimize / maximize / close buttons. Reserves the top strip of the viewport
void DrawTitleBar(const std::function<void()>& draw_menus);

float TitleBarHeight();
bool  IsWindowMaximized();

} // namespace slop::ui::chrome
