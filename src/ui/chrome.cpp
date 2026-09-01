#include "ui/chrome.hpp"

#include <windowsx.h>   // GET_X_LPARAM / GET_Y_LPARAM

#include "imgui.h"
#include "imgui_internal.h"   // BeginViewportSideBar

#include "ui/theme.hpp"

namespace slop::ui::chrome {

namespace {

HWND  g_hwnd = nullptr;
float g_dpi = 1.0f;
int   g_resize_border = 6;

// Screen-space geometry of the draggable caption band, refreshed each frame
float g_titlebar_bottom = 0.0f;
float g_titlebar_height = 0.0f;
float g_drag_left = 0.0f;
float g_drag_right = 0.0f;

// macOS-style traffic lights on the left: close / minimize / zoom
// Grey at rest; the whole cluster lights to its colors on hover
void DrawTrafficLights(float bh) {
    ImDrawList* dl  = ImGui::GetWindowDrawList();
    const float u   = g_dpi;
    const float d   = 12.0f * u;   // circle diameter
    const float r   = d * 0.5f;
    const float gap = 8.0f * u;

    const ImU32 grey   = IM_COL32(105, 108, 116, 255);
    const ImU32 col[3] = {
        IM_COL32(255,  95,  87, 255),  // close
        IM_COL32(254, 188,  46, 255),  // minimize
        IM_COL32( 40, 200,  64, 255),  // zoom
    };
    const char* ids[3] = { "##tl_close", "##tl_min", "##tl_max" };

    ImGui::Dummy(ImVec2(2.0f * u, bh));
    ImGui::SameLine(0.0f, gap);

    ImVec2 centers[3];
    bool   hovered[3] = { false, false, false };
    int    clicked = -1;
    for (int i = 0; i < 3; ++i) {
        const ImVec2 p = ImGui::GetCursorScreenPos();
        if (ImGui::InvisibleButton(ids[i], ImVec2(d, bh)))
            clicked = i;
        hovered[i] = ImGui::IsItemHovered();
        centers[i] = ImVec2(p.x + d * 0.5f, p.y + bh * 0.5f);
        ImGui::SameLine(0.0f, gap);
    }

    for (int i = 0; i < 3; ++i)
        dl->AddCircleFilled(centers[i], r, hovered[i] ? col[i] : grey, 24);

    if (clicked == 0)      PostMessageW(g_hwnd, WM_CLOSE, 0, 0);
    else if (clicked == 1) ShowWindow(g_hwnd, SW_MINIMIZE);
    else if (clicked == 2) {
        if (IsZoomed(g_hwnd)) ShowWindow(g_hwnd, SW_RESTORE);
        else                  ShowWindow(g_hwnd, SW_MAXIMIZE);
    }

    ImGui::Dummy(ImVec2(4.0f * u, bh));
    ImGui::SameLine(0.0f, gap);
}

} // namespace

void Init(HWND hwnd, float dpi_scale) {
    g_hwnd = hwnd;
    g_dpi = dpi_scale < 0.5f ? 1.0f : dpi_scale;
    g_resize_border = static_cast<int>(6.0f * g_dpi);

    RECT rc{};
    GetWindowRect(hwnd, &rc);
    g_titlebar_bottom = static_cast<float>(rc.top) + 32.0f * g_dpi;
    g_drag_left  = static_cast<float>(rc.left);
    g_drag_right = static_cast<float>(rc.right);
}

bool HandleMessage(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam, LRESULT& out) {
    switch (msg) {
    case WM_NCCALCSIZE:
        if (wparam == TRUE) {
            // strip the standard frame and inset when maximized so we dont spill
            // or cover the taskbar
            if (IsZoomed(hwnd)) {
                NCCALCSIZE_PARAMS* p = reinterpret_cast<NCCALCSIZE_PARAMS*>(lparam);
                const int fx = GetSystemMetrics(SM_CXFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
                const int fy = GetSystemMetrics(SM_CYFRAME) + GetSystemMetrics(SM_CXPADDEDBORDER);
                p->rgrc[0].left   += fx;
                p->rgrc[0].right  -= fx;
                p->rgrc[0].top    += fy;
                p->rgrc[0].bottom -= fy;
            }
            out = 0;
            return true;
        }
        return false;

    case WM_NCHITTEST: {
        const POINT pt = { GET_X_LPARAM(lparam), GET_Y_LPARAM(lparam) };
        RECT rc{};
        GetWindowRect(hwnd, &rc);
        const int b = g_resize_border;

        if (!IsZoomed(hwnd)) {
            const bool left   = pt.x < rc.left + b;
            const bool right  = pt.x >= rc.right - b;
            const bool top    = pt.y < rc.top + b;
            const bool bottom = pt.y >= rc.bottom - b;
            if (top && left)     { out = HTTOPLEFT;     return true; }
            if (top && right)    { out = HTTOPRIGHT;    return true; }
            if (bottom && left)  { out = HTBOTTOMLEFT;  return true; }
            if (bottom && right) { out = HTBOTTOMRIGHT; return true; }
            if (left)            { out = HTLEFT;        return true; }
            if (right)           { out = HTRIGHT;       return true; }
            if (top)             { out = HTTOP;         return true; }
            if (bottom)          { out = HTBOTTOM;      return true; }
        }

        // The titlebar geometry comes from ImGui in client-space coords, so
        // convert the screen-space hit point before testing the drag band
        POINT cpt = pt;
        ScreenToClient(hwnd, &cpt);
        if (static_cast<float>(cpt.y) < g_titlebar_bottom &&
            static_cast<float>(cpt.x) > g_drag_left &&
            static_cast<float>(cpt.x) < g_drag_right) {
            out = HTCAPTION;
            return true;
        }

        out = HTCLIENT;
        return true;
    }

    default:
        return false;
    }
}

float TitleBarHeight()    { return g_titlebar_height; }
bool  IsWindowMaximized() { return g_hwnd && IsZoomed(g_hwnd); }

void DrawTitleBar(const std::function<void()>& draw_menus) {
    ImGuiViewport* vp = ImGui::GetMainViewport();
    const float h = ImGui::GetFrameHeight();
    g_titlebar_height = h;

    const ImVec4 mb = ImGui::GetStyleColorVec4(ImGuiCol_MenuBarBg);
    ImGui::PushStyleColor(ImGuiCol_MenuBarBg, ImVec4(mb.x, mb.y, mb.z, 0.55f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

    const ImGuiWindowFlags f = ImGuiWindowFlags_NoScrollbar |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_MenuBar;

    if (ImGui::BeginViewportSideBar("##titlebar", vp, ImGuiDir_Up, h, f)) {
        const ImVec2 wpos   = ImGui::GetWindowPos();
        const float  wwidth = ImGui::GetWindowSize().x;
        g_titlebar_bottom = wpos.y + h;
        g_drag_right      = wpos.x + wwidth;

        if (ImGui::BeginMenuBar()) {
            DrawTrafficLights(h);

            draw_menus();

            g_drag_left = ImGui::GetItemRectMax().x + 6.0f;

            ImGui::EndMenuBar();
        }
        ImGui::End();
    }

    ImGui::PopStyleVar();
    ImGui::PopStyleColor();
}

} // namespace slop::ui::chrome
