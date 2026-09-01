#include "ui/theme.hpp"

#include <array>
#include <cstring>

namespace slop::ui::theme {

namespace {

constexpr ImVec4 rgba(float r, float g, float b, float a = 1.0f) { return ImVec4(r, g, b, a); }
constexpr ImVec4 alpha(ImVec4 c, float a) { return ImVec4(c.x, c.y, c.z, a); }
constexpr float clamp01(float v) { return v < 0.0f ? 0.0f : (v > 1.0f ? 1.0f : v); }

const std::array<Theme, 3> k_themes = {{
    Theme{
        "obsidian", "Obsidian",
        Palette{
            /*bg_0*/         rgba(0.031f, 0.033f, 0.040f),
            /*bg_1*/         rgba(0.055f, 0.058f, 0.066f),
            /*bg_2*/         rgba(0.075f, 0.078f, 0.088f),
            /*surface*/      rgba(0.088f, 0.092f, 0.104f, 0.98f),
            /*border*/       rgba(0.140f, 0.145f, 0.162f),
            /*border_soft*/  rgba(0.100f, 0.105f, 0.115f),
            /*text*/         rgba(0.860f, 0.872f, 0.900f),
            /*text_dim*/     rgba(0.620f, 0.635f, 0.660f),
            /*text_faint*/   rgba(0.480f, 0.494f, 0.520f),
            /*accent*/       rgba(0.180f, 0.720f, 0.650f),
            /*accent_hover*/ rgba(0.220f, 0.820f, 0.740f),
            /*accent_active*/rgba(0.260f, 0.900f, 0.820f),
            /*success*/      rgba(0.350f, 0.780f, 0.420f),
            /*warning*/      rgba(0.950f, 0.750f, 0.200f),
            /*danger*/       rgba(0.900f, 0.350f, 0.350f),
            /*selection*/    rgba(0.180f, 0.720f, 0.650f, 0.35f),
        },
        Tokens{},
    },
    Theme{
        "nord-slop", "Nord-slop",
        Palette{
            rgba(0.180f, 0.204f, 0.251f),
            rgba(0.231f, 0.259f, 0.322f),
            rgba(0.263f, 0.298f, 0.369f),
            rgba(0.298f, 0.337f, 0.416f, 0.98f),
            rgba(0.216f, 0.251f, 0.318f),
            rgba(0.196f, 0.220f, 0.271f),
            rgba(0.925f, 0.937f, 0.957f),
            rgba(0.741f, 0.765f, 0.816f),
            rgba(0.514f, 0.549f, 0.635f),
            rgba(0.533f, 0.753f, 0.816f),
            rgba(0.592f, 0.808f, 0.855f),
            rgba(0.651f, 0.851f, 0.882f),
            rgba(0.639f, 0.745f, 0.549f),
            rgba(0.922f, 0.796f, 0.545f),
            rgba(0.749f, 0.380f, 0.416f),
            rgba(0.533f, 0.753f, 0.816f, 0.35f),
        },
        Tokens{},
    },
    Theme{
        "blood-orange", "Blood-orange",
        Palette{
            rgba(0.055f, 0.045f, 0.045f),
            rgba(0.086f, 0.070f, 0.070f),
            rgba(0.110f, 0.090f, 0.090f),
            rgba(0.130f, 0.105f, 0.105f, 0.98f),
            rgba(0.190f, 0.145f, 0.145f),
            rgba(0.140f, 0.110f, 0.110f),
            rgba(0.940f, 0.900f, 0.880f),
            rgba(0.720f, 0.650f, 0.620f),
            rgba(0.540f, 0.480f, 0.450f),
            rgba(0.950f, 0.420f, 0.220f),
            rgba(1.000f, 0.520f, 0.300f),
            rgba(1.000f, 0.620f, 0.380f),
            rgba(0.600f, 0.780f, 0.420f),
            rgba(0.980f, 0.800f, 0.320f),
            rgba(0.900f, 0.300f, 0.300f),
            rgba(0.950f, 0.420f, 0.220f, 0.35f),
        },
        Tokens{},
    },
}};

int g_current_idx = 0;
bool g_accent_override_set = false;
ImVec4 g_accent_override = {};

void WriteStyle(const Palette& base, const Tokens& t, ImVec4 accent) {
    Palette p = base;
    p.accent = accent;
    // regenerate hover/active from accent so overrides feel consistent
    p.accent_hover  = ImVec4(clamp01(accent.x + 0.06f),
                             clamp01(accent.y + 0.06f),
                             clamp01(accent.z + 0.06f), accent.w);
    p.accent_active = ImVec4(clamp01(accent.x + 0.12f),
                             clamp01(accent.y + 0.12f),
                             clamp01(accent.z + 0.12f), accent.w);
    p.selection     = alpha(accent, 0.35f);

    ImGuiStyle& s = ImGui::GetStyle();

    s.WindowPadding    = ImVec2(t.pad_md, t.pad_md);
    s.FramePadding     = ImVec2(t.pad_sm + 2.0f, t.pad_sm - 1.0f);
    s.CellPadding      = ImVec2(t.pad_sm, t.pad_xs + 1.0f);
    s.ItemSpacing      = ImVec2(t.pad_sm + 2.0f, t.pad_sm + 1.0f);
    s.ItemInnerSpacing = ImVec2(t.pad_sm, t.pad_xs + 2.0f);
    s.IndentSpacing    = t.pad_lg + 6.0f;
    s.ScrollbarSize    = 12.0f;
    s.GrabMinSize      = 10.0f;

    s.WindowRounding    = t.radius_md + 1.0f;
    s.ChildRounding     = t.radius_md + 1.0f;
    s.PopupRounding     = t.radius_md;
    s.FrameRounding     = t.radius_sm + 1.0f;
    s.GrabRounding      = t.radius_sm + 1.0f;
    s.TabRounding       = t.radius_md;
    s.ScrollbarRounding = t.radius_lg;

    s.WindowBorderSize = 1.0f;
    s.FrameBorderSize  = 0.0f;
    s.PopupBorderSize  = 1.0f;
    s.TabBorderSize    = 0.0f;

    s.WindowTitleAlign         = ImVec2(0.0f, 0.5f);
    s.WindowMenuButtonPosition = ImGuiDir_None;
    s.ColorButtonPosition      = ImGuiDir_Left;

    ImVec4* c = s.Colors;
    c[ImGuiCol_Text]                  = p.text;
    c[ImGuiCol_TextDisabled]          = p.text_faint;
    c[ImGuiCol_WindowBg]              = p.bg_1;
    c[ImGuiCol_ChildBg]               = p.bg_2;
    c[ImGuiCol_PopupBg]               = p.surface;
    c[ImGuiCol_Border]                = p.border;
    c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_FrameBg]               = p.bg_2;
    c[ImGuiCol_FrameBgHovered]        = alpha(p.accent, 0.12f);
    c[ImGuiCol_FrameBgActive]         = alpha(p.accent, 0.22f);
    c[ImGuiCol_TitleBg]               = p.bg_0;
    c[ImGuiCol_TitleBgActive]         = p.bg_1;
    c[ImGuiCol_TitleBgCollapsed]      = p.bg_0;
    c[ImGuiCol_MenuBarBg]             = p.bg_0;
    c[ImGuiCol_ScrollbarBg]           = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ScrollbarGrab]         = p.border;
    c[ImGuiCol_ScrollbarGrabHovered]  = p.border_soft;
    c[ImGuiCol_ScrollbarGrabActive]   = p.accent;
    c[ImGuiCol_CheckMark]             = p.accent;
    c[ImGuiCol_SliderGrab]            = p.accent;
    c[ImGuiCol_SliderGrabActive]      = p.accent_hover;
    c[ImGuiCol_Button]                = p.bg_2;
    c[ImGuiCol_ButtonHovered]         = alpha(p.accent, 0.30f);
    c[ImGuiCol_ButtonActive]          = p.accent;
    c[ImGuiCol_Header]                = p.bg_2;
    c[ImGuiCol_HeaderHovered]         = alpha(p.accent, 0.24f);
    c[ImGuiCol_HeaderActive]          = alpha(p.accent, 0.36f);
    c[ImGuiCol_Separator]             = p.border;
    c[ImGuiCol_SeparatorHovered]      = p.accent_hover;
    c[ImGuiCol_SeparatorActive]       = p.accent;
    c[ImGuiCol_ResizeGrip]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_ResizeGripHovered]     = alpha(p.accent, 0.35f);
    c[ImGuiCol_ResizeGripActive]      = p.accent;
    c[ImGuiCol_Tab]                   = p.bg_0;
    c[ImGuiCol_TabHovered]            = alpha(p.accent, 0.20f);
    c[ImGuiCol_TabSelected]           = p.bg_1;
    c[ImGuiCol_TabSelectedOverline]   = p.accent;
    c[ImGuiCol_TabDimmed]             = p.bg_0;
    c[ImGuiCol_TabDimmedSelected]     = p.bg_1;
    c[ImGuiCol_DockingPreview]        = alpha(p.accent, 0.35f);
    c[ImGuiCol_DockingEmptyBg]        = p.bg_0;
    c[ImGuiCol_PlotLines]             = p.accent;
    c[ImGuiCol_PlotLinesHovered]      = p.accent_hover;
    c[ImGuiCol_PlotHistogram]         = p.accent;
    c[ImGuiCol_PlotHistogramHovered]  = p.accent_hover;
    c[ImGuiCol_TableHeaderBg]         = p.bg_2;
    c[ImGuiCol_TableBorderStrong]     = p.border;
    c[ImGuiCol_TableBorderLight]      = p.border_soft;
    c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
    c[ImGuiCol_TableRowBgAlt]         = ImVec4(1, 1, 1, 0.03f);
    c[ImGuiCol_TextSelectedBg]        = alpha(p.accent, 0.35f);
    c[ImGuiCol_DragDropTarget]        = p.accent;
    c[ImGuiCol_NavCursor]             = p.accent;
    c[ImGuiCol_NavWindowingHighlight] = p.accent_hover;
    c[ImGuiCol_NavWindowingDimBg]     = ImVec4(0, 0, 0, 0.40f);
    c[ImGuiCol_ModalWindowDimBg]      = ImVec4(0, 0, 0, 0.55f);
}

} // namespace

int Count() { return static_cast<int>(k_themes.size()); }

const Theme& Get(int idx) {
    if (idx < 0 || idx >= Count()) idx = 0;
    return k_themes[static_cast<size_t>(idx)];
}

int FindByID(std::string_view id) {
    for (int i = 0; i < Count(); ++i)
        if (id == k_themes[static_cast<size_t>(i)].id) return i;
    return -1;
}

int CurrentIndex() { return g_current_idx; }
const Theme& Current() { return Get(g_current_idx); }
void SetCurrent(int idx) {
    if (idx < 0 || idx >= Count()) return;
    g_current_idx = idx;
}

void OverrideAccent(ImVec4 accent) {
    g_accent_override_set = true;
    g_accent_override = accent;
}
void ClearAccentOverride() {
    g_accent_override_set = false;
    g_accent_override = ImVec4();
}
bool HasAccentOverride() { return g_accent_override_set; }

ImVec4 EffectiveAccent() {
    return g_accent_override_set ? g_accent_override : Current().palette.accent;
}

void Apply() {
    const Theme& t = Current();
    WriteStyle(t.palette, t.tokens, EffectiveAccent());
}

ScopedAccent::ScopedAccent(ImVec4 accent) {
    ImGui::PushStyleColor(ImGuiCol_CheckMark, accent);
    ImGui::PushStyleColor(ImGuiCol_SliderGrab, accent);
    ImGui::PushStyleColor(ImGuiCol_SliderGrabActive, alpha(accent, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, alpha(accent, 0.30f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive,  accent);
    ImGui::PushStyleColor(ImGuiCol_HeaderHovered, alpha(accent, 0.24f));
    ImGui::PushStyleColor(ImGuiCol_HeaderActive,  alpha(accent, 0.36f));
    ImGui::PushStyleColor(ImGuiCol_TabSelectedOverline, accent);
    ImGui::PushStyleColor(ImGuiCol_NavCursor, accent);
    ImGui::PushStyleColor(ImGuiCol_DragDropTarget, accent);
    ImGui::PushStyleColor(ImGuiCol_TextSelectedBg, alpha(accent, 0.35f));
}
ScopedAccent::~ScopedAccent() {
    ImGui::PopStyleColor(11);
}

} // namespace slop::ui::theme
