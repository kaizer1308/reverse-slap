#include "ui/command_palette.hpp"

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "imgui.h"

#include "ui/dockspace.hpp"
#include "ui/theme.hpp"
#include "ui/view_registry.hpp"

namespace slop::ui::palette {

namespace {

std::vector<Command> g_registered;   // persistent, added via Register()
std::vector<Command> g_commands;     // full list, rebuilt each open

struct Hit {
    int  cmd;
    int  score;
    std::vector<int> positions;      // matched char indices into title
};
std::vector<Hit> g_filtered;

bool  g_open        = false;
bool  g_just_opened = false;
bool  g_focus_input = false;
int   g_selected    = 0;
char  g_buf[256]    = {};
char  g_prev_buf[256] = {};

char Lower(char c) { return static_cast<char>(std::tolower(static_cast<unsigned char>(c))); }
bool IsSep(char c) { return c == ' ' || c == '_' || c == '-' || c == '/' || c == ':' || c == '.'; }
bool IsUpper(char c) { return std::isupper(static_cast<unsigned char>(c)) != 0; }
bool IsLower(char c) { return std::islower(static_cast<unsigned char>(c)) != 0; }

// Greedy earliest-match subsequence scorer. Returns false if `pat` is not a
// subsequence of `str`. Higher score = better. Positions (into str) optional
bool FuzzyScore(std::string_view pat, std::string_view str,
                std::vector<int>* out_pos, int& out_score) {
    if (out_pos) out_pos->clear();
    if (pat.empty()) { out_score = 0; return true; }

    int score = 0;
    int last_match = -2;
    size_t pi = 0;
    for (size_t si = 0; si < str.size() && pi < pat.size(); ++si) {
        if (Lower(str[si]) != Lower(pat[pi]))
            continue;

        int bonus = 2;
        if (si == 0) {
            bonus += 15;
        } else {
            const char prev = str[si - 1];
            if (IsSep(prev))                       bonus += 12;
            if (IsLower(prev) && IsUpper(str[si])) bonus += 9;
        }
        if (static_cast<int>(si) == last_match + 1) bonus += 8;
        else if (last_match >= 0)                   score -= 1;

        score += bonus;
        last_match = static_cast<int>(si);
        if (out_pos) out_pos->push_back(static_cast<int>(si));
        ++pi;
    }

    if (pi != pat.size()) return false;

    const int lead = out_pos && !out_pos->empty() ? (*out_pos)[0] : 0;
    score -= lead > 10 ? 10 : lead;
    out_score = score;
    return true;
}

void RebuildCommands() {
    g_commands.clear();
    g_commands.reserve(g_registered.size() + 16);

    for (const auto& c : g_registered)
        g_commands.push_back(c);

    for (const auto& vi : views::Snapshot()) {
        Command c;
        c.id       = "view." + vi.id;
        c.title    = (vi.open ? "Hide " : "Show ") + vi.title;
        c.group    = "View";
        c.shortcut = vi.shortcut;
        const std::string vid = vi.id;
        const bool open = vi.open;
        c.run = [vid, open] { views::SetOpen(vid, !open); };
        g_commands.push_back(std::move(c));
    }

    for (int i = 0; i < theme::Count(); ++i) {
        Command c;
        c.id    = std::string("theme.") + theme::Get(i).id;
        c.title = std::string("Theme: ") + theme::Get(i).label;
        c.group = "Theme";
        c.run   = [i] { theme::SetCurrent(i); theme::Apply(); };
        g_commands.push_back(std::move(c));
    }

    {
        Command c;
        c.id = "layout.reset"; c.title = "Reset Layout"; c.group = "Layout";
        c.run = [] { dockspace::RequestReset(); };
        g_commands.push_back(std::move(c));
    }
    {
        Command c;
        c.id = "app.quit"; c.title = "Quit reverse-slop"; c.group = "App"; c.shortcut = "Alt+F4";
        c.run = [] { PostQuitMessage(0); };
        g_commands.push_back(std::move(c));
    }
}

void BuildFiltered() {
    g_filtered.clear();
    const std::string_view pat = g_buf;

    for (int i = 0; i < static_cast<int>(g_commands.size()); ++i) {
        const Command& c = g_commands[static_cast<size_t>(i)];
        if (pat.empty()) {
            g_filtered.push_back(Hit{ i, 0, {} });
            continue;
        }
        std::vector<int> pos;
        int score = 0;
        if (FuzzyScore(pat, c.title, &pos, score)) {
            g_filtered.push_back(Hit{ i, score, std::move(pos) });
        } else {
            int gscore = 0;
            if (FuzzyScore(pat, c.group, nullptr, gscore))
                g_filtered.push_back(Hit{ i, gscore - 100, {} });
        }
    }

    if (!pat.empty()) {
        std::stable_sort(g_filtered.begin(), g_filtered.end(),
            [](const Hit& a, const Hit& b) { return a.score > b.score; });
    }
}

// Draw a title into the window draw list at screen-space `p`, tinting the
// fuzzy-matched characters with `hi` and the rest with `base`
void DrawHighlighted(ImDrawList* dl, ImVec2 p, const std::string& s,
                     const std::vector<int>& pos, ImU32 base, ImU32 hi) {
    size_t k = 0;
    float x = p.x;
    for (int i = 0; i < static_cast<int>(s.size()); ++i) {
        const bool m = (k < pos.size() && pos[k] == i);
        if (m) ++k;
        const char ch[2] = { s[static_cast<size_t>(i)], 0 };
        dl->AddText(ImVec2(x, p.y), m ? hi : base, ch);
        x += ImGui::CalcTextSize(ch).x;
    }
}

} // namespace

void Register(Command c) {
    for (auto& existing : g_registered) {
        if (existing.id == c.id) { existing = std::move(c); return; }
    }
    g_registered.push_back(std::move(c));
}

void Open() {
    g_open = true;
    g_just_opened = true;
}
void Close() {
    g_open = false;
}
void Toggle() {
    if (g_open) Close();
    else        Open();
}
bool IsOpen() { return g_open; }

void Render() {
    if (ImGui::Shortcut(ImGuiMod_Ctrl | ImGuiMod_Shift | ImGuiKey_P, ImGuiInputFlags_RouteGlobal))
        Toggle();

    if (!g_open)
        return;

    if (g_just_opened) {
        RebuildCommands();
        g_buf[0] = '\0';
        g_prev_buf[0] = '\0';
        g_selected = 0;
        g_focus_input = true;
        g_just_opened = false;
    }

    const ImGuiViewport* vp = ImGui::GetMainViewport();
    const float w = vp->WorkSize.x * 0.60f < 720.0f ? vp->WorkSize.x * 0.60f : 720.0f;
    const ImVec2 pos(vp->WorkPos.x + (vp->WorkSize.x - w) * 0.5f,
                     vp->WorkPos.y + vp->WorkSize.y * 0.12f);
    ImGui::SetNextWindowPos(pos, ImGuiCond_Always);
    ImGui::SetNextWindowSize(ImVec2(w, 0.0f), ImGuiCond_Always);
    ImGui::SetNextWindowBgAlpha(1.0f);

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(12.0f, 12.0f));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 10.0f);

    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize |
        ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_NoCollapse |
        ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_AlwaysAutoResize |
        ImGuiWindowFlags_NoScrollbar;

    if (!ImGui::Begin("##command_palette", nullptr, flags)) {
        ImGui::End();
        ImGui::PopStyleVar(2);
        return;
    }

    // Input row
    ImGui::PushItemWidth(-1.0f);
    if (g_focus_input) {
        ImGui::SetKeyboardFocusHere();
        g_focus_input = false;
    }
    bool submit = ImGui::InputTextWithHint("##pal_input", "Type a command\xE2\x80\xA6",
        g_buf, sizeof(g_buf), ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopItemWidth();

    // Reset selection when the query changes
    if (std::strncmp(g_buf, g_prev_buf, sizeof(g_buf)) != 0) {
        g_selected = 0;
        std::memcpy(g_prev_buf, g_buf, sizeof(g_prev_buf));
        g_prev_buf[sizeof(g_prev_buf) - 1] = '\0';
    }

    BuildFiltered();

    // Keyboard navigation (single-line input leaves the arrows free)
    bool nav_moved = false;
    if (!g_filtered.empty()) {
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow, true)) { g_selected++; nav_moved = true; }
        if (ImGui::IsKeyPressed(ImGuiKey_UpArrow, true))   { g_selected--; nav_moved = true; }
        const int n = static_cast<int>(g_filtered.size());
        if (g_selected < 0)  g_selected = n - 1;
        if (g_selected >= n) g_selected = 0;
    }

    ImGui::Spacing();
    ImGui::Separator();
    ImGui::Spacing();

    const ImU32 col_base   = ImGui::GetColorU32(ImGuiCol_Text);
    const ImU32 col_dim    = ImGui::GetColorU32(ImGuiCol_TextDisabled);
    const ImU32 col_accent = ImGui::ColorConvertFloat4ToU32(theme::EffectiveAccent());
    const float pad_x = ImGui::GetStyle().FramePadding.x + 4.0f;
    const float text_h = ImGui::GetTextLineHeight();
    const float row_h = text_h + ImGui::GetStyle().FramePadding.y * 2.0f + 6.0f;

    const int shown = static_cast<int>(g_filtered.size());
    const int rows = shown <= 0 ? 1 : (shown > 10 ? 10 : shown);
    const float list_h = rows * row_h + 6.0f;

    int run_index = -1;

    ImGui::BeginChild("##pal_list", ImVec2(0.0f, list_h), false, ImGuiWindowFlags_NoScrollbar);
    if (g_filtered.empty()) {
        ImGui::Spacing();
        ImGui::TextDisabled("   No matching commands");
    } else {
        for (int i = 0; i < shown; ++i) {
            const Hit& h = g_filtered[static_cast<size_t>(i)];
            const Command& c = g_commands[static_cast<size_t>(h.cmd)];
            const bool selected = (i == g_selected);

            ImGui::PushID(c.id.c_str());
            const float  avail_w = ImGui::GetContentRegionAvail().x;
            const ImVec2 sp = ImGui::GetCursorScreenPos();

            if (ImGui::Selectable("##row", selected, ImGuiSelectableFlags_None, ImVec2(0.0f, row_h)))
                run_index = h.cmd;
            if (ImGui::IsItemHovered())
                g_selected = i;

            ImDrawList* dl = ImGui::GetWindowDrawList();
            const float ty = sp.y + (row_h - text_h) * 0.5f;

            DrawHighlighted(dl, ImVec2(sp.x + pad_x, ty), c.title, h.positions, col_base, col_accent);

            std::string right = c.group;
            if (!c.shortcut.empty()) right += "   " + c.shortcut;
            if (!right.empty()) {
                const float rw = ImGui::CalcTextSize(right.c_str()).x;
                dl->AddText(ImVec2(sp.x + avail_w - rw - pad_x, ty), col_dim, right.c_str());
            }

            ImGui::PopID();

            if (selected && nav_moved)
                ImGui::SetScrollHereY(0.5f);
        }
    }
    ImGui::EndChild();

    ImGui::Spacing();
    ImGui::TextDisabled("\xE2\x86\x91\xE2\x86\x93 navigate   Enter run   Esc close   %d result%s",
        shown, shown == 1 ? "" : "s");

    if (submit && !g_filtered.empty())
        run_index = g_filtered[static_cast<size_t>(std::max(0, g_selected))].cmd;

    if (ImGui::IsKeyPressed(ImGuiKey_Escape))
        Close();

    // Dismiss on click outside the palette
    if (ImGui::IsMouseClicked(ImGuiMouseButton_Left) &&
        !ImGui::IsWindowHovered(ImGuiHoveredFlags_RootAndChildWindows))
        Close();

    ImGui::End();
    ImGui::PopStyleVar(2);

    if (run_index >= 0 && run_index < static_cast<int>(g_commands.size())) {
        auto fn = g_commands[static_cast<size_t>(run_index)].run;
        Close();
        if (fn) fn();
    }
}

} // namespace slop::ui::palette
