#include "ui/view_registry.hpp"

#include <algorithm>
#include <cctype>
#include <vector>

#include "imgui.h"

namespace slop::ui::views {

namespace {

struct Registered {
    View spec;
    bool open;
    ImGuiKeyChord chord;
};

std::vector<Registered> g_views;

int FindIndex(std::string_view id) {
    for (size_t i = 0; i < g_views.size(); ++i)
        if (g_views[i].spec.id == id) return static_cast<int>(i);
    return -1;
}

std::string Lower(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    return out;
}

ImGuiKey KeyFromToken(std::string_view t) {
    if (t.empty()) return ImGuiKey_None;
    if (t.size() == 1) {
        char c = static_cast<char>(std::tolower(static_cast<unsigned char>(t[0])));
        if (c >= 'a' && c <= 'z') return static_cast<ImGuiKey>(ImGuiKey_A + (c - 'a'));
        if (c >= '0' && c <= '9') return static_cast<ImGuiKey>(ImGuiKey_0 + (c - '0'));
    }
    if ((t[0] == 'f' || t[0] == 'F') && t.size() >= 2) {
        int n = 0;
        for (size_t i = 1; i < t.size(); ++i) {
            if (t[i] < '0' || t[i] > '9') return ImGuiKey_None;
            n = n * 10 + (t[i] - '0');
        }
        if (n >= 1 && n <= 12) return static_cast<ImGuiKey>(ImGuiKey_F1 + (n - 1));
    }
    const std::string lower = Lower(t);
    if (lower == "space")     return ImGuiKey_Space;
    if (lower == "enter" || lower == "return") return ImGuiKey_Enter;
    if (lower == "esc" || lower == "escape")   return ImGuiKey_Escape;
    if (lower == "tab")       return ImGuiKey_Tab;
    if (lower == "backspace") return ImGuiKey_Backspace;
    if (lower == "delete" || lower == "del")   return ImGuiKey_Delete;
    return ImGuiKey_None;
}

ImGuiKeyChord ParseChord(std::string_view s) {
    ImGuiKeyChord chord = 0;
    size_t i = 0;
    while (i < s.size()) {
        while (i < s.size() && (s[i] == ' ' || s[i] == '\t')) ++i;
        size_t j = i;
        while (j < s.size() && s[j] != '+') ++j;
        std::string_view tok = s.substr(i, j - i);
        while (!tok.empty() && (tok.back() == ' ' || tok.back() == '\t')) tok.remove_suffix(1);
        const std::string lower = Lower(tok);
        if      (lower == "ctrl"  || lower == "control") chord |= ImGuiMod_Ctrl;
        else if (lower == "shift")                        chord |= ImGuiMod_Shift;
        else if (lower == "alt")                          chord |= ImGuiMod_Alt;
        else if (lower == "super" || lower == "win")      chord |= ImGuiMod_Super;
        else {
            const ImGuiKey k = KeyFromToken(tok);
            if (k != ImGuiKey_None) chord |= k;
        }
        i = (j == s.size()) ? j : (j + 1);
    }
    return chord;
}

} // namespace

void Register(View v) {
    Registered r;
    r.chord = v.shortcut.empty() ? 0 : ParseChord(v.shortcut);
    r.open  = v.default_open;
    r.spec  = std::move(v);
    const int existing = FindIndex(r.spec.id);
    if (existing >= 0) g_views[static_cast<size_t>(existing)] = std::move(r);
    else               g_views.push_back(std::move(r));
}

void Toggle(std::string_view id) {
    const int i = FindIndex(id);
    if (i >= 0) g_views[static_cast<size_t>(i)].open = !g_views[static_cast<size_t>(i)].open;
}
void SetOpen(std::string_view id, bool open) {
    const int i = FindIndex(id);
    if (i >= 0) g_views[static_cast<size_t>(i)].open = open;
}
bool IsOpen(std::string_view id) {
    const int i = FindIndex(id);
    return i >= 0 && g_views[static_cast<size_t>(i)].open;
}

std::vector<ViewInfo> Snapshot() {
    std::vector<ViewInfo> out;
    out.reserve(g_views.size());
    for (const auto& r : g_views)
        out.push_back(ViewInfo{ r.spec.id, r.spec.title, r.spec.category, r.spec.shortcut, r.open });
    return out;
}

void DrawMenuItems() {
    std::vector<std::string> cat_order;
    for (const auto& r : g_views) {
        if (std::find(cat_order.begin(), cat_order.end(), r.spec.category) == cat_order.end())
            cat_order.push_back(r.spec.category);
    }
    bool first = true;
    for (const auto& cat : cat_order) {
        if (!first) ImGui::Separator();
        first = false;
        for (auto& r : g_views) {
            if (r.spec.category != cat) continue;
            const char* sc = r.spec.shortcut.empty() ? nullptr : r.spec.shortcut.c_str();
            if (ImGui::MenuItem(r.spec.title.c_str(), sc, r.open))
                r.open = !r.open;
        }
    }
}

void DrawAll() {
    for (auto& r : g_views) {
        if (r.chord == 0) continue;
        if (ImGui::Shortcut(r.chord, ImGuiInputFlags_RouteGlobal))
            r.open = !r.open;
    }
    for (auto& r : g_views) {
        if (!r.open) continue;
        if (ImGui::Begin(r.spec.title.c_str(), &r.open)) {
            if (r.spec.draw) r.spec.draw();
        }
        ImGui::End();
    }
}

} // namespace slop::ui::views
