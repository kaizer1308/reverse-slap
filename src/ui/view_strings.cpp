// src/ui/view_strings.cpp
// strings table with filters and xref counts

#include "ui/views_core.hpp"
#include "core/disasm/binary_state.hpp"

#include "ui/fonts.hpp"

#include "imgui.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <string>

namespace slop::ui {

namespace ds = slop::core::disasm::binary_state;

namespace {
char g_str_filter[64] = {};
}

namespace strings_view {

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    auto& b = ds::get();
    if (!ds::has_binary()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("no binary loaded.");
        return;
    }

    ImGui::SetNextItemWidth(240.0f);
    ImGui::InputTextWithHint("##strfilter", "filter", g_str_filter, sizeof(g_str_filter));
    ImGui::SameLine();
    ImGui::TextDisabled("%d strings", static_cast<int>(b.strings.size()));

    if (ImGui::BeginTable("strings", 3,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
        ImGui::TableSetupColumn("type", ImGuiTableColumnFlags_WidthFixed, 56.0f);
        ImGui::TableSetupColumn("string", ImGuiTableColumnFlags_WidthStretch);
        ImGui::TableHeadersRow();

        for (const auto& s : b.strings) {
            if (g_str_filter[0] != '\0') {
                // Case-insensitive substring on the string text
                std::string hay = s.text;
                std::transform(hay.begin(), hay.end(), hay.begin(),
                               [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
                if (hay.find(g_str_filter) == std::string::npos) continue;
            }

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char a[24];
            std::snprintf(a, sizeof(a), "%011llX",
                          static_cast<unsigned long long>(s.va));
            ImGui::TextUnformatted(a);
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", s.utf16 ? "utf16" : "ascii");
            ImGui::TableNextColumn();
            const auto& refs = b.xrefs.refs_to(s.va);
            const std::string label = refs.empty()
                ? s.text
                : s.text + "  (" + std::to_string(refs.size()) + " xrefs)";
            ImGui::TextUnformatted(label.c_str());
        }
        ImGui::EndTable();
    }

    if (pushed) ImGui::PopFont();
}

} // namespace strings_view
} // namespace slop::ui
