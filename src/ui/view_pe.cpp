// src/ui/view_pe.cpp
// pe header browser, sections, directories, imports, exports

#include "ui/views_core.hpp"
#include "core/disasm/binary_state.hpp"

#include "ui/fonts.hpp"

#include "imgui.h"

#include <cstdio>

namespace slop::ui {

namespace ds = slop::core::disasm::binary_state;

namespace pe_view {

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

    const auto& pe = b.pe;

    // Summary
    if (ImGui::CollapsingHeader("image", ImGuiTreeNodeFlags_DefaultOpen)) {
        char line[160];
        std::snprintf(line, sizeof(line),
            "base %012llX  entry-rva %08X  machine %04X  %s  subsystem %u",
            static_cast<unsigned long long>(pe.image_base),
            static_cast<unsigned>(pe.entry_rva),
            static_cast<unsigned>(pe.machine),
            pe.pe32plus ? "PE32+" : "PE32",
            static_cast<unsigned>(pe.subsystem));
        ImGui::TextUnformatted(line);
    }

    // Sections
    if (ImGui::CollapsingHeader("sections", ImGuiTreeNodeFlags_DefaultOpen)) {
        if (ImGui::BeginTable("secs", 6,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("name", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("rva", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("vsize", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("rawoff", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("rawsz", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("flags", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            for (const auto& s : pe.sections) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                ImGui::TextUnformatted(s.name);
                ImGui::TableNextColumn(); ImGui::Text("%08X", static_cast<unsigned>(s.rva));
                ImGui::TableNextColumn(); ImGui::Text("%X", static_cast<unsigned>(s.virtual_size));
                ImGui::TableNextColumn(); ImGui::Text("%X", static_cast<unsigned>(s.raw_offset));
                ImGui::TableNextColumn(); ImGui::Text("%X", static_cast<unsigned>(s.raw_size));
                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s%s%s", s.is_executable() ? "x" : "-",
                                    (s.characteristics & 0x40000000) ? "r" : "-",
                                    (s.characteristics & 0x80000000) ? "w" : "-");
            }
            ImGui::EndTable();
        }
    }

    // Data directories
    if (ImGui::CollapsingHeader("data directories")) {
        static constexpr const char* kNames[16] = {
            "export", "import", "resource", "exception", "security", "reloc",
            "debug", "arch", "globalptr", "tls", "loadcfg", "bound-import",
            "iat", "delay-import", "com", "reserved"
        };
        for (int i = 0; i < 16; ++i) {
            if (pe.data_dirs[i].rva == 0 && pe.data_dirs[i].size == 0) continue;
            char line[96];
            std::snprintf(line, sizeof(line), "%-13s rva %08X  size %X",
                          kNames[i], pe.data_dirs[i].rva, pe.data_dirs[i].size);
            ImGui::TextUnformatted(line);
        }
    }

    // Imports
    if (ImGui::CollapsingHeader("imports")) {
        for (const auto& dll : pe.imports) {
            if (!ImGui::TreeNode(dll.dll.c_str(), "%s (%d)",
                                 dll.dll.c_str(),
                                 static_cast<int>(dll.functions.size())))
                continue;
            for (const auto& f : dll.functions) {
                if (f.by_ordinal) ImGui::BulletText("#%u", f.ordinal);
                else              ImGui::BulletText("%s", f.name.c_str());
            }
            ImGui::TreePop();
        }
    }

    // Exports
    if (ImGui::CollapsingHeader("exports")) {
        if (pe.exports.empty()) ImGui::TextDisabled("(none)");
        else if (ImGui::BeginTable("exps", 3,
                                   ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("ordinal", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("rva", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("name");
            ImGui::TableHeadersRow();
            for (const auto& e : pe.exports) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::Text("%u", e.ordinal);
                ImGui::TableNextColumn(); ImGui::Text("%08X", e.rva);
                ImGui::TableNextColumn(); ImGui::TextUnformatted(e.name.c_str());
            }
            ImGui::EndTable();
        }
    }

    if (pushed) ImGui::PopFont();
}

} // namespace pe_view
} // namespace slop::ui
