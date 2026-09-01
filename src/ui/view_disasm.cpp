// src/ui/view_disasm.cpp
// disassembly view, function list and virtualized code view with xref jumps

#include <windows.h>
#include <commdlg.h>

#include "ui/views_core.hpp"
#include "ui/view_registry.hpp"
#include "core/disasm/binary_state.hpp"

#include "core/process/target_service.hpp"
#include "ui/fonts.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <cstdio>
#include <string>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace disasm  = slop::core::disasm;
namespace ds      = disasm::binary_state;

namespace {

uint64_t g_selected_fn  = 0;   // function start VA
uint64_t g_selected_va  = 0;   // instruction VA (detail pane)
char     g_fn_filter[64] = {};

std::string FnLabel(uint64_t va) {
    char hex[24];
    std::snprintf(hex, sizeof(hex), "%llX", static_cast<unsigned long long>(va));
    if (const char* s = ds::symbol_for(va))
        return std::string(s) + " (sub_" + hex + ")";
    return std::string("sub_") + hex;
}

} // namespace

namespace disasm_view {

uint64_t SelectedFunction()    { return g_selected_fn; }
void     SelectFunction(uint64_t va) { g_selected_fn = va; }

void SelectInstruction(uint64_t va) {
    g_selected_va = va;
    auto& b = ds::get();
    g_selected_fn = b.fns.containing(va).value_or(va);
}

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    auto& b = ds::get();

    // Toolbar
    if (ImGui::Button("open file...")) {
        OPENFILENAMEA ofn{};
        char file[MAX_PATH]{};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner   = GetActiveWindow();
        ofn.lpstrFilter = "Executables\0*.exe;*.dll;*.sys\0All files\0*.*\0";
        ofn.lpstrFile   = file;
        ofn.nMaxFile    = MAX_PATH;
        ofn.Flags       = OFN_FILEMUSTEXIST | OFN_NOCHANGEDIR;
        if (GetOpenFileNameA(&ofn)) {
            if (!ds::load_file(file))
                panels::AppendBootLog(std::string("failed to parse: ") + file);
        }
    }
    ImGui::SameLine();
    if (ImGui::Button("load from target")) {
        if (!ds::load_from_target())
            panels::AppendBootLog("disasm: no attached target module to load");
    }

    if (!ds::has_binary()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("no binary loaded.");
        return;
    }
    ImGui::SameLine();
    if (ImGui::SmallButton("unload")) ds::unload();

    ImGui::SameLine();
    if (ImGui::SmallButton("decompile (F5)") ||
        (ImGui::IsItemHovered() && ImGui::IsKeyPressed(ImGuiKey_F5, false)) ||
        (g_selected_fn != 0 &&
         ImGui::IsWindowFocused(ImGuiFocusedFlags_ChildWindows) &&
         ImGui::IsKeyPressed(ImGuiKey_F5, false))) {
        views::SetOpen("pseudocode", true);
    }

    ImGui::SameLine();
    ImGui::TextDisabled("%s, %d fns / %d xrefs / %d strings",
                        b.name.c_str(),
                        static_cast<int>(b.fns.functions().size()),
                        static_cast<int>(b.xrefs.total()),
                        static_cast<int>(b.strings.size()));
    ImGui::Separator();

    const auto& fns = b.fns.functions();

    // Left: function list
    ImGui::BeginChild("fnlist", ImVec2(260.0f, 0.0f),
                      ImGuiChildFlags_Borders | ImGuiChildFlags_ResizeX);
    ImGui::SetNextItemWidth(-1.0f);
    ImGui::InputTextWithHint("##fnfilter", "filter", g_fn_filter, sizeof(g_fn_filter));

    if (ImGui::BeginTable("fntable", 2,
                          ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("name");
        ImGui::TableSetupColumn("size", ImGuiTableColumnFlags_WidthFixed, 52.0f);
        ImGui::TableHeadersRow();

        for (const auto& f : fns) {
            const std::string label = FnLabel(f.va);
            if (g_fn_filter[0] != '\0' &&
                label.find(g_fn_filter) == std::string::npos)
                continue;

            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(static_cast<int>(f.va & 0xFFFFFF));
            if (ImGui::Selectable(label.c_str(), g_selected_fn == f.va))
                g_selected_fn = f.va;
            ImGui::PopID();
            ImGui::TableNextColumn();
            ImGui::TextDisabled("%u", static_cast<unsigned>(f.size));
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();

    ImGui::SameLine();

    // Right: code view
    ImGui::BeginChild("codeview", ImVec2(0.0f, 0.0f));

    if (g_selected_fn == 0 && !fns.empty())
        g_selected_fn = fns.front().va;

    const disasm::function_t* fn = nullptr;
    for (const auto& f : fns)
        if (f.va == g_selected_fn) { fn = &f; break; }

    if (!fn || !b.eng.ok()) {
        ImGui::TextDisabled("select a function.");
    } else {
        const auto off_opt = b.offset_of(fn->va);
        if (!off_opt) {
            ImGui::TextDisabled("function bytes not file-backed.");
        } else {
            constexpr int kMaxInsnRows = 4096;

            struct row_t { uint64_t va; disasm::insn_t insn; };
            static std::vector<row_t> rows;
            rows.clear();

            uint64_t va = fn->va;
            size_t off = *off_opt;
            const size_t end = std::min(*off_opt + fn->size, b.file.size());
            while (off < end && static_cast<int>(rows.size()) < kMaxInsnRows) {
                auto insn = b.eng.decode(va, b.file.data() + off, end - off);
                if (!insn) { ++off; ++va; continue; }
                rows.push_back({va, *insn});
                off += insn->length;
                va  += insn->length;
            }

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(rows.size()),
                          ImGui::GetTextLineHeightWithSpacing());

            const float addr_w = 150.0f;

            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                    const row_t& r = rows[static_cast<size_t>(i)];

                    char a[24];
                    std::snprintf(a, sizeof(a), "%011llX",
                                  static_cast<unsigned long long>(r.va));
                    ImGui::TextDisabled("%s", a);

                    ImGui::SameLine(addr_w);
                    ImGui::PushID(static_cast<int>(r.va & 0xFFFFFFFF));

                    std::string line = r.insn.text;
                    if (r.insn.flow == slop::core::disasm::flow_t::call &&
                        r.insn.has_rel_target) {
                        line += "  ; " + FnLabel(r.insn.rel_target);
                    }

                    if (ImGui::Selectable(line.c_str(), g_selected_va == r.va))
                        g_selected_va = r.va;
                    ImGui::PopID();

                    // Xref count annotation for branch/data targets
                    if ((r.insn.has_rel_target || r.insn.has_rip_rel)) {
                        const uint64_t target = r.insn.has_rel_target
                            ? r.insn.rel_target : r.insn.rip_rel_target;
                        const auto& refs = b.xrefs.refs_to(target);
                        if (!refs.empty()) {
                            ImGui::SameLine();
                            char note[32];
                            std::snprintf(note, sizeof(note), "<- %d xrefs",
                                          static_cast<int>(refs.size()));
                            ImGui::TextDisabled("%s", note);
                        }
                    }
                }
            }

            // Detail pane
            ImGui::Separator();
            if (g_selected_va != 0) {
                const disasm::insn_t* sel = nullptr;
                for (const auto& r : rows)
                    if (r.va == g_selected_va) { sel = &r.insn; break; }

                if (sel) {
                    char hex[64]{};
                    for (int i = 0; i < sel->length && i < 15; ++i)
                        std::snprintf(hex + i * 3, 4, "%02X ", sel->bytes[i]);
                    ImGui::Text("@ %011llX  bytes: %s",
                                static_cast<unsigned long long>(sel->va), hex);

                    const uint64_t target = sel->has_rel_target ? sel->rel_target
                                          : sel->has_rip_rel    ? sel->rip_rel_target : 0;
                    if (target) {
                        const auto& refs = b.xrefs.refs_to(target);
                        char tline[96];
                        std::snprintf(tline, sizeof(tline),
                            "target %011llX (%d xrefs)", 
                            static_cast<unsigned long long>(target),
                            static_cast<int>(refs.size()));
                        if (ImGui::Selectable(tline))
                            g_selected_fn = b.fns.containing(target).value_or(target);
                    }
                    if (sel->flow == slop::core::disasm::flow_t::call &&
                        sel->has_rel_target) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("follow call"))
                            g_selected_fn = sel->rel_target;
                    }
                    if (b.fns.containing(sel->va)) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("rename fn")) ImGui::OpenPopup("rename");
                        if (ImGui::BeginPopup("rename")) {
                            static char name_buf[64] = {};
                            ImGui::InputText("symbol", name_buf, sizeof(name_buf));
                            if (ImGui::Button("apply")) {
                                ds::set_symbol(g_selected_fn, name_buf);
                                ImGui::CloseCurrentPopup();
                            }
                            ImGui::EndPopup();
                        }
                    }
                } else {
                    ImGui::TextDisabled("select an instruction.");
                }
            }
        }
    }

    ImGui::EndChild();
    if (pushed) ImGui::PopFont();
}

} // namespace disasm_view
} // namespace slop::ui
