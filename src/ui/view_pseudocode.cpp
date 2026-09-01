// src/ui/view_pseudocode.cpp
// decompiler output panel with jump back navigation

#include "ui/views_core.hpp"
#include "core/disasm/binary_state.hpp"
#include "core/disasm/hyperion_session.hpp"

#include "ui/fonts.hpp"

#include "imgui.h"

#include <cstdio>
#include <string>
#include <vector>

namespace slop::ui {

namespace hs = slop::core::disasm::hyperion_session;
namespace ds = slop::core::disasm::binary_state;

namespace pseudocode_view {

namespace {

// Cached decompilation: rebuilt when the selected function or the analysis
// generation changes (re-analysis invalidates by clearing)
struct cache_t {
    uint64_t                       fn     = 0;
    bool                           valid  = false;
    std::string                    error;
    std::vector<hype::PseudoLine>  lines;
};
cache_t g_cache;

} // namespace

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    if (!ds::has_binary()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("no binary loaded.");
        return;
    }

    auto& b = ds::get();
    if (!b.hype) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("hyperion engine unavailable for this image.");
        return;
    }

    const uint64_t fn = disasm_view::SelectedFunction();

    // pin the session while touching the analyzer or an mcp reanalyze can
    // race its destruction
    {
        std::lock_guard lk(ds::state_mutex());
        if (!b.hype) {
            if (pushed) ImGui::PopFont();
            ImGui::TextDisabled("hyperion engine unavailable for this image.");
            return;
        }
        if (!b.hype->ready()) {
            char status[96];
            std::snprintf(status, sizeof(status),
                          "hyperion analysis running... %d%%",
                          static_cast<int>(b.hype->progress() * 100));
            ImGui::TextDisabled("%s", status);
            if (pushed) ImGui::PopFont();
            return;
        }
    }

    if (fn == 0) {
        if (g_cache.valid || !g_cache.lines.empty()) g_cache = cache_t{};
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("select a function in the Disassembly view.");
        return;
    }

    // (Re)decompile when the selection changed or the cache was invalidated
    if (!g_cache.valid || g_cache.fn != fn) {
        std::lock_guard lk(ds::state_mutex());
        if (!b.hype) {   // session torn down mid-frame
            g_cache = cache_t{};
            if (pushed) ImGui::PopFont();
            ImGui::TextDisabled("hyperion engine unavailable for this image.");
            return;
        }
        g_cache.fn    = fn;
        g_cache.valid = b.hype->decompile(fn, g_cache.lines, g_cache.error);
        if (!g_cache.valid) {
            if (pushed) ImGui::PopFont();
            ImGui::TextDisabled("decompile failed: %s", g_cache.error.c_str());
            return;
        }
    }

    // Header: function + line count + copy button
    {
        char hdr[160];
        std::snprintf(hdr, sizeof(hdr), "%s, %d lines",
                      g_cache.lines.empty() ? "?" :
                      g_cache.lines.front().text.c_str(),
                      static_cast<int>(g_cache.lines.size()));
        ImGui::TextDisabled("%s", hdr);
    }
    if (ImGui::SmallButton("copy")) {
        std::string all;
        for (const auto& l : g_cache.lines) {
            all.append(static_cast<size_t>(l.indent * 2), ' ');
            all += l.text;
            all += '\n';
        }
        ImGui::SetClipboardText(all.c_str());
    }
    ImGui::Separator();

    // Render: one selectable row per PseudoLine; lines with a VA jump the
    // disasm view's selection to their source instruction
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(g_cache.lines.size()),
                  ImGui::GetTextLineHeightWithSpacing());
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto& l = g_cache.lines[static_cast<size_t>(i)];
            ImGui::PushID(i);

            if (l.addr != 0) {
                char a[20];
                std::snprintf(a, sizeof(a), "%llX",
                              static_cast<unsigned long long>(l.addr));
                if (ImGui::SmallButton(a))
                    disasm_view::SelectInstruction(l.addr);
                ImGui::SameLine();
            }
            const std::string text(static_cast<size_t>(l.indent * 2), ' ');
            ImGui::TextUnformatted((text + l.text).c_str());
            ImGui::PopID();
        }
    }

    if (pushed) ImGui::PopFont();
}

} // namespace pseudocode_view

} // namespace slop::ui
