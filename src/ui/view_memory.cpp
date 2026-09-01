// src/ui/view_memory.cpp
// hex editor with region picker, goto and copy as exporters

#include <windows.h>

#include "ui/views_core.hpp"

#include "core/infra/text_format.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "ui/fonts.hpp"

#include "imgui.h"

#include <cstring>
#include <string>
#include <vector>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace infra   = slop::core::infra;

namespace {

using runtime::region_info_t;

constexpr size_t   kPageSize    = 4096;
constexpr int      kRowBytes    = 16;

std::vector<region_info_t> g_regions;
int                        g_region_idx     = -1;
uintptr_t                  g_view_base      = 0;
std::vector<uint8_t>       g_buffer(kPageSize, 0);
bool                       g_buffer_valid   = false;
char                       g_goto_buf[32]   = {};
char                       g_patch_buf[128] = {};
uintptr_t                  g_selected       = 0;
bool                       g_selected_valid = false;

const char* ProtectTag(uint32_t protect) {
    switch (protect & 0xFF) {
    case PAGE_NOACCESS:          return "---";
    case PAGE_READONLY:          return "R--";
    case PAGE_READWRITE:         return "RW-";
    case PAGE_WRITECOPY:         return "RWC";
    case PAGE_EXECUTE:           return "--X";
    case PAGE_EXECUTE_READ:      return "R-X";
    case PAGE_EXECUTE_READWRITE: return "RWX";
    default:                     return "???";
    }
}

bool RegionReadable(const region_info_t& r) {
    if (r.state != MEM_COMMIT) return false;
    if (r.protect & PAGE_GUARD) return false;
    constexpr uint32_t kReadable = PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                                   PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
                                   PAGE_EXECUTE_WRITECOPY;
    return (r.protect & 0xFF) & kReadable;
}

void RefreshBuffer() {
    const auto session = process::active_session();
    g_buffer_valid = false;
    if (!session || !session->valid()) return;
    auto io = session->read(g_view_base, g_buffer.data(), g_buffer.size());
    g_buffer_valid = io.ok;
}

void RefreshRegions() {
    const auto session = process::active_session();
    g_regions.clear();
    g_region_idx = -1;
    if (!session || !session->valid()) return;
    auto res = runtime::active().enum_regions(session->handle());
    if (!res.ok) return;
    for (const auto& r : res.items)
        if (RegionReadable(r)) g_regions.push_back(r);
}

void CopyAs(infra::fmt::copy_dialect_t dialect) {
    const std::string s = infra::fmt::format_as(g_buffer, dialect);
    ImGui::SetClipboardText(s.c_str());
}

} // namespace

namespace memory_view {

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    const auto session = process::active_session();
    if (!session || !session->valid()) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("attach a target to browse memory.");
        return;
    }

    // Toolbar
    if (ImGui::SmallButton("regions")) RefreshRegions();
    ImGui::SameLine();
    if (!g_regions.empty()) {
        if (g_region_idx < 0 || g_region_idx >= static_cast<int>(g_regions.size())) g_region_idx = 0;
        std::string labels;
        labels.reserve(64 * 8);
        std::vector<const char*> items;
        for (const auto& r : g_regions) {
            char line[96];
            std::snprintf(line, sizeof(line), "%012llX %s %uK",
                static_cast<unsigned long long>(r.base), ProtectTag(r.protect),
                static_cast<unsigned>(r.size >> 10));
            labels += line;
            labels.push_back('\0');
            items.push_back(labels.c_str() + (labels.size() - strlen(line) - 1));
        }
        ImGui::SetNextItemWidth(260.0f);
        int idx = g_region_idx;
        if (ImGui::Combo("##region", &idx, items.data(), static_cast<int>(items.size()))) {
            g_region_idx = idx;
            g_view_base  = g_regions[static_cast<size_t>(idx)].base;
            g_selected_valid = false;
            RefreshBuffer();
        }
    } else {
        ImGui::TextDisabled("no readable regions");
    }

    ImGui::SameLine();
    if (ImGui::InputTextWithHint("##goto", "goto (hex)", g_goto_buf, sizeof(g_goto_buf),
                                 ImGuiInputTextFlags_EnterReturnsTrue)) {
        std::vector<uint8_t> out;
        std::string err;
        // Reuse parse_hex on raw bytes then reassemble as big-endian address
        if (infra::fmt::parse_hex(g_goto_buf, out, err) && !out.empty() && out.size() <= 8) {
            uintptr_t addr = 0;
            for (uint8_t b : out) addr = (addr << 8) | b;
            g_view_base = addr & ~uintptr_t{0xF};
            g_selected = addr;
            g_selected_valid = true;
            RefreshBuffer();
        }
    }

    if (g_buffer_valid && ImGui::SmallButton("copy row: C##ca")) CopyAs(infra::fmt::copy_dialect_t::c_array);
    if (g_buffer_valid) {
        ImGui::SameLine();
        if (ImGui::SmallButton("Py##py")) CopyAs(infra::fmt::copy_dialect_t::python_bytes);
        ImGui::SameLine();
        if (ImGui::SmallButton("Rs##rs")) CopyAs(infra::fmt::copy_dialect_t::rust_array);
    }
    ImGui::Separator();

    if (!g_buffer_valid) {
        if (pushed) ImGui::PopFont();
        ImGui::TextDisabled("unreadable page @ %012llX",
                            static_cast<unsigned long long>(g_view_base));
        return;
    }

    // Hex grid
    const float row_h   = ImGui::GetTextLineHeight();
    const float pad_x   = ImGui::CalcTextSize(" ").x;
    const ImVec2 cell2  = ImGui::CalcTextSize("00");
    const float cell_w  = cell2.x * 1.35f;
    const float addr_w  = ImGui::CalcTextSize("000000000000").x + pad_x;

    ImGui::BeginChild("hexgrid", ImVec2(0.0f, ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing()));

    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(kPageSize / kRowBytes), row_h);
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const uintptr_t row_addr = g_view_base + static_cast<uintptr_t>(row) * kRowBytes;
            const float row_start_x = ImGui::GetCursorPosX();

            char addr_label[16];
            std::snprintf(addr_label, sizeof(addr_label), "%012llX",
                          static_cast<unsigned long long>(row_addr));
            ImGui::TextUnformatted(addr_label);

            for (int b = 0; b < kRowBytes; ++b) {
                const uintptr_t a = row_addr + static_cast<uintptr_t>(b);
                const uint8_t v = g_buffer[static_cast<size_t>(row) * kRowBytes + b];
                char label[4];
                std::snprintf(label, sizeof(label), "%02X", v);

                const bool sel = g_selected_valid && a == g_selected;
                if (sel) ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.75f, 0.25f, 1.0f));
                ImGui::SetCursorPosX(row_start_x + addr_w + static_cast<float>(b) * cell_w);
                ImGui::TextUnformatted(label);
                if (sel) ImGui::PopStyleColor();

                if (ImGui::IsItemHovered() && ImGui::IsMouseClicked(0)) {
                    g_selected = a;
                    g_selected_valid = true;
                }
            }

            // ASCII gutter
            ImGui::SetCursorPosX(row_start_x + addr_w + static_cast<float>(kRowBytes) * cell_w + pad_x);
            char ascii[kRowBytes + 1];
            for (int b = 0; b < kRowBytes; ++b) {
                const uint8_t v = g_buffer[static_cast<size_t>(row) * kRowBytes + b];
                ascii[b] = (v >= 0x20 && v < 0x7F) ? static_cast<char>(v) : '.';
            }
            ascii[kRowBytes] = '\0';
            ImGui::TextDisabled("%s", ascii);
        }
    }
    ImGui::EndChild();

    // Patch row
    if (g_selected_valid) {
        ImGui::Text("sel: %012llX", static_cast<unsigned long long>(g_selected));
        ImGui::SameLine();
        ImGui::SetNextItemWidth(300.0f);
        ImGui::InputTextWithHint("##patch", "patch bytes (hex)", g_patch_buf, sizeof(g_patch_buf));
        ImGui::SameLine();
        if (ImGui::SmallButton("write") && g_patch_buf[0] != '\0') {
            std::vector<uint8_t> bytes;
            std::string err;
            if (infra::fmt::parse_hex(g_patch_buf, bytes, err) && !bytes.empty()) {
                auto io = session->write(g_selected, bytes.data(), bytes.size());
                if (io.ok) {
                    RefreshBuffer(); // keep the visible window coherent
                    g_patch_buf[0] = '\0';
                }
            }
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("goto sel")) {
            g_view_base = g_selected & ~uintptr_t{0xF};
            RefreshBuffer();
        }
    }

    if (pushed) ImGui::PopFont();
}

} // namespace memory_view
} // namespace slop::ui
