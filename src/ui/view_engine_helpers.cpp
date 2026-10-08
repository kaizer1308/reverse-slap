// src/ui/view_engine_helpers.cpp
// Game engine helpers: world-to-screen projection, UE4/UE5 struct readers,
// Unity transform walker, TArray viewer, camera finder.
#include "ui/views_core.hpp"
#include "imgui.h"
#include "core/runtime/world_projection.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/game_tools.hpp"
#include "core/process/target_service.hpp"
#include <cstdio>
#include <string>
#include <vector>

namespace slop::ui::eh {

namespace projection = slop::core::runtime::projection;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
using slop::core::runtime::game_tools::reader_t;

static reader_t make_reader() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) return {};
    reader_t rd; rd.be = &runtime::active(); rd.h = sess->handle();
    return rd;
}

// ── world-to-screen tester ───────────────────────────────────────────────

void DrawW2STester() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static int mode = 0;  // 0=UE camera, 1=row-major matrix, 2=column-major
    static float world[3] = { 0, 0, 0 };
    static float screen_w = 1920, screen_h = 1080;
    static uint64_t camera_addr = 0;
    static float matrix[16] = {};
    static uint64_t matrix_addr = 0;
    static projection::screen_point_t result = {};

    ImGui::TextWrapped("project 3D world coordinates to 2D screen position. "
                       "supports UE4/UE5 camera, row-major (DirectX/Source), "
                       "and column-major (Unity/OpenGL) matrices.");
    ImGui::Separator();

    const char* modes[] = { "UE Camera (FMinimalViewInfo)",
                            "Row-major matrix (DirectX/Source)",
                            "Column-major matrix (Unity/OpenGL)" };
    ImGui::Combo("mode##w2s", &mode, modes, 3);

    ImGui::InputFloat3("world position", world);
    ImGui::InputFloat("screen width", &screen_w);
    ImGui::InputFloat("screen height", &screen_h);

    if (mode == 0) {
        ImGui::InputScalar("camera address##w2s", ImGuiDataType_U64,
                           &camera_addr, nullptr, nullptr, "%016llX",
                           ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::Button("project (UE)") && camera_addr) {
            auto rd = make_reader();
            auto view = projection::read_ue_view_info(rd, camera_addr);
            result = projection::ue_world_to_screen(
                { world[0], world[1], world[2] }, view, screen_w, screen_h);
        }
    } else {
        ImGui::InputScalar("matrix address##w2s", ImGuiDataType_U64,
                           &matrix_addr, nullptr, nullptr, "%016llX",
                           ImGuiInputTextFlags_CharsHexadecimal);
        if (ImGui::Button("read matrix") && matrix_addr) {
            auto rd = make_reader();
            rd.read(matrix_addr, matrix, sizeof(matrix));
        }
        // show matrix
        for (int r = 0; r < 4; ++r) {
            ImGui::Text("  [%.3f  %.3f  %.3f  %.3f]",
                        matrix[r*4+0], matrix[r*4+1],
                        matrix[r*4+2], matrix[r*4+3]);
        }
        if (ImGui::Button("project")) {
            if (mode == 1) {
                result = projection::world_to_screen_rowmajor(
                    { world[0], world[1], world[2] },
                    matrix, screen_w, screen_h);
            } else {
                result = projection::world_to_screen_transposed(
                    { world[0], world[1], world[2] },
                    matrix, screen_w, screen_h);
            }
        }
    }

    ImGui::SeparatorText("result");
    if (result.visible) {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                           "screen: (%.1f, %.1f) — visible", result.x, result.y);
    } else {
        ImGui::TextDisabled("not visible (behind camera or out of bounds)");
    }
}

// ── TArray viewer ────────────────────────────────────────────────────────

void DrawTArrayViewer() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static uint64_t tarray_addr = 0;
    static int max_count = 256;
    static std::vector<uint64_t> elements;

    ImGui::TextWrapped("read a UE4/UE5 TArray<T*> from memory. shows the "
                       "pointer values at each index.");
    ImGui::Separator();

    ImGui::InputScalar("TArray address", ImGuiDataType_U64, &tarray_addr,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputInt("max count", &max_count, 32, 256);

    if (ImGui::Button("read TArray") && tarray_addr) {
        auto rd = make_reader();
        elements = projection::read_tarray(rd, tarray_addr, max_count);
    }

    ImGui::Text("%zu elements", elements.size());
    if (!ImGui::BeginTable("tarray", 2,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("index");
    ImGui::TableSetupColumn("pointer");
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < elements.size(); ++i) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("[%zu]", i);
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(elements[i]));
    }
    ImGui::EndTable();
}

// ── UE camera finder ─────────────────────────────────────────────────────

void DrawUECameraFinder() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<std::pair<uint64_t, projection::ue_view_info_t>> candidates;

    ImGui::TextWrapped("scan memory for UE4/UE5 camera data "
                       "(FMinimalViewInfo with plausible FOV and rotation values).");

    if (ImGui::Button("scan for cameras")) {
        candidates.clear();
        auto rd = make_reader();
        auto regs = runtime::active().enum_regions(sess->handle());

        for (const auto& reg : regs.items) {
            if (reg.state != 0x1000) continue;
            if (reg.size > 16 * 1024 * 1024) continue;
            if (!(reg.protect & 0x04) && !(reg.protect & 0x40)) continue;

            const size_t count = reg.size / 4;
            std::vector<float> buf(count);
            if (!rd.read(reg.base, buf.data(), count * 4)) continue;

            for (size_t i = 0; i + 7 <= count; ++i) {
                float fov = buf[i + 6];
                if (fov < 30.0f || fov > 170.0f) continue;

                float pitch = buf[i + 3], yaw = buf[i + 4];
                if (std::abs(pitch) > 360 || std::abs(yaw) > 360) continue;

                // plausible location (not all zeros, not all same)
                float lx = buf[i], ly = buf[i+1], lz = buf[i+2];
                if (lx == 0 && ly == 0 && lz == 0) continue;
                if (lx == ly && ly == lz) continue;

                projection::ue_view_info_t v;
                v.location = { lx, ly, lz };
                v.rotation = { pitch, yaw, buf[i+5] };
                v.fov = fov;
                candidates.push_back({ reg.base + i * 4, v });
                if (candidates.size() > 64) goto done;
            }
        }
done:;
    }

    ImGui::Text("%zu candidates", candidates.size());
    if (!ImGui::BeginTable("cameras", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("address");
    ImGui::TableSetupColumn("location");
    ImGui::TableSetupColumn("rotation");
    ImGui::TableSetupColumn("FOV");
    ImGui::TableSetupColumn("refresh");
    ImGui::TableHeadersRow();
    for (size_t i = 0; i < candidates.size(); ++i) {
        auto& [addr, v] = candidates[i];
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(addr));
        ImGui::TableNextColumn();
        ImGui::Text("(%.0f, %.0f, %.0f)", v.location.x, v.location.y, v.location.z);
        ImGui::TableNextColumn();
        ImGui::Text("P:%.1f Y:%.1f R:%.1f", v.rotation.x, v.rotation.y, v.rotation.z);
        ImGui::TableNextColumn();
        ImGui::Text("%.1f", v.fov);
        ImGui::TableNextColumn();
        char id[16]; std::snprintf(id, sizeof(id), "##cam%zu", i);
        if (ImGui::SmallButton(id)) {
            auto rd = make_reader();
            v = projection::read_ue_view_info(rd, addr);
        }
    }
    ImGui::EndTable();
}

} // namespace slop::ui::eh
