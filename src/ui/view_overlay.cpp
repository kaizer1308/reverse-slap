// src/ui/view_overlay.cpp
// Discord overlay control panel: connect, draw commands, ESP config
#include "ui/views_core.hpp"
#include "imgui.h"
#include "core/overlay/discord_overlay.hpp"
#include "core/process/target_service.hpp"
#include <cstdio>
#include <string>

namespace slop::ui::ov {

namespace overlay = slop::core::overlay;
namespace process = slop::core::process;

void DrawOverlay() {
    auto sess = process::active_session();

    auto st = overlay::state();

    ImGui::TextWrapped(
        "discord overlay hijack: draws on top of the game through "
        "Discord's own in-game overlay framebuffer. no injection, "
        "no hooks, no new windows — uses Discord's existing shared memory.");
    ImGui::Separator();

    // connection
    if (!st.connected) {
        if (sess && sess->valid()) {
            if (ImGui::Button("connect to Discord overlay")) {
                overlay::connect(sess->pid());
                st = overlay::state();
            }
        } else {
            ImGui::TextDisabled("attach a target first");
        }
        if (!st.error.empty()) {
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
                               "%s", st.error.c_str());
        }
    } else {
        ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                           "connected to PID %u (%ux%u @ %.0f fps)",
                           st.target_pid, st.width, st.height, st.fps);
        if (ImGui::Button("disconnect")) {
            overlay::disconnect();
            return;
        }
        ImGui::SameLine();
        if (ImGui::Button("clear overlay")) overlay::clear();
    }

    if (!st.connected) return;

    // draw test controls
    ImGui::SeparatorText("draw commands");

    static float box_x = 100, box_y = 100, box_w = 200, box_h = 300;
    static float text_x = 100, text_y = 80;
    static char text_buf[128] = "ESP Target";
    static float health = 0.75f;
    static float cross_x = 960, cross_y = 540, cross_size = 10;
    static bool show_esp = false;
    static bool show_cross = false;

    ImGui::Checkbox("show ESP box", &show_esp);
    if (show_esp) {
        ImGui::SliderFloat("x##esp", &box_x, 0, static_cast<float>(st.width));
        ImGui::SliderFloat("y##esp", &box_y, 0, static_cast<float>(st.height));
        ImGui::SliderFloat("w##esp", &box_w, 10, 500);
        ImGui::SliderFloat("h##esp", &box_h, 10, 800);
        ImGui::InputText("label##esp", text_buf, sizeof(text_buf));
        ImGui::SliderFloat("health##esp", &health, 0.0f, 1.0f);
    }

    ImGui::Checkbox("show crosshair", &show_cross);
    if (show_cross) {
        ImGui::SliderFloat("x##cross", &cross_x, 0, static_cast<float>(st.width));
        ImGui::SliderFloat("y##cross", &cross_y, 0, static_cast<float>(st.height));
        ImGui::SliderFloat("size##cross", &cross_size, 2, 50);
    }

    // render frame
    std::vector<overlay::draw_cmd_t> cmds;

    if (show_esp) {
        // ESP box
        overlay::draw_cmd_t box;
        box.type = overlay::cmd_type_t::rect;
        box.x1 = box_x; box.y1 = box_y;
        box.x2 = box_x + box_w; box.y2 = box_y + box_h;
        box.color = { 255, 50, 50, 200 };
        box.thickness = 2.0f;
        cmds.push_back(box);

        // label
        overlay::draw_cmd_t lbl;
        lbl.type = overlay::cmd_type_t::text;
        lbl.x1 = box_x; lbl.y1 = box_y - 14;
        lbl.text = text_buf;
        lbl.color = { 255, 255, 255, 255 };
        lbl.font_size = 12.0f;
        cmds.push_back(lbl);

        // health bar (left side of box)
        overlay::draw_cmd_t hbar_bg;
        hbar_bg.type = overlay::cmd_type_t::filled_rect;
        hbar_bg.x1 = box_x - 6; hbar_bg.y1 = box_y;
        hbar_bg.x2 = box_x - 2; hbar_bg.y2 = box_y + box_h;
        hbar_bg.color = { 40, 40, 40, 180 };
        cmds.push_back(hbar_bg);

        float fill_h = box_h * health;
        overlay::draw_cmd_t hbar_fg;
        hbar_fg.type = overlay::cmd_type_t::filled_rect;
        hbar_fg.x1 = box_x - 6; hbar_fg.y1 = box_y + box_h - fill_h;
        hbar_fg.x2 = box_x - 2; hbar_fg.y2 = box_y + box_h;
        hbar_fg.color = health > 0.5f
            ? overlay::color_t{ 50, 255, 50, 220 }
            : health > 0.25f
                ? overlay::color_t{ 255, 200, 50, 220 }
                : overlay::color_t{ 255, 50, 50, 220 };
        cmds.push_back(hbar_fg);
    }

    if (show_cross) {
        overlay::draw_cmd_t cx;
        cx.type = overlay::cmd_type_t::cross;
        cx.x1 = cross_x; cx.y1 = cross_y;
        cx.radius = cross_size;
        cx.color = { 0, 255, 0, 255 };
        cx.thickness = 2.0f;
        cmds.push_back(cx);
    }

    overlay::submit(std::move(cmds));
    overlay::render();

    // stats
    ImGui::SeparatorText("stats");
    ImGui::Text("frames rendered: %u", st.frame_count);
    ImGui::Text("framebuffer: %ux%u (%zu KB)", st.width, st.height,
                static_cast<size_t>(st.width) * st.height * 4 / 1024);
}

} // namespace slop::ui::ov
