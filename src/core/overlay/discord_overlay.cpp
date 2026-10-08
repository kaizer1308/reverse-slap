// src/core/overlay/discord_overlay.cpp
// Discord overlay hijack implementation. Writes draw commands into
// Discord's shared memory framebuffer at native game FPS.

#include "core/overlay/discord_overlay.hpp"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstring>
#include <mutex>

namespace slop::core::overlay {

namespace {

// Discord's framebuffer shared memory header
#pragma pack(push, 1)
struct discord_fb_header_t {
    uint32_t magic;
    uint32_t frame_count;
    uint32_t unknown;
    uint32_t width;
    uint32_t height;
    // followed by BGRA pixel data: width * height * 4 bytes
};
#pragma pack(pop)

struct pixel_t {
    uint8_t b, g, r, a;
};

// connection state
struct connection_t {
    HANDLE              file_handle = nullptr;
    discord_fb_header_t* mapped = nullptr;
    uint32_t            pid = 0;
    uint32_t            width = 0;
    uint32_t            height = 0;
    uint32_t            last_frame_count = 0;
    std::string         error;

    // local framebuffer for rendering before memcpy to shared memory
    std::vector<pixel_t> local_fb;

    // FPS tracking
    int64_t             last_render_us = 0;
    float               fps = 0.0f;
    uint32_t            render_count = 0;
};

connection_t g_conn;
std::mutex g_cmd_mutex;
std::vector<draw_cmd_t> g_pending_cmds;
std::vector<draw_cmd_t> g_active_cmds;

int64_t now_us() {
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::high_resolution_clock::now().time_since_epoch()).count();
}

// ── pixel-level drawing into local framebuffer ───────────────────────────

void set_pixel(int x, int y, pixel_t color) {
    if (x < 0 || y < 0 ||
        x >= static_cast<int>(g_conn.width) ||
        y >= static_cast<int>(g_conn.height)) return;
    auto& dst = g_conn.local_fb[y * g_conn.width + x];
    if (color.a == 255) {
        dst = color;
    } else if (color.a > 0) {
        // alpha blend
        uint32_t sa = color.a, da = 255 - sa;
        dst.r = static_cast<uint8_t>((color.r * sa + dst.r * da) / 255);
        dst.g = static_cast<uint8_t>((color.g * sa + dst.g * da) / 255);
        dst.b = static_cast<uint8_t>((color.b * sa + dst.b * da) / 255);
        dst.a = static_cast<uint8_t>(std::min<uint32_t>(255, sa + dst.a));
    }
}

pixel_t to_pixel(color_t c) {
    return { c.b, c.g, c.r, c.a };
}

void draw_line_px(int x1, int y1, int x2, int y2, pixel_t color, float thickness) {
    // Bresenham with thickness
    int dx = std::abs(x2 - x1), sx = x1 < x2 ? 1 : -1;
    int dy = -std::abs(y2 - y1), sy = y1 < y2 ? 1 : -1;
    int err = dx + dy;
    int half_t = static_cast<int>(thickness / 2.0f);

    while (true) {
        for (int ty = -half_t; ty <= half_t; ++ty)
            for (int tx = -half_t; tx <= half_t; ++tx)
                set_pixel(x1 + tx, y1 + ty, color);
        if (x1 == x2 && y1 == y2) break;
        int e2 = 2 * err;
        if (e2 >= dy) { err += dy; x1 += sx; }
        if (e2 <= dx) { err += dx; y1 += sy; }
    }
}

void draw_rect_px(int x, int y, int w, int h, pixel_t color, float thickness) {
    int t = static_cast<int>(thickness);
    for (int i = 0; i < t; ++i) {
        for (int px = x - i; px < x + w + i; ++px) {
            set_pixel(px, y - i, color);
            set_pixel(px, y + h - 1 + i, color);
        }
        for (int py = y - i; py < y + h + i; ++py) {
            set_pixel(x - i, py, color);
            set_pixel(x + w - 1 + i, py, color);
        }
    }
}

void draw_filled_rect_px(int x, int y, int w, int h, pixel_t color) {
    for (int py = y; py < y + h; ++py)
        for (int px = x; px < x + w; ++px)
            set_pixel(px, py, color);
}

void draw_circle_px(int cx, int cy, int radius, pixel_t color, float thickness) {
    int t = std::max(1, static_cast<int>(thickness));
    for (int r = radius - t/2; r <= radius + t/2; ++r) {
        int x = r, y = 0, err = 1 - x;
        while (x >= y) {
            set_pixel(cx+x, cy+y, color); set_pixel(cx-x, cy+y, color);
            set_pixel(cx-x, cy-y, color); set_pixel(cx+x, cy-y, color);
            set_pixel(cx+y, cy+x, color); set_pixel(cx-y, cy+x, color);
            set_pixel(cx-y, cy-x, color); set_pixel(cx+y, cy-x, color);
            y++;
            if (err < 0) err += 2*y + 1;
            else { x--; err += 2*(y - x + 1); }
        }
    }
}

void draw_filled_circle_px(int cx, int cy, int radius, pixel_t color) {
    for (int y = -radius; y <= radius; ++y)
        for (int x = -radius; x <= radius; ++x)
            if (x*x + y*y <= radius*radius)
                set_pixel(cx + x, cy + y, color);
}

// simple 5x7 bitmap font for text rendering (ASCII 32-126)
void draw_char_px(int x, int y, char ch, pixel_t color, float size) {
    // minimal bitmap font: each character is 5 wide, 7 tall
    // stored as 7 bytes per character, each byte has 5 bits
    static const uint8_t font_data[95][7] = {
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00}, // space
        {0x04,0x04,0x04,0x04,0x04,0x00,0x04}, // !
        {0x0A,0x0A,0x00,0x00,0x00,0x00,0x00}, // "
        {0x0A,0x1F,0x0A,0x0A,0x1F,0x0A,0x00}, // #
        {0x04,0x0F,0x14,0x0E,0x05,0x1E,0x04}, // $
        {0x18,0x19,0x02,0x04,0x08,0x13,0x03}, // %
        {0x08,0x14,0x14,0x08,0x15,0x12,0x0D}, // &
        {0x04,0x04,0x00,0x00,0x00,0x00,0x00}, // '
        {0x02,0x04,0x08,0x08,0x08,0x04,0x02}, // (
        {0x08,0x04,0x02,0x02,0x02,0x04,0x08}, // )
        {0x00,0x04,0x15,0x0E,0x15,0x04,0x00}, // *
        {0x00,0x04,0x04,0x1F,0x04,0x04,0x00}, // +
        {0x00,0x00,0x00,0x00,0x00,0x04,0x08}, // ,
        {0x00,0x00,0x00,0x1F,0x00,0x00,0x00}, // -
        {0x00,0x00,0x00,0x00,0x00,0x00,0x04}, // .
        {0x01,0x01,0x02,0x04,0x08,0x10,0x10}, // /
        {0x0E,0x11,0x13,0x15,0x19,0x11,0x0E}, // 0
        {0x04,0x0C,0x04,0x04,0x04,0x04,0x0E}, // 1
        {0x0E,0x11,0x01,0x02,0x04,0x08,0x1F}, // 2
        {0x0E,0x11,0x01,0x06,0x01,0x11,0x0E}, // 3
        {0x02,0x06,0x0A,0x12,0x1F,0x02,0x02}, // 4
        {0x1F,0x10,0x1E,0x01,0x01,0x11,0x0E}, // 5
        {0x06,0x08,0x10,0x1E,0x11,0x11,0x0E}, // 6
        {0x1F,0x01,0x02,0x04,0x08,0x08,0x08}, // 7
        {0x0E,0x11,0x11,0x0E,0x11,0x11,0x0E}, // 8
        {0x0E,0x11,0x11,0x0F,0x01,0x02,0x0C}, // 9
        {0x00,0x00,0x04,0x00,0x00,0x04,0x00}, // :
        {0x00,0x00,0x04,0x00,0x00,0x04,0x08}, // ;
        {0x02,0x04,0x08,0x10,0x08,0x04,0x02}, // <
        {0x00,0x00,0x1F,0x00,0x1F,0x00,0x00}, // =
        {0x08,0x04,0x02,0x01,0x02,0x04,0x08}, // >
        {0x0E,0x11,0x01,0x02,0x04,0x00,0x04}, // ?
        {0x0E,0x11,0x17,0x15,0x17,0x10,0x0E}, // @
        {0x0E,0x11,0x11,0x1F,0x11,0x11,0x11}, // A
        {0x1E,0x11,0x11,0x1E,0x11,0x11,0x1E}, // B
        {0x0E,0x11,0x10,0x10,0x10,0x11,0x0E}, // C
        {0x1E,0x11,0x11,0x11,0x11,0x11,0x1E}, // D
        {0x1F,0x10,0x10,0x1E,0x10,0x10,0x1F}, // E
        {0x1F,0x10,0x10,0x1E,0x10,0x10,0x10}, // F
        {0x0E,0x11,0x10,0x17,0x11,0x11,0x0E}, // G
        {0x11,0x11,0x11,0x1F,0x11,0x11,0x11}, // H
        {0x0E,0x04,0x04,0x04,0x04,0x04,0x0E}, // I
        {0x07,0x02,0x02,0x02,0x02,0x12,0x0C}, // J
        {0x11,0x12,0x14,0x18,0x14,0x12,0x11}, // K
        {0x10,0x10,0x10,0x10,0x10,0x10,0x1F}, // L
        {0x11,0x1B,0x15,0x15,0x11,0x11,0x11}, // M
        {0x11,0x19,0x15,0x13,0x11,0x11,0x11}, // N
        {0x0E,0x11,0x11,0x11,0x11,0x11,0x0E}, // O
        {0x1E,0x11,0x11,0x1E,0x10,0x10,0x10}, // P
        {0x0E,0x11,0x11,0x11,0x15,0x12,0x0D}, // Q
        {0x1E,0x11,0x11,0x1E,0x14,0x12,0x11}, // R
        {0x0E,0x11,0x10,0x0E,0x01,0x11,0x0E}, // S
        {0x1F,0x04,0x04,0x04,0x04,0x04,0x04}, // T
        {0x11,0x11,0x11,0x11,0x11,0x11,0x0E}, // U
        {0x11,0x11,0x11,0x11,0x0A,0x0A,0x04}, // V
        {0x11,0x11,0x11,0x15,0x15,0x1B,0x11}, // W
        {0x11,0x11,0x0A,0x04,0x0A,0x11,0x11}, // X
        {0x11,0x11,0x0A,0x04,0x04,0x04,0x04}, // Y
        {0x1F,0x01,0x02,0x04,0x08,0x10,0x1F}, // Z
        {0x0E,0x08,0x08,0x08,0x08,0x08,0x0E}, // [
        {0x10,0x10,0x08,0x04,0x02,0x01,0x01}, // backslash
        {0x0E,0x02,0x02,0x02,0x02,0x02,0x0E}, // ]
        {0x04,0x0A,0x11,0x00,0x00,0x00,0x00}, // ^
        {0x00,0x00,0x00,0x00,0x00,0x00,0x1F}, // _
        {0x08,0x04,0x00,0x00,0x00,0x00,0x00}, // `
        // lowercase a-z (simplified)
        {0x00,0x00,0x0E,0x01,0x0F,0x11,0x0F}, // a
        {0x10,0x10,0x1E,0x11,0x11,0x11,0x1E}, // b
        {0x00,0x00,0x0E,0x11,0x10,0x11,0x0E}, // c
        {0x01,0x01,0x0F,0x11,0x11,0x11,0x0F}, // d
        {0x00,0x00,0x0E,0x11,0x1F,0x10,0x0E}, // e
        {0x06,0x08,0x1C,0x08,0x08,0x08,0x08}, // f
        {0x00,0x00,0x0F,0x11,0x0F,0x01,0x0E}, // g
        {0x10,0x10,0x1E,0x11,0x11,0x11,0x11}, // h
        {0x04,0x00,0x0C,0x04,0x04,0x04,0x0E}, // i
        {0x02,0x00,0x06,0x02,0x02,0x12,0x0C}, // j
        {0x10,0x10,0x12,0x14,0x18,0x14,0x12}, // k
        {0x0C,0x04,0x04,0x04,0x04,0x04,0x0E}, // l
        {0x00,0x00,0x1A,0x15,0x15,0x11,0x11}, // m
        {0x00,0x00,0x1E,0x11,0x11,0x11,0x11}, // n
        {0x00,0x00,0x0E,0x11,0x11,0x11,0x0E}, // o
        {0x00,0x00,0x1E,0x11,0x1E,0x10,0x10}, // p
        {0x00,0x00,0x0F,0x11,0x0F,0x01,0x01}, // q
        {0x00,0x00,0x16,0x19,0x10,0x10,0x10}, // r
        {0x00,0x00,0x0F,0x10,0x0E,0x01,0x1E}, // s
        {0x08,0x08,0x1C,0x08,0x08,0x09,0x06}, // t
        {0x00,0x00,0x11,0x11,0x11,0x13,0x0D}, // u
        {0x00,0x00,0x11,0x11,0x11,0x0A,0x04}, // v
        {0x00,0x00,0x11,0x11,0x15,0x15,0x0A}, // w
        {0x00,0x00,0x11,0x0A,0x04,0x0A,0x11}, // x
        {0x00,0x00,0x11,0x11,0x0F,0x01,0x0E}, // y
        {0x00,0x00,0x1F,0x02,0x04,0x08,0x1F}, // z
        {0x02,0x04,0x04,0x08,0x04,0x04,0x02}, // {
        {0x04,0x04,0x04,0x04,0x04,0x04,0x04}, // |
        {0x08,0x04,0x04,0x02,0x04,0x04,0x08}, // }
        {0x00,0x00,0x08,0x15,0x02,0x00,0x00}, // ~
    };

    if (ch < 32 || ch > 126) return;
    int idx = ch - 32;
    int scale = std::max(1, static_cast<int>(size / 7.0f));

    for (int row = 0; row < 7; ++row) {
        uint8_t bits = font_data[idx][row];
        for (int col = 0; col < 5; ++col) {
            if (bits & (0x10 >> col)) {
                for (int sy = 0; sy < scale; ++sy)
                    for (int sx = 0; sx < scale; ++sx)
                        set_pixel(x + col * scale + sx,
                                  y + row * scale + sy, color);
            }
        }
    }
}

void draw_text_px(int x, int y, const char* text, pixel_t color, float size) {
    int scale = std::max(1, static_cast<int>(size / 7.0f));
    int char_w = 6 * scale;  // 5 pixels + 1 spacing, scaled
    int cx = x;
    for (const char* p = text; *p; ++p) {
        draw_char_px(cx, y, *p, color, size);
        cx += char_w;
    }
}

// ── render a single draw command ─────────────────────────────────────────

void render_cmd(const draw_cmd_t& cmd) {
    pixel_t px = to_pixel(cmd.color);
    switch (cmd.type) {
    case cmd_type_t::line:
        draw_line_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                     static_cast<int>(cmd.x2), static_cast<int>(cmd.y2),
                     px, cmd.thickness);
        break;
    case cmd_type_t::rect:
        draw_rect_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                     static_cast<int>(cmd.x2 - cmd.x1),
                     static_cast<int>(cmd.y2 - cmd.y1),
                     px, cmd.thickness);
        break;
    case cmd_type_t::filled_rect:
        draw_filled_rect_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                            static_cast<int>(cmd.x2 - cmd.x1),
                            static_cast<int>(cmd.y2 - cmd.y1), px);
        break;
    case cmd_type_t::circle:
        draw_circle_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                       static_cast<int>(cmd.radius), px, cmd.thickness);
        break;
    case cmd_type_t::filled_circle:
        draw_filled_circle_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                              static_cast<int>(cmd.radius), px);
        break;
    case cmd_type_t::text:
        draw_text_px(static_cast<int>(cmd.x1), static_cast<int>(cmd.y1),
                     cmd.text.c_str(), px, cmd.font_size);
        break;
    case cmd_type_t::cross:
        draw_line_px(static_cast<int>(cmd.x1 - cmd.radius),
                     static_cast<int>(cmd.y1),
                     static_cast<int>(cmd.x1 + cmd.radius),
                     static_cast<int>(cmd.y1), px, cmd.thickness);
        draw_line_px(static_cast<int>(cmd.x1),
                     static_cast<int>(cmd.y1 - cmd.radius),
                     static_cast<int>(cmd.x1),
                     static_cast<int>(cmd.y1 + cmd.radius), px, cmd.thickness);
        break;
    }
}

} // namespace

// ── public API ───────────────────────────────────────────────────────────

bool connect(uint32_t target_pid) {
    disconnect();

    std::string name = "DiscordOverlay_Framebuffer_Memory_" +
                       std::to_string(target_pid);
    HANDLE h = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, name.c_str());
    if (!h || h == INVALID_HANDLE_VALUE) {
        g_conn.error = "Discord overlay not active for PID " +
                       std::to_string(target_pid) +
                       " (enable in-game overlay in Discord settings)";
        return false;
    }

    auto* mapped = static_cast<discord_fb_header_t*>(
        MapViewOfFile(h, FILE_MAP_ALL_ACCESS, 0, 0, 0));
    if (!mapped) {
        CloseHandle(h);
        g_conn.error = "failed to map Discord framebuffer";
        return false;
    }

    g_conn.file_handle = h;
    g_conn.mapped = mapped;
    g_conn.pid = target_pid;
    g_conn.width = mapped->width ? mapped->width : 1920;
    g_conn.height = mapped->height ? mapped->height : 1080;
    g_conn.last_frame_count = mapped->frame_count;
    g_conn.error.clear();
    g_conn.local_fb.resize(g_conn.width * g_conn.height);
    g_conn.last_render_us = now_us();

    return true;
}

void disconnect() {
    if (g_conn.mapped) {
        // clear the framebuffer before disconnecting
        if (g_conn.width && g_conn.height) {
            const size_t fb_size = g_conn.width * g_conn.height * 4;
            std::memset(g_conn.mapped + 1, 0, fb_size);
            g_conn.mapped->frame_count++;
        }
        UnmapViewOfFile(g_conn.mapped);
        g_conn.mapped = nullptr;
    }
    if (g_conn.file_handle) {
        CloseHandle(g_conn.file_handle);
        g_conn.file_handle = nullptr;
    }
    g_conn.pid = 0;
    g_conn.width = 0;
    g_conn.height = 0;
    g_conn.local_fb.clear();
}

overlay_state_t state() {
    overlay_state_t s;
    s.connected = g_conn.mapped != nullptr;
    s.target_pid = g_conn.pid;
    s.width = g_conn.width;
    s.height = g_conn.height;
    s.frame_count = g_conn.render_count;
    s.fps = g_conn.fps;
    s.error = g_conn.error;
    return s;
}

void submit(std::vector<draw_cmd_t> commands) {
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds = std::move(commands);
}

void render() {
    if (!g_conn.mapped) return;

    // update dimensions from Discord's header (game may have resized)
    if (g_conn.mapped->width && g_conn.mapped->height &&
        (g_conn.mapped->width != g_conn.width ||
         g_conn.mapped->height != g_conn.height)) {
        g_conn.width = g_conn.mapped->width;
        g_conn.height = g_conn.mapped->height;
        g_conn.local_fb.resize(g_conn.width * g_conn.height);
    }

    // swap command buffers
    {
        std::lock_guard lk(g_cmd_mutex);
        g_active_cmds.swap(g_pending_cmds);
    }

    // clear local framebuffer (fully transparent)
    std::memset(g_conn.local_fb.data(), 0,
                g_conn.local_fb.size() * sizeof(pixel_t));

    // render all commands
    for (const auto& cmd : g_active_cmds) {
        render_cmd(cmd);
    }

    // copy to Discord's shared memory
    const size_t fb_size = g_conn.width * g_conn.height * 4;
    auto* dst = reinterpret_cast<uint8_t*>(g_conn.mapped) +
                sizeof(discord_fb_header_t);
    std::memcpy(dst, g_conn.local_fb.data(), fb_size);

    // signal Discord to pick up the new frame
    g_conn.mapped->width = g_conn.width;
    g_conn.mapped->height = g_conn.height;
    g_conn.mapped->frame_count++;
    g_conn.render_count++;

    // FPS calculation
    int64_t now = now_us();
    int64_t dt = now - g_conn.last_render_us;
    if (dt > 0) g_conn.fps = 1000000.0f / static_cast<float>(dt);
    g_conn.last_render_us = now;
}

void clear() {
    submit({});
    render();
}

// ── convenience helpers ──────────────────────────────────────────────────

void draw_line(float x1, float y1, float x2, float y2,
               color_t color, float thickness) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::line;
    cmd.x1 = x1; cmd.y1 = y1; cmd.x2 = x2; cmd.y2 = y2;
    cmd.color = color; cmd.thickness = thickness;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_rect(float x, float y, float w, float h,
               color_t color, float thickness) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::rect;
    cmd.x1 = x; cmd.y1 = y; cmd.x2 = x + w; cmd.y2 = y + h;
    cmd.color = color; cmd.thickness = thickness;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_filled_rect(float x, float y, float w, float h, color_t color) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::filled_rect;
    cmd.x1 = x; cmd.y1 = y; cmd.x2 = x + w; cmd.y2 = y + h;
    cmd.color = color;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_circle(float cx, float cy, float radius,
                 color_t color, float thickness) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::circle;
    cmd.x1 = cx; cmd.y1 = cy; cmd.radius = radius;
    cmd.color = color; cmd.thickness = thickness;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_text(float x, float y, const std::string& text,
               color_t color, float font_size) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::text;
    cmd.x1 = x; cmd.y1 = y;
    cmd.text = text; cmd.color = color; cmd.font_size = font_size;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_cross(float cx, float cy, float size,
                color_t color, float thickness) {
    draw_cmd_t cmd;
    cmd.type = cmd_type_t::cross;
    cmd.x1 = cx; cmd.y1 = cy; cmd.radius = size;
    cmd.color = color; cmd.thickness = thickness;
    std::lock_guard lk(g_cmd_mutex);
    g_pending_cmds.push_back(std::move(cmd));
}

void draw_esp_box(float x, float y, float w, float h,
                  const std::string& label, color_t color,
                  float thickness) {
    // box
    draw_rect(x, y, w, h, color, thickness);
    // label above the box
    if (!label.empty()) {
        draw_text(x, y - 12, label, color, 10.0f);
    }
}

void draw_health_bar(float x, float y, float w, float h,
                     float health_pct, color_t bg_color, color_t fg_color) {
    // background
    draw_filled_rect(x, y, w, h, bg_color);
    // foreground (filled portion)
    float fill_h = h * std::clamp(health_pct, 0.0f, 1.0f);
    float fill_y = y + h - fill_h;  // fill from bottom
    draw_filled_rect(x, fill_y, w, fill_h, fg_color);
}

void draw_rounded_rect(float x, float y, float w, float h,
                       float cr, color_t color, float thickness) {
    // draw 4 straight edges minus the corner radius, plus 4 quarter-circles
    int ix = static_cast<int>(x), iy = static_cast<int>(y);
    int iw = static_cast<int>(w), ih = static_cast<int>(h);
    int icr = static_cast<int>(cr);
    // top edge
    draw_line(x + cr, y, x + w - cr, y, color, thickness);
    // bottom edge
    draw_line(x + cr, y + h, x + w - cr, y + h, color, thickness);
    // left edge
    draw_line(x, y + cr, x, y + h - cr, color, thickness);
    // right edge
    draw_line(x + w, y + cr, x + w, y + h - cr, color, thickness);
    // corners (quarter circles)
    draw_circle(x + cr, y + cr, cr, color, thickness);
    draw_circle(x + w - cr, y + cr, cr, color, thickness);
    draw_circle(x + cr, y + h - cr, cr, color, thickness);
    draw_circle(x + w - cr, y + h - cr, cr, color, thickness);
}

void draw_gradient_rect(float x, float y, float w, float h,
                        color_t top, color_t bottom) {
    for (int py = 0; py < static_cast<int>(h); ++py) {
        float t = static_cast<float>(py) / h;
        color_t c;
        c.r = static_cast<uint8_t>(top.r + (bottom.r - top.r) * t);
        c.g = static_cast<uint8_t>(top.g + (bottom.g - top.g) * t);
        c.b = static_cast<uint8_t>(top.b + (bottom.b - top.b) * t);
        c.a = static_cast<uint8_t>(top.a + (bottom.a - top.a) * t);
        draw_line(x, y + py, x + w, y + py, c, 1.0f);
    }
}

void draw_triangle(float x1, float y1, float x2, float y2,
                   float x3, float y3, color_t color, float thickness) {
    draw_line(x1, y1, x2, y2, color, thickness);
    draw_line(x2, y2, x3, y3, color, thickness);
    draw_line(x3, y3, x1, y1, color, thickness);
}

void draw_corner_box(float x, float y, float w, float h,
                     float cl, color_t color, float thickness) {
    // top-left corner
    draw_line(x, y, x + cl, y, color, thickness);
    draw_line(x, y, x, y + cl, color, thickness);
    // top-right corner
    draw_line(x + w, y, x + w - cl, y, color, thickness);
    draw_line(x + w, y, x + w, y + cl, color, thickness);
    // bottom-left corner
    draw_line(x, y + h, x + cl, y + h, color, thickness);
    draw_line(x, y + h, x, y + h - cl, color, thickness);
    // bottom-right corner
    draw_line(x + w, y + h, x + w - cl, y + h, color, thickness);
    draw_line(x + w, y + h, x + w, y + h - cl, color, thickness);
}

void draw_distance(float x, float y, float dist_m,
                   color_t color, float font_size) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%.0fm", dist_m);
    draw_text(x, y, buf, color, font_size);
}

void draw_snapline(float target_x, float target_y,
                   float screen_w, float screen_h,
                   color_t color, float thickness) {
    draw_line(screen_w / 2.0f, screen_h, target_x, target_y,
              color, thickness);
}

} // namespace slop::core::overlay
