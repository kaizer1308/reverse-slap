// src/core/overlay/discord_overlay.hpp
// Discord overlay hijack: renders ESP, text, lines, boxes, and circles
// through Discord's in-game overlay framebuffer shared memory.
//
// How it works:
//   Discord's DiscordHook64.dll (already injected into the game by Discord
//   itself via WH_DEBUG hook) reads a BGRA framebuffer from a memory-mapped
//   file named "DiscordOverlay_Framebuffer_Memory_<PID>". It composites this
//   framebuffer onto the game's Present call at the game's native framerate.
//
//   We open the same shared memory section from our external process and
//   write our overlay content into it. No injection into the game process,
//   no new hooks, no new windows, no new D3D devices in the target.
//
// Performance:
//   - Render locally into a CPU buffer, memcpy to shared memory
//   - No FPS limit — we write at our own rate, Discord reads at game FPS
//   - Frame latency is 1 Present call (typically <16ms at 60fps)
//   - The bottleneck is the memcpy, which is <1ms for 1080p BGRA
//
// Detection surface:
//   - We open a named shared memory section (externally visible)
//   - But this is Discord's own section name — AC would flag Discord itself
//   - No DLL injection, no hooks, no handles to the game process
//   - Our process doesn't even need to know the game's HWND
#pragma once

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <vector>

namespace slop::core::overlay {

// ── draw command types ───────────────────────────────────────────────────

struct color_t {
    uint8_t r = 255, g = 255, b = 255, a = 255;
};

enum class cmd_type_t : uint8_t {
    line, rect, filled_rect, circle, filled_circle, text, cross,
    rounded_rect, gradient_rect, triangle, polyline, corner_box
};

struct draw_cmd_t {
    cmd_type_t type;
    float x1, y1, x2, y2;     // rect: top-left / bottom-right; line: endpoints
    float radius;               // circle
    float thickness;            // line/rect thickness
    color_t color;
    std::string text;           // for text commands
    float font_size;            // text size
};

// ── overlay state ────────────────────────────────────────────────────────

struct overlay_state_t {
    bool     connected = false;
    uint32_t target_pid = 0;
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t frame_count = 0;
    float    fps = 0.0f;
    std::string error;
};

// ── overlay API ──────────────────────────────────────────────────────────

// connect to Discord's overlay framebuffer for a target process.
// requires Discord overlay to be enabled and DiscordHook64.dll loaded
// in the target. returns false if the shared memory doesn't exist.
bool connect(uint32_t target_pid);

// disconnect and release the shared memory mapping
void disconnect();

// get current state
overlay_state_t state();

// submit draw commands for the next frame. thread-safe.
// commands are consumed on the next render() call.
void submit(std::vector<draw_cmd_t> commands);

// render the submitted commands into the shared memory framebuffer.
// call this from a dedicated thread or timer at your desired rate.
// discord picks up the result at the game's native framerate.
void render();

// convenience: clear the overlay (write transparent frame)
void clear();

// ── high-level draw helpers ──────────────────────────────────────────────
// these build draw_cmd_t and submit them

void draw_line(float x1, float y1, float x2, float y2,
               color_t color, float thickness = 1.0f);

void draw_rect(float x, float y, float w, float h,
               color_t color, float thickness = 1.0f);

void draw_filled_rect(float x, float y, float w, float h,
                      color_t color);

void draw_circle(float cx, float cy, float radius,
                 color_t color, float thickness = 1.0f);

void draw_text(float x, float y, const std::string& text,
               color_t color, float font_size = 14.0f);

void draw_cross(float cx, float cy, float size,
                color_t color, float thickness = 1.0f);

// ESP box with label (the most common game overlay element)
void draw_esp_box(float x, float y, float w, float h,
                  const std::string& label, color_t color,
                  float thickness = 1.0f);

// health bar (filled rect with percentage)
void draw_health_bar(float x, float y, float w, float h,
                     float health_pct, // 0.0 to 1.0
                     color_t bg_color, color_t fg_color);

// rounded rectangle (corner radius)
void draw_rounded_rect(float x, float y, float w, float h,
                       float corner_radius, color_t color,
                       float thickness = 1.0f);

// gradient rectangle (top_color → bottom_color)
void draw_gradient_rect(float x, float y, float w, float h,
                        color_t top_color, color_t bottom_color);

// triangle (three vertices)
void draw_triangle(float x1, float y1, float x2, float y2,
                   float x3, float y3, color_t color,
                   float thickness = 1.0f);

// corner box (CS-style box with only corner lines, not full edges)
void draw_corner_box(float x, float y, float w, float h,
                     float corner_len, color_t color,
                     float thickness = 1.0f);

// distance marker (text with distance value at position)
void draw_distance(float x, float y, float distance_m,
                   color_t color, float font_size = 10.0f);

// snapline (line from bottom-center of screen to a point)
void draw_snapline(float target_x, float target_y,
                   float screen_w, float screen_h,
                   color_t color, float thickness = 1.0f);

} // namespace slop::core::overlay
