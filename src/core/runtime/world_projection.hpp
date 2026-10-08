// src/core/runtime/world_projection.hpp
// World-to-screen projection for game overlays: row-major (DirectX/Source/UE)
// and column-major (Unity/OpenGL) matrix layouts. UE4/UE5 camera readers
// and Unity transform hierarchy walker.
#pragma once

#include "core/runtime/game_tools.hpp"
#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::runtime::projection {

using game_tools::reader_t;

// ── world-to-screen math ─────────────────────────────────────────────────

struct vec2_t { float x = 0, y = 0; };
struct vec3_t { float x = 0, y = 0, z = 0; };

struct screen_point_t {
    float x = 0, y = 0;
    bool  visible = false;
};

// project a 3D world position to 2D screen coordinates using a
// row-major view-projection matrix (DirectX, Source, UE4)
screen_point_t world_to_screen_rowmajor(
    vec3_t world_pos, const float matrix[16],
    float screen_w, float screen_h);

// same but for column-major / transposed matrices (Unity, OpenGL)
screen_point_t world_to_screen_transposed(
    vec3_t world_pos, const float matrix[16],
    float screen_w, float screen_h);

// ── UE4/UE5 helpers ──────────────────────────────────────────────────────

struct ue_view_info_t {
    vec3_t location;
    vec3_t rotation;     // pitch, yaw, roll in degrees
    float  fov = 90.0f;
};

// read FMinimalViewInfo from UE4/UE5 memory (float32 version)
ue_view_info_t read_ue_view_info(const reader_t& r, std::uint64_t addr);

// read FMinimalViewInfo with double-precision location (UE5 large worlds)
ue_view_info_t read_ue_view_info_f64(const reader_t& r, std::uint64_t addr);

// project using UE camera data (builds the VP matrix internally)
screen_point_t ue_world_to_screen(
    vec3_t world_pos, const ue_view_info_t& view,
    float screen_w, float screen_h);

// read a TArray<T*> — returns a vector of pointers
std::vector<std::uint64_t> read_tarray(
    const reader_t& r, std::uint64_t tarray_addr,
    std::size_t max_count = 4096);

// read a FName/FString from UE memory
std::string read_ue_fname(const reader_t& r, std::uint64_t gnames_base,
                           int32_t name_index);

// ── Unity helpers ────────────────────────────────────────────────────────

// walk a Unity transform hierarchy to get world-space position
vec3_t unity_get_transform_position(const reader_t& r,
                                     std::uint64_t transform_addr);

} // namespace slop::core::runtime::projection
