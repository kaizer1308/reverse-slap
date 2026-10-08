// src/core/runtime/world_projection.cpp
#include "core/runtime/world_projection.hpp"
#include <cmath>
#include <cstring>

namespace slop::core::runtime::projection {

static constexpr float kPi = 3.14159265358979323846f;
static constexpr float kDegToRad = kPi / 180.0f;

// ── row-major W2S (DirectX/Source/UE) ────────────────────────────────────

screen_point_t world_to_screen_rowmajor(
    vec3_t w, const float m[16], float sw, float sh)
{
    // clip-space: [x,y,z,1] * M  (row-major: vector on the left)
    float cx = w.x * m[0] + w.y * m[4] + w.z * m[8]  + m[12];
    float cy = w.x * m[1] + w.y * m[5] + w.z * m[9]  + m[13];
    float cw = w.x * m[3] + w.y * m[7] + w.z * m[11] + m[15];

    if (cw < 0.001f) return { 0, 0, false };

    float ndcx = cx / cw;
    float ndcy = cy / cw;

    screen_point_t out;
    out.x = (sw * 0.5f) + ndcx * (sw * 0.5f);
    out.y = (sh * 0.5f) - ndcy * (sh * 0.5f);
    out.visible = true;
    return out;
}

// ── column-major W2S (Unity/OpenGL) ──────────────────────────────────────

screen_point_t world_to_screen_transposed(
    vec3_t w, const float m[16], float sw, float sh)
{
    // clip-space: M * [x,y,z,1]  (column-major: vector on the right)
    float cx = m[0]*w.x + m[1]*w.y + m[2]*w.z  + m[3];
    float cy = m[4]*w.x + m[5]*w.y + m[6]*w.z  + m[7];
    float cw = m[12]*w.x + m[13]*w.y + m[14]*w.z + m[15];

    if (cw < 0.001f) return { 0, 0, false };

    float ndcx = cx / cw;
    float ndcy = cy / cw;

    screen_point_t out;
    out.x = (sw * 0.5f) + ndcx * (sw * 0.5f);
    out.y = (sh * 0.5f) - ndcy * (sh * 0.5f);
    out.visible = true;
    return out;
}

// ── UE view info readers ─────────────────────────────────────────────────

ue_view_info_t read_ue_view_info(const reader_t& r, std::uint64_t addr) {
    ue_view_info_t v;
    // FMinimalViewInfo layout (UE4/5 float32):
    //   +0x00: FVector Location (3 floats)
    //   +0x0C: FRotator Rotation (pitch, yaw, roll — 3 floats)
    //   +0x18: float FOV
    float data[7] = {};
    r.read(addr, data, sizeof(data));
    v.location = { data[0], data[1], data[2] };
    v.rotation = { data[3], data[4], data[5] };
    v.fov = data[6];
    return v;
}

ue_view_info_t read_ue_view_info_f64(const reader_t& r, std::uint64_t addr) {
    ue_view_info_t v;
    // UE5 large world: FVector uses double
    //   +0x00: FVector Location (3 doubles = 24 bytes)
    //   +0x18: FRotator Rotation (3 floats = 12 bytes)  
    //   +0x24: float FOV
    double loc[3] = {};
    float rot_fov[4] = {};
    r.read(addr, loc, 24);
    r.read(addr + 24, rot_fov, 16);
    v.location = { static_cast<float>(loc[0]),
                   static_cast<float>(loc[1]),
                   static_cast<float>(loc[2]) };
    v.rotation = { rot_fov[0], rot_fov[1], rot_fov[2] };
    v.fov = rot_fov[3];
    return v;
}

// ── UE world-to-screen (builds VP matrix from camera data) ───────────────

screen_point_t ue_world_to_screen(
    vec3_t world, const ue_view_info_t& view,
    float sw, float sh)
{
    // translate world pos relative to camera
    float dx = world.x - view.location.x;
    float dy = world.y - view.location.y;
    float dz = world.z - view.location.z;

    // rotation angles
    float pitch = view.rotation.x * kDegToRad;
    float yaw   = view.rotation.y * kDegToRad;
    float roll  = view.rotation.z * kDegToRad;

    float cp = std::cos(pitch), sp = std::sin(pitch);
    float cy = std::cos(yaw),   sy = std::sin(yaw);
    float cr = std::cos(roll),  sr = std::sin(roll);

    // UE rotation matrix (Tait-Bryan ZYX)
    // forward = (cy*cp, sy*cp, sp)
    // right   = (cy*sp*sr - sy*cr, sy*sp*sr + cy*cr, -cp*sr)
    // up      = (-cy*sp*cr - sy*sr, -sy*sp*cr + cy*sr, cp*cr)

    float fx = cy*cp, fy = sy*cp, fz = sp;
    float rx = cy*sp*sr - sy*cr, ry = sy*sp*sr + cy*cr, rz = -cp*sr;
    float ux = -(cy*sp*cr + sy*sr), uy = -(sy*sp*cr - cy*sr), uz = cp*cr;

    // camera-space coordinates
    float cz_val = dx*fx + dy*fy + dz*fz;   // depth
    if (cz_val < 0.01f) return { 0, 0, false };  // behind camera

    float cx_val = dx*rx + dy*ry + dz*rz;   // horizontal
    float cy_val = dx*ux + dy*uy + dz*uz;   // vertical

    // perspective projection
    float fov_rad = view.fov * kDegToRad;
    float tan_half_fov = std::tan(fov_rad * 0.5f);
    float aspect = sw / sh;

    screen_point_t out;
    out.x = sw * 0.5f + (cx_val / (cz_val * tan_half_fov * aspect)) * sw * 0.5f;
    out.y = sh * 0.5f - (cy_val / (cz_val * tan_half_fov)) * sh * 0.5f;
    out.visible = (out.x >= 0 && out.x <= sw && out.y >= 0 && out.y <= sh);
    return out;
}

// ── TArray reader ────────────────────────────────────────────────────────

std::vector<std::uint64_t> read_tarray(
    const reader_t& r, std::uint64_t addr, std::size_t max_count)
{
    std::vector<std::uint64_t> result;
    // TArray layout: Data (ptr), Count (int32), Max (int32)
    struct { std::uint64_t data; int32_t count; int32_t max; } ta{};
    if (!r.read(addr, &ta, sizeof(ta))) return result;
    if (ta.count <= 0 || ta.count > static_cast<int32_t>(max_count)) return result;
    if (!ta.data) return result;

    result.resize(ta.count);
    r.read(ta.data, result.data(), ta.count * sizeof(std::uint64_t));
    return result;
}

// ── FName reader (simplified) ────────────────────────────────────────────

std::string read_ue_fname(const reader_t& r, std::uint64_t gnames,
                           int32_t index) {
    if (!gnames || index < 0) return {};
    // GNames is a TNameEntryArray = chunked array
    // chunk_index = index / 16384, within_chunk = index % 16384
    const int32_t chunk = index / 16384;
    const int32_t within = index % 16384;

    std::uint64_t chunk_ptr = 0;
    r.read(gnames + chunk * 8, &chunk_ptr, 8);
    if (!chunk_ptr) return {};

    std::uint64_t entry_ptr = 0;
    r.read(chunk_ptr + within * 8, &entry_ptr, 8);
    if (!entry_ptr) return {};

    // FNameEntry: +0x00 header (2 bytes), +0x02 name chars
    // header low 10 bits = length
    uint16_t header = 0;
    r.read(entry_ptr, &header, 2);
    int len = header >> 6;  // UE4 style
    if (len <= 0 || len > 256) {
        len = header & 0x3FF;  // UE5 style
    }
    if (len <= 0 || len > 256) return {};

    std::string name(len, '\0');
    r.read(entry_ptr + 2, name.data(), len);
    return name;
}

// ── Unity transform walker ───────────────────────────────────────────────

vec3_t unity_get_transform_position(const reader_t& r,
                                     std::uint64_t transform) {
    vec3_t result{};
    if (!transform) return result;

    // Unity Transform hierarchy: walk parent chain, accumulate localPosition
    // Transform layout (Il2Cpp):
    //   +0x10: parent (Transform*)
    //   +0x30 or +0x38: localPosition (Vector3 = 3 floats) — varies by Unity version
    //   +0x3C or +0x44: localRotation (Quaternion)
    //   +0x4C or +0x54: localScale (Vector3)
    // For world position: follow the internal hierarchy pointer

    // simplified: read the access object that stores world position
    // at +0x38: TransformAccess* (points to TransformHierarchy)
    std::uint64_t access = 0;
    r.read(transform + 0x38, &access, 8);
    if (!access) {
        // fallback: try to read localPosition directly at +0x30
        r.read(transform + 0x30, &result, 12);
        return result;
    }

    // TransformAccess stores the index into the hierarchy
    int32_t index = 0;
    r.read(access + 0x40, &index, 4);

    std::uint64_t hierarchy = 0;
    r.read(access + 0x18, &hierarchy, 8);
    if (!hierarchy) return result;

    // the world positions array is at hierarchy + 0x30
    std::uint64_t positions_array = 0;
    r.read(hierarchy + 0x30, &positions_array, 8);
    if (!positions_array) return result;

    // each position is 16 bytes (vec3 + padding float)
    struct { float x, y, z, w; } pos{};
    r.read(positions_array + index * 16, &pos, 16);
    result = { pos.x, pos.y, pos.z };
    return result;
}

} // namespace slop::core::runtime::projection
