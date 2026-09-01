#pragma once

#include "imgui.h"

namespace slop::ui {

struct Tokens {
    float pad_xs = 4.0f;
    float pad_sm = 6.0f;
    float pad_md = 10.0f;
    float pad_lg = 16.0f;

    float radius_sm = 3.0f;
    float radius_md = 5.0f;
    float radius_lg = 8.0f;

    float type_body   = 15.0f;
    float type_small  = 13.0f;
    float type_header = 18.0f;
    float type_mono   = 14.0f;
};

struct Palette {
    ImVec4 bg_0;
    ImVec4 bg_1;
    ImVec4 bg_2;
    ImVec4 surface;
    ImVec4 border;
    ImVec4 border_soft;
    ImVec4 text;
    ImVec4 text_dim;
    ImVec4 text_faint;
    ImVec4 accent;
    ImVec4 accent_hover;
    ImVec4 accent_active;
    ImVec4 success;
    ImVec4 warning;
    ImVec4 danger;
    ImVec4 selection;
};

} // namespace slop::ui
