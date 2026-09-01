#pragma once

// shell icon extraction for process rows, raw bgra so the web ui can
// canvas it without an encoder in core

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::process {

struct icon_bits_t {
    uint32_t             width  = 0;
    uint32_t             height = 0;
    std::vector<uint8_t> bgra;    // width * height * 4, top-down, premultiplied

    bool empty() const noexcept { return bgra.empty(); }
};

// large picks the 32x32 icon, downscaled 32 beats upscaled 16 on hidpi,
// empty result means draw a generic glyph
icon_bits_t icon_for_path(const std::string& image_path, bool large = true);

} // namespace slop::core::process
