#pragma once

// crypto constant hunt over a pe, aes sboxes, sha and md5 constants,
// crc32, base64 alphabets and stream magics

#include <cstdint>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"

namespace slop::core::analysis {

struct signature_hit_t {
    std::string name;
    uint64_t    va = 0;        // image VA when inside a section, else 0
    size_t      offset = 0;    // file offset
    bool        in_overlay = false;
};

std::vector<signature_hit_t> crypto_hunt(const disasm::pe_image_t& pe,
                                         const std::vector<uint8_t>& file,
                                         size_t limit = 256);

} // namespace slop::core::analysis
