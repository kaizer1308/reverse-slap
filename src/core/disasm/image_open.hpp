#pragma once

// src/core/disasm/image_open.hpp
// turns file bytes into something the disasm stack can analyze: a PE as is,
// or the main Mach-O of an .ipa / a thin or FAT Mach-O reduced to one thin
// slice plus a synthesized pe_image_t section map so offset, section and
// string consumers work unchanged. detection is by content, never extension

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/ipa.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/types.h"

namespace slop::core::disasm {

enum class image_format_t : uint8_t { pe, macho };
enum class image_arch_t   : uint8_t { x86, x64, arm, arm64 };

const char* image_format_name(image_format_t f) noexcept;   // "pe" | "macho"
const char* image_arch_name(image_arch_t a) noexcept;       // "x86" | "x64" | "arm" | "arm64"
hype::Arch  hype_arch(image_arch_t a) noexcept;

struct opened_image_t {
    bool                          ok = false;
    std::string                   error;
    image_format_t                format = image_format_t::pe;
    image_arch_t                  arch   = image_arch_t::x64;
    std::vector<uint8_t>          file;   // analyzed bytes: the PE, or the thin Mach-O slice
    pe_image_t                    pe;     // section/import/export map, synthesized for Mach-O
    bool                          encrypted = false;
    std::optional<ipa::bundle_t>  bundle; // set when opened from an .ipa

    bool is_x86() const noexcept {
        return arch == image_arch_t::x86 || arch == image_arch_t::x64;
    }
};

// PE, thin or FAT Mach-O, or .ipa. On failure ok is false and error says why
opened_image_t open_image(std::vector<uint8_t> raw);

} // namespace slop::core::disasm
