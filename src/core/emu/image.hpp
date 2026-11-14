#pragma once

// a PE file as the loader would map it, for the emulator: section bytes
// with base relocations applied, the IAT slots to stub, the TLS template.
// Shared by the emulate tool and the analysis passes that emulate; nothing
// here touches unicorn

#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"
#include "core/emu/session.hpp"

namespace slop::core::emu {

// The parsed image and its file bytes. Views do not own them, so a caller
// whose image can be replaced while a run is going passes them on every call
struct image_bytes_t {
    const disasm::pe_image_t* pe   = nullptr;
    const uint8_t*            file = nullptr;
    size_t                    size = 0;
    bool                      is_pe = true;   // false: a synthesized section map (Mach-O)
};

// Headers, section bytes up to VirtualSize, zero for BSS tails and gaps, and
// base relocations applied when the session base differs from ImageBase
// (every ASLR-loaded module), so absolute pointers in tables and code land
// in the rebased image
struct image_view_t {
    struct reloc_t { uint32_t rva = 0; uint8_t width = 0; };   // width 4 | 8

    uint64_t extent = 0;            // SizeOfImage, or the section span
    uint64_t delta  = 0;            // session base - ImageBase, mod 2^64
    std::vector<reloc_t> relocs;    // sorted by rva, empty when not rebased

    static std::shared_ptr<const image_view_t> make(const image_bytes_t& img, uint64_t base);

    // Raw mapped bytes for [rva, rva + len), no relocation
    static void copy_mapped(const image_bytes_t& img, uint64_t rva, size_t len, uint8_t* out);

    // Relocated mapped bytes for [rva, rva + len)
    void read(const image_bytes_t& img, uint64_t rva, size_t len, uint8_t* out) const;
};

// Demand pages over an image that stays put for the whole run
page_source_t image_page_source(std::shared_ptr<const image_view_t> view,
                                image_bytes_t img, uint64_t base);

// IAT slots of a PE32+ image, for the emulator's import stubs. returns maps
// lowercase "func" or "dll!func" to a per-import return value; matched keys
// are removed so the caller can report the rest. nullptr: no overrides
std::vector<import_slot_t> image_import_slots(
    const disasm::pe_image_t& pe, uint64_t base,
    std::map<std::string, uint64_t>* returns = nullptr);

// The TLS directory's template and the index the image reads its block
// through. Leaves req untouched when the image has no usable TLS directory
void image_tls(const image_view_t& view, const image_bytes_t& img, uint64_t base,
               run_request_t* req);

// A driver: native subsystem and not linked against ntdll, which every
// native user-mode program is
bool image_is_kernel(const disasm::pe_image_t& pe);

// Everything above for an image that outlives the run: image_base and demand
// paging, plus import stubs, TLS and the ring for a PE. False for anything
// but x64 code, which is all the emulator runs
bool attach_image(run_request_t* req, const image_bytes_t& img, uint64_t base);

// "MZ" at the start, for callers that only hold the bytes
bool is_pe_file(const uint8_t* file, size_t size);

} // namespace slop::core::emu
