#pragma once

// msvc x64 rtti reconstruction, type descriptors by name, locators by self
// offsets, vftables by their minus one slot

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "core/disasm/pe_parser.hpp"

namespace slop::core::re {

struct rtti_class_t {
    std::string             name;        // demangled-ish: "MyClass" from ".?AVMyClass@@"
    uint64_t                td_va = 0;   // TypeDescriptor VA
    std::vector<uint64_t>   col_vas;     // Complete Object Locator VAs
    std::vector<uint64_t>   vftables;    // vftable VAs (slot pointing at a COL)
};

struct rtti_result_t {
    std::vector<rtti_class_t> classes;
    size_t scanned_bytes = 0;
};

rtti_result_t rtti_scan(const disasm::pe_image_t& pe,
                        const std::vector<uint8_t>& file);

// Read up to `max_slots` function pointers starting at `vftable_va`
std::optional<std::vector<uint64_t>> read_vftable(
    const disasm::pe_image_t& pe,
    const std::vector<uint8_t>& file,
    uint64_t vftable_va, size_t max_slots = 32);

} // namespace slop::core::re
