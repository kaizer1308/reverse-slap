// src/core/runtime/injector.hpp
// single stealth mode: the ghost image is placed inside the target's own
// private vad and page table chain via covered placement only. no fresh
// mode, no vad insertion, no table forging, no kpti handling - the existing
// chain provides everything. backing page pfns are forged to point at the
// ghost ptes, source mappings orphaned, driver dkom/scrubbed/mutated/renamed.
// the trigger is a pte-level cow swap with a self-restoring stub. no mm
// call ever happens in the target, and zero kernel allocations are made.

#pragma once

#include "core/runtime/backend.hpp"

#include <string>

namespace slop::core::runtime::inject {

struct config_t {
    const wchar_t* hook_module = nullptr;   // target module holding the trigger function
    const char*   hook_export  = nullptr;   // export name to hook (used first)
    uintptr_t     hook_rva     = 0;         // fallback rva when hook_export is null
    bool          erase_header = true;      // zero the mapped pe header after mapping
};

struct result_t {
    bool        ok = false;
    std::uint64_t image_base = 0;
    std::uint64_t hook_address = 0;
    std::uint64_t stub_address = 0;
    // single stealth mode: covered placement inside the target's own vad
    // and pt chain. every enhancement (pfn forge, orphan, dkom, scrub,
    // mutate, rename) always attempts silently; failures degrade coverage
    // without affecting injection success or visibility
    bool        driver_hidden = false;   // all driver stealth layers landed
    std::string error;
};

result_t inject_dll(backend_t& be, const target_handle_t& h,
                    const wchar_t* dll_path, const config_t& cfg);

// resolve an export of a module in the target over the attach read path
std::uint64_t resolve_export(backend_t& be, const target_handle_t& h,
                             std::uint64_t module_base, const char* name,
                             std::uint16_t ordinal = 0, bool by_ordinal = false);

} // namespace slop::core::runtime::inject
