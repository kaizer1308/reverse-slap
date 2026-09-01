// src/core/analysis/danger.cpp

#include "core/analysis/danger.hpp"

#include <algorithm>
#include <cctype>

namespace slop::core::analysis {

namespace {

struct risk_entry_t {
    const char* name;
    const char* category;
};

constexpr risk_entry_t kRiskTable[] = {
    {"gets",               "unbounded-input"},
    {"strcpy",             "unbounded-copy"},
    {"strcat",             "unbounded-copy"},
    {"sprintf",            "format-string"},
    {"vsprintf",           "format-string"},
    {"swprintf",           "format-string"},
    {"scanf",              "format-string"},
    {"sscanf",             "format-string"},
    {"system",             "execution"},
    {"WinExec",            "execution"},
    {"CreateProcessA",     "execution"},
    {"CreateProcessW",     "execution"},
    {"ShellExecuteA",      "execution"},
    {"ShellExecuteW",      "execution"},
    {"LoadLibraryA",       "library-load"},
    {"LoadLibraryW",       "library-load"},
    {"LoadLibraryExA",     "library-load"},
    {"LoadLibraryExW",     "library-load"},
    {"GetProcAddress",     "library-load"},
    {"SetWindowsHookExA",  "hooking"},
    {"SetWindowsHookExW",  "hooking"},
    {"VirtualAllocEx",     "injection"},
    {"VirtualAllocExNuma", "injection"},
    {"WriteProcessMemory", "injection"},
    {"CreateRemoteThread", "injection"},
    {"CreateRemoteThreadEx", "injection"},
};

const char* risk_for(const std::string& name) {
    for (const auto& r : kRiskTable)
        if (_stricmp(r.name, name.c_str()) == 0) return r.category;
    return nullptr;
}

} // namespace

std::vector<danger_hit_t> danger_scan(const disasm::pe_image_t& pe,
                                      const xref_resolver_t& refs_to,
                                      uint64_t base) {
    std::vector<danger_hit_t> out;
    // Session base (defaults to the PE's preferred base): the IAT slot VAs
    // must land in the session's address space or the xref lookups miss
    const uint64_t va_base = base ? base : pe.image_base;

    for (const auto& dll : pe.imports) {
        for (const auto& fn : dll.functions) {
            if (fn.by_ordinal || fn.iat_rva == 0) continue;
            const char* category = risk_for(fn.name);
            if (!category) continue;

            danger_hit_t hit;
            hit.function = fn.name;
            hit.category = category;
            hit.iat_va   = va_base + fn.iat_rva;
            if (refs_to)
                hit.callsites = refs_to(hit.iat_va);
            out.push_back(std::move(hit));
        }
    }

    std::sort(out.begin(), out.end(),
              [](const danger_hit_t& a, const danger_hit_t& b) {
                  if (a.category != b.category) return a.category < b.category;
                  return a.function < b.function;
              });
    return out;
}

} // namespace slop::core::analysis
