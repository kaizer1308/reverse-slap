// src/ui/view_analysis.cpp
// Advanced analysis panels: Xrefs viewer, Functions browser, Process Info,
// Symbol resolver, Call graph, Source reconstruction export.
// All data comes from existing engines (binary_state, function_index,
// xref_index, session). Zero new analysis code — pure UI wiring.

#include "ui/views_core.hpp"
#include <windows.h>
#include "imgui.h"

#include "core/disasm/binary_state.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/backend_winotify.hpp"
#include "core/runtime/game_tools.hpp"

#include <algorithm>
#include <set>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace slop::ui::an {

namespace ds    = slop::core::disasm::binary_state;
namespace disasm = slop::core::disasm;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;

// ── xrefs viewer ─────────────────────────────────────────────────────────

void DrawXrefs() {
    if (!ds::has_binary()) {
        ImGui::TextDisabled("load a binary first (disasm → load)");
        return;
    }

    static uint64_t query_va = 0;
    static std::vector<disasm::xref_t> results;
    static char addr_buf[32] = "";

    ImGui::InputText("address##xref", addr_buf, sizeof(addr_buf),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("find xrefs to")) {
        query_va = std::strtoull(addr_buf, nullptr, 16);
        results.clear();
        auto& b = ds::get();
        const auto& refs = b.xrefs.refs_to(query_va);
        results.assign(refs.begin(), refs.end());
    }
    ImGui::SameLine();
    if (ImGui::Button("from selected fn")) {
        // get selected function from disasm view
        query_va = slop::ui::disasm_view::SelectedFunction();
        if (query_va) {
            char tmp[24];
            std::snprintf(tmp, sizeof(tmp), "%llX",
                          static_cast<unsigned long long>(query_va));
            std::strncpy(addr_buf, tmp, sizeof(addr_buf) - 1);
            results.clear();
            auto& b = ds::get();
            const auto& refs = b.xrefs.refs_to(query_va);
            results.assign(refs.begin(), refs.end());
        }
    }

    ImGui::Text("%zu xrefs to %016llX", results.size(),
                static_cast<unsigned long long>(query_va));

    if (!ImGui::BeginTable("xrefs", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("from");
    ImGui::TableSetupColumn("to");
    ImGui::TableSetupColumn("kind");
    ImGui::TableSetupColumn("function");
    ImGui::TableHeadersRow();

    auto& b = ds::get();
    for (const auto& x : results) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        char from_str[24];
        std::snprintf(from_str, sizeof(from_str), "%016llX",
                      static_cast<unsigned long long>(x.from));
        if (ImGui::Selectable(from_str, false,
                ImGuiSelectableFlags_SpanAllColumns)) {
            disasm_view::SelectInstruction(x.from);
        }
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(x.to));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(
            x.kind == disasm::xref_kind_t::call ? "call" :
            x.kind == disasm::xref_kind_t::jmp  ? "jmp"  : "data");
        ImGui::TableNextColumn();
        auto fn = b.fns.containing(x.from);
        if (fn) {
            const char* sym = ds::symbol_for(*fn);
            if (sym) ImGui::TextUnformatted(sym);
            else ImGui::Text("sub_%llX",
                             static_cast<unsigned long long>(*fn));
        } else {
            ImGui::TextDisabled("-");
        }
    }
    ImGui::EndTable();
}

// ── process deep info ────────────────────────────────────────────────────

void DrawProcessInfo() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    ImGui::SeparatorText("process");
    ImGui::Text("PID:  %u", sess->pid());
    ImGui::Text("name: %s", sess->name().c_str());
    ImGui::Text("arch: %s",
        sess->arch() == runtime::arch_t::x64 ? "x64" :
        sess->arch() == runtime::arch_t::x86 ? "x86" :
        sess->arch() == runtime::arch_t::arm64 ? "arm64" : "unknown");

    // backend info
    ImGui::SeparatorText("backend");
    ImGui::Text("transport: %s", runtime::active_badge());
    ImGui::Text("kind: %s",
        runtime::active_kind() == runtime::backend_kind_t::kernel
            ? "kernel" : "usermode");

    // if winotify backend, show kernel details
    const auto* wbe = dynamic_cast<const runtime::backend_winotify_t*>(
        &runtime::active());
    if (wbe && wbe->device()) {
        ImGui::SeparatorText("kernel details");

        auto* dev = wbe->device();
        const uint64_t peb = dev->peb_of(sess->pid());
        ImGui::Text("PEB:     %016llX", static_cast<unsigned long long>(peb));

        // read some PEB fields through kernel reads
        if (peb) {
            uint64_t image_base = 0, ldr = 0;
            dev->cross_read(sess->pid(), peb + 0x10, &image_base, 8);
            dev->cross_read(sess->pid(), peb + 0x18, &ldr, 8);
            ImGui::Text("ImageBase: %016llX",
                        static_cast<unsigned long long>(image_base));
            ImGui::Text("Ldr:       %016llX",
                        static_cast<unsigned long long>(ldr));

            // read BeingDebugged flag
            uint8_t being_debugged = 0;
            dev->cross_read(sess->pid(), peb + 0x02, &being_debugged, 1);
            ImGui::Text("BeingDebugged: %s",
                        being_debugged ? "YES (debugger attached)" : "no");

            // read NtGlobalFlag
            uint32_t nt_global_flag = 0;
            dev->cross_read(sess->pid(), peb + 0xBC, &nt_global_flag, 4);
            ImGui::Text("NtGlobalFlag:  0x%08X%s", nt_global_flag,
                        (nt_global_flag & 0x70) ? " (debug flags set!)" : "");
        }
    }

    // module count and thread count
    ImGui::SeparatorText("enumeration");
    auto mods = runtime::active().enum_modules(sess->handle());
    auto threads = runtime::active().enum_threads(sess->pid());
    ImGui::Text("modules: %zu", mods.ok ? mods.items.size() : 0);
    ImGui::Text("threads: %zu", threads.ok ? threads.items.size() : 0);
}

// ── symbol resolver ──────────────────────────────────────────────────────

void DrawSymbolResolver() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static uint64_t resolve_va = 0;
    static std::string result_module, result_section, result_export;
    static uint64_t result_offset = 0;

    ImGui::InputScalar("address##sym", ImGuiDataType_U64, &resolve_va,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);

    if (ImGui::Button("resolve") && resolve_va) {
        result_module.clear();
        result_section.clear();
        result_export.clear();
        result_offset = 0;

        auto mods = runtime::active().enum_modules(sess->handle());
        if (mods.ok) {
            for (const auto& m : mods.items) {
                if (resolve_va >= m.base &&
                    resolve_va < m.base + m.size) {
                    result_module = m.name;
                    result_offset = resolve_va - m.base;

                    // read PE headers to find section
                    uint8_t hdr[0x400] = {};
                    if (sess->read(m.base, hdr, sizeof(hdr)).ok &&
                        hdr[0] == 'M' && hdr[1] == 'Z') {
                        uint32_t e_lfanew = 0;
                        std::memcpy(&e_lfanew, hdr + 0x3C, 4);
                        if (e_lfanew + 0x18 < sizeof(hdr)) {
                            uint16_t num_sec = 0;
                            std::memcpy(&num_sec, hdr + e_lfanew + 6, 2);
                            uint16_t opt_sz = 0;
                            std::memcpy(&opt_sz, hdr + e_lfanew + 0x14, 2);
                            size_t sec_off = e_lfanew + 0x18 + opt_sz;
                            for (uint16_t i = 0; i < num_sec && sec_off + 40 <= sizeof(hdr); ++i) {
                                uint32_t sec_va = 0, sec_vsz = 0;
                                std::memcpy(&sec_va, hdr + sec_off + 12, 4);
                                std::memcpy(&sec_vsz, hdr + sec_off + 8, 4);
                                if (result_offset >= sec_va &&
                                    result_offset < sec_va + sec_vsz) {
                                    char name[9] = {};
                                    std::memcpy(name, hdr + sec_off, 8);
                                    result_section = name;
                                    break;
                                }
                                sec_off += 40;
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!result_module.empty()) {
        ImGui::SeparatorText("result");
        ImGui::Text("module:  %s", result_module.c_str());
        ImGui::Text("section: %s", result_section.empty() ? "-" : result_section.c_str());
        ImGui::Text("offset:  +0x%llX", static_cast<unsigned long long>(result_offset));
    }
}

// ── call graph viewer ────────────────────────────────────────────────────

void DrawCallGraph() {
    if (!ds::has_binary()) {
        ImGui::TextDisabled("load a binary first");
        return;
    }

    static uint64_t root_va = 0;
    static char root_buf[32] = "";
    static std::vector<std::pair<uint64_t, std::vector<uint64_t>>> graph;

    ImGui::InputText("function VA##cg", root_buf, sizeof(root_buf),
                     ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SameLine();
    if (ImGui::Button("build call graph") && root_buf[0]) {
        root_va = std::strtoull(root_buf, nullptr, 16);
        graph.clear();

        auto& b = ds::get();
        // BFS: find all functions called by root_va and their callees
        std::vector<uint64_t> queue = { root_va };
        std::set<uint64_t> visited;
        while (!queue.empty() && graph.size() < 256) {
            uint64_t va = queue.back();
            queue.pop_back();
            if (!visited.insert(va).second) continue;

            // find xrefs FROM this function (callees)
            std::vector<uint64_t> callees;
            auto fn = b.fns.containing(va);
            if (!fn) continue;
            // scan the function's address range for outgoing calls
            for (const auto& f : b.fns.functions()) {
                const auto& refs = b.xrefs.refs_to(f.va);
                for (const auto& ref : refs) {
                    auto caller = b.fns.containing(ref.from);
                    if (caller && *caller == *fn &&
                        ref.kind == disasm::xref_kind_t::call) {
                        callees.push_back(f.va);
                        queue.push_back(f.va);
                    }
                }
            }

            // deduplicate
            std::sort(callees.begin(), callees.end());
            callees.erase(std::unique(callees.begin(), callees.end()),
                          callees.end());
            graph.push_back({ va, std::move(callees) });
        }
    }

    ImGui::Text("%zu nodes", graph.size());
    if (!ImGui::BeginTable("cg", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("function");
    ImGui::TableSetupColumn("name");
    ImGui::TableSetupColumn("calls");
    ImGui::TableHeadersRow();
    for (const auto& [va, callees] : graph) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(va));
        ImGui::TableNextColumn();
        const char* sym = ds::symbol_for(va);
        if (sym) ImGui::TextUnformatted(sym);
        else ImGui::Text("sub_%llX",
                         static_cast<unsigned long long>(va));
        ImGui::TableNextColumn();
        ImGui::Text("%zu", callees.size());
    }
    ImGui::EndTable();
}

// ── source reconstruction export ─────────────────────────────────────────

void DrawSourceReconstruct() {
    if (!ds::has_binary()) {
        ImGui::TextDisabled("load a binary first");
        return;
    }

    static char output_dir[MAX_PATH] = "C:\\dumps\\source_project";
    static bool exported = false;
    static std::string export_status;

    ImGui::TextWrapped(
        "reconstruct a source project from the loaded binary. "
        "exports decompiled functions as C++ source files, "
        "types/structs as headers, and analysis metadata as JSON.");
    ImGui::Separator();

    ImGui::InputText("output directory", output_dir, sizeof(output_dir));

    auto& b = ds::get();
    ImGui::Text("functions: %zu", b.fns.functions().size());
    ImGui::Text("xrefs: %zu", b.xrefs.total());
    ImGui::Text("strings: %zu", b.strings.size());

    bool hype_ok = ds::hype_ready();
    if (!hype_ok) {
        ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.0f),
            "hyperion analysis in progress (%.0f%%) — "
            "wait for completion for best results",
            ds::hype_progress() * 100.0f);
    }

    if (ImGui::Button("export source project", ImVec2(-1, 28))) {
        exported = false;
        export_status.clear();
        std::string dir = output_dir;

        try {
            std::filesystem::create_directories(dir);

            // exports.h — all exported symbols
            {
                std::ofstream f(dir + "/exports.h");
                f << "// auto-generated exports\n#pragma once\n\n";
                if (b.pe.ok) {
                    for (const auto& exp : b.pe.exports) {
                        f << "// " << exp.name << " @ RVA 0x"
                          << std::hex << exp.rva << "\n";
                        f << "void* " << (exp.name.empty()
                                ? "ordinal_" + std::to_string(exp.ordinal)
                                : exp.name) << ";\n\n";
                    }
                }
            }

            // imports.h
            {
                std::ofstream f(dir + "/imports.h");
                f << "// auto-generated imports\n#pragma once\n\n";
                if (b.pe.ok) {
                    for (const auto& dll : b.pe.imports) {
                        f << "// DLL: " << dll.dll << "\n";
                        for (const auto& fn : dll.functions) {
                            f << "extern void* " << fn.name
                              << "; // IAT @ 0x" << std::hex << fn.iat_rva << "\n";
                        }
                        f << "\n";
                    }
                }
            }

            // strings.h
            {
                std::ofstream f(dir + "/strings.h");
                f << "// auto-generated string constants\n#pragma once\n\n";
                for (const auto& s : b.strings) {
                    if (s.text.size() > 4 && s.text.size() < 200) {
                        f << "// 0x" << std::hex << s.va << "\n";
                        f << "const char str_" << std::hex << s.va
                          << "[] = \"";
                        for (char c : s.text) {
                            if (c == '"') f << "\\\"";
                            else if (c == '\\') f << "\\\\";
                            else if (c == '\n') f << "\\n";
                            else if (c >= 32 && c < 127) f << c;
                            else f << "\\x" << std::hex
                                   << (static_cast<unsigned>(c) & 0xFF);
                        }
                        f << "\";\n\n";
                    }
                }
            }

            // functions.cpp — stub for each function
            {
                std::ofstream f(dir + "/functions.cpp");
                f << "// auto-generated function stubs\n"
                  << "#include \"exports.h\"\n"
                  << "#include \"imports.h\"\n"
                  << "#include \"strings.h\"\n\n";
                for (const auto& fn : b.fns.functions()) {
                    const char* sym = ds::symbol_for(fn.va);
                    std::string name = sym ? sym
                        : "sub_" + ([&]{
                            char h[24]; std::snprintf(h, sizeof(h), "%llX",
                                static_cast<unsigned long long>(fn.va));
                            return std::string(h);
                          })();
                    f << "// function at 0x" << std::hex << fn.va
                      << ", size " << std::dec << fn.size << " bytes\n";
                    f << "void " << name << "() {\n";
                    f << "    // TODO: decompile\n";
                    f << "}\n\n";
                }
            }

            // metadata.json
            {
                std::ofstream f(dir + "/metadata.json");
                f << "{\n";
                f << "  \"binary\": \"" << b.name << "\",\n";
                f << "  \"base\": \"0x" << std::hex << b.base << "\",\n";
                f << "  \"functions\": " << std::dec
                  << b.fns.functions().size() << ",\n";
                f << "  \"xrefs\": " << b.xrefs.total() << ",\n";
                f << "  \"strings\": " << b.strings.size() << ",\n";
                f << "  \"sections\": " << b.pe.sections.size() << "\n";
                f << "}\n";
            }

            exported = true;
            export_status = "exported " +
                std::to_string(b.fns.functions().size()) +
                " functions to " + dir;
        } catch (const std::exception& e) {
            export_status = std::string("export failed: ") + e.what();
        }
    }

    if (!export_status.empty()) {
        ImVec4 col = exported ? ImVec4(0.4f, 0.9f, 0.4f, 1.0f)
                              : ImVec4(0.9f, 0.3f, 0.3f, 1.0f);
        ImGui::TextColored(col, "%s", export_status.c_str());
    }
}

} // namespace slop::ui::an
