// src/ui/view_kernel_tools.cpp
// kernel-backed inspection panels: driver status, memory map (vad walk),
// modules, handles, threads. all data rides the active backend (kernel
// winotify path when loaded), degrade gracefully when no target is
// attached.

#include "ui/views_core.hpp"

#include <windows.h>
#include "imgui.h"

#include "core/runtime/backend_registry.hpp"
#include "core/process/runtime_dump.hpp"
#include "core/process/module_dump.hpp"
#include "core/process/target_service.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

namespace slop::ui {
namespace kt {

using namespace slop::core;

static uint32_t s_last_pid = 0;

static bool target_changed() {
    auto sess = process::active_session();
    uint32_t pid = sess && sess->valid() ? sess->pid() : 0;
    if (pid != s_last_pid) { s_last_pid = pid; return true; }
    return false;
}

static runtime::target_handle_t current_target() {
    auto sess = process::active_session();
    if (!sess) return {};
    return runtime::active().attach(sess->pid());
}

static bool have_kernel() {
    return runtime::active_kind() == runtime::backend_kind_t::kernel;
}

void DrawDriverStatus() {
    using namespace slop::core::runtime;

    if (ImGui::BeginTable("drv_status", 2, ImGuiTableFlags_BordersInnerV)) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted("transport");
        ImGui::TableNextColumn(); ImGui::Text("%s", active_badge());

        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted("preference");
        ImGui::TableNextColumn(); ImGui::Text("%s",
            current_preference() == backend_pref_t::force_kernel ? "force kernel" :
            current_preference() == backend_pref_t::force_user   ? "force user"   : "auto");

        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted("kind");
        ImGui::TableNextColumn(); ImGui::Text("%s",
            active_kind() == backend_kind_t::kernel ? "kernel" : "usermode");
        ImGui::EndTable();
    }

    ImGui::Separator();

    if (ImGui::Button("load kernel transport")) {
        set_backend_preference(backend_pref_t::force_kernel);
    }
    ImGui::SameLine();
    if (ImGui::Button("switch to usermode")) {
        set_backend_preference(backend_pref_t::force_user);
    }

    ImGui::SeparatorText("stealth layers");
    static const struct { const char* layer; const char* what; } layers[] = {
        { "placement",    "covered-only inside target private vad + existing pt chain" },
        { "pte perms",    "per-page nx from pe section characteristics" },
        { "pfn forge",    "pteaddress repointed to ghost pte slots, flink/blink zeroed" },
        { "ws coverage",  "wsle entries inserted for ghost pages" },
        { "orphan",       "source ptes zeroed in injector process" },
        { "kldr dkom",    "dllbase overwritten to legitimate module, size zeroed" },
        { "scrub",        "pdb strings + pe headers zeroed in driver image" },
        { "mutate",       "cc + zero padding runs randomized in driver image" },
        { "device name",  "object header name info zeroed + image strings wiped" },
        { "etw",          "codeintegrity channel clear attempt" },
        { "trigger",      "pte-level cow swap, self-restoring stub" },
        { "threads",      "no new threads (hijacks existing game thread)" },
    };
    for (const auto& l : layers) {
        ImGui::BulletText("%s: %s", l.layer, l.what);
    }
}

void DrawMemoryMap() {
    if (target_changed()) { /* reset stale flags on target change */ }
    auto h = current_target();
    if (!h.valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<runtime::region_info_t> regions;
    static bool stale = true;

    if (stale || ImGui::Button("refresh##memmap")) {
        regions.clear();
        stale = false;
        auto r = runtime::active().enum_regions(h);
        if (r.ok) regions = std::move(r.items);
    }

    ImGui::Text("%zu regions", regions.size());
    ImGui::SameLine();
    if (ImGui::Button("mark stale")) stale = true;

    if (!ImGui::BeginTable("memmap", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("base");
    ImGui::TableSetupColumn("size");
    ImGui::TableSetupColumn("protect");
    ImGui::TableSetupColumn("state");
    ImGui::TableHeadersRow();

    for (const auto& r : regions) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%016llX",
            static_cast<unsigned long long>(r.base));
        ImGui::TableNextColumn(); ImGui::Text("%llX",
            static_cast<unsigned long long>(r.size));
        ImGui::TableNextColumn(); ImGui::Text("%08X", r.protect);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(r.state == 0x1000 ? "commit" :
                               r.state == 0x2000 ? "reserve" : "free");
    }
    ImGui::EndTable();
}

void DrawModules() {
    if (target_changed()) { /* reset stale flags on target change */ }
    auto h = current_target();
    if (!h.valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<runtime::module_info_t> mods;
    static bool stale = true;

    if (stale || ImGui::Button("refresh##mods")) {
        mods.clear();
        stale = false;
        auto r = runtime::active().enum_modules(h);
        if (r.ok) {
            mods = std::move(r.items);
            std::sort(mods.begin(), mods.end(),
                      [](const auto& a, const auto& b) { return a.base < b.base; });
        }
    }

    ImGui::Text("%zu modules", mods.size());
    ImGui::SameLine();
    if (ImGui::Button("mark stale##mods")) stale = true;

    if (!ImGui::BeginTable("mods", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("base");
    ImGui::TableSetupColumn("size");
    ImGui::TableSetupColumn("name");
    ImGui::TableHeadersRow();

    for (const auto& m : mods) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%016llX",
            static_cast<unsigned long long>(m.base));
        ImGui::TableNextColumn(); ImGui::Text("%u", m.size);
        ImGui::TableNextColumn(); ImGui::TextUnformatted(m.name.c_str());
    }
    ImGui::EndTable();
}

void DrawHandles() {
    if (target_changed()) { /* reset stale flags on target change */ }
    auto h = current_target();
    if (!h.valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<runtime::handle_info_t> handles;
    static bool fetched = false;

    if (ImGui::Button("enumerate handles")) {
        handles.clear();
        fetched = true;
        auto r = runtime::active().enum_handles(h.pid);
        if (r.ok) handles = std::move(r.items);
    }

    if (!fetched) {
        ImGui::TextDisabled("click to enumerate (kernel transport recommended)");
        return;
    }

    ImGui::Text("%zu handles", handles.size());

    if (!ImGui::BeginTable("handles", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("handle");
    ImGui::TableSetupColumn("type");
    ImGui::TableSetupColumn("name");
    ImGui::TableHeadersRow();

    for (const auto& hd : handles) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%llX",
            static_cast<unsigned long long>(hd.handle_value));
        ImGui::TableNextColumn(); ImGui::TextUnformatted(hd.type_name.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(hd.object_name.c_str());
    }
    ImGui::EndTable();
}

void DrawThreads() {
    if (target_changed()) { /* reset stale flags on target change */ }
    auto h = current_target();
    if (!h.valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<runtime::thread_info_t> threads;
    static bool stale = true;

    if (stale || ImGui::Button("refresh##threads")) {
        threads.clear();
        stale = false;
        auto r = runtime::active().enum_threads(h.pid);
        if (r.ok) threads = std::move(r.items);
    }

    ImGui::Text("%zu threads", threads.size());
    ImGui::SameLine();
    if (ImGui::Button("mark stale##threads")) stale = true;

    if (!ImGui::BeginTable("threads", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;

    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("tid");
    ImGui::TableSetupColumn("start address");
    ImGui::TableSetupColumn("priority");
    ImGui::TableHeadersRow();

    for (const auto& t : threads) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::Text("%u", t.tid);
        ImGui::TableNextColumn(); ImGui::Text("%016llX",
            static_cast<unsigned long long>(t.start_address));
        ImGui::TableNextColumn(); ImGui::Text("%d", t.priority);
    }
    ImGui::EndTable();
}



void DrawRuntimeDump() {
    if (target_changed()) {}
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return;
    }

    static std::vector<runtime::module_info_t> cached_mods;
    static std::vector<std::string> mod_names;
    static int selected_mod = 0;
    static char output_path[MAX_PATH] = "";
    static process::runtime_dump_result_t last_result;
    static bool has_result = false;

    // options
    static bool opt_imports = true;
    static bool opt_oep = true;
    static bool opt_fix_sections = true;
    static bool opt_remove_packer = true;
    static bool opt_checksum = true;

    ImGui::TextWrapped(
        "dump a fully deobfuscated binary from runtime memory. "
        "captures the unpacked/decrypted state after the packer has "
        "finished initializing. reconstructs imports by matching "
        "resolved IAT entries against exports of all loaded DLLs "
        "(Scylla-class). detects the original entry point. "
        "all reads through the kernel phys path — invisible to AC.");
    ImGui::Separator();

    if (ImGui::Button("refresh modules##rtdump")) {
        auto mods = runtime::active().enum_modules(sess->handle());
        cached_mods = std::move(mods.items);
        mod_names.clear();
        for (const auto& m : cached_mods) mod_names.push_back(m.name);
    }

    if (!cached_mods.empty()) {
        std::vector<const char*> items;
        for (const auto& n : mod_names) items.push_back(n.c_str());
        ImGui::Combo("target module", &selected_mod,
                     items.data(), static_cast<int>(items.size()));
    }

    ImGui::InputText("output path", output_path, sizeof(output_path));
    ImGui::SameLine();
    if (ImGui::SmallButton("...##rtdump")) {
        // auto-generate path
        if (selected_mod >= 0 && selected_mod < static_cast<int>(cached_mods.size())) {
            std::snprintf(output_path, sizeof(output_path),
                          "C:\\dumps\\%s_deobfuscated.exe",
                          cached_mods[selected_mod].name.c_str());
        }
    }

    ImGui::SeparatorText("options");
    ImGui::Checkbox("reconstruct imports (IAT scan)", &opt_imports);
    ImGui::Checkbox("detect original entry point", &opt_oep);
    ImGui::Checkbox("fix section table from memory", &opt_fix_sections);
    ImGui::Checkbox("remove packer sections", &opt_remove_packer);
    ImGui::Checkbox("fix PE checksum", &opt_checksum);

    ImGui::Separator();
    bool can_dump = selected_mod >= 0 &&
                    selected_mod < static_cast<int>(cached_mods.size()) &&
                    output_path[0];

    ImGui::BeginDisabled(!can_dump);
    if (ImGui::Button("dump deobfuscated binary", ImVec2(-1, 32))) {
        process::runtime_dump_options_t opts;
        opts.reconstruct_imports = opt_imports;
        opts.detect_oep = opt_oep;
        opts.fix_sections = opt_fix_sections;
        opts.remove_packer_sections = opt_remove_packer;
        opts.fix_checksum = opt_checksum;

        const auto& mod = cached_mods[selected_mod];
        last_result = process::dump_deobfuscated(
            const_cast<runtime::session_t&>(*sess),
            mod.base, mod.size, output_path, opts);
        has_result = true;
    }
    ImGui::EndDisabled();

    // show result
    if (has_result) {
        ImGui::SeparatorText("result");
        if (last_result.ok) {
            ImGui::TextColored(ImVec4(0.4f, 0.9f, 0.4f, 1.0f),
                               "dump successful: %zu bytes written",
                               last_result.bytes_written);
        } else {
            ImGui::TextColored(ImVec4(0.9f, 0.3f, 0.3f, 1.0f),
                               "dump failed: %s", last_result.error.c_str());
        }

        if (last_result.ok) {
            ImGui::Text("module base: %016llX",
                        static_cast<unsigned long long>(last_result.module_base));
            ImGui::Text("module size: %u bytes", last_result.module_size);

            if (last_result.detected_oep) {
                ImGui::TextColored(ImVec4(0.9f, 0.8f, 0.3f, 1.0f),
                    "OEP: %016llX (RVA %08X) — %s",
                    static_cast<unsigned long long>(last_result.detected_oep),
                    last_result.detected_oep_rva,
                    last_result.oep_method.c_str());
            }

            ImGui::Text("imports: %zu total, %zu resolved, %zu unresolved",
                        last_result.total_imports,
                        last_result.resolved_imports,
                        last_result.unresolved_imports);
            ImGui::Text("sections rebuilt: %zu, packer sections removed: %zu",
                        last_result.sections_rebuilt,
                        last_result.packer_sections_removed);
            ImGui::Text("checksum: %08X", last_result.checksum);

            // import details
            if (!last_result.imports.empty()) {
                ImGui::SeparatorText("reconstructed imports");
                if (ImGui::BeginTable("rt_imports", 3,
                        ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                        ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable,
                        ImVec2(0, 200))) {
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableSetupColumn("DLL");
                    ImGui::TableSetupColumn("function");
                    ImGui::TableSetupColumn("IAT RVA");
                    ImGui::TableHeadersRow();
                    for (const auto& mod : last_result.imports) {
                        for (const auto& f : mod.functions) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn();
                            ImGui::TextUnformatted(mod.dll_name.c_str());
                            ImGui::TableNextColumn();
                            if (f.func_name.empty())
                                ImGui::Text("ordinal #%u", f.ordinal);
                            else
                                ImGui::TextUnformatted(f.func_name.c_str());
                            ImGui::TableNextColumn();
                            ImGui::Text("%08llX",
                                static_cast<unsigned long long>(f.iat_rva));
                        }
                    }
                    ImGui::EndTable();
                }
            }

            for (const auto& w : last_result.warnings) {
                ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.0f),
                                   "warning: %s", w.c_str());
            }
        }
    }
}

} // namespace kt
} // namespace slop::ui
