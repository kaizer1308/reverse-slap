// src/ui/view_engine_dump.cpp
#include "ui/views_core.hpp"
#include "imgui.h"
#include "core/runtime/engine_dumper.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/process/target_service.hpp"
#include <cstdio>
#include <string>
#include <vector>

namespace slop::ui::ed {
namespace engine_dump = slop::core::runtime::engine_dump;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
using slop::core::runtime::game_tools::reader_t;

static reader_t make_reader() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) return {};
    reader_t rd; rd.be = &runtime::active(); rd.h = sess->handle();
    return rd;
}

void DrawUEDumper() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) { ImGui::TextDisabled("attach a target first"); return; }

    static engine_dump::ue_sdk_dump_t sdk;
    static bool has_sdk = false;
    static char out_dir[256] = "C:\\dumps\\ue_sdk";

    ImGui::TextWrapped("UE4/UE5 SDK dumper (Dumper-7 approach): walks GObjects and GNames "
                       "from live memory via kernel reads, generates C++ SDK headers.");

    auto mods = runtime::active().enum_modules(sess->handle());
    static int sel_mod = 0;
    static std::vector<std::string> mod_names;
    static std::vector<runtime::module_info_t> cached_mods;
    if (ImGui::Button("refresh modules##ue")) {
        cached_mods = mods.ok ? mods.items : std::vector<runtime::module_info_t>{};
        mod_names.clear();
        for (const auto& m : cached_mods) mod_names.push_back(m.name);
    }
    if (!cached_mods.empty()) {
        std::vector<const char*> items;
        for (const auto& n : mod_names) items.push_back(n.c_str());
        ImGui::Combo("module##ue", &sel_mod, items.data(), static_cast<int>(items.size()));
    }

    if (ImGui::Button("dump UE SDK") && sel_mod < static_cast<int>(cached_mods.size())) {
        auto rd = make_reader();
        sdk = engine_dump::dump_ue_sdk(rd, cached_mods[sel_mod].base, cached_mods[sel_mod].size);
        has_sdk = true;
    }

    if (has_sdk) {
        ImGui::Text("GObjects: 0x%llX", (unsigned long long)sdk.gobjects_addr);
        ImGui::Text("GNames: 0x%llX", (unsigned long long)sdk.gnames_addr);
        ImGui::Text("objects: %zu, classes: %zu", sdk.object_count, sdk.classes.size());
        for (const auto& w : sdk.warnings) ImGui::TextColored(ImVec4(0.9f,0.7f,0.2f,1), "%s", w.c_str());

        ImGui::InputText("output dir##ue", out_dir, sizeof(out_dir));
        if (ImGui::Button("export SDK headers")) engine_dump::export_ue_sdk(sdk, out_dir);

        if (!sdk.classes.empty() && ImGui::BeginTable("ue_classes", 4,
                ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0,200))) {
            ImGui::TableSetupScrollFreeze(0,1);
            ImGui::TableSetupColumn("class"); ImGui::TableSetupColumn("super");
            ImGui::TableSetupColumn("size"); ImGui::TableSetupColumn("address");
            ImGui::TableHeadersRow();
            for (const auto& c : sdk.classes) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn(); ImGui::TextUnformatted(c.name.c_str());
                ImGui::TableNextColumn(); ImGui::TextUnformatted(c.super_class.c_str());
                ImGui::TableNextColumn(); ImGui::Text("0x%X", c.size);
                ImGui::TableNextColumn(); ImGui::Text("%016llX", (unsigned long long)c.address);
            }
            ImGui::EndTable();
        }
    }
}

void DrawIl2CppDumper() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) { ImGui::TextDisabled("attach a target first"); return; }

    static engine_dump::il2cpp_dump_t dump;
    static bool has_dump = false;
    static char filter[128] = "";
    static char out_path[256] = "C:\\dumps\\dump.cs";

    ImGui::TextWrapped("Unity Il2Cpp metadata dumper: reads class/method/field info "
                       "from GameAssembly.dll in live memory. Generates dump.cs and C++ headers.");

    auto mods = runtime::active().enum_modules(sess->handle());
    // find GameAssembly.dll automatically
    uint64_t ga_base = 0; uint32_t ga_size = 0;
    if (mods.ok) for (const auto& m : mods.items) {
        if (m.name.find("GameAssembly") != std::string::npos ||
            m.name.find("gameassembly") != std::string::npos) {
            ga_base = m.base; ga_size = m.size;
        }
    }

    if (ga_base) {
        ImGui::Text("GameAssembly.dll: 0x%llX (0x%X)", (unsigned long long)ga_base, ga_size);
        if (ImGui::Button("dump Il2Cpp metadata")) {
            auto rd = make_reader();
            dump = engine_dump::dump_il2cpp(rd, ga_base, ga_size);
            has_dump = true;
        }
    } else {
        ImGui::TextDisabled("GameAssembly.dll not found in loaded modules");
    }

    if (has_dump) {
        ImGui::Text("classes: %zu", dump.classes.size());
        for (const auto& w : dump.warnings) ImGui::TextColored(ImVec4(0.9f,0.7f,0.2f,1), "%s", w.c_str());

        ImGui::InputText("output##il2", out_path, sizeof(out_path));
        if (ImGui::Button("export dump.cs")) engine_dump::export_il2cpp_cs(dump, out_path);
        ImGui::SameLine();
        if (ImGui::Button("export .h")) engine_dump::export_il2cpp_header(dump, std::string(out_path) + ".h");

        ImGui::InputText("filter##il2", filter, sizeof(filter));
        if (!ImGui::BeginTable("il2_classes", 4,
                ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY|ImGuiTableFlags_Resizable, ImVec2(0,200))) return;
        ImGui::TableSetupScrollFreeze(0,1);
        ImGui::TableSetupColumn("class"); ImGui::TableSetupColumn("namespace");
        ImGui::TableSetupColumn("parent"); ImGui::TableSetupColumn("size");
        ImGui::TableHeadersRow();
        for (const auto& c : dump.classes) {
            if (filter[0] && c.full_name.find(filter) == std::string::npos) continue;
            ImGui::TableNextRow();
            ImGui::TableNextColumn(); ImGui::TextUnformatted(c.name.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(c.namespace_name.c_str());
            ImGui::TableNextColumn(); ImGui::TextUnformatted(c.parent.c_str());
            ImGui::TableNextColumn(); ImGui::Text("0x%X", c.instance_size);
        }
        ImGui::EndTable();
    }
}

void DrawTelescope() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) { ImGui::TextDisabled("attach a target first"); return; }

    static uint64_t start_addr = 0;
    static int max_depth = 8;
    static std::vector<engine_dump::telescope_entry_t> chain;

    ImGui::TextWrapped("telescope: recursive pointer dereference (pwndbg-style). "
                       "follows pointer chains and classifies each level.");

    ImGui::InputScalar("address##tel", ImGuiDataType_U64, &start_addr, nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SliderInt("max depth##tel", &max_depth, 1, 16);

    if (ImGui::Button("telescope") && start_addr) {
        auto rd = make_reader();
        auto mods = runtime::active().enum_modules(sess->handle());
        auto regs = runtime::active().enum_regions(sess->handle());
        chain = engine_dump::telescope(rd, start_addr, mods.items, regs.items, max_depth);
    }

    if (chain.empty()) return;
    for (const auto& e : chain) {
        char indent[32] = {};
        for (int i = 0; i < e.depth && i < 15; ++i) { indent[i*2] = ' '; indent[i*2+1] = ' '; }
        ImVec4 col = e.is_pointer ? ImVec4(0.4f,0.8f,1.0f,1) : ImVec4(0.8f,0.8f,0.8f,1);
        ImGui::TextColored(col, "%s%016llX → %016llX  %s",
            indent, (unsigned long long)e.address, (unsigned long long)e.value, e.annotation.c_str());
    }
}

void DrawApiSchema() {
    static engine_dump::api_schema_t schema;
    static bool has_schema = false;
    static char out_path[256] = "api_spec.yaml";

    ImGui::TextWrapped("auto-discover API endpoints from captured network traffic "
                       "and generate OpenAPI/Swagger spec (mitmproxy2swagger approach).");

    if (ImGui::Button("infer API schema from traffic")) {
        auto sess = process::active_session();
        schema = engine_dump::infer_api_schema(slop::core::network::traffic_store_t{},
            sess ? sess->pid() : 0);
        has_schema = true;
    }

    if (!has_schema) return;
    ImGui::Text("%zu endpoints, %zu total requests", schema.endpoints.size(), schema.total_requests);

    ImGui::InputText("output##api", out_path, sizeof(out_path));
    if (ImGui::Button("export OpenAPI YAML")) engine_dump::export_openapi(schema, out_path);

    if (!ImGui::BeginTable("api_eps", 5,
            ImGuiTableFlags_Borders|ImGuiTableFlags_RowBg|ImGuiTableFlags_ScrollY, ImVec2(0,200))) return;
    ImGui::TableSetupScrollFreeze(0,1);
    ImGui::TableSetupColumn("method"); ImGui::TableSetupColumn("path");
    ImGui::TableSetupColumn("host"); ImGui::TableSetupColumn("requests");
    ImGui::TableSetupColumn("content-type");
    ImGui::TableHeadersRow();
    for (const auto& ep : schema.endpoints) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(ep.method.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(ep.path.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(ep.host.c_str());
        ImGui::TableNextColumn(); ImGui::Text("%zu", ep.request_count);
        ImGui::TableNextColumn();
        for (const auto& ct : ep.content_types) ImGui::TextUnformatted(ct.c_str());
    }
    ImGui::EndTable();
}

} // namespace slop::ui::ed
