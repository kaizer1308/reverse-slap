// src/ui/view_investigation.cpp
// Investigation panels: findings tracker, security audit, open questions,
// investigation workflows, evidence export/import.
#include "ui/views_core.hpp"
#include "imgui.h"
#include "core/runtime/investigation.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/process/target_service.hpp"
#include "core/disasm/binary_state.hpp"
#include <cstdio>
#include <string>

namespace slop::ui::iv {

namespace inv = slop::core::runtime::investigation;
namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace ds = slop::core::disasm::binary_state;

static inv::findings_db_t g_findings;

// ── findings tracker ─────────────────────────────────────────────────────

void DrawFindings() {
    static char title[128] = "", desc[512] = "", limitations[256] = "";
    static int category = 0, confidence = 0;
    static char export_path[256] = "findings.json";

    ImGui::SeparatorText("add finding");
    ImGui::InputText("title##f", title, sizeof(title));
    ImGui::InputTextMultiline("description##f", desc, sizeof(desc), ImVec2(-1, 60));
    const char* cats[] = {"vulnerability","behavior","structure","unknown"};
    ImGui::Combo("category##f", &category, cats, 4);
    const char* confs[] = {"certain","high","medium","low","unknown"};
    ImGui::Combo("confidence##f", &confidence, confs, 5);
    ImGui::InputText("limitations##f", limitations, sizeof(limitations));

    if (ImGui::Button("add finding") && title[0]) {
        inv::finding_t f;
        f.title = title; f.description = desc;
        f.category = cats[category];
        f.confidence = static_cast<inv::confidence_t>(confidence);
        f.limitations = limitations;
        g_findings.add_finding(std::move(f));
        title[0] = 0; desc[0] = 0; limitations[0] = 0;
    }

    ImGui::SeparatorText("export / import");
    ImGui::InputText("path##fexp", export_path, sizeof(export_path));
    ImGui::SameLine();
    if (ImGui::Button("export")) g_findings.export_json(export_path);
    ImGui::SameLine();
    if (ImGui::Button("import")) g_findings.import_json(export_path);

    ImGui::SeparatorText("findings");
    ImGui::Text("%zu findings", g_findings.all().size());

    if (!ImGui::BeginTable("findings", 5,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("ID"); ImGui::TableSetupColumn("title");
    ImGui::TableSetupColumn("category"); ImGui::TableSetupColumn("confidence");
    ImGui::TableSetupColumn("status");
    ImGui::TableHeadersRow();
    for (const auto& f : g_findings.all()) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(f.id.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(f.title.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(f.category.c_str());
        ImGui::TableNextColumn();
        const char* conf_names[] = {"certain","high","medium","low","unknown"};
        ImVec4 col = f.confidence == inv::confidence_t::certain ? ImVec4(0.4f,0.9f,0.4f,1)
                   : f.confidence == inv::confidence_t::high ? ImVec4(0.5f,0.8f,0.4f,1)
                   : f.confidence == inv::confidence_t::medium ? ImVec4(0.9f,0.8f,0.3f,1)
                   : ImVec4(0.9f,0.4f,0.3f,1);
        ImGui::TextColored(col, "%s", conf_names[static_cast<int>(f.confidence)]);
        ImGui::TableNextColumn(); ImGui::TextUnformatted(f.status.c_str());
    }
    ImGui::EndTable();
}

// ── open questions ───────────────────────────────────────────────────────

void DrawQuestions() {
    static char question[256] = "", context[256] = "";

    ImGui::SeparatorText("add question");
    ImGui::InputText("question##q", question, sizeof(question));
    ImGui::InputText("context##q", context, sizeof(context));
    if (ImGui::Button("add question") && question[0]) {
        inv::open_question_t q;
        q.question = question; q.context = context;
        g_findings.add_question(std::move(q));
        question[0] = 0; context[0] = 0;
    }

    ImGui::SeparatorText("open questions");
    if (!ImGui::BeginTable("questions", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("ID"); ImGui::TableSetupColumn("question");
    ImGui::TableSetupColumn("status"); ImGui::TableSetupColumn("answer");
    ImGui::TableHeadersRow();
    for (const auto& q : g_findings.questions()) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(q.id.c_str());
        ImGui::TableNextColumn(); ImGui::TextWrapped("%s", q.question.c_str());
        ImGui::TableNextColumn();
        ImVec4 col = q.status == "answered" ? ImVec4(0.4f,0.9f,0.4f,1)
                   : q.status == "investigating" ? ImVec4(0.9f,0.8f,0.3f,1)
                   : ImVec4(0.7f,0.7f,0.7f,1);
        ImGui::TextColored(col, "%s", q.status.c_str());
        ImGui::TableNextColumn(); ImGui::TextWrapped("%s", q.answer.c_str());
    }
    ImGui::EndTable();
}

// ── security audit ───────────────────────────────────────────────────────

void DrawSecurityAudit() {
    static inv::security_audit_t audit;
    static bool has_audit = false;

    // audit from loaded binary
    if (ds::has_binary()) {
        if (ImGui::Button("audit loaded binary")) {
            auto& b = ds::get();
            audit = inv::audit_file(b.file, b.name);
            has_audit = true;
        }
    }

    // audit from attached target module
    auto sess = process::active_session();
    if (sess && sess->valid()) {
        ImGui::SameLine();
        if (ImGui::Button("audit main module")) {
            auto mods = runtime::active().enum_modules(sess->handle());
            if (mods.ok && !mods.items.empty()) {
                const auto& m = mods.items[0];
                audit = inv::audit_module(runtime::active(), sess->handle(),
                                           m.base, m.size, m.name);
                has_audit = true;
            }
        }
    }

    if (!has_audit) {
        ImGui::TextDisabled("load a binary or attach a target, then click audit");
        return;
    }

    ImGui::SeparatorText("binary info");
    ImGui::Text("module: %s", audit.module_name.c_str());
    ImGui::Text("base: 0x%llX  size: 0x%X",
                static_cast<unsigned long long>(audit.base), audit.size);
    ImGui::Text("sections: %zu", audit.section_count);

    ImGui::SeparatorText("hashes");
    if (!audit.md5.empty()) ImGui::Text("MD5:    %s", audit.md5.c_str());
    if (!audit.sha1.empty()) ImGui::Text("SHA1:   %s", audit.sha1.c_str());
    if (!audit.sha256.empty()) ImGui::Text("SHA256: %s", audit.sha256.c_str());
    if (!audit.crc32.empty()) ImGui::Text("CRC32:  %s", audit.crc32.c_str());

    ImGui::SeparatorText("entropy");
    ImGui::Text("overall: %.2f / 8.0", audit.overall_entropy);
    if (audit.likely_packed) {
        ImGui::TextColored(ImVec4(0.9f,0.4f,0.3f,1),
                           "HIGH ENTROPY — likely packed/encrypted");
    }

    ImGui::SeparatorText("security features");
    for (const auto& f : audit.features) {
        ImVec4 col = f.enabled ? ImVec4(0.4f,0.9f,0.4f,1)
                               : ImVec4(0.9f,0.4f,0.3f,1);
        ImGui::TextColored(col, "%s %s", f.enabled ? "✓" : "✗", f.name.c_str());
    }

    if (audit.has_writable_exec) {
        ImGui::TextColored(ImVec4(0.9f,0.3f,0.3f,1),
                           "WARNING: writable + executable sections detected (W+X)");
    }
    if (audit.has_no_relocs) {
        ImGui::TextColored(ImVec4(0.9f,0.7f,0.2f,1),
                           "NOTE: no relocation directory (fixed base address)");
    }

    if (!audit.dangerous_apis.empty()) {
        ImGui::SeparatorText("suspicious imports");
        ImGui::Text("%zu dangerous APIs detected:", audit.suspicious_imports);
        for (const auto& api : audit.dangerous_apis) {
            ImGui::BulletText("%s", api.c_str());
        }
    }
}

// ── investigation workflows ──────────────────────────────────────────────

void DrawWorkflows() {
    auto workflows = inv::get_workflows();

    ImGui::TextWrapped("guided investigation workflows — follow these step-by-step "
                       "or use the MCP tool names in the AI chat to automate.");
    ImGui::Separator();

    for (const auto& w : workflows) {
        if (ImGui::CollapsingHeader(w.name.c_str())) {
            ImGui::TextWrapped("%s", w.description.c_str());
            ImGui::Spacing();
            for (size_t i = 0; i < w.steps.size(); ++i) {
                const auto& s = w.steps[i];
                ImGui::Text("%zu. %s", i + 1, s.description.c_str());
                ImGui::TextColored(ImVec4(0.5f, 0.7f, 1.0f, 1.0f),
                                   "   tool: %s", s.action.c_str());
                ImGui::TextDisabled("   look for: %s", s.expected.c_str());
                ImGui::Spacing();
            }
        }
    }
}

} // namespace slop::ui::iv
