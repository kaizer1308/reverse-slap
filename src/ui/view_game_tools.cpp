// src/ui/view_game_tools.cpp
// ImGui panels for the stealth game analysis toolkit. every read rides the
// active backend (kernel phys when winotify is loaded). zero handles in
// the target, zero api calls in target context.
#include "ui/views_core.hpp"
#include "imgui.h"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/game_tools.hpp"
#include "core/process/target_service.hpp"
#include <algorithm>
#include <cstdio>
#include <string>
#include <vector>

namespace slop::ui::gt {

using namespace slop::core;
using namespace slop::core::runtime;
using namespace slop::core::runtime::game_tools;

// ── shared helpers ───────────────────────────────────────────────────────
static uint32_t s_gt_last_pid = 0;

static bool gt_target_changed() {
    auto sess = process::active_session();
    uint32_t pid = sess && sess->valid() ? sess->pid() : 0;
    if (pid != s_gt_last_pid) { s_gt_last_pid = pid; return true; }
    return false;
}

static reader_t make_reader() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) return {};
    reader_t rd;
    rd.be = &runtime::active();
    rd.h  = sess->handle();
    return rd;
}

static bool no_target() {
    auto sess = process::active_session();
    if (!sess || !sess->valid()) {
        ImGui::TextDisabled("attach a target first");
        return true;
    }
    return false;
}

// ── 1. pointer scanner ──────────────────────────────────────────────────
void DrawPointerScanner() {
    if (no_target()) return;

    static uint64_t target_addr = 0;
    static int max_depth = 3;
    static int max_offset = 0x2000;
    static std::vector<pointer_chain_t> results;

    ImGui::InputScalar("target address", ImGuiDataType_U64, &target_addr,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SliderInt("max depth", &max_depth, 1, 5);
    ImGui::SliderInt("max offset", &max_offset, 0x100, 0x4000);

    if (ImGui::Button("scan")) {
        auto rd = make_reader();
        if (rd.be) {
            auto sess = process::active_session();
            auto mods = runtime::active().enum_modules(sess->handle());
            auto regs = runtime::active().enum_regions(sess->handle());
            pointer_scan_config_t cfg;
            cfg.target_address = target_addr;
            cfg.max_depth = max_depth;
            cfg.max_offset = max_offset;
            results = scan_pointer_chains(rd, mods.items, regs.items, cfg);
        }
    }

    ImGui::Text("%zu chains found", results.size());
    if (!ImGui::BeginTable("ptr_chains", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("module");
    ImGui::TableSetupColumn("chain");
    ImGui::TableSetupColumn("resolved");
    ImGui::TableHeadersRow();

    for (const auto& c : results) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(c.module_name.c_str());
        ImGui::TableNextColumn();
        std::string chain_str;
        for (size_t i = 0; i < c.offsets.size(); ++i) {
            if (i > 0) chain_str += " -> ";
            char tmp[32];
            std::snprintf(tmp, sizeof(tmp), "+0x%llX",
                          static_cast<unsigned long long>(c.offsets[i]));
            chain_str += tmp;
        }
        ImGui::TextUnformatted(chain_str.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(c.resolved));
    }
    ImGui::EndTable();
}

// ── 2. snapshot diff ─────────────────────────────────────────────────────
void DrawSnapshotDiff() {
    if (no_target()) return;

    static uint64_t snap_base = 0;
    static int snap_size = 0x1000;
    static snapshot_t snap_a, snap_b;
    static std::vector<diff_entry_t> diffs;
    static bool has_a = false, has_b = false;

    ImGui::InputScalar("base", ImGuiDataType_U64, &snap_base, nullptr,
                       nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputInt("size", &snap_size, 0x100, 0x1000);
    if (snap_size < 1) snap_size = 1;
    if (snap_size > 16 * 1024 * 1024) snap_size = 16 * 1024 * 1024;

    if (ImGui::Button("snapshot A")) {
        auto rd = make_reader();
        snap_a = take_snapshot(rd, snap_base, snap_size);
        has_a = !snap_a.data.empty();
    }
    ImGui::SameLine();
    if (ImGui::Button("snapshot B")) {
        auto rd = make_reader();
        snap_b = take_snapshot(rd, snap_base, snap_size);
        has_b = !snap_b.data.empty();
    }
    ImGui::SameLine();
    if (has_a && has_b && ImGui::Button("diff")) {
        diffs = diff_snapshots(snap_a, snap_b);
    }

    ImGui::Text("A: %s  B: %s  diffs: %zu",
                has_a ? "taken" : "-", has_b ? "taken" : "-", diffs.size());

    if (!ImGui::BeginTable("snap_diff", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("offset");
    ImGui::TableSetupColumn("old");
    ImGui::TableSetupColumn("new");
    ImGui::TableHeadersRow();
    for (const auto& d : diffs) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("+%04llX", static_cast<unsigned long long>(d.offset));
        ImGui::TableNextColumn(); ImGui::Text("%02X", d.old_val);
        ImGui::TableNextColumn(); ImGui::Text("%02X", d.new_val);
    }
    ImGui::EndTable();
}

// ── 3. AOB generator ─────────────────────────────────────────────────────
void DrawAobGenerator() {
    if (no_target()) return;

    static uint64_t aob_addr = 0;
    static int aob_len = 32;
    static char aob_label[64] = "";
    static aob_pattern_t last_pat;
    static char search_pat[512] = "";
    static std::vector<uint64_t> search_hits;

    ImGui::SeparatorText("generate");
    ImGui::InputScalar("address##aob", ImGuiDataType_U64, &aob_addr,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::SliderInt("length##aob", &aob_len, 4, 128);
    ImGui::InputText("label##aob", aob_label, sizeof(aob_label));

    if (ImGui::Button("generate pattern")) {
        auto rd = make_reader();
        last_pat = generate_aob(rd, aob_addr, aob_len, aob_label);
    }

    if (!last_pat.pattern.empty()) {
        ImGui::TextWrapped("pattern: %s", last_pat.pattern.c_str());
        if (ImGui::Button("copy to search")) {
            std::strncpy(search_pat, last_pat.pattern.c_str(),
                         sizeof(search_pat) - 1);
        }
    }

    ImGui::SeparatorText("search");
    ImGui::InputText("pattern##search", search_pat, sizeof(search_pat));
    if (ImGui::Button("scan")) {
        auto rd = make_reader();
        auto sess = process::active_session();
        auto regs = runtime::active().enum_regions(sess->handle());
        search_hits.clear();
        for (const auto& reg : regs.items) {
            if (reg.state != 0x1000) continue;
            auto h = scan_aob(rd, reg.base, reg.size, search_pat);
            for (auto va : h) search_hits.push_back(va);
            if (search_hits.size() > 4096) break;
        }
    }

    ImGui::Text("%zu hits", search_hits.size());
    if (ImGui::BeginTable("aob_hits", 1,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupColumn("address");
        ImGui::TableHeadersRow();
        for (auto va : search_hits) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::Text("%016llX", static_cast<unsigned long long>(va));
        }
        ImGui::EndTable();
    }
}

// ── 4. struct dissector ──────────────────────────────────────────────────
void DrawStructDissector() {
    if (no_target()) return;

    static uint64_t struct_base = 0;
    static struct_def_t def;
    static std::vector<field_value_t> vals;
    static bool auto_refresh = false;
    static char new_field_name[64] = "";
    static int new_field_type = 0;
    static int new_field_offset = 0;

    ImGui::InputScalar("base address##struct", ImGuiDataType_U64,
                       &struct_base, nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::Checkbox("auto refresh", &auto_refresh);

    ImGui::SeparatorText("add field");
    ImGui::InputText("name##field", new_field_name, sizeof(new_field_name));
    const char* type_names[] = {
        "u8","u16","u32","u64","i8","i16","i32","i64",
        "f32","f64","ptr","vec3","str","pad"
    };
    ImGui::Combo("type##field", &new_field_type, type_names, 14);
    ImGui::InputInt("offset##field", &new_field_offset, 1, 8);
    if (ImGui::Button("add field") && new_field_name[0]) {
        struct_field_t f;
        f.name = new_field_name;
        f.type = static_cast<field_type_t>(new_field_type);
        f.offset = new_field_offset;
        def.fields.push_back(f);
        new_field_name[0] = 0;
    }
    ImGui::SameLine();
    if (ImGui::Button("clear fields")) { def.fields.clear(); vals.clear(); }

    if ((auto_refresh || ImGui::Button("read")) && struct_base && !def.fields.empty()) {
        auto rd = make_reader();
        vals = read_struct(rd, struct_base, def);
    }

    if (!ImGui::BeginTable("struct_vals", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("offset");
    ImGui::TableSetupColumn("name");
    ImGui::TableSetupColumn("type");
    ImGui::TableSetupColumn("value");
    ImGui::TableHeadersRow();

    for (size_t i = 0; i < vals.size() && i < def.fields.size(); ++i) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("+0x%X", static_cast<unsigned>(def.fields[i].offset));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(vals[i].name.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(type_names[static_cast<int>(vals[i].type)]);
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(vals[i].display.c_str());
    }
    ImGui::EndTable();
}

// ── 5. encrypted pointer decoder ─────────────────────────────────────────
void DrawEncPtrDecoder() {
    if (no_target()) return;

    static uint64_t scan_base = 0;
    static int scan_size = 0x10000;
    static uint64_t expect_lo = 0x7FF600000000;
    static uint64_t expect_hi = 0x7FFFFFFFFFFF;
    static std::vector<decoded_pointer_t> results;

    ImGui::InputScalar("scan base##enc", ImGuiDataType_U64, &scan_base,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputInt("scan size##enc", &scan_size, 0x1000, 0x10000);
    ImGui::InputScalar("expected low##enc", ImGuiDataType_U64, &expect_lo,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);
    ImGui::InputScalar("expected high##enc", ImGuiDataType_U64, &expect_hi,
                       nullptr, nullptr, "%016llX",
                       ImGuiInputTextFlags_CharsHexadecimal);

    if (ImGui::Button("scan encrypted pointers")) {
        auto rd = make_reader();
        results = scan_encrypted_pointers(rd, scan_base, scan_size,
                                           expect_lo, expect_hi);
    }

    ImGui::Text("%zu decoded", results.size());
    if (!ImGui::BeginTable("enc_ptrs", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("raw");
    ImGui::TableSetupColumn("decoded");
    ImGui::TableSetupColumn("method");
    ImGui::TableSetupColumn("key");
    ImGui::TableHeadersRow();
    for (const auto& d : results) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(d.raw));
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(d.decoded));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(d.method.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(d.key));
    }
    ImGui::EndTable();
}

// ── 6. offset database ──────────────────────────────────────────────────
void DrawOffsetDb() {
    static offset_db_t db;
    static char label[64] = "", module[64] = "", comment[128] = "";
    static int offset_val = 0;
    static char db_path[256] = "offsets.db";

    ImGui::InputText("db path", db_path, sizeof(db_path));
    if (ImGui::Button("load")) db.load(db_path);
    ImGui::SameLine();
    if (ImGui::Button("save")) db.save(db_path);

    ImGui::SeparatorText("add entry");
    ImGui::InputText("label##odb", label, sizeof(label));
    ImGui::InputText("module##odb", module, sizeof(module));
    ImGui::InputInt("offset##odb", &offset_val, 1, 0x10);
    ImGui::InputText("comment##odb", comment, sizeof(comment));
    if (ImGui::Button("add") && label[0]) {
        offset_entry_t e;
        e.label = label; e.module = module;
        e.offset = offset_val; e.comment = comment;
        db.add(std::move(e));
        label[0] = 0;
    }

    if (!ImGui::BeginTable("odb", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("label");
    ImGui::TableSetupColumn("module");
    ImGui::TableSetupColumn("offset");
    ImGui::TableSetupColumn("comment");
    ImGui::TableHeadersRow();
    for (const auto& e : db.all()) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn(); ImGui::TextUnformatted(e.label.c_str());
        ImGui::TableNextColumn(); ImGui::TextUnformatted(e.module.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("0x%llX", static_cast<unsigned long long>(e.offset));
        ImGui::TableNextColumn(); ImGui::TextUnformatted(e.comment.c_str());
    }
    ImGui::EndTable();
}

// ── 7. crypto constant scanner ───────────────────────────────────────────
void DrawCryptoScanner() {
    if (no_target()) return;

    static std::vector<crypto_hit_t> hits;

    if (ImGui::Button("scan all modules for crypto constants")) {
        auto rd = make_reader();
        auto sess = process::active_session();
        auto mods = runtime::active().enum_modules(sess->handle());
        hits.clear();
        for (const auto& m : mods.items) {
            auto h = scan_crypto_constants(rd, m.base, m.size);
            for (auto& hit : h) hits.push_back(std::move(hit));
            if (hits.size() > 1024) break;
        }
    }

    ImGui::Text("%zu crypto constants found", hits.size());
    if (!ImGui::BeginTable("crypto", 3,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("address");
    ImGui::TableSetupColumn("algorithm");
    ImGui::TableSetupColumn("constant");
    ImGui::TableHeadersRow();
    for (const auto& h : hits) {
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(h.address));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(h.algorithm.c_str());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(h.constant_name.c_str());
    }
    ImGui::EndTable();
}

// ── 8. RTTI / VMT walker ─────────────────────────────────────────────────
void DrawRttiWalker() {
    if (no_target()) return;

    static std::vector<rtti_class_t> classes;
    static char filter[128] = "";

    if (ImGui::Button("scan RTTI in all modules")) {
        auto rd = make_reader();
        auto sess = process::active_session();
        auto mods = runtime::active().enum_modules(sess->handle());
        classes.clear();
        for (const auto& m : mods.items) {
            auto c = scan_rtti(rd, m.base, m.size);
            for (auto& cls : c) classes.push_back(std::move(cls));
            if (classes.size() > 2048) break;
        }
    }

    ImGui::InputText("filter##rtti", filter, sizeof(filter));
    ImGui::Text("%zu classes", classes.size());

    if (!ImGui::BeginTable("rtti", 4,
            ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) return;
    ImGui::TableSetupScrollFreeze(0, 1);
    ImGui::TableSetupColumn("vtable");
    ImGui::TableSetupColumn("class");
    ImGui::TableSetupColumn("methods");
    ImGui::TableSetupColumn("raw name");
    ImGui::TableHeadersRow();
    for (const auto& c : classes) {
        if (filter[0] && c.class_name.find(filter) == std::string::npos)
            continue;
        ImGui::TableNextRow();
        ImGui::TableNextColumn();
        ImGui::Text("%016llX", static_cast<unsigned long long>(c.vtable_va));
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(c.class_name.c_str());
        ImGui::TableNextColumn();
        ImGui::Text("%zu", c.method_vas.size());
        ImGui::TableNextColumn();
        ImGui::TextUnformatted(c.raw_name.c_str());
    }
    ImGui::EndTable();
}

// ── 9. binary map / heatmap ──────────────────────────────────────────────
void DrawBinaryMap() {
    if (no_target()) return;

    static std::vector<map_block_t> blocks;
    static int selected_module = 0;
    static std::vector<std::string> mod_names;
    static std::vector<module_info_t> cached_mods;

    if (ImGui::Button("refresh modules##bmap")) {
        auto sess = process::active_session();
        auto mods = runtime::active().enum_modules(sess->handle());
        cached_mods = std::move(mods.items);
        mod_names.clear();
        for (const auto& m : cached_mods) mod_names.push_back(m.name);
    }

    if (!cached_mods.empty()) {
        std::vector<const char*> items;
        for (const auto& n : mod_names) items.push_back(n.c_str());
        ImGui::Combo("module##bmap", &selected_module,
                     items.data(), static_cast<int>(items.size()));

        if (ImGui::Button("build map") &&
            selected_module >= 0 &&
            selected_module < static_cast<int>(cached_mods.size())) {
            auto rd = make_reader();
            const auto& m = cached_mods[selected_module];
            blocks = build_binary_map(rd, m.base, m.size, 256);
        }
    }

    if (blocks.empty()) return;

    // draw the heatmap as a grid of colored rectangles
    const float cell = 4.0f;
    const int cols = static_cast<int>(ImGui::GetContentRegionAvail().x / cell);
    if (cols <= 0) return;

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 origin = ImGui::GetCursorScreenPos();

    for (size_t i = 0; i < blocks.size(); ++i) {
        int x = static_cast<int>(i) % cols;
        int y = static_cast<int>(i) / cols;
        ImVec2 p0(origin.x + x * cell, origin.y + y * cell);
        ImVec2 p1(p0.x + cell - 1, p0.y + cell - 1);

        // color by entropy (0 = dark, 8 = bright)
        float t = blocks[i].entropy / 8.0f;
        ImU32 col;
        switch (blocks[i].kind) {
        case map_block_t::kind_t::code:
            col = ImGui::ColorConvertFloat4ToU32(
                ImVec4(0.1f, 0.2f + 0.6f*t, 0.3f, 1.0f)); break;
        case map_block_t::kind_t::data:
            col = ImGui::ColorConvertFloat4ToU32(
                ImVec4(0.2f + 0.6f*t, 0.2f, 0.1f, 1.0f)); break;
        case map_block_t::kind_t::rdata:
            col = ImGui::ColorConvertFloat4ToU32(
                ImVec4(0.1f, 0.1f, 0.3f + 0.5f*t, 1.0f)); break;
        default:
            col = ImGui::ColorConvertFloat4ToU32(
                ImVec4(t*0.3f, t*0.3f, t*0.3f, 1.0f)); break;
        }
        dl->AddRectFilled(p0, p1, col);

        // tooltip on hover
        if (ImGui::IsMouseHoveringRect(p0, p1)) {
            ImGui::BeginTooltip();
            ImGui::Text("VA: %016llX",
                        static_cast<unsigned long long>(blocks[i].va));
            ImGui::Text("entropy: %.2f", blocks[i].entropy);
            const char* kind_str = "unknown";
            switch (blocks[i].kind) {
            case map_block_t::kind_t::code:  kind_str = ".text";  break;
            case map_block_t::kind_t::data:  kind_str = ".data";  break;
            case map_block_t::kind_t::rdata: kind_str = ".rdata"; break;
            case map_block_t::kind_t::bss:   kind_str = ".bss";   break;
            case map_block_t::kind_t::rsrc:  kind_str = ".rsrc";  break;
            case map_block_t::kind_t::reloc: kind_str = ".reloc"; break;
            default: break;
            }
            ImGui::Text("section: %s", kind_str);
            ImGui::EndTooltip();
        }
    }

    int rows = (static_cast<int>(blocks.size()) + cols - 1) / cols;
    ImGui::Dummy(ImVec2(cols * cell, rows * cell));

    // legend
    ImGui::SeparatorText("legend");
    ImGui::TextColored(ImVec4(0.1f, 0.8f, 0.3f, 1.0f), "green = code");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.8f, 0.2f, 0.1f, 1.0f), "red = data");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.1f, 0.1f, 0.8f, 1.0f), "blue = rdata");
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.5f, 0.5f, 0.5f, 1.0f), "gray = other");
}

} // namespace slop::ui::gt
