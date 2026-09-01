// src/ui/view_scanner.cpp
// scanner ui over the ce port engine, watchlist, freeze and pointer scan

#include <windows.h>

#include "ui/views_core.hpp"

#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"
#include "core/infra/limits.hpp"
#include "core/infra/text_format.hpp"
#include "core/memory/aob.hpp"
#include "core/memory/memscan.hpp"
#include "core/memory/pointer_scan.hpp"
#include "core/process/target_service.hpp"
#include "core/runtime/backend_registry.hpp"
#include "core/runtime/scan_bridge.hpp"
#include "ui/fonts.hpp"
#include "ui/panels.hpp"

#include "imgui.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace slop::ui {

namespace runtime = slop::core::runtime;
namespace process = slop::core::process;
namespace infra   = slop::core::infra;

namespace {

using core::memory::rounding_t;
using core::memory::scan_config_t;
using core::memory::scan_result_t;
using core::memory::scan_type_t;
using core::memory::value_width_t;

// Shared helpers

const char* WidthName(value_width_t w) noexcept {
    switch (w) {
    case value_width_t::i8:  return "i8";
    case value_width_t::u8:  return "u8";
    case value_width_t::i16: return "i16";
    case value_width_t::u16: return "u16";
    case value_width_t::i32: return "i32";
    case value_width_t::u32: return "u32";
    case value_width_t::i64: return "i64";
    case value_width_t::u64: return "u64";
    case value_width_t::f32: return "f32";
    case value_width_t::f64: return "f64";
    }
    return "?";
}

// Scanner state

struct scan_state_t {
    std::mutex                    mu;
    core::memory::memscan_t       engine;
    std::vector<scan_result_t>    view;    // capped UI copy, refreshed post-job
    core::memory::scan_stats_t    stats;
    bool                          has = false; // a scan ran (or region scan active)
};

struct pointer_shared_t {
    std::mutex                                        mu;
    std::vector<core::memory::pointer_chain_result_t> chains;
    core::memory::pointer_scan_stats_t                stats;
};

value_width_t g_width       = value_width_t::u32;
int           g_width_idx   = 5;             // {i8..f64, all}
int           g_kind_idx    = 1;             // first: {exact, unknown}; next: CE set
int           g_round_idx   = 0;             // {exact, rounded, truncated, extreme}
char          g_value_buf[48] = {};
char          g_value2_buf[48] = {};
int           g_alignment   = 1;             // index into {1,4,8}, CE default 4

uint64_t                    g_job_id  = 0;
uint64_t                    g_passes  = 0;
std::shared_ptr<scan_state_t> g_scan;

uint64_t                       g_pjob_id = 0;
char                           g_ptarget_buf[32] = {};
int                            g_pdepth   = 3 - 1; // index
int                            g_pmin_off = -4096;
int                            g_pmax_off = 4096;
int                            g_palign_idx = 2;   // {1,4,8}
bool                           g_pstatic = false;
std::shared_ptr<pointer_shared_t> g_pscan;

struct watch_entry_t {
    uint64_t      id;
    uintptr_t     addr;
    value_width_t width;
    std::string   label;
    bool          freeze;
    uint64_t      frozen_bits;
};
std::vector<watch_entry_t> g_watch;
uint64_t                   g_watch_next_id = 1;
int64_t                    g_last_freeze_ms = 0;

constexpr value_width_t kWidths[] = {
    value_width_t::i8, value_width_t::u8,
    value_width_t::i16, value_width_t::u16,
    value_width_t::i32, value_width_t::u32,
    value_width_t::i64, value_width_t::u64,
    value_width_t::f32, value_width_t::f64
};

constexpr int kAlignments[] = { 1, 4, 8 };

using session_ref_t = std::shared_ptr<runtime::session_t>;
void DrawWatchTable(const session_ref_t& session);
void DrawPointerScan(const session_ref_t& session);

// First-pass kinds (CE): exact value / unknown initial value
constexpr scan_type_t kFirstKinds[] = {
    scan_type_t::exact_value, scan_type_t::unknown_initial
};
// Next-scan kinds: the CE filter set
constexpr scan_type_t kNextKinds[] = {
    scan_type_t::exact_value,
    scan_type_t::increased,
    scan_type_t::increased_by,
    scan_type_t::decreased,
    scan_type_t::decreased_by,
    scan_type_t::changed,
    scan_type_t::unchanged
};

// Operand requirements per kind (first and next sets)
bool kind_needs_value(scan_type_t k) noexcept {
    switch (k) {
    case scan_type_t::increased:
    case scan_type_t::decreased:
    case scan_type_t::changed:
    case scan_type_t::unchanged:
    case scan_type_t::unknown_initial:
        return false;
    default:
        return true;
    }
}

bool kind_needs_value2(scan_type_t k) noexcept {
    return k == scan_type_t::between;
}

scan_type_t KindForPass(int idx, bool first) noexcept {
    if (first) return kFirstKinds[idx & 1];
    return kNextKinds[std::clamp(idx, 0, 6)];
}

void AddWatch(uintptr_t addr, value_width_t w) {
    if (g_watch.size() >= infra::limits::max_watch_entries) return;
    watch_entry_t e;
    e.id    = g_watch_next_id++;
    e.addr  = addr;
    e.width = w;
    e.label = std::to_string(addr);
    e.freeze = false;
    e.frozen_bits = 0;
    g_watch.push_back(std::move(e));
}

// Build the CE scan config from the UI widgets
bool BuildConfig(scan_config_t& cfg, scan_type_t kind) {
    cfg.type  = kind;
    cfg.width = g_width;
    cfg.scan_all_types = (g_width_idx == 10);
    switch (g_round_idx) {
    case 1: cfg.rounding = rounding_t::rounded;   break;
    case 2: cfg.rounding = rounding_t::truncated; break;
    case 3: cfg.rounding = rounding_t::extreme;   break;
    default: cfg.rounding = rounding_t::exact;    break;
    }
    cfg.fast = core::memory::fastscan_method_t::alignment;
    cfg.fast_alignment = static_cast<uint32_t>(kAlignments[g_alignment]);
    cfg.max_results = infra::limits::max_scan_hits;

    if (kind_needs_value(kind)) {
        uint64_t bits = 0;
        if (!core::memory::parse_value_text(g_width,
                std::string_view{g_value_buf}, bits))
            return false;
        cfg.value1 = core::memory::value_to_double(g_width, bits);
        cfg.float_accuracy =
            core::memory::float_accuracy_from_text(g_value_buf);
        if (kind_needs_value2(kind)) {
            uint64_t bits2 = 0;
            if (!core::memory::parse_value_text(g_width,
                    std::string_view{g_value2_buf}, bits2))
                return false;
            cfg.value2 = core::memory::value_to_double(g_width, bits2);
        }
    }
    return true;
}

// Watchlist

void DrawWatchTable(const session_ref_t& session) {
    if (!ImGui::CollapsingHeader("watchlist", ImGuiTreeNodeFlags_DefaultOpen)) return;

    if (!session || !session->valid()) {
        ImGui::TextDisabled("no target.");
        return;
    }

    static constexpr int kMaxLiveReads = 64;

    if (ImGui::BeginTable("watch", 5,
                          ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                              ImGuiTableFlags_ScrollY)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 130.0f);
        ImGui::TableSetupColumn("type", ImGuiTableColumnFlags_WidthFixed, 50.0f);
        ImGui::TableSetupColumn("value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
        ImGui::TableSetupColumn("freeze", ImGuiTableColumnFlags_WidthFixed, 60.0f);
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30.0f);
        ImGui::TableHeadersRow();

        int reads = 0;
        int row = 0;
        for (auto it = g_watch.begin(); it != g_watch.end(); ++row) {
            watch_entry_t& e = *it;

            uint64_t bits = 0;
            bool have_value = false;
            const size_t n = core::memory::value_size(e.width);
            if (reads < kMaxLiveReads &&
                session->read(e.addr, &bits, n).ok) {
                ++reads;
                have_value = true;
            }
            if (!e.freeze && have_value) e.frozen_bits = bits; // track while unfrozen

            ImGui::PushID(static_cast<int>(e.id));
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            char a[24];
            std::snprintf(a, sizeof(a), "%012llX", static_cast<unsigned long long>(e.addr));
            ImGui::TextUnformatted(a);
            ImGui::TableNextColumn();
            ImGui::TextUnformatted(WidthName(e.width));
            ImGui::TableNextColumn();
            if (!e.freeze && have_value)
                ImGui::TextUnformatted(core::memory::format_value_text(e.width, bits).c_str());
            else if (e.freeze)
                ImGui::Text("%s *", core::memory::format_value_text(e.width, e.frozen_bits).c_str());
            else
                ImGui::TextDisabled("-");
            ImGui::TableNextColumn();
            if (ImGui::Checkbox("##fz", &e.freeze)) {
                if (e.freeze) e.frozen_bits = have_value ? bits : e.frozen_bits;
                panels::AppendBootLog(e.freeze ? "freeze ON @ " + e.label
                                               : "freeze OFF @ " + e.label);
            }
            ImGui::TableNextColumn();
            if (ImGui::SmallButton("x")) it = g_watch.erase(it);
            else ++it;
            ImGui::PopID();
        }
        (void)row;
        ImGui::EndTable();
    }
}

// Pointer scan

void DrawPointerScan(const session_ref_t& session) {
    if (!ImGui::CollapsingHeader("pointer scan")) return;

    const bool running = g_pjob_id != 0 && infra::jobs::alive(g_pjob_id);

    ImGui::SetNextItemWidth(150.0f);
    ImGui::InputTextWithHint("target", "address (hex)", g_ptarget_buf, sizeof(g_ptarget_buf));
    ImGui::SameLine();
    ImGui::SetNextItemWidth(60.0f);
    ImGui::SliderInt("depth", &g_pdepth, 1, infra::limits::max_pointer_depth);
    ImGui::SetNextItemWidth(110.0f);
    ImGui::InputInt("min off", &g_pmin_off);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(110.0f);
    ImGui::InputInt("max off", &g_pmax_off);
    ImGui::SameLine();
    ImGui::Checkbox("static roots", &g_pstatic);

    if (!session || !session->valid()) {
        ImGui::TextDisabled("no target.");
        return;
    }

    if (running) {
        if (ImGui::Button("Cancel")) infra::jobs::cancel(g_pjob_id);
        ImGui::SameLine();
        ImGui::TextUnformatted("scanning...");
    } else if (ImGui::Button("Run Pointer Scan")) {
        uintptr_t target = 0;
        std::vector<uint8_t> out;
        std::string err;
        if (infra::fmt::parse_hex(g_ptarget_buf, out, err) && !out.empty() && out.size() <= 8) {
            for (uint8_t b : out) target = (target << 8) | b;
        }
        if (target == 0) {
            panels::AppendBootLog("pointer scan: bad target address");
        } else {
            g_pscan = std::make_shared<pointer_shared_t>();
            auto handle = session->handle();

            core::memory::pointer_scan_options_t popt;
            popt.target      = target;
            popt.depth       = static_cast<uint32_t>(g_pdepth);
            popt.min_offset  = g_pmin_off;
            popt.max_offset  = g_pmax_off;
            popt.alignment   = static_cast<uint32_t>(kAlignments[g_palign_idx]);
            popt.only_module_backed = g_pstatic;

            infra::job_desc_t d;
            d.label = "pointer scan";
            d.owner = "scanner";
            d.cancellable = true;
            d.body = [handle, popt](infra::job_context_t& ctx) {
                runtime::backend_reader_t r(runtime::active(), handle);
                auto regions = runtime::target_scan_regions(handle);

                core::memory::pointer_scan_stats_t total{};
                auto chains = core::memory::pointer_scan(r, regions, popt,
                                                         ctx.cancel(), &total);
                total.cancelled = ctx.cancelled();

                std::lock_guard<std::mutex> lk(g_pscan->mu);
                g_pscan->chains = std::move(chains);
                g_pscan->stats = total;
            };
            g_pjob_id = infra::jobs::submit(d);
        }
    }

    if (g_pscan) {
        std::vector<core::memory::pointer_chain_result_t> view_copy;
        {
            std::lock_guard<std::mutex> lk(g_pscan->mu);
            view_copy.assign(g_pscan->chains.begin(),
                             g_pscan->chains.begin() +
                                 std::min<size_t>(g_pscan->chains.size(), 200));
        }
        if (!view_copy.empty()) {
            ImFont* mono = fonts::Get().mono;
            if (mono) ImGui::PushFont(mono);
            for (const auto& c : view_copy) {
                std::string line;
                for (size_t i = 0; i < c.addresses.size(); ++i) {
                    char hop[48];
                    std::snprintf(hop, sizeof(hop), "[%llX %+lld]",
                        static_cast<unsigned long long>(c.addresses[i]),
                        static_cast<long long>(c.offsets[i]));
                    line += hop;
                    line += (i + 1 < c.addresses.size()) ? " -> " : " -> TARGET";
                }
                ImGui::TextUnformatted(line.c_str());
            }
            if (mono) ImGui::PopFont();
        }
    }
}

} // namespace

namespace scanner_view {

void Tick() {
    if (g_watch.empty()) return;
    const auto session = process::active_session();
    if (!session || !session->valid()) return;

    const int64_t now = infra::steady_ms();
    if (now - g_last_freeze_ms < 100) return; // ~10 Hz refresh of frozen values
    g_last_freeze_ms = now;

    for (const auto& e : g_watch) {
        if (!e.freeze) continue;
        const size_t n = core::memory::value_size(e.width);
        session->write(e.addr, &e.frozen_bits, n); // little-endian truncation by size
    }
}

void Draw() {
    ImFont* mono = fonts::Get().mono;
    const bool pushed = mono != nullptr;
    if (pushed) ImGui::PushFont(mono);

    const auto session = process::active_session();
    const bool attached = session && session->valid();

    // Config row
    ImGui::SetNextItemWidth(70.0f);
    if (ImGui::Combo("width", &g_width_idx,
                     "i8\0u8\0i16\0u16\0i32\0u32\0i64\0u64\0f32\0f64\0all\0")) {
        g_width = (g_width_idx <= 9) ? kWidths[g_width_idx] : value_width_t::u32;
    }
    ImGui::SameLine();

    const bool has_state = g_scan && g_scan->has;
    const bool scanning = g_job_id != 0 && infra::jobs::alive(g_job_id);

    if (!has_state) {
        ImGui::SetNextItemWidth(130.0f);
        ImGui::Combo("kind", &g_kind_idx, "exact\0unknown initial\0");
    } else {
        ImGui::SetNextItemWidth(130.0f);
        ImGui::Combo("kind", &g_kind_idx,
                     "exact\0increased\0increased by\0decreased\0"
                     "decreased by\0changed\0unchanged\0");
    }
    ImGui::SameLine();

    ImGui::SetNextItemWidth(150.0f);
    ImGui::InputText("value", g_value_buf, sizeof(g_value_buf));
    ImGui::SameLine();

    ImGui::SetNextItemWidth(60.0f);
    ImGui::Combo("align", &g_alignment, "1\0 4\0 8\0");
    ImGui::SameLine();

    // Float rounding selector (CE rounding types), only meaningful for floats
    if (g_width == value_width_t::f32 || g_width == value_width_t::f64) {
        ImGui::SetNextItemWidth(110.0f);
        ImGui::Combo("rounding", &g_round_idx,
                     "exact\0rounded\0truncated\0extreme\0");
        ImGui::SameLine();
    }

    // Action buttons
    const scan_type_t kind_now = KindForPass(g_kind_idx, !has_state);
    scan_config_t cfg;
    const bool value_ok = BuildConfig(cfg, kind_now);

    if (!attached) {
        ImGui::TextDisabled("attach a target first.");
        if (pushed) ImGui::PopFont();
        DrawWatchTable(session);
        return;
    }

    if (!scanning) {
        if (!has_state) {
            if (ImGui::Button("First Scan") && value_ok) {
                g_scan = std::make_shared<scan_state_t>();
                auto handle = session->handle();
                const auto config = cfg;

                infra::job_desc_t d;
                d.label = "scan: first pass (CE engine)";
                d.owner = "scanner";
                d.cancellable = true;
                d.body = [handle, config](infra::job_context_t& ctx) {
                    runtime::backend_reader_t r(runtime::active(), handle);
                    auto regions = runtime::target_scan_regions(handle);
                    std::string err;
                    g_scan->engine.first_scan(r, std::move(regions), config,
                                              ctx.cancel(), &err);
                    if (!err.empty())
                        panels::AppendBootLog("scan: " + err);

                    std::lock_guard<std::mutex> lk(g_scan->mu);
                    g_scan->stats = g_scan->engine.stats();
                    const auto& res = g_scan->engine.results();
                    g_scan->view.assign(res.begin(),
                                        res.begin() + std::min<size_t>(res.size(), 500));
                    g_scan->has = g_scan->engine.has_results();
                };
                g_job_id = infra::jobs::submit(d);
                ++g_passes;
            }
        } else if (ImGui::Button("Next Scan") && value_ok) {
            auto handle = session->handle();
            const auto config = cfg;

            infra::job_desc_t d;
            d.label = "scan: next pass (CE engine)";
            d.owner = "scanner";
            d.cancellable = true;
            d.body = [handle, config](infra::job_context_t& ctx) {
                runtime::backend_reader_t r(runtime::active(), handle);
                std::string err;
                g_scan->engine.next_scan(r, config, ctx.cancel(), &err);
                if (!err.empty())
                    panels::AppendBootLog("scan: " + err);

                std::lock_guard<std::mutex> lk(g_scan->mu);
                g_scan->stats = g_scan->engine.stats();
                const auto& res = g_scan->engine.results();
                g_scan->view.assign(res.begin(),
                                    res.begin() + std::min<size_t>(res.size(), 500));
                g_scan->has = g_scan->engine.has_results();
            };
            g_job_id = infra::jobs::submit(d);
            ++g_passes;
        }
        ImGui::SameLine();
        if (ImGui::Button("Reset")) {
            g_scan.reset();
            g_passes = 0;
            g_job_id = 0;
        }
    } else {
        if (ImGui::Button("Cancel")) infra::jobs::cancel(g_job_id);
        ImGui::SameLine();

        // Live progress from the engine atomics
        char prog[96];
        std::snprintf(prog, sizeof(prog), "scanning... %llu MB, %llu found",
            static_cast<unsigned long long>(
                g_scan->engine.progress().bytes.load() >> 20),
            static_cast<unsigned long long>(
                g_scan->engine.progress().found.load()));
        ImGui::TextUnformatted(prog);
    }

    ImGui::SameLine();
    ImGui::TextDisabled("pass %llu%s", static_cast<unsigned long long>(g_passes),
                        has_state ? "" : " (empty)");

    // Results
    if (g_scan) {
        std::vector<scan_result_t> view_copy;
        core::memory::scan_stats_t st{};
        {
            std::lock_guard<std::mutex> lk(g_scan->mu);
            view_copy = g_scan->view;
            st = g_scan->stats;
        }

        char head[128];
        std::snprintf(head, sizeof(head),
                      "hits: %zu%s  (%.1f MB scanned%s)",
                      st.found, st.truncated ? " (truncated)" : "",
                      static_cast<double>(st.bytes_scanned) / (1024.0 * 1024.0),
                      st.cancelled ? ", cancelled" : "");
        ImGui::TextUnformatted(head);

        if (g_scan->engine.region_scan_active() && !scanning) {
            ImGui::TextDisabled("region scan active: %zu bytes tracked, "
                                "run a next scan (increased/decreased/...) "
                                "to build the address list",
                                st.slots_tracked);
        }

        if (ImGui::BeginTable("scanres", 3,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                  ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableSetupColumn("address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("value", ImGuiTableColumnFlags_WidthStretch, 1.0f);
            ImGui::TableSetupColumn("+watch", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableHeadersRow();

            for (const auto& h : view_copy) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                char addr_s[24];
                std::snprintf(addr_s, sizeof(addr_s), "%012llX",
                              static_cast<unsigned long long>(h.address));
                ImGui::Selectable(addr_s);
                ImGui::TableNextColumn();
                char val_s[64];
                std::snprintf(val_s, sizeof(val_s), "%s  (%s)",
                              core::memory::format_value_text(h.matched, h.bits).c_str(),
                              WidthName(h.matched));
                ImGui::TextUnformatted(val_s);
                ImGui::TableNextColumn();
                ImGui::PushID(static_cast<int>(h.address & 0xFFFFFF));
                if (ImGui::SmallButton("add")) AddWatch(h.address, h.matched);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
    }

    ImGui::Separator();
    DrawPointerScan(session);
    ImGui::Separator();
    DrawWatchTable(session);

    if (pushed) ImGui::PopFont();
}

} // namespace scanner_view
} // namespace slop::ui
