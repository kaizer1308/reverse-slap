#include "analyzer.h"
#include "core/disasm/disassembler.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <algorithm>
#include <chrono>
#include <queue>
#include <unordered_set>
#include <cstring>
#include <Zydis/Zydis.h>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#else
#include <cxxabi.h>
#endif

namespace hype {

namespace {
u32 operand_size_bytes(const Operand& op, u32 fallback) {
    return op.size ? (static_cast<u32>(op.size) + 7) / 8 : fallback;
}

bool is_stack_register(u16 reg) {
    switch (static_cast<ZydisRegister>(reg)) {
    case ZYDIS_REGISTER_SP:
    case ZYDIS_REGISTER_ESP:
    case ZYDIS_REGISTER_RSP:
    case ZYDIS_REGISTER_BP:
    case ZYDIS_REGISTER_EBP:
    case ZYDIS_REGISTER_RBP:
        return true;
    default:
        return false;
    }
}

std::string demangle(const std::string& name) {
    if (name.empty()) return name;
#ifdef _WIN32
    if (name[0] == '?' || name[0] == '@') {
        char buf[1024];
        DWORD result = UnDecorateSymbolName(name.c_str(), buf, sizeof(buf),
            UNDNAME_COMPLETE | UNDNAME_NO_ACCESS_SPECIFIERS | UNDNAME_NO_ALLOCATION_MODEL);
        if (result > 0)
            return buf;
    }
#else
    if (name.size() > 2 && name[0] == '_' && name[1] == 'Z') {
        int status = 0;
        char* demangled = abi::__cxa_demangle(name.c_str(), nullptr, nullptr, &status);
        if (status == 0 && demangled) {
            std::string result(demangled);
            std::free(demangled);
            return result;
        }
    }
#endif
    if (name.size() > 1 && name[0] == '_' && name[1] != '_')
        return name.substr(1);
    return name;
}
}

Analyzer::Analyzer(PEImage& img, WorkerPool& pool)
    : img_(img), pool_(pool), sched_(pool) {
    disasm_.set_arch(img.arch);
    cap_disasm_.set_arch(img.arch);
    db_.image_base = img.base;
    db_.arch = img.arch;
    build_segment_index();
}

void Analyzer::build_segment_index() {
    segment_index_.clear();
    segment_index_.reserve(img_.segments.size());
    for (const auto& seg : img_.segments) {
        if (seg.size == 0) continue;
        segment_index_.push_back({seg.va, seg.va + seg.size, &seg, seg.executable()});
    }
    std::sort(segment_index_.begin(), segment_index_.end(),
              [](const SegmentSpan& a, const SegmentSpan& b) { return a.va < b.va; });
}

const Analyzer::SegmentSpan* Analyzer::span_for(va_t addr) const {
    // greatest span with va <= addr, then one containment test
    auto it = std::upper_bound(segment_index_.begin(), segment_index_.end(), addr,
                               [](va_t value, const SegmentSpan& span) { return value < span.va; });
    if (it == segment_index_.begin()) return nullptr;
    --it;
    return addr < it->end ? &*it : nullptr;
}

const u8* Analyzer::va_to_ptr(va_t addr, size_t* max_len) {
    const SegmentSpan* span = span_for(addr);
    if (!span) return nullptr;
    const size_t off = static_cast<size_t>(addr - span->va);
    if (off >= span->seg->data.size()) return nullptr;
    if (max_len) *max_len = span->seg->data.size() - off;
    return span->seg->data.data() + off;
}

bool Analyzer::over_budget() {
    if (insn_budget_ == 0) return false;
    std::lock_guard lk(descend_mu_);
    if (db_.insns.size() < insn_budget_) return false;
    if (!budget_hit_.exchange(true, std::memory_order_relaxed))
        spdlog::warn("analysis: instruction budget of {} reached, "
                     "the database covers part of the image", insn_budget_);
    return true;
}

bool Analyzer::is_iat_addr(va_t addr) const {
    for (auto& imp : img_.imports)
        if (imp.iat_addr == addr) return true;
    return false;
}

bool Analyzer::is_code_addr(va_t addr) const {
    const SegmentSpan* span = span_for(addr);
    return span && span->executable;
}

bool Analyzer::in_section(va_t addr, const char* name) const {
    const SegmentSpan* span = span_for(addr);
    return span && span->seg->name == name;
}

const Segment* Analyzer::section_for(va_t addr) const {
    const SegmentSpan* span = span_for(addr);
    return span ? span->seg : nullptr;
}

void Analyzer::run() {
    spdlog::info("analysis: starting");
    progress_ = 0.0f;

    // Per-phase wall clock, so a slow image says which phase is slow instead
    // of just taking a long time. Logged at debug, the totals at info.
    const auto run_start = std::chrono::steady_clock::now();
    auto phase_mark = run_start;
    const auto phase = [&phase_mark](const char* name) {
        const auto now = std::chrono::steady_clock::now();
        spdlog::debug("analysis phase {}: {:.1f} ms", name,
                      std::chrono::duration<double, std::milli>(now - phase_mark).count());
        phase_mark = now;
    };

    // phase sequence bail. Checked between every phase and inside the
    // long walk (descend).
    const auto bail = [this] {
        if (!cancel_.load(std::memory_order_relaxed)) return false;
        cancelled_.store(true, std::memory_order_relaxed);
        spdlog::warn("analysis: cancelled by request");
        return true;
    };

    recursive_descent();   phase("recursive_descent"); if (bail()) return; progress_ = 0.25f;
    detect_functions();    phase("detect_functions"); if (bail()) return; progress_ = 0.38f;
    rtti_.parse(img_, db_); phase("rtti_parse"); if (bail()) return;
    // Share the visited set across every RTTI descend call. The old code
    // reset it per-method, so on huge binaries (300MB UE builds) we would
    // re-decode the entire reachable graph tens of thousands of times.
    // Skip descend outright when the method entry already has an insn
    // decoded — .pdata + call-target discovery already covered it.
    {
        std::unordered_set<va_t> rtti_visited;
        const auto& classes = rtti_.classes();
        // Serial pass: function records are cheap, and pre-filtering methods
        // whose body is already decoded keeps the parallel pass dense.
        // (Collected methods stay unmarked: descend() claims them through
        // the shared visited set itself.)
        std::unordered_set<va_t> seen;
        std::vector<va_t> methods;
        for (const auto& cls : classes) {
            for (va_t method : cls.methods) {
                if (!db_.funcs.count(method)) {
                    Function function;
                    function.entry = method;
                    auto name = db_.names.find(method);
                    function.name = name != db_.names.end() ? name->second : fmt::format("sub_{:X}", method - img_.base);
                    db_.add_func(std::move(function));
                }
                if (db_.insns.count(method)) continue;
                if (!seen.insert(method).second) continue;
                methods.push_back(method);
            }
        }
        std::atomic<size_t> methods_done{0};
        parallel_for(pool_, methods.size(), [&](size_t i) {
            if (cancel_.load(std::memory_order_relaxed)) return;
            descend(methods[i], rtti_visited);
            const size_t done = methods_done.fetch_add(1) + 1;
            // slide progress from 0.38 -> 0.41 as methods are consumed
            progress_ = 0.38f + 0.03f * (static_cast<float>(done) / static_cast<float>(methods.size()));
        });
        if (bail()) return;
    }
    phase("rtti_descend");

    detect_thunks();       phase("detect_thunks"); if (bail()) return; progress_ = 0.42f;

    sigmatch_.match_functions(db_, img_);
    phase("signatures");
    if (bail()) return;    progress_ = 0.45f;

    discover_cfg_fixed_point(); phase("cfg_fixed_point"); if (bail()) return; progress_ = 0.62f;
    build_xrefs();         phase("build_xrefs"); if (bail()) return; progress_ = 0.72f;
    find_strings();        phase("find_strings"); if (bail()) return; progress_ = 0.78f;
    find_string_refs();    phase("find_string_refs"); if (bail()) return; progress_ = 0.82f;
    detect_vtables();      phase("detect_vtables"); if (bail()) return; progress_ = 0.85f;
    detect_globals();      phase("detect_globals"); if (bail()) return; progress_ = 0.88f;
    detect_noreturn();     phase("detect_noreturn"); if (bail()) return; progress_ = 0.87f;
    detect_tail_calls();   phase("detect_tail_calls"); if (bail()) return; progress_ = 0.89f;
    detect_calling_conventions(); phase("callconv"); if (bail()) return; progress_ = 0.91f;
    detect_loops();        phase("detect_loops"); if (bail()) return; progress_ = 0.95f;
    recover_structs();     phase("recover_structs"); if (bail()) return; progress_ = 0.97f;
    propagate_interproc_types(); phase("interproc_types"); if (bail()) return; progress_ = 0.98f;
    populate_data_sections();    phase("populate_data"); if (bail()) return; progress_ = 0.99f;
    apply_names();         phase("apply_names"); if (bail()) return; progress_ = 0.99f;
    detect_main();         phase("detect_main"); if (bail()) return; progress_ = 0.995f;

    rtti_.parse(img_, db_);
    phase("rtti_parse2");
    if (bail()) return;
    progress_ = 1.0f;

    spdlog::info("analysis: total {:.1f} ms",
                 std::chrono::duration<double, std::milli>(
                     std::chrono::steady_clock::now() - run_start).count());
    spdlog::info("analysis: done - {} insns, {} funcs, {} xrefs, {} strings, {} vtables, {} globals, {} resolved_indirect",
                 db_.insns.size(), db_.funcs.size(), db_.xrefs.size(),
                 db_.strings.size(), db_.vtables.size(), db_.globals.size(),
                 db_.resolved_indirect.size());
}

void Analyzer::recursive_descent() {
    size_t total_exec_bytes = 0;
    for (const auto& seg : img_.segments) {
        if (seg.executable()) total_exec_bytes += seg.size;
    }
    size_t est_insns = total_exec_bytes / 4;
    if (insn_budget_ && est_insns > insn_budget_) est_insns = insn_budget_;
    if (est_insns > 0) db_.insns.reserve(est_insns);

    // Roots are independent work items sharing one visited set: whichever
    // worker pops an address first claims it, so the decoded set is the
    // same as the serial run while decode itself fans out.
    std::vector<va_t> roots;
    roots.push_back(img_.entry);
    for (auto& exp : img_.exports)
        if (!exp.forwarded && is_code_addr(exp.addr)) roots.push_back(exp.addr);
    for (auto& runtime : img_.runtime_funcs)
        roots.push_back(runtime.start);

    std::unordered_set<va_t> visited;
    // Serial root loop: the overlap pruning inside descend_queue already
    // skips re-decoding covered ranges, and the instruction-map inserts
    // serialize through one lock anyway — fanning the roots out only adds
    // redundant decode plus lock contention (measured slower, not faster).
    for (va_t root : roots) descend(root, visited);
}

void Analyzer::descend(va_t addr, std::unordered_set<va_t>& visited) {
    if (over_budget()) return;

    std::queue<va_t> wl;
    wl.push(addr);
    descend_queue(wl, visited);
}

void Analyzer::descend_queue(std::queue<va_t>& wl,
                             std::unordered_set<va_t>& visited) {
    // Batched inserts: one lock per 128 instructions instead of one per
    // instruction. Overlapping walks may buffer the same address twice;
    // decode is deterministic so the overwrite is identical content.
    std::vector<std::pair<va_t, Insn>> pending;
    pending.reserve(128);
    auto flush = [&] {
        if (pending.empty()) return;
        std::lock_guard lk(descend_mu_);
        for (auto& [addr, insn] : pending) db_.insns.insert_or_assign(addr, insn);
        pending.clear();
    };

    size_t since_hit_check = 0;

    while (!wl.empty()) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        va_t cur = wl.front(); wl.pop();
        {
            std::lock_guard lk(descend_mu_);
            if (!visited.insert(cur).second) continue;
            if (!is_code_addr(cur)) continue;
        }

        size_t max_len = 0;
        const u8* ptr = va_to_ptr(cur, &max_len);
        if (!ptr || !max_len) continue;

        size_t off = 0;
        while (off < max_len) {
            Insn insn{};
            const va_t insn_addr = cur + off;
            if (!decode_insn(insn_addr, ptr + off, max_len - off, insn)) {
                break;
            }
            // Prune redundant overlap: another walk already decoded this
            // address, and decode is deterministic, so that walk covers our
            // suffix exactly — stopping loses nothing. Checked throttled;
            // our own buffered addresses are never in the map yet, so a hit
            // always means another worker's coverage.
            if (++since_hit_check >= 32) {
                since_hit_check = 0;
                bool covered = false;
                {
                    std::lock_guard lk(descend_mu_);
                    covered = db_.insns.count(insn_addr) != 0;
                }
                if (covered) break;
            }
            pending.emplace_back(insn.addr, insn);
            if (pending.size() >= 128) {
                flush();
                if (over_budget()) return;
            }
            off += insn.len;

            if (insn.is_ret()) break;
            if (insn.is_call()) {
                va_t t = insn.branch_target();
                if (t) {
                    bool known = false;
                    {
                        std::lock_guard lk(descend_mu_);
                        known = visited.count(t) != 0;
                    }
                    if (!known) wl.push(t);
                }
            }
            if (insn.is_branch()) {
                va_t t = insn.branch_target();
                if (t) {
                    bool known = false;
                    {
                        std::lock_guard lk(descend_mu_);
                        known = visited.count(t) != 0;
                    }
                    if (!known) wl.push(t);
                }
                if (insn.type == InsnType::Jmp) break;
            }
        }
        flush();
    }
    flush();
}

void Analyzer::detect_functions() {
    std::unordered_set<va_t> entries;
    entries.insert(img_.entry);
    for (auto& exp : img_.exports)
        if (!exp.forwarded && is_code_addr(exp.addr)) entries.insert(exp.addr);

    // .pdata runtime functions — most reliable source for x64. Once the budget
    // has bitten, most of them have no decoded body behind them, and a few
    // hundred thousand empty Function records is a lot of memory spent on
    // nothing, so take only the ones descent actually reached
    const bool truncated = budget_reached();
    for (auto& rf : img_.runtime_funcs) {
        if (truncated && !db_.insns.count(rf.start)) continue;
        entries.insert(rf.start);
    }

    // call targets reached from confirmed code only. Snapshot first: the
    // scan is read-only and fans out, the set merge stays serial.
    std::vector<const Insn*> all_insns;
    all_insns.reserve(db_.insns.size());
    for (auto& [addr, insn] : db_.insns) all_insns.push_back(&insn);
    std::vector<va_t> call_targets(all_insns.size(), 0);
    parallel_for(pool_, all_insns.size(), [&](size_t i) {
        const Insn& insn = *all_insns[i];
        if (!insn.is_call()) return;
        va_t t = insn.branch_target();
        if (t && db_.insns.count(t)) call_targets[i] = t;
    });
    for (va_t t : call_targets)
        if (t) entries.insert(t);

    for (va_t e : entries) {
        Function func;
        func.entry = e;
        func.name = fmt::format("sub_{:X}", e - img_.base);
        db_.add_func(std::move(func));
    }

    // apply known end addresses from .pdata
    for (auto& rf : img_.runtime_funcs) {
        auto it = db_.funcs.find(rf.start);
        if (it != db_.funcs.end() && rf.end > rf.start)
            it->second.ranges.emplace_back(rf.start, rf.end);
    }

    spdlog::info("detected {} functions", db_.funcs.size());
}

void Analyzer::detect_thunks() {
    // Look for jmp [rip+disp32] (FF 25 xx xx xx xx) at function entries
    // that target IAT addresses — label them with the import name
    std::unordered_map<va_t, std::string> iat_names;
    for (auto& imp : img_.imports)
        iat_names[imp.iat_addr] = imp.name;

    u32 found = 0;
    std::atomic<u32> found_atomic{0};
    // Section shards are independent (writes go through the DB's own locks).
    parallel_for(pool_, img_.segments.size(), [&](size_t s) {
        const auto& seg = img_.segments[s];
        if (!seg.executable() || seg.data.empty()) return;
        const u8* data = seg.data.data();
        size_t sz = seg.data.size();

        for (size_t i = 0; i + 6 <= sz; ++i) {
            if (data[i] != 0xFF || data[i + 1] != 0x25) continue;

            va_t insn_addr = seg.va + i;
            i32 disp = 0;
            std::memcpy(&disp, data + i + 2, 4);
            va_t target = insn_addr + 6 + disp;

            auto it = iat_names.find(target);
            if (it == iat_names.end()) continue;

            // Structural funcs access serializes here; the byte scan above
            // stays parallel and hits are rare.
            {
                std::lock_guard lk(funcs_mu_);
                if (!db_.funcs.count(insn_addr)) {
                    Function func;
                    func.entry = insn_addr;
                    func.name = it->second;
                    db_.add_func(std::move(func));
                } else {
                    db_.funcs[insn_addr].name = it->second;
                }
            }
            db_.set_name(insn_addr, it->second);
            ++found_atomic;
        }
    });
    found = found_atomic.load();
    spdlog::info("detected {} import thunks", found);
}

void Analyzer::remove_junk_code() {
    // collect all addresses that belong to a function's CFG
    std::unordered_set<va_t> in_func;
    for (auto& [entry, func] : db_.funcs) {
        for (auto& [ba, bb] : func.blocks) {
            va_t cur = bb.start;
            while (cur < bb.end) {
                in_func.insert(cur);
                auto it = db_.insns.find(cur);
                if (it == db_.insns.end()) break;
                cur += it->second.len;
            }
        }
    }

    // remove instructions not in any function that are clearly junk:
    // - null bytes (00 00 = add [rax], al)
    // - int3 padding (CC)
    // - nop padding (90)
    // - sequences of identical 2-byte instructions (padding patterns)
    std::vector<va_t> to_remove;
    for (auto& [addr, insn] : db_.insns) {
        if (in_func.count(addr)) continue;

        bool junk = false;
        if (insn.len <= 2 && insn.bytes[0] == 0x00 && (insn.len == 1 || insn.bytes[1] == 0x00))
            junk = true;
        if (insn.len == 1 && insn.bytes[0] == 0xCC)
            junk = true;
        if (insn.len == 1 && insn.bytes[0] == 0x90)
            junk = true;

        if (junk) to_remove.push_back(addr);
    }

    for (va_t a : to_remove)
        db_.insns.erase(a);

    spdlog::info("removed {} junk instructions", to_remove.size());
}

void Analyzer::build_cfgs(const std::unordered_set<va_t>* only) {
    // Snapshot the scope first: workers mutate their own Function's blocks
    // while the map structure stays fixed (no inserts/erases in this phase).
    std::vector<Function*> scope;
    scope.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (only && !only->count(entry)) continue;
        func.blocks.clear();
        func.block_addrs.clear();
        func.analyzed = false;
        scope.push_back(&func);
    }
    parallel_for(pool_, scope.size(), [&](size_t i) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        build_one_cfg(*scope[i]);
    });
}

void Analyzer::build_one_cfg(Function& func) {
    const va_t entry = func.entry;
    {
        std::unordered_set<va_t> visited;
        std::queue<va_t> wl;
        wl.push(entry);

        while (!wl.empty()) {
            va_t bb_start = wl.front(); wl.pop();
            if (visited.count(bb_start)) continue;
            visited.insert(bb_start);

            BasicBlock bb;
            bb.start = bb_start;
            va_t cur = bb_start;

            for (;;) {
                const auto found = db_.insns.find(cur);
                if (found == db_.insns.end()) break;
                if (!func.ranges.empty()) {
                    bool in_range = false;
                    for (const auto& [start, end] : func.ranges)
                        if (cur >= start && cur < end) { in_range = true; break; }
                    if (!in_range) break;
                }
                auto& insn = found->second;
                bb.insns.push_back(insn);
                cur += insn.len;

                if (insn.is_ret()) break;
                if (insn.type == InsnType::Jmp) {
                    va_t t = insn.branch_target();
                    if (t) { bb.succs.push_back(t); wl.push(t); }
                    const auto recovered = recovered_edges_.find(insn.addr);
                    if (recovered != recovered_edges_.end())
                        for (va_t target : recovered->second) {
                            bb.succs.push_back(target);
                            wl.push(target);
                        }
                    break;
                }
                if (insn.is_cond_jmp()) {
                    va_t t = insn.branch_target();
                    if (t) { bb.succs.push_back(t); wl.push(t); }
                    bb.succs.push_back(cur); wl.push(cur);
                    break;
                }
                if (cur != entry && db_.funcs.count(cur)) break;
            }

            bb.end = cur;
            // push_back doubles, so a block can carry up to its own size again
            // in slack; across millions of instructions that is gigabytes
            bb.insns.shrink_to_fit();
            // Queued addresses with no decoded instruction (an unreached
            // .pdata entry, a branch into padding) yield empty blocks with
            // end == start. They carry no instructions and, by construction
            // above, no successors either, so drop them instead of
            // publishing zero-length ranges to the blocks APIs. Every succ
            // consumer already guards its block lookups.
            if (bb.insns.empty()) continue;
            func.block_addrs.push_back(bb.start);
            func.blocks[bb.start] = std::move(bb);
        }
    }

    for (auto& [ba, block] : func.blocks) {
        std::sort(block.succs.begin(), block.succs.end());
        block.succs.erase(std::unique(block.succs.begin(), block.succs.end()), block.succs.end());
        block.preds.clear();
    }
    for (auto& [ba, block] : func.blocks)
        for (va_t s : block.succs)
            if (func.blocks.count(s))
                func.blocks[s].preds.push_back(ba);

    func.analyzed = true;
}

void Analyzer::discover_cfg_fixed_point() {
    constexpr int kMaxIterations = 4;
    size_t previous_edges = static_cast<size_t>(-1);
    size_t previous_functions = static_cast<size_t>(-1);

    // Round 0 has to look at everything. After that only functions that gained
    // an edge or a resolved call site can produce a different CFG, so later
    // rounds work off that set instead of re-walking the whole image
    std::unordered_set<va_t> pending;
    bool first_round = true;

    for (int iteration = 0; iteration < kMaxIterations; ++iteration) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        if (!first_round && pending.empty()) return;

        const std::unordered_set<va_t>* scope = first_round ? nullptr : &pending;
        cfg_dirty_.clear();
        build_cfgs(scope);
        detect_switches(scope);
        propagate_dataflow(scope);

        std::vector<va_t> new_functions;
        for (const auto& [site, target] : db_.resolved_indirect) {
            auto instruction = db_.insns.find(site);
            if (instruction == db_.insns.end()) continue;
            if (instruction->second.is_call()) {
                if (!db_.funcs.count(target)) new_functions.push_back(target);
            } else if (instruction->second.type == InsnType::Jmp) {
                recovered_edges_[site].push_back(target);
            }
        }
        for (va_t entry : new_functions) {
            Function function;
            function.entry = entry;
            function.name = fmt::format("sub_{:X}", entry - img_.base);
            db_.add_func(std::move(function));
        }

        size_t edge_count = 0;
        for (auto& [site, edges] : recovered_edges_) {
            std::sort(edges.begin(), edges.end());
            edges.erase(std::unique(edges.begin(), edges.end()), edges.end());
            edge_count += edges.size();
        }
        if (edge_count == previous_edges && db_.funcs.size() == previous_functions) {
            // nothing new this round, so the CFGs built at the top of it
            // already reflect every edge and function we know about
            return;
        }
        previous_edges = edge_count;
        previous_functions = db_.funcs.size();

        // next round: functions whose edges moved, plus the ones just
        // discovered, which have no CFG at all yet
        pending = std::move(cfg_dirty_);
        cfg_dirty_.clear();
        for (va_t entry : new_functions) pending.insert(entry);
        first_round = false;
    }
    if (!pending.empty()) build_cfgs(&pending);
}

void Analyzer::detect_switches(const std::unordered_set<va_t>* only) {
    std::atomic<u32> tables_found{0};

    std::vector<Function*> scope;
    scope.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed) continue;
        if (only && !only->count(entry)) continue;
        scope.push_back(&func);
    }
    parallel_for(pool_, scope.size(), [&](size_t i) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        Function& func = *scope[i];
        const va_t entry = func.entry;

        for (auto& [ba, block] : func.blocks) {
            if (block.insns.size() < 2) continue;
            auto& last = block.insns.back();
            if (last.type != InsnType::Jmp) continue;

            // Pattern 1: jmp reg (indirect through register, table was loaded)
            // Pattern 2: jmp [reg*scale + table_addr]
            if (last.op_count < 1) continue;
            auto& op = last.ops[0];

            // Direct memory operand: jmp [reg*8 + table_addr]
            if (op.type == OpType::Mem && op.mem.base == 0 && op.mem.index != 0 &&
                op.val != 0) {
                va_t table_addr = op.val;
                size_t max_len = 0;
                const u8* tbl = va_to_ptr(table_addr, &max_len);
                if (!tbl) continue;

                u32 max_entries = static_cast<u32>(max_len / 8);
                if (max_entries > 256) max_entries = 256;

                for (u32 e = 0; e < max_entries; ++e) {
                    va_t target = 0;
                    std::memcpy(&target, tbl + e * 8, 8);
                    if (!is_code_addr(target)) break;
                    block.succs.push_back(target);
                    {
                        std::lock_guard lk(edge_mu_);
                        recovered_edges_[last.addr].push_back(target);
                        cfg_dirty_.insert(entry);
                    }
                }
                ++tables_found;
                continue;
            }

            // RIP-relative LEA pattern: look back for lea+movsxd pattern
            // scan backwards for a LEA with rip-relative addressing
            va_t table_base = 0;
            for (int j = static_cast<int>(block.insns.size()) - 2; j >= 0; --j) {
                auto& prev = block.insns[j];
                if (prev.type == InsnType::Lea && prev.op_count >= 2 &&
                    prev.ops[1].type == OpType::Mem && prev.ops[1].val != 0) {
                    table_base = prev.ops[1].val;
                    break;
                }
            }
            if (!table_base) continue;

            // Look for bound: scan block preds for cmp+ja pattern
            u32 max_cases = 64;
            for (va_t pred_addr : block.preds) {
                auto pit = func.blocks.find(pred_addr);
                if (pit == func.blocks.end()) continue;
                auto& pblk = pit->second;
                for (auto& pi : pblk.insns) {
                    if (pi.type == InsnType::Cmp && pi.op_count >= 2 &&
                        pi.ops[1].type == OpType::Imm) {
                        max_cases = static_cast<u32>(pi.ops[1].val) + 1;
                        if (max_cases > 512) max_cases = 512;
                    }
                }
            }

            size_t max_len = 0;
            const u8* tbl = va_to_ptr(table_base, &max_len);
            if (!tbl) continue;

            u32 avail = static_cast<u32>(max_len / 4);
            if (max_cases > avail) max_cases = avail;

            for (u32 e = 0; e < max_cases; ++e) {
                i32 offset = 0;
                std::memcpy(&offset, tbl + e * 4, 4);
                va_t target = table_base + offset;
                if (!is_code_addr(target)) break;
                block.succs.push_back(target);
                {
                    std::lock_guard lk(edge_mu_);
                    recovered_edges_[last.addr].push_back(target);
                    cfg_dirty_.insert(entry);
                }
            }
            ++tables_found;
        }
    });
    spdlog::info("detected {} switch tables", tables_found.load());
}

void Analyzer::build_xrefs() {
    // Most instructions contribute at least one xref, so size the flat list
    // and both direction maps from the instruction count rather than letting
    // them grow (and rehash, and relink) their way there.
    // Deliberately serial: the per-instruction work is a few branch checks,
    // so a chunked fan-out costs more in snapshot/merge overhead than the
    // scan itself (measured slower, not faster).
    db_.xrefs.reserve(db_.insns.size());
    db_.xrefs_to.reserve(db_.insns.size() / 2);
    db_.xrefs_from.reserve(db_.insns.size() / 2);

    for (auto& [addr, insn] : db_.insns) {
        if (insn.is_call()) {
            va_t t = insn.branch_target();
            if (!t) {
                auto resolved = db_.resolved_indirect.find(addr);
                if (resolved != db_.resolved_indirect.end()) t = resolved->second;
            }
            if (t) db_.add_xref_unlocked({addr, t, XrefType::CodeCall});
        } else if (insn.is_branch()) {
            va_t t = insn.branch_target();
            if (!t) {
                auto resolved = db_.resolved_indirect.find(addr);
                if (resolved != db_.resolved_indirect.end()) t = resolved->second;
            }
            if (t) db_.add_xref_unlocked({addr, t, XrefType::CodeJump});
        }
        for (u8 i = 0; i < insn.op_count; ++i) {
            auto& op = insn.ops[i];
            if (op.type == OpType::Mem && op.val) {
                const bool read = op.read || !op.write;
                if (read) db_.add_xref_unlocked({addr, op.val, XrefType::DataRead});
                if (op.write) db_.add_xref_unlocked({addr, op.val, XrefType::DataWrite});
            } else if (op.type == OpType::Imm && op.val > img_.base &&
                     op.val < img_.base + 0x10000000)
                db_.add_xref_unlocked({addr, op.val, XrefType::DataOffset});
        }
    }
}

void Analyzer::find_strings() {
    constexpr size_t kMaxStringLen = 256;
    // One output per segment, concatenated in segment order: deterministic.
    std::vector<std::vector<std::pair<va_t, std::string>>> outs(img_.segments.size());
    parallel_for(pool_, img_.segments.size(), [&](size_t s) {
        const Segment& seg = img_.segments[s];
        if (seg.data.empty()) return;
        auto& out = outs[s];
        size_t i = 0;
        while (i < seg.data.size()) {
            if (seg.data[i] >= 0x20 && seg.data[i] < 0x7F) {
                size_t start = i;
                while (i < seg.data.size() && seg.data[i] >= 0x20 && seg.data[i] < 0x7F)
                    ++i;
                if (i - start >= 4 && i < seg.data.size() && seg.data[i] == 0) {
                    size_t len = (std::min)(i - start, kMaxStringLen);
                    std::string str(seg.data.begin() + start, seg.data.begin() + start + len);
                    out.emplace_back(seg.va + start, std::move(str));
                }
            } else {
                ++i;
            }
        }
    });
    for (auto& out : outs)
        for (auto& entry : out) db_.strings.emplace_back(entry.first, std::move(entry.second));
    spdlog::info("found {} strings", db_.strings.size());
}

void Analyzer::find_string_refs() {
    // Build lookup of string addresses for fast checking
    std::unordered_set<va_t> str_addrs;
    for (auto& [addr, s] : db_.strings)
        str_addrs.insert(addr);

    // Serial like build_xrefs above: the LEA scan is too cheap to fan out.
    u32 refs_added = 0;
    for (auto& [addr, insn] : db_.insns) {
        if (insn.type != InsnType::Lea) continue;
        // LEA reg, [rip+X] — operand 1 is mem with computed VA
        for (u8 i = 0; i < insn.op_count; ++i) {
            auto& op = insn.ops[i];
            if (op.type == OpType::Mem && op.val && str_addrs.count(op.val)) {
                db_.add_xref_unlocked({addr, op.val, XrefType::DataOffset});
                ++refs_added;
            }
        }
    }
    spdlog::info("found {} string refs via LEA", refs_added);
}

void Analyzer::detect_vtables() {
    const size_t ptr_sz = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4;
    // Per-segment candidates merged in segment order: deterministic.
    std::vector<std::vector<Vtable>> outs(img_.segments.size());
    parallel_for(pool_, img_.segments.size(), [&](size_t s) {
        const Segment& seg = img_.segments[s];
        if (seg.executable() || seg.data.empty()) return;
        if (seg.name != ".rdata" && seg.name != ".data") return;

        const u8* data = seg.data.data();
        size_t sz = seg.data.size();
        auto& out = outs[s];

        for (size_t i = 0; i + ptr_sz * 2 <= sz; i += ptr_sz) {
            // need at least 2 consecutive code pointers to consider it a vtable
            va_t first = 0;
            if (ptr_sz == 8)
                std::memcpy(&first, data + i, 8);
            else {
                u32 v = 0; std::memcpy(&v, data + i, 4); first = v;
            }

            if (!is_code_addr(first)) continue;

            Vtable vt;
            vt.addr = seg.va + i;

            size_t j = i;
            while (j + ptr_sz <= sz) {
                va_t val = 0;
                if (ptr_sz == 8)
                    std::memcpy(&val, data + j, 8);
                else {
                    u32 v = 0; std::memcpy(&v, data + j, 4); val = v;
                }
                if (!is_code_addr(val)) break;
                vt.entries.push_back(val);
                j += ptr_sz;
            }

            if (vt.entries.size() >= 2) {
                out.push_back(std::move(vt));
                i = j - ptr_sz; // advance past this vtable
            }
        }
    });
    u32 found = 0;
    for (auto& out : outs) {
        for (auto& vt : out) {
            db_.set_name(vt.addr, fmt::format("vtable_{:X}", vt.addr));
            for (size_t s = 0; s < vt.entries.size(); ++s)
                db_.set_name(vt.addr + s * ptr_sz,
                             fmt::format("vtable_{:X}_slot{}", vt.addr, s));
            db_.vtables.push_back(std::move(vt));
            ++found;
        }
    }
    spdlog::info("detected {} vtables", found);
}

void Analyzer::detect_globals() {
    std::vector<const Insn*> all;
    all.reserve(db_.insns.size());
    for (auto& [addr, insn] : db_.insns) all.push_back(&insn);

    // Per-chunk (addr, size) hits merged in snapshot order; the merge keeps
    // the widest access per address, which is order-independent.
    const size_t chunks = chunk_count(pool_, all.size());
    std::vector<std::vector<std::pair<va_t, u32>>> outs(chunks);
    parallel_for_chunks(pool_, all.size(), [&](size_t c, size_t begin, size_t end) {
        auto& out = outs[c];
        for (size_t k = begin; k < end; ++k) {
            const Insn& insn = *all[k];
            for (u8 i = 0; i < insn.op_count; ++i) {
                auto& op = insn.ops[i];
                if (op.type != OpType::Mem || op.val == 0) continue;

                va_t target = op.val;
                auto* sec = section_for(target);
                if (!sec) continue;
                if (sec->executable()) continue;
                if (sec->name != ".data" && sec->name != ".bss") continue;
                out.emplace_back(target, operand_size_bytes(op, 4));
            }
        }
    });
    u32 found = 0;
    for (auto& out : outs) {
        for (auto& [target, sz] : out) {
            auto it = db_.globals.find(target);
            if (it != db_.globals.end()) {
                // update size if wider access
                if (sz > it->second.size)
                    it->second.size = sz;
                continue;
            }

            Global g;
            g.addr = target;
            g.size = sz;
            g.name = fmt::format("g_var_{:X}", target);
            db_.globals[target] = std::move(g);
            db_.set_name(target, fmt::format("g_var_{:X}", target));
            ++found;
        }
    }
    spdlog::info("detected {} global variables", found);
}

void Analyzer::apply_names() {
    db_.set_name(img_.entry, "entry_point");
    for (auto& imp : img_.imports) {
        std::string demangled = demangle(imp.name);
        db_.set_name(imp.iat_addr, imp.dll + "!" + demangled);
    }
    for (auto& exp : img_.exports) {
        if (exp.forwarded || !is_code_addr(exp.addr)) continue;
        std::string demangled = demangle(exp.name);
        db_.set_name(exp.addr, demangled);
        auto fit = db_.funcs.find(exp.addr);
        if (fit != db_.funcs.end())
            fit->second.name = demangled;
    }

    DataSize ptr_size = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? DataSize::Qword : DataSize::Dword;
    for (auto& imp : img_.imports) {
        db_.insns.erase(imp.iat_addr);
        db_.data_items[imp.iat_addr] = {imp.iat_addr, ptr_size, DataStyle::Import, false};
    }
    spdlog::info("defined {} IAT data items", img_.imports.size());
}

void Analyzer::apply_signatures() {
    sigmatch_.match_functions(db_, img_);
}

void Analyzer::detect_noreturn() {
    static const std::unordered_set<std::string> known_noreturn = {
        "exit", "_exit", "abort", "__fastfail", "ExitProcess",
        "TerminateProcess", "RtlFailFast", "__report_rangecheckfailure",
        "_Exit", "quick_exit", "_abort", "FatalExit"
    };

    std::vector<Function*> order;
    order.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) order.push_back(&func);

    // Pass 1 (name-based) writes disjoint flags, so it fans out directly.
    std::atomic<u32> count{0};
    parallel_for(pool_, order.size(), [&](size_t i) {
        Function& func = *order[i];
        for (auto& nr_name : known_noreturn) {
            if (func.name.find(nr_name) != std::string::npos) {
                func.noreturn = true;
                ++count;
                return;
            }
        }
    });

    // Pass 2 (structural) reads other functions' flags, so snapshot them
    // first: concurrent read-your-neighbour/write-your-own would race.
    // Rounds run to a fixed point so multi-level noreturn chains (B calls
    // noreturn A, C calls B, ...) resolve fully and deterministically —
    // the old serial pass propagated them only in lucky hash order.
    std::vector<char> add(order.size(), 0);
    for (int round = 0; round < 8; ++round) {
        std::unordered_set<va_t> noreturn_entries;
        for (auto* f : order)
            if (f->noreturn) noreturn_entries.insert(f->entry);

        std::fill(add.begin(), add.end(), 0);
        parallel_for(pool_, order.size(), [&](size_t i) {
            Function& func = *order[i];
            if (func.noreturn) return;
            if (!func.analyzed || func.blocks.empty()) return;
            bool has_ret = false;
            for (auto& [ba, bb] : func.blocks) {
                for (auto& insn : bb.insns) {
                    if (insn.is_ret()) { has_ret = true; break; }
                }
                if (has_ret) break;
            }
            if (has_ret) return;
            bool has_exit_path = false;
            for (auto& [ba, bb] : func.blocks) {
                if (bb.succs.empty() && !bb.insns.empty() && !bb.insns.back().is_ret()) {
                    auto& last = bb.insns.back();
                    if (last.is_call()) {
                        va_t t = last.branch_target();
                        if (t && noreturn_entries.count(t))
                            continue;
                    }
                }
                if (!bb.succs.empty()) has_exit_path = true;
            }
            if (!has_exit_path && func.blocks.size() > 0) add[i] = 1;
        });

        size_t added = 0;
        for (size_t i = 0; i < order.size(); ++i) {
            if (add[i] && !order[i]->noreturn) {
                order[i]->noreturn = true;
                ++added;
                ++count;
            }
        }
        if (added == 0) break;
    }
    spdlog::info("detected {} noreturn functions", count.load());
}

void Analyzer::detect_tail_calls() {
    // Retyping a jump xref used to std::find_if over the whole flat xref
    // vector per candidate, which is quadratic once an image has millions of
    // them. Index the flat vector by source address once instead.
    std::unordered_map<va_t, std::vector<size_t>> flat_by_from;
    flat_by_from.reserve(db_.xrefs.size());
    for (size_t i = 0; i < db_.xrefs.size(); ++i)
        flat_by_from[db_.xrefs[i].from].push_back(i);

    // Pass 1 (read-only) fans out; pass 2 mutates the xref stores serially.
    std::vector<Function*> order;
    order.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (func.analyzed) order.push_back(&func);
    }
    const size_t chunks = chunk_count(pool_, order.size());
    std::vector<std::vector<std::pair<va_t, va_t>>> outs(chunks);
    parallel_for_chunks(pool_, order.size(), [&](size_t c, size_t begin, size_t end) {
        auto& out = outs[c];
        for (size_t k = begin; k < end; ++k) {
            Function& func = *order[k];
            const va_t entry = func.entry;
            va_t func_end = 0;
            for (auto& [ba, bb] : func.blocks)
                if (bb.end > func_end) func_end = bb.end;

            for (auto& [ba, bb] : func.blocks) {
                if (bb.insns.empty()) continue;
                auto& last = bb.insns.back();
                if (last.type != InsnType::Jmp) continue;

                va_t target = last.branch_target();
                if (!target) continue;

                bool is_tail = false;
                if (db_.funcs.count(target) && target != entry)
                    is_tail = true;
                else if (target < entry || target >= func_end)
                    if (!func.blocks.count(target))
                        is_tail = true;

                if (is_tail) out.emplace_back(last.addr, target);
            }
        }
    });

    u32 count = 0;
    for (auto& out : outs) {
        for (auto& [from, target] : out) {
            bool retyped = false;
            const auto candidates = flat_by_from.find(from);
            if (candidates != flat_by_from.end()) {
                for (size_t i : candidates->second) {
                    Xref& x = db_.xrefs[i];
                    if (x.to != target || x.type != XrefType::CodeJump) continue;
                    x.type = XrefType::CodeCall;
                    retyped = true;
                    break;
                }
            }
            if (retyped) {
                for (auto& xr : db_.xrefs_to[target])
                    if (xr.from == from && xr.type == XrefType::CodeJump)
                        xr.type = XrefType::CodeCall;
                for (auto& xr : db_.xrefs_from[from])
                    if (xr.to == target && xr.type == XrefType::CodeJump)
                        xr.type = XrefType::CodeCall;
            } else {
                db_.add_xref({from, target, XrefType::CodeCall});
            }
            ++count;
        }
    }
    spdlog::info("detected {} tail calls", count);
}

void Analyzer::detect_calling_conventions() {
    bool is_x64 = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC);

    for (auto& [entry, func] : db_.funcs) {
        if (is_x64) {
            func.callconv = CallConv::X64;
            continue;
        }

        if (!func.analyzed) continue;

        bool has_ret_n = false;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (insn.is_ret() && insn.op_count > 0 && insn.ops[0].type == OpType::Imm &&
                    insn.ops[0].val > 0) {
                    has_ret_n = true;
                    break;
                }
            }
            if (has_ret_n) break;
        }

        if (has_ret_n)
            func.callconv = CallConv::Stdcall;
        else
            func.callconv = CallConv::Cdecl;
    }
    spdlog::info("calling conventions assigned (x64={})", is_x64 ? "yes" : "no");
}

void Analyzer::propagate_dataflow(const std::unordered_set<va_t>* only) {
    std::atomic<u32> resolved{0};

    std::vector<Function*> scope;
    scope.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (!func.analyzed || func.blocks.empty()) continue;
        if (only && !only->count(entry)) continue;
        scope.push_back(&func);
    }
    // Helper: record one resolution under a single lock so the first-writer
    // accounting stays exact across workers.
    auto resolve = [&](va_t site, va_t target, va_t entry) {
        std::lock_guard lk(edge_mu_);
        if (!db_.resolved_indirect.count(site)) {
            ++resolved;
            cfg_dirty_.insert(entry);
        }
        db_.resolved_indirect[site] = target;
    };

    parallel_for(pool_, scope.size(), [&](size_t i) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        Function& func = *scope[i];
        const va_t entry = func.entry;
        std::unordered_map<u16, va_t> reg_vals;

        for (auto& ba : func.block_addrs) {
            auto bit = func.blocks.find(ba);
            if (bit == func.blocks.end()) continue;
            auto& bb = bit->second;

            for (auto& insn : bb.insns) {
                if (insn.type == InsnType::Mov && insn.op_count >= 2 &&
                    insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Imm) {
                    reg_vals[insn.ops[0].reg] = insn.ops[1].val;
                }
                else if (insn.type == InsnType::Lea && insn.op_count >= 2 &&
                         insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Mem &&
                         insn.ops[1].val != 0) {
                    reg_vals[insn.ops[0].reg] = insn.ops[1].val;
                }
                else if (insn.op_count > 0 && insn.ops[0].type == OpType::Reg &&
                         insn.type != InsnType::Cmp && insn.type != InsnType::Test) {
                    reg_vals.erase(insn.ops[0].reg);
                }

                if ((insn.is_call() || insn.type == InsnType::Jmp) &&
                    insn.op_count > 0 && insn.ops[0].type == OpType::Reg) {
                    auto it = reg_vals.find(insn.ops[0].reg);
                    if (it != reg_vals.end() && it->second != 0 && is_code_addr(it->second)) {
                        resolve(insn.addr, it->second, entry);
                    }
                }
                else if ((insn.is_call() || insn.type == InsnType::Jmp) &&
                         insn.op_count > 0 && insn.ops[0].type == OpType::Mem &&
                         insn.ops[0].mem.base != 0 && insn.ops[0].val == 0) {
                    auto it = reg_vals.find(insn.ops[0].mem.base);
                    if (it != reg_vals.end() && it->second != 0) {
                        va_t effective = it->second + insn.ops[0].mem.disp;
                        size_t max_len = 0;
                        const u8* ptr = va_to_ptr(effective, &max_len);
                        if (ptr && max_len >= 8) {
                            va_t target = 0;
                            std::memcpy(&target, ptr, (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4);
                            if (is_code_addr(target)) {
                                resolve(insn.addr, target, entry);
                            }
                        }
                    }
                }

                if (insn.is_call()) reg_vals.clear();
            }
        }
    });
    spdlog::info("dataflow: resolved {} indirect call/jump targets", resolved.load());
}

void Analyzer::detect_loops() {
    std::atomic<u32> count{0};
    std::vector<Function*> scope;
    scope.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (func.analyzed && func.blocks.count(entry)) scope.push_back(&func);
    }
    parallel_for(pool_, scope.size(), [&](size_t i) {
        if (cancel_.load(std::memory_order_relaxed)) return;
        Function& func = *scope[i];
        const va_t entry = func.entry;
        func.loops.clear();

        // Cooper-Harvey-Kennedy dominators over a reverse-postorder index:
        // near-linear, replacing the former per-block dominator *sets* whose
        // set intersections made large functions quadratic.
        std::vector<va_t> order;
        order.reserve(func.blocks.size());
        for (const auto& [addr, block] : func.blocks) order.push_back(addr);
        std::sort(order.begin(), order.end());

        // DFS from entry to get reachable blocks + postorder.
        std::vector<int> postorder;
        std::unordered_set<va_t> visited;
        std::vector<va_t> stack{entry};
        while (!stack.empty()) {
            const va_t current = stack.back();
            stack.pop_back();
            if (!visited.insert(current).second) continue;
            auto bit = func.blocks.find(current);
            if (bit == func.blocks.end()) continue;
            for (va_t succ : bit->second.succs)
                if (func.blocks.count(succ) && !visited.count(succ)) stack.push_back(succ);
            postorder.push_back(current);
        }
        std::vector<va_t> rpo(postorder.rbegin(), postorder.rend());
        std::unordered_map<va_t, int> rpo_index;
        for (size_t i = 0; i < rpo.size(); ++i) rpo_index[rpo[i]] = static_cast<int>(i);

        const int kNoDom = -1;
        std::vector<int> idom(order.size(), kNoDom);
        const int entry_idx = rpo_index.count(entry) ? rpo_index[entry] : kNoDom;
        if (entry_idx == kNoDom) return;
        idom[entry_idx] = entry_idx;

        const auto intersect = [&](int a, int b) {
            while (a != b) {
                while (a > b) a = idom[a];
                while (b > a) b = idom[b];
            }
            return a;
        };

        bool changed = true;
        while (changed) {
            changed = false;
            for (size_t ri = 1; ri < rpo.size(); ++ri) {
                const va_t addr = rpo[ri];
                const auto& block = func.blocks.at(addr);
                int new_idom = kNoDom;
                for (va_t pred : block.preds) {
                    auto pit = rpo_index.find(pred);
                    if (pit == rpo_index.end() || idom[pit->second] == kNoDom) continue;
                    new_idom = new_idom == kNoDom ? pit->second
                                                  : intersect(new_idom, pit->second);
                }
                if (new_idom != kNoDom && idom[ri] != new_idom) {
                    idom[ri] = new_idom;
                    changed = true;
                }
            }
        }

        // A back edge is an edge whose target dominates its source.
        for (auto& [ba, bb] : func.blocks) {
            auto sit = rpo_index.find(ba);
            if (sit == rpo_index.end()) continue;
            for (va_t succ : bb.succs) {
                auto tit = rpo_index.find(succ);
                if (tit == rpo_index.end()) continue;
                int runner = sit->second;
                bool dominates = false;
                while (runner != kNoDom) {
                    if (runner == tit->second) { dominates = true; break; }
                    if (runner == idom[runner]) break;
                    runner = idom[runner];
                }
                if (!dominates) continue;

                LoopInfo loop;
                loop.header = succ;
                loop.back_edge_src = ba;

                std::unordered_set<va_t> loop_blocks{succ, ba};
                std::queue<va_t> worklist;
                worklist.push(ba);
                while (!worklist.empty()) {
                    const va_t current = worklist.front();
                    worklist.pop();
                    for (va_t pred : func.blocks[current].preds)
                        if (loop_blocks.insert(pred).second && pred != succ) worklist.push(pred);
                }

                for (va_t loop_block : loop_blocks) {
                    for (const auto& insn : func.blocks[loop_block].insns) {
                        if (insn.type == InsnType::Inc && insn.op_count > 0 &&
                            insn.ops[0].type == OpType::Reg) {
                            loop.induction_reg = insn.ops[0].reg;
                            goto found_induction;
                        }
                        if (insn.type == InsnType::Add && insn.op_count >= 2 &&
                            insn.ops[0].type == OpType::Reg && insn.ops[1].type == OpType::Imm &&
                            insn.ops[1].val == 1) {
                            loop.induction_reg = insn.ops[0].reg;
                            goto found_induction;
                        }
                    }
                }
                found_induction:
                func.loops.push_back(loop);
                ++count;
            }
        }
    });
    spdlog::info("detected {} loops", count.load());
}

void Analyzer::recover_structs() {
    // The builtin ids never move, so resolve them once instead of four
    // name lookups per recovered field
    const TypeDef* builtin_u8  = db_.types.find_by_name("u8");
    const TypeDef* builtin_u16 = db_.types.find_by_name("u16");
    const TypeDef* builtin_u32 = db_.types.find_by_name("u32");
    const TypeDef* builtin_u64 = db_.types.find_by_name("u64");
    const u32 id_u8  = builtin_u8  ? builtin_u8->id  : 0;
    const u32 id_u16 = builtin_u16 ? builtin_u16->id : 0;
    const u32 id_u32 = builtin_u32 ? builtin_u32->id : 0;
    const u32 id_u64 = builtin_u64 ? builtin_u64->id : 0;

    struct candidate_t {
        std::string name;
        u32 total_size = 0;
        std::vector<std::pair<i64, u32>> fields;  // (offset, size), sorted
    };

    std::vector<Function*> order;
    order.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) {
        if (func.analyzed) order.push_back(&func);
    }
    // Scan fans out (read-only); the TypeSystem commit below stays serial.
    const size_t chunks = chunk_count(pool_, order.size());
    std::vector<std::vector<candidate_t>> outs(chunks);
    parallel_for_chunks(pool_, order.size(), [&](size_t c, size_t begin, size_t end) {
        auto& out = outs[c];
        for (size_t k = begin; k < end; ++k) {
            Function& func = *order[k];
            const va_t entry = func.entry;

            struct Access { u16 base_reg; i64 offset; u32 size; };
            std::unordered_map<u16, std::vector<Access>> accesses;

            for (auto& [ba, bb] : func.blocks) {
                for (auto& insn : bb.insns) {
                    for (u8 i = 0; i < insn.op_count; ++i) {
                        auto& op = insn.ops[i];
                        if (op.type != OpType::Mem) continue;
                        if (op.mem.base == 0) continue;
                        // skip RSP/RBP-based (stack frame)
                        if (is_stack_register(op.mem.base)) continue;
                        if (op.mem.disp < 0) continue;
                        if (op.mem.disp > 4096) continue;

                        Access a;
                        a.base_reg = op.mem.base;
                        a.offset = op.mem.disp;
                        a.size = operand_size_bytes(op, 8);
                        accesses[a.base_reg].push_back(a);
                    }
                }
            }

            for (auto& [reg, accs] : accesses) {
                if (accs.size() < 3) continue;

                std::set<std::pair<i64, u32>> fields_set;
                for (auto& a : accs)
                    fields_set.insert({a.offset, a.size});
                if (fields_set.size() < 3) continue;

                candidate_t cand;
                cand.name = fmt::format("struct_{:X}_{}", entry, reg);
                for (auto& [off, sz] : fields_set) {
                    cand.fields.emplace_back(off, sz);
                    if (static_cast<u32>(off) + sz > cand.total_size)
                        cand.total_size = static_cast<u32>(off) + sz;
                }
                out.push_back(std::move(cand));
            }
        }
    });

    u32 count = 0;
    for (auto& out : outs) {
        for (auto& cand : out) {
            auto* existing = db_.types.find_by_name(cand.name);
            if (existing) continue;

            u32 sid = db_.types.add_struct(cand.name, cand.total_size);
            for (auto& [off, sz] : cand.fields) {
                u32 type_id = 0;
                if (sz == 1 && id_u8) type_id = id_u8;
                else if (sz == 2 && id_u16) type_id = id_u16;
                else if (sz == 4 && id_u32) type_id = id_u32;
                else if (sz == 8 && id_u64) type_id = id_u64;
                else if (id_u32) type_id = id_u32;
                db_.types.add_field(sid, fmt::format("field_{:X}", off), type_id,
                                    static_cast<u32>(off));
            }
            ++count;
        }
    }
    spdlog::info("recovered {} struct types", count);
}

void Analyzer::populate_data_sections() {
    constexpr size_t kLargeSectionThreshold = 5ULL * 1024 * 1024;
    constexpr u32    kZeroRunThreshold = 4;

    std::unordered_set<va_t> str_addrs;
    for (auto& [addr, _] : db_.strings)
        str_addrs.insert(addr);

    std::unordered_set<va_t> iat_addrs;
    for (auto& imp : img_.imports)
        iat_addrs.insert(imp.iat_addr);

    size_t ptr_sz = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? 8 : 4;
    DataSize ds = (img_.arch == Arch::X64 || img_.arch == Arch::ARM64 || img_.arch == Arch::PPC) ? DataSize::Qword : DataSize::Dword;
    u32 defined = 0;

    size_t total_data_bytes = 0;
    for (const auto& seg : img_.segments) {
        if (!seg.executable() && !seg.data.empty()) total_data_bytes += seg.data.size();
    }
    if (total_data_bytes > 0) db_.data_items.reserve(std::min<size_t>(total_data_bytes / (ptr_sz * 4), 65536));

    // Per-segment item lists merged in segment order (addresses are disjoint
    // across segments, so the merge is deterministic).
    std::vector<std::vector<DataItem>> outs(img_.segments.size());
    parallel_for(pool_, img_.segments.size(), [&](size_t s) {
        const Segment& seg = img_.segments[s];
        if (seg.executable() || seg.data.empty()) return;

        bool large = seg.data.size() > kLargeSectionThreshold;
        const u8* data = seg.data.data();
        size_t sz = seg.data.size();
        auto& out = outs[s];

        for (size_t i = 0; i + ptr_sz <= sz; i += ptr_sz) {
            va_t addr = seg.va + i;

            if (str_addrs.count(addr)) continue;
            if (iat_addrs.count(addr)) continue;

            va_t val = 0;
            if (ptr_sz == 8)
                std::memcpy(&val, data + i, 8);
            else {
                u32 v = 0; std::memcpy(&v, data + i, 4); val = v;
            }

            if (val == 0) {
                u32 run = 0;
                size_t j = i;
                while (j + ptr_sz <= sz) {
                    va_t zv = 0;
                    if (ptr_sz == 8)
                        std::memcpy(&zv, data + j, 8);
                    else {
                        u32 v2 = 0; std::memcpy(&v2, data + j, 4); zv = v2;
                    }
                    if (zv != 0) break;
                    ++run;
                    j += ptr_sz;
                }
                if (run >= kZeroRunThreshold) {
                    out.push_back({addr, ds, DataStyle::Align, false});
                    i = j - ptr_sz;
                    continue;
                }
            }

            if (large && !db_.xrefs_to.count(addr) && !is_code_addr(val))
                continue;

            if (is_code_addr(val)) {
                out.push_back({addr, ds, DataStyle::Pointer, false});
            } else {
                out.push_back({addr, ds, DataStyle::Raw, false});
            }
        }
    });

    u32 defined_out = 0;
    for (auto& out : outs) {
        for (auto& item : out) {
            if (db_.data_items.count(item.addr)) continue;
            db_.data_items[item.addr] = item;
            ++defined_out;
        }
    }
    defined = defined_out;

    for (auto& imp : img_.imports) {
        auto it = db_.data_items.find(imp.iat_addr);
        if (it != db_.data_items.end())
            it->second.style = DataStyle::Import;
    }

    spdlog::info("populate_data_sections: defined {} data items", defined);
}

void Analyzer::detect_main() {
    static const std::unordered_set<std::string> crt_starters = {
        "__scrt_common_main_seh", "mainCRTStartup", "__tmainCRTStartup",
        "WinMainCRTStartup", "__wWinMainCRTStartup"
    };

    for (auto& [entry, func] : db_.funcs) {
        if (!crt_starters.count(func.name)) continue;
        if (!func.analyzed) continue;

        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t target = insn.branch_target();
                if (!target) continue;
                if (!db_.funcs.count(target)) continue;
                if (crt_starters.count(db_.funcs[target].name)) continue;

                auto& callee = db_.funcs[target];
                bool is_winmain = func.name.find("WinMain") != std::string::npos;

                if (is_winmain) {
                    callee.name = "WinMain";
                    db_.set_name(target, "WinMain");
                } else {
                    callee.name = "main";
                    db_.set_name(target, "main");
                }
                spdlog::info("detected {} at {:X}", callee.name, target);
                return;
            }
        }
    }

    // Fallback: entry calls a CRT stub which calls main
    auto eit = db_.funcs.find(img_.entry);
    if (eit == db_.funcs.end() || !eit->second.analyzed) return;

    for (auto& [ba, bb] : eit->second.blocks) {
        for (auto& insn : bb.insns) {
            if (!insn.is_call()) continue;
            va_t stub = insn.branch_target();
            if (!stub || !db_.funcs.count(stub)) continue;
            auto& stub_func = db_.funcs[stub];
            if (!stub_func.analyzed) continue;

            for (auto& [ba2, bb2] : stub_func.blocks) {
                for (auto& ins2 : bb2.insns) {
                    if (!ins2.is_call()) continue;
                    va_t target = ins2.branch_target();
                    if (!target || !db_.funcs.count(target)) continue;
                    auto& callee = db_.funcs[target];
                    if (callee.name.rfind("sub_", 0) != 0) continue;

                    callee.name = "main";
                    db_.set_name(target, "main");
                    spdlog::info("detected main at {:X} (via entry stub)", target);
                    return;
                }
            }
        }
    }
}

void Analyzer::propagate_interproc_types() {
    static const std::unordered_map<std::string, FuncSignature> known_sigs = {
        {"strlen",   {{"str"}, {"const char*"}, "size_t", 1}},
        {"strcmp",   {{"s1","s2"}, {"const char*","const char*"}, "int32_t", 2}},
        {"strcpy",   {{"dst","src"}, {"char*","const char*"}, "char*", 2}},
        {"memcpy",   {{"dst","src","n"}, {"void*","const void*","size_t"}, "void*", 3}},
        {"memset",   {{"dst","val","n"}, {"void*","int32_t","size_t"}, "void*", 3}},
        {"malloc",   {{"size"}, {"size_t"}, "void*", 1}},
        {"free",     {{"ptr"}, {"void*"}, "void", 1}},
        {"printf",   {{"fmt"}, {"const char*"}, "int32_t", 1}},
        {"CreateFileA", {{"lpFileName","dwDesiredAccess","dwShareMode","lpSecurity","dwCreation","dwFlags","hTemplate"},
                         {"const char*","uint32_t","uint32_t","void*","uint32_t","uint32_t","void*"}, "void*", 7}},
    };

    u32 propagated = 0;

    // Loop 1 (known library names) and loop 2 (parameter surface) only
    // insert disjoint signature entries: collect in parallel, commit serially.
    std::vector<Function*> order;
    order.reserve(db_.funcs.size());
    for (auto& [entry, func] : db_.funcs) order.push_back(&func);

    const size_t sig_chunks = chunk_count(pool_, order.size());
    std::vector<std::vector<std::pair<va_t, FuncSignature>>> sig_outs(sig_chunks);
    parallel_for_chunks(pool_, order.size(), [&](size_t c, size_t begin, size_t end) {
        auto& out = sig_outs[c];
        for (size_t k = begin; k < end; ++k) {
            Function& func = *order[k];
            const va_t entry = func.entry;
            auto kit = known_sigs.find(func.name);
            if (kit != known_sigs.end()) {
                out.emplace_back(entry, kit->second);
                continue;
            }
            if (!func.analyzed) continue;

            int param_reg_count = 0;
            bool uses_rcx = false, uses_rdx = false, uses_r8 = false, uses_r9 = false;

            for (auto& [ba, bb] : func.blocks) {
                for (auto& insn : bb.insns) {
                    for (u8 i = 0; i < insn.op_count; ++i) {
                        if (insn.ops[i].type == OpType::Reg) {
                            if (insn.ops[i].reg == 1) uses_rcx = true;
                            if (insn.ops[i].reg == 2) uses_rdx = true;
                            if (insn.ops[i].reg == 8) uses_r8 = true;
                            if (insn.ops[i].reg == 9) uses_r9 = true;
                        }
                    }
                }
            }

            if (uses_r9) param_reg_count = 4;
            else if (uses_r8) param_reg_count = 3;
            else if (uses_rdx) param_reg_count = 2;
            else if (uses_rcx) param_reg_count = 1;

            FuncSignature sig;
            sig.param_count = param_reg_count;
            sig.return_type = "int64_t";
            for (int p = 0; p < param_reg_count; ++p) {
                sig.param_names.push_back(fmt::format("a{}", p + 1));
                sig.param_types.push_back("int64_t");
            }
            out.emplace_back(entry, std::move(sig));
        }
    });
    for (auto& out : sig_outs) {
        for (auto& [entry, sig] : out) {
            if (!db_.signatures.count(entry)) {
                db_.signatures[entry] = std::move(sig);
                ++propagated;
            }
        }
    }

    // Loop 3 (call-site propagation) is currently a read-only no-op
    // placeholder: every analyzed function already owns a signature from
    // the commit above, so the lookup below can never insert. Fans out
    // freely.
    parallel_for(pool_, order.size(), [&](size_t k) {
        Function& func = *order[k];
        const va_t entry = func.entry;
        if (!func.analyzed) return;
        for (auto& [ba, bb] : func.blocks) {
            for (auto& insn : bb.insns) {
                if (!insn.is_call()) continue;
                va_t target = insn.branch_target();
                if (!target) continue;
                auto sit = db_.signatures.find(target);
                if (sit == db_.signatures.end()) continue;
                auto& callee_sig = sit->second;

                if (callee_sig.return_type != "int64_t") {
                    auto caller_it = db_.signatures.find(entry);
                    (void)caller_it;
                }
            }
        }
    });

    spdlog::info("interproc: propagated {} function signatures", propagated + (u32)db_.signatures.size());
}

bool Analyzer::decode_insn(va_t addr, const u8* data, size_t len, Insn& out) {
    if (use_capstone()) {
        // Capstone's shared handle carries decode state: serialize. The
        // x86/x64 Zydis path below stays lock-free (const decoder,
        // formatter skipped), which is where the time goes.
        std::lock_guard lk(cap_mu_);
        return cap_disasm_.decode(addr, data, len, out);
    }
    // Analysis never reads mnemonic/op_str text (classification keys off
    // InsnType/mnemonic_id/operands), so skip the formatter per instruction.
    // Decompile/display paths re-render on demand via format_text().
    return disasm_.decode(addr, data, len, out, false);
}

std::vector<Insn> Analyzer::decode_insn_range(va_t start, const u8* data, size_t len) {
    if (use_capstone())
        return cap_disasm_.decode_range(start, data, len);
    return disasm_.decode_range(start, data, len);
}

}
