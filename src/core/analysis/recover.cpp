// src/core/analysis/recover.cpp

#include "core/analysis/recover.hpp"

#include "core/emu/session.hpp"

#include <algorithm>
#include <cstring>
#include <map>
#include <random>
#include <set>
#include <unordered_map>

namespace slop::core::analysis::recover {

namespace {

using disasm::insn_t;
using disasm::op_class_t;

constexpr size_t kMaxFnBytes = 64u << 10;

// Image reads (local to avoid exposing read_img)
bool xray_decode_at(const xray::image_ref_t& img, uint64_t va, uint8_t (&buf)[16]) {
    if (va < img.base) return false;
    auto off = img.pe->rva_to_offset(static_cast<uint32_t>(va - img.base));
    if (!off || *off + sizeof(buf) > img.file->size()) return false;
    std::memcpy(buf, img.file->data() + *off, sizeof(buf));
    return true;
}

// Decode a linear run from va (bounded, image-backed)
std::vector<insn_t> decode_run(const xray::image_ref_t& img, uint64_t va,
                               size_t max) {
    std::vector<insn_t> out;
    uint64_t cur = va;
    for (size_t i = 0; i < max; ++i) {
        uint8_t buf[16];
        if (!xray_decode_at(img, cur, buf)) break;
        auto in = img.eng->decode(cur, buf, sizeof(buf));
        if (!in || in->length == 0) break;
        out.push_back(std::move(*in));
        cur += out.back().length;
    }
    return out;
}

bool read_qword_img(const xray::image_ref_t& img, uint64_t va, uint64_t* out) {
    if (va < img.base) return false;
    auto off = img.pe->rva_to_offset(static_cast<uint32_t>(va - img.base));
    if (!off || *off + 8 > img.file->size()) return false;
    std::memcpy(out, img.file->data() + *off, 8);
    return true;
}

bool is_exec_va(const xray::image_ref_t& img, uint64_t va) {
    if (va < img.base) return false;
    const uint32_t rva = static_cast<uint32_t>(va - img.base);
    for (const auto& s : img.pe->sections)
        if (s.is_executable() && rva >= s.rva &&
            rva < s.rva + std::max(s.virtual_size, s.raw_size))
            return true;
    return false;
}

// Deterministic per-run register seeding: splitmix-ish spread over the GPs
void seed_regs(emu::run_request_t& req, uint64_t seed) {
    uint64_t st = seed * 0x9E3779B97F4A7C15ull + 0xD1B54A32D192ED03ull;
    auto next = [&st] {
        st += 0x9E3779B97F4A7C15ull;
        uint64_t z = st;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    // NB: rbp is seeded too -- an unseeded (zero) rbp faults every
    // `MOV rax,[rbp+...]` frame access on the first instructions.
    static const char* kRegs[] = { "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                                   "rbp",
                                   "r8", "r9", "r10", "r11", "r12", "r13",
                                   "r14", "r15" };
    for (const char* r : kRegs)
        req.regs[r] = next() | 1;   // never zero: zero-heavy inputs mask branches
}

// Run the function body under Unicorn with the given seed.
// Only the function slice is executable; data sections (.rdata/.data/.pdata)
// are mapped read-only alongside so plain `MOV rax,[rip+...]` / IAT loads do
// not fault after a handful of instructions. Cross-function CALLs still stop
// at the callee (not mapped) with invalid_mem_fetch -- that is inherent to
// slice emulation, and callers surface it with a note.
emu::run_result_t run_fn(const xray::image_ref_t& img, uint64_t fn_va,
                         uint64_t seed, bool want_trace) {
    emu::run_request_t req;

    // Function bytes: decode-bounded extent (stop at first ret followed by
    // non-code, or cap)
    std::vector<uint8_t> bytes;
    uint64_t cur = fn_va;
    for (size_t i = 0; i < 8192; ++i) {
        uint8_t buf[16];
        if (!xray_decode_at(img, cur, buf)) break;
        auto in = img.eng->decode(cur, buf, sizeof(buf));
        if (!in || in->length == 0) break;
        bytes.insert(bytes.end(), buf, buf + in->length);
        cur += in->length;
        if (bytes.size() >= kMaxFnBytes) break;
    }
    if (bytes.empty()) return {};

    req.code           = std::move(bytes);
    req.code_base      = fn_va;
    req.entry_absolute = true;
    req.entry          = fn_va;
    req.max_instructions = 20000;
    req.timeout_ms     = 3000;
    req.trace          = want_trace;
    seed_regs(req, seed);

    // Map data sections so static loads resolve. Skip anything overlapping
    // the code slice, cap per-section bytes to bound Unicorn memory.
    const uint64_t code_end = fn_va + req.code.size();
    for (const auto& s : img.pe->sections) {
        if (s.is_executable() || s.raw_size == 0) continue;
        const uint64_t va = img.base + s.rva;
        const uint64_t vend = va + std::max(s.virtual_size, s.raw_size);
        if (va < code_end && vend > fn_va) continue; // overlap guard
        auto off = img.pe->rva_to_offset(s.rva);
        if (!off || *off + s.raw_size > img.file->size()) continue;
        constexpr size_t kMaxMap = 4u << 20;
        const size_t take = std::min<size_t>(s.raw_size, kMaxMap);
        emu::emu_mem_region_t reg;
        reg.addr = va;
        reg.bytes.assign(img.file->data() + *off,
                         img.file->data() + *off + take);
        req.maps.push_back(std::move(reg));
        if (req.maps.size() >= 16) break;
    }

    emu::run_result_t res = emu::emulate_run(req);
    return res;
}

} // namespace

// flattening recovery

recovery_result_t recover_flattened(const xray::image_ref_t& img,
                                    uint64_t fn_va, size_t runs) {
    recovery_result_t res;
    res.fn_va = fn_va;
    if (runs == 0) runs = 1;

    auto cff = xray::detect_cff(img, fn_va);
    res.blocks = cff.block_count;
    if (!cff.flattened) {
        res.ok = true;
        res.mode = "none";
        res.note = "control-flow flattening not detected";
        return res;
    }

    res.flattened = true;
    res.dispatcher = cff.dispatcher;
    res.fake_edges = cff.dispatcher_backedges;

    // static dispatch-map extraction
    auto disasm_block = [&](uint64_t va, size_t max) {
        return decode_run(img, va, max);
    };

    // Case A: cmp-chain dispatcher. Walk dispatcher instructions tracking
    // `cmp state, K` -> `jcc target` pairs
    int64_t pending_state = 0;
    bool have_pending = false;
    bool saw_cmp_chain = false;
    for (const auto& in : disasm_block(cff.dispatcher, 128)) {
        const bool is_cmp_imm =
            (in.mnemonic == ZYDIS_MNEMONIC_CMP ||
             in.mnemonic == ZYDIS_MNEMONIC_SUB ||
             in.mnemonic == ZYDIS_MNEMONIC_TEST) &&
            in.op_count == 2 && in.ops[1].cls == op_class_t::imm;
        if (is_cmp_imm) {
            pending_state = static_cast<int64_t>(in.ops[1].imm);
            have_pending  = true;
            continue;
        }
        if (have_pending && in.flow == disasm::flow_t::jcc && in.has_rel_target &&
            in.rel_target != cff.dispatcher) {
            res.dispatch_map.push_back({pending_state, in.rel_target});
            saw_cmp_chain = true;
            have_pending = false;
        }
        if (in.flow == disasm::flow_t::jmp || in.flow == disasm::flow_t::ret)
            break;
    }

    // Case B: jump-table dispatcher, `jmp [table + reg*s]`
    if (!saw_cmp_chain) {
        for (const auto& in : disasm_block(cff.dispatcher, 64)) {
            if (in.flow != disasm::flow_t::jmp || in.has_rel_target) continue;
            if (in.op_count == 0 || in.ops[0].cls != op_class_t::mem) continue;
            const auto& m = in.ops[0];

            uint64_t table = 0;
            if (m.mem_base == ZYDIS_REGISTER_RIP)
                table = in.rip_rel_target;
            else if (m.mem_base == ZYDIS_REGISTER_NONE && m.mem_index != ZYDIS_REGISTER_NONE)
                table = static_cast<uint64_t>(m.disp);   // x64: absolute disp32
            else
                continue;

            const uint32_t scale = m.scale ? m.scale : 8;
            const size_t max_entries = 256;
            for (uint32_t i = 0; i < max_entries; ++i) {
                uint64_t target = 0;
                if (!read_qword_img(img, table + static_cast<uint64_t>(i) * scale,
                                    &target))
                    break;
                if (target == 0 || !is_exec_va(img, target)) break;
                res.dispatch_map.push_back({static_cast<int64_t>(i), target});
            }
            if (!res.dispatch_map.empty()) {
                res.mode = "jump_table";
                break;
            }
        }
    } else {
        res.mode = "cmp_chain";
    }

    res.real_edges_recovered = res.dispatch_map.size();
    res.ok = true;

    // emulation corroboration
    for (size_t r = 0; r < runs; ++r) {
        auto rr = run_fn(img, fn_va, 0x51CE + r, true);
        if (!rr.ok) continue;
        res.runs++;
        for (const auto& t : rr.trace)
            if (t.ip == cff.dispatcher) ++res.dispatcher_entries_observed;
    }
    res.corroborated = res.dispatcher_entries_observed > 0;
    return res;
}

// opaque predicate proof

std::vector<predicate_proof_t> prove_predicates(const xray::image_ref_t& img,
                                                uint64_t fn_va, size_t runs) {
    return prove_predicates_ex(img, fn_va, runs).proofs;
}

predicate_batch_t prove_predicates_ex(const xray::image_ref_t& img,
                                      uint64_t fn_va, size_t runs) {
    predicate_batch_t batch;
    if (runs == 0) runs = 1;

    // Static idiom candidates: jcc right after xor r,r / test r,r
    std::vector<predicate_proof_t> out;
    std::unordered_map<uint64_t, size_t> by_va; // index, not pointer: vector may reallocate
    {
        auto insns = decode_run(img, fn_va, 4096);
        out.reserve(128);
        for (size_t i = 1; i < insns.size(); ++i) {
            const auto& in   = insns[i];
            const auto& prev = insns[i - 1];
            if (in.flow != disasm::flow_t::jcc) continue;
            const bool xor_self = prev.mnemonic == ZYDIS_MNEMONIC_XOR &&
                                  prev.op_count >= 2 &&
                                  prev.ops[0].cls == op_class_t::reg &&
                                  prev.ops[1].cls == op_class_t::reg &&
                                  prev.ops[0].reg == prev.ops[1].reg;
            const bool test_self = prev.mnemonic == ZYDIS_MNEMONIC_TEST &&
                                   prev.op_count >= 2 &&
                                   prev.ops[0].cls == op_class_t::reg &&
                                   prev.ops[1].cls == op_class_t::reg &&
                                   prev.ops[0].reg == prev.ops[1].reg;
            if (!xor_self && !test_self) continue;
            predicate_proof_t p;
            p.jcc_va       = in.va;
            p.text         = in.text;
            p.static_idiom = true;
            p.total_runs   = static_cast<int>(runs);
            by_va[in.va] = out.size();
            out.push_back(p);
        }
    }

    // Dynamic sampling across seeded runs. A run that faults AFTER the branch
    // still yields a valid direction observation (the trace prefix counts);
    // only runs with no usable trace are skipped. Faults are tracked for the
    // caller's note so seen=0/total=N is explainable instead of contradictory.
    int completed_runs = 0;
    int failed_runs = 0;
    int faulted_runs = 0;
    std::string first_fault;
    for (int r = 0; r < static_cast<int>(runs); ++r) {
        auto rr = run_fn(img, fn_va, 0xBEEF + static_cast<uint64_t>(r) * 7919,
                         true);
        if (!rr.ok || rr.trace.size() < 2) {
            ++failed_runs;
            if (first_fault.empty())
                first_fault = rr.error.empty() ? rr.stopped_reason : rr.error;
            continue;
        }
        ++completed_runs;
        if (rr.fault) {
            ++faulted_runs;
            if (first_fault.empty())
                first_fault = "invalid_mem_" + rr.fault->access + " at fault ip " +
                              std::to_string(rr.fault->ip) + " (slice emulation: only "
                              "the function slice + data sections are mapped)";
        }

        std::set<uint64_t> counted;
        for (size_t i = 0; i + 1 < rr.trace.size(); ++i) {
            const auto it = by_va.find(rr.trace[i].ip);
            if (it == by_va.end()) continue;
            // One observation per branch per run (first execution wins  
            // loop-iterating predicates are not opaque)
            if (counted.count(rr.trace[i].ip)) continue;
            counted.insert(rr.trace[i].ip);

            // Taken iff the next trace ip equals the branch target. Resolve
            // the target from the static decode
            uint64_t target = 0;
            {
                auto one = decode_run(img, rr.trace[i].ip, 1);
                if (one.size() == 1 && one[0].has_rel_target)
                    target = one[0].rel_target;
            }
            predicate_proof_t& p = out[it->second];
            ++p.seen_runs;
            if (target != 0 && rr.trace[i + 1].ip == target) ++p.taken_runs;
        }
    }

    // proven_* keep their original meaning (every requested run observed the
    // branch and agreed); the batch counts + fault note let callers tell "no
    // observation because the slice faulted first" apart from "observed and
    // mixed". Faults after the branch do not invalidate its observation.
    for (auto& p : out) {
        p.proven_always_taken =
            p.seen_runs > 0 && p.taken_runs == p.seen_runs &&
            p.seen_runs == p.total_runs;
        p.proven_never_taken =
            p.seen_runs > 0 && p.taken_runs == 0 &&
            p.seen_runs == p.total_runs;
        // total_runs stays the requested count for compat.
        if (p.seen_runs == 0 && (failed_runs > 0 || faulted_runs > 0)) {
            p.text += " [no dynamic observation: " +
                      std::to_string(failed_runs + faulted_runs) + "/" +
                      std::to_string(p.total_runs) +
                      " runs unusable (slice-emulation fault" +
                      (faulted_runs > 0 ? " after branch region" : "") +
                      (first_fault.empty() ? "" : ": " + first_fault) + ")]";
        }
    }
    batch.proofs = std::move(out);
    batch.completed_runs = completed_runs;
    batch.failed_runs = failed_runs;
    batch.faulted_runs = faulted_runs;
    batch.first_fault = first_fault;
    return batch;
}

// invariant observation

invariant_result_t observe_invariants(const xray::image_ref_t& img,
                                      uint64_t fn_va, size_t runs) {
    invariant_result_t res;
    if (runs == 0) runs = 1;

    std::map<std::string, uint64_t> common;
    bool first = true;

    for (size_t r = 0; r < runs; ++r) {
        auto rr = run_fn(img, fn_va, 0xCAFE + r * 104729, false);
        if (!rr.ok) {
            res.error = "emulation failed: " +
                        (rr.error.empty() ? rr.stopped_reason : rr.error);
            return res;
        }
        // Slice emulation stops at the first unmapped callee/import: report
        // the fault with an IAT note instead of bare invalid_mem_read.
        if (rr.fault) {
            res.instructions_executed = std::max(res.instructions_executed,
                                                 rr.instructions);
            res.stopped_reason = res.stopped_reason.empty()
                ? std::string("invalid_mem_") + rr.fault->access
                : res.stopped_reason;
            res.error =
                "slice emulation faulted after " +
                std::to_string(rr.instructions) + " insns at " +
                std::to_string(rr.fault->ip) + " accessing " +
                std::to_string(rr.fault->addr) + " (" + rr.fault->access +
                "); only the function slice + data sections are mapped -- "
                "calls/jmps to other functions and unmapped IAT/import "
                "targets stop the run (pass maps= via emulate.run, or use "
                "devirt handlers for cross-function flow)";
            return res;
        }
        res.instructions_executed = std::max(res.instructions_executed,
                                             rr.instructions);
        res.stopped_reason = rr.stopped_reason;

        if (first) {
            common = rr.regs;
            first = false;
        } else {
            std::map<std::string, uint64_t> next;
            for (const auto& [name, val] : common) {
                const auto it = rr.regs.find(name);
                if (it != rr.regs.end() && it->second == val)
                    next[name] = val;
            }
            common = std::move(next);
        }
    }

    for (const auto& [name, val] : common) {
        // rsp differs legitimately with input-dependent paths only rarely;
        // report everything and let consumers judge
        res.invariants.push_back({name, val});
    }
    res.ok = true;
    return res;
}

// IAT audit

iat_audit_result_t iat_audit(const xray::image_ref_t& img,
                             uint64_t scan_va, size_t scan_size) {
    iat_audit_result_t res;

    // Known import slots by VA (from the parsed import table)
    std::map<uint64_t, std::string> known;
    for (const auto& dll : img.pe->imports)
        for (const auto& fn : dll.functions)
            if (fn.iat_rva)
                known[img.base + fn.iat_rva] = dll.dll + "!" + fn.name;

    // Scan ranges: an explicit addr+size range, else the parsed import
    // address table slots themselves (not every data-section qword). The old
    // default brute-scanned all non-exec sections as qword==pointer, so ASCII
    // text/counters/relocs counted as 551k "slots" with 542k "invalid".
    std::vector<std::pair<uint64_t, size_t>> ranges;
    if (scan_va != 0) {
        ranges.emplace_back(scan_va, scan_size);
    } else if (!known.empty()) {
        for (const auto& [slot, name] : known)
            ranges.emplace_back(slot, 8);
    } else {
        // No import table at all: fall back to the import directory region
        // when present, else report empty instead of scanning megabytes of
        // unrelated data.
        res.ok = true;
        res.note = "no import slots in parsed table; pass addr+size for a targeted scan";
        return res;
    }

    auto is_thunk = [&](uint64_t va) {
        uint8_t buf[16];
        if (!xray_decode_at(img, va, buf)) return false;
        auto in = img.eng->decode(va, buf, sizeof(buf));
        return in.has_value();
    };

    const bool explicit_range = (scan_va != 0);
    for (const auto& [base, len] : ranges) {
        const size_t qwords = len / 8;
        for (size_t i = 0; i < qwords; ++i) {
            const uint64_t slot = base + i * 8;
            uint64_t ptr = 0;
            if (!read_qword_img(img, slot, &ptr) || ptr == 0) continue;

            const auto it = known.find(slot);
            if (it != known.end()) {
                // A parsed IAT slot is a slot by construction.
                ++res.slots_scanned;
                ++res.named;
                continue;
            }
            if (!explicit_range) continue; // known-slots mode: nothing else counts
            // Explicit-range mode: only image-VA-shaped values are pointer
            // candidates; ASCII/counters are skipped, not counted invalid.
            const uint64_t img_end = img.base + img.pe->size_of_image;
            if (ptr < img.base || ptr >= img_end) continue;
            ++res.slots_scanned;
            if (is_exec_va(img, ptr) && is_thunk(ptr)) {
                ++res.unnamed_valid;
                if (res.unnamed.size() < 128)
                    res.unnamed.push_back({slot, ptr, ""});
            } else {
                ++res.invalid;
            }
        }
    }

    res.ok = true;
    return res;
}

} // namespace slop::core::analysis::recover
