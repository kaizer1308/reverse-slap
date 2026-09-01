// src/core/debugger/callstack.cpp

#include "core/debugger/callstack.hpp"

#include <cstring>
#include <set>

namespace slop::core::debugger::unwind {

namespace {

constexpr uint64_t kUserMax = 0x7FFFFFFEFFFFull;   // highest user VA

bool plausible_code(disasm::engine_t& eng, reader_t& rdr, uint64_t va) {
    if (va == 0 || va > kUserMax) return false;
    uint8_t buf[16]{};
    if (!rdr.read(va, buf, sizeof(buf))) return false;
    auto in = eng.decode(va, buf, sizeof(buf));
    return in.has_value() && in->length > 0;
}

} // namespace

std::vector<frame_t> walk_stack(disasm::engine_t& eng, reader_t& rdr,
                                uint64_t rip, uint64_t rsp, uint64_t rbp,
                                size_t max_frames) {
    std::vector<frame_t> out;
    if (max_frames == 0) return out;

    // Frame 0: the return address at [rsp] is the caller of the paused site
    uint64_t ret = 0;
    if (rdr.read(rsp, &ret, 8) && ret != 0 && ret <= kUserMax) {
        frame_t f;
        f.ret_addr = ret;
        uint8_t buf[16];
        if (rdr.read(ret, buf, sizeof(buf))) {
            if (auto in = eng.decode(ret, buf, sizeof(buf))) f.snippet = in->text;
        }
        out.push_back(std::move(f));
        if (out.size() >= max_frames) return out;
    }

    // RBP-chain walk with sanity gates
    std::set<uint64_t> seen;
    uint64_t fp = rbp;
    for (size_t guard = 0; guard < max_frames * 4 + 32; ++guard) {
        if (fp == 0 || fp > kUserMax || !seen.insert(fp).second) break;
        uint64_t saved_rbp = 0, saved_ret = 0;
        if (!rdr.read(fp, &saved_rbp, 8)) break;
        if (!rdr.read(fp + 8, &saved_ret, 8)) break;

        const bool ok_chain =
            saved_rbp == 0 ||
            (saved_rbp > fp && saved_rbp <= kUserMax);
        if (!ok_chain) break;

        frame_t f;
        f.frame_ptr = fp;
        f.ret_addr  = saved_ret;
        uint8_t buf[16];
        if (saved_ret && saved_ret <= kUserMax && rdr.read(saved_ret, buf, sizeof(buf))) {
            if (auto in = eng.decode(saved_ret, buf, sizeof(buf)))
                f.snippet = in->text;
            else
                f.ret_addr = 0;   // not code: drop frame
        }
        if (f.ret_addr) {
            // Frame 0 already reported [rsp]; skip a duplicate
            if (!(out.size() == 1 && out[0].ret_addr == f.ret_addr &&
                  out[0].frame_ptr == 0))
                out.push_back(std::move(f));
        }
        if (saved_rbp == 0) break;
        fp = saved_rbp;
        if (out.size() >= max_frames) break;
    }

    // Scan fallback when the chain died early
    if (out.size() < 3) {
        constexpr size_t kScanBytes = 0x800;
        std::set<uint64_t> known;
        for (const auto& f : out) known.insert(f.ret_addr);

        for (size_t off = 8; off < kScanBytes && out.size() < max_frames; off += 8) {
            uint64_t cand = 0;
            if (!rdr.read(rsp + off, &cand, 8)) break;
            if (cand <= rsp || cand > kUserMax || known.count(cand)) continue;

            // Memory-query gate proxy: readable via our reader, decodes as
            // an instruction start, and sits above the current stack top
            // (a real return address points back into code)
            if (!plausible_code(eng, rdr, cand)) continue;

            bool dup = false;
            for (const auto& f : out)
                if (f.ret_addr == cand) { dup = true; break; }
            if (dup) continue;

            frame_t f;
            f.ret_addr = cand;
            f.scanned  = true;
            uint8_t buf[16];
            if (rdr.read(cand, buf, sizeof(buf))) {
                if (auto in = eng.decode(cand, buf, sizeof(buf))) f.snippet = in->text;
            }
            out.push_back(std::move(f));
        }
    }
    return out;
}

seh_result_t seh_chain(reader_t& rdr, uint64_t teb_addr) {
    seh_result_t res;
    if (teb_addr == 0) {
        res.note = "no TEB address available";
        return res;
    }

    // NT_TIB at TEB+0: ExceptionList (x86), plus ExpectedDfr / etc. On x64
    // the list must be empty (-1); walk it only if it isn't
    uint64_t head = 0;
    if (!rdr.read(teb_addr, &head, 8)) {
        res.note = "TEB read failed";
        return res;
    }

    constexpr uint64_t kSentinel = 0xFFFFFFFFFFFFFFFFull;
    std::set<uint64_t> seen;
    while (head != kSentinel && head != 0) {
        if (head > kUserMax || !seen.insert(head).second) {
            res.note = "chain stop reason: implausible or cyclic entry";
            break;
        }
        // _EXCEPTION_REGISTRATION_RECORD { Next; Handler; }
        uint64_t next = 0, handler = 0;
        if (!rdr.read(head, &next, 8) || !rdr.read(head + 8, &handler, 8)) {
            res.note = "chain stop reason: unreadable record";
            break;
        }
        seh_entry_t e;
        e.handler = handler;
        e.filter  = 0;
        e.frame   = head;
        res.chain.push_back(e);
        head = next;
        if (res.chain.size() >= 32) {
            res.note = "chain truncated at 32 entries";
            break;
        }
    }
    if (head == kSentinel)
        res.chain_empty_proven = res.chain.empty();

    // x64 framed-handler candidates: scan the stack for values that look
    // like code pointers (heuristic parity with the reference viewer)
    return res;
}

} // namespace slop::core::debugger::unwind
