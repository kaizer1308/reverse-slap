// src/core/emu/session.cpp
// unicorn hooks and zydis operand sorting, all the unicorn includes stay in here

#include "core/emu/session.hpp"

#include "core/disasm/engine.hpp"
#include "core/emu/unicorn.hpp"

#include <unicorn/unicorn.h>

// Vendored header defines an unused static helper (usleep shim) that trips
// C4505 at TU end, kept suppressed for the rest of this file
#pragma warning(disable : 4505)
#include <Zydis/Zydis.h>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace slop::core::emu {

namespace {

constexpr uint64_t kReturnPage = 0x00110000;   // sentinel RET trampoline

struct reg_alias_t { const char* name; int uc_reg; };

constexpr reg_alias_t kRegAliases[] = {
    {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX},
    {"rdx", UC_X86_REG_RDX}, {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI},
    {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP},
    {"r8",  UC_X86_REG_R8},  {"r9",  UC_X86_REG_R9},  {"r10", UC_X86_REG_R10},
    {"r11", UC_X86_REG_R11}, {"r12", UC_X86_REG_R12}, {"r13", UC_X86_REG_R13},
    {"r14", UC_X86_REG_R14}, {"r15", UC_X86_REG_R15},
    {"rip", UC_X86_REG_RIP}, {"rflags", UC_X86_REG_EFLAGS},
};

bool lookup_reg(const std::string& name, int* out) {
    for (const auto& a : kRegAliases) {
        if (name == a.name) { *out = a.uc_reg; return true; }
    }
    return false;
}

const char* display_name(uint64_t canonical) {
    switch (canonical) {
    case ZYDIS_REGISTER_RAX: return "rax";
    case ZYDIS_REGISTER_RCX: return "rcx";
    case ZYDIS_REGISTER_RDX: return "rdx";
    case ZYDIS_REGISTER_RBX: return "rbx";
    case ZYDIS_REGISTER_RSP: return "rsp";
    case ZYDIS_REGISTER_RBP: return "rbp";
    case ZYDIS_REGISTER_RSI: return "rsi";
    case ZYDIS_REGISTER_RDI: return "rdi";
    case ZYDIS_REGISTER_R8:  return "r8";
    case ZYDIS_REGISTER_R9:  return "r9";
    case ZYDIS_REGISTER_R10: return "r10";
    case ZYDIS_REGISTER_R11: return "r11";
    case ZYDIS_REGISTER_R12: return "r12";
    case ZYDIS_REGISTER_R13: return "r13";
    case ZYDIS_REGISTER_R14: return "r14";
    case ZYDIS_REGISTER_R15: return "r15";
    case ZYDIS_REGISTER_RFLAGS: return "rflags";
    default: return "?";
    }
}

struct run_ctx_t {
    run_request_t const* req      = nullptr;
    taint_tracker_t      taint;
    bool                 taint_on = false;

    disasm::engine_t     eng;        // trace/event text formatting
    ZydisDecoder         decoder{};  // operand classification

    uint64_t instructions = 0;
    bool     until_hit    = false;
    bool     return_hit   = false;

    std::vector<run_result_t::trace_entry_t> trace;
    std::vector<run_result_t::write_entry_t> writes;
    size_t total_writes = 0;

    std::optional<run_result_t::fault_t> fault;

    uint64_t cur_ip        = 0;
    std::string cur_text;
    uint64_t last_event_ip = 0;
};

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);

    if (c->taint_on) c->taint.boundary();

    if (c->req->until_addr && address == c->req->until_addr) {
        c->until_hit = true;
        uc_emu_stop(uc);
        return;
    }
    if (address >= kReturnPage && address < kReturnPage + 0x1000) {
        c->return_hit = true;
        uc_emu_stop(uc);
        return;
    }

    ++c->instructions;
    c->cur_ip = address;
    c->cur_text.clear();

    // If the bytes are unreadable (unmapped callee after a CALL outside the
    // slice), do NOT decode zeros -- 00 00 decodes as "ADD [rax],al" and
    // poisons the trace with a fake fall-through. Record the gap instead.
    uint8_t bytes[16] = {};
    const size_t n = size <= sizeof(bytes) ? size : sizeof(bytes);
    bool readable = false;
    if (n > 0 && uc_mem_read(uc, address, bytes, n) == UC_ERR_OK)
        readable = true;

    if (readable) {
        if (auto insn = c->eng.decode(address, bytes, sizeof(bytes)))
            c->cur_text = insn->text;
    } else {
        c->cur_text = "<unmapped>";
    }
    if (c->req->trace && c->trace.size() < c->req->trace_max)
        c->trace.push_back({address, c->cur_text});

    if (!c->taint_on || n == 0 || !readable) return;

    ZydisDecodedInstruction zin{};
    ZydisDecodedOperand     ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&c->decoder, bytes, n, &zin, ops)))
        return;

    taint_tracker_t::insn_sources_t src;
    for (uint8_t i = 0; i < zin.operand_count; ++i) {
        // Full operand list: includes implicit GPRs (div/mul rax:rdx, rep
        // rcx/rsi/rdi, stack ops) so coarse register taint stays faithful
        const auto& op = ops[i];
        if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && op.visibility != ZYDIS_OPERAND_VISIBILITY_INVALID) {
            const uint64_t canon = taint_canonical_reg(op.reg.value);
            if (!canon) continue;
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                src.src_regs_tainted |= c->taint.reg(canon);
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE)
                src.dests.push_back({static_cast<uint32_t>(canon),
                                     /*zeroing*/ false,
                                     display_name(canon)});
        } else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (op.actions & ZYDIS_OPERAND_ACTION_MASK_READ)
                src.reads_memory = true;
        }
    }

    // Zeroing idioms clear taint even when sources appear tainted
    if ((zin.mnemonic == ZYDIS_MNEMONIC_XOR || zin.mnemonic == ZYDIS_MNEMONIC_SUB) &&
        zin.operand_count_visible == 2 &&
        ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
        ops[1].type == ZYDIS_OPERAND_TYPE_REGISTER) {
        const uint64_t a = taint_canonical_reg(ops[0].reg.value);
        const uint64_t b = taint_canonical_reg(ops[1].reg.value);
        if (a && a == b)
            for (auto& d : src.dests)
                if (d.canonical == a) d.zeroing = true;
    }

    c->taint.analyze(address, c->cur_text, src);
}

void hook_mem_read(uc_engine*, uc_mem_type, uint64_t address, int size,
                   int64_t, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    if (c->taint_on) c->taint.note_mem_read(address, static_cast<size_t>(size));
}

bool hook_mem_write(uc_engine*, uc_mem_type, uint64_t address, int size,
                    int64_t, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    const bool tainted =
        c->taint_on && c->taint.note_mem_write(address, static_cast<size_t>(size));
    ++c->total_writes;
    if (c->writes.size() < 2048)
        c->writes.push_back({c->cur_ip, address, static_cast<size_t>(size)});
    if (tainted) {
        // Propagate: the stored bytes themselves become taint carriers
        c->taint.mark_memory(address, static_cast<size_t>(size));
        if (c->cur_ip != c->last_event_ip) {
            char addr_text[32];
            std::snprintf(addr_text, sizeof(addr_text), "mem %llX",
                          static_cast<unsigned long long>(address));
            c->taint.record_event({c->cur_ip, c->cur_text, "mem", addr_text});
            c->last_event_ip = c->cur_ip;
        }
    }
    return false;
}

bool hook_mem_invalid(uc_engine* uc, uc_mem_type access, uint64_t address,
                      int size, int64_t value, void* user_data) {
    (void)size; (void)value;
    auto* c = static_cast<run_ctx_t*>(user_data);
    if (!c->fault) {   // keep the first fault
        const char* what = access == UC_MEM_FETCH_UNMAPPED ? "fetch"
                         : access == UC_MEM_WRITE_UNMAPPED ? "write"
                         : access == UC_MEM_FETCH_PROT     ? "fetch_prot"
                         : access == UC_MEM_WRITE_PROT     ? "write_prot"
                                                           : "read";
        c->fault = {c->cur_ip, address, what};
    }
    uc_emu_stop(uc);
    return false;
}

} // namespace

run_result_t emulate_run(const run_request_t& req) {
    run_result_t res;
    if (req.code.empty()) { res.error = "no code bytes"; return res; }

    unicorn_t uc;
    if (!uc.ok()) { res.error = "unicorn init failed"; return res; }

    if (!uc.map(req.code_base, req.code.size()) ||
        !uc.write(req.code_base, req.code.data(), req.code.size())) {
        res.error = "code mapping failed (unmapped/overlap?)";
        return res;
    }
    if (req.stack_size < 0x1000 || !uc.map(req.stack_base, req.stack_size)) {
        res.error = "stack mapping failed";
        return res;
    }
    for (const auto& r : req.maps) {
        if (r.bytes.empty() || !uc.map(r.addr, r.bytes.size()) ||
            !uc.write(r.addr, r.bytes.data(), r.bytes.size())) {
            res.error = "data mapping failed";
            return res;
        }
    }

    static constexpr uint8_t kRet = 0xC3;
    if (!uc.map(kReturnPage, 0x1000) || !uc.write(kReturnPage, &kRet, 1)) {
        res.error = "trampoline mapping failed";
        return res;
    }

    // Initial RSP with a return-address sentinel so clean leaf routines halt
    // deterministically with stopped_reason="return"
    uint64_t rsp = req.sp_set ? req.sp
                              : req.stack_base + req.stack_size - 0x1000;
    rsp &= ~0x7ull;
    rsp -= 8;
    uint64_t ret_sentinel = kReturnPage;
    if (!uc.write(rsp, &ret_sentinel, sizeof(ret_sentinel))) {
        res.error = "stack sentinel write failed";
        return res;
    }

    run_ctx_t ctx{};
    ctx.req       = &req;
    ctx.taint_on  = !req.taint_sources.empty();
    if (ctx.taint_on) {
        ctx.taint.reset();
        for (const auto& s : req.taint_sources)
            ctx.taint.mark_memory(s.addr, s.len);
    }
    if (!ctx.eng.init()) { res.error = "zydis engine init failed"; return res; }
    if (ZydisDecoderInit(&ctx.decoder, ZYDIS_MACHINE_MODE_LONG_64,
                         ZYDIS_STACK_WIDTH_64) != ZYAN_STATUS_SUCCESS) {
        res.error = "zydis decoder init failed";
        return res;
    }

    for (const auto& [name, value] : req.regs) {
        int id = 0;
        if (!lookup_reg(name, &id)) {
            res.error = "unknown register '" + name +
                        "' (use rax..r15, rip, rflags)";
            return res;
        }
        uint64_t v = value;
        uc_reg_write(uc.handle(), id, &v);
    }

    if (!req.entry_absolute && req.entry >= req.code.size()) {
        res.error = "entry offset outside code bytes";
        return res;
    }
    const uint64_t entry_va = req.entry_absolute ? req.entry
                                                 : req.code_base + req.entry;

    uc_hook h_code = 0, h_read = 0, h_write = 0, h_bad = 0;
    uc_hook_add(uc.handle(), &h_code, UC_HOOK_CODE,
                reinterpret_cast<void*>(hook_code), &ctx, 1, 0);
    uc_hook_add(uc.handle(), &h_read, UC_HOOK_MEM_READ,
                reinterpret_cast<void*>(hook_mem_read), &ctx, 1, 0);
    uc_hook_add(uc.handle(), &h_write, UC_HOOK_MEM_WRITE,
                reinterpret_cast<void*>(hook_mem_write), &ctx, 1, 0);
    uc_hook_add(uc.handle(), &h_bad, UC_HOOK_MEM_INVALID,
                reinterpret_cast<void*>(hook_mem_invalid), &ctx, 1, 0);

    uint64_t rip = entry_va, spv = rsp;
    uc_reg_write(uc.handle(), UC_X86_REG_RIP, &rip);
    uc_reg_write(uc.handle(), UC_X86_REG_RSP, &spv);

    const uint64_t until = req.until_addr ? req.until_addr : kReturnPage;
    const uint64_t count = req.max_instructions ? req.max_instructions : 100000;
    const uint32_t timeout_ms = std::min<uint32_t>(
        req.timeout_ms ? req.timeout_ms : 5000, 60000);
    const auto started = std::chrono::steady_clock::now();
    const uc_err err = uc_emu_start(uc.handle(), entry_va, until,
                                    static_cast<uint64_t>(timeout_ms) * 1000ull,
                                    count);
    const auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - started).count();

    // Final register snapshot
    uint64_t final_rip = 0;
    for (const auto& a : kRegAliases) {
        uint64_t v = 0;
        if (uc_reg_read(uc.handle(), a.uc_reg, &v) == UC_ERR_OK) {
            res.regs[a.name] = v;
            if (a.uc_reg == UC_X86_REG_RIP) final_rip = v;
        }
    }
    res.instructions = ctx.instructions;
    res.trace  = std::move(ctx.trace);
    res.writes = std::move(ctx.writes);
    res.total_writes = ctx.total_writes;
    res.fault  = ctx.fault;

    if (ctx.return_hit)          res.stopped_reason = "return";
    else if (ctx.until_hit)      res.stopped_reason = "until";
    else if (ctx.fault)          res.stopped_reason = std::string("invalid_mem_") + ctx.fault->access;
    else if (elapsed_ms >= static_cast<int64_t>(timeout_ms) - 50 &&
             ctx.instructions < count)
        res.stopped_reason = "timeout";   // unicorn returns OK on timeout
    else if (err == UC_ERR_OK || err == UC_ERR_FETCH_UNMAPPED ||
             err == UC_ERR_INSN_INVALID) {
        if (err == UC_ERR_FETCH_UNMAPPED && !res.fault)
            res.stopped_reason = "invalid_mem_fetch";
        else if (err == UC_ERR_INSN_INVALID)
            res.stopped_reason = "invalid_insn";
        else if (final_rip >= kReturnPage && final_rip < kReturnPage + 0x1000)
            res.stopped_reason = "return";   // stopped at the sentinel via until
        else if (req.until_addr && final_rip == req.until_addr)
            res.stopped_reason = "until";    // ditto for an explicit until
        else
            res.stopped_reason = "count";
    } else {
        res.stopped_reason = "cpu_exception";
        res.error = uc_strerror(err);
    }
    res.ok = true;

    if (ctx.taint_on) {
        ctx.taint.boundary();   // flush the final instruction's deferred dests
        res.taint_ranges = ctx.taint.tainted_ranges();
        res.taint_events = ctx.taint.events();
        res.output_tainted = req.watch_len > 0 &&
                             ctx.taint.memory_any(req.watch_addr, req.watch_len);
    }
    return res;
}

} // namespace slop::core::emu
