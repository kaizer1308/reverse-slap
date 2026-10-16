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
#include <cstdio>
#include <cstring>

namespace slop::core::emu {

namespace {

constexpr uint64_t kPageMask   = kPageSize - 1;
constexpr uint64_t kReturnPage = 0x00110000;   // sentinel RET trampoline
constexpr uint64_t kStubBase   = 0x00120000;   // one RET per import slot
constexpr uint64_t kStubStride = 8;
constexpr uint64_t kTebBase    = kStubBase + kMaxImports * kStubStride;
constexpr uint64_t kTebSize    = 0x2000;       // x64 TEB is 0x1838 bytes
constexpr uint64_t kPebBase    = kTebBase + kTebSize;
constexpr size_t   kMaxApiCalls = 1024;

struct reg_alias_t { const char* name; int uc_reg; };

constexpr reg_alias_t kRegAliases[] = {
    {"rax", UC_X86_REG_RAX}, {"rbx", UC_X86_REG_RBX}, {"rcx", UC_X86_REG_RCX},
    {"rdx", UC_X86_REG_RDX}, {"rsi", UC_X86_REG_RSI}, {"rdi", UC_X86_REG_RDI},
    {"rbp", UC_X86_REG_RBP}, {"rsp", UC_X86_REG_RSP},
    {"r8",  UC_X86_REG_R8},  {"r9",  UC_X86_REG_R9},  {"r10", UC_X86_REG_R10},
    {"r11", UC_X86_REG_R11}, {"r12", UC_X86_REG_R12}, {"r13", UC_X86_REG_R13},
    {"r14", UC_X86_REG_R14}, {"r15", UC_X86_REG_R15},
    {"rip", UC_X86_REG_RIP}, {"rflags", UC_X86_REG_EFLAGS},
    {"fs_base", UC_X86_REG_FS_BASE}, {"gs_base", UC_X86_REG_GS_BASE},
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
    bool     cancelled    = false;

    std::vector<run_result_t::trace_entry_t> trace;
    std::vector<run_result_t::write_entry_t> writes;
    size_t total_writes = 0;

    std::optional<run_result_t::fault_t> fault;

    uint64_t cur_ip        = 0;
    std::string cur_text;
    uint64_t last_event_ip = 0;

    std::map<uint64_t, uint64_t> slot_stubs;   // IAT slot va -> stub va
    uint64_t stub_end = kStubBase;             // kStubBase: no stubs
    std::vector<run_result_t::api_call_t> api_calls;
    size_t total_api_calls = 0;

    size_t paged_in          = 0;
    bool   page_in_exhausted = false;
    std::vector<uint8_t> page_buf = std::vector<uint8_t>(kPageSize);
};

// The source is caller code running under a C callback, nothing may unwind
// through unicorn
bool fetch_page(const run_request_t& req, uint64_t page, uint8_t* out) noexcept {
    if (!req.page_in) return false;
    try {
        return req.page_in(page, out);
    } catch (...) {
        return false;
    }
}

// Point every IAT slot in [lo, hi) at its stub. Unmapped slots fail quietly
// and get patched when their page comes in
void patch_slots(uc_engine* uc, const run_ctx_t& c, uint64_t lo, uint64_t hi) {
    for (auto it = c.slot_stubs.lower_bound(lo);
         it != c.slot_stubs.end() && it->first < hi; ++it)
        uc_mem_write(uc, it->first, &it->second, sizeof(it->second));
}

// Map every page an unmapped access touches from the page source. False
// leaves the access faulting
bool page_in_range(uc_engine* uc, run_ctx_t* c, uint64_t address, int size) {
    if (!c->req->page_in) return false;
    const uint64_t first = address & ~kPageMask;
    uint64_t last = (address + static_cast<uint64_t>(size > 1 ? size - 1 : 0)) & ~kPageMask;
    if (last < first) last = first;   // wrapped at the top of the address space
    for (uint64_t page = first;; page += kPageSize) {
        // a straddling access can fault with one of its pages already mapped
        uint8_t probe = 0;
        if (uc_mem_read(uc, page, &probe, 1) != UC_ERR_OK) {
            if (c->paged_in >= c->req->page_in_max) {
                c->page_in_exhausted = true;
                return false;
            }
            if (!fetch_page(*c->req, page, c->page_buf.data())) return false;
            if (uc_mem_map(uc, page, kPageSize, UC_PROT_ALL) != UC_ERR_OK ||
                uc_mem_write(uc, page, c->page_buf.data(), kPageSize) != UC_ERR_OK)
                return false;
            patch_slots(uc, *c, page, page + kPageSize);
            ++c->paged_in;
        }
        if (page == last) return true;
    }
}

// A call through a stubbed IAT slot landed here: log it, set the return
// value, and let the stub's RET go back to the caller
void on_import(uc_engine* uc, run_ctx_t* c, uint64_t address) {
    const size_t idx = static_cast<size_t>((address - kStubBase) / kStubStride);
    const import_slot_t& slot = c->req->imports[idx];
    const std::string& name = slot.name;

    ++c->total_api_calls;
    if (c->api_calls.size() < kMaxApiCalls) {
        run_result_t::api_call_t call;
        call.ip   = c->cur_ip;   // still the instruction that got us here
        call.name = name;
        uint64_t rsp = 0;
        uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
        uc_mem_read(uc, rsp, &call.ret, sizeof(call.ret));
        static constexpr int kArgRegs[4] = {UC_X86_REG_RCX, UC_X86_REG_RDX,
                                            UC_X86_REG_R8,  UC_X86_REG_R9};
        for (int i = 0; i < 4; ++i) uc_reg_read(uc, kArgRegs[i], &call.args[i]);
        c->api_calls.push_back(std::move(call));
    }

    uint64_t rax = slot.has_ret ? slot.ret : c->req->api_ret;
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);

    ++c->instructions;
    c->cur_ip = address;
    c->cur_text = "api " + name;
    if (c->req->trace && c->trace.size() < c->req->trace_max)
        c->trace.push_back({address, c->cur_text});
    if (c->taint_on) {
        // rax is a constant now, and an empty analyze keeps the previous
        // instruction's dests from being applied a second time
        c->taint.set_reg(ZYDIS_REGISTER_RAX, false);
        c->taint.analyze(address, c->cur_text, {});
    }
}

void hook_code(uc_engine* uc, uint64_t address, uint32_t size, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);

    if (c->taint_on) c->taint.boundary();

    // Caller cancellation (MCP notifications/cancelled) must stop the run now,
    // not after the full timeout budget
    if (c->req->cancel.cancelled()) {
        c->cancelled = true;
        uc_emu_stop(uc);
        return;
    }

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
    if (address >= kStubBase && address < c->stub_end) {
        on_import(uc, c, address);
        return;
    }

    ++c->instructions;
    c->cur_ip = address;

    // Instruction text and operands only feed the trace and taint; skip the
    // per-instruction read + decode + format when neither wants them
    const bool want_trace = c->req->trace && c->trace.size() < c->req->trace_max;
    if (!want_trace && !c->taint_on) return;
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
    if (want_trace)
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
                    int64_t value, void* user_data) {
    auto* c = static_cast<run_ctx_t*>(user_data);
    const bool tainted =
        c->taint_on && c->taint.note_mem_write(address, static_cast<size_t>(size));
    ++c->total_writes;
    if (c->writes.size() < 2048) {
        uint64_t stored = 0;
        if (size == 8)                stored = static_cast<uint64_t>(value);
        else if (size > 0 && size < 8) stored = static_cast<uint64_t>(value) &
                                                ((1ull << (size * 8)) - 1);
        c->writes.push_back({c->cur_ip, address, static_cast<size_t>(size), stored});
    }
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
    (void)value;
    auto* c = static_cast<run_ctx_t*>(user_data);
    // unicorn 2 retries the access when the hook maps the page and returns true
    const bool unmapped = access == UC_MEM_READ_UNMAPPED ||
                          access == UC_MEM_WRITE_UNMAPPED ||
                          access == UC_MEM_FETCH_UNMAPPED;
    if (unmapped && page_in_range(uc, c, address, size)) return true;
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

// Zeroed TEB + PEB with the fields code reads first: gs:[0x30] self,
// gs:[0x60] PEB, stack bounds, client ids, PEB.ImageBaseAddress. Everything
// else reads 0, so PEB.BeingDebugged / NtGlobalFlag checks see a clean process
bool map_teb(unicorn_t& uc, const run_request_t& req) {
    if (!uc.map(kTebBase, kTebSize + kPageSize)) return false;
    std::vector<uint8_t> blk(kTebSize + kPageSize, 0);
    auto put = [&blk](size_t off, uint64_t v) { std::memcpy(blk.data() + off, &v, sizeof(v)); };
    put(0x08, req.stack_base + req.stack_size);   // NtTib.StackBase
    put(0x10, req.stack_base);                    // NtTib.StackLimit
    put(0x30, kTebBase);                          // NtTib.Self
    put(0x40, 0x1000);                            // ClientId.UniqueProcess
    put(0x48, 0x1004);                            // ClientId.UniqueThread
    put(0x60, kPebBase);                          // ProcessEnvironmentBlock
    put(kTebSize + 0x10, req.image_base);         // PEB.ImageBaseAddress
    if (!uc.write(kTebBase, blk.data(), blk.size())) return false;
    uint64_t gs = kTebBase;
    return uc_reg_write(uc.handle(), UC_X86_REG_GS_BASE, &gs) == UC_ERR_OK;
}

// Page by page so a dump running into unmapped memory keeps its readable
// head. Pages the run never touched still read from the page source
emu_mem_region_t read_back(const unicorn_t& uc, const run_request_t& req,
                           const run_request_t::dump_range_t& d) {
    emu_mem_region_t m;
    m.addr = d.addr;
    m.bytes.reserve(d.len);
    std::vector<uint8_t> page;
    uint64_t a = d.addr;
    size_t left = d.len;
    while (left) {
        const size_t chunk = std::min<size_t>(left, kPageSize - (a & kPageMask));
        const size_t at = m.bytes.size();
        m.bytes.resize(at + chunk);
        if (!uc.read(a, m.bytes.data() + at, chunk)) {
            if (page.empty()) page.resize(kPageSize);
            if (!fetch_page(req, a & ~kPageMask, page.data())) {
                m.bytes.resize(at);
                break;
            }
            std::memcpy(m.bytes.data() + at, page.data() + (a & kPageMask), chunk);
        }
        a += chunk;
        left -= chunk;
    }
    return m;
}

} // namespace

run_result_t emulate_run(const run_request_t& req) {
    run_result_t res;
    if (req.code.empty()) { res.error = "no code bytes"; return res; }
    if (req.imports.size() > kMaxImports) {
        res.error = "too many imports (max 16384)";
        return res;
    }

    unicorn_t uc;
    if (!uc.ok()) { res.error = "unicorn init failed"; return res; }

    if (!uc.map(req.code_base, req.code.size())) {
        res.error = "code mapping failed (unmapped/overlap?)";
        return res;
    }
    // A slice ending mid-page has to run into the real next bytes, not zero
    // fill, so the pages it shares come from the source first
    if (req.page_in) {
        std::vector<uint8_t> page(kPageSize);
        const uint64_t lo = req.code_base & ~kPageMask;
        const uint64_t hi = (req.code_base + req.code.size() + kPageMask) & ~kPageMask;
        for (uint64_t p = lo; p < hi; p += kPageSize)
            if (fetch_page(req, p, page.data())) uc.write(p, page.data(), kPageSize);
    }
    if (!uc.write(req.code_base, req.code.data(), req.code.size())) {
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

    run_ctx_t ctx{};
    ctx.req = &req;

    // One RET per import, int3 between them so a stray jump into a stub
    // stops instead of sliding into the next one
    if (!req.imports.empty()) {
        const size_t len = req.imports.size() * kStubStride;
        std::vector<uint8_t> stubs((len + kPageMask) & ~kPageMask, 0xCC);
        for (size_t i = 0; i < req.imports.size(); ++i) {
            stubs[i * kStubStride] = kRet;
            ctx.slot_stubs[req.imports[i].slot] = kStubBase + i * kStubStride;
        }
        if (!uc.map(kStubBase, stubs.size()) ||
            !uc.write(kStubBase, stubs.data(), stubs.size())) {
            res.error = "import stub mapping failed";
            return res;
        }
        ctx.stub_end = kStubBase + len;
        patch_slots(uc.handle(), ctx, 0, UINT64_MAX);
    }

    // Best effort: a caller map over the TEB pages or a caller gs_base wins
    if (!req.regs.count("gs_base")) res.teb_mapped = map_teb(uc, req);

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
                        "' (use rax..r15, rip, rflags, fs_base, gs_base)";
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
    if (ctx.taint_on)   // the read hook only feeds taint; skip the per-access callback otherwise
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
        req.timeout_ms ? req.timeout_ms : 5000, kMaxTimeoutMs);
    const uc_err err = uc_emu_start(uc.handle(), entry_va, until,
                                    static_cast<uint64_t>(timeout_ms) * 1000ull,
                                    count);
    // unicorn returns OK on timeout; its timer thread records whether it fired
    size_t timed_out = 0;
    uc_query(uc.handle(), UC_QUERY_TIMEOUT, &timed_out);

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
    res.api_calls = std::move(ctx.api_calls);
    res.total_api_calls = ctx.total_api_calls;
    res.paged_in = ctx.paged_in;
    res.page_in_exhausted = ctx.page_in_exhausted;
    res.fault  = ctx.fault;

    if (ctx.cancelled)           res.stopped_reason = "cancelled";
    else if (ctx.return_hit)     res.stopped_reason = "return";
    else if (ctx.until_hit)      res.stopped_reason = "until";
    else if (ctx.fault)          res.stopped_reason = std::string("invalid_mem_") + ctx.fault->access;
    else if (timed_out)          res.stopped_reason = "timeout";
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

    for (const auto& d : req.dumps) res.memory.push_back(read_back(uc, req, d));

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
