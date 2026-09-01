// src/core/analysis/devirt.cpp

#include "core/analysis/devirt.hpp"

#include "core/emu/session.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <set>

namespace slop::core::analysis::devirt {

namespace {

using disasm::insn_t;
using disasm::op_class_t;

bool read_img(const xray::image_ref_t& img, uint64_t va, void* dst, size_t len) {
    if (va < img.base) return false;
    auto off = img.pe->rva_to_offset(static_cast<uint32_t>(va - img.base));
    if (!off || *off + len > img.file->size()) return false;
    std::memcpy(dst, img.file->data() + *off, len);
    return true;
}

std::vector<insn_t> decode_run(const xray::image_ref_t& img, uint64_t va,
                               size_t max) {
    std::vector<insn_t> out;
    uint64_t cur = va;
    for (size_t i = 0; i < max; ++i) {
        uint8_t buf[16];
        if (!read_img(img, cur, buf, sizeof(buf))) break;
        auto in = img.eng->decode(cur, buf, sizeof(buf));
        if (!in || in->length == 0) break;
        const bool stops = in->flow == disasm::flow_t::jmp ||
                           in->flow == disasm::flow_t::ret;
        out.push_back(std::move(*in));
        cur += out.back().length;
        if (stops) break;   // handlers end at their tail jump/ret
    }
    return out;
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

// Emulate the VM entry with deterministic seeds; trace on
emu::run_result_t run_vm(const xray::image_ref_t& img, uint64_t entry_va,
                         uint64_t seed, size_t max_insns) {
    std::vector<uint8_t> bytes;
    uint64_t cur = entry_va;
    for (size_t i = 0; i < 16384; ++i) {
        uint8_t buf[16];
        if (!read_img(img, cur, buf, sizeof(buf))) break;
        auto in = img.eng->decode(cur, buf, sizeof(buf));
        if (!in || in->length == 0) break;
        bytes.insert(bytes.end(), buf, buf + in->length);
        cur += in->length;
        if (bytes.size() >= (128u << 10)) break;
    }
    if (bytes.empty()) return {};

    emu::run_request_t req;
    req.code             = std::move(bytes);
    req.code_base        = entry_va;
    req.entry_absolute   = true;
    req.entry            = entry_va;
    req.max_instructions = static_cast<uint64_t>(max_insns);
    req.timeout_ms       = 4000;
    req.trace            = true;

    uint64_t st = seed * 0x9E3779B97F4A7C15ull + 0xA24BAED4963EE407ull;
    auto next = [&st] {
        st += 0x9E3779B97F4A7C15ull;
        uint64_t z = st;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (const char* r : { "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
                           "r8", "r9", "r10", "r11", "r12", "r13",
                           "r14", "r15" })
        req.regs[r] = next() | 1;

    return emu::emulate_run(req);
}

} // namespace

// identify

identify_result_t identify(const xray::image_ref_t& img, uint64_t fn_va) {
    identify_result_t res;
    res.fn_va = fn_va;

    auto insns = decode_run(img, fn_va, 8192);
    if (insns.empty()) { res.error = "cannot decode function range"; return res; }

    int confidence = 0;
    uint64_t last_cmp_va = 0;
    size_t chain = 0;

    for (const auto& in : insns) {
        // Indirect jumps through register-indexed memory: the dispatcher form
        if (in.flow == disasm::flow_t::jmp && !in.has_rel_target &&
            in.op_count > 0 && in.ops[0].cls == op_class_t::mem &&
            (in.ops[0].mem_index != ZYDIS_REGISTER_NONE ||
             in.ops[0].mem_base != ZYDIS_REGISTER_RIP)) {
            if (res.dispatcher == 0) {
                res.dispatcher = in.va;
                // Table-base candidates from the memory operand
                if (in.ops[0].mem_base == ZYDIS_REGISTER_RIP)
                    res.handler_table = in.rip_rel_target;
                else if (in.ops[0].mem_base == ZYDIS_REGISTER_NONE)
                    res.handler_table =
                        static_cast<uint64_t>(in.ops[0].disp);  // x64: abs disp32
                res.table_entry_size =
                    in.ops[0].scale == 4 ? 4 : 8;
            }
            ++res.indirect_jumps;
        }

        // CMP-chain density: comparisons within a 32-byte window
        if ((in.mnemonic == ZYDIS_MNEMONIC_CMP ||
             in.mnemonic == ZYDIS_MNEMONIC_SUB) && in.op_count >= 2 &&
            in.ops[1].cls == op_class_t::imm) {
            if (last_cmp_va != 0 && in.va - last_cmp_va <= 32) ++chain;
            last_cmp_va = in.va;
        }
    }
    res.cmp_chain_len = chain;

    // Reference scoring ladder: indirect jumps + cmp-chain density
    if (res.indirect_jumps > 0) confidence += 25;
    if (chain >= 3)  confidence += 25;
    if (chain >= 8)  confidence += 25;
    if (res.indirect_jumps > 2) confidence += 25;
    res.confidence_pct = std::min(confidence, 100);
    res.likely_vm = res.confidence_pct >= 25 && res.dispatcher != 0;

    res.ok = true;
    return res;
}

// handler classification

const char* classify_handler_insns(const std::vector<disasm::insn_t>& insns) {
    bool has_push = false, has_pop = false;
    bool has_add = false, has_sub = false;
    bool has_xor = false, has_and = false, has_or = false;
    bool has_shr = false, has_shl = false;
    bool has_cmp_jcc = false, has_call = false;
    bool mem_read = false, mem_write = false;

    for (const auto& in : insns) {
        switch (in.mnemonic) {
        case ZYDIS_MNEMONIC_PUSH: has_push = true; break;
        case ZYDIS_MNEMONIC_POP:  has_pop  = true; break;
        case ZYDIS_MNEMONIC_ADD:
        case ZYDIS_MNEMONIC_ADC:  has_add  = true; break;
        case ZYDIS_MNEMONIC_SUB:
        case ZYDIS_MNEMONIC_SBB:  has_sub  = true; break;
        case ZYDIS_MNEMONIC_XOR:  has_xor  = true; break;
        case ZYDIS_MNEMONIC_AND:  has_and  = true; break;
        case ZYDIS_MNEMONIC_OR:   has_or   = true; break;
        case ZYDIS_MNEMONIC_SHR:
        case ZYDIS_MNEMONIC_SAR:  has_shr  = true; break;
        case ZYDIS_MNEMONIC_SHL:  has_shl  = true; break;
        case ZYDIS_MNEMONIC_CALL: has_call = true; break;
        default: break;
        }
        if (in.flow == disasm::flow_t::jcc &&
            std::any_of(insns.begin(), insns.end(), [](const insn_t& c) {
                return c.mnemonic == ZYDIS_MNEMONIC_CMP ||
                       c.mnemonic == ZYDIS_MNEMONIC_TEST;
            }))
            has_cmp_jcc = true;

        for (uint8_t i = 0; i < in.op_count; ++i) {
            if (in.ops[i].cls != op_class_t::mem) continue;
            if (in.ops[i].write) mem_write = true;
            else                 mem_read  = true;
        }
    }

    // Priority cascade (documented reference order)
    if (has_push && !has_pop && !has_add && !has_sub && !has_xor && !has_and && !has_or)
        return "vm_push";
    if (has_pop && !has_push)                                              return "vm_pop";
    if (has_add && !has_sub)                                               return "vm_add";
    if (has_sub)                                                           return "vm_sub";
    if (has_xor && !has_and && !has_or)                                    return "vm_xor";
    if (has_and)                                                           return "vm_and";
    if (has_or)                                                            return "vm_or";
    if (has_shr)                                                           return "vm_shr";
    if (has_shl)                                                           return "vm_shl";
    if (has_cmp_jcc)                                                       return "vm_cmp_jcc";
    if (has_call)                                                          return "vm_call";
    if (mem_read && !mem_write)                                            return "vm_load";
    if (mem_write)                                                         return "vm_store";
    if (insns.size() <= 3)                                                 return "vm_nop";
    return "vm_complex";
}

classify_result_t classify_handlers(const xray::image_ref_t& img,
                                    uint64_t handler_table,
                                    uint32_t entry_size, size_t max_handlers) {
    classify_result_t res;
    res.handler_table = handler_table;

    if (handler_table == 0) { res.error = "no handler table"; return res; }

    const uint32_t sizes[] = {entry_size, 8, 4};
    for (uint32_t es : sizes) {
        if (es != 8 && es != 4) continue;
        res.entry_size = es;
        break;
    }
    if (res.entry_size == 0) { res.error = "bad entry_size (4|8)"; return res; }

    for (uint32_t slot = 0; slot < max_handlers; ++slot) {
        uint64_t target = 0;
        const uint64_t addr = handler_table +
                              static_cast<uint64_t>(slot) * res.entry_size;
        if (!read_img(img, addr, &target, res.entry_size)) break;
        if (target == 0 || !is_exec_va(img, target)) break;

        handler_t h;
        h.opcode = slot;
        h.va     = target;
        auto insns = decode_run(img, target, 128);
        h.instruction_count = insns.size();
        for (size_t i = 0; i < insns.size() && i < 16; ++i)
            h.insns.push_back(insns[i].text);
        h.classification = classify_handler_insns(insns);
        res.handlers.push_back(std::move(h));
        ++res.valid_entries;
    }

    if (res.handlers.empty()) {
        res.error = "handler table yielded no valid entries";
        return res;
    }
    res.ok = true;
    return res;
}

// bytecode trace

trace_result_t trace_bytecode(const xray::image_ref_t& img,
                              uint64_t entry_va, uint64_t dispatcher,
                              const std::vector<uint64_t>& handler_vas,
                              size_t max_ops) {
    trace_result_t res;

    // Handler VA -> opcode slot lookup with instruction-extent windows
    std::vector<std::pair<uint64_t, uint32_t>> ranges;   // [start, slot]
    for (uint32_t i = 0; i < handler_vas.size(); ++i)
        ranges.emplace_back(handler_vas[i], i);

    auto opcode_for_ip = [&](uint64_t ip) -> int {
        // Greatest handler start <= ip within its window wins
        int best = -1;
        uint64_t best_start = 0;
        for (const auto& [start, slot] : ranges)
            if (ip >= start && ip < start + 256 && start >= best_start) {
                best_start = start;
                best = static_cast<int>(slot);
            }
        return best;
    };

    emu::run_result_t rr = run_vm(img, entry_va, 0xD1CE, 60000);
    if (!rr.ok && rr.trace.empty()) {
        res.error = "emulation failed: " +
                    (rr.error.empty() ? rr.stopped_reason : rr.error);
        return res;
    }
    res.runs = 1;
    res.stopped_reason = rr.stopped_reason;

    bool in_dispatcher = false;
    std::set<uint32_t> ops_this_round;
    auto flush = [&] {
        for (uint32_t op : ops_this_round) {
            if (res.bytecode.size() >= max_ops) return;
            res.bytecode.push_back(op);
            res.handler_order.push_back(handler_vas[op]);
        }
        ops_this_round.clear();
    };

    for (const auto& t : rr.trace) {
        if (t.ip == dispatcher) {
            ++res.dispatcher_hits;
            flush();                       // close the previous handler round
            in_dispatcher = true;
            continue;
        }
        in_dispatcher = false;
        const int op = opcode_for_ip(t.ip);
        if (op >= 0) ops_this_round.insert(static_cast<uint32_t>(op));
    }
    flush();

    if (res.dispatcher_hits == 0) {
        res.note = "dispatcher never reached under seeded runs";
    }
    res.ok = true;
    return res;
}

// lifting

lift_result_t lift(const trace_result_t& trace, const classify_result_t& cls) {
    lift_result_t out;
    if (!cls.ok) { out.error = cls.error; return out; }

    std::map<uint32_t, const handler_t*> by_opcode;
    for (const auto& h : cls.handlers) by_opcode[h.opcode] = &h;

    for (size_t i = 0; i < trace.bytecode.size(); ++i) {
        const uint32_t op = trace.bytecode[i];
        lift_line_t line;
        line.opcode = op;
        if (i < trace.handler_order.size())
            line.handler_va = trace.handler_order[i];

        const auto it = by_opcode.find(op);
        if (it == by_opcode.end()) {
            line.il = "unknown_op(" + std::to_string(op) + ")";
        } else {
            ++out.covered;
            const handler_t* h = it->second;
            line.il = std::string(h->classification) + "  ; handler @ 0x" +
                      [&] {
                          char t[24];
                          std::snprintf(t, sizeof(t), "%llX",
                                        static_cast<unsigned long long>(h->va));
                          return std::string(t);
                      }();
            // First real instruction as the IL operand hint
            if (!h->insns.empty()) line.il += "\n      " + h->insns.front();
        }
        out.lines.push_back(std::move(line));
    }
    out.ok = true;
    return out;
}

std::string pseudocode(const lift_result_t& lifted) {
    std::string out = "// recovered virtual-program\nvoid vm_entry(void) {\n";
    for (const auto& l : lifted.lines) {
        // First line of an il entry is the classification token
        std::string head = l.il.substr(0, l.il.find(';'));
        while (!head.empty() && (head.back() == ' ' || head.back() == '\n'))
            head.pop_back();
        if (head.empty()) continue;
        if (head.rfind("vm_", 0) == 0) head = head.substr(3);
        out += "    " + head + "();\n";
    }
    out += "}\n";
    return out;
}

} // namespace slop::core::analysis::devirt
