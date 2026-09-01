// src/core/analysis/xray.cpp

#include "core/analysis/xray.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace slop::core::analysis::xray {

namespace {

using disasm::insn_t;
using disasm::op_class_t;

// Read `len` bytes at va out of the pinned image. False when unmapped
bool read_img(const image_ref_t& img, uint64_t va, void* dst, size_t len) {
    if (va < img.base) return false;
    const uint32_t rva = static_cast<uint32_t>(va - img.base);
    auto off = img.pe->rva_to_offset(rva);
    if (!off) return false;
    if (*off + len > img.file->size()) return false;
    std::memcpy(dst, img.file->data() + *off, len);
    return true;
}

// Section containing va (by VA), nullptr when outside the image
const disasm::pe_section_t* section_for_va(const image_ref_t& img, uint64_t va) {
    const uint32_t rva = static_cast<uint32_t>(va - img.base);
    for (const auto& s : img.pe->sections)
        if (rva >= s.rva && rva < s.rva + std::max(s.virtual_size, s.raw_size))
            return &s;
    return nullptr;
}

bool is_exec_va(const image_ref_t& img, uint64_t va) {
    const auto* s = section_for_va(img, va);
    return s && s->is_executable();
}

std::string reg_name(ZydisRegister r) {
    const char* s = ZydisRegisterGetString(r);
    return s ? s : "";
}

// Import map: IAT slot VA -> "dll!name" for API-name lookups
std::unordered_map<uint64_t, std::string> build_iat_map(const image_ref_t& img) {
    std::unordered_map<uint64_t, std::string> out;
    for (const auto& dll : img.pe->imports)
        for (const auto& fn : dll.functions)
            if (fn.iat_rva && !fn.name.empty())
                out[img.base + fn.iat_rva] = dll.dll + "!" + fn.name;
    return out;
}

} // namespace

// shared decode helpers

uint64_t function_bound(const image_ref_t& img, uint64_t va) {
    if (!img.fns || va < img.base) return 0;
    for (const auto& f : img.fns->functions()) {
        if (f.size == 0) continue;
        if (va >= f.va && va < f.va + f.size) return f.va + f.size;
    }
    return 0;
}

std::vector<disasm::insn_t> decode_range(const image_ref_t& img,
                                         uint64_t va, size_t max,
                                         uint64_t end_va) {
    std::vector<insn_t> out;
    out.reserve(std::min<size_t>(max, 4096));
    uint64_t cur = va;
    for (size_t i = 0; i < max; ++i) {
        if (end_va && cur >= end_va) break;   // function (or caller) bound
        uint8_t buf[16];
        if (!read_img(img, cur, buf, sizeof(buf))) break;
        auto insn = img.eng->decode(cur, buf, sizeof(buf));
        if (!insn || insn->length == 0) break;
        out.push_back(std::move(*insn));
        cur += out.back().length;
    }
    return out;
}

// CFG

cfg_result_t build_cfg(const image_ref_t& img, uint64_t fn_va,
                       size_t max_blocks) {
    cfg_result_t res;
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));
    if (insns.empty()) { res.error = "cannot decode function range"; return res; }

    // Block heads: entry + branch targets + post-branch fallthroughs
    std::set<uint64_t> heads{fn_va};
    uint64_t end = fn_va;
    std::vector<std::pair<uint64_t, uint64_t>> edges;   // from_insn -> target
    for (const auto& in : insns) {
        end = in.va + in.length;
        if (in.flow == disasm::flow_t::ret) continue;
        if (in.flow == disasm::flow_t::call) continue;
        if (in.has_rel_target) {
            heads.insert(in.rel_target);
            edges.emplace_back(in.va, in.rel_target);
            if (in.va + in.length < end + 16)
                heads.insert(in.va + in.length);          // fallthrough head
        } else if (in.flow == disasm::flow_t::jmp) {
            break;                                        // unconditional tail
        }
    }

    heads.erase(heads.upper_bound(end), heads.end());

    std::vector<block_t>& blocks = res.blocks;
    for (auto it = heads.begin(); it != heads.end(); ++it) {
        block_t b;
        b.start = *it;
        auto nxt = std::next(it);
        b.end = (nxt != heads.end()) ? *nxt : end;
        if (b.end <= b.start) continue;
        blocks.push_back(b);
        if (blocks.size() >= max_blocks) { res.truncated = true; break; }
    }

    // Instruction counts per block + successor edges from branch insns
    std::unordered_map<uint64_t, size_t> idx_of;
    for (size_t i = 0; i < blocks.size(); ++i) idx_of[blocks[i].start] = i;

    size_t cursor = 0;
    for (auto& b : blocks) {
        while (cursor < insns.size() && insns[cursor].va < b.start) ++cursor;
        size_t c = cursor;
        while (c < insns.size() && insns[c].va < b.end) { ++b.instructions; ++c; }
    }

    for (const auto& [from, to] : edges) {
        // Which block does `from` live in?
        block_t* src = nullptr;
        for (auto& b : blocks)
            if (from >= b.start && from < b.end) { src = &b; break; }
        if (!src) continue;
        if (std::find(src->successors.begin(), src->successors.end(), to)
                == src->successors.end())
            src->successors.push_back(to);
    }

    // Fallthrough successors for conditional branches that end a block
    for (size_t i = 0; i < blocks.size(); ++i) {
        auto& b = blocks[i];
        insn_t last{};
        size_t c = 0;
        while (c < insns.size() && insns[c].va < b.start) ++c;
        while (c < insns.size() && insns[c].va < b.end) { last = insns[c]; ++c; }
        if (last.flow != disasm::flow_t::jcc &&
            last.flow != disasm::flow_t::none) continue;
        const uint64_t fall = last.va + last.length;
        if ((last.flow == disasm::flow_t::jcc || fall == b.end) &&
            idx_of.count(fall) &&
            std::find(b.successors.begin(), b.successors.end(), fall)
                == b.successors.end())
            b.successors.push_back(fall);
    }

    res.edge_count = 0;
    for (const auto& b : blocks) res.edge_count += b.successors.size();
    for (const auto& b : blocks)
        for (uint64_t t : b.successors)
            if (t <= b.start) ++res.back_edges;

    const double n = static_cast<double>(blocks.size());
    const double e = static_cast<double>(res.edge_count);
    res.cyclomatic = static_cast<uint64_t>(std::max(1.0, e - n + 2.0));
    res.ok = true;
    return res;
}

// complexity

namespace {

bool is_arith_mnemonic(ZydisMnemonic m) {
    switch (m) {
    case ZYDIS_MNEMONIC_ADD: case ZYDIS_MNEMONIC_SUB:
    case ZYDIS_MNEMONIC_MUL: case ZYDIS_MNEMONIC_IMUL:
    case ZYDIS_MNEMONIC_DIV: case ZYDIS_MNEMONIC_IDIV:
    case ZYDIS_MNEMONIC_SHL: case ZYDIS_MNEMONIC_SHR:
    case ZYDIS_MNEMONIC_SAR:
        return true;
    default:
        return false;
    }
}

bool is_string_mnemonic(ZydisMnemonic m) {
    switch (m) {
    case ZYDIS_MNEMONIC_MOVSB: case ZYDIS_MNEMONIC_MOVSW:
    case ZYDIS_MNEMONIC_MOVSD: case ZYDIS_MNEMONIC_MOVSQ:
    case ZYDIS_MNEMONIC_CMPSB: case ZYDIS_MNEMONIC_CMPSW:
    case ZYDIS_MNEMONIC_CMPSD: case ZYDIS_MNEMONIC_CMPSQ:
    case ZYDIS_MNEMONIC_SCASB: case ZYDIS_MNEMONIC_SCASW:
    case ZYDIS_MNEMONIC_SCASD: case ZYDIS_MNEMONIC_SCASQ:
    case ZYDIS_MNEMONIC_LODSB: case ZYDIS_MNEMONIC_LODSW:
    case ZYDIS_MNEMONIC_LODSD: case ZYDIS_MNEMONIC_LODSQ:
    case ZYDIS_MNEMONIC_STOSB: case ZYDIS_MNEMONIC_STOSW:
    case ZYDIS_MNEMONIC_STOSD: case ZYDIS_MNEMONIC_STOSQ:
        return true;
    }
    return false;
}

} // namespace

complexity_result_t function_complexity(const image_ref_t& img, uint64_t fn_va) {
    complexity_result_t out;
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));
    auto cfg = build_cfg(img, fn_va);

    out.basic_block_count = cfg.blocks.size();
    out.edge_count        = cfg.edge_count;
    out.cyclomatic        = cfg.cyclomatic;

    std::unordered_set<uint32_t> opcodes;
    std::unordered_set<uint64_t> operands;
    for (const auto& in : insns) {
        ++out.instruction_count;
        opcodes.insert(static_cast<uint32_t>(in.mnemonic));
        switch (in.flow) {
        case disasm::flow_t::call: ++out.call_count; break;
        case disasm::flow_t::jcc:
        case disasm::flow_t::jmp:  ++out.branch_count; break;
        case disasm::flow_t::ret:  ++out.return_count; break;
        default: break;
        }
        if (is_arith_mnemonic(in.mnemonic))   ++out.arithmetic_ops;
        if (is_string_mnemonic(in.mnemonic))  ++out.string_operations;
        for (uint8_t i = 0; i < in.op_count; ++i) {
            const auto& op = in.ops[i];
            if (op.cls == op_class_t::mem) ++out.memory_accesses;
            // Halstead-style proxies: unique opcode, unique operand shape
            uint64_t key = static_cast<uint64_t>(in.mnemonic) << 32;
            if (op.cls == op_class_t::reg)  key ^= static_cast<uint64_t>(op.reg);
            if (op.cls == op_class_t::imm)  key ^= op.imm;
            if (op.cls == op_class_t::mem)  key ^= static_cast<uint64_t>(op.mem_base);
            operands.insert(key);
        }
    }
    out.unique_operators = opcodes.size();
    out.unique_operands  = operands.size();

    const size_t branches = out.branch_count + out.call_count / 4;
    const char* rating = "simple";
    if      (branches > 50) rating = "extremely_complex";
    else if (branches > 20) rating = "very_complex";
    else if (branches > 10) rating = "complex";
    else if (branches > 5)  rating = "moderate";
    out.rating = rating;
    return out;
}

// obfuscation

obfuscation_result_t detect_obfuscation(const image_ref_t& img, uint64_t fn_va) {
    obfuscation_result_t res;
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));
    if (insns.empty()) return res;

    int nop_run = 0;
    for (size_t i = 0; i < insns.size(); ++i) {
        const auto& in = insns[i];

        if (in.mnemonic == ZYDIS_MNEMONIC_NOP) {
            ++nop_run;
            continue;
        }
        if (nop_run >= 4) {
            pattern_hit_t h;
            h.type    = "nop_sled";
            h.address = insns[i - nop_run].va;
            h.detail  = std::to_string(nop_run) + " consecutive nops";
            res.patterns.push_back(std::move(h));
            ++res.junk_sequences;
        }
        nop_run = 0;

        // Opaque predicate: jcc right after zeroing idiom
        if (i > 0 && in.flow == disasm::flow_t::jcc) {
            const auto& prev = insns[i - 1];
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
            if (xor_self || test_self) {
                pattern_hit_t h;
                h.type    = "opaque_predicate";
                h.address = in.va;
                h.detail  = in.text + " after " +
                            (xor_self ? "xor r,r" : "test r,r");
                res.patterns.push_back(std::move(h));
                ++res.opaque_predicates;
            }
        }

        // Indirect jumps (through reg/mem)
        if (in.flow == disasm::flow_t::jmp && !in.has_rel_target) {
            pattern_hit_t h;
            h.type    = "indirect_jump";
            h.address = in.va;
            h.detail  = in.text;
            res.patterns.push_back(std::move(h));
            ++res.indirect_jumps;
        }

        // push/ret trampolines
        if (in.mnemonic == ZYDIS_MNEMONIC_PUSH && i + 1 < insns.size() &&
            insns[i + 1].mnemonic == ZYDIS_MNEMONIC_RET) {
            pattern_hit_t h;
            h.type    = "push_ret";
            h.address = in.va;
            h.detail  = "push+ret redirect";
            res.patterns.push_back(std::move(h));
            ++res.push_ret;
        }
    }
    if (nop_run >= 4) {
        pattern_hit_t h;
        h.type = "nop_sled";
        h.address = insns[insns.size() - nop_run].va;
        h.detail = std::to_string(nop_run) + " consecutive nops";
        res.patterns.push_back(std::move(h));
        ++res.junk_sequences;
    }

    // dead heads means function scope heads with no incoming refs, the
    // mcp layer passes the session index when it matters
    if (img.fns) {
        int reported = 0;
        for (const auto& fn : img.fns->functions()) {
            if (fn.va < fn_va || fn.va >= fn_va + 0x10000) continue;
            if (!is_exec_va(img, fn.va)) continue;
            if (fn.va == fn_va) continue;
            // A previous instruction falling through disqualifies
            uint8_t probe[16];
            bool falls_in = false;
            for (int back = 1; back <= 16 && !falls_in; ++back) {
                if (!read_img(img, fn.va - back, probe, sizeof(probe))) break;
                auto p = img.eng->decode(fn.va - back, probe, sizeof(probe));
                if (p && p->length == back &&
                    p->flow != disasm::flow_t::jmp &&
                    p->flow != disasm::flow_t::ret &&
                    p->flow != disasm::flow_t::jcc)
                    falls_in = true;
            }
            if (falls_in) continue;
            if (reported < 10) {
                pattern_hit_t h;
                h.type    = "dead_head";
                h.address = fn.va;
                h.detail  = "no incoming references";
                res.patterns.push_back(std::move(h));
                ++res.dead_heads;
                ++reported;
            }
        }
    }

    // Weighted score (documented heuristic ladder)
    int score = 0;
    score += static_cast<int>(std::min(res.opaque_predicates * 10, size_t{25}));
    if (res.dead_heads > 2)     score += 15;
    score += static_cast<int>(std::min(res.junk_sequences * 8, size_t{20}));
    score += static_cast<int>(std::min(res.indirect_jumps * 15, size_t{25}));
    if (res.push_ret > 0)       score += 15;
    res.score_pct = std::min(score, 100);
    return res;
}

// string decryption recon

std::vector<string_cand_t> string_decrypt_recon(const image_ref_t& img,
                                                uint64_t fn_va) {
    std::vector<string_cand_t> out;
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));

    auto printable = [](uint64_t v, int nbytes) {
        int ok = 0;
        for (int i = 0; i < nbytes; ++i) {
            const uint8_t c = static_cast<uint8_t>(v >> (8 * i));
            if (c >= 0x20 && c <= 0x7E) ++ok;
        }
        return ok == nbytes;
    };

    // Stack strings: mov [mem], imm with printable immediates
    std::string acc;
    uint64_t acc_start = 0;
    size_t acc_units = 0;
    auto flush = [&]() {
        if (acc_units >= 3 && !acc.empty()) {
            string_cand_t c;
            c.type = "stack_string";
            c.address = acc_start;
            c.reconstructed = acc;
            c.length = acc.size();
            out.push_back(std::move(c));
        }
        acc.clear();
        acc_units = 0;
    };
    for (const auto& in : insns) {
        const bool stack_mov =
            in.mnemonic == ZYDIS_MNEMONIC_MOV &&
            in.op_count == 2 &&
            in.ops[0].cls == op_class_t::mem &&
            in.ops[1].cls == op_class_t::imm;
        if (stack_mov) {
            const auto& imm_op = in.ops[1];
            int nbytes = 1;
            if ((imm_op.imm & 0xFFFFFF00ull) != 0) nbytes = 4;
            if ((imm_op.imm & 0xFFFFFFFF00000000ull) != 0) nbytes = 8;
            if (printable(imm_op.imm, nbytes)) {
                if (acc_units == 0) acc_start = in.va;
                for (int i = 0; i < nbytes; ++i) {
                    char ch = static_cast<char>(imm_op.imm >> (8 * i));
                    if (ch) acc.push_back(ch);
                }
                ++acc_units;
                continue;
            }
        }
        flush();
    }
    flush();

    // XOR-with-immediate patterns (decryption-loop fingerprints)
    size_t run = 0;
    uint64_t run_start = 0, last_key = 0;
    for (const auto& in : insns) {
        const bool xor_imm =
            in.mnemonic == ZYDIS_MNEMONIC_XOR &&
            in.op_count == 2 &&
            in.ops[0].cls == op_class_t::reg &&
            in.ops[1].cls == op_class_t::imm &&
            in.ops[1].imm != 0;
        if (xor_imm) {
            if (run == 0) run_start = in.va;
            last_key = in.ops[1].imm;
            ++run;
        } else {
            if (run >= 2) {
                string_cand_t c;
                c.type    = "xor_pattern";
                c.address = run_start;
                c.xor_key = last_key;
                c.length  = run;
                out.push_back(std::move(c));
            }
            run = 0;
        }
    }
    if (run >= 2) {
        string_cand_t c;
        c.type = "xor_pattern"; c.address = run_start;
        c.xor_key = last_key;   c.length = run;
        out.push_back(std::move(c));
    }
    return out;
}

// indirect calls

std::vector<indirect_call_t> indirect_calls(const image_ref_t& img,
                                            uint64_t fn_va) {
    std::vector<indirect_call_t> out;
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));
    for (const auto& in : insns) {
        if (in.flow != disasm::flow_t::call && in.flow != disasm::flow_t::jmp)
            continue;
        if (in.has_rel_target) continue;                 // direct

        indirect_call_t c;
        c.address = in.va;
        c.text    = in.text;
        for (uint8_t i = 0; i < in.op_count; ++i) {
            const auto& op = in.ops[i];
            if (op.cls == op_class_t::mem) {
                if (op.mem_base != ZYDIS_REGISTER_NONE &&
                    op.mem_base != ZYDIS_REGISTER_RIP) {
                    c.classification = "vtable_call";
                    c.base_register  = reg_name(op.mem_base);
                    c.offset         = op.disp;
                } else if (op.mem_base == ZYDIS_REGISTER_RIP) {
                    c.classification = "function_pointer";
                    c.target         = in.rip_rel_target;
                    uint64_t ptr = 0;
                    if (read_img(img, c.target, &ptr, sizeof(ptr)) &&
                        is_exec_va(img, ptr))
                        c.target = ptr;
                } else if (op.disp != 0 || op.mem_index != ZYDIS_REGISTER_NONE) {
                    c.classification = "function_pointer";
                }
            } else if (op.cls == op_class_t::reg) {
                c.classification = "register_call";
            }
        }
        if (!c.classification.empty()) out.push_back(std::move(c));
    }
    return out;
}

// anti-analysis

anti_analysis_result_t detect_anti_analysis(const image_ref_t& img,
                                            uint64_t fn_va) {
    static const char* kDebugApis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "GetTickCount", "QueryPerformanceCounter",
        "NtQuerySystemInformation", "DbgBreakPoint", "DbgUiRemoteBreakin"
    };
    static const char* kVmApis[] = {
        "GetSystemFirmwareTable", "EnumSystemFirmwareTable"
    };

    anti_analysis_result_t res;
    auto iat = build_iat_map(img);
    auto insns = decode_range(img, fn_va, 8192, function_bound(img, fn_va));

    for (const auto& in : insns) {
        // Calls/jmps through IAT slots (rip-relative or absolute mem)
        if (in.flow == disasm::flow_t::call || in.flow == disasm::flow_t::jmp) {
            uint64_t slot = 0;
            if (in.has_rip_rel) slot = in.rip_rel_target;
            else if (in.op_count > 0 && in.ops[0].cls == op_class_t::mem &&
                     in.ops[0].mem_base == ZYDIS_REGISTER_NONE)
                slot = img.base + static_cast<uint32_t>(in.ops[0].disp);
            if (slot) {
                const auto it = iat.find(slot);
                if (it != iat.end()) {
                    for (const char* api : kDebugApis)
                        if (it->second.find(api) != std::string::npos) {
                            detection_t d;
                            d.type = "debug_api"; d.address = in.va;
                            d.detail = it->second;
                            res.detections.push_back(std::move(d));
                            ++res.anti_debug;
                        }
                    for (const char* api : kVmApis)
                        if (it->second.find(api) != std::string::npos) {
                            detection_t d;
                            d.type = "vm_api"; d.address = in.va;
                            d.detail = it->second;
                            res.detections.push_back(std::move(d));
                            ++res.anti_vm;
                        }
                }
            }
        }

        if (in.mnemonic == ZYDIS_MNEMONIC_CPUID) {
            detection_t d; d.type = "cpuid"; d.address = in.va;
            d.detail = "CPUID (VM detection primitive)";
            res.detections.push_back(std::move(d));
            ++res.anti_vm;
        }
        if (in.mnemonic == ZYDIS_MNEMONIC_RDTSC) {
            detection_t d; d.type = "rdtsc"; d.address = in.va;
            d.detail = "RDTSC timing check";
            res.detections.push_back(std::move(d));
            ++res.timing_checks;
        }
        if (in.mnemonic == ZYDIS_MNEMONIC_INT3 ||
            in.mnemonic == ZYDIS_MNEMONIC_INT) {
            detection_t d; d.type = "int_trap"; d.address = in.va;
            d.detail = in.text;
            res.detections.push_back(std::move(d));
            ++res.traps;
        }
        if (in.mnemonic == ZYDIS_MNEMONIC_IN) {
            detection_t d; d.type = "vm_backdoor_port"; d.address = in.va;
            d.detail = "IN instruction (VMware/QEMU backdoor port)";
            res.detections.push_back(std::move(d));
            ++res.anti_vm;
        }
    }

    int score = 0;
    score += static_cast<int>(std::min(res.anti_debug * 15, size_t{40}));
    score += static_cast<int>(std::min(res.anti_vm * 15, size_t{30}));
    score += static_cast<int>(std::min(res.timing_checks * 15, size_t{20}));
    if (res.traps > 0) score += 10;
    res.score_pct = std::min(score, 100);
    return res;
}

// inline hooks

std::vector<hook_hit_t> detect_hooks(const image_ref_t& img,
                                     size_t max_functions) {
    std::vector<hook_hit_t> out;
    if (!img.fns) return out;
    const auto& fns = img.fns->functions();
    const size_t cap = std::min(fns.size(), max_functions);

    for (size_t i = 0; i < cap; ++i) {
        uint8_t pro[16]{};
        if (!read_img(img, fns[i].va, pro, sizeof(pro))) continue;

        hook_hit_t h;
        h.address = fns[i].va;
        h.prologue_hex.reserve(32);
        char tmp[8];
        for (int b = 0; b < 8; ++b) {
            std::snprintf(tmp, sizeof(tmp), "%02X", pro[b]);
            h.prologue_hex += tmp;
        }

        if (pro[0] == 0xE9) {
            const int32_t rel =
                static_cast<int32_t>(pro[1]) |
                (static_cast<int32_t>(pro[2]) << 8) |
                (static_cast<int32_t>(pro[3]) << 16) |
                (static_cast<int32_t>(pro[4]) << 24);
            h.hook_type = "jmp_rel32";
            h.target    = fns[i].va + 5 + static_cast<int64_t>(rel);
            out.push_back(std::move(h));
            continue;
        }
        if (pro[0] == 0xFF && pro[1] == 0x25) {
            const int32_t disp = static_cast<int32_t>(
                pro[2] | (pro[3] << 8) | (pro[4] << 16) | (pro[5] << 24));
            h.hook_type = "jmp_indirect_rip";
            const uint64_t slot = fns[i].va + 6 + static_cast<int64_t>(disp);
            uint64_t tgt = 0;
            if (read_img(img, slot, &tgt, sizeof(tgt))) h.target = tgt;
            out.push_back(std::move(h));
            continue;
        }
        if (pro[0] == 0x48 && pro[1] == 0xB8 && pro[10] == 0xFF && pro[11] == 0xE0) {
            uint64_t tgt = 0;
            std::memcpy(&tgt, pro + 2, 8);
            h.hook_type = "mov_rax_jmp_rax";
            h.target    = tgt;
            out.push_back(std::move(h));
            continue;
        }
        if (pro[0] == 0x68 && pro[5] == 0xC3) {
            h.hook_type = "push_ret";
            h.target = pro[1] | (pro[2] << 8) | (pro[3] << 16) |
                       (static_cast<uint64_t>(pro[4]) << 24);
            out.push_back(std::move(h));
            continue;
        }
        if (pro[0] == 0xCC) {
            h.hook_type = "int3_prologue";
            out.push_back(std::move(h));
        }
    }
    return out;
}

// direct syscalls

std::vector<syscall_hit_t> detect_syscalls(const image_ref_t& img,
                                           uint64_t va, size_t size) {
    std::vector<syscall_hit_t> out;

    // Default: all executable sections
    std::vector<std::pair<uint64_t, size_t>> ranges;
    if (va != 0 && size != 0) {
        ranges.emplace_back(va, size);
    } else {
        for (const auto& s : img.pe->sections)
            if (s.is_executable() && s.raw_size > 0)
                ranges.emplace_back(img.base + s.rva,
                                    std::min<uint32_t>(s.raw_size, s.virtual_size));
    }

    for (const auto& [rva_start, rlen] : ranges) {
        if (rlen < 6) continue;
        std::vector<uint8_t> buf(rlen);
        if (!read_img(img, rva_start, buf.data(), buf.size())) continue;

        for (size_t i = 0; i + 7 <= buf.size(); ++i) {
            // mov r10, rcx ; mov eax, N ; syscall
            if (buf[i] == 0x4C && buf[i + 1] == 0x8B && buf[i + 2] == 0xD1 &&
                buf[i + 3] == 0xB8 && buf[i + 8] == 0x0F && buf[i + 9] == 0x05) {
                const uint32_t ssn = buf[i + 4] | (buf[i + 5] << 8) |
                                     (buf[i + 6] << 16) | (buf[i + 7] << 24);
                if (ssn <= 0x1000) {
                    syscall_hit_t h;
                    h.address = rva_start + i;
                    h.ssn = ssn;
                    h.pattern = "mov_r10_rcx";
                    out.push_back(std::move(h));
                }
                i += 9;
                continue;
            }
            // mov eax, N ; syscall
            if (buf[i] == 0xB8 && buf[i + 5] == 0x0F && buf[i + 6] == 0x05) {
                const uint32_t ssn = buf[i + 1] | (buf[i + 2] << 8) |
                                     (buf[i + 3] << 16) | (buf[i + 4] << 24);
                if (ssn <= 0x1000) {
                    syscall_hit_t h;
                    h.address = rva_start + i;
                    h.ssn = ssn;
                    h.pattern = "mov_eax_syscall";
                    out.push_back(std::move(h));
                }
                i += 6;
                continue;
            }
            // mov eax, N ... ; int 2E (within 5 bytes)
            if (buf[i] == 0xCD && buf[i + 1] == 0x2E && i >= 5 && buf[i - 5] == 0xB8) {
                const uint32_t ssn = buf[i - 4] | (buf[i - 3] << 8) |
                                     (buf[i - 2] << 16) | (buf[i - 1] << 24);
                if (ssn <= 0x1000) {
                    syscall_hit_t h;
                    h.address = rva_start + i - 5;
                    h.ssn = ssn;
                    h.pattern = "int_2e";
                    out.push_back(std::move(h));
                }
            }
        }
    }
    return out;
}

// API hashing

uint32_t hash_api(std::string_view name, std::string_view algo,
                  bool include_dll_name) {
    // Composite form hashes the full "DLL!API" text; plain form skips any
    // dll prefix the caller passed in
    std::string text(name);
    if (!include_dll_name) {
        const size_t bang = text.find('!');
        if (bang != std::string::npos) text = text.substr(bang + 1);
    }

    uint32_t h = 0;
    if (algo == "ror13") {
        h = 0;
        for (char c : text)
            h = (h >> 13 | h << 19) + static_cast<uint8_t>(c);
        return h;
    }
    if (algo == "djb2") {
        h = 5381;
        for (char c : text) h = h * 33 + static_cast<uint8_t>(c);
        return h;
    }
    if (algo == "crc32") {
        h = 0xFFFFFFFFu;
        for (char c : text) {
            h ^= static_cast<uint8_t>(c);
            for (int k = 0; k < 8; ++k)
                h = (h >> 1) ^ (0xEDB88320u & (0u - (h & 1)));
        }
        return ~h;
    }
    if (algo == "fnv1a") {
        h = 0x811C9DC5u;
        for (char c : text) {
            h ^= static_cast<uint8_t>(c);
            h *= 0x01000193u;
        }
        return h;
    }
    if (algo == "sdbm") {
        h = 0;
        for (char c : text)
            h = static_cast<uint8_t>(c) + (h << 6) + (h << 16) - h;
        return h;
    }
    return 0;
}

std::vector<api_hash_hit_t> resolve_api_hashes(const image_ref_t& img,
                                               const std::vector<uint64_t>& hashes,
                                               const std::string& algo) {
    std::vector<api_hash_hit_t> out;
    if (hashes.empty()) return out;

    for (const auto& dll : img.pe->imports) {
        for (const auto& fn : dll.functions) {
            for (uint64_t want : hashes) {
                const uint32_t w = static_cast<uint32_t>(want);
                if (hash_api(fn.name, algo, false) == w ||
                    hash_api(dll.dll + "!" + fn.name, algo, true) == w) {
                    api_hash_hit_t hit;
                    hit.hash = w;
                    hit.api  = fn.name;
                    hit.dll  = dll.dll;
                    out.push_back(std::move(hit));
                }
            }
        }
    }
    return out;
}

// entropy

double shannon_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    uint32_t hist[256] = {};
    for (size_t i = 0; i < len; ++i) ++hist[data[i]];
    double e = 0.0;
    const double n = static_cast<double>(len);
    for (uint32_t c : hist) {
        if (!c) continue;
        const double p = static_cast<double>(c) / n;
        e -= p * std::log2(p);
    }
    return e;
}

entropy_result_t entropy_scan(const image_ref_t& img, uint64_t va,
                              size_t size, size_t window) {
    entropy_result_t res;
    constexpr size_t kMaxScan = 1u << 20;
    if (size > kMaxScan) { size = kMaxScan; res.truncated = true; }
    if (window < 32) window = 32;
    if (window > size) window = size;

    std::vector<uint8_t> buf(size);
    if (!read_img(img, va, buf.data(), buf.size())) {
        res.verdict = "unmapped";
        return res;
    }

    res.overall = shannon_entropy(buf.data(), buf.size());
    res.min_window = 8.0;
    res.max_window = 0.0;
    const size_t step = std::max<size_t>(window / 2, 1);
    for (size_t off = 0; off < buf.size(); off += step) {
        const size_t len = std::min(window, buf.size() - off);
        const double e = shannon_entropy(buf.data() + off, len);
        window_entropy_t w;
        w.offset  = off;
        w.entropy = e;
        w.verdict = e > 7.0 ? "encrypted_or_compressed"
                  : e > 6.0 ? "suspicious"
                  : e < 1.0 ? "nearly_empty"
                            : "normal";
        res.min_window = std::min(res.min_window, e);
        res.max_window = std::max(res.max_window, e);
        res.windows.push_back(std::move(w));
        if (res.windows.size() >= 512) { res.truncated = true; break; }
    }

    res.verdict = res.overall > 7.5 ? "almost_certainly_encrypted_or_compressed"
                : res.overall > 7.0 ? "likely_packed"
                : res.overall > 6.0 ? "suspicious_high_entropy"
                                    : "normal";
    return res;
}

// page classification

std::vector<page_class_t> classify_pages(const image_ref_t& img,
                                         uint64_t va, size_t size,
                                         size_t page_size) {
    std::vector<page_class_t> out;
    if (page_size < 256) page_size = 256;
    constexpr size_t kMaxTotal = 1u << 20;
    size = std::min(size, kMaxTotal);

    for (size_t off = 0; off < size; off += page_size) {
        const size_t len = std::min(page_size, size - off);
        std::vector<uint8_t> buf(len);
        page_class_t p;
        p.address = va + off;
        p.size    = len;
        if (!read_img(img, va + off, buf.data(), buf.size())) {
            p.klass = "unmapped";
            out.push_back(std::move(p));
            continue;
        }

        p.entropy = shannon_entropy(buf.data(), buf.size());

        // Feature extraction: decodability, zeros, printable ratio
        size_t valid_insns = 0, decoded_len = 0;
        uint64_t cur = 0;
        while (cur + 1 < len) {
            auto in = img.eng->decode(va + off + cur, buf.data() + cur,
                                      len - cur);
            if (!in || in->length == 0) { ++cur; continue; }
            ++valid_insns;
            cur += in->length;
            decoded_len += in->length;
        }
        p.insn_ratio = len ? static_cast<double>(decoded_len) / len : 0.0;

        size_t zeros = 0, printable = 0;
        for (uint8_t b : buf) {
            if (b == 0) ++zeros;
            if (b >= 0x20 && b <= 0x7E) ++printable;
        }
        p.zero_ratio   = len ? static_cast<double>(zeros) / len : 0.0;
        p.string_ratio = len ? static_cast<double>(printable) / len : 0.0;

        // Decision cascade
        uint32_t max_freq = 0;
        {
            uint32_t hist[256] = {};
            for (uint8_t b : buf) max_freq = std::max(max_freq, ++hist[b]);
        }
        const double uniformity =
            len ? static_cast<double>(max_freq) / len : 0.0;

        if (p.zero_ratio > 0.85)                             p.klass = "padding";
        else if (uniformity > 0.7)                           p.klass = "single_byte_encrypted";
        else if (p.entropy > 7.2 && p.insn_ratio < 0.3)      p.klass = "encrypted_or_compressed";
        else if (p.entropy > 6.5 && p.insn_ratio < 0.5)      p.klass = "obfuscated_code";
        else if (p.insn_ratio > 0.75 && p.entropy < 6.5)     p.klass = "code";
        else if (p.string_ratio > 0.6)                       p.klass = "string_data";
        else if (p.insn_ratio < 0.3 && p.entropy < 5.0)      p.klass = "structured_data";
        else                                                 p.klass = "mixed";

        out.push_back(std::move(p));
        if (out.size() >= 512) break;
    }
    return out;
}

// control-flow flattening

cff_result_t detect_cff(const image_ref_t& img, uint64_t fn_va) {
    cff_result_t res;
    auto cfg = build_cfg(img, fn_va, 512);
    if (!cfg.ok) return res;
    res.block_count = cfg.blocks.size();

    // Back-edge histogram -> dispatcher candidate
    std::unordered_map<uint64_t, size_t> back_targets;
    for (const auto& b : cfg.blocks)
        for (uint64_t t : b.successors)
            if (t <= b.start) ++back_targets[t];
    uint64_t dispatcher = 0;
    size_t   best       = 0;
    for (const auto& [t, n] : back_targets)
        if (n > best) { best = n; dispatcher = t; }

    if (dispatcher == 0 || best < 3 || cfg.blocks.size() < 5)
        return res;                                       // not flattened

    res.flattened            = true;
    res.dispatcher           = dispatcher;
    res.dispatcher_backedges = best;

    // State variable: first cmp/sub/test inside the dispatcher block
    const disasm::pe_section_t* sec = section_for_va(img, dispatcher);
    if (sec) {
        auto insns = decode_range(img, dispatcher, 64);
        for (const auto& in : insns) {
            if (in.mnemonic == ZYDIS_MNEMONIC_CMP ||
                in.mnemonic == ZYDIS_MNEMONIC_SUB ||
                in.mnemonic == ZYDIS_MNEMONIC_TEST) {
                res.has_state_var = true;
                if (in.op_count > 0 && in.ops[0].cls == op_class_t::reg)
                    res.state_var_desc = "reg:" + reg_name(in.ops[0].reg);
                else if (in.op_count > 0 && in.ops[0].cls == op_class_t::mem)
                    res.state_var_desc = "mem:[base+" +
                                         std::to_string(in.ops[0].disp) + "]";
                break;
            }
        }
    }

    // State blocks: everything jumping back to the dispatcher
    auto blocks = build_cfg(img, fn_va, 512);
    for (const auto& b : blocks.blocks) {
        bool jumps_dispatcher = false;
        for (uint64_t t : b.successors)
            if (t == dispatcher) jumps_dispatcher = true;
        if (!jumps_dispatcher) continue;

        cff_state_block_t sb;
        sb.start = b.start;
        sb.end   = b.end;

        // next_state from the last mov reg/mem, imm in the block
        auto insns = decode_range(img, b.start, 128);
        uint64_t cover = b.start;
        for (const auto& in : insns) {
            if (in.va >= b.end) break;
            cover = in.va + in.length;
            if (in.mnemonic == ZYDIS_MNEMONIC_MOV &&
                in.op_count == 2 &&
                (in.ops[0].cls == op_class_t::reg ||
                 in.ops[0].cls == op_class_t::mem) &&
                in.ops[1].cls == op_class_t::imm) {
                sb.has_next    = true;
                sb.next_state  = static_cast<int64_t>(in.ops[1].imm);
                sb.assign_addr = in.va;
            }
        }
        res.state_blocks.push_back(std::move(sb));
    }
    return res;
}

// ROP gadgets

std::vector<gadget_t> rop_gadgets(const image_ref_t& img,
                                  size_t limit, size_t max_gadget_len) {
    std::vector<gadget_t> out;

    auto emit_gadget = [&](uint64_t ret_va) {
        // Walk backwards up to 15 bytes looking for valid instruction chains
        // that END exactly at ret_va
        for (int back = 1; back <= 15; ++back) {
            const uint64_t start = ret_va - back;
            if (!is_exec_va(img, start)) continue;
            auto chain = decode_range(img, start, max_gadget_len + 1);
            if (chain.empty()) continue;
            uint64_t cur = start;
            size_t used = 0;
            std::string text;
            bool ends_at_ret = false;
            for (const auto& in : chain) {
                if (used == max_gadget_len) break;
                if (!text.empty()) text += " ; ";
                text += in.text;
                ++used;
                cur += in.length;
                if (cur == ret_va) {
                    ends_at_ret = in.mnemonic == ZYDIS_MNEMONIC_RET;
                    break;
                }
                if (in.flow != disasm::flow_t::none) break;   // control flow kills gadget
            }
            if (!ends_at_ret) continue;
            if (used < 2) continue;                           // bare ret: noise
            gadget_t g;
            g.address = start;
            g.text    = std::move(text);
            out.push_back(std::move(g));
            return;                                           // one gadget per ret site
        }
    };

    for (const auto& sec : img.pe->sections) {
        if (!sec.is_executable() || sec.raw_size == 0) continue;
        auto off = img.pe->rva_to_offset(sec.rva);
        if (!off) continue;
        const size_t len = std::min<uint32_t>(sec.raw_size,
                                              static_cast<uint32_t>(img.file->size() - *off));
        const uint8_t* data = img.file->data() + *off;
        for (size_t i = 0; i < len; ++i) {
            if (data[i] == 0xC3) {
                emit_gadget(img.base + sec.rva + i);
                if (out.size() >= limit) return out;
            }
        }
    }
    return out;
}

// crypto constant hunt

namespace {

struct crypto_const_t {
    uint64_t    value;
    const char* algorithm;
    const char* name;
};

constexpr crypto_const_t kCryptoConsts[] = {
    { 0x6A09E667ull, "SHA-256", "H0" },
    { 0xBB67AE85ull, "SHA-256", "H1" },
    { 0x3C6EF372ull, "SHA-256", "H2" },
    { 0xA54FF53Aull, "SHA-256", "H3" },
    { 0x428A2F98ull, "SHA-256", "K0" },
    { 0x71374491ull, "SHA-256", "K1" },
    { 0x67452301ull, "MD5",     "init_A" },
    { 0xEFCDAB89ull, "MD5",     "init_B" },
    { 0x98BADCFEull, "MD5",     "init_C" },
    { 0x10325476ull, "MD5",     "init_D" },
    { 0xD76AA478ull, "MD5",     "T1" },
    { 0xE8C7B756ull, "MD5",     "T2" },
    { 0x242070DBull, "MD5",     "T3" },
    { 0xC66363A5ull, "AES",     "Te0[0]" },
    { 0xF87C7C84ull, "AES",     "Te0[1]" },
    { 0x51F4A750ull, "AES",     "Td0[0]" },
    { 0x637C777Bull, "AES",     "sbox[0..3]" },
    { 0xEDB88320ull, "CRC32",   "poly_reflected" },
    { 0x04C11DB7ull, "CRC32",   "poly" },
    { 0x243F6A88ull, "Blowfish","P[0]" },
    { 0x85A308D3ull, "Blowfish","P[1]" },
    { 0x5A827999ull, "SHA-1",   "K0" },
    { 0x6ED9EBA1ull, "SHA-1",   "K1" },
    { 0x8F1BBCDCull, "SHA-1",   "K2" },
    { 0xCA62C1D6ull, "SHA-1",   "K3" },
    { 0x9E3779B9ull, "TEA/XTEA/RC5", "delta/P32" },
    { 0xB7E15163ull, "RC5/RC6", "P32" },
    { 0x61707865ull, "ChaCha20/Salsa20", "sigma[0]" },
};

const crypto_const_t* match_const(uint64_t v) {
    for (const auto& c : kCryptoConsts)
        if (c.value == v) return &c;
    return nullptr;
}

} // namespace

std::vector<crypto_hit_t> crypto_range_bytes(uint64_t base_va,
                                             const uint8_t* data, size_t len,
                                             const disasm::engine_t* eng,
                                             size_t limit) {
    std::vector<crypto_hit_t> out;

    // Phase 1: immediate operands of decoded instructions
    if (eng && eng->ok()) {
        uint64_t cur = 0;
        while (cur + 1 < len && out.size() < limit) {
            auto in = eng->decode(base_va + cur, data + cur, len - cur);
            if (!in || in->length == 0) { ++cur; continue; }
            for (uint8_t i = 0; i < in->op_count; ++i) {
                if (in->ops[i].cls != op_class_t::imm) continue;
                if (const auto* c = match_const(in->ops[i].imm)) {
                    crypto_hit_t h;
                    h.va       = base_va + cur;
                    h.algorithm = c->algorithm;
                    h.constant_name = c->name;
                    h.value    = c->value;
                    h.source   = "immediate";
                    out.push_back(std::move(h));
                }
            }
            cur += in->length;
        }
    }

    // Phase 2: stride-4 dword scan over raw bytes (data tables)
    for (size_t off = 0; off + 4 <= len && out.size() < limit; off += 4) {
        const uint32_t dw = data[off] | (data[off + 1] << 8) |
                            (data[off + 2] << 16) | (data[off + 3] << 24);
        if (const auto* c = match_const(dw)) {
            crypto_hit_t h;
            h.va       = base_va + off;
            h.algorithm = c->algorithm;
            h.constant_name = c->name;
            h.value    = c->value;
            h.source   = "data";
            out.push_back(std::move(h));
        }
    }
    return out;
}

std::vector<crypto_hit_t> crypto_range(const image_ref_t& img,
                                       uint64_t va, size_t size, size_t limit) {
    constexpr size_t kMaxScan = 1u << 20;
    size = std::min(size, kMaxScan);
    std::vector<uint8_t> buf(size);
    if (!read_img(img, va, buf.data(), buf.size())) return {};
    return crypto_range_bytes(va, buf.data(), buf.size(), img.eng, limit);
}

} // namespace slop::core::analysis::xray
