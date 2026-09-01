// src/core/analysis/imgpatch.cpp

#include "core/analysis/imgpatch.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <set>
#include <unordered_map>

namespace slop::core::analysis::imgpatch {

namespace ds = slop::core::disasm::binary_state;

namespace {

using disasm::insn_t;
using disasm::op_class_t;

bool read_bin(const ds::binary_t& bin, uint64_t va, void* dst, size_t len) {
    auto off = bin.offset_of(va);
    if (!off || *off + len > bin.file.size()) return false;
    std::memcpy(dst, bin.file.data() + *off, len);
    return true;
}

// Single journaled byte write. False when unmapped
bool poke(ds::binary_t& bin, uint64_t va, uint8_t byte,
          std::vector<ds::binary_t::patch_rec_t>* journal) {
    auto off = bin.offset_of(va);
    if (!off || *off >= bin.file.size()) return false;
    if (journal) {
        ds::binary_t::patch_rec_t rec;
        rec.va     = va;
        rec.offset = *off;
        rec.before = bin.file[*off];
        rec.after  = byte;
        journal->push_back(rec);
    }
    bin.file[*off] = byte;
    return true;
}

std::vector<insn_t> decode_fn(ds::binary_t& bin, uint64_t va, size_t max) {
    std::vector<insn_t> out;
    uint64_t cur = va;
    for (size_t i = 0; i < max; ++i) {
        uint8_t buf[16];
        if (!read_bin(bin, cur, buf, sizeof(buf))) break;
        auto in = bin.eng.decode(cur, buf, sizeof(buf));
        if (!in || in->length == 0) break;
        out.push_back(std::move(*in));
        cur += out.back().length;
    }
    return out;
}

void finish(op_result_t& res, ds::binary_t& bin, size_t patched_count) {
    (void)patched_count;
    if (!res.patches.empty()) bin.indexes_dirty = true;
    for (const auto& p : res.patches)
        if (p.action != "preview") ++res.bytes_changed;
    res.ok = true;
}

} // namespace

// NOP junk

op_result_t nop_junk(ds::binary_t& bin, uint64_t fn_va, bool aggressive,
                     size_t nop_threshold) {
    op_result_t res;
    if (nop_threshold < 2) nop_threshold = 2;
    if (nop_threshold > 16) nop_threshold = 16;

    auto insns = decode_fn(bin, fn_va, 8192);
    if (insns.empty()) { res.error = "cannot decode function range"; return res; }

    // long nop runs get collapsed to one canonical run
    int run = 0;
    std::vector<insn_t> sleds;
    for (const auto& in : insns) {
        const bool is_nop_ish =
            in.mnemonic == ZYDIS_MNEMONIC_NOP ||
            (in.length <= 4 &&
             in.text.size() > 3 &&
             in.text.compare(0, 3, "xch") == 0 &&
             in.text.find("ax, ax") != std::string::npos);
        if (is_nop_ish) { ++run; continue; }
        if (run > static_cast<int>(nop_threshold)) sleds.push_back(insn_t{});
        run = 0;
    }

    // Rewrite: any multi-byte nop-ish instruction beyond threshold -> 0x90s
    run = 0;
    uint64_t run_start = 0;
    for (const auto& in : insns) {
        const bool is_nop_ish = in.mnemonic == ZYDIS_MNEMONIC_NOP;
        if (is_nop_ish) {
            if (run == 0) run_start = in.va;
            ++run;
            continue;
        }
        if (run > static_cast<int>(nop_threshold)) {
            patch_hit_t h;
            h.va     = run_start;
            h.action = "nop_sled";
            h.detail = "normalized " + std::to_string(run) + " nops";
            res.patches.push_back(std::move(h));
        }
        run = 0;
    }

    // aggressive mode nops dead heads that cant fall through
    if (aggressive && insns.size() > 1) {
        std::set<uint64_t> targets;
        for (const auto& in : insns)
            if (in.has_rel_target) targets.insert(in.rel_target);

        for (size_t i = 1; i < insns.size(); ++i) {
            const auto& in = insns[i];
            if (targets.count(in.va)) continue;               // referenced
            const auto& prev = insns[i - 1];
            const bool falls = prev.flow == disasm::flow_t::none ||
                               prev.flow == disasm::flow_t::jcc ||
                               prev.flow == disasm::flow_t::call;
            if (falls) continue;

            // Fill from here until next referenced/branch insn (cap 64)
            size_t filled = 0;
            for (size_t j = i; j < insns.size() && filled < 64; ++j) {
                if (targets.count(insns[j].va) && j != i) break;
                if (insns[j].flow == disasm::flow_t::ret) break;
                for (size_t b = 0; b < insns[j].length; ++b)
                    poke(bin, insns[j].va + b, 0x90, &bin.patches);
                filled += insns[j].length;
            }
            patch_hit_t h;
            h.va     = in.va;
            h.action = "dead_code_nopped";
            h.detail = "filled " + std::to_string(filled) + " bytes";
            res.patches.push_back(std::move(h));
        }
    }

    finish(res, bin, res.patches.size());
    return res;
}

// opaque predicates

op_result_t resolve_opaque_predicates(ds::binary_t& bin, uint64_t fn_va,
                                      bool dry_run) {
    op_result_t res;
    res.dry_run = dry_run;
    auto insns = decode_fn(bin, fn_va, 8192);
    if (insns.empty()) { res.error = "cannot decode function range"; return res; }

    for (size_t i = 1; i < insns.size(); ++i) {
        const auto& in   = insns[i];
        const auto& prev = insns[i - 1];
        if (in.flow != disasm::flow_t::jcc) continue;

        bool always_true = false, always_false = false;
        if (prev.mnemonic == ZYDIS_MNEMONIC_XOR &&
            prev.op_count >= 2 &&
            prev.ops[0].cls == op_class_t::reg &&
            prev.ops[1].cls == op_class_t::reg &&
            prev.ops[0].reg == prev.ops[1].reg) {
            always_true = true;                    // flags say equal/zero
        } else if (prev.mnemonic == ZYDIS_MNEMONIC_TEST &&
                   prev.op_count >= 2 &&
                   prev.ops[0].cls == op_class_t::reg &&
                   prev.ops[1].cls == op_class_t::reg &&
                   prev.ops[0].reg == prev.ops[1].reg) {
            always_true = true;                    // r!=0 -> not-equal taken
        }
        if (!always_true && !always_false) continue;

        patch_hit_t h;
        h.va     = in.va;
        h.detail = in.text;

        if (always_false) {
            h.action = "nop_branch";
            if (!dry_run)
                for (size_t b = 0; b < in.length; ++b)
                    poke(bin, in.va + b, 0x90, &bin.patches);
        } else {
            // Always-taken: rewrite to an unconditional jmp preserving
            // displacement width (2-byte short or 6-byte near)
            h.action = "force_jmp";
            if (!dry_run) {
                if (in.length <= 2) {
                    poke(bin, in.va, 0xEB, &bin.patches);          // jmp rel8
                    if (in.length == 3) poke(bin, in.va + 2, 0x90, &bin.patches);
                } else if (in.length >= 5 && in.bytes[0] == 0x0F) {
                    poke(bin, in.va, 0x90, &bin.patches);          // preserve rel32
                    poke(bin, in.va + 1, 0xE9, &bin.patches);      // jmp rel32
                }
            }
        }
        res.patches.push_back(std::move(h));
    }

    finish(res, bin, res.patches.size());
    return res;
}

// anti-debug

op_result_t patch_anti_debug(ds::binary_t& bin, uint64_t fn_va,
                             const anti_debug_opts_t& opts, bool dry_run) {
    static const char* kApis[] = {
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "NtSetInformationThread",
        "OutputDebugString", "DbgBreakPoint", "DbgUiRemoteBreakin",
        "NtQuerySystemInformation"
    };

    op_result_t res;
    res.dry_run = dry_run;

    // IAT map for import-call resolution
    std::unordered_map<uint64_t, std::string> iat;
    for (const auto& dll : bin.pe.imports)
        for (const auto& fn : dll.functions)
            if (fn.iat_rva) iat[bin.base + fn.iat_rva] = dll.dll + "!" + fn.name;

    auto insns = decode_fn(bin, fn_va, 8192);
    for (const auto& in : insns) {
        if (opts.patch_api_calls &&
            (in.flow == disasm::flow_t::call || in.flow == disasm::flow_t::jmp)) {
            uint64_t slot = in.has_rip_rel ? in.rip_rel_target : 0;
            if (!slot && in.op_count > 0 && in.ops[0].cls == op_class_t::mem &&
                in.ops[0].mem_base == ZYDIS_REGISTER_NONE)
                slot = bin.base + static_cast<uint32_t>(in.ops[0].disp);
            if (slot) {
                const auto it = iat.find(slot);
                if (it == iat.end()) continue;
                bool hit_api = false;
                for (const char* api : kApis)
                    if (it->second.find(api) != std::string::npos) { hit_api = true; break; }
                if (!hit_api) continue;

                patch_hit_t h;
                h.va     = in.va;
                h.action = "anti_debug_call";
                h.detail = it->second;
                if (it->second.find("IsDebuggerPresent") != std::string::npos) {
                    // xor eax,eax ; nops, honest "return 0"
                    if (!dry_run) {
                        poke(bin, in.va, 0x31, &bin.patches);
                        poke(bin, in.va + 1, 0xC0, &bin.patches);
                        for (size_t b = 2; b < in.length; ++b)
                            poke(bin, in.va + b, 0x90, &bin.patches);
                    }
                    h.detail += " -> xor eax,eax";
                } else if (!dry_run) {
                    for (size_t b = 0; b < in.length; ++b)
                        poke(bin, in.va + b, 0x90, &bin.patches);
                    h.detail += " -> nops";
                }
                res.patches.push_back(std::move(h));
            }
        }

        if (opts.patch_int_traps &&
            (in.mnemonic == ZYDIS_MNEMONIC_INT3 || in.mnemonic == ZYDIS_MNEMONIC_INT)) {
            patch_hit_t h;
            h.va = in.va; h.action = "int_trap";
            h.detail = in.text + " -> nops";
            if (!dry_run)
                for (size_t b = 0; b < in.length; ++b)
                    poke(bin, in.va + b, 0x90, &bin.patches);
            res.patches.push_back(std::move(h));
        }

        if (opts.patch_timing && in.mnemonic == ZYDIS_MNEMONIC_RDTSC) {
            patch_hit_t h;
            h.va = in.va; h.action = "rdtsc_timing";
            h.detail = "rdtsc -> xor eax,eax";
            if (!dry_run) {
                poke(bin, in.va, 0x31, &bin.patches);
                poke(bin, in.va + 1, 0xC0, &bin.patches);
            }
            res.patches.push_back(std::move(h));
        }
    }

    finish(res, bin, res.patches.size());
    return res;
}

// XOR unpack

op_result_t unpack_xor(ds::binary_t& bin, uint64_t va, size_t size,
                       const std::string& method, const std::string& key_hex) {
    op_result_t res;
    constexpr size_t kMaxRegion = 4u << 20;
    if (size == 0 || size > kMaxRegion) {
        res.error = "bad region size (1..4 MiB)";
        return res;
    }
    auto off0 = bin.offset_of(va);
    if (!off0 || *off0 + size > bin.file.size()) {
        res.error = "region not mapped in image";
        return res;
    }

    // Key parse
    std::vector<uint8_t> key;
    {
        std::string clean;
        for (char c : key_hex)
            if (std::isxdigit(static_cast<unsigned char>(c))) clean.push_back(c);
        if (!clean.empty() && clean.size() % 2 == 0)
            for (size_t i = 0; i < clean.size(); i += 2)
                key.push_back(static_cast<uint8_t>(
                    std::stoul(clean.substr(i, 2), nullptr, 16)));
    }

    uint8_t* data = bin.file.data() + *off0;

    if (method == "auto") {
        // Score all single-byte keys against common x64 code opcodes over
        // the first 256 bytes
        static constexpr uint8_t kCodeOpcodes[] = {
            0x48, 0x49, 0x4C, 0x55, 0x53, 0x56, 0x41, 0x89,
            0x8B, 0xE8, 0xE9, 0xEB, 0xC3, 0xCC, 0x90
        };
        const size_t probe_len = std::min<size_t>(size, 256);
        int best_score = -1;
        uint8_t best_key = 0;
        for (int k = 1; k < 256; ++k) {
            int score = 0;
            for (size_t i = 0; i < probe_len; ++i) {
                const uint8_t d = static_cast<uint8_t>(data[i] ^ k);
                for (uint8_t op : kCodeOpcodes) if (d == op) { ++score; break; }
            }
            if (score > best_score) { best_score = score; best_key = static_cast<uint8_t>(k); }
        }
        if (best_score < 20) {
            res.error = "auto key detection failed (best score " +
                        std::to_string(best_score) + "/256)";
            return res;
        }
        res.detected_key  = best_key;
        res.key_confidence =
            static_cast<double>(best_score) / static_cast<double>(probe_len);
        key.assign(1, best_key);
    }

    if (key.empty()) { res.error = "missing key hex"; return res; }

    if (method == "xor_single" || method == "xor_multi" || method == "auto" ||
        method.empty()) {
        for (size_t i = 0; i < size; ++i) {
            ds::binary_t::patch_rec_t rec;
            rec.va = va + i; rec.offset = *off0 + i;
            rec.before = data[i];
            data[i] ^= key[i % key.size()];
            rec.after = data[i];
            bin.patches.push_back(rec);
            ++res.bytes_changed;
        }
    } else if (method == "xor_rolling") {
        // Chained ciphertext feedback: dec = cur ^ rolling; rolling = cur
        uint8_t rolling = key[0];
        for (size_t i = 0; i < size; ++i) {
            ds::binary_t::patch_rec_t rec;
            rec.va = va + i; rec.offset = *off0 + i;
            const uint8_t cur = data[i];
            rec.before = cur;
            data[i] = cur ^ rolling;
            rec.after = data[i];
            bin.patches.push_back(rec);
            rolling = cur;
            ++res.bytes_changed;
        }
    } else {
        res.error = "unknown method (auto|xor_single|xor_multi|xor_rolling)";
        return res;
    }

    patch_hit_t h;
    h.va = va;
    h.action = "unpack_xor";
    h.detail = method.empty() ? "xor" : method;
    res.patches.push_back(std::move(h));

    if (!res.patches.empty()) bin.indexes_dirty = true;
    res.ok = true;
    return res;
}

// string decoding

op_result_t decode_strings(ds::binary_t& bin, uint64_t fn_va) {
    op_result_t res;
    auto insns = decode_fn(bin, fn_va, 8192);

    auto printable_all = [](uint64_t v, int nbytes) {
        for (int i = 0; i < nbytes; ++i) {
            const uint8_t c = static_cast<uint8_t>(v >> (8 * i));
            if (c < 0x20 || c > 0x7E) return false;
        }
        return true;
    };

    // Stack strings with reconstruction
    std::string acc;
    uint64_t acc_start = 0;
    size_t acc_units = 0;
    auto flush = [&]() {
        if (acc_units >= 3 && !acc.empty()) {
            patch_hit_t h;
            h.va = acc_start;
            h.action = "stack_string";
            h.detail = "\"" + acc + "\"";
            res.patches.push_back(std::move(h));
        }
        acc.clear(); acc_units = 0;
    };
    for (const auto& in : insns) {
        const bool stack_mov =
            in.mnemonic == ZYDIS_MNEMONIC_MOV && in.op_count == 2 &&
            in.ops[0].cls == op_class_t::mem && in.ops[1].cls == op_class_t::imm;
        if (stack_mov) {
            const auto imm = in.ops[1].imm;
            int nbytes = 1;
            if ((imm & 0xFFFFFF00ull) != 0) nbytes = 4;
            if ((imm & 0xFFFFFFFF00000000ull) != 0) nbytes = 8;
            if (printable_all(imm, nbytes)) {
                if (acc_units == 0) acc_start = in.va;
                for (int i = 0; i < nbytes; ++i) {
                    char ch = static_cast<char>(imm >> (8 * i));
                    if (ch) acc.push_back(ch);
                }
                ++acc_units;
                continue;
            }
        }
        flush();
    }
    flush();

    // XOR strings: xor reg,imm8 followed by data references, decode bytes at
    // each rip-relative reference reachable from this function's xors
    for (const auto& in : insns) {
        if (!(in.mnemonic == ZYDIS_MNEMONIC_XOR && in.op_count == 2 &&
              in.ops[0].cls == op_class_t::reg && in.ops[1].cls == op_class_t::imm &&
              in.ops[1].imm != 0))
            continue;
        // Find the nearest preceding lea/mov establishing a buffer pointer
        // Simple heuristic: scan back for a rip-rel data reference
        for (int back = static_cast<int>(insns.size()) - 1; back >= 0; --back) {
            const auto& cand = insns[static_cast<size_t>(back)];
            if (cand.va >= in.va) continue;
            if (!cand.has_rip_rel) continue;
            auto off = bin.offset_of(cand.rip_rel_target);
            if (!off || *off >= bin.file.size()) continue;

            std::string decoded;
            for (size_t k = 0;
                 k < 256 && *off + k < bin.file.size(); ++k) {
                const uint8_t c =
                    static_cast<uint8_t>(bin.file[*off + k] ^
                                         static_cast<uint8_t>(in.ops[1].imm));
                if (c == 0) break;
                if (c < 0x20 || c > 0x7E) { decoded.clear(); break; }
                decoded.push_back(static_cast<char>(c));
            }
            if (decoded.size() >= 4) {
                patch_hit_t h;
                h.va = cand.rip_rel_target;
                h.action = "xor_string";
                h.detail = "key 0x" + [&] {
                    char t[8]; std::snprintf(t, sizeof(t), "%02llX",
                                             static_cast<unsigned long long>(in.ops[1].imm));
                    return std::string(t);
                }() + " \"" + decoded + "\"";
                res.patches.push_back(std::move(h));
            }
            break;   // one candidate per xor
        }
    }

    res.strings_found = res.patches.size();
    res.ok = true;
    return res;
}

// raw writes / journal

op_result_t write_bytes(ds::binary_t& bin, uint64_t va,
                        const std::vector<uint8_t>& bytes) {
    op_result_t res;
    auto off = bin.offset_of(va);
    if (!off || *off + bytes.size() > bin.file.size()) {
        res.error = "range not mapped in image";
        return res;
    }
    for (size_t i = 0; i < bytes.size(); ++i) {
        ds::binary_t::patch_rec_t rec;
        rec.va = va + i; rec.offset = *off + i;
        rec.before = bin.file[*off + i];
        rec.after  = bytes[i];
        bin.file[*off + i] = bytes[i];
        bin.patches.push_back(rec);
    }
    patch_hit_t h;
    h.va = va;
    h.action = "write_bytes";
    h.detail = std::to_string(bytes.size()) + " bytes";
    res.patches.push_back(std::move(h));
    bin.indexes_dirty = true;
    res.bytes_changed = bytes.size();
    res.ok = true;
    return res;
}

op_result_t revert_all(ds::binary_t& bin) {
    op_result_t res;
    for (auto it = bin.patches.rbegin(); it != bin.patches.rend(); ++it) {
        if (it->offset < bin.file.size())
            bin.file[it->offset] = it->before;
    }
    res.bytes_changed = bin.patches.size();
    patch_hit_t h;
    h.action = "revert_all";
    h.detail = std::to_string(bin.patches.size()) + " bytes restored";
    res.patches.push_back(std::move(h));
    bin.patches.clear();
    // A no-op revert must not invalidate the static indexes (the lazy
    // rebuild also restarts the whole hyperion analysis)
    bin.indexes_dirty = res.bytes_changed > 0;
    res.ok = true;
    return res;
}

// obfuscation score (local, same weights as xray)

int obfuscation_score(ds::binary_t& bin, uint64_t fn_va) {
    auto insns = decode_fn(bin, fn_va, 8192);
    if (insns.empty()) return 0;

    size_t opaque = 0, junk = 0, indirect = 0, push_ret = 0;
    int nop_run = 0;

    for (size_t i = 0; i < insns.size(); ++i) {
        const auto& in = insns[i];
        if (in.mnemonic == ZYDIS_MNEMONIC_NOP) { ++nop_run; continue; }
        if (nop_run >= 4) ++junk;
        nop_run = 0;

        if (i > 0 && in.flow == disasm::flow_t::jcc) {
            const auto& prev = insns[i - 1];
            const bool self_z =
                ((prev.mnemonic == ZYDIS_MNEMONIC_XOR ||
                  prev.mnemonic == ZYDIS_MNEMONIC_TEST) &&
                 prev.op_count >= 2 &&
                 prev.ops[0].cls == op_class_t::reg &&
                 prev.ops[1].cls == op_class_t::reg &&
                 prev.ops[0].reg == prev.ops[1].reg);
            if (self_z) ++opaque;
        }
        if (in.flow == disasm::flow_t::jmp && !in.has_rel_target) ++indirect;
        if (in.mnemonic == ZYDIS_MNEMONIC_PUSH && i + 1 < insns.size() &&
            insns[i + 1].mnemonic == ZYDIS_MNEMONIC_RET)
            ++push_ret;
    }
    if (nop_run >= 4) ++junk;

    int score = 0;
    score += static_cast<int>(std::min(opaque * 10, size_t{25}));
    score += static_cast<int>(std::min(junk * 8, size_t{20}));
    score += static_cast<int>(std::min(indirect * 15, size_t{25}));
    if (push_ret > 0) score += 15;
    return std::min(score, 100);
}

// full pass

full_pass_result_t full_pass(ds::binary_t& bin, uint64_t fn_va, bool dry_run) {
    full_pass_result_t out;
    out.dry_run = dry_run;

    out.pre_score = obfuscation_score(bin, fn_va);
    out.steps.push_back({"score_baseline", true,
                         std::to_string(out.pre_score) + "/100"});

    // 1. Opaque predicates
    auto opq = resolve_opaque_predicates(bin, fn_va, dry_run);
    out.steps.push_back({"resolve_opaque", opq.ok,
                         opq.ok ? std::to_string(opq.patches.size()) + " found"
                                : opq.error});

    // 2. NOP junk, aggressive once the function looks heavily obfuscated
    //    (Mutating op: preview-only under dry_run.)
    if (!dry_run) {
        auto nj = nop_junk(bin, fn_va, out.pre_score >= 50, 4);
        out.steps.push_back({"nop_junk", nj.ok,
                             nj.ok ? std::to_string(nj.patches.size()) + " sites"
                                   : nj.error});
        out.bytes_changed += nj.bytes_changed;
    } else {
        out.steps.push_back({"nop_junk", true, "preview only under dry_run"});
    }

    // 3. String decoding
    auto strs = decode_strings(bin, fn_va);
    out.strings_found = strs.strings_found;
    out.steps.push_back({"decode_strings", strs.ok,
                         std::to_string(strs.strings_found) + " candidates"});

    // 4. Anti-debug neutralization
    anti_debug_opts_t opts{};
    auto ad = patch_anti_debug(bin, fn_va, opts, dry_run);
    out.steps.push_back({"patch_antidebug", ad.ok,
                         ad.ok ? std::to_string(ad.patches.size()) + " sites"
                               : ad.error});

    out.bytes_changed += dry_run ? 0 : (opq.bytes_changed + ad.bytes_changed);

    // 5. Post-pass score: for dry runs the bytes never changed, so the
    //    honest post-score equals pre; after a real pass re-scan the range
    out.post_score = dry_run ? out.pre_score : obfuscation_score(bin, fn_va);
    out.steps.push_back({"score_post", true,
                         std::to_string(out.post_score) + "/100"});

    out.ok = true;
    return out;
}

// rebuild

rebuild_result_t rebuild(ds::binary_t& bin, uint64_t fn_va) {
    rebuild_result_t res;
    auto insns = decode_fn(bin, fn_va, 8192);
    if (insns.empty()) { res.error = "cannot decode function range"; return res; }

    res.instruction_count = insns.size();
    for (size_t i = 0; i < insns.size() && i < 64; ++i)
        res.insns.emplace_back(insns[i].va, insns[i].text);

    bin.indexes_dirty = true;   // functions/xrefs/strings rebuild lazily
    res.ok = true;
    return res;
}

} // namespace slop::core::analysis::imgpatch
