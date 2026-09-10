#include "dotnet_disasm.h"
#include <spdlog/spdlog.h>
#include <fmt/format.h>
#include <cstring>

namespace hype {

namespace {

// Sanity caps for attacker-controlled counts, matching the loader's style.
constexpr u32 kMaxMethods   = 2'000'000;
constexpr u32 kMaxTypes     = 1'000'000;
constexpr u32 kMaxCodeSize  = 4 * 1024 * 1024;   // per-method IL byte cap
constexpr u32 kMaxInsns     = 2'000'000;         // per-method instruction cap

// TypeAttributes / MethodAttributes bits we care about (II.23.1).
constexpr u16 kMethodStatic = 0x0010;

// RVA -> pointer into the mapped section bytes, with the count of bytes still
// available in that section. Mirrors pe_loader's translation but walks the
// already-loaded Segment::data (BSS tails have no backing bytes, so bound on
// data.size(), not the virtual size).
const u8* rva_to_ptr(const PEImage& img, u32 rva, size_t* avail) {
    for (const auto& seg : img.segments) {
        u32 seg_rva = static_cast<u32>(seg.va - img.base);
        if (rva >= seg_rva && rva < seg_rva + seg.data.size()) {
            size_t off = rva - seg_rva;
            if (avail) *avail = seg.data.size() - off;
            return seg.data.data() + off;
        }
    }
    return nullptr;
}

u16 rd16(const u8* p) { u16 v = 0; std::memcpy(&v, p, 2); return v; }
u32 rd32(const u8* p) { u32 v = 0; std::memcpy(&v, p, 4); return v; }

InsnType flow_to_insn_type(ILFlow f) {
    switch (f) {
    case ILFlow::Call:   return InsnType::Call;
    case ILFlow::Return: return InsnType::Ret;
    case ILFlow::Branch: return InsnType::Jmp;
    case ILFlow::Cond:   return InsnType::Jcc;
    default:             return InsnType::Other;
    }
}

} // anon

// -------------------------------------------------------------------------

bool DotNetDisassembler::read_cor20(const PEImage& img, Cor20& out) const {
    // Re-parse the PE optional header from the raw image to reach data
    // directory 14 (IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR); PEImage does not
    // surface it. Everything here is bounds-checked against img.raw.
    const u8* base = img.raw.data();
    size_t size = img.raw.size();
    if (size < 0x40) return false;

    u32 lfanew = rd32(base + 0x3C);
    if (static_cast<size_t>(lfanew) + 4 > size) return false;
    if (std::memcmp(base + lfanew, "PE\0\0", 4) != 0) return false;

    size_t coff = static_cast<size_t>(lfanew) + 4;
    if (coff + 20 > size) return false;
    u16 opt_size = rd16(base + coff + 16);
    size_t opt = coff + 20;
    if (opt + 2 > size || opt_size < 2) return false;

    u16 magic = rd16(base + opt);
    // Number-of-data-directories and the directory array sit at a fixed offset
    // within the optional header, differing only by the 32/64-bit body size.
    size_t num_dd_off, dd_off;
    if (magic == 0x20B) {          // PE32+
        num_dd_off = opt + 108;
        dd_off = opt + 112;
    } else if (magic == 0x10B) {   // PE32
        num_dd_off = opt + 92;
        dd_off = opt + 96;
    } else {
        return false;
    }
    if (num_dd_off + 4 > size) return false;
    u32 num_dd = rd32(base + num_dd_off);
    if (num_dd < 15) return false;                 // no COM descriptor entry

    size_t com_off = dd_off + 14 * 8;              // dd[14]
    if (com_off + 8 > size) return false;
    u32 com_rva = rd32(base + com_off);
    u32 com_size = rd32(base + com_off + 4);
    if (com_rva == 0 || com_size < 72) return false;

    size_t avail = 0;
    const u8* c = rva_to_ptr(img, com_rva, &avail);
    if (!c || avail < 72) return false;

    out.cb          = rd32(c + 0);
    out.major       = rd16(c + 4);
    out.minor       = rd16(c + 6);
    out.meta_rva    = rd32(c + 8);
    out.meta_size   = rd32(c + 12);
    out.flags       = rd32(c + 16);
    out.entry_point = rd32(c + 20);
    return out.meta_rva != 0;
}

bool DotNetDisassembler::detect(const PEImage& img) const {
    Cor20 hdr;
    return read_cor20(img, hdr);
}

bool DotNetDisassembler::load(const PEImage& img) {
    image_ = {};

    Cor20 hdr;
    if (!read_cor20(img, hdr)) return false;

    size_t avail = 0;
    const u8* meta = rva_to_ptr(img, hdr.meta_rva, &avail);
    if (!meta) {
        spdlog::warn("dotnet: metadata RVA 0x{:X} not mapped", hdr.meta_rva);
        return false;
    }
    size_t meta_sz = (std::min)(static_cast<size_t>(hdr.meta_size), avail);

    if (!md_.init(meta, meta_sz)) {
        spdlog::warn("dotnet: metadata parse failed");
        return false;
    }

    image_.cor_flags = hdr.flags;
    image_.major_runtime = hdr.major;
    image_.minor_runtime = hdr.minor;
    image_.entry_point_token = hdr.entry_point;
    image_.il_only = (hdr.flags & 0x00000001) != 0;   // COMIMAGE_FLAGS_ILONLY
    image_.runtime_version = md_.version();
    image_.assembly_name = md_.assembly_name();

    const u32 type_rows = (std::min)(md_.table_rows(mdt::TypeDef), kMaxTypes);
    const u32 meth_rows = (std::min)(md_.table_rows(mdt::MethodDef), kMaxMethods);

    image_.types.reserve(type_rows);
    image_.methods.reserve(meth_rows);

    // Build types.
    for (u32 t = 1; t <= type_rows; ++t) {
        MetadataReader::TypeDefRow td = md_.type_def(t);
        DnType dt;
        dt.token = (mdt::TypeDef << 24) | t;
        dt.ns = md_.string_at(td.ns);
        dt.name = md_.string_at(td.name);
        dt.full_name = md_.type_name(dt.token);
        dt.flags = td.flags;
        if (td.extends) {
            MetadataReader::TokenRef ex = md_.decode_coded(
                MetadataReader::Coded::TypeDefOrRef, td.extends);
            if (ex.rid) dt.base_type = md_.type_name((ex.table << 24) | ex.rid);
        }
        image_.types.push_back(std::move(dt));
    }

    // Build methods; associate each with its declaring type.
    for (u32 r = 1; r <= meth_rows; ++r) {
        MetadataReader::MethodDefRow mr = md_.method_def(r);
        DnMethod m;
        m.token = (mdt::MethodDef << 24) | r;
        m.rva = mr.rva;
        m.flags = mr.flags;
        m.impl_flags = mr.impl_flags;
        m.is_static = (mr.flags & kMethodStatic) != 0;
        m.name = md_.string_at(mr.name);

        u32 owner = md_.method_decl_type(r);
        m.decl_type = owner ? md_.type_name((mdt::TypeDef << 24) | owner) : std::string();
        m.full_name = m.decl_type.empty() ? m.name : m.decl_type + "::" + m.name;

        // Signature -> return type, parameters, and a rendered C# line.
        MetadataReader::MethodSig sig = md_.parse_method_sig(mr.sig);
        m.ret_type = sig.ret.empty() ? "void" : sig.ret;

        // Parameter names come from the Param table via the ParamList range.
        std::vector<std::string> pnames;
        {
            u32 p_start = mr.param_list;
            u32 p_end = (r < md_.table_rows(mdt::MethodDef))
                            ? md_.method_def(r + 1).param_list
                            : md_.table_rows(mdt::Param) + 1;
            for (u32 pr = p_start; pr < p_end && pr <= md_.table_rows(mdt::Param); ++pr) {
                MetadataReader::ParamRow prow = md_.param(pr);
                if (prow.seq == 0) continue;   // seq 0 is the return-value pseudo-param
                pnames.push_back(md_.string_at(prow.name));
            }
        }
        for (size_t i = 0; i < sig.params.size(); ++i) {
            DnParam p;
            p.type = sig.params[i];
            p.name = i < pnames.size() ? pnames[i] : fmt::format("arg{}", i);
            m.params.push_back(std::move(p));
        }

        std::string param_str;
        for (size_t i = 0; i < m.params.size(); ++i) {
            if (i) param_str += ", ";
            param_str += m.params[i].type;
            if (!m.params[i].name.empty()) param_str += " " + m.params[i].name;
        }
        m.signature = fmt::format("{}{} {}({})", m.is_static ? "static " : "",
                                  m.ret_type, m.full_name, param_str);

        if (owner && owner <= image_.types.size())
            image_.types[owner - 1].method_tokens.push_back(m.token);

        // Decode the body (fills entry, max_stack, code_size, locals, il, EH).
        decode_body(img, m);

        image_.methods.push_back(std::move(m));
    }

    image_.valid = true;
    spdlog::info("dotnet: {} runtime, {} types, {} methods, il_only={}",
                 image_.runtime_version.empty() ? "?" : image_.runtime_version,
                 image_.types.size(), image_.methods.size(), image_.il_only);
    return true;
}

void DotNetDisassembler::decode_body(const PEImage& img, DnMethod& m) const {
    if (m.rva == 0) return;   // abstract, interface, or P/Invoke: no IL body

    size_t avail = 0;
    const u8* p = rva_to_ptr(img, m.rva, &avail);
    if (!p || avail < 1) return;

    u32 header_size = 0;
    u32 code_size = 0;
    u32 local_sig_tok = 0;
    bool more_sects = false;
    bool init_locals = false;

    u8 b = p[0];
    if ((b & 0x03) == 0x02) {
        // Tiny header: 1 byte, code size in the top 6 bits.
        header_size = 1;
        code_size = b >> 2;
        m.max_stack = 8;
    } else if ((b & 0x03) == 0x03) {
        if (avail < 12) return;
        u16 flags_size = rd16(p);
        u16 flags = flags_size & 0x0FFF;
        u32 hdr_dwords = flags_size >> 12;
        header_size = hdr_dwords * 4;
        if (header_size < 12) header_size = 12;
        m.max_stack = rd16(p + 2);
        code_size = rd32(p + 4);
        local_sig_tok = rd32(p + 8);
        more_sects = (flags & 0x08) != 0;   // CorILMethod_MoreSects
        init_locals = (flags & 0x10) != 0;  // CorILMethod_InitLocals
        (void)init_locals;
    } else {
        return;   // not a valid method header
    }

    if (code_size == 0 || code_size > kMaxCodeSize) return;
    if (static_cast<size_t>(header_size) + code_size > avail) return;

    m.code_size = code_size;
    va_t il_base = img.base + m.rva + header_size;
    m.entry = il_base;

    // Local variable types from the StandAloneSig LOCAL_SIG.
    if (local_sig_tok) {
        auto ltypes = md_.parse_local_sig(local_sig_tok);
        for (size_t i = 0; i < ltypes.size(); ++i)
            m.locals.push_back({static_cast<u16>(i), ltypes[i]});
    }

    decode_il(p + header_size, code_size, il_base, m);

    // Exception-handling clauses (fat method, MoreSects). Small or fat section
    // format, DWORD-aligned right after the code.
    if (more_sects) {
        size_t sect_off = header_size + code_size;
        sect_off = (sect_off + 3) & ~size_t(3);
        while (sect_off + 4 <= avail) {
            const u8* s = p + sect_off;
            u8 kind = s[0];
            bool is_fat = (kind & 0x40) != 0;
            bool is_eh = (kind & 0x01) != 0;
            u32 data_size;
            u32 clause_count;
            size_t clause_base;
            if (is_fat) {
                data_size = rd32(s) >> 8;      // 3-byte size
                clause_base = sect_off + 4;
                clause_count = data_size >= 4 ? (data_size - 4) / 24 : 0;
            } else {
                data_size = s[1];
                clause_base = sect_off + 4;
                clause_count = data_size >= 4 ? (data_size - 4) / 12 : 0;
            }
            if (is_eh) {
                for (u32 i = 0; i < clause_count && i < 4096; ++i) {
                    size_t co = clause_base + static_cast<size_t>(i) * (is_fat ? 24 : 12);
                    if (co + (is_fat ? 24 : 12) > avail) break;
                    const u8* cp = p + co;
                    DnExClause ec;
                    u32 eflags, try_off, try_len, h_off, h_len, extra;
                    if (is_fat) {
                        eflags = rd32(cp);
                        try_off = rd32(cp + 4);
                        try_len = rd32(cp + 8);
                        h_off = rd32(cp + 12);
                        h_len = rd32(cp + 16);
                        extra = rd32(cp + 20);
                    } else {
                        eflags = rd16(cp);
                        try_off = rd16(cp + 2);
                        try_len = cp[4];
                        h_off = rd16(cp + 5);
                        h_len = cp[7];
                        extra = rd32(cp + 8);
                    }
                    ec.try_offset = try_off; ec.try_length = try_len;
                    ec.handler_offset = h_off; ec.handler_length = h_len;
                    switch (eflags & 0x7) {
                    case 0x0: ec.kind = "catch"; ec.catch_type = md_.type_name(extra); break;
                    case 0x1: ec.kind = "filter"; break;
                    case 0x2: ec.kind = "finally"; break;
                    case 0x4: ec.kind = "fault"; break;
                    default:  ec.kind = "catch"; break;
                    }
                    m.handlers.push_back(std::move(ec));
                }
            }
            if (!(kind & 0x80)) break;   // no more sections
            // data_size covers the section including its 4-byte header; the
            // next section begins there, DWORD-aligned.
            sect_off = (sect_off + data_size + 3) & ~size_t(3);
        }
    }
}

void DotNetDisassembler::decode_il(const u8* code, u32 size, va_t il_base, DnMethod& m) const {
    u32 pos = 0;
    u32 count = 0;
    while (pos < size && count < kMaxInsns) {
        ++count;
        DnInsn di;
        di.offset = pos;
        di.addr = il_base + pos;

        u16 opcode = code[pos++];
        if (opcode == 0xFE && pos < size) opcode = 0xFE00 | code[pos++];
        di.opcode = opcode;

        const ILOpcode* oc = il_lookup(opcode);
        if (!oc) {
            di.mnemonic = fmt::format("unknown.0x{:02X}", opcode & 0xFF);
            di.flow = ILFlow::Next;
            di.size = static_cast<u8>(pos - di.offset);
            m.il.push_back(std::move(di));
            continue;
        }
        di.mnemonic = oc->name;
        di.flow = oc->flow;

        const auto need = [&](u32 n) { return pos + n <= size; };

        switch (oc->operand) {
        case ILOperand::None:
            break;
        case ILOperand::ShortVar: {
            if (!need(1)) break;
            u8 v = code[pos]; pos += 1;
            if (di.mnemonic.rfind("ldloc", 0) == 0 || di.mnemonic.rfind("stloc", 0) == 0)
                di.operand = fmt::format("V_{}", v);
            else
                di.operand = fmt::format("{}", v);
            break;
        }
        case ILOperand::Var: {
            if (!need(2)) break;
            u16 v = rd16(code + pos); pos += 2;
            if (di.mnemonic.rfind("ldloc", 0) == 0 || di.mnemonic.rfind("stloc", 0) == 0)
                di.operand = fmt::format("V_{}", v);
            else
                di.operand = fmt::format("{}", v);
            break;
        }
        case ILOperand::ShortI: {
            if (!need(1)) break;
            i8 v = static_cast<i8>(code[pos]); pos += 1;
            di.operand = fmt::format("{}", static_cast<int>(v));
            break;
        }
        case ILOperand::I: {
            if (!need(4)) break;
            i32 v = static_cast<i32>(rd32(code + pos)); pos += 4;
            di.operand = fmt::format("{}", v);
            break;
        }
        case ILOperand::I8: {
            if (!need(8)) break;
            u64 lo = rd32(code + pos), hi = rd32(code + pos + 4); pos += 8;
            i64 v = static_cast<i64>((hi << 32) | lo);
            di.operand = fmt::format("{}", v);
            break;
        }
        case ILOperand::ShortR: {
            if (!need(4)) break;
            u32 raw = rd32(code + pos); pos += 4;
            float f; std::memcpy(&f, &raw, 4);
            di.operand = fmt::format("{}", f);
            break;
        }
        case ILOperand::R: {
            if (!need(8)) break;
            u64 lo = rd32(code + pos), hi = rd32(code + pos + 4); pos += 8;
            u64 raw = (hi << 32) | lo;
            double d; std::memcpy(&d, &raw, 8);
            di.operand = fmt::format("{}", d);
            break;
        }
        case ILOperand::Method: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = md_.method_name(tok);
            break;
        }
        case ILOperand::Field: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = md_.field_name(tok);
            break;
        }
        case ILOperand::Type: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = md_.type_name(tok);
            break;
        }
        case ILOperand::Tok: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = md_.token_name(tok);
            break;
        }
        case ILOperand::Str: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = "\"" + md_.user_string_at(tok & 0x00FFFFFF) + "\"";
            break;
        }
        case ILOperand::Sig: {
            if (!need(4)) break;
            u32 tok = rd32(code + pos); pos += 4;
            di.operand = fmt::format("sig:0x{:08X}", tok);
            break;
        }
        case ILOperand::ShortBrTarget: {
            if (!need(1)) break;
            i8 delta = static_cast<i8>(code[pos]); pos += 1;
            u32 tgt = pos + delta;
            di.target = il_base + tgt;
            di.operand = fmt::format("IL_{:04X}", tgt);
            break;
        }
        case ILOperand::BrTarget: {
            if (!need(4)) break;
            i32 delta = static_cast<i32>(rd32(code + pos)); pos += 4;
            u32 tgt = pos + delta;
            di.target = il_base + tgt;
            di.operand = fmt::format("IL_{:04X}", tgt);
            break;
        }
        case ILOperand::Switch: {
            if (!need(4)) break;
            u32 n = rd32(code + pos); pos += 4;
            if (n > (size - pos) / 4) n = (size - pos) / 4;   // clamp to remaining
            std::vector<i32> deltas(n);
            for (u32 i = 0; i < n; ++i) { deltas[i] = static_cast<i32>(rd32(code + pos)); pos += 4; }
            std::string ops;
            for (u32 i = 0; i < n; ++i) {
                u32 tgt = pos + deltas[i];
                di.switch_targets.push_back(il_base + tgt);
                if (i) ops += ", ";
                ops += fmt::format("IL_{:04X}", tgt);
            }
            di.operand = "(" + ops + ")";
            break;
        }
        }

        di.size = static_cast<u8>(pos - di.offset);
        m.il.push_back(std::move(di));
    }
}

void DotNetDisassembler::populate_db(AnalysisDB& db) const {
    if (!image_.valid) return;

    size_t added_funcs = 0, added_insns = 0;
    for (const auto& m : image_.methods) {
        if (m.il.empty() || m.entry == 0) continue;

        std::string fname = m.full_name.empty() ? fmt::format("method_{:X}", m.token)
                                                 : m.full_name;
        Function f;
        f.entry = m.entry;
        f.name = fname;

        // One basic block spanning the whole method body. IL branch structure
        // isn't split into native-style blocks; this keeps the listing intact
        // and lets function_at / block views resolve the method.
        BasicBlock bb;
        bb.start = m.entry;
        bb.end = m.entry + m.code_size;
        bb.insns.reserve(m.il.size());

        for (const auto& di : m.il) {
            Insn ins{};
            ins.addr = di.addr;
            ins.len = di.size ? di.size : 1;
            ins.type = flow_to_insn_type(di.flow);
            ins.op_count = 0;
            ins.mnemonic_id = 0;
            ins.set_mnemonic(di.mnemonic);
            ins.set_op_str(di.operand);
            bb.insns.push_back(ins);
            db.insns[di.addr] = ins;
            ++added_insns;
        }

        f.block_addrs.push_back(bb.start);
        f.blocks[bb.start] = std::move(bb);
        f.analyzed = true;
        f.callconv = m.is_static ? CallConv::Unknown : CallConv::Thiscall;

        db.funcs[f.entry] = std::move(f);
        db.names[m.entry] = fname;
        if (!m.signature.empty()) db.comments[m.entry] = m.signature;
        ++added_funcs;
    }

    spdlog::info("dotnet: populated {} methods, {} IL insns into analysis db",
                 added_funcs, added_insns);
}

// -------------------------------------------------------------------------

std::string DotNetDisassembler::render_method(const DnMethod& m) const {
    std::string out;
    out += fmt::format(".method {} // token 0x{:08X}\n", m.signature, m.token);
    if (!m.locals.empty()) {
        out += "    .locals (";
        for (size_t i = 0; i < m.locals.size(); ++i) {
            if (i) out += ", ";
            out += fmt::format("[{}] {}", m.locals[i].index, m.locals[i].type);
        }
        out += ")\n";
    }
    out += fmt::format("    .maxstack {}\n", m.max_stack);
    if (m.rva == 0) {
        out += "    // no body (abstract / pinvoke / internalcall)\n";
        return out;
    }
    for (const auto& di : m.il) {
        if (di.operand.empty())
            out += fmt::format("    IL_{:04X}: {}\n", di.offset, di.mnemonic);
        else
            out += fmt::format("    IL_{:04X}: {:<12} {}\n", di.offset, di.mnemonic, di.operand);
    }
    for (const auto& h : m.handlers) {
        out += fmt::format("    .try IL_{:04X}..IL_{:04X} {} handler IL_{:04X}..IL_{:04X} {}\n",
                           h.try_offset, h.try_offset + h.try_length, h.kind,
                           h.handler_offset, h.handler_offset + h.handler_length,
                           h.catch_type);
    }
    return out;
}

std::string DotNetDisassembler::render_all() const {
    std::string out;
    out += fmt::format("// .NET assembly - runtime {} - {} types, {} methods\n\n",
                       image_.runtime_version, image_.types.size(), image_.methods.size());
    for (const auto& t : image_.types) {
        if (t.method_tokens.empty()) continue;
        out += fmt::format(".class {}{}\n", t.full_name,
                           t.base_type.empty() ? "" : " extends " + t.base_type);
        for (u32 tok : t.method_tokens) {
            u32 rid = tok & 0x00FFFFFF;
            if (rid == 0 || rid > image_.methods.size()) continue;
            out += render_method(image_.methods[rid - 1]);
            out += "\n";
        }
        out += "\n";
    }
    return out;
}

}
