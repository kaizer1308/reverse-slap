#include "dotnet_decompiler.h"
#include "cil_opcodes.h"
#include <fmt/format.h>
#include <cctype>
#include <set>
#include <vector>
#include <cstdlib>

namespace hype {

namespace {

// Split "Declaring.Type::member" -> "member" (or the whole string if no "::").
std::string simple_member(const std::string& qualified) {
    auto pos = qualified.rfind("::");
    return pos == std::string::npos ? qualified : qualified.substr(pos + 2);
}

// "A.B::c" -> "A.B.c" for static member access rendering.
std::string dotted(const std::string& qualified) {
    std::string s = qualified;
    auto pos = s.find("::");
    if (pos != std::string::npos) s.replace(pos, 2, ".");
    return s;
}

// Strip a leading address-of/deref decoration so "&x" / "*x" render as "x".
std::string deref(const std::string& e) {
    if (!e.empty() && (e[0] == '&' || e[0] == '*')) return e.substr(1);
    return e;
}

// C# target type for a conv.* opcode (base + overflow variants share a type).
const char* conv_type(u16 op) {
    switch (op) {
    case 0x67: case 0xB3: case 0x82: return "sbyte";   // conv.i1 family
    case 0xD2: case 0xB4: case 0x86: return "byte";    // conv.u1 family
    case 0x68: case 0xB5: case 0x83: return "short";   // conv.i2 family
    case 0xD1: case 0xB6: case 0x87: return "ushort";  // conv.u2 family
    case 0x69: case 0xB7: case 0x84: return "int";     // conv.i4 family
    case 0x6D: case 0xB8: case 0x88: return "uint";    // conv.u4 family
    case 0x6A: case 0xB9: case 0x85: return "long";    // conv.i8 family
    case 0x6E: case 0xBA: case 0x89: return "ulong";   // conv.u8 family
    case 0x6B: return "float";                         // conv.r4
    case 0x6C: case 0x76: return "double";             // conv.r8 / conv.r.un
    case 0xD3: case 0xD4: case 0x8A: return "IntPtr";  // conv.i family
    case 0xE0: case 0xD5: case 0x8B: return "UIntPtr"; // conv.u family
    default: return nullptr;
    }
}

// C# binary operator for an arithmetic/bitwise IL opcode; nullptr if not one.
const char* bin_op(u16 op) {
    switch (op) {
    case 0x58: case 0xD6: case 0xD7: return "+";   // add (+ovf)
    case 0x59: case 0xDA: case 0xDB: return "-";   // sub (+ovf)
    case 0x5A: case 0xD8: case 0xD9: return "*";   // mul (+ovf)
    case 0x5B: case 0x5C: return "/";              // div (+un)
    case 0x5D: case 0x5E: return "%";              // rem (+un)
    case 0x5F: return "&";
    case 0x60: return "|";
    case 0x61: return "^";
    case 0x62: return "<<";
    case 0x63: case 0x64: return ">>";             // shr (+un)
    default: return nullptr;
    }
}

// Condition operator for a two-operand conditional branch; nullptr otherwise.
const char* cmp_branch_op(u16 op) {
    switch (op) {
    case 0x2E: case 0x3B: return "==";  // beq
    case 0x33: case 0x40: return "!=";  // bne.un
    case 0x2F: case 0x34: case 0x3C: case 0x41: return ">=";  // bge (+un)
    case 0x30: case 0x35: case 0x3D: case 0x42: return ">";   // bgt (+un)
    case 0x31: case 0x36: case 0x3E: case 0x43: return "<=";  // ble (+un)
    case 0x32: case 0x37: case 0x3F: case 0x44: return "<";   // blt (+un)
    default: return nullptr;
    }
}

struct Decompiler {
    const DnMethod& m;
    const DnImage& img;
    const MetadataReader& md;
    const std::string& indent;

    std::vector<std::string> stack;
    std::vector<std::string> lines;
    std::set<u32> labels;      // IL offsets that are branch targets
    u32 unknowns = 0;
    u32 temp_id = 0;
    bool has_this = false;

    explicit Decompiler(const DnMethod& mm, const DnImage& i,
                        const MetadataReader& d, const std::string& ind)
        : m(mm), img(i), md(d), indent(ind) { has_this = !m.is_static; }

    void push(const std::string& s) { stack.push_back(s); }
    std::string pop() {
        if (stack.empty()) { ++unknowns; return "?"; }
        std::string v = std::move(stack.back());
        stack.pop_back();
        return v;
    }
    void emit(const std::string& s) { lines.push_back(indent + s); }

    std::string arg_name(u32 i) const {
        if (has_this) {
            if (i == 0) return "this";
            u32 idx = i - 1;
            if (idx < m.params.size() && !m.params[idx].name.empty())
                return m.params[idx].name;
            return fmt::format("arg{}", idx);
        }
        if (i < m.params.size() && !m.params[i].name.empty())
            return m.params[i].name;
        return fmt::format("arg{}", i);
    }
    static std::string local_name(u32 i) { return fmt::format("V_{}", i); }

    // Extract the numeric index from an operand like "3" or "V_3".
    static u32 var_index(const std::string& operand) {
        const char* p = operand.c_str();
        if (operand.size() > 2 && operand[0] == 'V' && operand[1] == '_') p += 2;
        return static_cast<u32>(std::strtoul(p, nullptr, 10));
    }

    std::string field_target(const DnInsn& in, bool is_static) {
        // Operand is "DeclType::name"; instance access pops the receiver.
        std::string name = simple_member(in.operand);
        if (is_static) return dotted(in.operand);
        std::string recv = pop();
        return recv + "." + name;
    }

    void do_call(const DnInsn& in, bool is_newobj) {
        MetadataReader::CallInfo ci = md.call_info(in.token);
        std::vector<std::string> args;
        args.reserve(ci.arg_count);
        for (u32 i = 0; i < ci.arg_count; ++i) args.push_back(pop());
        std::reverse(args.begin(), args.end());
        std::string arglist;
        for (size_t i = 0; i < args.size(); ++i) {
            if (i) arglist += ", ";
            arglist += args[i];
        }

        if (is_newobj) {
            push(fmt::format("new {}({})", ci.decl_type, arglist));
            return;
        }

        // Receiver for an instance call (popped after the args, deepest on stack).
        std::string recv;
        if (ci.has_this) recv = pop();

        // Base constructor chaining: `this.ctor(...)` at the top of a .ctor.
        // An implicit parameterless base call is noise, so only surface it when
        // it actually forwards arguments.
        if (ci.simple_name == ".ctor" && ci.has_this) {
            if (!arglist.empty()) emit(fmt::format("base({});", arglist));
            return;
        }
        // Property accessors read back as property access.
        if (ci.simple_name.rfind("get_", 0) == 0 && ci.arg_count == 0) {
            std::string prop = ci.simple_name.substr(4);
            push(ci.has_this ? recv + "." + prop : ci.decl_type + "." + prop);
            return;
        }
        if (ci.simple_name.rfind("set_", 0) == 0 && ci.arg_count == 1) {
            std::string prop = ci.simple_name.substr(4);
            std::string lhs = ci.has_this ? recv + "." + prop : ci.decl_type + "." + prop;
            emit(fmt::format("{} = {};", lhs, args.empty() ? "?" : args[0]));
            return;
        }

        std::string callee = ci.has_this ? recv + "." + ci.simple_name
                                          : ci.decl_type + "." + ci.simple_name;
        std::string expr = fmt::format("{}({})", callee, arglist);
        if (ci.returns_void) emit(expr + ";");
        else                 push(expr);
    }

    void run() {
        // Collect branch targets so we can print labels only where needed.
        for (const auto& in : m.il) {
            if (in.br_offset || in.flow == ILFlow::Branch || in.flow == ILFlow::Cond) {
                if (in.br_offset) labels.insert(in.br_offset);
            }
            for (u32 off : in.switch_offsets) labels.insert(off);
        }

        // Declare locals up front (V_0..), matching the .locals directive.
        for (const auto& l : m.locals)
            emit(fmt::format("{} {};", l.type.empty() ? "object" : l.type, local_name(l.index)));

        for (const auto& in : m.il) {
            if (labels.count(in.offset)) {
                // A value flowing across a branch (ternary / && / ||): spill it
                // so the label statement is well-formed and the value survives.
                while (!stack.empty()) {
                    std::string front = stack.front();
                    stack.erase(stack.begin());
                    // A "?" is a prior underflow placeholder; spilling it adds
                    // noise without preserving anything. Real values are kept as
                    // temps so their side effects survive the branch.
                    if (front != "?") {
                        std::string t = fmt::format("stk{}", temp_id++);
                        lines.push_back(indent + fmt::format("var {} = {};", t, front));
                    }
                }
                lines.push_back(indent + fmt::format("IL_{:04X}:;", in.offset));
            }
            step(in);
        }

        // Trailing values (e.g. a method that leaves a return value implicit).
        stack.clear();
    }

    void step(const DnInsn& in) {
        const u16 op = in.opcode;

        // ldarg.0..3 / ldloc.0..3 / stloc.0..3 short forms.
        if (op >= 0x02 && op <= 0x05) { push(arg_name(op - 0x02)); return; }
        if (op >= 0x06 && op <= 0x09) { push(local_name(op - 0x06)); return; }
        if (op >= 0x0A && op <= 0x0D) { emit(local_name(op - 0x0A) + " = " + pop() + ";"); return; }

        if (const char* ct = conv_type(op)) { push(fmt::format("({}){}", ct, pop())); return; }
        if (const char* bo = bin_op(op)) {
            std::string b = pop(), a = pop();
            push(fmt::format("({} {} {})", a, bo, b));
            return;
        }
        if (const char* cb = cmp_branch_op(op)) {
            std::string b = pop(), a = pop();
            emit(fmt::format("if ({} {} {}) goto IL_{:04X};", a, cb, b, in.br_offset));
            return;
        }
        // Array element load (ldelem.* / ldelem <type>): push arr[idx].
        if ((op >= 0x90 && op <= 0x9A) || op == 0xA3) {
            std::string i = pop(), a = pop();
            push(fmt::format("{}[{}]", a, i));
            return;
        }
        // Array element store (stelem.* / stelem <type>): arr[idx] = v.
        if ((op >= 0x9B && op <= 0xA2) || op == 0xA4) {
            std::string v = pop(), i = pop(), a = pop();
            emit(fmt::format("{}[{}] = {};", a, i, v));
            return;
        }

        switch (op) {
        // --- loads --------------------------------------------------------
        case 0x0E: case 0xFE09: push(arg_name(var_index(in.operand))); break;   // ldarg(.s)
        case 0x0F: case 0xFE0A: push("&" + arg_name(var_index(in.operand))); break; // ldarga
        case 0x11: case 0xFE0C: push(local_name(var_index(in.operand))); break; // ldloc(.s)
        case 0x12: case 0xFE0D: push("&" + local_name(var_index(in.operand))); break; // ldloca
        case 0x14: push("null"); break;                                         // ldnull
        case 0x15: push("-1"); break;                                           // ldc.i4.m1
        case 0x16: case 0x17: case 0x18: case 0x19:
        case 0x1A: case 0x1B: case 0x1C: case 0x1D: case 0x1E:
            push(std::to_string(op - 0x16)); break;                             // ldc.i4.0..8
        case 0x1F: case 0x20: case 0x21: case 0x22: case 0x23:
            push(in.operand); break;                                            // ldc.i4.s/i4/i8/r4/r8
        case 0x72: push(in.operand); break;                                     // ldstr (already quoted)

        // --- stores -------------------------------------------------------
        case 0x10: case 0xFE0B: emit(arg_name(var_index(in.operand)) + " = " + pop() + ";"); break; // starg
        case 0x13: case 0xFE0E: emit(local_name(var_index(in.operand)) + " = " + pop() + ";"); break; // stloc(.s)

        // --- fields -------------------------------------------------------
        case 0x7B: push(field_target(in, false)); break;                        // ldfld
        case 0x7C: push("&" + field_target(in, false)); break;                  // ldflda
        case 0x7E: push(field_target(in, true)); break;                         // ldsfld
        case 0x7F: push("&" + field_target(in, true)); break;                   // ldsflda
        case 0x7D: { std::string v = pop(); emit(field_target(in, false) + " = " + v + ";"); break; } // stfld
        case 0x80: { std::string v = pop(); emit(field_target(in, true) + " = " + v + ";"); break; }  // stsfld

        // --- arrays -------------------------------------------------------
        case 0x8E: push(pop() + ".Length"); break;                              // ldlen
        case 0x8D: push(fmt::format("new {}[{}]", in.operand, pop())); break;   // newarr
        case 0x8F: { std::string i = pop(), a = pop(); push(fmt::format("{}[{}]", a, i)); break; } // ldelema

        // --- comparisons (push 0/1) --------------------------------------
        case 0xFE01: { std::string b = pop(), a = pop(); push(fmt::format("({} == {})", a, b)); break; } // ceq
        case 0xFE02: case 0xFE03: { std::string b = pop(), a = pop(); push(fmt::format("({} > {})", a, b)); break; } // cgt(.un)
        case 0xFE04: case 0xFE05: { std::string b = pop(), a = pop(); push(fmt::format("({} < {})", a, b)); break; } // clt(.un)

        // --- unary --------------------------------------------------------
        case 0x65: push("(-" + pop() + ")"); break;                             // neg
        case 0x66: push("(~" + pop() + ")"); break;                             // not

        // --- object model -------------------------------------------------
        case 0x28: case 0x6F: do_call(in, false); break;                        // call / callvirt
        case 0x73: do_call(in, true); break;                                    // newobj
        case 0x74: push(fmt::format("(({}){})", in.operand, pop())); break;     // castclass
        case 0x75: push(fmt::format("({} as {})", pop(), in.operand)); break;   // isinst
        case 0x79: case 0xA5: push(fmt::format("(({}){})", in.operand, pop())); break; // unbox(.any)
        case 0x8C: /* box: implicit in C# */ break;                             // box
        case 0xFE15: { std::string a = deref(pop()); emit(fmt::format("{} = default({});", a, in.operand)); break; } // initobj
        case 0xFE1C: push(fmt::format("sizeof({})", in.operand)); break;        // sizeof
        case 0xD0:                                                              // ldtoken
            push((in.token >> 24) == 0x02 || (in.token >> 24) == 0x01 || (in.token >> 24) == 0x1B
                     ? fmt::format("typeof({})", in.operand)
                     : fmt::format("ldtoken({})", in.operand));
            break;
        case 0xFE06: case 0xFE07: push(fmt::format("&{}", dotted(in.operand))); break; // ldftn/ldvirtftn

        // --- stack shuffles ----------------------------------------------
        case 0x25: {                                                            // dup
            // A simple lvalue can be duplicated verbatim; anything with side
            // effects (a call, `new`, an operator) is spilled to a temp so it
            // evaluates once. Keeps array/object initializers readable.
            std::string e = pop();
            const bool simple = !e.empty() &&
                (std::isalpha(static_cast<unsigned char>(e[0])) || e[0] == '_') &&
                e.find(' ') == std::string::npos && e.find('(') == std::string::npos;
            if (simple) { push(e); push(e); }
            else {
                std::string t = fmt::format("_t{}", temp_id++);
                emit(fmt::format("var {} = {};", t, e));
                push(t); push(t);
            }
            break;
        }
        case 0x26: { std::string e = pop(); if (e != "?") emit(e + ";"); break; } // pop
        case 0x00: case 0xFE13: case 0xFE14: case 0xFE16: case 0xFE1E: break;   // nop / prefixes

        // --- indirect load/store -----------------------------------------
        case 0x46: case 0x47: case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: case 0x50: case 0x71:
            push("*" + deref(pop())); break;                                    // ldind.* / ldobj
        case 0x51: case 0x52: case 0x53: case 0x54: case 0x55: case 0x56:
        case 0x57: case 0xDF: case 0x81:
            { std::string v = pop(); emit("*" + deref(pop()) + " = " + v + ";"); break; } // stind.* / stobj

        // --- branches -----------------------------------------------------
        case 0x2B: case 0x38: case 0xDD: case 0xDE:                             // br(.s) / leave(.s)
            emit(fmt::format("goto IL_{:04X};", in.br_offset)); break;
        case 0x2C: case 0x39: emit(fmt::format("if (!({})) goto IL_{:04X};", pop(), in.br_offset)); break; // brfalse(.s)
        case 0x2D: case 0x3A: emit(fmt::format("if ({}) goto IL_{:04X};", pop(), in.br_offset)); break;    // brtrue(.s)
        case 0x45: {                                                            // switch
            std::string v = pop();
            emit(fmt::format("switch ({}) {{", v));
            for (size_t i = 0; i < in.switch_offsets.size(); ++i)
                emit(fmt::format("case {}: goto IL_{:04X};", i, in.switch_offsets[i]));
            emit("}");
            break;
        }

        // --- returns / throws --------------------------------------------
        case 0x2A:                                                              // ret
            if (m.ret_type == "void" || m.ret_type.empty() || stack.empty()) emit("return;");
            else emit("return " + pop() + ";");
            break;
        case 0x7A: emit("throw " + pop() + ";"); break;                         // throw
        case 0xFE1A: emit("throw;"); break;                                     // rethrow
        case 0xDC: emit("// endfinally"); break;                                // endfinally
        case 0xFE11: emit("// endfilter"); pop(); break;                        // endfilter

        default:
            // Anything unmodeled: keep the IL as a comment, leave stack alone.
            emit(fmt::format("// {} {}", in.mnemonic, in.operand));
            ++unknowns;
            break;
        }
    }
};

} // namespace

CSharpBody decompile_body(const DnMethod& m, const DnImage& img,
                          const MetadataReader& md, const std::string& indent) {
    CSharpBody out;
    if (m.rva == 0 || m.il.empty()) {
        out.structured = false;
        return out;   // abstract / interface / pinvoke: no body to rebuild
    }

    Decompiler dc(m, img, md, indent);
    dc.run();

    std::string code;
    for (const auto& l : dc.lines) { code += l; code += "\n"; }
    out.code = std::move(code);
    out.unknowns = dc.unknowns;
    out.structured = !dc.lines.empty() && dc.unknowns * 3 < m.il.size() + 1;
    return out;
}

}
