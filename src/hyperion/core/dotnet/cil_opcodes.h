#pragma once
#include "core/types.h"

// Complete CIL/MSIL opcode table per ECMA-335 (Common Language Infrastructure),
// Partition III and Partition VI Annex A. Covers the single-byte opcode space
// and the two-byte 0xFE-prefixed space. Modelled on the operand taxonomy used by
// ILDASM / dnSpy so the disassembler can decode every operand form the runtime
// emits. This is pure reference data; keeping it header-only lets both the method
// body decoder and any future IL analysis share one source of truth.

namespace hype {

// Operand encoding that follows an opcode in the instruction stream. Widths are
// fixed by ECMA-335 III.1.2; InlineSwitch is variable (a u32 count followed by
// that many i32 jump deltas).
enum class ILOperand : u8 {
    None,           // no operand
    ShortVar,       // u8  local/arg index
    Var,            // u16 local/arg index
    ShortI,         // i8  integer
    I,              // i32 integer
    I8,             // i64 integer
    ShortR,         // f32 float
    R,              // f64 float
    Method,         // u32 metadata token (MethodDef/MemberRef/MethodSpec)
    Field,          // u32 metadata token (Field/MemberRef)
    Type,           // u32 metadata token (TypeDef/TypeRef/TypeSpec)
    Tok,            // u32 metadata token (any — ldtoken)
    Str,            // u32 #US token (ldstr)
    Sig,            // u32 StandAloneSig token (calli)
    ShortBrTarget,  // i8  branch delta from end of instruction
    BrTarget,       // i32 branch delta from end of instruction
    Switch          // u32 count, then count * i32 deltas
};

// Coarse control-flow class, used to build basic blocks and mark call sites
// without re-deriving them from the mnemonic string.
enum class ILFlow : u8 {
    Next,      // falls through
    Branch,    // unconditional branch (br, leave)
    Cond,      // conditional branch (brtrue, beq, ...)
    Call,      // call / callvirt / newobj / calli / jmp
    Return,    // ret / endfinally / endfilter
    Throw,     // throw / rethrow
    Meta       // prefix opcode (volatile., tail., constrained., ...)
};

struct ILOpcode {
    u16        value;    // 0x00..0xE0, or 0xFE00..0xFE1E for two-byte forms
    const char* name;    // canonical mnemonic, e.g. "ldarg.0"
    ILOperand  operand;
    ILFlow     flow;
};

// Single-byte opcodes. Gaps in the numeric range (unused/reserved encodings) are
// simply absent; lookup falls back to an "unknown" rendering.
inline constexpr ILOpcode kILOpcodes1[] = {
    {0x00, "nop",            ILOperand::None,          ILFlow::Next},
    {0x01, "break",          ILOperand::None,          ILFlow::Next},
    {0x02, "ldarg.0",        ILOperand::None,          ILFlow::Next},
    {0x03, "ldarg.1",        ILOperand::None,          ILFlow::Next},
    {0x04, "ldarg.2",        ILOperand::None,          ILFlow::Next},
    {0x05, "ldarg.3",        ILOperand::None,          ILFlow::Next},
    {0x06, "ldloc.0",        ILOperand::None,          ILFlow::Next},
    {0x07, "ldloc.1",        ILOperand::None,          ILFlow::Next},
    {0x08, "ldloc.2",        ILOperand::None,          ILFlow::Next},
    {0x09, "ldloc.3",        ILOperand::None,          ILFlow::Next},
    {0x0A, "stloc.0",        ILOperand::None,          ILFlow::Next},
    {0x0B, "stloc.1",        ILOperand::None,          ILFlow::Next},
    {0x0C, "stloc.2",        ILOperand::None,          ILFlow::Next},
    {0x0D, "stloc.3",        ILOperand::None,          ILFlow::Next},
    {0x0E, "ldarg.s",        ILOperand::ShortVar,      ILFlow::Next},
    {0x0F, "ldarga.s",       ILOperand::ShortVar,      ILFlow::Next},
    {0x10, "starg.s",        ILOperand::ShortVar,      ILFlow::Next},
    {0x11, "ldloc.s",        ILOperand::ShortVar,      ILFlow::Next},
    {0x12, "ldloca.s",       ILOperand::ShortVar,      ILFlow::Next},
    {0x13, "stloc.s",        ILOperand::ShortVar,      ILFlow::Next},
    {0x14, "ldnull",         ILOperand::None,          ILFlow::Next},
    {0x15, "ldc.i4.m1",      ILOperand::None,          ILFlow::Next},
    {0x16, "ldc.i4.0",       ILOperand::None,          ILFlow::Next},
    {0x17, "ldc.i4.1",       ILOperand::None,          ILFlow::Next},
    {0x18, "ldc.i4.2",       ILOperand::None,          ILFlow::Next},
    {0x19, "ldc.i4.3",       ILOperand::None,          ILFlow::Next},
    {0x1A, "ldc.i4.4",       ILOperand::None,          ILFlow::Next},
    {0x1B, "ldc.i4.5",       ILOperand::None,          ILFlow::Next},
    {0x1C, "ldc.i4.6",       ILOperand::None,          ILFlow::Next},
    {0x1D, "ldc.i4.7",       ILOperand::None,          ILFlow::Next},
    {0x1E, "ldc.i4.8",       ILOperand::None,          ILFlow::Next},
    {0x1F, "ldc.i4.s",       ILOperand::ShortI,        ILFlow::Next},
    {0x20, "ldc.i4",         ILOperand::I,             ILFlow::Next},
    {0x21, "ldc.i8",         ILOperand::I8,            ILFlow::Next},
    {0x22, "ldc.r4",         ILOperand::ShortR,        ILFlow::Next},
    {0x23, "ldc.r8",         ILOperand::R,             ILFlow::Next},
    {0x25, "dup",            ILOperand::None,          ILFlow::Next},
    {0x26, "pop",            ILOperand::None,          ILFlow::Next},
    {0x27, "jmp",            ILOperand::Method,        ILFlow::Call},
    {0x28, "call",           ILOperand::Method,        ILFlow::Call},
    {0x29, "calli",          ILOperand::Sig,           ILFlow::Call},
    {0x2A, "ret",            ILOperand::None,          ILFlow::Return},
    {0x2B, "br.s",           ILOperand::ShortBrTarget, ILFlow::Branch},
    {0x2C, "brfalse.s",      ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x2D, "brtrue.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x2E, "beq.s",          ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x2F, "bge.s",          ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x30, "bgt.s",          ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x31, "ble.s",          ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x32, "blt.s",          ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x33, "bne.un.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x34, "bge.un.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x35, "bgt.un.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x36, "ble.un.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x37, "blt.un.s",       ILOperand::ShortBrTarget, ILFlow::Cond},
    {0x38, "br",             ILOperand::BrTarget,      ILFlow::Branch},
    {0x39, "brfalse",        ILOperand::BrTarget,      ILFlow::Cond},
    {0x3A, "brtrue",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x3B, "beq",            ILOperand::BrTarget,      ILFlow::Cond},
    {0x3C, "bge",            ILOperand::BrTarget,      ILFlow::Cond},
    {0x3D, "bgt",            ILOperand::BrTarget,      ILFlow::Cond},
    {0x3E, "ble",            ILOperand::BrTarget,      ILFlow::Cond},
    {0x3F, "blt",            ILOperand::BrTarget,      ILFlow::Cond},
    {0x40, "bne.un",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x41, "bge.un",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x42, "bgt.un",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x43, "ble.un",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x44, "blt.un",         ILOperand::BrTarget,      ILFlow::Cond},
    {0x45, "switch",         ILOperand::Switch,        ILFlow::Cond},
    {0x46, "ldind.i1",       ILOperand::None,          ILFlow::Next},
    {0x47, "ldind.u1",       ILOperand::None,          ILFlow::Next},
    {0x48, "ldind.i2",       ILOperand::None,          ILFlow::Next},
    {0x49, "ldind.u2",       ILOperand::None,          ILFlow::Next},
    {0x4A, "ldind.i4",       ILOperand::None,          ILFlow::Next},
    {0x4B, "ldind.u4",       ILOperand::None,          ILFlow::Next},
    {0x4C, "ldind.i8",       ILOperand::None,          ILFlow::Next},
    {0x4D, "ldind.i",        ILOperand::None,          ILFlow::Next},
    {0x4E, "ldind.r4",       ILOperand::None,          ILFlow::Next},
    {0x4F, "ldind.r8",       ILOperand::None,          ILFlow::Next},
    {0x50, "ldind.ref",      ILOperand::None,          ILFlow::Next},
    {0x51, "stind.ref",      ILOperand::None,          ILFlow::Next},
    {0x52, "stind.i1",       ILOperand::None,          ILFlow::Next},
    {0x53, "stind.i2",       ILOperand::None,          ILFlow::Next},
    {0x54, "stind.i4",       ILOperand::None,          ILFlow::Next},
    {0x55, "stind.i8",       ILOperand::None,          ILFlow::Next},
    {0x56, "stind.r4",       ILOperand::None,          ILFlow::Next},
    {0x57, "stind.r8",       ILOperand::None,          ILFlow::Next},
    {0x58, "add",            ILOperand::None,          ILFlow::Next},
    {0x59, "sub",            ILOperand::None,          ILFlow::Next},
    {0x5A, "mul",            ILOperand::None,          ILFlow::Next},
    {0x5B, "div",            ILOperand::None,          ILFlow::Next},
    {0x5C, "div.un",         ILOperand::None,          ILFlow::Next},
    {0x5D, "rem",            ILOperand::None,          ILFlow::Next},
    {0x5E, "rem.un",         ILOperand::None,          ILFlow::Next},
    {0x5F, "and",            ILOperand::None,          ILFlow::Next},
    {0x60, "or",             ILOperand::None,          ILFlow::Next},
    {0x61, "xor",            ILOperand::None,          ILFlow::Next},
    {0x62, "shl",            ILOperand::None,          ILFlow::Next},
    {0x63, "shr",            ILOperand::None,          ILFlow::Next},
    {0x64, "shr.un",         ILOperand::None,          ILFlow::Next},
    {0x65, "neg",            ILOperand::None,          ILFlow::Next},
    {0x66, "not",            ILOperand::None,          ILFlow::Next},
    {0x67, "conv.i1",        ILOperand::None,          ILFlow::Next},
    {0x68, "conv.i2",        ILOperand::None,          ILFlow::Next},
    {0x69, "conv.i4",        ILOperand::None,          ILFlow::Next},
    {0x6A, "conv.i8",        ILOperand::None,          ILFlow::Next},
    {0x6B, "conv.r4",        ILOperand::None,          ILFlow::Next},
    {0x6C, "conv.r8",        ILOperand::None,          ILFlow::Next},
    {0x6D, "conv.u4",        ILOperand::None,          ILFlow::Next},
    {0x6E, "conv.u8",        ILOperand::None,          ILFlow::Next},
    {0x6F, "callvirt",       ILOperand::Method,        ILFlow::Call},
    {0x70, "cpobj",          ILOperand::Type,          ILFlow::Next},
    {0x71, "ldobj",          ILOperand::Type,          ILFlow::Next},
    {0x72, "ldstr",          ILOperand::Str,           ILFlow::Next},
    {0x73, "newobj",         ILOperand::Method,        ILFlow::Call},
    {0x74, "castclass",      ILOperand::Type,          ILFlow::Next},
    {0x75, "isinst",         ILOperand::Type,          ILFlow::Next},
    {0x76, "conv.r.un",      ILOperand::None,          ILFlow::Next},
    {0x79, "unbox",          ILOperand::Type,          ILFlow::Next},
    {0x7A, "throw",          ILOperand::None,          ILFlow::Throw},
    {0x7B, "ldfld",          ILOperand::Field,         ILFlow::Next},
    {0x7C, "ldflda",         ILOperand::Field,         ILFlow::Next},
    {0x7D, "stfld",          ILOperand::Field,         ILFlow::Next},
    {0x7E, "ldsfld",         ILOperand::Field,         ILFlow::Next},
    {0x7F, "ldsflda",        ILOperand::Field,         ILFlow::Next},
    {0x80, "stsfld",         ILOperand::Field,         ILFlow::Next},
    {0x81, "stobj",          ILOperand::Type,          ILFlow::Next},
    {0x82, "conv.ovf.i1.un", ILOperand::None,          ILFlow::Next},
    {0x83, "conv.ovf.i2.un", ILOperand::None,          ILFlow::Next},
    {0x84, "conv.ovf.i4.un", ILOperand::None,          ILFlow::Next},
    {0x85, "conv.ovf.i8.un", ILOperand::None,          ILFlow::Next},
    {0x86, "conv.ovf.u1.un", ILOperand::None,          ILFlow::Next},
    {0x87, "conv.ovf.u2.un", ILOperand::None,          ILFlow::Next},
    {0x88, "conv.ovf.u4.un", ILOperand::None,          ILFlow::Next},
    {0x89, "conv.ovf.u8.un", ILOperand::None,          ILFlow::Next},
    {0x8A, "conv.ovf.i.un",  ILOperand::None,          ILFlow::Next},
    {0x8B, "conv.ovf.u.un",  ILOperand::None,          ILFlow::Next},
    {0x8C, "box",            ILOperand::Type,          ILFlow::Next},
    {0x8D, "newarr",         ILOperand::Type,          ILFlow::Next},
    {0x8E, "ldlen",          ILOperand::None,          ILFlow::Next},
    {0x8F, "ldelema",        ILOperand::Type,          ILFlow::Next},
    {0x90, "ldelem.i1",      ILOperand::None,          ILFlow::Next},
    {0x91, "ldelem.u1",      ILOperand::None,          ILFlow::Next},
    {0x92, "ldelem.i2",      ILOperand::None,          ILFlow::Next},
    {0x93, "ldelem.u2",      ILOperand::None,          ILFlow::Next},
    {0x94, "ldelem.i4",      ILOperand::None,          ILFlow::Next},
    {0x95, "ldelem.u4",      ILOperand::None,          ILFlow::Next},
    {0x96, "ldelem.i8",      ILOperand::None,          ILFlow::Next},
    {0x97, "ldelem.i",       ILOperand::None,          ILFlow::Next},
    {0x98, "ldelem.r4",      ILOperand::None,          ILFlow::Next},
    {0x99, "ldelem.r8",      ILOperand::None,          ILFlow::Next},
    {0x9A, "ldelem.ref",     ILOperand::None,          ILFlow::Next},
    {0x9B, "stelem.i",       ILOperand::None,          ILFlow::Next},
    {0x9C, "stelem.i1",      ILOperand::None,          ILFlow::Next},
    {0x9D, "stelem.i2",      ILOperand::None,          ILFlow::Next},
    {0x9E, "stelem.i4",      ILOperand::None,          ILFlow::Next},
    {0x9F, "stelem.i8",      ILOperand::None,          ILFlow::Next},
    {0xA0, "stelem.r4",      ILOperand::None,          ILFlow::Next},
    {0xA1, "stelem.r8",      ILOperand::None,          ILFlow::Next},
    {0xA2, "stelem.ref",     ILOperand::None,          ILFlow::Next},
    {0xA3, "ldelem",         ILOperand::Type,          ILFlow::Next},
    {0xA4, "stelem",         ILOperand::Type,          ILFlow::Next},
    {0xA5, "unbox.any",      ILOperand::Type,          ILFlow::Next},
    {0xB3, "conv.ovf.i1",    ILOperand::None,          ILFlow::Next},
    {0xB4, "conv.ovf.u1",    ILOperand::None,          ILFlow::Next},
    {0xB5, "conv.ovf.i2",    ILOperand::None,          ILFlow::Next},
    {0xB6, "conv.ovf.u2",    ILOperand::None,          ILFlow::Next},
    {0xB7, "conv.ovf.i4",    ILOperand::None,          ILFlow::Next},
    {0xB8, "conv.ovf.u4",    ILOperand::None,          ILFlow::Next},
    {0xB9, "conv.ovf.i8",    ILOperand::None,          ILFlow::Next},
    {0xBA, "conv.ovf.u8",    ILOperand::None,          ILFlow::Next},
    {0xC2, "refanyval",      ILOperand::Type,          ILFlow::Next},
    {0xC3, "ckfinite",       ILOperand::None,          ILFlow::Next},
    {0xC6, "mkrefany",       ILOperand::Type,          ILFlow::Next},
    {0xD0, "ldtoken",        ILOperand::Tok,           ILFlow::Next},
    {0xD1, "conv.u2",        ILOperand::None,          ILFlow::Next},
    {0xD2, "conv.u1",        ILOperand::None,          ILFlow::Next},
    {0xD3, "conv.i",         ILOperand::None,          ILFlow::Next},
    {0xD4, "conv.ovf.i",     ILOperand::None,          ILFlow::Next},
    {0xD5, "conv.ovf.u",     ILOperand::None,          ILFlow::Next},
    {0xD6, "add.ovf",        ILOperand::None,          ILFlow::Next},
    {0xD7, "add.ovf.un",     ILOperand::None,          ILFlow::Next},
    {0xD8, "mul.ovf",        ILOperand::None,          ILFlow::Next},
    {0xD9, "mul.ovf.un",     ILOperand::None,          ILFlow::Next},
    {0xDA, "sub.ovf",        ILOperand::None,          ILFlow::Next},
    {0xDB, "sub.ovf.un",     ILOperand::None,          ILFlow::Next},
    {0xDC, "endfinally",     ILOperand::None,          ILFlow::Return},
    {0xDD, "leave",          ILOperand::BrTarget,      ILFlow::Branch},
    {0xDE, "leave.s",        ILOperand::ShortBrTarget, ILFlow::Branch},
    {0xDF, "stind.i",        ILOperand::None,          ILFlow::Next},
    {0xE0, "conv.u",         ILOperand::None,          ILFlow::Next},
};

// Two-byte opcodes (0xFE prefix). Stored with the full 0xFExx value so a single
// map keyed on u16 can hold both spaces.
inline constexpr ILOpcode kILOpcodes2[] = {
    {0xFE00, "arglist",      ILOperand::None,   ILFlow::Next},
    {0xFE01, "ceq",          ILOperand::None,   ILFlow::Next},
    {0xFE02, "cgt",          ILOperand::None,   ILFlow::Next},
    {0xFE03, "cgt.un",       ILOperand::None,   ILFlow::Next},
    {0xFE04, "clt",          ILOperand::None,   ILFlow::Next},
    {0xFE05, "clt.un",       ILOperand::None,   ILFlow::Next},
    {0xFE06, "ldftn",        ILOperand::Method, ILFlow::Next},
    {0xFE07, "ldvirtftn",    ILOperand::Method, ILFlow::Next},
    {0xFE09, "ldarg",        ILOperand::Var,    ILFlow::Next},
    {0xFE0A, "ldarga",       ILOperand::Var,    ILFlow::Next},
    {0xFE0B, "starg",        ILOperand::Var,    ILFlow::Next},
    {0xFE0C, "ldloc",        ILOperand::Var,    ILFlow::Next},
    {0xFE0D, "ldloca",       ILOperand::Var,    ILFlow::Next},
    {0xFE0E, "stloc",        ILOperand::Var,    ILFlow::Next},
    {0xFE0F, "localloc",     ILOperand::None,   ILFlow::Next},
    {0xFE11, "endfilter",    ILOperand::None,   ILFlow::Return},
    {0xFE12, "unaligned.",   ILOperand::ShortI, ILFlow::Meta},
    {0xFE13, "volatile.",    ILOperand::None,   ILFlow::Meta},
    {0xFE14, "tail.",        ILOperand::None,   ILFlow::Meta},
    {0xFE15, "initobj",      ILOperand::Type,   ILFlow::Next},
    {0xFE16, "constrained.", ILOperand::Type,   ILFlow::Meta},
    {0xFE17, "cpblk",        ILOperand::None,   ILFlow::Next},
    {0xFE18, "initblk",      ILOperand::None,   ILFlow::Next},
    {0xFE19, "no.",          ILOperand::ShortI, ILFlow::Meta},
    {0xFE1A, "rethrow",      ILOperand::None,   ILFlow::Throw},
    {0xFE1C, "sizeof",       ILOperand::Type,   ILFlow::Next},
    {0xFE1D, "refanytype",   ILOperand::None,   ILFlow::Next},
    {0xFE1E, "readonly.",    ILOperand::None,   ILFlow::Meta},
};

// Look up an opcode by its full value (single byte, or 0xFE00|second for the
// two-byte space). Returns nullptr for reserved/unused encodings.
inline const ILOpcode* il_lookup(u16 value) {
    if (value < 0x100) {
        for (auto& op : kILOpcodes1)
            if (op.value == value) return &op;
    } else {
        for (auto& op : kILOpcodes2)
            if (op.value == value) return &op;
    }
    return nullptr;
}

}
