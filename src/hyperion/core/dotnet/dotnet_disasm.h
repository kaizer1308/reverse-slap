#pragma once
#include "core/types.h"
#include "core/loader/pe_loader.h"
#include "core/analysis/analysis_db.h"
#include "cil_opcodes.h"
#include "dotnet_metadata.h"
#include <string>
#include <vector>

// Managed-code (.NET / CLI) disassembler. Detects a CLI image from its PE COM
// descriptor directory, reads the ECMA-335 metadata through MetadataReader, and
// decodes every MethodDef body's CIL into a resolved, ILDASM/dnSpy-style
// listing. Results are also folded into the native AnalysisDB (methods as
// Functions, IL as Insns) so the existing UI / MCP surface shows them with no
// downstream changes.

namespace hype {

// One decoded CIL instruction.
struct DnInsn {
    u32         offset;       // byte offset from the method's IL start
    va_t        addr;         // absolute VA of the opcode
    u16         opcode;       // 0x00..0xE0 or 0xFE00..0xFE1E
    u8          size;         // total encoded length (opcode + operand)
    ILFlow      flow;
    std::string mnemonic;
    std::string operand;      // fully resolved operand text ("" if none)
    va_t        target = 0;   // branch target VA (branches only), else 0
    std::vector<va_t> switch_targets;
};

struct DnLocal {
    u16         index;
    std::string type;
};

struct DnParam {
    std::string type;
    std::string name;
};

struct DnExClause {
    std::string kind;         // "catch" / "finally" / "filter" / "fault"
    u32 try_offset, try_length;
    u32 handler_offset, handler_length;
    std::string catch_type;   // for "catch"
};

struct DnMethod {
    u32         token = 0;    // 0x06xxxxxx MethodDef token
    u32         rva = 0;      // method body RVA (0 = abstract/pinvoke, no body)
    va_t        entry = 0;    // VA of first IL byte
    u16         flags = 0;
    u16         impl_flags = 0;
    u16         max_stack = 0;
    u32         code_size = 0;
    bool        is_static = false;
    std::string name;         // simple name
    std::string decl_type;    // declaring type full name
    std::string full_name;    // Type::Name
    std::string ret_type;
    std::string signature;    // rendered C#-style signature line
    std::vector<DnParam>   params;
    std::vector<DnLocal>   locals;
    std::vector<DnExClause> handlers;
    std::vector<DnInsn>    il;
};

struct DnField {
    u32         token = 0;
    std::string name;
    std::string type;
    bool        is_static = false;
};

struct DnType {
    u32         token = 0;    // 0x02xxxxxx TypeDef token
    std::string ns;
    std::string name;
    std::string full_name;
    std::string base_type;
    u32         flags = 0;
    std::vector<u32> method_tokens;
    std::vector<u32> field_tokens;
};

struct DnImage {
    bool        valid = false;
    std::string runtime_version;     // metadata root version string
    std::string assembly_name;
    u16         major_runtime = 0;
    u16         minor_runtime = 0;
    u32         cor_flags = 0;        // COR20 header flags
    u32         entry_point_token = 0;
    bool        il_only = false;      // COMIMAGE_FLAGS_ILONLY

    std::vector<DnType>   types;
    std::vector<DnMethod> methods;
};

class DotNetDisassembler {
public:
    // True if the PE carries a valid CLI header (COM descriptor directory 14).
    // Cheap: parses only the optional header + COR20 header.
    bool detect(const PEImage& img) const;

    // Full parse: metadata tables, types, methods, signatures and IL bodies.
    bool load(const PEImage& img);

    bool valid() const { return image_.valid; }
    const DnImage& image() const { return image_; }

    // Fold methods/IL into the native analysis DB so existing consumers see
    // them (one Function per method with a single block of IL Insns, plus names
    // and a signature comment). Idempotent; safe to call once after load().
    void populate_db(AnalysisDB& db) const;

    // Render an ILDASM-style textual listing for one method or the whole image.
    std::string render_method(const DnMethod& m) const;
    std::string render_all() const;

private:
    // COR20 / IMAGE_COR20_HEADER, read from directory 14.
    struct Cor20 {
        u32 cb = 0;
        u16 major = 0, minor = 0;
        u32 meta_rva = 0, meta_size = 0;
        u32 flags = 0;
        u32 entry_point = 0;
    };
    bool read_cor20(const PEImage& img, Cor20& out) const;

    // Decode one method body (header + IL + EH) starting at the given RVA.
    void decode_body(const PEImage& img, DnMethod& m) const;
    void decode_il(const u8* code, u32 size, va_t il_base, DnMethod& m) const;

    DnImage        image_;
    MetadataReader md_;
};

}
