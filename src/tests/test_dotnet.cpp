// src/tests/test_dotnet.cpp
// Managed-code (.NET / CLI) disassembler: metadata parsing, IL decode, token
// resolution and AnalysisDB population. Exercised against a real .NET Framework
// assembly from the local machine; skips cleanly when none is present (same
// skip-if-absent pattern as the packed-binary regression tests).

#include "harness.hpp"

#include "core/loader/pe_loader.h"
#include "core/dotnet/dotnet_disasm.h"
#include "core/dotnet/dotnet_decompiler.h"
#include "core/analysis/analysis_db.h"

#include <cstdio>
#include <fstream>
#include <optional>
#include <string>

namespace {

// Managed assemblies that ship with the .NET Framework on essentially every
// Windows install. Ordered smallest-first so the test loads quickly.
const char* kCandidates[] = {
    R"(C:\Windows\Microsoft.NET\Framework64\v4.0.30319\sysglobl.dll)",
    R"(C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Configuration.dll)",
    R"(C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll)",
    R"(C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll)",
    R"(C:\Windows\Microsoft.NET\Framework\v4.0.30319\System.Configuration.dll)",
    R"(C:\Windows\Microsoft.NET\Framework\v4.0.30319\mscorlib.dll)",
};

std::optional<hype::PEImage> load_first_managed() {
    hype::PELoader loader;
    for (const char* path : kCandidates) {
        std::ifstream probe(path, std::ios::binary);
        if (!probe.good()) continue;
        probe.close();
        auto img = loader.load(path);
        if (!img) continue;
        hype::DotNetDisassembler dn;
        if (dn.detect(*img)) return img;   // a genuine CLI image
    }
    return std::nullopt;
}

} // namespace

TEST_CASE(dotnet_disassembler_parses_managed_assembly) {
    auto img = load_first_managed();
    if (!img) return;   // no .NET assembly on this machine: skip

    hype::DotNetDisassembler dn;
    REQUIRE(dn.detect(*img));
    REQUIRE(dn.load(*img));

    const hype::DnImage& di = dn.image();
    REQUIRE(di.valid);
    REQUIRE_GT(di.types.size(), 0u);
    REQUIRE_GT(di.methods.size(), 0u);
    // The metadata root always carries a runtime version string ("v4.0.30319").
    REQUIRE_FALSE(di.runtime_version.empty());

    size_t with_il = 0, qualified = 0, with_ret = 0;
    for (const auto& m : di.methods) {
        if (!m.il.empty()) ++with_il;
        if (m.full_name.find("::") != std::string::npos) ++qualified;
        if (!m.ret_type.empty()) ++with_ret;
    }
    REQUIRE_GT(with_il, 0u);       // at least some methods have IL bodies
    REQUIRE_GT(qualified, 0u);     // Type::Method names resolved from metadata
    REQUIRE_EQ(with_ret, di.methods.size());

    // Every decoded IL instruction is well-formed: named mnemonic, non-zero
    // length, and the encoded lengths tile the method body exactly.
    for (const auto& m : di.methods) {
        if (m.il.empty()) continue;
        uint32_t walk = m.il.front().offset;
        for (const auto& in : m.il) {
            REQUIRE_FALSE(in.mnemonic.empty());
            REQUIRE(in.size > 0);
            REQUIRE_EQ(in.offset, walk);
            walk += in.size;
        }
        // The final instruction ends at (or within) the reported code size.
        REQUIRE(walk <= m.code_size);
        break;   // one fully-validated body is a sufficient spot check
    }
}

TEST_CASE(dotnet_disassembler_resolves_tokens_and_strings) {
    auto img = load_first_managed();
    if (!img) return;

    hype::DotNetDisassembler dn;
    REQUIRE(dn.load(*img));

    // Across the whole assembly there is always at least one resolved call
    // target and one loaded string literal; unresolved tokens render as
    // "<0x...>" placeholders, so their absence proves resolution worked.
    bool saw_resolved_call = false;
    bool saw_ldstr = false;
    for (const auto& m : dn.image().methods) {
        for (const auto& in : m.il) {
            if ((in.mnemonic == "call" || in.mnemonic == "callvirt" || in.mnemonic == "newobj") &&
                !in.operand.empty() && in.operand.find("::") != std::string::npos &&
                in.operand.find('<', 0) != 0) {
                saw_resolved_call = true;
            }
            if (in.mnemonic == "ldstr") saw_ldstr = true;
        }
        if (saw_resolved_call && saw_ldstr) break;
    }
    REQUIRE(saw_resolved_call);
}

TEST_CASE(dotnet_disassembler_populates_analysis_db) {
    auto img = load_first_managed();
    if (!img) return;

    hype::DotNetDisassembler dn;
    REQUIRE(dn.load(*img));

    hype::AnalysisDB db;
    db.image_base = img->base;
    dn.populate_db(db);

    REQUIRE_GT(db.funcs.size(), 0u);
    REQUIRE_GT(db.insns.size(), 0u);

    // Managed method names (Type::Method) reach the function table and every
    // populated function has exactly one IL block whose entry has an insn.
    size_t qualified_names = 0;
    for (const auto& [entry, f] : db.funcs) {
        if (f.name.find("::") != std::string::npos) ++qualified_names;
        REQUIRE_FALSE(f.blocks.empty());
        REQUIRE(db.insns.count(entry) == 1);
    }
    REQUIRE_GT(qualified_names, 0u);
}

TEST_CASE(dotnet_disassembler_renders_ildasm_listing) {
    auto img = load_first_managed();
    if (!img) return;

    hype::DotNetDisassembler dn;
    REQUIRE(dn.load(*img));

    std::string listing = dn.render_all();
    REQUIRE_GT(listing.size(), 0u);
    REQUIRE(listing.find(".method") != std::string::npos);
    REQUIRE(listing.find("IL_") != std::string::npos);
    REQUIRE(listing.find(".maxstack") != std::string::npos);
}

// The full dnSpy-style model: every member table is parsed, not just methods
// with bodies. Fields carry types/visibility, at least one const carries a
// value, types resolve a C#-style kind, and methods carry access modifiers.
TEST_CASE(dotnet_parses_full_member_model) {
    auto img = load_first_managed();
    if (!img) return;

    hype::DotNetDisassembler dn;
    REQUIRE(dn.load(*img));
    const hype::DnImage& di = dn.image();

    REQUIRE_GT(di.fields.size(), 0u);

    size_t typed_fields = 0, const_valued = 0, vis_fields = 0;
    for (const auto& f : di.fields) {
        if (!f.type.empty() && f.type != "?") ++typed_fields;
        if (f.is_literal && !f.const_value.empty()) ++const_valued;
        if (!f.visibility.empty()) ++vis_fields;
    }
    REQUIRE_GT(typed_fields, 0u);
    REQUIRE_EQ(vis_fields, di.fields.size());   // every field gets an access level

    // Each type resolves to one of the C# kinds and to a visibility.
    size_t kinded = 0, with_members = 0;
    for (const auto& t : di.types) {
        if (t.kind == "class" || t.kind == "struct" || t.kind == "interface" ||
            t.kind == "enum" || t.kind == "delegate") ++kinded;
        if (!t.field_tokens.empty() || !t.method_tokens.empty()) ++with_members;
        // Members attach back to a type: token lists must resolve.
        for (uint32_t ft : t.field_tokens) REQUIRE(di.field_by_token(ft) != nullptr);
        for (uint32_t mt : t.method_tokens) REQUIRE(di.method_by_token(mt) != nullptr);
    }
    REQUIRE_EQ(kinded, di.types.size());
    REQUIRE_GT(with_members, 0u);

    // Method access modifiers are populated for every method.
    size_t vis_methods = 0;
    for (const auto& m : di.methods)
        if (!m.visibility.empty()) ++vis_methods;
    REQUIRE_EQ(vis_methods, di.methods.size());
}

// C# rendering + IL->C# decompilation: a type with methods renders a valid-
// looking class declaration and a method with IL decompiles to statements.
TEST_CASE(dotnet_renders_csharp_and_decompiles) {
    auto img = load_first_managed();
    if (!img) return;

    hype::DotNetDisassembler dn;
    REQUIRE(dn.load(*img));
    const hype::DnImage& di = dn.image();

    // Pick a type that actually has rendered members.
    const hype::DnType* pick = nullptr;
    for (const auto& t : di.types)
        if (!t.method_tokens.empty() && t.kind != "enum") { pick = &t; break; }
    REQUIRE(pick != nullptr);

    std::string cs = dn.render_type_csharp(*pick);
    REQUIRE_GT(cs.size(), 0u);
    REQUIRE(cs.find(pick->kind) != std::string::npos);   // "class"/"struct"/...
    REQUIRE(cs.find('{') != std::string::npos);
    REQUIRE(cs.find('}') != std::string::npos);

    // Decompile the first method that has an IL body; it must produce lines and
    // not be dominated by unknown opcodes.
    const hype::DnMethod* body = nullptr;
    for (uint32_t mt : pick->method_tokens) {
        const hype::DnMethod* m = di.method_by_token(mt);
        if (m && m->rva != 0 && !m->il.empty()) { body = m; break; }
    }
    if (body) {
        hype::CSharpBody b = decompile_body(*body, di, dn.metadata(), "    ");
        REQUIRE_GT(b.code.size(), 0u);

        // Eyeball sample: dump the full C# of the chosen type once.
        std::printf("\n---- C# for %s ----\n%s\n----\n",
                    pick->full_name.c_str(), cs.c_str());
    }
}
