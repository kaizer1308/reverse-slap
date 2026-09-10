#pragma once
#include "core/types.h"
#include "dotnet_disasm.h"
#include "dotnet_metadata.h"
#include <string>

// Best-effort IL -> C# body reconstructor. This is NOT a full ILSpy-grade
// decompiler: it simulates the CIL evaluation stack to rebuild C# expressions
// and statements (assignments, calls, property access, object creation, array
// indexing, returns, throws), and lowers control flow to labels + goto. Simple
// methods come out reading like real C#; heavy branching stays correct but
// goto-heavy. The IL view remains the ground truth alongside it.
//
// It never throws and never emits a hard crash on malformed IL: a stack
// underflow yields a "?" placeholder and bumps `unknowns` so callers can decide
// whether to trust the result or fall back to the IL listing.

namespace hype {

struct CSharpBody {
    std::string code;        // statement lines, each already prefixed with `indent`
    bool        structured = false;  // true when at least some statements were rebuilt
    u32         unknowns = 0;         // opcodes the reconstructor could not model
};

// Reconstruct one method body. `indent` prefixes every emitted line (so the
// caller controls nesting). `md`/`img` resolve call signatures and token names.
CSharpBody decompile_body(const DnMethod& m, const DnImage& img,
                          const MetadataReader& md, const std::string& indent);

}
