#pragma once

// src/ui/views_core.hpp
// Phase-2 workspace views: targets, memory hex editor, scanner

#include <cstdint>

namespace slop::ui {

namespace targets_view {
void Draw();
}

namespace memory_view {
void Draw();
}

namespace scanner_view {
void Draw();
// Per-frame tick, applies watchlist freeze writes. Call from main loop
void Tick();
} // namespace scanner_view

namespace disasm_view {
void Draw();
// Currently selected function entry VA (0 = none), shared with the
// pseudocode view so F5/decompile follow the disasm selection
uint64_t SelectedFunction();
void     SelectFunction(uint64_t va);
// Jump to an instruction VA: selects its containing function + the VA
void     SelectInstruction(uint64_t va);
}

namespace pseudocode_view {
void Draw();
}

namespace strings_view {
void Draw();
}

namespace pe_view {
void Draw();
}

namespace debugger_view {
void Draw();
}

namespace unpacker_view {
void Draw();
}

} // namespace slop::ui
