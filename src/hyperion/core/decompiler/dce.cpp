#include "dce.h"
#include "core/decompiler/def_use.h"
#include <unordered_set>
#include <algorithm>

namespace hype {

bool DCE::is_callee_saved(int id) const {
    return id == 3 || id == 5 || id == 6 || id == 7 ||
           id == 12 || id == 13 || id == 14 || id == 15;
}

bool DCE::is_dead_flag(const PcodeInsn& op, const PcodeFunc& func) {
    if (!op.output.valid()) return false;
    if (!is_flag_reg(op.output.id)) return false;
    for (auto& blk : func.blocks)
        for (auto& o : blk.ops) {
            if (o.op == PcodeOp::NOP) continue;
            for (auto& in : o.inputs)
                if (in.kind == op.output.kind && in.id == op.output.id && in.offset == op.output.offset)
                    return false;
        }
    return true;
}

bool DCE::is_dead_stack_op(const PcodeInsn& op, const PcodeFunc&) {
    if (op.op == PcodeOp::STORE && !op.inputs.empty() && op.inputs[0].is_reg() && op.inputs[0].id == 4)
        return true;
    return false;
}

void DCE::run(PcodeFunc& func) {
    [[maybe_unused]] static constexpr int RSP_ID = 4;
    [[maybe_unused]] static constexpr int RBP_ID = 5;

    // Pass 1: eliminate ONLY redundant prologue/epilogue register saves/restores
    // and flag computations not used by branches. One use-count pass replaces
    // the former whole-function rescan per candidate.
    {
        const UseCountMap uses = count_uses(func);
        for (auto& blk : func.blocks) {
            for (auto& op : blk.ops) {
                if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL || op.op == PcodeOp::INTRINSIC ||
                    op.op == PcodeOp::RETURN || op.op == PcodeOp::CBRANCH ||
                    op.op == PcodeOp::BRANCH) continue;

                if (op.output.valid() && is_flag_reg(op.output.id)) {
                    if (!has_use(uses, op.output)) {
                        op.op = PcodeOp::NOP;
                        continue;
                    }
                }

                if (op.op == PcodeOp::LOAD && op.output.valid() && op.output.is_reg()) {
                    if (is_callee_saved(op.output.id)) {
                        if (!has_use(uses, op.output)) {
                            op.op = PcodeOp::NOP;
                            continue;
                        }
                    }
                }
            }
        }
    }

    // Pass 2: iterative dead code elimination. Use counts are rebuilt per
    // pass (bounded, 6) instead of rescanning the function per candidate.
    for (int pass = 0; pass < 6; ++pass) {
        bool changed = false;
        const UseCountMap uses = count_uses(func);
        for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
            auto& blk = func.blocks[bi];
            for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
                auto& op = blk.ops[oi];
                if (op.op == PcodeOp::NOP || op.op == PcodeOp::CALL || op.op == PcodeOp::INTRINSIC ||
                    op.op == PcodeOp::RETURN || op.op == PcodeOp::CBRANCH ||
                    op.op == PcodeOp::BRANCH || op.op == PcodeOp::STORE) continue;

                if (!op.output.valid()) continue;

                // keep RAX (return value)
                if (op.output.is_reg() && op.output.id == 0) continue;

                if (!has_use(uses, op.output)) {
                    op.op = PcodeOp::NOP;
                    changed = true;
                }
            }
        }
        if (!changed) break;
    }

    // Remove NOP ops
    for (auto& blk : func.blocks)
        std::erase_if(blk.ops, [](const PcodeInsn& op) { return op.op == PcodeOp::NOP; });
}

}
