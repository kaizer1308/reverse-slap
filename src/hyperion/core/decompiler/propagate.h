#pragma once
#include "core/decompiler/ir.h"

namespace hype {

class Propagate {
public:
    void run(PcodeFunc& func);

private:
    void eliminate_identity(PcodeFunc& func);
    void copy_propagation(PcodeFunc& func);
    void constant_fold(PcodeFunc& func);
    void fold_flags(PcodeFunc& func);
    void fold_arg_setup(PcodeFunc& func);
    void dead_copy_elim(PcodeFunc& func);
    void replace_uses(PcodeFunc& func, const Varnode& old_vn, const Varnode& new_vn, int def_blk, int def_idx);
};

}
