#pragma once
#include "core/decompiler/ir.h"
#include <unordered_map>

namespace hype {

// Full-identity key for SSA varnodes: two varnodes are the same value only
// when kind, id, SSA version (offset) and width all match.
struct VnKey {
    VarnodeKind kind;
    int         id;
    u64         offset;
    int         size;
    bool operator==(const VnKey& o) const {
        return kind == o.kind && id == o.id && offset == o.offset && size == o.size;
    }
};

struct VnKeyHash {
    size_t operator()(const VnKey& k) const {
        size_t h = std::hash<int>()(k.id);
        h ^= std::hash<u64>()(k.offset) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<int>()(static_cast<int>(k.kind)) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        h ^= std::hash<int>()(k.size) + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
        return h;
    }
};

using UseCountMap = std::unordered_map<VnKey, int, VnKeyHash>;

// Count uses of every varnode across all inputs. `skip` excludes one op.
inline UseCountMap count_uses(const PcodeFunc& func, int skip_blk = -1, int skip_idx = -1) {
    UseCountMap uses;
    for (int bi = 0; bi < (int)func.blocks.size(); ++bi) {
        const auto& blk = func.blocks[bi];
        for (int oi = 0; oi < (int)blk.ops.size(); ++oi) {
            if (bi == skip_blk && oi == skip_idx) continue;
            const auto& op = blk.ops[oi];
            if (op.op == PcodeOp::NOP) continue;
            for (const auto& in : op.inputs)
                uses[{in.kind, in.id, in.offset, in.size}]++;
        }
    }
    return uses;
}

inline bool has_use(const UseCountMap& uses, const Varnode& vn) {
    auto it = uses.find({vn.kind, vn.id, vn.offset, vn.size});
    return it != uses.end() && it->second > 0;
}

}
