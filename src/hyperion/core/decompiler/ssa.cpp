#include "ssa.h"
#include <algorithm>
#include <queue>

namespace hype {

int SSABuilder::var_key(const Varnode& vn) const {
    if (vn.is_reg()) return vn.id;
    if (vn.is_temp()) return 1000 + vn.id;
    if (vn.is_stack()) {
        // Distinct stack offsets are distinct variables, not versions of one.
        const u64 slot = (static_cast<u64>(static_cast<u32>(vn.id)) << 32) ^
                         (vn.offset & 0xFFFFFFFFull);
        auto it = const_cast<SSABuilder*>(this)->stack_slots_.find(slot);
        if (it != const_cast<SSABuilder*>(this)->stack_slots_.end()) return it->second;
        const int key = 2000 + static_cast<int>(const_cast<SSABuilder*>(this)->stack_slots_.size());
        const_cast<SSABuilder*>(this)->stack_slots_[slot] = key;
        const_cast<SSABuilder*>(this)->stack_nodes_[key] = vn;
        return key;
    }
    return -1;
}

int SSABuilder::new_version(const Varnode& vn) {
    (void)vn;
    return ++ssa_counter_;
}

void SSABuilder::compute_reverse_postorder() {
    entry_block_ = 0;
    for (int i = 0; i < num_blocks_; ++i) {
        if (func_->blocks[i].addr == func_->entry) {
            entry_block_ = i;
            break;
        }
    }

    std::vector<bool> visited(num_blocks_, false);
    std::vector<int> postorder;
    const auto visit = [&](const auto& self, int block) -> void {
        if (block < 0 || block >= num_blocks_ || visited[block]) return;
        visited[block] = true;
        for (int successor : func_->blocks[block].succs)
            self(self, successor);
        postorder.push_back(block);
    };
    visit(visit, entry_block_);
    std::reverse(postorder.begin(), postorder.end());
    rpo_ = std::move(postorder);
    rpo_index_.assign(num_blocks_, -1);
    for (int i = 0; i < static_cast<int>(rpo_.size()); ++i)
        rpo_index_[rpo_[i]] = i;
}

int SSABuilder::intersect(int first, int second) const {
    while (first != second) {
        while (rpo_index_[first] > rpo_index_[second]) first = idom_[first];
        while (rpo_index_[second] > rpo_index_[first]) second = idom_[second];
    }
    return first;
}

void SSABuilder::compute_dominators() {
    idom_.assign(num_blocks_, -1);
    idom_[entry_block_] = entry_block_;

    bool changed = true;
    while (changed) {
        changed = false;
        for (size_t order = 1; order < rpo_.size(); ++order) {
            const int block = rpo_[order];
            const auto& preds = func_->blocks[block].preds;
            int new_idom = -1;
            for (int pred : preds) {
                if (pred < 0 || pred >= num_blocks_ || idom_[pred] < 0) continue;
                new_idom = new_idom < 0 ? pred : intersect(pred, new_idom);
            }
            if (new_idom >= 0 && idom_[block] != new_idom) {
                idom_[block] = new_idom;
                changed = true;
            }
        }
    }

    dom_children_.assign(num_blocks_, {});
    for (int block : rpo_)
        if (block != entry_block_ && idom_[block] >= 0)
            dom_children_[idom_[block]].push_back(block);
}

void SSABuilder::compute_dom_frontiers() {
    dom_frontier_.assign(num_blocks_, {});
    for (int b = 0; b < num_blocks_; ++b) {
        auto& preds = func_->blocks[b].preds;
        if (preds.size() < 2) continue;
        for (int p : preds) {
            int runner = p;
            while (runner >= 0 && runner != idom_[b]) {
                dom_frontier_[runner].push_back(b);
                runner = idom_[runner];
            }
        }
    }
    for (auto& df : dom_frontier_) {
        std::sort(df.begin(), df.end());
        df.erase(std::unique(df.begin(), df.end()), df.end());
    }
}

void SSABuilder::insert_phis() {
    std::unordered_map<int, std::vector<int>> def_blocks;
    for (int b = 0; b < num_blocks_; ++b) {
        for (auto& op : func_->blocks[b].ops) {
            int k = var_key(op.output);
            if (k >= 0) {
                def_blocks[k].push_back(b);
                all_vars_.insert(k);
            }
        }
    }

    for (auto& [v, defs] : def_blocks) {
        std::queue<int> worklist;
        std::unordered_set<int> has_phi;
        std::unordered_set<int> processed;

        for (int d : defs) worklist.push(d);

        while (!worklist.empty()) {
            int d = worklist.front(); worklist.pop();
            if (processed.count(d)) continue;
            processed.insert(d);

            for (int f : dom_frontier_[d]) {
                if (has_phi.count(f)) continue;
                has_phi.insert(f);

                int num_preds = (int)func_->blocks[f].preds.size();
                PcodeInsn phi;
                phi.op = PcodeOp::COPY;
                if (v >= 2000) {
                    auto nit = stack_nodes_.find(v);
                    phi.output = nit != stack_nodes_.end() ? nit->second : Varnode{};
                } else {
                    phi.output.kind = (v < 1000) ? VarnodeKind::Reg : VarnodeKind::Temp;
                    phi.output.id = (v < 1000) ? v : v - 1000;
                    phi.output.size = 8;
                }
                phi.seq = -1; // mark as phi
                for (int i = 0; i < num_preds; ++i)
                    phi.inputs.push_back(phi.output);
                func_->blocks[f].ops.insert(func_->blocks[f].ops.begin(), std::move(phi));

                worklist.push(f);
            }
        }
    }
}

void SSABuilder::rename() {
    std::unordered_map<int, std::vector<int>> stacks;
    for (int v : all_vars_)
        stacks[v].push_back(0);
    rename_block(entry_block_, stacks);
}

void SSABuilder::rename_block(int blk_idx, std::unordered_map<int, std::vector<int>>& stacks) {
    if (blk_idx < 0 || blk_idx >= num_blocks_) return;

    auto& blk = func_->blocks[blk_idx];
    std::unordered_map<int, int> pushed;

    for (auto& op : blk.ops) {
        // rename inputs (skip phi inputs handled separately)
        if (op.seq != -1) {
            for (auto& in : op.inputs) {
                int k = var_key(in);
                if (k >= 0 && stacks.count(k) && !stacks[k].empty())
                    in.offset = stacks[k].back();
            }
        }

        // rename output
        int k = var_key(op.output);
        if (k >= 0) {
            int ver = new_version(op.output);
            stacks[k].push_back(ver);
            pushed[k]++;
            op.output.offset = ver;
        }
    }

    // update phi inputs in successors
    for (int s : blk.succs) {
        if (s < 0 || s >= num_blocks_) continue;
        auto& succ = func_->blocks[s];
        int pred_idx = -1;
        for (int i = 0; i < (int)succ.preds.size(); ++i)
            if (succ.preds[i] == blk_idx) { pred_idx = i; break; }
        if (pred_idx < 0) continue;

        for (auto& op : succ.ops) {
            if (op.seq != -1) break; // phis are at the front
            if (pred_idx < (int)op.inputs.size()) {
                int k = var_key(op.inputs[pred_idx]);
                if (k >= 0 && stacks.count(k) && !stacks[k].empty())
                    op.inputs[pred_idx].offset = stacks[k].back();
            }
        }
    }

    for (int c : dom_children_[blk_idx])
        rename_block(c, stacks);

    for (auto& [k, cnt] : pushed)
        for (int i = 0; i < cnt; ++i)
            stacks[k].pop_back();
}

void SSABuilder::build(PcodeFunc& func) {
    func_ = &func;
    num_blocks_ = (int)func.blocks.size();
    if (num_blocks_ == 0) return;

    ssa_counter_ = 0;
    all_vars_.clear();
    stack_slots_.clear();
    stack_nodes_.clear();
    rpo_.clear();
    rpo_index_.clear();
    idom_.clear();
    dom_frontier_.clear();
    dom_children_.clear();

    compute_reverse_postorder();
    compute_dominators();
    compute_dom_frontiers();
    insert_phis();
    rename();

    func.next_ssa = ssa_counter_;
}

}
