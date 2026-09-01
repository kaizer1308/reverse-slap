// src/core/memory/pointer_scan.cpp
// backward pointer scan, sweep the aligned qwords then walk the sorted edges

#include "core/memory/pointer_scan.hpp"

#include "core/infra/limits.hpp"
#include "core/memory/read_util.hpp"

#include <algorithm>
#include <cstring>

namespace slop::core::memory {

namespace {

struct edge_t {
    uint64_t  value;   // qword read from the region set
    uintptr_t holder;  // address of that qword
};

struct node_t {
    uintptr_t addr      = 0;   // holder address
    int64_t   parent    = -1;  // index into nodes of the destination
    int64_t   offset    = 0;   // *addr + offset == nodes[parent].addr (or target)
};

bool in_module_backed(uintptr_t addr,
                      const std::vector<scan_region_t>& regions) noexcept {
    constexpr uint32_t kMemImage = 0x1000000;
    for (const auto& reg : regions) {
        if (!(reg.type & kMemImage)) continue;
        if (addr >= reg.base && addr < reg.base + reg.size) return true;
    }
    return false;
}

} // namespace

std::vector<pointer_chain_result_t>
pointer_scan(reader_t& r,
             const std::vector<scan_region_t>& regions,
             const pointer_scan_options_t& opt,
             const infra::cancel_token_t& tok,
             pointer_scan_stats_t* stats) {

    std::vector<pointer_chain_result_t> results;
    pointer_scan_stats_t local{};
    pointer_scan_stats_t& st = stats ? *stats : local;

    const uint32_t depth = std::min<uint32_t>(
        opt.depth ? opt.depth : 1,
        static_cast<uint32_t>(infra::limits::max_pointer_depth));
    const int64_t min_off = opt.min_offset;
    const int64_t max_off = std::max<int64_t>(opt.max_offset, opt.min_offset);
    const size_t align = std::max<size_t>(opt.alignment ? opt.alignment : 1, 1);

    // Merge the region set into aligned spans
    struct span_t { uintptr_t begin; uintptr_t end; };
    std::vector<span_t> spans;
    for (const auto& reg : regions) {
        if (reg.size < 8) continue;
        const uintptr_t b = (reg.base + align - 1) / align * align;
        const uintptr_t e = reg.base + reg.size;
        if (e <= b + 8) continue;
        spans.push_back({b, e});
    }

    std::vector<node_t> nodes;

    // Level-0 frontier is the pseudo-node standing in for the target
    nodes.push_back({opt.target, -1, 0});
    std::vector<size_t> frontier{0};

    for (uint32_t level = 0; level < depth && !frontier.empty(); ++level) {
        if (tok.cancelled()) { st.cancelled = true; break; }

        // One sweep over all spans: collect every aligned non-null qword
        std::vector<edge_t> edges;
        constexpr size_t kChunk = 1u << 20;

        auto sink = [&](uintptr_t run_addr, const uint8_t* data, size_t len) {
            uintptr_t p = run_addr; // runs may start unaligned to `align`
            const uintptr_t run_end = run_addr + len;
            // Align the starting pointer within the run
            p = (p + align - 1) / align * align;
            while (p + 8 <= run_end) {
                uint64_t v;
                std::memcpy(&v, data + (p - run_addr), 8);
                if (v != 0) { // null pointers are noise
                    edges.push_back({v, p});
                    ++st.edges_explored;
                    if (st.edges_explored > infra::limits::max_pointer_edges) {
                        st.truncated = true;
                        return;
                    }
                }
                p += align;
            }
        };

        for (const auto& s : spans) {
            if (st.truncated || tok.cancelled()) break;
            uintptr_t cursor = s.begin;
            while (cursor < s.end && !st.truncated) {
                if (tok.cancelled()) { st.cancelled = true; break; }
                const size_t want = static_cast<size_t>(
                    std::min<uint64_t>(kChunk, s.end - cursor));
                detail::resilient_read(r, cursor, want, 8, tok, sink);
                cursor += want;
            }
        }

        if (edges.empty()) break;
        std::sort(edges.begin(), edges.end(),
                  [](const edge_t& a, const edge_t& b) { return a.value < b.value; });

        // Expand every frontier address against the sorted edge list
        std::vector<size_t> next_frontier;
        bool frontier_full = false;

        for (const size_t fidx : frontier) {
            if (tok.cancelled()) { st.cancelled = true; break; }
            if (frontier_full) break;

            const uintptr_t dest = nodes[fidx].addr;

            // Accept V where diff = dest - V in [min_off, max_off]
            // => V in [dest - max_off, dest - min_off] (unsigned window)
            if (min_off > 0 && static_cast<uint64_t>(min_off) > dest) continue;
            const uint64_t lo = (max_off > 0 && static_cast<uint64_t>(max_off) > dest)
                ? 0u
                : dest - static_cast<uint64_t>(max_off);
            const uint64_t hi = dest - static_cast<uint64_t>(min_off); // wraps on negative
            if (hi < lo) continue;

            auto first = std::lower_bound(edges.begin(), edges.end(), lo,
                [](const edge_t& e, uint64_t v) { return e.value < v; });
            auto last = std::upper_bound(edges.begin(), edges.end(), hi,
                [](uint64_t v, const edge_t& e) { return v < e.value; });

            for (auto it = first; it != last; ++it) {
                const int64_t off = static_cast<int64_t>(dest - it->value);
                nodes.push_back({it->holder, static_cast<int64_t>(fidx), off});
                next_frontier.push_back(nodes.size() - 1);
                if (next_frontier.size() >= opt.frontier_cap) {
                    st.truncated = true;
                    frontier_full = true;
                    break;
                }
            }
        }

        frontier = std::move(next_frontier);
        if (st.truncated && frontier.empty()) break;
    }

    // build chains from every node, the parent walk yields root first
    for (size_t i = 1; i < nodes.size(); ++i) {
        if (results.size() >= infra::limits::max_pointer_chains) {
            st.truncated = true;
            break;
        }
        if (opt.only_module_backed) {
            // Root (deepest holder) must live in a module-backed region
            int64_t n = static_cast<int64_t>(i);
            while (nodes[static_cast<size_t>(n)].parent > 0)
                n = nodes[static_cast<size_t>(n)].parent;
            if (!in_module_backed(nodes[static_cast<size_t>(n)].addr, regions))
                continue;
        }
        pointer_chain_result_t chain;
        for (int64_t n = static_cast<int64_t>(i); n > 0;
             n = nodes[static_cast<size_t>(n)].parent) {
            const node_t& nd = nodes[static_cast<size_t>(n)];
            chain.addresses.push_back(nd.addr);
            chain.offsets.push_back(nd.offset);
        }
        results.push_back(std::move(chain));
    }

    return results;
}

} // namespace slop::core::memory
