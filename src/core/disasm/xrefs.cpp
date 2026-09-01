// src/core/disasm/xrefs.cpp

#include "core/disasm/xrefs.hpp"

#include <cmath>

namespace slop::core::disasm {

const std::vector<xref_t> xref_index_t::kEmpty{};

namespace {

// skip high entropy sections, compressed blobs only produce garbage refs
// and can eat the cap before real code is indexed
double section_entropy(const uint8_t* data, size_t len) {
    if (!data || len == 0) return 0.0;
    // Sample up to 64 KiB from the section for speed
    const size_t sample = std::min<size_t>(len, 65536);
    uint32_t hist[256] = {};
    for (size_t i = 0; i < sample; ++i) ++hist[data[i]];
    double e = 0.0;
    const double n = static_cast<double>(sample);
    for (uint32_t c : hist) {
        if (!c) continue;
        const double p = static_cast<double>(c) / n;
        e -= p * std::log2(p);
    }
    return e;
}

} // namespace

bool xref_index_t::build(const pe_image_t& pe, const std::vector<uint8_t>& file,
                         engine_t& eng, uint64_t base, size_t max_refs) {
    by_target_.clear();
    total_ = 0;
    if (!pe.ok || !eng.ok()) return false;

    for (const auto& s : pe.sections) {
        if (!s.is_executable() || s.raw_size == 0) continue;
        if (static_cast<size_t>(s.raw_offset) + s.raw_size > file.size()) continue;

        const uint8_t* data = file.data() + s.raw_offset;
        const uint64_t sec_va = base + s.rva;

        // Skip high-entropy sections (compressed/encrypted blobs produce
        // only noise refs and burn through the max_refs budget)
        if (s.raw_size > 4096 && section_entropy(data, s.raw_size) > 6.5)
            continue;

        size_t off = 0;
        while (off < s.raw_size) {
            if (total_ >= max_refs) return true;   // index full, still usable

            auto insn = eng.decode(sec_va + off, data + off, s.raw_size - off);
            if (!insn) { ++off; continue; }        // resync by one byte

            const uint64_t from = insn->va;
            if (insn->has_rel_target && insn->flow != flow_t::none) {
                // Validate target is within the image VA range to reduce noise
                const uint64_t target = insn->rel_target;
                if (target >= base && target < base + pe.size_of_image) {
                    const xref_kind_t k = (insn->flow == flow_t::call)
                                              ? xref_kind_t::call
                                              : xref_kind_t::jmp;
                    by_target_[target].push_back({from, target, k});
                    ++total_;
                }
            }
            if (insn->has_rip_rel) {
                const uint64_t target = insn->rip_rel_target;
                if (target >= base && target < base + pe.size_of_image) {
                    by_target_[target].push_back(
                        {from, target, xref_kind_t::data});
                    ++total_;
                }
            }

            off += insn->length;
        }
    }
    return true;
}

const std::vector<xref_t>& xref_index_t::refs_to(uint64_t va) const {
    const auto it = by_target_.find(va);
    return it != by_target_.end() ? it->second : kEmpty;
}

std::vector<uint64_t> xref_index_t::targets() const {
    std::vector<uint64_t> out;
    out.reserve(by_target_.size());
    for (const auto& [va, refs] : by_target_) out.push_back(va);
    return out;
}

} // namespace slop::core::disasm
