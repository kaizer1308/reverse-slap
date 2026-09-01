#pragma once

// src/core/debugger/callstack.hpp
// pure unwinding and seh chain walking over a reader callback, rbp chain
// first with a stack scan fallback, no os calls so it tests against
// synthetic stacks

#include <cstdint>
#include <string>
#include <vector>

#include "core/disasm/engine.hpp"

namespace slop::core::debugger::unwind {

struct reader_t {
    virtual ~reader_t() = default;
    virtual bool read(uint64_t addr, void* dst, size_t len) = 0;
};

struct frame_t {
    uint64_t    ret_addr  = 0;      // return address into the caller
    uint64_t    frame_ptr = 0;      // rbp of this frame (chain walk) or 0
    std::string snippet;            // disassembly at ret_addr (best effort)
    bool        scanned  = false;   // found by scan fallback, not rbp chain
};

// Walk up to max_frames frames starting from the given context
std::vector<frame_t> walk_stack(disasm::engine_t& eng, reader_t& rdr,
                                uint64_t rip, uint64_t rsp, uint64_t rbp,
                                size_t max_frames = 32);

struct seh_entry_t {
    uint64_t handler = 0;
    uint64_t filter  = 0;
    uint64_t frame   = 0;
};

struct seh_result_t {
    std::vector<seh_entry_t> chain;
    std::vector<uint64_t>    scan_candidates;   // framed-handler candidates
    bool chain_empty_proven = false;            // sentinel reached (x64 norm)
    std::string note;
};

// teb_addr is the threads teb base, the x64 exception list is normally
// the minus one sentinel, anything else gets walked
seh_result_t seh_chain(reader_t& rdr, uint64_t teb_addr);

} // namespace slop::core::debugger::unwind
