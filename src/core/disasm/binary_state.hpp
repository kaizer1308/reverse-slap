#pragma once

// src/core/disasm/binary_state.hpp
// the one shared binary session behind the ui and the mcp tools
// whatever is loaded here is what everyone sees, renames included
// load unload and set_symbol are thread safe, get is render thread only

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "core/disasm/engine.hpp"
#include "core/disasm/function_index.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/disasm/strings.hpp"
#include "core/disasm/xrefs.hpp"

namespace slop::core::disasm::binary_state {

namespace disasm = slop::core::disasm;

} // hyperion_session is a sibling namespace

namespace slop::core::disasm::hyperion_session { struct session_t; }

namespace slop::core::disasm::binary_state {

struct binary_t {
    bool                     ready  = false;
    std::string              name;            // display name
    std::string              path;            // source file path
    std::vector<uint8_t>     file;
    // fnv1a over `file`, computed once at load. It keys the annotation store
    // and every rename/comment/bookmark writes that store back, so rehashing
    // a few hundred megabytes per keystroke is not an option
    uint64_t                 file_hash = 0;
    disasm::pe_image_t       pe;
    uint64_t                 base   = 0;      // VA base used everywhere
    disasm::engine_t         eng;
    disasm::function_index_t fns;
    disasm::xref_index_t     xrefs;
    std::vector<disasm::string_hit_t> strings;

    // hyperion session, null until first load, analysis runs in the background
    std::unique_ptr<hyperion_session::session_t> hype;

    // defined in the cpp where the type is complete
    ~binary_t();

    // user renames keyed by va
    std::unordered_map<uint64_t, std::string> symbols;

    // per va comments and bookmarks
    std::unordered_map<uint64_t, std::string> comments;
    std::vector<uint64_t>                     bookmarks;

    // every byte mutated since load, in order
    struct patch_rec_t {
        uint64_t va;
        size_t   offset;
        uint8_t  before;
        uint8_t  after;
    };
    std::vector<patch_rec_t> patches;

    // set by patch mutations, indexes are stale until rebuilt
    bool indexes_dirty = false;

    // file offset for a va when backed
    std::optional<size_t> offset_of(uint64_t va) const;
};

// shared instance, render thread convenience
binary_t& get();

// load a file, base_override rebases everything so static vas match live ones
bool load_file(const std::string& path, uint64_t base_override = 0);

// load the main module of the attached target
bool load_from_target();

bool has_binary();
void unload();   // thread safe

// hyperion analysis state, empty when no binary
bool  hype_ready();         // analysis complete and db usable
float hype_progress();      // 0 to 1

// one shot snapshot for status displays
struct hype_status_t {
    bool        has_image   = false;
    std::string image;               // binary display name
    std::string engine_error;        // empty when healthy
    bool        engine_present = false;
    bool        ready          = false;
    bool        running        = false;   // analysis in flight
    bool        truncated      = false;   // ready, but the image outgrew the budget
    float       progress       = 0.f;     // 0..1 while running
};
hype_status_t hype_status();

// cancel an in flight analysis, no-op when idle
void hype_stop();

// rename helpers, empty string clears
void        set_symbol(uint64_t va, const std::string& name);
std::string symbol_name(uint64_t va);                       // copy, safe anywhere
std::vector<std::pair<uint64_t, std::string>> symbols_snapshot();

// annotations and bookmarks, persisted per binary hash
void        set_comment(uint64_t va, const std::string& text);   // empty clears
std::string comment_for(uint64_t va);
std::vector<std::pair<uint64_t, std::string>> comments_snapshot();

bool toggle_bookmark(uint64_t va);       // true when now bookmarked
bool is_bookmarked(uint64_t va);
std::vector<uint64_t> bookmarks_snapshot();

// render thread conveniences, no lock
const char* symbol_for(uint64_t va);                        // null when unnamed

// out of thread access
// pin the session while reading fns xrefs pe or file from another thread

std::mutex& state_mutex();

class binary_lock_t {
public:
    binary_lock_t() : lk_(state_mutex()) {}
    binary_lock_t(const binary_lock_t&)            = delete;
    binary_lock_t& operator=(const binary_lock_t&) = delete;

private:
    std::unique_lock<std::mutex> lk_;
};

} // namespace slop::core::disasm::binary_state
