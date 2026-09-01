#pragma once

#include "core/runtime/backend.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace slop::core::runtime { class session_t; }

namespace slop::core::process {

using module_read_fn_t =
    std::function<runtime::io_result_t(uintptr_t, void*, size_t)>;

struct module_dump_options_t {
    size_t chunk_size = 64u * 1024u;
    bool strict_reads = true;
};

struct module_dump_result_t {
    bool ok = false;
    bool complete = false;
    std::string error;
    std::string output_path;
    uint64_t module_base = 0;
    size_t bytes_written = 0;
    size_t section_count = 0;
    std::vector<std::string> warnings;
};

// rebuild a file layout pe from a mapped image, separated so it tests
// without a live process
module_dump_result_t reconstruct_mapped_pe(
    uintptr_t module_base,
    uint32_t module_size,
    const module_read_fn_t& read,
    std::vector<uint8_t>& output,
    const module_dump_options_t& options = {});

// dump one module through the active session, works with rpm and the
// driver alike
module_dump_result_t dump_module_pe(
    runtime::session_t& session,
    const runtime::module_info_t& module,
    const std::string& output_path,
    const module_dump_options_t& options = {});

} // namespace slop::core::process
