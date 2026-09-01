#pragma once

// Magicmida integration. Upstream is a separate GPLv3 debugger executable;
// this service selects and supervises the matching x86/x64 sidecar

#include "core/infra/cancel.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace slop::core::analysis::magicmida {

enum class arch_t : uint8_t { unknown, x86, x64 };
enum class state_t : uint8_t { queued, running, succeeded, cancelled, failed };

struct installation_t {
    std::string root;
    std::string x86_exe;
    std::string x64_exe;
    bool x86_available = false;
    bool x64_available = false;
    bool x64_scyllahide_available = false;
};

struct pe_info_t {
    bool ok = false;
    arch_t arch = arch_t::unknown;
    uint32_t entry_rva = 0;
    uint32_t size_of_image = 0;
    uint16_t sections = 0;
    uint64_t file_size = 0;
    std::string error;
};

struct request_t {
    std::string input_path;
    std::string output_path;
    uint32_t timeout_ms = 300000;
    bool overwrite = false;
    bool load_result = true;
};

struct result_t {
    bool ok = false;
    bool cancelled = false;
    bool timed_out = false;
    uint32_t exit_code = 0;
    uint64_t duration_ms = 0;
    arch_t arch = arch_t::unknown;
    std::string input_path;
    std::string generated_path;
    std::string output_path;
    pe_info_t output;
    std::string error;
    std::vector<std::string> warnings;
};

struct job_t {
    uint64_t id = 0;
    state_t state = state_t::queued;
    request_t request;
    result_t result;
};

const char* arch_name(arch_t arch) noexcept;
const char* state_name(state_t state) noexcept;
installation_t installation();
pe_info_t inspect_pe(const std::string& path);
std::string generated_output_path(const std::string& input_path);
result_t run(const request_t& request, const infra::cancel_token_t& cancel);

uint64_t start(request_t request, std::string& error);
bool cancel(uint64_t id);
bool get_job(uint64_t id, job_t& out);
std::vector<job_t> jobs();
void shutdown();

} // namespace slop::core::analysis::magicmida
