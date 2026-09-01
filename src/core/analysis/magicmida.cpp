#include "core/analysis/magicmida.hpp"

#include "core/disasm/binary_state.hpp"
#include "core/disasm/pe_parser.hpp"
#include "core/infra/clock.hpp"
#include "core/infra/jobs.hpp"

#include <windows.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <mutex>
#include <system_error>
#include <unordered_map>
#include <utility>

namespace slop::core::analysis::magicmida {

namespace fs = std::filesystem;

namespace {

constexpr uint16_t kMachineI386 = 0x014c;
constexpr uint16_t kMachineAmd64 = 0x8664;
constexpr uint64_t kMaxPeBytes = 512ull * 1024ull * 1024ull;
constexpr const char* kVersion = "2026-05-14";

struct handle_closer_t {
    void operator()(void* handle) const noexcept {
        if (handle && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
    }
};
using unique_handle_t = std::unique_ptr<void, handle_closer_t>;

struct job_record_t {
    mutable std::mutex mutex;
    state_t state = state_t::queued;
    request_t request;
    result_t result;
};

std::mutex g_jobs_mutex;
std::unordered_map<uint64_t, std::shared_ptr<job_record_t>> g_jobs;

std::string env_value(const char* name) {
    const DWORD needed = GetEnvironmentVariableA(name, nullptr, 0);
    if (needed == 0) return {};
    std::string value(needed, '\0');
    const DWORD written = GetEnvironmentVariableA(name, value.data(), needed);
    if (written == 0 || written >= needed) return {};
    value.resize(written);
    return value;
}

fs::path executable_dir() {
    std::string path(MAX_PATH, '\0');
    for (;;) {
        const DWORD count = GetModuleFileNameA(nullptr, path.data(),
                                               static_cast<DWORD>(path.size()));
        if (count == 0) return fs::current_path();
        if (count < static_cast<DWORD>(path.size() - 1)) {
            path.resize(count);
            return fs::path(path).parent_path();
        }
        path.resize(path.size() * 2);
    }
}

fs::path default_root() {
    const std::string configured = env_value("SLOP_MAGICMIDA_ROOT");
    if (!configured.empty()) return configured;

    const fs::path bundled = executable_dir() / "tools" / "magicmida" / kVersion;
    if (fs::exists(bundled)) return bundled;

    const std::string local = env_value("LOCALAPPDATA");
    if (!local.empty())
        return fs::path(local) / "reverse-slop" / "tools" / "magicmida" / kVersion;
    return bundled;
}

std::string quote_arg(const std::string& arg) {
    std::string out{"\""};
    size_t slashes = 0;
    for (const char ch : arg) {
        if (ch == '\\') {
            ++slashes;
        } else if (ch == '\"') {
            out.append(slashes * 2 + 1, '\\');
            out.push_back('\"');
            slashes = 0;
        } else {
            out.append(slashes, '\\');
            out.push_back(ch);
            slashes = 0;
        }
    }
    out.append(slashes * 2, '\\');
    out.push_back('\"');
    return out;
}

bool move_output(const fs::path& from, const fs::path& to, std::string& error) {
    if (from == to) return true;
    std::error_code ec;
    fs::create_directories(to.parent_path(), ec);
    ec.clear();
    fs::rename(from, to, ec);
    if (!ec) return true;
    ec.clear();
    fs::copy_file(from, to, fs::copy_options::overwrite_existing, ec);
    if (ec) {
        error = "failed to move unpacked image: " + ec.message();
        return false;
    }
    fs::remove(from, ec);
    return true;
}

} // namespace

const char* arch_name(arch_t arch) noexcept {
    switch (arch) {
    case arch_t::x86: return "x86";
    case arch_t::x64: return "x64";
    default: return "unknown";
    }
}

const char* state_name(state_t state) noexcept {
    switch (state) {
    case state_t::queued: return "queued";
    case state_t::running: return "running";
    case state_t::succeeded: return "succeeded";
    case state_t::cancelled: return "cancelled";
    case state_t::failed: return "failed";
    }
    return "failed";
}

installation_t installation() {
    const fs::path root = default_root();
    const std::string x86_override = env_value("SLOP_MAGICMIDA_X86");
    const std::string x64_override = env_value("SLOP_MAGICMIDA_X64");
    const fs::path x86 = x86_override.empty() ? root / "x86" / "Magicmida.exe"
                                               : fs::path(x86_override);
    const fs::path x64 = x64_override.empty() ? root / "x64" / "Magicmida.exe"
                                               : fs::path(x64_override);
    installation_t out;
    out.root = root.string();
    out.x86_exe = x86.string();
    out.x64_exe = x64.string();
    out.x86_available = fs::is_regular_file(x86);
    out.x64_available = fs::is_regular_file(x64);
    out.x64_scyllahide_available =
        fs::is_regular_file(x64.parent_path() / "InjectorCLIx64.exe") &&
        fs::is_regular_file(x64.parent_path() / "HookLibraryx64.dll") &&
        fs::is_regular_file(x64.parent_path() / "scylla_hide.ini");
    return out;
}

pe_info_t inspect_pe(const std::string& path) {
    pe_info_t out;
    std::error_code ec;
    out.file_size = fs::file_size(path, ec);
    if (ec) {
        out.error = "cannot read input file: " + ec.message();
        return out;
    }
    if (out.file_size == 0 || out.file_size > kMaxPeBytes) {
        out.error = "PE file is empty or exceeds 512 MiB";
        return out;
    }

    std::ifstream file(path, std::ios::binary);
    if (!file) {
        out.error = "cannot open PE file";
        return out;
    }
    std::vector<uint8_t> bytes(static_cast<size_t>(out.file_size));
    file.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!file) {
        out.error = "failed to read complete PE file";
        return out;
    }
    const auto pe = disasm::pe_parse(bytes.data(), bytes.size());
    if (!pe.ok) {
        out.error = "file is not a valid PE image";
        return out;
    }
    if (pe.machine == kMachineI386 && !pe.pe32plus) out.arch = arch_t::x86;
    else if (pe.machine == kMachineAmd64 && pe.pe32plus) out.arch = arch_t::x64;
    else {
        out.error = "Magicmida supports only PE32 i386 and PE32+ amd64 images";
        return out;
    }
    if (pe.entry_rva >= pe.size_of_image || pe.sections.empty()) {
        out.error = "PE image has an invalid entry point or section table";
        return out;
    }
    out.ok = true;
    out.entry_rva = pe.entry_rva;
    out.size_of_image = pe.size_of_image;
    out.sections = static_cast<uint16_t>(pe.sections.size());
    return out;
}

std::string generated_output_path(const std::string& input_path) {
    const fs::path input(input_path);
    return (input.parent_path() / (input.stem().string() + "U" + input.extension().string())).string();
}

result_t run(const request_t& request, const infra::cancel_token_t& cancel_token) {
    result_t out;
    out.input_path = request.input_path;
    const int64_t started = infra::steady_ms();
    const auto finish = [&] { out.duration_ms = static_cast<uint64_t>(infra::steady_ms() - started); };

    const pe_info_t input = inspect_pe(request.input_path);
    if (!input.ok) {
        out.error = input.error;
        finish();
        return out;
    }
    out.arch = input.arch;

    const installation_t install = installation();
    const fs::path sidecar = input.arch == arch_t::x86 ? install.x86_exe : install.x64_exe;
    if (!fs::is_regular_file(sidecar)) {
        out.error = std::string("Magicmida ") + arch_name(input.arch) +
                    " sidecar is not installed: " + sidecar.string();
        finish();
        return out;
    }
    if (input.arch == arch_t::x64 && !install.x64_scyllahide_available) {
        out.error = "Magicmida x64 requires InjectorCLIx64.exe, HookLibraryx64.dll, and scylla_hide.ini";
        finish();
        return out;
    }

    const fs::path generated = generated_output_path(request.input_path);
    const fs::path destination = request.output_path.empty() ? generated : fs::path(request.output_path);
    out.generated_path = generated.string();
    out.output_path = destination.string();
    std::error_code ec;
    if ((fs::exists(generated, ec) || (destination != generated && fs::exists(destination, ec))) &&
        !request.overwrite) {
        out.error = "output already exists; enable overwrite or choose another path";
        finish();
        return out;
    }
    if (request.overwrite) {
        fs::remove(generated, ec);
        if (destination != generated) fs::remove(destination, ec);
    }

    const std::string command = quote_arg(sidecar.string()) + " /unpack " +
                                quote_arg(fs::absolute(request.input_path).string());
    std::vector<char> command_line(command.begin(), command.end());
    command_line.push_back('\0');
    STARTUPINFOA startup{};
    startup.cb = sizeof(startup);
    PROCESS_INFORMATION process{};
    const std::string working_dir = fs::absolute(request.input_path).parent_path().string();
    const DWORD flags = CREATE_NO_WINDOW | CREATE_SUSPENDED;
    if (!CreateProcessA(sidecar.string().c_str(), command_line.data(), nullptr, nullptr, FALSE,
                        flags, nullptr, working_dir.c_str(), &startup, &process)) {
        out.error = "failed to launch Magicmida (Win32 error " +
                    std::to_string(GetLastError()) + ")";
        finish();
        return out;
    }
    unique_handle_t process_handle(process.hProcess);
    unique_handle_t thread_handle(process.hThread);
    unique_handle_t job(CreateJobObjectA(nullptr, nullptr));
    if (!job) {
        TerminateProcess(process.hProcess, 1);
        out.error = "failed to create unpacker Job Object";
        finish();
        return out;
    }
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if (!SetInformationJobObject(job.get(), JobObjectExtendedLimitInformation,
                                 &limits, sizeof(limits)) ||
        !AssignProcessToJobObject(job.get(), process.hProcess)) {
        TerminateProcess(process.hProcess, 1);
        out.error = "failed to contain Magicmida in a Job Object";
        finish();
        return out;
    }
    ResumeThread(process.hThread);

    const uint32_t timeout = std::clamp(request.timeout_ms, 1000u, 1800000u);
    for (;;) {
        const DWORD wait = WaitForSingleObject(process.hProcess, 100);
        if (wait == WAIT_OBJECT_0) break;
        if (wait == WAIT_FAILED) {
            TerminateJobObject(job.get(), 1);
            out.error = "failed while waiting for Magicmida";
            finish();
            return out;
        }
        if (cancel_token.cancelled()) {
            TerminateJobObject(job.get(), 1);
            WaitForSingleObject(process.hProcess, 5000);
            out.cancelled = true;
            out.error = "unpack cancelled";
            finish();
            return out;
        }
        if (static_cast<uint64_t>(infra::steady_ms() - started) >= timeout) {
            TerminateJobObject(job.get(), 1);
            WaitForSingleObject(process.hProcess, 5000);
            out.timed_out = true;
            out.error = "Magicmida timed out";
            finish();
            return out;
        }
    }
    DWORD exit_code = 0;
    GetExitCodeProcess(process.hProcess, &exit_code);
    out.exit_code = exit_code;

    const pe_info_t generated_info = inspect_pe(generated.string());
    if (!generated_info.ok) {
        out.error = "Magicmida did not produce a valid unpacked PE: " + generated_info.error;
        finish();
        return out;
    }
    if (generated_info.arch != input.arch) {
        out.error = "unpacked PE architecture does not match the input";
        finish();
        return out;
    }
    if (!move_output(generated, destination, out.error)) {
        finish();
        return out;
    }
    out.output = inspect_pe(destination.string());
    if (!out.output.ok) {
        out.error = "final unpacked PE validation failed: " + out.output.error;
        finish();
        return out;
    }
    if (out.exit_code != 0)
        out.warnings.push_back("Magicmida returned a nonzero exit code despite producing a valid PE");
    out.ok = true;
    finish();
    return out;
}

uint64_t start(request_t request, std::string& error) {
    const pe_info_t pe = inspect_pe(request.input_path);
    if (!pe.ok) {
        error = pe.error;
        return 0;
    }
    const installation_t install = installation();
    if ((pe.arch == arch_t::x86 && !install.x86_available) ||
        (pe.arch == arch_t::x64 && (!install.x64_available || !install.x64_scyllahide_available))) {
        error = std::string("Magicmida ") + arch_name(pe.arch) +
                " sidecar or required dependencies are not installed";
        return 0;
    }

    auto record = std::make_shared<job_record_t>();
    record->request = std::move(request);
    const uint64_t id = infra::jobs::submit({
        "Themida unpack", "magicmida", true,
        [record](infra::job_context_t& context) {
            {
                std::lock_guard lock(record->mutex);
                record->state = state_t::running;
            }
            context.set_stage("Magicmida debugger running");
            result_t result = run(record->request, context.cancel());
            if (result.ok && record->request.load_result &&
                !disasm::binary_state::load_file(result.output_path)) {
                result.warnings.push_back("unpacked PE was not loaded into the analysis session");
            }
            {
                std::lock_guard lock(record->mutex);
                record->result = std::move(result);
                record->state = record->result.ok ? state_t::succeeded
                              : record->result.cancelled ? state_t::cancelled
                                                         : state_t::failed;
                if (!record->result.ok && !record->result.cancelled)
                    context.fail(record->result.error);
            }
            context.set_progress(1.0f);
        }});
    if (id == 0) {
        error = "job capacity reached";
        return 0;
    }
    std::lock_guard lock(g_jobs_mutex);
    g_jobs[id] = std::move(record);
    return id;
}

bool cancel(uint64_t id) {
    return infra::jobs::cancel(id);
}

bool get_job(uint64_t id, job_t& out) {
    std::shared_ptr<job_record_t> record;
    {
        std::lock_guard lock(g_jobs_mutex);
        const auto it = g_jobs.find(id);
        if (it == g_jobs.end()) return false;
        record = it->second;
    }
    std::lock_guard lock(record->mutex);
    out.id = id;
    out.state = record->state;
    out.request = record->request;
    out.result = record->result;
    return true;
}

std::vector<job_t> jobs() {
    std::vector<uint64_t> ids;
    {
        std::lock_guard lock(g_jobs_mutex);
        ids.reserve(g_jobs.size());
        for (const auto& [id, record] : g_jobs) {
            (void)record;
            ids.push_back(id);
        }
    }
    std::sort(ids.begin(), ids.end(), std::greater<>{});
    std::vector<job_t> out;
    out.reserve(ids.size());
    for (const uint64_t id : ids) {
        job_t job;
        if (get_job(id, job)) out.push_back(std::move(job));
    }
    return out;
}

void shutdown() {
    std::vector<uint64_t> ids;
    {
        std::lock_guard lock(g_jobs_mutex);
        for (const auto& [id, record] : g_jobs) {
            (void)record;
            ids.push_back(id);
        }
    }
    for (const uint64_t id : ids) infra::jobs::cancel(id);
}

} // namespace slop::core::analysis::magicmida
