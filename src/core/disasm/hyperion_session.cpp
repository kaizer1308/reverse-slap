// src/core/disasm/hyperion_session.cpp

// GlobalMemoryStatusEx, for sizing the analysis budget against available RAM
#include <windows.h>

#include "core/disasm/hyperion_session.hpp"

#include "core/infra/diag.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace slop::core::disasm::hyperion_session {

// ---------------------------------------------------------------------------
// shared decoder

hype::Disassembler& shared_decoder() {
    // The Zydis decoder/formatter carry no cross-call state; concurrent use
    // is serialized by g_decoder_mu at the call sites below
    static hype::Disassembler dec;
    return dec;
}

size_t analysis_insn_budget() {
    static const size_t budget = [] {
        if (const char* env = std::getenv("SLOP_HYPERION_INSN_BUDGET")) {
            char* end = nullptr;
            const unsigned long long v = std::strtoull(env, &end, 10);
            if (end != env) return static_cast<size_t>(v);
        }
        MEMORYSTATUSEX mem{};
        mem.dwLength = sizeof(mem);
        if (!GlobalMemoryStatusEx(&mem)) return static_cast<size_t>(1'000'000);

        // The instruction map, sweep cache, CFG copy, xrefs and allocator
        // overhead coexist during analysis. Leave most currently available
        // memory to the loaded image, the UI and the operating system.
        constexpr uint64_t kBytesPerInsn = 1024;
        const uint64_t affordable = (mem.ullAvailPhys / 4) / kBytesPerInsn;
        return static_cast<size_t>(std::clamp<uint64_t>(affordable, 250'000, 2'000'000));
    }();
    return budget;
}

namespace {

std::mutex g_decoder_mu;

std::string upper_mnemonic(const char* s) {
    std::string out(s);
    for (char& c : out)
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    return out;
}

} // namespace

// ---------------------------------------------------------------------------
// compat shim

insn_t session_t::convert(const hype::Insn& in) {
    insn_t out;
    out.va     = in.addr;
    out.length = in.len < ZYDIS_MAX_INSTRUCTION_LENGTH ? in.len
                                                        : ZYDIS_MAX_INSTRUCTION_LENGTH;
    std::memcpy(out.bytes, in.bytes, out.length);

    // x86/x64: hyperion stores the raw Zydis enums as u16
    out.mnemonic = static_cast<ZydisMnemonic>(in.mnemonic_id);
    out.text     = upper_mnemonic(in.mnemonic);
    if (in.op_str[0] != '\0') out.text += " ", out.text += in.op_str;

    switch (in.type) {
    case hype::InsnType::Call: out.flow = flow_t::call; break;
    case hype::InsnType::Jmp:  out.flow = flow_t::jmp;  break;
    case hype::InsnType::Jcc:  out.flow = flow_t::jcc;  break;
    case hype::InsnType::Ret:  out.flow = flow_t::ret;  break;
    default:                   out.flow = flow_t::none; break;
    }

    for (uint8_t i = 0; i < in.op_count && i < ZYDIS_MAX_OPERAND_COUNT_VISIBLE; ++i) {
        const hype::Operand& src = in.ops[i];
        operand_t&           o   = out.ops[out.op_count++];
        o.read = src.read;
        o.write = src.write;
        switch (src.type) {
        case hype::OpType::Reg:
            o.cls = op_class_t::reg;
            o.reg = static_cast<ZydisRegister>(src.reg);
            break;
        case hype::OpType::Imm:
            o.cls = op_class_t::imm;
            o.imm = src.val;
            break;
        case hype::OpType::Mem:
            o.cls       = op_class_t::mem;
            o.mem_base  = static_cast<ZydisRegister>(src.mem.base);
            o.mem_index = static_cast<ZydisRegister>(src.mem.index);
            o.scale     = src.mem.scale ? src.mem.scale : 1;
            o.disp      = src.mem.disp;
            break;
        default:
            o.cls = op_class_t::none;
            break;
        }
    }

    // Branch destination: first immediate operand (hyperion's own
    // branch_target() contract)
    if (out.flow == flow_t::call || out.flow == flow_t::jmp ||
        out.flow == flow_t::jcc) {
        if (in.op_count > 0 && in.ops[0].type == hype::OpType::Imm) {
            out.has_rel_target = true;
            out.rel_target     = in.ops[0].val;
        }
    }

    // First rip-relative memory operand, hyperion precomputed the absolute
    // address into Operand::val for RIP/EIP-based operands
    for (uint8_t i = 0; i < in.op_count; ++i) {
        const hype::Operand& src = in.ops[i];
        if (src.type != hype::OpType::Mem) continue;
        if (src.mem.base != static_cast<uint16_t>(ZYDIS_REGISTER_RIP) &&
            src.mem.base != static_cast<uint16_t>(ZYDIS_REGISTER_EIP))
            continue;
        out.has_rip_rel    = true;
        out.rip_rel_target = src.val;
        break;
    }

    return out;
}

bool session_t::decode(uint64_t va, const uint8_t* buf, size_t len,
                       insn_t& out) {
    if (!buf || len == 0) return false;
    std::lock_guard lk(g_decoder_mu);
    hype::Insn in;
    if (!shared_decoder().decode(va, buf, len, in)) return false;
    out = convert(in);
    return true;
}

std::vector<insn_t> session_t::decode_range(uint64_t va, const uint8_t* buf,
                                             size_t len, size_t count) {
    std::vector<insn_t> out;
    if (!buf || len == 0 || count == 0) return out;

    std::lock_guard lk(g_decoder_mu);
    out.reserve(count);
    size_t off = 0;
    while (off < len && out.size() < count) {
        hype::Insn in;
        if (shared_decoder().decode(va + off, buf + off, len - off, in)) {
            out.push_back(convert(in));
            off += in.len ? in.len : 1;
        } else {
            ++off;  // 1-byte resync on bad bytes
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// lifecycle

session_t::session_t()  = default;

session_t::~session_t() {
    std::lock_guard lk(start_mu_);
    if (analyzer_ && !ready_.load(std::memory_order_acquire))
        analyzer_->request_cancel();
    if (worker_.joinable()) worker_.join();
    analyzer_.reset();
}

void session_t::join_worker() {
    // caller holds start_mu_
    if (worker_.joinable()) worker_.join();
}

void session_t::set_error(std::string msg) {
    std::lock_guard lk(err_mu_);
    err_ = std::move(msg);
    ready_.store(false, std::memory_order_release);
}

bool session_t::begin(const uint8_t* bytes, size_t len, uint64_t base_override) {
    // caller holds start_mu_ and the worker is joined
    ready_.store(false, std::memory_order_release);
    block_ranges_.clear();
    invalidate_decomp_cache();
    {
        std::lock_guard lk(err_mu_);
        err_.clear();
    }

    hype::PELoader loader;
    auto parsed = loader.load_buffer(bytes, len);
    if (!parsed) {
        set_error("hyperion: PE parse failed");
        return false;
    }
    img_ = std::move(*parsed);
    base_override_ = base_override;
    if (base_override) {
        // Rebase: shift every segment VA and the image base
        const uint64_t delta = base_override - img_.base;
        img_.base = base_override;
        img_.entry += delta;
        for (auto& seg : img_.segments) seg.va += delta;
        for (auto& imp : img_.imports)   imp.iat_addr += delta;
        for (auto& ex : img_.exports)    ex.addr += delta;
        for (auto& rf : img_.runtime_funcs) { rf.start += delta; rf.end += delta; }
    }

    analyzer_ = std::make_unique<hype::Analyzer>(img_, pool_);
    analyzer_->set_insn_budget(analysis_insn_budget());
    return true;
}

void session_t::run_pipeline() {
    // Clear the running flag on every exit path (including the cancel
    // return and exceptions)
    struct flag_guard_t {
        std::atomic<bool>& f;
        ~flag_guard_t() { f.store(false, std::memory_order_release); }
    } run_flag{running_};

    try {
        analyzer_->run();
        if (analyzer_->was_cancelled()) {
            set_error("analysis cancelled");
            return;
        }
        // Re-apply user renames queued while analysis was running (and the
        // pre-load set from the persisted symbol store)
        {
            std::lock_guard plk(pending_mu_);
            for (const auto& [va, name] : pending_names_)
                analyzer_->db().names[va] = name;
        }
        ready_.store(true, std::memory_order_release);
        build_interval_index();
        slop::core::infra::diag::info(
            "hyperion", "analysis done — " +
                std::to_string(db().funcs.size()) + " functions, " +
                std::to_string(db().insns.size()) + " insns" +
                (analyzer_->budget_reached()
                     ? " (partial: instruction budget of " +
                           std::to_string(analyzer_->insn_budget()) + " reached)"
                     : std::string{}));
    } catch (const std::exception& e) {
        set_error(std::string("hyperion analysis failed: ") + e.what());
    } catch (...) {
        set_error("hyperion analysis failed: unknown error");
    }
}

void session_t::queue_names(
        const std::unordered_map<uint64_t, std::string>& names) {
    std::lock_guard plk(pending_mu_);
    for (const auto& [va, name] : names) {
        if (name.empty()) pending_names_.erase(va);
        else              pending_names_[va] = name;
    }
    // Late arrivals after analysis completed: apply straight to the DB and
    // drop cached pseudocode (renames change emitted call names)
    if (ready_.load(std::memory_order_acquire)) {
        invalidate_decomp_cache();
        for (const auto& [va, name] : names) {
            if (name.empty()) analyzer_->db().names.erase(va);
            else              analyzer_->db().names[va] = name;
        }
    }
}

bool session_t::start(const uint8_t* bytes, size_t len, uint64_t base_override) {
    std::lock_guard lk(start_mu_);
    join_worker();
    if (!begin(bytes, len, base_override)) return false;
    // Flip before spawning so running() is true the instant start()
    // returns, no "stopped" gap while the thread spins up
    running_.store(true, std::memory_order_release);
    worker_ = std::thread([this] { run_pipeline(); });
    return true;
}

bool session_t::start_sync(const uint8_t* bytes, size_t len,
                           uint64_t base_override) {
    std::lock_guard lk(start_mu_);
    join_worker();
    if (!begin(bytes, len, base_override)) return false;
    running_.store(true, std::memory_order_release);
    run_pipeline();
    return ready_.load(std::memory_order_acquire);
}

void session_t::reanalyze(const std::vector<uint8_t>& patched_bytes) {
    std::lock_guard lk(start_mu_);
    invalidate_decomp_cache();
    if (analyzer_ && !ready_.load(std::memory_order_acquire))
        analyzer_->request_cancel();
    join_worker();
    if (!begin(patched_bytes.data(), patched_bytes.size(), base_override_)) return;
    running_.store(true, std::memory_order_release);
    worker_ = std::thread([this] { run_pipeline(); });
}

void session_t::stop() {
    std::lock_guard lk(start_mu_);
    if (analyzer_ && !ready_.load(std::memory_order_acquire))
        analyzer_->request_cancel();
    join_worker();
    // A completed run between the flag and the join is fine, stop() is a
    // no-op then. A cancelled one left ready_ false with the error set
}

bool session_t::truncated() const {
    if (!ready_.load(std::memory_order_acquire)) return false;
    std::lock_guard lk(start_mu_);
    return analyzer_ && analyzer_->budget_reached();
}

bool session_t::running() const {
    if (ready_.load(std::memory_order_acquire)) return false;
    return running_.load(std::memory_order_acquire);
}

float session_t::progress() const {
    if (ready_.load(std::memory_order_acquire)) return 1.f;
    std::lock_guard lk(start_mu_);
    // analyzer_ exists between begin() and destruction (both under
    // start_mu_); run() itself never touches the pointer
    return analyzer_ ? analyzer_->progress() : 0.f;
}

std::string session_t::error() const {
    if (ready_.load(std::memory_order_acquire)) return {};
    std::lock_guard lk(err_mu_);
    return err_;
}

// ---------------------------------------------------------------------------
// results

const hype::AnalysisDB& session_t::db() const { return analyzer_->db(); }
hype::AnalysisDB& session_t::db_mut() { return analyzer_->db(); }
const hype::RTTIParser& session_t::rtti() const { return analyzer_->rtti_parser(); }

const hype::SignatureMatcher& session_t::signatures() const {
    return analyzer_->sig_matcher();
}

const hype::Function* session_t::function_entry(uint64_t va) const {
    if (!ready()) return nullptr;
    const auto& funcs = db().funcs;
    const auto  it    = funcs.find(va);
    return it != funcs.end() ? &it->second : nullptr;
}

const hype::Function* session_t::function_at(uint64_t va) const {
    if (!ready()) return nullptr;
    // Exact entries win (deterministic), then the interval index
    if (const hype::Function* exact = function_entry(va)) return exact;
    // sorted interval index built once per analysis, binary search with a
    // short walk back for the rare overlaps
    auto it = std::upper_bound(
        block_ranges_.begin(), block_ranges_.end(), va,
        [](uint64_t value, const BlockRange& range) { return value < range.start; });
    while (it != block_ranges_.begin()) {
        --it;
        if (va < it->end) return it->func;
        if (va - it->start > (1ull << 20)) break;
    }
    return nullptr;
}

void session_t::build_interval_index() {
    block_ranges_.clear();
    for (const auto& [entry, f] : db().funcs) {
        (void)entry;
        for (const auto& [start, bb] : f.blocks) {
            if (bb.end <= start) continue;
            block_ranges_.push_back({start, bb.end, &f});
        }
    }
    std::sort(block_ranges_.begin(), block_ranges_.end(),
              [](const BlockRange& a, const BlockRange& b) { return a.start < b.start; });
}

void session_t::invalidate_decomp_cache() {
    decomp_cache_.clear();
    ++decomp_cache_gen_;
}

bool session_t::decompile(uint64_t va, std::vector<hype::PseudoLine>& out,
                          std::string& err) {
    if (!ready()) {
        err = "hyperion analysis not ready";
        return false;
    }
    const hype::Function* f = function_at(va);
    if (!f) {
        err = "no function contains address " + std::to_string(va);
        return false;
    }
    {
        std::lock_guard lk(decomp_mu_);
        auto cached = decomp_cache_.find(f->entry);
        if (cached != decomp_cache_.end()) {
            out = cached->second;
            return true;
        }
        hype::Decompiler dec;
        out = dec.decompile(*f, db(), &rtti());
        if (out.empty()) {
            err = "decompiler produced no output";
            return false;
        }
        // Bound the cache so pathological decompile-everything sessions don't
        // grow it without limit
        if (decomp_cache_.size() >= 256) decomp_cache_.clear();
        decomp_cache_[f->entry] = out;
    }
    return true;
}

} // namespace slop::core::disasm::hyperion_session
