#pragma once

// models for imports whose behavior is fixed by their contract: the memory
// and string routines, the heap families, TLS/FLS, TEB-backed state, the
// clock, and the calls that never return. Internal to core/emu: session.cpp
// implements api_host_t over the running machine and dispatches a stubbed
// import here before its RET runs

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace slop::core::emu {

// What a model may do to the machine. Guest accesses page in on demand like
// the code's own; one that cannot be satisfied returns false and has already
// recorded the fault, the model just returns and the run stops there
class api_host_t {
public:
    // Win64 arguments: rcx, rdx, r8, r9, then the caller's stack slots
    virtual uint64_t arg(size_t index) = 0;
    virtual bool     arg_tainted(size_t index) = 0;

    virtual bool read(uint64_t addr, void* out, size_t len) = 0;
    virtual bool write(uint64_t addr, const void* data, size_t len) = 0;   // logged, untaints
    virtual bool fill(uint64_t addr, uint8_t value, size_t len, bool tainted) = 0;
    virtual bool copy(uint64_t dst, uint64_t src, size_t len) = 0;   // memmove, taint follows
    virtual bool tainted(uint64_t addr, size_t len) = 0;
    virtual void taint_result(bool tainted) = 0;   // rax depends on tainted bytes

    // Zeroed block from the private heap, 0 when it is spent. align is a
    // power of two; blocks are never reused
    virtual uint64_t alloc(uint64_t size, uint64_t align) = 0;
    virtual bool     alloc_size(uint64_t ptr, uint64_t* size) = 0;
    // Zeroed pages at a caller-chosen address (VirtualAlloc with lpAddress)
    virtual bool     map_fixed(uint64_t addr, uint64_t size) = 0;

    virtual uint64_t gs_base() = 0;        // the TEB in user mode
    virtual uint64_t image_base() = 0;
    virtual uint64_t heap_handle() = 0;

    // Virtual time: nanoseconds since boot, advances with executed instructions
    virtual uint64_t clock_ns() = 0;
    virtual void     sleep_ns(uint64_t ns) = 0;

    virtual uint64_t fls_get(uint64_t index) = 0;
    virtual void     fls_set(uint64_t index, uint64_t value) = 0;
    virtual uint64_t fls_alloc() = 0;
    virtual uint64_t tls_alloc() = 0;      // ~0 when the 64 TEB slots are taken

    // The call does not return: stop with "exit" / "api_exception"
    virtual void exit_process(uint64_t code) = 0;
    virtual void raise(uint32_t code, const char* name) = 0;

protected:
    ~api_host_t() = default;
};

// Returns the value for rax
using api_model_fn = uint64_t (*)(api_host_t&);

// Model for an import by its function name (the part after "dll!"), nullptr
// when it has none. Names are matched exactly, the way the loader binds them
api_model_fn find_api_model(std::string_view function);

// Virtual clock anchors shared with the KUSER_SHARED_DATA page
inline constexpr uint64_t kBootUptimeNs   = 3600ull * 1000000000ull;     // booted an hour ago
inline constexpr uint64_t kBootFileTime   = 133485408000000000ull;       // 2024-01-01 00:00 UTC at boot
inline constexpr uint64_t kQpcFrequency   = 10000000ull;                 // 100 ns units
inline constexpr uint64_t kUnixEpochDelta = 116444736000000000ull;       // 1601 -> 1970 in 100 ns

// IsProcessorFeaturePresent for the emulated CPU (SSE4.2, AES, BMI, no AVX)
bool processor_feature(uint64_t feature);

} // namespace slop::core::emu
