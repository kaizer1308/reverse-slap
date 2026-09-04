// src/tests/inject_fixture_dll.cpp
// Payload DLL for the live kernel-injector tests. Built like a normal /MT
// DLL on purpose: the static CRT gives the image a real TLS directory with
// CRT callbacks (exercises the injector's TLS-callback path), the imports
// pull kernel32 forwarders that resolve into kernelbase (exercises the
// forwarder-chasing resolver), and the relocs give the base-relocation walk
// something to chew on since ASLR virtually guarantees a delta.
//
// DllMain drops a marker file into %TEMP% carrying the module base it was
// loaded at (via GetModuleHandleExW FROM_ADDRESS) so the test can prove the
// code actually executed inside the target at the base the injector
// reported -- not just that memory got mapped.

#include <windows.h>

#include <cstdint>
#include <cstdio>

namespace {

constexpr uint32_t kMarkerMagicV1 = 0x315A4E49u; // 'INZ1' LE

// thread_local with a dynamic initializer forces the CRT to emit a TLS
// directory + callbacks (__dyn_tls_init style), which the injector's
// call_tls_callbacks stage is supposed to run before DllMain.
static int tls_seed() { return 0x51; }
thread_local int tls_canary = tls_seed();
thread_local int tls_probe  = 0;

#pragma pack(push, 1)
struct marker_file_t {
    uint32_t magic;          // kMarkerMagicV1
    uint32_t reason;         // DLL_PROCESS_ATTACH / DETACH
    uint32_t pid;            // GetCurrentProcessId() inside the target
    uint32_t tls_value;      // tls_canary as seen from inside DllMain
    uint64_t module_base;    // our own base via FROM_ADDRESS lookup
    uint64_t marker_fn_addr; // address of write_marker, proves reloc fixups
};
#pragma pack(pop)

bool write_marker(uint32_t reason) {
    char path[MAX_PATH] = {};
    if (GetTempPathA(MAX_PATH, path) == 0) return false;
    char tail[64] = {};
    _snprintf_s(tail, sizeof(tail), _TRUNCATE, "slop_inject_marker_%u.bin",
                GetCurrentProcessId());
    strcat_s(path, MAX_PATH, tail);

    HMODULE self = nullptr;
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                                GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(&write_marker), &self)) {
        self = nullptr; // manual-mapped images without LDR entry return FAIL
    }

    // touch the TLS slot so a working CRT TLS init (callbacks ran) shows up
    if (tls_canary == 0) tls_canary = 0x51;
    tls_probe = tls_canary + 1;

    marker_file_t m{};
    m.magic         = kMarkerMagicV1;
    m.reason        = reason;
    m.pid           = GetCurrentProcessId();
    m.tls_value     = static_cast<uint32_t>(tls_canary);
    m.module_base   = reinterpret_cast<uint64_t>(self);
    m.marker_fn_addr = reinterpret_cast<uint64_t>(&write_marker);

    HANDLE f = CreateFileA(path, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS,
                           FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = WriteFile(f, &m, sizeof(m), &written, nullptr);
    CloseHandle(f);
    return ok && written == sizeof(m);
}

} // namespace

BOOL WINAPI DllMain(HINSTANCE, DWORD reason, LPVOID) {
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        write_marker(DLL_PROCESS_ATTACH);
        break;
    case DLL_PROCESS_DETACH:
        write_marker(DLL_PROCESS_DETACH);
        break;
    default:
        break;
    }
    return TRUE;
}

// Exported so the test can resolve it by name in the target and remote-call
// it through the driver's thread-hijack primitive. The return values are
// distinctive so a garbage/zero return is obvious.
extern "C" __declspec(dllexport) uint64_t fixture_marker_value() {
    return 0x51075107ULL; // 'QT' 'QT'
}

extern "C" __declspec(dllexport) uint64_t fixture_export_sum(uint64_t a,
                                                             uint64_t b) {
    // pull a real import in so the IAT must be resolved for this to work
    const uint64_t tick = GetTickCount64();
    return (a + b) ^ (tick & 0); // tick forces the import, mask keeps it pure
}

extern "C" __declspec(dllexport) uint64_t fixture_tls_canary() {
    if (tls_canary == 0) tls_canary = 0x51;
    return static_cast<uint64_t>(tls_canary);
}
