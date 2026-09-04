// src/tests/test_driver_abi.cpp
// ABI parity between the user-mode voyager comm structs and the kernel
// driver's request structs. The driver side is pinned at driver-build time
// by static_asserts in driver/slopdrvr/src/function/Struct.h (the .sys link
// fails if they drift); this file pins the user-mode side to the same
// numbers so a UM edit can never silently desync the IOCTL wire format.
//
// The expected values below are transcribed from the driver's own
// static_asserts and dispatcher constants — when a struct legitimately
// changes, both sides change together or these tests fail loudly.

#include "harness.hpp"

#include "core/runtime/voyager_comm.h"

#include <windows.h>
#include <cstddef>

namespace {

namespace km = voyager::detail;

} // namespace

// ---------------------------------------------------------------------------
// Core request structs (driver Struct.h static_asserts, transcribed)
// ---------------------------------------------------------------------------

TEST_CASE(abi_dtb_solve_matches_kernel) {
    REQUIRE_EQ(sizeof(km::dtb_solve), 16u);
    REQUIRE_EQ(offsetof(km::dtb_solve, pid), 0u);
    REQUIRE_EQ(offsetof(km::dtb_solve, dtb), 8u);
}

TEST_CASE(abi_physical_rw_matches_kernel) {
    REQUIRE_EQ(sizeof(km::physical_request), 56u);
    REQUIRE_EQ(offsetof(km::physical_request, pid), 0u);
    REQUIRE_EQ(offsetof(km::physical_request, dtb), 8u);
    REQUIRE_EQ(offsetof(km::physical_request, address), 16u);
    REQUIRE_EQ(offsetof(km::physical_request, buffer), 24u);
    REQUIRE_EQ(offsetof(km::physical_request, size), 32u);
    REQUIRE_EQ(offsetof(km::physical_request, should_write), 48u);
}

TEST_CASE(abi_base_address_matches_kernel) {
    REQUIRE_EQ(sizeof(km::base_address_request), 16u);
    REQUIRE_EQ(offsetof(km::base_address_request, pid), 0u);
    REQUIRE_EQ(offsetof(km::base_address_request, out_address), 8u);
}

TEST_CASE(abi_remote_call_matches_kernel) {
    REQUIRE_EQ(sizeof(km::remote_call_request), 96u);
    // Field order mirrors the driver's remote_call exactly; the poll path
    // (call_result_request) reads only the first 32 bytes
    REQUIRE_EQ(offsetof(km::remote_call_request, dtb), 0u);
    REQUIRE_EQ(offsetof(km::remote_call_request, target_function), 8u);
    REQUIRE_EQ(offsetof(km::remote_call_request, result), 64u);
    REQUIRE_EQ(offsetof(km::remote_call_request, completed), 72u);
    REQUIRE_EQ(offsetof(km::remote_call_request, trampoline_addr), 88u);
}

TEST_CASE(abi_call_result_matches_kernel) {
    REQUIRE_EQ(sizeof(km::call_result_request), 32u);
    REQUIRE_EQ(offsetof(km::call_result_request, dtb), 0u);
    REQUIRE_EQ(offsetof(km::call_result_request, result_address), 8u);
    REQUIRE_EQ(offsetof(km::call_result_request, result), 16u);
    REQUIRE_EQ(offsetof(km::call_result_request, completed), 24u);
}

TEST_CASE(abi_alloc_free_mem_matches_kernel) {
    REQUIRE_EQ(sizeof(km::alloc_mem_request), 32u);
    REQUIRE_EQ(offsetof(km::alloc_mem_request, pid), 0u);
    REQUIRE_EQ(offsetof(km::alloc_mem_request, size), 8u);
    REQUIRE_EQ(offsetof(km::alloc_mem_request, allocated_address), 16u);

    REQUIRE_EQ(sizeof(km::free_mem_request), 16u);
    REQUIRE_EQ(offsetof(km::free_mem_request, pid), 0u);
    REQUIRE_EQ(offsetof(km::free_mem_request, address), 8u);
}

TEST_CASE(abi_shellcode_context_offsets_match_kernel) {
    // The kernel shellcode (assembled at runtime, offsets baked in) reads
    // the SHELLCODE_CONTEXT the UM side writes. Driver pins: result@0x30,
    // original_rip@0x40, completed@0x50, trampoline@0x58, total 0x140.
    REQUIRE_EQ(km::CTX_TARGET_FUNC, 0x00u);
    REQUIRE_EQ(km::CTX_SPOOF_GADGET, 0x08u);
    REQUIRE_EQ(km::CTX_PARAM1, 0x10u);
    REQUIRE_EQ(km::CTX_PARAM4, 0x28u);
    REQUIRE_EQ(km::CTX_RET_VALUE, 0x30u);
    REQUIRE_EQ(km::CTX_SAVED_RSP, 0x38u);
    REQUIRE_EQ(km::CTX_ORIGINAL_RIP, 0x40u);
    REQUIRE_EQ(km::CTX_RBX_BACKUP, 0x48u);
    REQUIRE_EQ(km::CTX_EXEC_DONE, 0x50u);
    REQUIRE_EQ(km::CTX_TRAMPOLINE, 0x58u);
    // Context fits in the first page of the 2-page shellcode allocation,
    // code lives at 0x200, epilogue at 0x600
    REQUIRE(km::CONTEXT_OFFSET < km::CODE_OFFSET);
    REQUIRE(km::CODE_OFFSET < km::EPILOGUE_OFFSET);
    REQUIRE_EQ(km::SHELLCODE_ALLOC_SIZE, 0x2000u);
}

TEST_CASE(abi_thread_structs_match_kernel) {
    REQUIRE_EQ(sizeof(km::thread_ctx_request), 232u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, pid), 0u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, should_set), 8u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, register_mask), 16u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, rax), 24u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, rip), 152u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, rflags), 160u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, dr0), 184u);
    REQUIRE_EQ(offsetof(km::thread_ctx_request, dr7), 224u);

    REQUIRE_EQ(sizeof(km::thread_entry), 16u);
    REQUIRE_EQ(km::MAX_ENUM_THREADS, 256u);
    REQUIRE_EQ(sizeof(km::thread_enum_request),
               8u + 16u * km::MAX_ENUM_THREADS);

    REQUIRE_EQ(sizeof(km::suspend_resume_request), 16u);
    REQUIRE_EQ(sizeof(km::thread_query_information_request), 72u);
    REQUIRE_EQ(sizeof(km::terminate_thread_request), 16u);
    REQUIRE_EQ(sizeof(km::close_handle_request), 16u);
}

TEST_CASE(abi_memory_query_structs_match_kernel) {
    REQUIRE_EQ(sizeof(km::query_memory_request), 56u);
    REQUIRE_EQ(offsetof(km::query_memory_request, address), 8u);
    REQUIRE_EQ(offsetof(km::query_memory_request, region_base), 16u);

    REQUIRE_EQ(sizeof(km::protect_memory_request), 32u);
    REQUIRE_EQ(offsetof(km::protect_memory_request, new_protect), 4u);
    REQUIRE_EQ(offsetof(km::protect_memory_request, old_protect), 24u);

    REQUIRE_EQ(sizeof(km::region_entry), 32u);
    REQUIRE_EQ(km::MAX_ENUM_REGIONS, 4096u);
    REQUIRE_EQ(sizeof(km::enum_regions_request),
               32u + 32u * km::MAX_ENUM_REGIONS);
}

TEST_CASE(abi_peb_spoof_export_v2p_ssdt_match_kernel) {
    REQUIRE_EQ(sizeof(km::read_peb_request), 64u);
    REQUIRE_EQ(offsetof(km::read_peb_request, peb_address), 8u);
    REQUIRE_EQ(offsetof(km::read_peb_request, image_base), 16u);

    REQUIRE_EQ(sizeof(km::spoof_debug_request), 8u);

    REQUIRE_EQ(sizeof(km::module_export_request), 160u);
    REQUIRE_EQ(offsetof(km::module_export_request, export_name), 16u);
    REQUIRE_EQ(offsetof(km::module_export_request, resolved_address), 144u);

    REQUIRE_EQ(sizeof(km::virt_to_phys_request), 24u);
    REQUIRE_EQ(offsetof(km::virt_to_phys_request, virtual_address), 8u);
    REQUIRE_EQ(offsetof(km::virt_to_phys_request, physical_address), 16u);

    REQUIRE_EQ(sizeof(km::ssdt_query_request), 48u);
    REQUIRE_EQ(offsetof(km::ssdt_query_request, service_table), 16u);
    REQUIRE_EQ(offsetof(km::ssdt_query_request, service_limit), 40u);
}

// ---------------------------------------------------------------------------
// Lifecycle structs: IDENT / SHUTDOWN / LOGCTL
// ---------------------------------------------------------------------------

TEST_CASE(abi_ident_matches_kernel) {
    REQUIRE_EQ(sizeof(km::ident_request), 536u);
    REQUIRE_EQ(offsetof(km::ident_request, driver_version), 0u);
    REQUIRE_EQ(offsetof(km::ident_request, unloading), 4u);
    REQUIRE_EQ(offsetof(km::ident_request, service_path_len), 8u);
    REQUIRE_EQ(offsetof(km::ident_request, service_path), 16u);
    // 260 wchar path fits the driver's fixed buffer
    REQUIRE_EQ(sizeof(km::ident_request{}.service_path) / sizeof(wchar_t), 260u);
}

TEST_CASE(abi_shutdown_matches_kernel) {
    REQUIRE_EQ(sizeof(km::shutdown_request), 8u);
    REQUIRE_EQ(offsetof(km::shutdown_request, magic), 0u);
    REQUIRE_EQ(offsetof(km::shutdown_request, status), 4u);
    // The magic constant itself lives inline in arm_shutdown (UM) and the
    // dispatcher (KM), both 0x5D100D0C — the live driver_shutdown test in
    // test_driver.cpp exercises the actual round-trip
}

TEST_CASE(abi_logctl_matches_kernel) {
    REQUIRE_EQ(sizeof(km::logctl_request), 16u);
    REQUIRE_EQ(offsetof(km::logctl_request, magic), 0u);
    REQUIRE_EQ(offsetof(km::logctl_request, log_level), 4u);
    REQUIRE_EQ(offsetof(km::logctl_request, log_cap_mb), 8u);
    REQUIRE_EQ(offsetof(km::logctl_request, status), 12u);
}

// ---------------------------------------------------------------------------
// Network + malware-safe ABI
// ---------------------------------------------------------------------------

TEST_CASE(abi_network_structs_match_kernel) {
    REQUIRE_EQ(sizeof(km::net_conn_entry), 320u);
    REQUIRE_EQ(km::MAX_NET_CONNECTIONS, 1024u);

    REQUIRE_EQ(sizeof(km::net_cap_ctrl_request), 48u);
    REQUIRE_EQ(sizeof(km::net_packet_entry), 1576u);
    REQUIRE_EQ(km::NET_PKT_MAX_PAYLOAD, 1500u);
    REQUIRE_EQ(km::NET_CAP_GET_MAX, 32u);
    REQUIRE_EQ(sizeof(km::net_dns_entry), 304u);
    REQUIRE_EQ(km::NET_DNS_GET_MAX, 64u);
    REQUIRE_EQ(sizeof(km::net_filter_rule_request), 64u);
    REQUIRE_EQ(sizeof(km::net_stats_request), 64u);

    REQUIRE_EQ(sizeof(km::wfp_callout_entry), 184u);
    REQUIRE_EQ(km::MAX_WFP_CALLOUTS, 256u);
    REQUIRE_EQ(sizeof(km::socket_handle_entry), 72u);
    REQUIRE_EQ(km::MAX_SOCKET_HANDLES, 512u);
    REQUIRE_EQ(sizeof(km::sniff_capture), 2072u);
    REQUIRE_EQ(km::SNIFF_MAX_CAPTURES, 16u);
    REQUIRE_EQ(km::SNIFF_MAX_BUF_SIZE, 2048u);
    REQUIRE_EQ(sizeof(km::tcpip_conn_entry), 96u);
    REQUIRE_EQ(km::MAX_TCPIP_CONNECTIONS, 1024u);
    REQUIRE_EQ(sizeof(km::bw_process_entry), 48u);
    REQUIRE_EQ(km::BW_MAX_PROCESSES, 128u);
}

TEST_CASE(abi_debug_events_match_kernel) {
    REQUIRE_EQ(sizeof(km::debug_event_t), 560u);
    REQUIRE_EQ(offsetof(km::debug_event_t, event_type), 0u);
    REQUIRE_EQ(offsetof(km::debug_event_t, process_id), 4u);
    REQUIRE_EQ(offsetof(km::debug_event_t, flags), 12u);
    REQUIRE_EQ(offsetof(km::debug_event_t, timestamp), 16u);
    REQUIRE_EQ(offsetof(km::debug_event_t, image_base), 24u);
    REQUIRE_EQ(offsetof(km::debug_event_t, image_size), 32u);
    REQUIRE_EQ(offsetof(km::debug_event_t, image_path), 40u);
    REQUIRE_EQ(km::DEBUG_EVENT_PATH_CHARS, 260u);

    REQUIRE_EQ(km::DRAIN_DEBUG_EVENTS_CAP, 64u);
    REQUIRE_EQ(sizeof(km::drain_debug_events_request),
               32u + 64u * 560u);
    REQUIRE_EQ(offsetof(km::drain_debug_events_request, returned_count), 8u);
    REQUIRE_EQ(offsetof(km::drain_debug_events_request, total_dropped), 16u);
    REQUIRE_EQ(offsetof(km::drain_debug_events_request, total_published), 24u);
    REQUIRE_EQ(offsetof(km::drain_debug_events_request, events), 32u);
}

TEST_CASE(abi_sandbox_structs_match_kernel) {
    REQUIRE_EQ(sizeof(km::protect_sandbox_request), 32u);
    REQUIRE_EQ(offsetof(km::protect_sandbox_request, pid), 8u);
    REQUIRE_EQ(offsetof(km::protect_sandbox_request, flags), 12u);
    REQUIRE_EQ(offsetof(km::protect_sandbox_request, result), 16u);
    REQUIRE_EQ(offsetof(km::protect_sandbox_request, denials_so_far), 24u);

    REQUIRE_EQ(sizeof(km::net_log_register_request), 24u);

    // Driver MalwareSafe.h flag values, transcribed
    REQUIRE_EQ(km::SANDBOX_FLAG_BLOCK_PERSISTENCE, 0x00000001u);
    REQUIRE_EQ(km::SANDBOX_FLAG_BLOCK_DRIVER_INSTALL, 0x00000002u);
    REQUIRE_EQ(km::SANDBOX_FLAG_BLOCK_RAW_DISK, 0x00000004u);
    REQUIRE_EQ(km::SANDBOX_FLAG_BLOCK_KERNEL_HANDLE, 0x00000008u);
    REQUIRE_EQ(km::SANDBOX_FLAG_LOG_NETWORK, 0x00000010u);
    REQUIRE_EQ(km::SANDBOX_FLAG_BLOCK_CHILD_SPAWN, 0x00000020u);
    // Default mask matches the driver's FLAG_DEFAULT composition
    REQUIRE_EQ(km::SANDBOX_FLAG_DEFAULT,
               0x00000001u | 0x00000002u | 0x00000004u | 0x00000008u |
               0x00000010u);
}

TEST_CASE(abi_net_packet_pull_matches_kernel) {
    REQUIRE_EQ(km::NET_PKT_PULL_RING_CAPACITY, 2048u);
    REQUIRE_EQ(km::NET_PKT_PULL_PAYLOAD_RETAIN, 256u);
    REQUIRE_EQ(km::NET_PKT_PULL_RECORD_SIZE, 384u);
    REQUIRE_EQ(km::NET_PKT_PULL_REQ_MAGIC, 0x4E50414Bu);
    REQUIRE_EQ(km::NET_PKT_PULL_RESP_MAGIC, 0x4E50414Du);

    REQUIRE_EQ(sizeof(km::net_packet_pull_request), 24u);
    REQUIRE_EQ(sizeof(km::net_packet_pull_response_header), 16u);
    REQUIRE_EQ(sizeof(km::net_packet_record), 384u);
    // Record layout: fixed header + 256 payload + 60 pad
    REQUIRE_EQ(offsetof(km::net_packet_record, tcp_seq), 8u);
    REQUIRE_EQ(offsetof(km::net_packet_record, local_port), 28u);
    REQUIRE_EQ(offsetof(km::net_packet_record, local_addr), 36u);
    REQUIRE_EQ(offsetof(km::net_packet_record, payload), 68u);
    REQUIRE_EQ(sizeof(km::net_packet_record{}.payload), 256u);
}

// ---------------------------------------------------------------------------
// IOCTL code parity: UM make() must equal the driver's make() and the
// canonical CTL_CODE expansion for every dispatched function number
// ---------------------------------------------------------------------------

TEST_CASE(abi_ioctl_formula_matches_ctl_code) {
    constexpr DWORD device_unknown = 0x22u;   // FILE_DEVICE_UNKNOWN
    constexpr DWORD method_buffered = 0u;     // METHOD_BUFFERED
    constexpr DWORD any_access = 0u;          // FILE_ANY_ACCESS
    const auto ctl = [&](DWORD fn) {
        return (device_unknown << 16) | (fn << 2) | method_buffered | any_access;
    };

    // Function numbering mirrors the driver's kFunctionBase = 0x800
    REQUIRE_EQ(ioctl_codes::DTB(), ctl(0x800));
    REQUIRE_EQ(ioctl_codes::PHYS(), ctl(0x801));
    REQUIRE_EQ(ioctl_codes::BASE(), ctl(0x802));
    REQUIRE_EQ(ioctl_codes::RC(), ctl(0x804));
    REQUIRE_EQ(ioctl_codes::CR(), ctl(0x805));
    REQUIRE_EQ(ioctl_codes::AM(), ctl(0x806));
    REQUIRE_EQ(ioctl_codes::FM(), ctl(0x807));

    REQUIRE_EQ(ioctl_codes::TCTX(), ctl(0x809));
    REQUIRE_EQ(ioctl_codes::TENUM(), ctl(0x80A));
    REQUIRE_EQ(ioctl_codes::TSR(), ctl(0x80B));
    REQUIRE_EQ(ioctl_codes::QM(), ctl(0x80C));
    REQUIRE_EQ(ioctl_codes::PM(), ctl(0x80D));
    REQUIRE_EQ(ioctl_codes::ER(), ctl(0x80E));
    REQUIRE_EQ(ioctl_codes::RPEB(), ctl(0x80F));
    REQUIRE_EQ(ioctl_codes::SDF(), ctl(0x810));
    REQUIRE_EQ(ioctl_codes::MEX(), ctl(0x811));
    REQUIRE_EQ(ioctl_codes::V2P(), ctl(0x812));

    REQUIRE_EQ(ioctl_codes::NCON(), ctl(0x813));
    REQUIRE_EQ(ioctl_codes::NCAP(), ctl(0x814));
    REQUIRE_EQ(ioctl_codes::NCPG(), ctl(0x815));
    REQUIRE_EQ(ioctl_codes::NDNS(), ctl(0x816));
    REQUIRE_EQ(ioctl_codes::NFLT(), ctl(0x817));
    REQUIRE_EQ(ioctl_codes::NSTS(), ctl(0x818));

    REQUIRE_EQ(ioctl_codes::EWFP(), ctl(0x819));
    REQUIRE_EQ(ioctl_codes::GSKT(), ctl(0x81A));
    REQUIRE_EQ(ioctl_codes::SNBF(), ctl(0x81B));
    REQUIRE_EQ(ioctl_codes::DTCP(), ctl(0x81C));

    REQUIRE_EQ(ioctl_codes::PINJ(), ctl(0x81D));
    REQUIRE_EQ(ioctl_codes::PMOD(), ctl(0x81E));
    REQUIRE_EQ(ioctl_codes::PRED(), ctl(0x81F));
    REQUIRE_EQ(ioctl_codes::STRM(), ctl(0x820));
    REQUIRE_EQ(ioctl_codes::DPIN(), ctl(0x821));
    REQUIRE_EQ(ioctl_codes::IHLD(), ctl(0x822));
    REQUIRE_EQ(ioctl_codes::CKIL(), ctl(0x823));
    REQUIRE_EQ(ioctl_codes::DNSS(), ctl(0x824));
    REQUIRE_EQ(ioctl_codes::BWMN(), ctl(0x825));
    REQUIRE_EQ(ioctl_codes::NIFS(), ctl(0x826));
    REQUIRE_EQ(ioctl_codes::PCEX(), ctl(0x827));
    REQUIRE_EQ(ioctl_codes::NFPR(), ctl(0x828));
    REQUIRE_EQ(ioctl_codes::EVTS(), ctl(0x836));   // 0x800 + 54

    REQUIRE_EQ(ioctl_codes::PSBX(), ctl(0x837));
    REQUIRE_EQ(ioctl_codes::USBX(), ctl(0x838));
    REQUIRE_EQ(ioctl_codes::NLOG(), ctl(0x839));
    REQUIRE_EQ(ioctl_codes::NPKT(), ctl(0x83A));
    REQUIRE_EQ(ioctl_codes::SSDT(), ctl(0x83B));
    REQUIRE_EQ(ioctl_codes::TQIF(), ctl(0x83C));
    REQUIRE_EQ(ioctl_codes::TTERM(), ctl(0x83D));
    REQUIRE_EQ(ioctl_codes::HCLS(), ctl(0x83E));

    REQUIRE_EQ(ioctl_codes::IDENT(), ctl(0x83F));
    REQUIRE_EQ(ioctl_codes::SHUTDOWN(), ctl(0x840));
    REQUIRE_EQ(ioctl_codes::LOGCTL(), ctl(0x841));
}

TEST_CASE(abi_ioctl_codes_are_distinct) {
    // A collision would route one handler's struct into another's parser —
    // with METHOD_BUFFERED that's an instant kernel infoleak/corruption
    const DWORD all[] = {
        ioctl_codes::DTB(), ioctl_codes::PHYS(), ioctl_codes::BASE(),
        ioctl_codes::RC(), ioctl_codes::CR(), ioctl_codes::AM(),
        ioctl_codes::FM(), ioctl_codes::TCTX(), ioctl_codes::TENUM(),
        ioctl_codes::TSR(), ioctl_codes::QM(), ioctl_codes::PM(),
        ioctl_codes::ER(), ioctl_codes::RPEB(), ioctl_codes::SDF(),
        ioctl_codes::MEX(), ioctl_codes::V2P(), ioctl_codes::NCON(),
        ioctl_codes::NCAP(), ioctl_codes::NCPG(), ioctl_codes::NDNS(),
        ioctl_codes::NFLT(), ioctl_codes::NSTS(), ioctl_codes::EWFP(),
        ioctl_codes::GSKT(), ioctl_codes::SNBF(), ioctl_codes::DTCP(),
        ioctl_codes::PINJ(), ioctl_codes::PMOD(), ioctl_codes::PRED(),
        ioctl_codes::STRM(), ioctl_codes::DPIN(), ioctl_codes::IHLD(),
        ioctl_codes::CKIL(), ioctl_codes::DNSS(), ioctl_codes::BWMN(),
        ioctl_codes::NIFS(), ioctl_codes::PCEX(), ioctl_codes::NFPR(),
        ioctl_codes::EVTS(), ioctl_codes::PSBX(), ioctl_codes::USBX(),
        ioctl_codes::NLOG(), ioctl_codes::NPKT(), ioctl_codes::SSDT(),
        ioctl_codes::TQIF(), ioctl_codes::TTERM(), ioctl_codes::HCLS(),
        ioctl_codes::IDENT(), ioctl_codes::SHUTDOWN(), ioctl_codes::LOGCTL(),
    };
    constexpr std::size_t kCount = sizeof(all) / sizeof(all[0]);
    for (std::size_t i = 0; i < kCount; ++i) {
        for (std::size_t j = i + 1; j < kCount; ++j) {
            if (all[i] == all[j]) {
                std::printf("  collision: index %zu and %zu both 0x%08lX\n",
                            i, j, static_cast<unsigned long>(all[i]));
            }
            REQUIRE_NE(all[i], all[j]);
        }
    }
}
