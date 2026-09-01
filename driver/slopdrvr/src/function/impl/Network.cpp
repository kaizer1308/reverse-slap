#include "../Functions.h"
#include "../../imports/Defs.h"
#include "driver/Strong.h"
#include "../CoreSecurity.h"
#include "../Struct.h"
#include "../KernelLayout.h"
#include "../MalwareSafe.h"
#include <ndis.h>
#include <ndis/nbl.h>
#include <ndis/nblaccessors.h>
#include <ndis/nblapi.h>
#include <fwpmk.h>


#ifndef AF_INET
#define AF_INET 2
#endif

#ifndef AF_INET6
#define AF_INET6 23
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

#define FWPS_INJECTION_TYPE_STREAM    0x00000001
#define FWPS_INJECTION_TYPE_TRANSPORT 0x00000002
#define FWPS_INJECTION_TYPE_NETWORK   0x00000004
#define FWPS_INJECTION_TYPE_FORWARD   0x00000008

typedef struct _SLOP_WSACMSGHDR {
    SIZE_T cmsg_len;
    INT cmsg_level;
    INT cmsg_type;
} SLOP_WSACMSGHDR;

typedef struct _FWPS_TRANSPORT_SEND_PARAMS0_COMPAT {
    UCHAR* remoteAddress;
    ULONG remoteScopeId;
    SLOP_WSACMSGHDR* controlData;
    ULONG controlDataLength;
} FWPS_TRANSPORT_SEND_PARAMS0_COMPAT;

#define SLOP_ENDPOINT_PID_CACHE_SIZE 128


#ifdef SLOP_NET_DEBUG


#define NET_DBG(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[SLOP-NET] " fmt "\n", ##__VA_ARGS__); } while(0)

#define NET_ERR(fmt, ...) \
    do { if (_DbgPrintEx) _DbgPrintEx(77, 0, "[SLOP-NET][ERR] " fmt "\n", ##__VA_ARGS__); } while(0)

#else
#define NET_DBG(fmt, ...) ((void)0)
#define NET_ERR(fmt, ...) ((void)0)
#endif


typedef struct _FWPS_CALLOUT2_COMPAT {
    GUID   calloutKey;
    UINT32 flags;
    PVOID  classifyFn;
    PVOID  notifyFn;
    PVOID  flowDeleteFn;
} FWPS_CALLOUT2_COMPAT;

typedef FWP_ACTION_TYPE FWP_ACTION_TYPE_;
typedef FWP_VALUE0 FWP_VALUE0_COMPAT;
typedef FWP_BYTE_BLOB FWP_BYTE_BLOB_COMPAT;
typedef FWP_CONDITION_VALUE0 FWP_CONDITION_VALUE0_COMPAT;
typedef FWPM_FILTER_CONDITION0 FWPM_FILTER_CONDITION0_COMPAT;
typedef FWPM_ACTION0 FWPM_ACTION0_COMPAT;
typedef FWPM_FILTER0 FWPM_FILTER0_COMPAT;
typedef FWPM_CALLOUT0 FWPM_CALLOUT0_COMPAT;
typedef FWPM_SUBLAYER0 FWPM_SUBLAYER0_COMPAT;

typedef struct _FWPS_INCOMING_VALUE0_COMPAT {
    FWP_VALUE0_COMPAT value;
} FWPS_INCOMING_VALUE0_COMPAT;

typedef struct _FWPS_INCOMING_VALUES0_COMPAT {
    UINT16 layerId;
    UINT16 reserved;
    UINT32 valueCount;
    FWPS_INCOMING_VALUE0_COMPAT* incomingValue;
} FWPS_INCOMING_VALUES0_COMPAT;

typedef struct _FWPS_DISCARD_METADATA0_COMPAT {
    UINT64 handle;
    UINT32 flags;
    UINT32 reserved;
} FWPS_DISCARD_METADATA0_COMPAT;

typedef struct _FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT {
    UINT32 fragmentOffset;
    UINT32 fragmentLength;
    UINT32 flags;
    UINT32 reserved;
} FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT;

typedef struct _SCOPE_ID_COMPAT {
    ULONG Value;
} SCOPE_ID_COMPAT;

typedef struct _FWPS_INCOMING_METADATA_VALUES0_COMPAT {
    UINT32 currentMetadataValues;
    UINT32 flags;
    UINT64 reserved;
    FWPS_DISCARD_METADATA0_COMPAT discardMetadata;
    UINT64 flowHandle;
    UINT32 ipHeaderSize;
    UINT32 transportHeaderSize;
    FWP_BYTE_BLOB_COMPAT* processPath;
    UINT64 token;
    UINT64 processId;
    UINT32 sourceInterfaceIndex;
    UINT32 destinationInterfaceIndex;
    ULONG compartmentId;
    FWPS_INBOUND_FRAGMENT_METADATA0_COMPAT fragmentMetadata;
    ULONG pathMtu;
    HANDLE completionHandle;
    UINT64 transportEndpointHandle;
    SCOPE_ID_COMPAT remoteScopeId;
    SLOP_WSACMSGHDR* controlData;
    ULONG controlDataLength;
} FWPS_INCOMING_METADATA_VALUES0_COMPAT;

typedef struct _FWPS_CLASSIFY_OUT0_COMPAT {
    FWP_ACTION_TYPE_ actionType;
    UINT64 outContext;
    UINT64 filterId;
    UINT32 rights;
    UINT32 flags;
    UINT32 reserved;
} FWPS_CLASSIFY_OUT0_COMPAT;

#define FWP_ACTION_BLOCK_ FWP_ACTION_BLOCK
#define FWP_ACTION_PERMIT_ FWP_ACTION_PERMIT
#define FWP_ACTION_CONTINUE_ FWP_ACTION_CONTINUE
#define FWP_ACTION_CALLOUT_TERMINATING_ FWP_ACTION_CALLOUT_TERMINATING
#define FWP_EMPTY_ FWP_EMPTY
#define FWP_CONDITION_FLAG_IS_LOOPBACK_ FWP_CONDITION_FLAG_IS_LOOPBACK
#define FWPS_METADATA_FIELD_PROCESS_ID_ 0x00000020
#define FWPS_RIGHT_ACTION_WRITE_ 0x00000001
#define FWPS_CLASSIFY_OUT_FLAG_ABSORB_ 0x00000001


typedef NTSTATUS(NTAPI* fn_FwpsCalloutRegister2)(
    PVOID deviceObject, const FWPS_CALLOUT2_COMPAT* callout,
    UINT32* calloutId);
typedef NTSTATUS(NTAPI* fn_FwpsCalloutUnregisterById0)(UINT32 calloutId);
typedef NTSTATUS(NTAPI* fn_FwpmEngineOpen0)(
    const wchar_t* serverName, UINT32 authnService,
    PVOID authIdentity, PVOID session, HANDLE* engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmEngineClose0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionBegin0)(HANDLE engineHandle, UINT32 flags);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionCommit0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmTransactionAbort0)(HANDLE engineHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutAdd0)(
    HANDLE engineHandle, const FWPM_CALLOUT0_COMPAT* callout,
    PVOID sd, UINT32* id);
typedef NTSTATUS(NTAPI* fn_FwpmSubLayerAdd0)(
    HANDLE engineHandle, const FWPM_SUBLAYER0_COMPAT* subLayer, PVOID sd);
typedef NTSTATUS(NTAPI* fn_FwpmFilterAdd0)(
    HANDLE engineHandle, const FWPM_FILTER0_COMPAT* filter,
    PVOID sd, UINT64* id);
typedef NTSTATUS(NTAPI* fn_FwpmFilterDeleteById0)(HANDLE engineHandle, UINT64 filterId);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDeleteById0)(HANDLE engineHandle, UINT32 calloutId);
typedef NTSTATUS(NTAPI* fn_FwpmSubLayerDeleteByKey0)(HANDLE engineHandle, const GUID* key);
typedef NTSTATUS(NTAPI* fn_FwpmFilterCreateEnumHandle0_NET)(
    HANDLE engineHandle, const VOID* enumTemplate, HANDLE* enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmFilterDestroyEnumHandle0_NET)(
    HANDLE engineHandle, HANDLE enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmFilterEnum0_NET)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
    FWPM_FILTER0_COMPAT*** entries, UINT32* numEntriesReturned);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutCreateEnumHandle0_NET)(
    HANDLE engineHandle, const VOID* enumTemplate, HANDLE* enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDestroyEnumHandle0_NET)(
    HANDLE engineHandle, HANDLE enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutEnum0_NET)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
    FWPM_CALLOUT0_COMPAT*** entries, UINT32* numEntriesReturned);
typedef VOID(NTAPI* fn_FwpmFreeMemory0_NET)(VOID** p);


static const GUID GUID_LAYER_INBOUND_V4 =
    { 0x5926dfc8, 0xe3cf, 0x4426, { 0xa2, 0x83, 0xdc, 0x39, 0x3f, 0x5d, 0x0f, 0x9d } };

static const GUID GUID_LAYER_OUTBOUND_V4 =
    { 0x09e61aea, 0xd214, 0x46e2, { 0x9b, 0x21, 0xb2, 0x6b, 0x0b, 0x2f, 0x28, 0xc8 } };

static const GUID GUID_LAYER_DATAGRAM_V4 =
    { 0x3d08bf4e, 0x45f6, 0x4930, { 0xa9, 0x22, 0x41, 0x70, 0x98, 0xe2, 0x00, 0x27 } };

static const GUID GUID_LAYER_ALE_CONNECT_V4 =
    { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };

static const GUID GUID_LAYER_ALE_RECV_V4 =
    { 0xe1cd9fe7, 0xf4b5, 0x4273, { 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50 } };


#define FWPS_FIELD_IN_TRANS_V4_PROTOCOL      0
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR    1
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR   2
#define FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT    4
#define FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT   5


#define FWPS_FIELD_OUT_TRANS_V4_PROTOCOL     0
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR   1
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR  3
#define FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT   4
#define FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT  5

#define FWPS_FIELD_DATAGRAM_V4_PROTOCOL      0
#define FWPS_FIELD_DATAGRAM_V4_LOCAL_ADDR    1
#define FWPS_FIELD_DATAGRAM_V4_REMOTE_ADDR   2
#define FWPS_FIELD_DATAGRAM_V4_LOCAL_PORT    4
#define FWPS_FIELD_DATAGRAM_V4_REMOTE_PORT   5
#define FWPS_FIELD_DATAGRAM_V4_DIRECTION     9


#define FWPS_FIELD_ALE_V4_IP_LOCAL_ADDR     1
#define FWPS_FIELD_ALE_V4_IP_LOCAL_PORT     3
#define FWPS_FIELD_ALE_V4_IP_PROTOCOL       4
#define FWPS_FIELD_ALE_V4_IP_REMOTE_ADDR    5
#define FWPS_FIELD_ALE_V4_IP_REMOTE_PORT    6


namespace net_bw {
    enum : UINT32 {
        PID_SOURCE_NONE = 0,
        PID_SOURCE_METADATA = 1,
        PID_SOURCE_ENDPOINT = 2,
        PID_SOURCE_PORT_CACHE = 3,
        PID_SOURCE_UDP_CACHE = 4
    };

    enum : UINT32 {
        LAYER_INBOUND_TRANSPORT = 1,
        LAYER_OUTBOUND_TRANSPORT = 2,
        LAYER_DATAGRAM = 3
    };

    void record_traffic(UINT32 pid, UINT32 direction, UINT32 bytes,
                        UINT32 attribution_source, UINT32 layer,
                        UINT32 protocol, UINT32 local_port, UINT32 remote_port);
    void init_lock();
}
namespace net_mod {
    BOOLEAN apply_modifications(UINT8* data, UINT32* data_len, UINT32 max_len,
                                UINT32 direction, UINT32 protocol,
                                UINT32 port, UINT32 pid);
    BOOLEAN has_active_rules();
    LONG active_rule_count();
    LONG64 current_generation();
}
namespace net_stream {
    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len);
    BOOLEAN has_active_streams();
    BOOLEAN get_first_active_stream(UINT32* src_port, UINT32* dst_port,
                                    UINT32* pid, UINT8* src_addr, UINT8* dst_addr);
    void cleanup();
}

static UINT32 slop_resolve_packet_pid(UINT64 endpoint_handle,
                                      UINT32 protocol,
                                      UINT32 local_port,
                                      UINT32 remote_port);
static UINT32 slop_lookup_cached_port_pid(UINT32 protocol,
                                          UINT32 local_port,
                                          UINT32 remote_port);
static VOID slop_store_cached_port_pid(UINT32 protocol,
                                       UINT32 port,
                                       UINT32 pid);
static NTSTATUS slop_refresh_pid_cache_for_process(UINT32 target_pid,
                                                   UINT32 protocol_filter);
static VOID slop_store_cached_endpoint_pid(UINT64 endpoint_handle,
                                           UINT32 protocol,
                                           UINT32 local_port,
                                           UINT32 pid);
static __forceinline BOOLEAN slop_can_query_system_handles();
static void afd_init_offsets();

namespace net_capture {
    void NTAPI classify_inbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_outbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_datagram_v4(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_ale_connect(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    void NTAPI classify_ale_recv(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut);
    NTSTATUS NTAPI callout_notify(UINT32 notifyType, const GUID* filterKey, const void* filter);
    static ULONG status_to_win32(NTSTATUS status);
}
namespace net_fingerprint {
    inline KSPIN_LOCK g_fp_lock;
    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl);
    BOOLEAN is_active();
    void cleanup();
}
namespace net_dpi {
    NTSTATUS init();
    NTSTATUS start();
    void stop();
    void analyze_packet(UINT64 timestamp, UINT32 direction, UINT32 protocol,
                        UINT32 src_port, UINT32 dst_port,
                        const UINT8* src_addr, const UINT8* dst_addr,
                        UINT32 af, UINT32 pid,
                        const UINT8* payload, UINT32 payload_len);
    BOOLEAN is_active();
    LONG entry_count();
    void cleanup();
}
namespace net_intercept {
    void init_lock();
    BOOLEAN try_hold_packet(UINT32 direction, UINT32 protocol,
                            UINT32 src_port, UINT32 dst_port,
                            const UINT8* src_addr, const UINT8* dst_addr,
                            UINT32 af, UINT32 pid,
                            const UINT8* payload, UINT32 payload_len,
                            UINT32 payload_flags);
    BOOLEAN is_active();
    void cleanup();
}
namespace net_redirect {
    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32 pid, UINT32* new_port, UINT8* new_addr,
                           UINT32* matched_rule_id, LONG* match_before, LONG* match_after);
    void record_redirect_flow(UINT32 rule_id, UINT32 protocol, UINT32 af, UINT32 pid,
                              const UINT8* local_addr, UINT32 local_port,
                              const UINT8* original_remote_addr, UINT32 original_remote_port,
                              const UINT8* redirected_remote_addr, UINT32 redirected_remote_port,
                              const UINT8* injected_local_addr, UINT32 injected_local_port,
                              const UINT8* injected_remote_addr, UINT32 injected_remote_port,
                              UINT64 endpoint_handle, UINT32 compartment_id,
                              UINT32 interface_index, UINT32 sub_interface_index);
    BOOLEAN find_reverse_redirect(UINT32 protocol, UINT32 af, UINT32 pid,
                                  const UINT8* local_addr, UINT32 local_port,
                                  const UINT8* remote_addr, UINT32 remote_port,
                                  UINT64 endpoint_handle, UINT32 compartment_id,
                                  UINT32 interface_index, UINT32 sub_interface_index,
                                  UINT32* rule_id, UINT8* original_remote_addr,
                                  UINT32* original_remote_port, UINT32* flow_pid,
                                  LONG* active_flow_count);
    void init_lock();
    void cleanup();
    BOOLEAN has_active_rules();
}
namespace net_dns_spoof {
    BOOLEAN check_spoof(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl);
    BOOLEAN inspect_spoof_rule(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl,
                               UINT32* out_rule_id, char* out_rule_domain, UINT32 out_rule_domain_len,
                               LONG* match_before, LONG* match_after, BOOLEAN increment_match);
    BOOLEAN has_active_rules();
    void cleanup();
}
namespace net_bw {
    void init_lock();
    BOOLEAN is_active();
    void cleanup();
}
namespace net_inject {
    inline constexpr UINT32 INJECT_FLAG_RAW_TRANSPORT = 0x80000000u;
    struct inject_metadata {
        UINT64 endpoint_handle;
        UINT32 compartment_id;
        UINT32 interface_index;
        UINT32 sub_interface_index;
        UINT32 remote_scope_id;
    };
    BOOLEAN resolve_inject_functions();
    BOOLEAN prepare_injection_runtime();
    NTSTATUS inject_packet(p_packet_inject_request request);
    NTSTATUS inject_packet(p_packet_inject_request request, const inject_metadata* metadata);
    void cleanup();
    extern HANDLE g_inject_handle_v4;
    extern HANDLE g_inject_handle_net_v4;
    typedef UINT32(NTAPI* fn_FwpsQueryPacketInjectionState0)(
        HANDLE injectionHandle, PVOID netBufferList, HANDLE* injectionContext);
    extern fn_FwpsQueryPacketInjectionState0 _FwpsQueryPacketInjectionState0;
}

static __forceinline net_inject::inject_metadata make_inject_metadata(
    const FWPS_INCOMING_METADATA_VALUES0_COMPAT* meta) {
    net_inject::inject_metadata result = {};
    if (meta) {
        result.endpoint_handle = meta->transportEndpointHandle;
        result.compartment_id = meta->compartmentId;
        result.interface_index = meta->sourceInterfaceIndex;
        result.sub_interface_index = 0;
        result.remote_scope_id = meta->remoteScopeId.Value;
    }
    return result;
}
namespace net_checksum {
    UINT16 ip_checksum(const UINT8* ip_header, UINT32 header_len);
    UINT16 tcp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* tcp_data, UINT32 tcp_len);
    UINT16 udp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* udp_data, UINT32 udp_len);
    void recalculate_transport_checksums(UINT8* ip_header, UINT32 total_len);
}
namespace net_seq_delta {
    SEQ_DELTA_ENTRY* find_or_create(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
    BOOLEAN apply_delta(UINT8* tcp_header, UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound);
    void record_size_change(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound, LONG32 delta);
    void cleanup_expired();
    void handle_fin_rst(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
}
namespace net_fragment {
    UINT8* process_fragment(const UINT8* ip_header, UINT32 total_packet_len, UINT32* out_reassembled_len);
    void init();
    void cleanup();
    void cleanup_expired();
}
namespace net_udp_cache {
    UINT32 lookup(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port);
    void store(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, UINT32 pid);
    void cleanup_expired();
}

namespace net_capture {


    inline fn_FwpsCalloutRegister2       _FwpsCalloutRegister2       = nullptr;
    inline fn_FwpsCalloutUnregisterById0 _FwpsCalloutUnregisterById0 = nullptr;
    inline fn_FwpmEngineOpen0            _FwpmEngineOpen0            = nullptr;
    inline fn_FwpmEngineClose0           _FwpmEngineClose0           = nullptr;
    inline fn_FwpmTransactionBegin0      _FwpmTransactionBegin0      = nullptr;
    inline fn_FwpmTransactionCommit0     _FwpmTransactionCommit0     = nullptr;
    inline fn_FwpmTransactionAbort0      _FwpmTransactionAbort0      = nullptr;
    inline fn_FwpmCalloutAdd0            _FwpmCalloutAdd0            = nullptr;
    inline fn_FwpmSubLayerAdd0           _FwpmSubLayerAdd0           = nullptr;
    inline fn_FwpmFilterAdd0             _FwpmFilterAdd0             = nullptr;
    inline fn_FwpmFilterDeleteById0      _FwpmFilterDeleteById0      = nullptr;
    inline fn_FwpmCalloutDeleteById0     _FwpmCalloutDeleteById0     = nullptr;
    inline fn_FwpmSubLayerDeleteByKey0   _FwpmSubLayerDeleteByKey0   = nullptr;
    inline fn_FwpmFilterCreateEnumHandle0_NET  _FwpmFilterCreateEnumHandle0  = nullptr;
    inline fn_FwpmFilterDestroyEnumHandle0_NET _FwpmFilterDestroyEnumHandle0 = nullptr;
    inline fn_FwpmFilterEnum0_NET              _FwpmFilterEnum0              = nullptr;
    inline fn_FwpmCalloutCreateEnumHandle0_NET _FwpmCalloutCreateEnumHandle0 = nullptr;
    inline fn_FwpmCalloutDestroyEnumHandle0_NET _FwpmCalloutDestroyEnumHandle0 = nullptr;
    inline fn_FwpmCalloutEnum0_NET             _FwpmCalloutEnum0             = nullptr;
    inline fn_FwpmFreeMemory0_NET              _FwpmFreeMemory0              = nullptr;


    inline volatile LONG g_wfp_initialized = 0;
    inline volatile LONG g_wfp_degraded = 0;
    inline volatile LONG g_capture_active = 0;
    inline volatile LONG64 g_hot_filter_rejects = 0;
    inline HANDLE g_engine_handle = nullptr;
    inline PDEVICE_OBJECT g_device_object = nullptr;


    inline UINT32 g_callout_id_inbound = 0;
    inline UINT32 g_callout_id_outbound = 0;
    inline UINT32 g_callout_id_datagram = 0;
    inline UINT32 g_callout_id_ale_connect = 0;
    inline UINT32 g_callout_id_ale_recv = 0;
    inline UINT32 g_fwpm_callout_id_inbound = 0;
    inline UINT32 g_fwpm_callout_id_outbound = 0;
    inline UINT32 g_fwpm_callout_id_datagram = 0;
    inline UINT32 g_fwpm_callout_id_ale_connect = 0;
    inline UINT32 g_fwpm_callout_id_ale_recv = 0;
    inline UINT64 g_filter_id_inbound = 0;
    inline UINT64 g_filter_id_outbound = 0;
    inline UINT64 g_filter_id_datagram = 0;
    inline UINT64 g_filter_id_ale_connect = 0;
    inline UINT64 g_filter_id_ale_recv = 0;


    static const GUID GUID_SLOP_CALLOUT_INBOUND =
        { 0x7a8b3c1d, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6 } };
    static const GUID GUID_SLOP_CALLOUT_OUTBOUND =
        { 0x7a8b3c1e, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf7 } };
    static const GUID GUID_SLOP_CALLOUT_DATAGRAM =
        { 0x7a8b3c22, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xfb } };
    static const GUID GUID_SLOP_CALLOUT_ALE_CONNECT =
        { 0x7a8b3c20, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf9 } };
    static const GUID GUID_SLOP_CALLOUT_ALE_RECV =
        { 0x7a8b3c21, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xfa } };
    static const GUID GUID_SLOP_SUBLAYER =
        { 0x7a8b3c1f, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf8 } };
    static const GUID GUID_SLOP_PROVIDER =
        { 0x7a8b3c23, 0x2e4f, 0x5a6b, { 0x8c, 0x9d, 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xfc } };
    static const UINT32 WFP_BFE_AUTH_SERVICE = 0x0000000A;
    static const GUID GUID_CONDITION_ALE_APP_ID =
        { 0xd78e1e87, 0x8644, 0x4ea5, { 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71 } };
    static const GUID GUID_CONDITION_ALE_ORIGINAL_APP_ID =
        { 0x0e6cd086, 0xe1fb, 0x4212, { 0x84, 0x2f, 0x8a, 0x9f, 0x99, 0x3f, 0xb3, 0xf6 } };


    inline UINT32 g_filter_pid = 0;
    inline UINT32 g_filter_port = 0;
    inline UINT32 g_filter_protocol = 0;
    inline UINT8  g_filter_ip[16] = {};
    inline UINT32 g_max_payload = NET_PKT_MAX_PAYLOAD;


    #define RING_BUFFER_SIZE 2048
    inline NET_PACKET_ENTRY* g_ring_buffer = nullptr;
    inline volatile LONG g_ring_head = 0;
    inline volatile LONG g_ring_tail = 0;
    inline volatile LONG g_ring_count = 0;
    inline KSPIN_LOCK g_ring_lock;
    inline volatile LONG g_total_captured = 0;
    inline volatile LONG g_total_dropped = 0;


    inline volatile LONG64 g_global_bytes_sent = 0;
    inline volatile LONG64 g_global_bytes_recv = 0;
    inline volatile LONG64 g_global_pkts_sent = 0;
    inline volatile LONG64 g_global_pkts_recv = 0;

    static ULONG runtime_build_number() {
        if (!_RtlGetVersion) {
            return 0;
        }
        RTL_OSVERSIONINFOW version = {};
        version.dwOSVersionInfoSize = sizeof(version);
        if (!NT_SUCCESS(_RtlGetVersion(&version))) {
            return 0;
        }
        return version.dwBuildNumber;
    }

    static BOOLEAN startup_wfp_degraded_for_build(ULONG build) {
        return build >= 26200;
    }


    #define DNS_RING_SIZE 256
    inline NET_DNS_ENTRY* g_dns_ring = nullptr;
    inline volatile LONG g_dns_head = 0;
    inline volatile LONG g_dns_tail = 0;
    inline volatile LONG g_dns_count = 0;
    inline KSPIN_LOCK g_dns_lock;
    inline volatile LONG g_total_dns = 0;


    #define MAX_FILTER_RULES 64
    typedef struct _ACTIVE_FILTER_RULE {
        UINT32 rule_id;
        UINT32 action;
        UINT32 direction;
        UINT32 protocol;
        UINT32 pid;
        UINT32 port;
        UINT8  ip_addr[16];
        UINT8  ip_mask[16];
        volatile LONG active;
    } ACTIVE_FILTER_RULE;

    inline ACTIVE_FILTER_RULE g_filter_rules[MAX_FILTER_RULES] = {};
    inline volatile LONG g_next_rule_id = 1;
    inline volatile LONG g_active_rule_count = 0;


    inline SEQ_DELTA_ENTRY g_seq_delta[MAX_SEQ_DELTA_ENTRIES] = {};
    inline KSPIN_LOCK g_seq_delta_lock;


    inline FRAGMENT_ENTRY* g_fragment_entries = nullptr;
    inline KSPIN_LOCK g_fragment_lock;


    inline UDP_FLOW_ENTRY g_udp_flow[MAX_UDP_FLOW_ENTRIES] = {};
    inline KSPIN_LOCK g_udp_flow_lock;


    #define PID_PATH_CACHE_SIZE 64
    typedef struct _PID_PATH_CACHE_ENTRY {
        UINT32 pid;
        UINT32 padding;
        UINT64 timestamp;
        char path[260];
        UINT32 padding2;
    } PID_PATH_CACHE_ENTRY;
    inline PID_PATH_CACHE_ENTRY g_pid_path_cache[PID_PATH_CACHE_SIZE] = {};
    inline KSPIN_LOCK g_pid_path_lock;


    __forceinline BOOLEAN is_zero_ip(const UINT8* ip) {
        for (int i = 0; i < 16; i++) {
            if (ip[i] != 0) return FALSE;
        }
        return TRUE;
    }

    __forceinline BOOLEAN ip_matches(const UINT8* pkt_ip, const UINT8* rule_ip,
                                      const UINT8* rule_mask, UINT32 af) {
        UINT32 len = (af == 23) ? 16 : 4;
        for (UINT32 i = 0; i < len; i++) {
            if ((pkt_ip[i] & rule_mask[i]) != (rule_ip[i] & rule_mask[i]))
                return FALSE;
        }
        return TRUE;
    }

    __forceinline void copy_ipv4_fixed_value(UINT32 address, UINT8* out_ip) {
        strong::kmemset(out_ip, 0, 16);
        out_ip[0] = (UINT8)((address >> 24) & 0xFF);
        out_ip[1] = (UINT8)((address >> 16) & 0xFF);
        out_ip[2] = (UINT8)((address >> 8) & 0xFF);
        out_ip[3] = (UINT8)(address & 0xFF);
    }

    __forceinline UINT32 copy_transport_bytes(void* layerData, UINT8* out_data, UINT32 max_len) {
        if (!layerData || !out_data || max_len == 0)
            return 0;

        __try {
            PNET_BUFFER_LIST nbl = (PNET_BUFFER_LIST)layerData;
            PNET_BUFFER first_nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (!first_nb) {
                return 0;
            }

            ULONG data_length = NET_BUFFER_DATA_LENGTH(first_nb);
            if (data_length == 0) {
                return 0;
            }

            ULONG copy_len = (data_length < max_len) ? data_length : max_len;
            ULONG copied = 0;
            PMDL mdl = NET_BUFFER_CURRENT_MDL(first_nb);
            ULONG mdl_offset = NET_BUFFER_CURRENT_MDL_OFFSET(first_nb);

            while (mdl && copied < copy_len) {
                PUCHAR mapped = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority | MdlMappingNoExecute);
                if (!mapped) {
                    break;
                }

                ULONG mdl_len = MmGetMdlByteCount(mdl);
                if (mdl_offset >= mdl_len) {
                    mdl_offset -= mdl_len;
                    mdl = mdl->Next;
                    continue;
                }

                ULONG avail = mdl_len - mdl_offset;
                ULONG chunk = ((copy_len - copied) < avail) ? (copy_len - copied) : avail;
                strong::kmemcpy(out_data + copied, mapped + mdl_offset, chunk);
                copied += chunk;
                mdl = mdl->Next;
                mdl_offset = 0;
            }

            if (copied == 0 && NET_BUFFER_CURRENT_MDL(first_nb)) {
            }

            return copied;
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }


    __forceinline UINT32 get_transport_data_length(void* layerData) {
        if (!layerData)
            return 0;
        __try {
            PNET_BUFFER_LIST nbl = reinterpret_cast<PNET_BUFFER_LIST>(layerData);
            PNET_BUFFER first_nb = NET_BUFFER_LIST_FIRST_NB(nbl);
            if (!first_nb)
                return 0;
            return NET_BUFFER_DATA_LENGTH(first_nb);
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            return 0;
        }
    }

    __forceinline BOOLEAN select_dns_payload(UINT8* data, UINT32 data_len,
                                             UINT32 local_port, UINT32 remote_port,
                                             UINT8** dns_data, UINT32* dns_len,
                                             UINT32* header_skip) {
        if (dns_data) *dns_data = nullptr;
        if (dns_len) *dns_len = 0;
        if (header_skip) *header_skip = 0;
        if (!data || data_len < 12 || (!dns_data && !dns_len)) return FALSE;

        UINT8* selected = data;
        UINT32 selected_len = data_len;
        UINT32 skip = 0;

        if (data_len >= 20) {
            UINT16 udp_src = ((UINT16)data[0] << 8) | data[1];
            UINT16 udp_dst = ((UINT16)data[2] << 8) | data[3];
            UINT16 udp_len = ((UINT16)data[4] << 8) | data[5];
            BOOLEAN ports_match =
                ((udp_src == (UINT16)local_port || udp_src == (UINT16)remote_port ||
                  udp_dst == (UINT16)local_port || udp_dst == (UINT16)remote_port) &&
                 (udp_src == 53 || udp_dst == 53));
            if (ports_match && udp_len >= 20 && udp_len <= data_len) {
                selected = data + 8;
                selected_len = udp_len - 8;
                skip = 8;
            }
        }

        if (selected_len < 12) return FALSE;
        if (dns_data) *dns_data = selected;
        if (dns_len) *dns_len = selected_len;
        if (header_skip) *header_skip = skip;
        return TRUE;
    }

    __forceinline UINT32 udp_header_skip_if_present(const UINT8* data, UINT32 data_len,
                                                    UINT32 local_port, UINT32 remote_port) {
        if (!data || data_len < 8) return 0;
        UINT16 udp_src = ((UINT16)data[0] << 8) | data[1];
        UINT16 udp_dst = ((UINT16)data[2] << 8) | data[3];
        UINT16 udp_len = ((UINT16)data[4] << 8) | data[5];
        BOOLEAN ports_match =
            (udp_src == (UINT16)local_port && udp_dst == (UINT16)remote_port) ||
            (udp_src == (UINT16)remote_port && udp_dst == (UINT16)local_port);
        if (!ports_match) return 0;
        if (udp_len < 8 || udp_len > data_len) return 0;
        return 8;
    }

    __forceinline UINT32 parse_dns_name(const UINT8* dns_data, UINT32 offset,
                                         UINT32 data_len, char* out, UINT32 out_size) {
        UINT32 pos = offset;
        UINT32 out_pos = 0;
        UINT32 jumps = 0;
        BOOLEAN jumped = FALSE;
        UINT32 return_pos = 0;

        while (pos < data_len && out_pos < out_size - 1) {
            UINT8 label_len = dns_data[pos];
            if (label_len == 0) {
                pos++;
                break;
            }

            if ((label_len & 0xC0) == 0xC0) {
                if (pos + 1 >= data_len) break;
                if (!jumped) return_pos = pos + 2;
                UINT16 ptr_off = ((UINT16)(label_len & 0x3F) << 8) | dns_data[pos + 1];
                pos = ptr_off;
                jumped = TRUE;
                jumps++;
                if (jumps > 64) break;
                continue;
            }
            if (label_len > 63) break;
            pos++;
            if (pos + label_len > data_len) break;
            if (out_pos > 0 && out_pos < out_size - 1) {
                out[out_pos++] = '.';
            }
            for (UINT8 i = 0; i < label_len && out_pos < out_size - 1; i++) {
                out[out_pos++] = (char)dns_data[pos + i];
            }
            pos += label_len;
        }
        out[out_pos] = '\0';
        return jumped ? return_pos : pos;
    }

    __forceinline void dns_write16(UINT8* dst, UINT16 value) {
        dst[0] = (UINT8)(value >> 8);
        dst[1] = (UINT8)(value & 0xFF);
    }

    __forceinline void dns_write32(UINT8* dst, UINT32 value) {
        dst[0] = (UINT8)(value >> 24);
        dst[1] = (UINT8)((value >> 16) & 0xFF);
        dst[2] = (UINT8)((value >> 8) & 0xFF);
        dst[3] = (UINT8)(value & 0xFF);
    }

    __forceinline UINT16 dns_read16(const UINT8* src) {
        return ((UINT16)src[0] << 8) | src[1];
    }

    __forceinline UINT32 build_dns_spoof_response(const UINT8* query_data,
                                                  UINT32 query_len,
                                                  UINT32 qpos,
                                                  const UINT8* spoof_addr,
                                                  UINT32 spoof_af,
                                                  UINT32 spoof_ttl,
                                                  UINT8* out_data,
                                                  UINT32 out_cap,
                                                  UINT32* answer_offset,
                                                  UINT32* answer_size) {
        if (answer_offset) *answer_offset = 0;
        if (answer_size) *answer_size = 0;
        if (!query_data || !spoof_addr || !out_data) return 0;
        if (query_len < 12 || qpos == 0 || qpos + 4 > query_len) return 0;
        UINT16 qtype = dns_read16(query_data + qpos);
        UINT16 qclass = dns_read16(query_data + qpos + 2);
        UINT32 rdata_len = 0;
        if (qtype == 1 && spoof_af == AF_INET) {
            rdata_len = 4;
        } else if (qtype == 28 && spoof_af == AF_INET6) {
            rdata_len = 16;
        } else {
            return 0;
        }
        UINT32 question_len = qpos + 4;
        UINT32 total_len = question_len + 12 + rdata_len;
        if (total_len > out_cap) return 0;
        strong::kmemcpy(out_data, query_data, question_len);
        UINT16 query_flags = dns_read16(query_data + 2);
        UINT16 response_flags = (UINT16)(0x8000u | 0x0080u | (query_flags & 0x0110u));
        dns_write16(out_data + 2, response_flags);
        dns_write16(out_data + 4, 1);
        dns_write16(out_data + 6, 1);
        dns_write16(out_data + 8, 0);
        dns_write16(out_data + 10, 0);
        UINT32 pos = question_len;
        out_data[pos++] = 0xC0;
        out_data[pos++] = 0x0C;
        dns_write16(out_data + pos, qtype);
        pos += 2;
        dns_write16(out_data + pos, qclass);
        pos += 2;
        dns_write32(out_data + pos, spoof_ttl);
        pos += 4;
        dns_write16(out_data + pos, (UINT16)rdata_len);
        pos += 2;
        if (answer_offset) *answer_offset = pos;
        if (answer_size) *answer_size = rdata_len;
        strong::kmemcpy(out_data + pos, spoof_addr, rdata_len);
        pos += rdata_len;
        return pos;
    }

    __forceinline BOOLEAN rewrite_dns_answers(UINT8* dns_data, UINT32 dns_len,
                                              UINT32 qpos, UINT16 ancount,
                                              const UINT8* spoof_addr, UINT32 spoof_af,
                                              UINT32 spoof_ttl, UINT16* spoofed_type,
                                              UINT32* answer_offset, UINT32* answer_size) {
        if (spoofed_type) *spoofed_type = 0;
        if (answer_offset) *answer_offset = 0;
        if (answer_size) *answer_size = 0;
        if (!dns_data || !spoof_addr || dns_len < 12 || qpos == 0 || qpos + 4 > dns_len)
            return FALSE;
        UINT32 ans_pos = qpos + 4;
        for (UINT16 ai = 0; ai < ancount && ans_pos < dns_len; ai++) {
            if ((dns_data[ans_pos] & 0xC0) == 0xC0) {
                ans_pos += 2;
            } else {
                while (ans_pos < dns_len && dns_data[ans_pos] != 0) {
                    if ((dns_data[ans_pos] & 0xC0) == 0xC0) { ans_pos += 2; goto dns_rewrite_after_name; }
                    if (dns_data[ans_pos] > 63) break;
                    ans_pos += dns_data[ans_pos] + 1;
                }
                ans_pos++;
            }
            dns_rewrite_after_name:
            if (ans_pos + 10 > dns_len) break;
            UINT16 atype = dns_read16(dns_data + ans_pos);
            ans_pos += 4;
            UINT32 ttl_pos = ans_pos;
            ans_pos += 4;
            UINT16 rdlength = dns_read16(dns_data + ans_pos);
            ans_pos += 2;
            if (atype == 1 && rdlength == 4 && ans_pos + 4 <= dns_len && spoof_af == AF_INET) {
                dns_write32(dns_data + ttl_pos, spoof_ttl);
                strong::kmemcpy(&dns_data[ans_pos], spoof_addr, 4);
                if (spoofed_type) *spoofed_type = atype;
                if (answer_offset) *answer_offset = ans_pos;
                if (answer_size) *answer_size = 4;
                return TRUE;
            }
            if (atype == 28 && rdlength == 16 && ans_pos + 16 <= dns_len && spoof_af == AF_INET6) {
                dns_write32(dns_data + ttl_pos, spoof_ttl);
                strong::kmemcpy(&dns_data[ans_pos], spoof_addr, 16);
                if (spoofed_type) *spoofed_type = atype;
                if (answer_offset) *answer_offset = ans_pos;
                if (answer_size) *answer_size = 16;
                return TRUE;
            }
            ans_pos += rdlength;
        }
        return FALSE;
    }


    __forceinline UINT32 check_filter_rules(UINT32 direction, UINT32 protocol,
                                             UINT32 pid, UINT32 local_port, UINT32 remote_port,
                                             const UINT8* remote_ip, UINT32 af) {

        for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
            if (g_filter_rules[i].active != 1) continue;
            const ACTIVE_FILTER_RULE* r = &g_filter_rules[i];

            if (r->direction != 2 && r->direction != direction) continue;
            if (r->protocol != 0 && r->protocol != protocol) continue;
            if (r->pid != 0 && r->pid != pid) continue;
            if (r->port != 0 && r->port != local_port && r->port != remote_port) continue;
            if (!is_zero_ip(r->ip_addr)) {
                if (!ip_matches(remote_ip, r->ip_addr, r->ip_mask, af))
                    continue;
            }
            return r->action;
        }
        return 0;
    }

    __forceinline BOOLEAN packet_matches_capture_filters(UINT32 protocol,
                                                          UINT32 pid,
                                                          UINT32 local_port,
                                                          UINT32 remote_port,
                                                          UINT32 af,
                                                          const UINT8* remote_ip) {
        if (g_filter_pid != 0 && pid != g_filter_pid) return FALSE;
        if (g_filter_port != 0 && local_port != g_filter_port && remote_port != g_filter_port) return FALSE;
        if (g_filter_protocol != 0 && protocol != g_filter_protocol) return FALSE;
        if (!is_zero_ip(g_filter_ip)) {
            UINT8 mask[16];
            strong::kmemset(mask, 0xFF, sizeof(mask));
            if (!remote_ip || !ip_matches(remote_ip, g_filter_ip, mask, af)) return FALSE;
        }
        return TRUE;
    }

    __forceinline void store_packet(UINT32 direction, UINT32 protocol,
                                     UINT32 pid, UINT32 local_port, UINT32 remote_port,
                                     UINT32 af, const UINT8* local_ip, const UINT8* remote_ip,
                                     const UINT8* payload_data, UINT32 payload_len) {
        if (!g_ring_buffer) return;

        UINT32 effective_pid = pid;
        if (!packet_matches_capture_filters(protocol, effective_pid, local_port, remote_port, af, remote_ip)) {
            _InterlockedIncrement64(&g_hot_filter_rejects);
            return;
        }

        UINT32 cap_len = payload_len;
        if (cap_len > g_max_payload) cap_len = g_max_payload;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_ring_lock, &old_irql);

        if (g_ring_count >= RING_BUFFER_SIZE) {
            g_ring_tail = (g_ring_tail + 1) % RING_BUFFER_SIZE;
            g_ring_count--;
            _InterlockedIncrement(&g_total_dropped);
        }

        NET_PACKET_ENTRY* entry = &g_ring_buffer[g_ring_head];
        strong::kmemset(entry, 0, sizeof(NET_PACKET_ENTRY));

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        entry->timestamp = ts.QuadPart;
        entry->pid = effective_pid;
        entry->protocol = protocol;
        entry->direction = direction;
        entry->payload_size = cap_len;
        entry->local_port = local_port;
        entry->remote_port = remote_port;
        entry->address_family = af;

        if (local_ip) {
            UINT32 copy_len = (af == 23) ? 16 : 4;
            strong::kmemcpy(entry->local_addr, local_ip, copy_len);
        }
        if (remote_ip) {
            UINT32 copy_len = (af == 23) ? 16 : 4;
            strong::kmemcpy(entry->remote_addr, remote_ip, copy_len);
        }
        if (payload_data && cap_len > 0) {
            strong::kmemcpy(entry->payload, payload_data, cap_len);
        }

        g_ring_head = (g_ring_head + 1) % RING_BUFFER_SIZE;
        g_ring_count++;
        _InterlockedIncrement(&g_total_captured);

        KeReleaseSpinLock(&g_ring_lock, old_irql);
    }


    __forceinline void store_dns_entry(UINT32 pid, const char* domain,
                                        UINT32 query_type, UINT32 response_code,
                                        const UINT8* resolved, UINT32 ttl) {
        if (!g_dns_ring) return;

        UINT32 effective_pid = pid;

        KIRQL old_irql;
        KeAcquireSpinLock(&g_dns_lock, &old_irql);

        if (g_dns_count >= DNS_RING_SIZE) {
            g_dns_tail = (g_dns_tail + 1) % DNS_RING_SIZE;
            g_dns_count--;
        }

        NET_DNS_ENTRY* entry = &g_dns_ring[g_dns_head];
        strong::kmemset(entry, 0, sizeof(NET_DNS_ENTRY));

        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);
        entry->timestamp = ts.QuadPart;
        entry->pid = effective_pid;
        entry->query_type = query_type;
        entry->response_code = response_code;
        entry->ttl = ttl;

        if (domain) {
            UINT32 i = 0;
            while (domain[i] && i < 259) {
                entry->domain[i] = domain[i];
                i++;
            }
            entry->domain[i] = '\0';
        }
        if (resolved) {
            strong::kmemcpy(entry->resolved_addr, resolved, 16);
        }

        g_dns_head = (g_dns_head + 1) % DNS_RING_SIZE;
        g_dns_count++;
        _InterlockedIncrement(&g_total_dns);

        KeReleaseSpinLock(&g_dns_lock, old_irql);
    }


    __forceinline void try_parse_dns(UINT32 pid, const UINT8* data, UINT32 data_len,
                                      UINT32 local_port, UINT32 remote_port) {
        if (local_port != 53 && remote_port != 53) return;
        if (data_len < 12) return;

        const UINT8* dns_data = data;
        UINT32 dns_len = data_len;

        if (data_len >= 20) {
            UINT16 udp_src = ((UINT16)data[0] << 8) | data[1];
            UINT16 udp_dst = ((UINT16)data[2] << 8) | data[3];
            UINT16 udp_len = ((UINT16)data[4] << 8) | data[5];
            BOOLEAN ports_match =
                ((udp_src == (UINT16)local_port || udp_src == (UINT16)remote_port ||
                  udp_dst == (UINT16)local_port || udp_dst == (UINT16)remote_port) &&
                 (udp_src == 53 || udp_dst == 53));
            if (ports_match && udp_len >= 20 && udp_len <= data_len) {
                dns_data = data + 8;
                dns_len = udp_len - 8;
            }
        }

        if (dns_len < 12) return;

        UINT16 flags = ((UINT16)dns_data[2] << 8) | dns_data[3];
        UINT16 qdcount = ((UINT16)dns_data[4] << 8) | dns_data[5];
        UINT16 ancount = ((UINT16)dns_data[6] << 8) | dns_data[7];
        UINT8  rcode = dns_data[3] & 0x0F;
        BOOLEAN is_response = (flags & 0x8000) != 0;

        if (qdcount == 0 || qdcount > 16) return;

        char domain[260] = {};
        UINT32 pos = 12;


        pos = parse_dns_name(dns_data, pos, dns_len, domain, sizeof(domain));
        if (pos == 0 || pos + 4 > dns_len) return;

        UINT16 qtype = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
        pos += 4;

        UINT8 resolved[16] = {};
        UINT32 ttl = 0;


        if (is_response && ancount > 0 && pos < dns_len) {
            for (UINT16 i = 0; i < ancount && pos < dns_len; i++) {

                if ((dns_data[pos] & 0xC0) == 0xC0) {
                    pos += 2;
                } else {
                    while (pos < dns_len && dns_data[pos] != 0) {
                        if ((dns_data[pos] & 0xC0) == 0xC0) { pos += 2; goto after_name; }
                        if (dns_data[pos] > 63) break;
                        pos += dns_data[pos] + 1;
                    }
                    pos++;
                }
                after_name:
                if (pos + 10 > dns_len) break;

                UINT16 atype = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
                pos += 4;
                ttl = ((UINT32)dns_data[pos] << 24) | ((UINT32)dns_data[pos+1] << 16) |
                      ((UINT32)dns_data[pos+2] << 8) | dns_data[pos+3];
                pos += 4;
                UINT16 rdlength = ((UINT16)dns_data[pos] << 8) | dns_data[pos + 1];
                pos += 2;

                if (atype == 1 && rdlength == 4 && pos + 4 <= dns_len) {
                    strong::kmemcpy(resolved, &dns_data[pos], 4);
                    break;
                } else if (atype == 28 && rdlength == 16 && pos + 16 <= dns_len) {
                    strong::kmemcpy(resolved, &dns_data[pos], 16);
                    break;
                }
                pos += rdlength;
            }
        }

        store_dns_entry(pid, domain, qtype, rcode, resolved, ttl);
    }

    __forceinline BOOLEAN should_process_packet_pipeline() {
        if (g_capture_active) return TRUE;
        if (g_active_rule_count != 0) return TRUE;
        if (net_bw::is_active()) return TRUE;
        if (net_intercept::is_active()) return TRUE;
        if (net_dpi::is_active()) return TRUE;
        if (net_fingerprint::is_active()) return TRUE;
        if (net_mod::has_active_rules()) return TRUE;
        if (net_redirect::has_active_rules()) return TRUE;
        if (net_dns_spoof::has_active_rules()) return TRUE;
        if (net_stream::has_active_streams()) return TRUE;
        if (malware_safe::any_sandboxed()) return TRUE;
        return FALSE;
    }


    void NTAPI classify_inbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;

        classifyOut->actionType = FWP_ACTION_PERMIT_;


        if (layerData && net_inject::_FwpsQueryPacketInjectionState0) {
            if (net_inject::g_inject_handle_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
            if (net_inject::g_inject_handle_net_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_net_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
        }

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

        __try {
        UINT8* pkt_data = nullptr;
        packet_inject_request* inj_buf = nullptr;
        __try {
            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;
            UINT8 local_ip[16] = {};
            UINT8 remote_ip[16] = {};
            UINT32 pid = 0;
            UINT32 pid_source = net_bw::PID_SOURCE_NONE;

            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_PROTOCOL) {
                protocol = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_PROTOCOL].value.uint8;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT) {
                local_port = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_LOCAL_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT) {
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_LOCAL_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, local_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_IN_TRANS_V4_REMOTE_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, remote_ip);
            }

            if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) != 0) {
                pid = (UINT32)inMetaValues->processId;
                if (pid != 0) pid_source = net_bw::PID_SOURCE_METADATA;
            }
            if (pid != 0 && inMetaValues->transportEndpointHandle != 0) {
                slop_store_cached_endpoint_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, pid);
            }
            if (pid == 0) {
                pid = slop_resolve_packet_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_ENDPOINT;
            }
            if (pid == 0) {
                pid = slop_lookup_cached_port_pid(protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_PORT_CACHE;
            }
            if (pid == 0 && protocol == 17) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                pid = net_udp_cache::lookup(rip, lip, (UINT16)remote_port, (UINT16)local_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_UDP_CACHE;
            }
            if (pid != 0) {
                slop_store_cached_port_pid(protocol, local_port, pid);
                slop_store_cached_port_pid(protocol, remote_port, pid);
                if (protocol == 17) {
                    UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                 ((UINT32)local_ip[2] << 8) | local_ip[3];
                    UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                 ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                    net_udp_cache::store(rip, lip, (UINT16)remote_port, (UINT16)local_port, pid);
                }
            }
            BOOLEAN capture_active_now = (g_capture_active != 0);
            BOOLEAN capture_filter_match = capture_active_now
                ? packet_matches_capture_filters(protocol, pid, local_port, remote_port, 2, remote_ip)
                : FALSE;
            if (capture_active_now && !capture_filter_match)
                _InterlockedIncrement64(&g_hot_filter_rejects);

            _InterlockedIncrement64(&g_global_pkts_recv);

            UINT32 rule_action = check_filter_rules(0, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                NET_DBG("classify_inbound: BLOCKED by filter rule proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            BOOLEAN malsafe_log_inbound = FALSE;
            if (pid != 0 && malware_safe::any_sandboxed()) {
                HANDLE pid_handle_check = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                if (malware_safe::sandbox_has_net_logging(pid_handle_check)) {
                    malsafe_log_inbound = TRUE;
                }
            }

            {
                UINT32 data_length = get_transport_data_length(layerData);
                _InterlockedExchangeAdd64(&g_global_bytes_recv, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 0, data_length, pid_source,
                    net_bw::LAYER_INBOUND_TRANSPORT, protocol, local_port, remote_port);

                BOOLEAN need_full_pipeline = FALSE;
                if (g_active_rule_count != 0) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_mod::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_intercept::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dpi::is_active() && (!capture_active_now || capture_filter_match)) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_fingerprint::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dns_spoof::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_redirect::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_stream::has_active_streams()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && malsafe_log_inbound) need_full_pipeline = TRUE;
                if (!need_full_pipeline && !capture_filter_match) __leave;
            }

            pkt_data = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, NET_PKT_MAX_PAYLOAD, 'pdNW');
            if (!pkt_data) __leave;
            inj_buf = (packet_inject_request*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(packet_inject_request), 'piNW');
            if (!inj_buf) __leave;

            UINT32 pkt_len = 0;
            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }

            if (pkt_len > 0 && net_redirect::has_active_rules()) {
                UINT8 original_remote_ip[16] = {};
                UINT32 original_remote_port = 0;
                UINT32 reverse_rule_id = 0;
                UINT32 reverse_flow_pid = 0;
                LONG reverse_flow_count = 0;
                net_inject::inject_metadata reverse_meta = make_inject_metadata(inMetaValues);
                if (net_redirect::find_reverse_redirect(protocol, 2, pid,
                        local_ip, local_port, remote_ip, remote_port,
                        reverse_meta.endpoint_handle, reverse_meta.compartment_id,
                        reverse_meta.interface_index, reverse_meta.sub_interface_index,
                        &reverse_rule_id, original_remote_ip,
                        &original_remote_port, &reverse_flow_pid,
                        &reverse_flow_count)) {
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 0;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = original_remote_port;
                    inj_buf->dst_port = local_port;
                    strong::kmemcpy(inj_buf->src_addr, original_remote_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                    UINT32 payload_skip = 0;
                    if (protocol == IPPROTO_TCP) {
                        inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                        payload_skip = 0;
                    } else if (protocol == IPPROTO_UDP) {
                        payload_skip = udp_header_skip_if_present(pkt_data, pkt_len, local_port, remote_port);
                    }
                    if (payload_skip > pkt_len) payload_skip = pkt_len;
                    inj_buf->payload_size = pkt_len - payload_skip;
                    if (inj_buf->payload_size > 0)
                        strong::kmemcpy(inj_buf->payload, pkt_data + payload_skip, inj_buf->payload_size);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    NTSTATUS reverse_status = net_inject::inject_packet(inj_buf, &reverse_meta);
                    if (NT_SUCCESS(reverse_status) && inj_buf->status == 0) {
                        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                    }
                    SD_LOG_PACKET("net_redirect::reverse_inject layer=in_trans rule_id=%u status=0x%08X win32=%lu request_status=%u protocol=%u pid=%u flow_pid=%u active_flows=%ld tuple_before=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u tuple_after=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u pkt_len=%u payload_skip=%u payload_size=%u raw_transport=%u action=blocked_original",
                        reverse_rule_id,
                        reverse_status,
                        net_capture::status_to_win32(reverse_status),
                        inj_buf->status,
                        protocol,
                        pid,
                        reverse_flow_pid,
                        reverse_flow_count,
                        local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                        remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
                        local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                        original_remote_ip[0], original_remote_ip[1], original_remote_ip[2], original_remote_ip[3], original_remote_port,
                        pkt_len,
                        payload_skip,
                        inj_buf->payload_size,
                        (inj_buf->tcp_flags & net_inject::INJECT_FLAG_RAW_TRANSPORT) ? 1u : 0u);
                    __leave;
                }
            }


            if (protocol == 17 && remote_port == 53 && net_dns_spoof::has_active_rules()) {
                UINT8* dns_data = nullptr;
                UINT32 dns_len = 0;
                UINT32 dns_skip = 0;
                if (select_dns_payload(pkt_data, pkt_len, local_port, remote_port, &dns_data, &dns_len, &dns_skip)) {
                    UINT16 dns_flags = ((UINT16)dns_data[2] << 8) | dns_data[3];
                    BOOLEAN is_dns_response = (dns_flags & 0x8000) != 0;
                    UINT16 qdcount = ((UINT16)dns_data[4] << 8) | dns_data[5];
                    UINT16 ancount = ((UINT16)dns_data[6] << 8) | dns_data[7];
                    char spoof_domain[260] = {};
                    UINT16 qtype = 0;
                    UINT32 qpos = 0;
                    if (qdcount > 0 && qdcount <= 16) {
                        qpos = parse_dns_name(dns_data, 12, dns_len, spoof_domain, sizeof(spoof_domain));
                        if (qpos != 0 && qpos + 4 <= dns_len) {
                            qtype = ((UINT16)dns_data[qpos] << 8) | dns_data[qpos + 1];
                        }
                    }
                    UINT8 spoof_addr[16] = {};
                    UINT32 spoof_af = 0;
                    UINT32 spoof_ttl = 0;
                    UINT32 spoof_rule_id = 0;
                    char spoof_rule_domain[DNS_SPOOF_MAX_DOMAIN] = {};
                    LONG match_before = 0;
                    LONG match_after = 0;
                    BOOLEAN eligible_response = is_dns_response && qpos != 0 && qpos + 4 <= dns_len && spoof_domain[0] != '\0';
                    BOOLEAN rule_match = net_dns_spoof::inspect_spoof_rule(spoof_domain, spoof_addr, &spoof_af, &spoof_ttl,
                        &spoof_rule_id, spoof_rule_domain, sizeof(spoof_rule_domain),
                        &match_before, &match_after, eligible_response);
                    SD_LOG_PACKET("net_dns_spoof::classify layer=in_trans direction=0 pid=%u ports=%u<-%u qr=%u flags=0x%04X qdcount=%u ancount=%u qtype=%u qname='%s' rule_id=%u rule_domain='%s' match=%u match_before=%ld match_after=%ld spoof_af=%u ttl=%u dns_skip=%u dns_len=%u pkt_len=%u action=%s",
                        pid,
                        local_port,
                        remote_port,
                        is_dns_response ? 1u : 0u,
                        dns_flags,
                        qdcount,
                        ancount,
                        qtype,
                        spoof_domain,
                        spoof_rule_id,
                        spoof_rule_domain,
                        rule_match ? 1u : 0u,
                        match_before,
                        match_after,
                        spoof_af,
                        spoof_ttl,
                        dns_skip,
                        dns_len,
                        pkt_len,
                        eligible_response ? "response_eligible" : "not_response_or_no_question");
                    if (eligible_response && rule_match) {
                        UINT16 spoofed_type = 0;
                        UINT32 answer_offset = 0;
                        UINT32 answer_size = 0;
                        BOOLEAN spoofed = rewrite_dns_answers(dns_data, dns_len, qpos, ancount,
                            spoof_addr, spoof_af, spoof_ttl, &spoofed_type, &answer_offset, &answer_size);
                        UINT16 dns_query_id = dns_read16(dns_data);
                        SD_LOG_PACKET("net_dns_spoof::modify_result layer=in_trans rule_id=%u qname='%s' query_id=0x%04X spoofed=%u spoofed_type=%u ancount=%u dns_skip=%u dns_len=%u answer_offset=%u answer_size=%u answer=%u.%u.%u.%u checksum_recompute=1",
                            spoof_rule_id,
                            spoof_domain,
                            dns_query_id,
                            spoofed ? 1u : 0u,
                            spoofed_type,
                            ancount,
                            dns_skip,
                            dns_len,
                            answer_offset,
                            answer_size,
                            spoof_addr[0], spoof_addr[1], spoof_addr[2], spoof_addr[3]);
                        if (spoofed) {
                            NET_DBG("classify_inbound: DNS SPOOFED domain=%s", spoof_domain);
                            RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                            inj_buf->direction = 0;
                            inj_buf->protocol = 17;
                            inj_buf->address_family = 2;
                            inj_buf->src_port = remote_port;
                            inj_buf->dst_port = local_port;
                            strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                            strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                            if (dns_skip == 8) {
                                inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                                inj_buf->payload_size = pkt_len;
                                if (pkt_len <= INJECT_MAX_PAYLOAD)
                                    strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                            } else {
                                inj_buf->tcp_flags = 0;
                                inj_buf->payload_size = dns_len;
                                if (dns_len <= INJECT_MAX_PAYLOAD)
                                    strong::kmemcpy(inj_buf->payload, dns_data, dns_len);
                            }
                            classifyOut->actionType = FWP_ACTION_BLOCK_;
                            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                            net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                            NTSTATUS dns_inject_status = net_inject::inject_packet(inj_buf, &inject_meta);
                            if (NT_SUCCESS(dns_inject_status) && inj_buf->status == 0) {
                                classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                            }
                            SD_LOG_PACKET("net_dns_spoof::inject_result layer=in_trans rule_id=%u qname='%s' status=0x%08X win32=%lu request_status=%u raw_transport=%u payload_size=%u action=blocked_original",
                                spoof_rule_id,
                                spoof_domain,
                                dns_inject_status,
                                net_capture::status_to_win32(dns_inject_status),
                                inj_buf->status,
                                (inj_buf->tcp_flags & net_inject::INJECT_FLAG_RAW_TRANSPORT) ? 1u : 0u,
                                inj_buf->payload_size);
                            __leave;
                        }
                    }
                }
            }


            BOOLEAN needs_reinject = FALSE;

            if (protocol == 6 && pkt_len >= 20) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                needs_reinject = net_seq_delta::apply_delta(pkt_data, rip, lip, (UINT16)remote_port, (UINT16)local_port, FALSE);

                UINT8 tcp_flags = pkt_data[13];
                if (tcp_flags & 0x05) {
                    net_seq_delta::handle_fin_rst(rip, lip, (UINT16)remote_port, (UINT16)local_port);
                }
            }


            if (pkt_len > 0) {
                UINT32 orig_len = pkt_len;
                LONG mod_active = net_mod::active_rule_count();
                LONG64 mod_generation = net_mod::current_generation();
                if (mod_active != 0) {
                    SD_LOG_PACKET("net_mod::classify APPLY_BEGIN layer=in_trans direction=0 irql=%u cpu=%lu pid=%u protocol=%u ports=%u<-%u pkt_len=%u active_rules=%ld generation=%lld action_before=0x%08X rights_before=0x%08X",
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        pkt_len,
                        mod_active,
                        mod_generation,
                        (UINT32)classifyOut->actionType,
                        classifyOut->rights);
                }
                BOOLEAN was_modified = net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            0, protocol, remote_port, pid);
                if (mod_active != 0) {
                    SD_LOG_PACKET("net_mod::classify APPLY_END layer=in_trans direction=0 modified=%u irql=%u cpu=%lu pid=%u protocol=%u ports=%u<-%u len_before=%u len_after=%u active_rules=%ld generation_before=%lld generation_after=%lld needs_reinject_before=%u",
                        was_modified ? 1u : 0u,
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        orig_len,
                        pkt_len,
                        mod_active,
                        mod_generation,
                        net_mod::current_generation(),
                        needs_reinject ? 1u : 0u);
                }
                if (was_modified) {
                    NET_DBG("classify_inbound: MODIFIED proto=%u pid=%u port=%u (len %u->%u)",
                            protocol, pid, remote_port, orig_len, pkt_len);
                    if (protocol == 6 && pkt_len != orig_len) {
                        UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                     ((UINT32)local_ip[2] << 8) | local_ip[3];
                        UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                     ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                        LONG32 delta = (LONG32)pkt_len - (LONG32)orig_len;
                        net_seq_delta::record_size_change(rip, lip, (UINT16)remote_port, (UINT16)local_port, FALSE, delta);
                    }
                    needs_reinject = TRUE;
                }
            }


            if (needs_reinject && pkt_len > 0) {
                if (net_inject::g_inject_handle_v4) {
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 0;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = remote_port;
                    inj_buf->dst_port = local_port;
                    strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                    inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                    inj_buf->payload_size = pkt_len;
                    if (pkt_len <= INJECT_MAX_PAYLOAD)
                        strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                    NTSTATUS mod_inject_status = net_inject::inject_packet(inj_buf, &inject_meta);
                    if (NT_SUCCESS(mod_inject_status) && inj_buf->status == 0) {
                        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                    }
                    SD_LOG_PACKET("net_mod::classify REINJECT layer=in_trans direction=0 status=0x%08X win32=%lu request_status=%u irql=%u cpu=%lu pid=%u protocol=%u ports=%u<-%u payload_size=%u active_rules=%ld generation=%lld action=blocked_original",
                        mod_inject_status,
                        net_capture::status_to_win32(mod_inject_status),
                        inj_buf->status,
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        inj_buf->payload_size,
                        net_mod::active_rule_count(),
                        net_mod::current_generation());
                } else {
                    NET_ERR("classify_inbound: packet modified/delta-adjusted but inject handle unavailable, blocking proto=%u pid=%u", protocol, pid);
                    SD_LOG_PACKET("net_mod::classify REINJECT_SKIP layer=in_trans direction=0 reason=inject_handle_unavailable irql=%u cpu=%lu pid=%u protocol=%u ports=%u<-%u pkt_len=%u active_rules=%ld generation=%lld action=blocked_original",
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        pkt_len,
                        net_mod::active_rule_count(),
                        net_mod::current_generation());
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    __leave;
                }
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }


            if (protocol == 6 && pkt_len >= 20) {
                UINT8 ip_ttl = 0;
                if (layerData && inMetaValues->ipHeaderSize >= 20) {
                    __try {
                        PNET_BUFFER_LIST ttl_nbl = reinterpret_cast<PNET_BUFFER_LIST>(layerData);
                        PNET_BUFFER ttl_nb = NET_BUFFER_LIST_FIRST_NB(ttl_nbl);
                        if (ttl_nb) {
                            PMDL curMdl = NET_BUFFER_CURRENT_MDL(ttl_nb);
                            ULONG curOff = NET_BUFFER_CURRENT_MDL_OFFSET(ttl_nb);
                            ULONG ipSz = inMetaValues->ipHeaderSize;
                            if (curMdl && curOff >= ipSz) {
                                PUCHAR mapped = reinterpret_cast<PUCHAR>(
                                    MmGetSystemAddressForMdlSafe(curMdl, NormalPagePriority | MdlMappingNoExecute));
                                if (mapped) {
                                    ULONG ttlOff = curOff - ipSz + 8;
                                    if (ttlOff < MmGetMdlByteCount(curMdl)) {
                                        ip_ttl = mapped[ttlOff];
                                    }
                                }
                            }
                        }
                    } __except(EXCEPTION_EXECUTE_HANDLER) {}
                }
                if (ip_ttl == 0) ip_ttl = 128;
                net_fingerprint::analyze_tcp_syn(remote_ip, 2, pkt_data, pkt_len, ip_ttl);
            }


            if (net_dpi::is_active()) {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 0, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }


            if (net_intercept::try_hold_packet(0, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, pkt_data, pkt_len,
                    protocol == IPPROTO_TCP ? net_inject::INJECT_FLAG_RAW_TRANSPORT : 0)) {
                NET_DBG("classify_inbound: HELD by intercept proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                __leave;
            }


            if (capture_filter_match) {
                store_packet(0, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);


                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
            }

            if (malsafe_log_inbound) {
                HANDLE pid_handle = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                UINT64 tcp_seq = 0;
                if (protocol == 6 && pkt_len >= 8) {
                    tcp_seq = ((UINT64)pkt_data[4] << 24) | ((UINT64)pkt_data[5] << 16) |
                              ((UINT64)pkt_data[6] << 8)  | (UINT64)pkt_data[7];
                }
                malware_safe::record_packet_for_pid(pid_handle,
                    (UINT8)0,
                    (UINT8)(protocol & 0xFFu),
                    (UINT16)(local_port & 0xFFFFu),
                    (UINT16)(remote_port & 0xFFFFu),
                    (UINT16)2,
                    local_ip, remote_ip,
                    pkt_len, tcp_seq, pkt_data);
            }
        } __finally {
            if (inj_buf) ExFreePoolWithTag(inj_buf, 'piNW');
            if (pkt_data) ExFreePoolWithTag(pkt_data, 'pdNW');
        }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    void NTAPI classify_outbound(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;

        classifyOut->actionType = FWP_ACTION_PERMIT_;


        if (layerData && net_inject::_FwpsQueryPacketInjectionState0) {
            if (net_inject::g_inject_handle_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
            if (net_inject::g_inject_handle_net_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_net_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
        }

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

        __try {
        UINT8* pkt_data = nullptr;
        packet_inject_request* inj_buf = nullptr;
        __try {
            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;
            UINT8 local_ip[16] = {};
            UINT8 remote_ip[16] = {};
            UINT32 pid = 0;
            UINT32 pid_source = net_bw::PID_SOURCE_NONE;

            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_PROTOCOL) {
                protocol = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_PROTOCOL].value.uint8;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT) {
                local_port = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_LOCAL_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT) {
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_LOCAL_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, local_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_OUT_TRANS_V4_REMOTE_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, remote_ip);
            }

            if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) != 0) {
                pid = (UINT32)inMetaValues->processId;
                if (pid != 0) pid_source = net_bw::PID_SOURCE_METADATA;
            }
            if (pid != 0 && inMetaValues->transportEndpointHandle != 0) {
                slop_store_cached_endpoint_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, pid);
            }
            if (pid == 0) {
                pid = slop_resolve_packet_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_ENDPOINT;
            }
            if (pid == 0) {
                pid = slop_lookup_cached_port_pid(protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_PORT_CACHE;
            }
            if (pid == 0 && protocol == 17) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                pid = net_udp_cache::lookup(lip, rip, (UINT16)local_port, (UINT16)remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_UDP_CACHE;
            }
            if (pid != 0) {
                slop_store_cached_port_pid(protocol, local_port, pid);
                slop_store_cached_port_pid(protocol, remote_port, pid);
                if (protocol == 17) {
                    UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                 ((UINT32)local_ip[2] << 8) | local_ip[3];
                    UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                 ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                    net_udp_cache::store(lip, rip, (UINT16)local_port, (UINT16)remote_port, pid);
                }
            }
            BOOLEAN capture_active_now = (g_capture_active != 0);
            BOOLEAN capture_filter_match = capture_active_now
                ? packet_matches_capture_filters(protocol, pid, local_port, remote_port, 2, remote_ip)
                : FALSE;
            if (capture_active_now && !capture_filter_match)
                _InterlockedIncrement64(&g_hot_filter_rejects);

            _InterlockedIncrement64(&g_global_pkts_sent);

            UINT32 rule_action = check_filter_rules(1, protocol, pid, local_port, remote_port, remote_ip, 2);
            if (rule_action == 1) {
                NET_DBG("classify_outbound: BLOCKED by filter rule proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                return;
            }


            BOOLEAN malsafe_log_outbound = FALSE;
            if (pid != 0 && malware_safe::any_sandboxed()) {
                HANDLE pid_handle_check = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                if (malware_safe::sandbox_has_net_logging(pid_handle_check)) {
                    malsafe_log_outbound = TRUE;
                }
            }

            {
                UINT32 data_length = get_transport_data_length(layerData);
                _InterlockedExchangeAdd64(&g_global_bytes_sent, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 1, data_length, pid_source,
                    net_bw::LAYER_OUTBOUND_TRANSPORT, protocol, local_port, remote_port);

                BOOLEAN need_full_pipeline = FALSE;
                if (g_active_rule_count != 0) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_mod::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_intercept::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dpi::is_active() && (!capture_active_now || capture_filter_match)) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_fingerprint::is_active()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_dns_spoof::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_redirect::has_active_rules()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && net_stream::has_active_streams()) need_full_pipeline = TRUE;
                if (!need_full_pipeline && malsafe_log_outbound) need_full_pipeline = TRUE;
                if (!need_full_pipeline && !capture_filter_match) __leave;
            }

            pkt_data = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, NET_PKT_MAX_PAYLOAD, 'pdNW');
            if (!pkt_data) __leave;
            inj_buf = (packet_inject_request*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(packet_inject_request), 'piNW');
            if (!inj_buf) __leave;

            UINT32 pkt_len = 0;
            pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0 && layerData) {
            }


            if (pkt_len > 0 && net_redirect::has_active_rules()) {
                UINT32 redir_port = 0;
                UINT8 redir_addr[16] = {};
                UINT32 redir_rule_id = 0;
                LONG redir_match_before = 0;
                LONG redir_match_after = 0;
                if (net_redirect::check_redirect(protocol, remote_port, remote_ip, 2, pid, &redir_port, redir_addr,
                        &redir_rule_id, &redir_match_before, &redir_match_after)) {
                    NET_DBG("classify_outbound: REDIRECTING proto=%u pid=%u port=%u -> %u.%u.%u.%u:%u",
                            protocol, pid, remote_port,
                            redir_addr[0], redir_addr[1], redir_addr[2], redir_addr[3], redir_port);
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 1;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = local_port;
                    inj_buf->dst_port = redir_port;
                    strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, redir_addr, 4);
                    UINT32 hdr_skip = 0;
                    BOOLEAN raw_transport = FALSE;
                    if (protocol == 6 && pkt_len >= 20) {
                        hdr_skip = ((UINT32)(pkt_data[12] >> 4)) * 4;
                        if (hdr_skip < 20) hdr_skip = 20;
                        if (hdr_skip > pkt_len) hdr_skip = pkt_len;
                        inj_buf->tcp_seq = ((UINT32)pkt_data[4] << 24) | ((UINT32)pkt_data[5] << 16) |
                                      ((UINT32)pkt_data[6] << 8) | pkt_data[7];
                        inj_buf->tcp_ack = ((UINT32)pkt_data[8] << 24) | ((UINT32)pkt_data[9] << 16) |
                                      ((UINT32)pkt_data[10] << 8) | pkt_data[11];
                        inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                        inj_buf->payload_size = pkt_len;
                        if (inj_buf->payload_size > INJECT_MAX_PAYLOAD)
                            inj_buf->payload_size = INJECT_MAX_PAYLOAD;
                        strong::kmemcpy(inj_buf->payload, pkt_data, inj_buf->payload_size);
                        inj_buf->payload[2] = (UINT8)((redir_port >> 8) & 0xFF);
                        inj_buf->payload[3] = (UINT8)(redir_port & 0xFF);
                        raw_transport = TRUE;
                    } else if (protocol == 17 && pkt_len >= 8) {
                        hdr_skip = udp_header_skip_if_present(pkt_data, pkt_len, local_port, remote_port);
                        inj_buf->payload_size = pkt_len - hdr_skip;
                        if (inj_buf->payload_size > 0)
                            strong::kmemcpy(inj_buf->payload, pkt_data + hdr_skip, inj_buf->payload_size);
                    } else {
                        inj_buf->payload_size = pkt_len;
                        if (inj_buf->payload_size > INJECT_MAX_PAYLOAD)
                            inj_buf->payload_size = INJECT_MAX_PAYLOAD;
                        if (inj_buf->payload_size > 0)
                            strong::kmemcpy(inj_buf->payload, pkt_data, inj_buf->payload_size);
                    }
                    net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                    net_redirect::record_redirect_flow(redir_rule_id, protocol, 2, pid,
                        local_ip, local_port, remote_ip, remote_port, redir_addr, redir_port,
                        inj_buf->src_addr, inj_buf->src_port, inj_buf->dst_addr, inj_buf->dst_port,
                        inject_meta.endpoint_handle, inject_meta.compartment_id,
                        inject_meta.interface_index, inject_meta.sub_interface_index);
                    SD_LOG_PACKET("net_redirect::classify layer=out_trans direction=1 protocol=%u pid=%u rule_id=%u match_before=%ld match_after=%ld tuple_before=%u.%u.%u.%u:%u->%u.%u.%u.%u:%u tuple_after=%u.%u.%u.%u:%u->%u.%u.%u.%u:%u iface_src=%u iface_dst=%u compartment=%lu transport_len=%u hdr_skip=%u payload_size=%u raw_transport=%u tcp_options_size=%u decision=block_inject",
                        protocol,
                        pid,
                        redir_rule_id,
                        redir_match_before,
                        redir_match_after,
                        local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                        remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
                        local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                        redir_addr[0], redir_addr[1], redir_addr[2], redir_addr[3], redir_port,
                        inMetaValues->sourceInterfaceIndex,
                        inMetaValues->destinationInterfaceIndex,
                        inMetaValues->compartmentId,
                        pkt_len,
                        hdr_skip,
                        inj_buf->payload_size,
                        raw_transport ? 1u : 0u,
                        (hdr_skip > 20) ? (hdr_skip - 20) : 0u);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    NTSTATUS inject_status = net_inject::inject_packet(inj_buf, &inject_meta);
                    if (NT_SUCCESS(inject_status) && inj_buf->status == 0) {
                        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                    }
                    SD_LOG_PACKET("net_redirect::inject_result layer=out_trans rule_id=%u status=0x%08X win32=%lu request_status=%u action=blocked_original direction=%u protocol=%u pid=%u dst_port_before=%u dst_port_after=%u payload_size=%u hdr_skip=%u raw_transport=%u iface_src=%u iface_dst=%u compartment=%lu",
                        redir_rule_id,
                        inject_status,
                        net_capture::status_to_win32(inject_status),
                        inj_buf->status,
                        inj_buf->direction,
                        inj_buf->protocol,
                        pid,
                        remote_port,
                        redir_port,
                        inj_buf->payload_size,
                        hdr_skip,
                        raw_transport ? 1u : 0u,
                        inMetaValues->sourceInterfaceIndex,
                        inMetaValues->destinationInterfaceIndex,
                        inMetaValues->compartmentId);
                    __leave;
                }
            }


            BOOLEAN needs_reinject_out = FALSE;

            if (protocol == 6 && pkt_len >= 20) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                needs_reinject_out = net_seq_delta::apply_delta(pkt_data, lip, rip, (UINT16)local_port, (UINT16)remote_port, TRUE);

                UINT8 tcp_flags = pkt_data[13];
                if (tcp_flags & 0x05) {
                    net_seq_delta::handle_fin_rst(lip, rip, (UINT16)local_port, (UINT16)remote_port);
                }
            }


            if (pkt_len > 0) {
                UINT32 orig_len = pkt_len;
                LONG mod_active = net_mod::active_rule_count();
                LONG64 mod_generation = net_mod::current_generation();
                if (mod_active != 0) {
                    SD_LOG_PACKET("net_mod::classify APPLY_BEGIN layer=out_trans direction=1 irql=%u cpu=%lu pid=%u protocol=%u ports=%u->%u pkt_len=%u active_rules=%ld generation=%lld action_before=0x%08X rights_before=0x%08X",
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        pkt_len,
                        mod_active,
                        mod_generation,
                        (UINT32)classifyOut->actionType,
                        classifyOut->rights);
                }
                BOOLEAN was_modified = net_mod::apply_modifications(pkt_data, &pkt_len, NET_PKT_MAX_PAYLOAD,
                                            1, protocol, remote_port, pid);
                if (mod_active != 0) {
                    SD_LOG_PACKET("net_mod::classify APPLY_END layer=out_trans direction=1 modified=%u irql=%u cpu=%lu pid=%u protocol=%u ports=%u->%u len_before=%u len_after=%u active_rules=%ld generation_before=%lld generation_after=%lld needs_reinject_before=%u",
                        was_modified ? 1u : 0u,
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        orig_len,
                        pkt_len,
                        mod_active,
                        mod_generation,
                        net_mod::current_generation(),
                        needs_reinject_out ? 1u : 0u);
                }
                if (was_modified) {
                    NET_DBG("classify_outbound: MODIFIED proto=%u pid=%u port=%u (len %u->%u)",
                            protocol, pid, remote_port, orig_len, pkt_len);
                    if (protocol == 6 && pkt_len != orig_len) {
                        UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                                     ((UINT32)local_ip[2] << 8) | local_ip[3];
                        UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                                     ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                        LONG32 delta = (LONG32)pkt_len - (LONG32)orig_len;
                        net_seq_delta::record_size_change(lip, rip, (UINT16)local_port, (UINT16)remote_port, TRUE, delta);
                    }
                    needs_reinject_out = TRUE;
                }
            }


            if (needs_reinject_out && pkt_len > 0) {
                if (net_inject::g_inject_handle_v4) {
                    RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                    inj_buf->direction = 1;
                    inj_buf->protocol = protocol;
                    inj_buf->address_family = 2;
                    inj_buf->src_port = local_port;
                    inj_buf->dst_port = remote_port;
                    strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                    strong::kmemcpy(inj_buf->dst_addr, remote_ip, 4);
                    inj_buf->tcp_flags = net_inject::INJECT_FLAG_RAW_TRANSPORT;
                    inj_buf->payload_size = pkt_len;
                    if (pkt_len <= INJECT_MAX_PAYLOAD)
                        strong::kmemcpy(inj_buf->payload, pkt_data, pkt_len);
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                    NTSTATUS mod_inject_status = net_inject::inject_packet(inj_buf, &inject_meta);
                    if (NT_SUCCESS(mod_inject_status) && inj_buf->status == 0) {
                        classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                    }
                    SD_LOG_PACKET("net_mod::classify REINJECT layer=out_trans direction=1 status=0x%08X win32=%lu request_status=%u irql=%u cpu=%lu pid=%u protocol=%u ports=%u->%u payload_size=%u active_rules=%ld generation=%lld action=blocked_original",
                        mod_inject_status,
                        net_capture::status_to_win32(mod_inject_status),
                        inj_buf->status,
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        inj_buf->payload_size,
                        net_mod::active_rule_count(),
                        net_mod::current_generation());
                } else {
                    NET_ERR("classify_outbound: packet modified/delta-adjusted but inject handle unavailable, blocking proto=%u pid=%u", protocol, pid);
                    SD_LOG_PACKET("net_mod::classify REINJECT_SKIP layer=out_trans direction=1 reason=inject_handle_unavailable irql=%u cpu=%lu pid=%u protocol=%u ports=%u->%u pkt_len=%u active_rules=%ld generation=%lld action=blocked_original",
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        pid,
                        protocol,
                        local_port,
                        remote_port,
                        pkt_len,
                        net_mod::active_rule_count(),
                        net_mod::current_generation());
                    classifyOut->actionType = FWP_ACTION_BLOCK_;
                    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                    __leave;
                }
            }


            if (protocol == 6 && pkt_len > 0) {
                net_stream::feed_packet(local_port, remote_port, pid,
                                       local_ip, remote_ip, pkt_data, pkt_len);
            }

            if (protocol == 6 && pkt_len >= 20) {
                net_fingerprint::analyze_tcp_syn(local_ip, 2, pkt_data, pkt_len, 128);
            }


            if (net_dpi::is_active()) {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, 1, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }


            if (net_intercept::try_hold_packet(1, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, pkt_data, pkt_len,
                    protocol == IPPROTO_TCP ? net_inject::INJECT_FLAG_RAW_TRANSPORT : 0)) {
                NET_DBG("classify_outbound: HELD by intercept proto=%u pid=%u port=%u", protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                __leave;
            }

            if (capture_filter_match) {
                store_packet(1, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);

                if (protocol == 17) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
            }

            if (malsafe_log_outbound) {
                HANDLE pid_handle = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                UINT64 tcp_seq = 0;
                if (protocol == 6 && pkt_len >= 8) {
                    tcp_seq = ((UINT64)pkt_data[4] << 24) | ((UINT64)pkt_data[5] << 16) |
                              ((UINT64)pkt_data[6] << 8)  | (UINT64)pkt_data[7];
                }
                malware_safe::record_packet_for_pid(pid_handle,
                    (UINT8)1,
                    (UINT8)(protocol & 0xFFu),
                    (UINT16)(local_port & 0xFFFFu),
                    (UINT16)(remote_port & 0xFFFFu),
                    (UINT16)2,
                    local_ip, remote_ip,
                    pkt_len, tcp_seq, pkt_data);
            }
        } __finally {
            if (inj_buf) ExFreePoolWithTag(inj_buf, 'piNW');
            if (pkt_data) ExFreePoolWithTag(pkt_data, 'pdNW');
        }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }


    void NTAPI classify_datagram_v4(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;

        classifyOut->actionType = FWP_ACTION_PERMIT_;

        if (layerData && net_inject::_FwpsQueryPacketInjectionState0) {
            if (net_inject::g_inject_handle_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
            if (net_inject::g_inject_handle_net_v4) {
                UINT32 state = net_inject::_FwpsQueryPacketInjectionState0(
                    net_inject::g_inject_handle_net_v4, layerData, nullptr);
                if (state == 1 || state == 3) return;
            }
        }

        if (!inFixedValues || !inMetaValues) return;
        if (!should_process_packet_pipeline()) return;

        __try {
        UINT8* pkt_data = nullptr;
        packet_inject_request* inj_buf = nullptr;
        __try {
            UINT32 protocol = 0;
            UINT32 local_port = 0;
            UINT32 remote_port = 0;
            UINT32 direction = 1;
            UINT8 local_ip[16] = {};
            UINT8 remote_ip[16] = {};
            UINT32 pid = 0;
            UINT32 pid_source = net_bw::PID_SOURCE_NONE;

            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_PROTOCOL) {
                protocol = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_PROTOCOL].value.uint8;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_LOCAL_PORT) {
                local_port = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_LOCAL_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_REMOTE_PORT) {
                remote_port = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_REMOTE_PORT].value.uint16;
            }
            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_LOCAL_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_LOCAL_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, local_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_REMOTE_ADDR) {
                UINT32 ip = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_REMOTE_ADDR].value.uint32;
                copy_ipv4_fixed_value(ip, remote_ip);
            }
            if (inFixedValues->valueCount > FWPS_FIELD_DATAGRAM_V4_DIRECTION) {
                UINT32 fwp_direction = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_V4_DIRECTION].value.uint32;
                direction = (fwp_direction == 0) ? 1u : 0u;
            }

            if (protocol != 17) __leave;

            if ((inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) != 0) {
                pid = (UINT32)inMetaValues->processId;
                if (pid != 0) pid_source = net_bw::PID_SOURCE_METADATA;
            }
            if (pid != 0 && inMetaValues->transportEndpointHandle != 0) {
                slop_store_cached_endpoint_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, pid);
            }
            if (pid == 0) {
                pid = slop_resolve_packet_pid(inMetaValues->transportEndpointHandle,
                    protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_ENDPOINT;
            }
            if (pid == 0) {
                pid = slop_lookup_cached_port_pid(protocol, local_port, remote_port);
                if (pid != 0) pid_source = net_bw::PID_SOURCE_PORT_CACHE;
            }
            if (pid == 0) {
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                if (direction == 0) {
                    pid = net_udp_cache::lookup(rip, lip, (UINT16)remote_port, (UINT16)local_port);
                } else {
                    pid = net_udp_cache::lookup(lip, rip, (UINT16)local_port, (UINT16)remote_port);
                }
                if (pid != 0) pid_source = net_bw::PID_SOURCE_UDP_CACHE;
            }
            if (pid != 0) {
                slop_store_cached_port_pid(protocol, local_port, pid);
                slop_store_cached_port_pid(protocol, remote_port, pid);
                UINT32 lip = ((UINT32)local_ip[0] << 24) | ((UINT32)local_ip[1] << 16) |
                             ((UINT32)local_ip[2] << 8) | local_ip[3];
                UINT32 rip = ((UINT32)remote_ip[0] << 24) | ((UINT32)remote_ip[1] << 16) |
                             ((UINT32)remote_ip[2] << 8) | remote_ip[3];
                if (direction == 0) {
                    net_udp_cache::store(rip, lip, (UINT16)remote_port, (UINT16)local_port, pid);
                } else {
                    net_udp_cache::store(lip, rip, (UINT16)local_port, (UINT16)remote_port, pid);
                }
            }
            BOOLEAN capture_active_now = (g_capture_active != 0);
            BOOLEAN capture_filter_match = capture_active_now
                ? packet_matches_capture_filters(protocol, pid, local_port, remote_port, 2, remote_ip)
                : FALSE;
            if (capture_active_now && !capture_filter_match)
                _InterlockedIncrement64(&g_hot_filter_rejects);

            UINT32 data_length = get_transport_data_length(layerData);
            if (direction == 0) {
                _InterlockedIncrement64(&g_global_pkts_recv);
                _InterlockedExchangeAdd64(&g_global_bytes_recv, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 0, data_length, pid_source,
                    net_bw::LAYER_DATAGRAM, protocol, local_port, remote_port);
            } else {
                _InterlockedIncrement64(&g_global_pkts_sent);
                _InterlockedExchangeAdd64(&g_global_bytes_sent, static_cast<LONG64>(data_length));
                net_bw::record_traffic(pid, 1, data_length, pid_source,
                    net_bw::LAYER_DATAGRAM, protocol, local_port, remote_port);
            }

            BOOLEAN malsafe_log = FALSE;
            if (pid != 0 && malware_safe::any_sandboxed()) {
                HANDLE pid_handle_check = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                if (malware_safe::sandbox_has_net_logging(pid_handle_check)) {
                    malsafe_log = TRUE;
                }
            }

            BOOLEAN need_full_pipeline = FALSE;
            if (g_active_rule_count != 0) need_full_pipeline = TRUE;
            if (!need_full_pipeline && net_mod::has_active_rules()) need_full_pipeline = TRUE;
            if (!need_full_pipeline && net_intercept::is_active()) need_full_pipeline = TRUE;
            if (!need_full_pipeline && net_dpi::is_active() && (!capture_active_now || capture_filter_match)) need_full_pipeline = TRUE;
            if (!need_full_pipeline && net_dns_spoof::has_active_rules()) need_full_pipeline = TRUE;
            if (!need_full_pipeline && net_redirect::has_active_rules()) need_full_pipeline = TRUE;
            if (!need_full_pipeline && malsafe_log) need_full_pipeline = TRUE;
            if (!need_full_pipeline && !capture_filter_match) __leave;

            pkt_data = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, NET_PKT_MAX_PAYLOAD, 'pdNW');
            if (!pkt_data) __leave;
            if (net_redirect::has_active_rules() || net_dns_spoof::has_active_rules()) {
                inj_buf = (packet_inject_request*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(packet_inject_request), 'piNW');
                if (!inj_buf) __leave;
            }

            UINT32 pkt_len = copy_transport_bytes(layerData, pkt_data, NET_PKT_MAX_PAYLOAD);
            if (pkt_len == 0) __leave;

            if (protocol == 17 && (local_port == 53 || remote_port == 53) && net_dns_spoof::has_active_rules()) {
                UINT8* dns_data = nullptr;
                UINT32 dns_len = 0;
                UINT32 dns_skip = 0;
                if (select_dns_payload(pkt_data, pkt_len, local_port, remote_port, &dns_data, &dns_len, &dns_skip)) {
                    UINT16 dns_flags = ((UINT16)dns_data[2] << 8) | dns_data[3];
                    BOOLEAN is_dns_response = (dns_flags & 0x8000) != 0;
                    UINT16 qdcount = ((UINT16)dns_data[4] << 8) | dns_data[5];
                    UINT16 ancount = ((UINT16)dns_data[6] << 8) | dns_data[7];
                    char qname[260] = {};
                    UINT16 qtype = 0;
                    UINT32 qpos = 0;
                    if (qdcount > 0 && qdcount <= 16) {
                        qpos = parse_dns_name(dns_data, 12, dns_len, qname, sizeof(qname));
                        if (qpos != 0 && qpos + 4 <= dns_len) {
                            qtype = ((UINT16)dns_data[qpos] << 8) | dns_data[qpos + 1];
                        }
                    }
                    UINT8 spoof_addr[16] = {};
                    UINT32 spoof_af = 0;
                    UINT32 spoof_ttl = 0;
                    UINT32 spoof_rule_id = 0;
                    char spoof_rule_domain[DNS_SPOOF_MAX_DOMAIN] = {};
                    LONG match_before = 0;
                    LONG match_after = 0;
                    BOOLEAN eligible_query = direction == 1 && !is_dns_response &&
                        remote_port == 53 && qpos != 0 && qpos + 4 <= dns_len && qname[0] != '\0';
                    BOOLEAN eligible_response = is_dns_response && qpos != 0 &&
                        qpos + 4 <= dns_len && qname[0] != '\0' && ancount > 0;
                    BOOLEAN rule_match = net_dns_spoof::inspect_spoof_rule(qname, spoof_addr, &spoof_af, &spoof_ttl,
                        &spoof_rule_id, spoof_rule_domain, sizeof(spoof_rule_domain),
                        &match_before, &match_after, eligible_query || eligible_response);
                    SD_LOG_PACKET("net_dns_spoof::classify layer=datagram direction=%u pid=%u ports=%u%s%u qr=%u flags=0x%04X qdcount=%u ancount=%u qtype=%u qname='%s' rule_id=%u rule_domain='%s' match=%u match_before=%ld match_after=%ld spoof_af=%u ttl=%u dns_skip=%u dns_len=%u pkt_len=%u action=%s",
                        direction,
                        pid,
                        local_port,
                        direction == 0 ? "<-" : "->",
                        remote_port,
                        is_dns_response ? 1u : 0u,
                        dns_flags,
                        qdcount,
                        ancount,
                        qtype,
                        qname,
                        spoof_rule_id,
                        spoof_rule_domain,
                        rule_match ? 1u : 0u,
                        match_before,
                        match_after,
                        spoof_af,
                        spoof_ttl,
                        dns_skip,
                        dns_len,
                        pkt_len,
                        eligible_query ? "query_synth_eligible" : eligible_response ? "response_eligible" : is_dns_response ? "response_observed" : "query_observed");
                    if (rule_match && eligible_query && inj_buf) {
                        RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                        UINT32 answer_offset = 0;
                        UINT32 answer_size = 0;
                        UINT32 response_len = build_dns_spoof_response(dns_data, dns_len, qpos,
                            spoof_addr, spoof_af, spoof_ttl, inj_buf->payload, INJECT_MAX_PAYLOAD,
                            &answer_offset, &answer_size);
                        UINT16 dns_query_id = dns_read16(dns_data);
                        if (response_len != 0) {
                            inj_buf->direction = 0;
                            inj_buf->protocol = IPPROTO_UDP;
                            inj_buf->address_family = AF_INET;
                            inj_buf->src_port = remote_port;
                            inj_buf->dst_port = local_port;
                            strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                            strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                            inj_buf->payload_size = response_len;
                            classifyOut->actionType = FWP_ACTION_BLOCK_;
                            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                            net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                            NTSTATUS synth_status = net_inject::inject_packet(inj_buf, &inject_meta);
                            if (NT_SUCCESS(synth_status) && inj_buf->status == 0) {
                                classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                            }
                            SD_LOG("net_dns_spoof::synth_response layer=datagram rule_id=%u qname='%s' query_id=0x%04X status=0x%08X win32=%lu request_status=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u response_len=%u answer_offset=%u answer_size=%u answer=%u.%u.%u.%u checksum_recompute=1 action=blocked_original",
                                spoof_rule_id,
                                qname,
                                dns_query_id,
                                synth_status,
                                net_capture::status_to_win32(synth_status),
                                inj_buf->status,
                                remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
                                local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                                response_len,
                                answer_offset,
                                answer_size,
                                spoof_addr[0], spoof_addr[1], spoof_addr[2], spoof_addr[3]);
                            __leave;
                        }
                        SD_LOG("net_dns_spoof::synth_response layer=datagram rule_id=%u qname='%s' query_id=0x%04X status=0x%08X reason=unsupported_qtype_or_size qtype=%u spoof_af=%u dns_len=%u",
                            spoof_rule_id,
                            qname,
                            dns_query_id,
                            (UINT32)STATUS_NOT_SUPPORTED,
                            qtype,
                            spoof_af,
                            dns_len);
                    }
                    if (rule_match && eligible_response && inj_buf) {
                        UINT16 spoofed_type = 0;
                        UINT32 answer_offset = 0;
                        UINT32 answer_size = 0;
                        BOOLEAN spoofed = rewrite_dns_answers(dns_data, dns_len, qpos, ancount,
                            spoof_addr, spoof_af, spoof_ttl, &spoofed_type, &answer_offset, &answer_size);
                        UINT16 dns_query_id = dns_read16(dns_data);
                        SD_LOG_PACKET("net_dns_spoof::modify_result layer=datagram rule_id=%u qname='%s' query_id=0x%04X spoofed=%u spoofed_type=%u ancount=%u dns_skip=%u dns_len=%u answer_offset=%u answer_size=%u answer=%u.%u.%u.%u checksum_recompute=1",
                            spoof_rule_id,
                            qname,
                            dns_query_id,
                            spoofed ? 1u : 0u,
                            spoofed_type,
                            ancount,
                            dns_skip,
                            dns_len,
                            answer_offset,
                            answer_size,
                            spoof_addr[0], spoof_addr[1], spoof_addr[2], spoof_addr[3]);
                        if (spoofed) {
                            RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                            inj_buf->direction = 0;
                            inj_buf->protocol = IPPROTO_UDP;
                            inj_buf->address_family = AF_INET;
                            if (direction == 0) {
                                inj_buf->src_port = remote_port;
                                inj_buf->dst_port = local_port;
                                strong::kmemcpy(inj_buf->src_addr, remote_ip, 4);
                                strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                            } else {
                                inj_buf->src_port = local_port;
                                inj_buf->dst_port = remote_port;
                                strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                                strong::kmemcpy(inj_buf->dst_addr, remote_ip, 4);
                            }
                            inj_buf->payload_size = dns_len;
                            if (dns_len <= INJECT_MAX_PAYLOAD)
                                strong::kmemcpy(inj_buf->payload, dns_data, dns_len);
                            classifyOut->actionType = FWP_ACTION_BLOCK_;
                            classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                            net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                            NTSTATUS datagram_dns_status = net_inject::inject_packet(inj_buf, &inject_meta);
                            if (NT_SUCCESS(datagram_dns_status) && inj_buf->status == 0) {
                                classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                            }
                            SD_LOG_PACKET("net_dns_spoof::inject_result layer=datagram rule_id=%u qname='%s' query_id=0x%04X status=0x%08X win32=%lu request_status=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u payload_size=%u action=blocked_original",
                                spoof_rule_id,
                                qname,
                                dns_query_id,
                                datagram_dns_status,
                                net_capture::status_to_win32(datagram_dns_status),
                                inj_buf->status,
                                inj_buf->src_addr[0], inj_buf->src_addr[1], inj_buf->src_addr[2], inj_buf->src_addr[3], inj_buf->src_port,
                                inj_buf->dst_addr[0], inj_buf->dst_addr[1], inj_buf->dst_addr[2], inj_buf->dst_addr[3], inj_buf->dst_port,
                                inj_buf->payload_size);
                            __leave;
                        }
                    }
                } else {
                    SD_LOG_PACKET("net_dns_spoof::classify layer=datagram direction=%u pid=%u ports=%u%s%u pkt_len=%u action=dns_payload_select_failed",
                        direction,
                        pid,
                        local_port,
                        direction == 0 ? "<-" : "->",
                        remote_port,
                        pkt_len);
                }
            }

            if (pkt_len > 0 && net_redirect::has_active_rules() && inj_buf) {
                if (direction == 0) {
                    UINT8 original_remote_ip[16] = {};
                    UINT32 original_remote_port = 0;
                    UINT32 reverse_rule_id = 0;
                    UINT32 reverse_flow_pid = 0;
                    LONG reverse_flow_count = 0;
                    net_inject::inject_metadata reverse_meta = make_inject_metadata(inMetaValues);
                    if (net_redirect::find_reverse_redirect(protocol, 2, pid,
                            local_ip, local_port, remote_ip, remote_port,
                            reverse_meta.endpoint_handle, reverse_meta.compartment_id,
                            reverse_meta.interface_index, reverse_meta.sub_interface_index,
                            &reverse_rule_id, original_remote_ip,
                            &original_remote_port, &reverse_flow_pid,
                            &reverse_flow_count)) {
                        RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                        inj_buf->direction = 0;
                        inj_buf->protocol = protocol;
                        inj_buf->address_family = 2;
                        inj_buf->src_port = original_remote_port;
                        inj_buf->dst_port = local_port;
                        strong::kmemcpy(inj_buf->src_addr, original_remote_ip, 4);
                        strong::kmemcpy(inj_buf->dst_addr, local_ip, 4);
                        UINT32 payload_skip = udp_header_skip_if_present(pkt_data, pkt_len, local_port, remote_port);
                        inj_buf->payload_size = pkt_len - payload_skip;
                        if (inj_buf->payload_size > 0)
                            strong::kmemcpy(inj_buf->payload, pkt_data + payload_skip, inj_buf->payload_size);
                        classifyOut->actionType = FWP_ACTION_BLOCK_;
                        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                        NTSTATUS reverse_status = net_inject::inject_packet(inj_buf, &reverse_meta);
                        if (NT_SUCCESS(reverse_status) && inj_buf->status == 0) {
                            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                        }
                        SD_LOG_PACKET("net_redirect::reverse_inject layer=datagram rule_id=%u status=0x%08X win32=%lu request_status=%u protocol=%u pid=%u flow_pid=%u active_flows=%ld tuple_before=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u tuple_after=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u pkt_len=%u payload_skip=%u payload_size=%u action=blocked_original",
                            reverse_rule_id,
                            reverse_status,
                            net_capture::status_to_win32(reverse_status),
                            inj_buf->status,
                            protocol,
                            pid,
                            reverse_flow_pid,
                            reverse_flow_count,
                            local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
                            local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                            original_remote_ip[0], original_remote_ip[1], original_remote_ip[2], original_remote_ip[3], original_remote_port,
                            pkt_len,
                            payload_skip,
                            inj_buf->payload_size);
                        __leave;
                    }
                } else {
                    UINT32 redir_port = 0;
                    UINT8 redir_addr[16] = {};
                    UINT32 redir_rule_id = 0;
                    LONG redir_match_before = 0;
                    LONG redir_match_after = 0;
                    if (net_redirect::check_redirect(protocol, remote_port, remote_ip, 2, pid,
                            &redir_port, redir_addr, &redir_rule_id,
                            &redir_match_before, &redir_match_after)) {
                        RtlZeroMemory(inj_buf, sizeof(*inj_buf));
                        inj_buf->direction = 1;
                        inj_buf->protocol = protocol;
                        inj_buf->address_family = 2;
                        inj_buf->src_port = local_port;
                        inj_buf->dst_port = redir_port;
                        strong::kmemcpy(inj_buf->src_addr, local_ip, 4);
                        strong::kmemcpy(inj_buf->dst_addr, redir_addr, 4);
                        UINT32 payload_skip = udp_header_skip_if_present(pkt_data, pkt_len, local_port, remote_port);
                        inj_buf->payload_size = pkt_len - payload_skip;
                        if (inj_buf->payload_size > 0)
                            strong::kmemcpy(inj_buf->payload, pkt_data + payload_skip, inj_buf->payload_size);
                        net_inject::inject_metadata inject_meta = make_inject_metadata(inMetaValues);
                        net_redirect::record_redirect_flow(redir_rule_id, protocol, 2, pid,
                            local_ip, local_port, remote_ip, remote_port, redir_addr, redir_port,
                            inj_buf->src_addr, inj_buf->src_port, inj_buf->dst_addr, inj_buf->dst_port,
                            inject_meta.endpoint_handle, inject_meta.compartment_id,
                            inject_meta.interface_index, inject_meta.sub_interface_index);
                        classifyOut->actionType = FWP_ACTION_BLOCK_;
                        classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                        NTSTATUS redirect_status = net_inject::inject_packet(inj_buf, &inject_meta);
                        if (NT_SUCCESS(redirect_status) && inj_buf->status == 0) {
                            classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB_;
                        }
                        SD_LOG_PACKET("net_redirect::classify layer=datagram direction=1 protocol=%u pid=%u rule_id=%u match_before=%ld match_after=%ld tuple_before=%u.%u.%u.%u:%u->%u.%u.%u.%u:%u tuple_after=%u.%u.%u.%u:%u->%u.%u.%u.%u:%u iface_src=%u iface_dst=%u compartment=%lu pkt_len=%u payload_skip=%u payload_size=%u status=0x%08X win32=%lu request_status=%u decision=block_inject",
                            protocol,
                            pid,
                            redir_rule_id,
                            redir_match_before,
                            redir_match_after,
                            local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                            remote_ip[0], remote_ip[1], remote_ip[2], remote_ip[3], remote_port,
                            local_ip[0], local_ip[1], local_ip[2], local_ip[3], local_port,
                            redir_addr[0], redir_addr[1], redir_addr[2], redir_addr[3], redir_port,
                            inMetaValues->sourceInterfaceIndex,
                            inMetaValues->destinationInterfaceIndex,
                            inMetaValues->compartmentId,
                            pkt_len,
                            payload_skip,
                            inj_buf->payload_size,
                            redirect_status,
                            net_capture::status_to_win32(redirect_status),
                            inj_buf->status);
                        __leave;
                    }
                }
            }

            if (net_dpi::is_active()) {
                LARGE_INTEGER dpi_ts;
                KeQuerySystemTime(&dpi_ts);
                net_dpi::analyze_packet(dpi_ts.QuadPart, direction, protocol,
                    local_port, remote_port, local_ip, remote_ip, 2, pid,
                    pkt_data, pkt_len);
            }

            UINT32 intercept_payload_skip = udp_header_skip_if_present(pkt_data, pkt_len, local_port, remote_port);
            const UINT8* intercept_payload = pkt_data + intercept_payload_skip;
            UINT32 intercept_payload_len = pkt_len - intercept_payload_skip;
            if (net_intercept::try_hold_packet(direction, protocol, local_port, remote_port,
                    local_ip, remote_ip, 2, pid, intercept_payload, intercept_payload_len, 0)) {
                NET_DBG("classify_datagram_v4: HELD by intercept dir=%u proto=%u pid=%u port=%u",
                    direction, protocol, pid, remote_port);
                classifyOut->actionType = FWP_ACTION_BLOCK_;
                classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE_;
                __leave;
            }

            if (capture_filter_match) {
                store_packet(direction, protocol, pid, local_port, remote_port,
                    2, local_ip, remote_ip, pkt_data, pkt_len);
                if (local_port == 53 || remote_port == 53) {
                    try_parse_dns(pid, pkt_data, pkt_len, local_port, remote_port);
                }
            }

            if (malsafe_log) {
                HANDLE pid_handle = reinterpret_cast<HANDLE>((ULONG_PTR)pid);
                malware_safe::record_packet_for_pid(pid_handle,
                    (UINT8)(direction & 0xFFu),
                    (UINT8)(protocol & 0xFFu),
                    (UINT16)(local_port & 0xFFFFu),
                    (UINT16)(remote_port & 0xFFFFu),
                    (UINT16)2,
                    local_ip, remote_ip,
                    pkt_len, 0, pkt_data);
            }
        } __finally {
            if (inj_buf) ExFreePoolWithTag(inj_buf, 'piNW');
            if (pkt_data) ExFreePoolWithTag(pkt_data, 'pdNW');
        }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }


    void NTAPI classify_ale_connect(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(layerData);
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;
        classifyOut->actionType = FWP_ACTION_PERMIT_;

        if (!inFixedValues || !inMetaValues) return;

        __try {
            UINT32 pid = 0;
            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid == 0) return;


            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                slop_store_cached_endpoint_pid(endpoint_handle, 0, 0, pid);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    void NTAPI classify_ale_recv(
        const FWPS_INCOMING_VALUES0_COMPAT* inFixedValues,
        const FWPS_INCOMING_METADATA_VALUES0_COMPAT* inMetaValues,
        void* layerData,
        const void* classifyContext,
        const void* filter,
        UINT64 flowContext,
        FWPS_CLASSIFY_OUT0_COMPAT* classifyOut)
    {
        UNREFERENCED_PARAMETER(layerData);
        UNREFERENCED_PARAMETER(classifyContext);
        UNREFERENCED_PARAMETER(filter);
        UNREFERENCED_PARAMETER(flowContext);

        if (!classifyOut) return;
        classifyOut->actionType = FWP_ACTION_PERMIT_;

        if (!inFixedValues || !inMetaValues) return;

        __try {
            UINT32 pid = 0;
            if (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID_) {
                pid = (UINT32)inMetaValues->processId;
            }
            if (pid == 0) return;


            UINT64 endpoint_handle = 0;
            if (inMetaValues->transportEndpointHandle != 0)
                endpoint_handle = inMetaValues->transportEndpointHandle;

            if (endpoint_handle != 0) {
                slop_store_cached_endpoint_pid(endpoint_handle, 0, 0, pid);
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
        }
    }

    NTSTATUS NTAPI callout_notify(
        UINT32 notifyType, const GUID* filterKey, const void* filter)
    {
        UNREFERENCED_PARAMETER(notifyType);
        UNREFERENCED_PARAMETER(filterKey);
        UNREFERENCED_PARAMETER(filter);
        return STATUS_SUCCESS;
    }


    PVOID find_module_base(const char* module_name) {
        NET_DBG("find_module_base: looking for '%s' IRQL=%u", module_name, (UINT32)KeGetCurrentIrql());
        ULONG required = 0;
        NET_DBG("find_module_base: calling ZwQuerySystemInformation(size query)...");
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, nullptr, 0, &required);
        NET_DBG("find_module_base: size query returned 0x%08x required=%lu", status, required);
        if (required == 0) return nullptr;

        required += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required, 'teNW');
        if (!mods) { NET_ERR("find_module_base: alloc failed size=%lu", required); return nullptr; }

        NET_DBG("find_module_base: calling ZwQuerySystemInformation(full query size=%lu)...", required);
        status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, mods, required, nullptr);
        NET_DBG("find_module_base: full query returned 0x%08x modules=%lu", status, NT_SUCCESS(status) ? mods->NumberOfModules : 0);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(mods, 'teNW');
            return nullptr;
        }

        PVOID base = nullptr;
        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
            const char* full_path = (const char*)mods->Modules[i].FullPathName;
            const char* name = full_path + mods->Modules[i].OffsetToFileName;
            if (_strcmpi_a((char*)name, (char*)module_name) == 0) {
                base = mods->Modules[i].ImageBase;
                break;
            }
        }

        ExFreePoolWithTag(mods, 'teNW');
        NET_DBG("find_module_base: '%s' => %p", module_name, base);
        return base;
    }

    BOOLEAN resolve_wfp_functions() {
        NET_DBG("resolve_wfp_functions: locating FWPKCLNT.SYS");
        PVOID fwp_base = find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) {
            NET_DBG("resolve_wfp_functions: trying lowercase fwpkclnt.sys");
            fwp_base = find_module_base("fwpkclnt.sys");
        }
        if (!fwp_base) {
            NET_ERR("resolve_wfp_functions: FWPKCLNT.SYS not found");
            return FALSE;
        }
        NET_DBG("resolve_wfp_functions: FWPKCLNT.SYS base=%p", fwp_base);

        CHAR n1[] = {'F','w','p','s','C','a','l','l','o','u','t','R','e','g','i','s','t','e','r','2',0};
        CHAR n2[] = {'F','w','p','s','C','a','l','l','o','u','t','U','n','r','e','g','i','s','t','e','r','B','y','I','d','0',0};
        CHAR n3[] = {'F','w','p','m','E','n','g','i','n','e','O','p','e','n','0',0};
        CHAR n4[] = {'F','w','p','m','E','n','g','i','n','e','C','l','o','s','e','0',0};
        CHAR n5[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','B','e','g','i','n','0',0};
        CHAR n6[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','C','o','m','m','i','t','0',0};
        CHAR n7[] = {'F','w','p','m','T','r','a','n','s','a','c','t','i','o','n','A','b','o','r','t','0',0};
        CHAR n8[] = {'F','w','p','m','C','a','l','l','o','u','t','A','d','d','0',0};
        CHAR n9[] = {'F','w','p','m','S','u','b','L','a','y','e','r','A','d','d','0',0};
        CHAR n10[] = {'F','w','p','m','F','i','l','t','e','r','A','d','d','0',0};
        CHAR n11[] = {'F','w','p','m','F','i','l','t','e','r','D','e','l','e','t','e','B','y','I','d','0',0};
        CHAR n12[] = {'F','w','p','m','C','a','l','l','o','u','t','D','e','l','e','t','e','B','y','I','d','0',0};
        CHAR n13[] = {'F','w','p','m','S','u','b','L','a','y','e','r','D','e','l','e','t','e','B','y','K','e','y','0',0};
        CHAR n14[] = {'F','w','p','m','F','i','l','t','e','r','C','r','e','a','t','e','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR n15[] = {'F','w','p','m','F','i','l','t','e','r','D','e','s','t','r','o','y','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR n16[] = {'F','w','p','m','F','i','l','t','e','r','E','n','u','m','0',0};
        CHAR n17[] = {'F','w','p','m','C','a','l','l','o','u','t','C','r','e','a','t','e','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR n18[] = {'F','w','p','m','C','a','l','l','o','u','t','D','e','s','t','r','o','y','E','n','u','m','H','a','n','d','l','e','0',0};
        CHAR n19[] = {'F','w','p','m','C','a','l','l','o','u','t','E','n','u','m','0',0};
        CHAR n20[] = {'F','w','p','m','F','r','e','e','M','e','m','o','r','y','0',0};

        *(PVOID*)&_FwpsCalloutRegister2       = GetProcAddress(fwp_base, n1);
        *(PVOID*)&_FwpsCalloutUnregisterById0 = GetProcAddress(fwp_base, n2);
        *(PVOID*)&_FwpmEngineOpen0            = GetProcAddress(fwp_base, n3);
        *(PVOID*)&_FwpmEngineClose0           = GetProcAddress(fwp_base, n4);
        *(PVOID*)&_FwpmTransactionBegin0      = GetProcAddress(fwp_base, n5);
        *(PVOID*)&_FwpmTransactionCommit0     = GetProcAddress(fwp_base, n6);
        *(PVOID*)&_FwpmTransactionAbort0      = GetProcAddress(fwp_base, n7);
        *(PVOID*)&_FwpmCalloutAdd0            = GetProcAddress(fwp_base, n8);
        *(PVOID*)&_FwpmSubLayerAdd0           = GetProcAddress(fwp_base, n9);
        *(PVOID*)&_FwpmFilterAdd0             = GetProcAddress(fwp_base, n10);
        *(PVOID*)&_FwpmFilterDeleteById0      = GetProcAddress(fwp_base, n11);
        *(PVOID*)&_FwpmCalloutDeleteById0     = GetProcAddress(fwp_base, n12);
        *(PVOID*)&_FwpmSubLayerDeleteByKey0   = GetProcAddress(fwp_base, n13);
        *(PVOID*)&_FwpmFilterCreateEnumHandle0 = GetProcAddress(fwp_base, n14);
        *(PVOID*)&_FwpmFilterDestroyEnumHandle0 = GetProcAddress(fwp_base, n15);
        *(PVOID*)&_FwpmFilterEnum0            = GetProcAddress(fwp_base, n16);
        *(PVOID*)&_FwpmCalloutCreateEnumHandle0 = GetProcAddress(fwp_base, n17);
        *(PVOID*)&_FwpmCalloutDestroyEnumHandle0 = GetProcAddress(fwp_base, n18);
        *(PVOID*)&_FwpmCalloutEnum0           = GetProcAddress(fwp_base, n19);
        *(PVOID*)&_FwpmFreeMemory0            = GetProcAddress(fwp_base, n20);

        BOOLEAN ok = (_FwpsCalloutRegister2 && _FwpsCalloutUnregisterById0 &&
                _FwpmEngineOpen0 && _FwpmEngineClose0 &&
                _FwpmTransactionBegin0 && _FwpmTransactionCommit0 &&
                _FwpmTransactionAbort0 && _FwpmCalloutAdd0 &&
                _FwpmSubLayerAdd0 && _FwpmFilterAdd0 &&
                _FwpmFilterDeleteById0 && _FwpmCalloutDeleteById0 &&
                _FwpmSubLayerDeleteByKey0 && _FwpmFilterCreateEnumHandle0 &&
                _FwpmFilterDestroyEnumHandle0 && _FwpmFilterEnum0 &&
                _FwpmCalloutCreateEnumHandle0 && _FwpmCalloutDestroyEnumHandle0 &&
                _FwpmCalloutEnum0 && _FwpmFreeMemory0);
        ULONG missing_mask = 0;
        if (!_FwpsCalloutRegister2) missing_mask |= 0x00000001u;
        if (!_FwpsCalloutUnregisterById0) missing_mask |= 0x00000002u;
        if (!_FwpmEngineOpen0) missing_mask |= 0x00000004u;
        if (!_FwpmEngineClose0) missing_mask |= 0x00000008u;
        if (!_FwpmTransactionBegin0) missing_mask |= 0x00000010u;
        if (!_FwpmTransactionCommit0) missing_mask |= 0x00000020u;
        if (!_FwpmTransactionAbort0) missing_mask |= 0x00000040u;
        if (!_FwpmCalloutAdd0) missing_mask |= 0x00000080u;
        if (!_FwpmSubLayerAdd0) missing_mask |= 0x00000100u;
        if (!_FwpmFilterAdd0) missing_mask |= 0x00000200u;
        if (!_FwpmFilterDeleteById0) missing_mask |= 0x00000400u;
        if (!_FwpmCalloutDeleteById0) missing_mask |= 0x00000800u;
        if (!_FwpmSubLayerDeleteByKey0) missing_mask |= 0x00001000u;
        if (!_FwpmFilterCreateEnumHandle0) missing_mask |= 0x00002000u;
        if (!_FwpmFilterDestroyEnumHandle0) missing_mask |= 0x00004000u;
        if (!_FwpmFilterEnum0) missing_mask |= 0x00008000u;
        if (!_FwpmCalloutCreateEnumHandle0) missing_mask |= 0x00010000u;
        if (!_FwpmCalloutDestroyEnumHandle0) missing_mask |= 0x00020000u;
        if (!_FwpmCalloutEnum0) missing_mask |= 0x00040000u;
        if (!_FwpmFreeMemory0) missing_mask |= 0x00080000u;
        SD_LOG("KVALIDATE build=%lu kind=resolver name=WFP.FWPKCLNT.exports source=export_table value=%p validation=%s evidence=\"missing_mask=0x%08lX register=%p engine_open=%p filter_add=%p enum_filter=%p enum_callout=%p free=%p\" fail_closed=%s",
            sd_kernel_validation_build(),
            fwp_base,
            sd_kernel_validation_state(ok),
            missing_mask,
            _FwpsCalloutRegister2,
            _FwpmEngineOpen0,
            _FwpmFilterAdd0,
            _FwpmFilterEnum0,
            _FwpmCalloutEnum0,
            _FwpmFreeMemory0,
            ok ? "none" : "critical_wfp_export_missing");
        NET_DBG("resolve_wfp_functions: Register2=%p UnregById=%p EngOpen=%p EngClose=%p",
                _FwpsCalloutRegister2, _FwpsCalloutUnregisterById0,
                _FwpmEngineOpen0, _FwpmEngineClose0);
        NET_DBG("resolve_wfp_functions: TxnBegin=%p TxnCommit=%p CalloutAdd=%p SubLayerAdd=%p FilterAdd=%p",
                _FwpmTransactionBegin0, _FwpmTransactionCommit0,
                _FwpmCalloutAdd0, _FwpmSubLayerAdd0, _FwpmFilterAdd0);
        NET_DBG("resolve_wfp_functions: FilterEnum=%p CalloutEnum=%p FreeMem=%p FilterDel=%p CalloutDel=%p SubLayerDel=%p",
                _FwpmFilterEnum0, _FwpmCalloutEnum0, _FwpmFreeMemory0,
                _FwpmFilterDeleteById0, _FwpmCalloutDeleteById0,
                _FwpmSubLayerDeleteByKey0);
        if (!ok) {
            NET_ERR("resolve_wfp_functions: one or more critical functions not resolved");
        } else {
            NET_DBG("resolve_wfp_functions: all critical functions resolved OK");
        }
        return ok;
    }

    static BOOLEAN guid_equal(const GUID* a, const GUID* b) {
        return a && b && RtlCompareMemory(a, b, sizeof(GUID)) == sizeof(GUID);
    }

    static BOOLEAN is_slop_callout_key(const GUID* key) {
        return guid_equal(key, &GUID_SLOP_CALLOUT_INBOUND) ||
               guid_equal(key, &GUID_SLOP_CALLOUT_OUTBOUND) ||
               guid_equal(key, &GUID_SLOP_CALLOUT_DATAGRAM) ||
               guid_equal(key, &GUID_SLOP_CALLOUT_ALE_CONNECT) ||
               guid_equal(key, &GUID_SLOP_CALLOUT_ALE_RECV);
    }

    static BOOLEAN is_slop_provider_key(const GUID* key) {
        return key && guid_equal(key, &GUID_SLOP_PROVIDER);
    }

    static char ascii_lower(char c) {
        return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
    }

    static BOOLEAN text_contains_ascii_ci(const char* text, const char* needle) {
        if (!text || !needle || needle[0] == 0) return FALSE;
        SIZE_T text_len = 0;
        SIZE_T needle_len = 0;
        while (text[text_len] && text_len < 255) ++text_len;
        while (needle[needle_len] && needle_len < 127) ++needle_len;
        if (needle_len == 0 || text_len < needle_len) return FALSE;
        for (SIZE_T i = 0; i <= text_len - needle_len; ++i) {
            BOOLEAN ok = TRUE;
            for (SIZE_T j = 0; j < needle_len; ++j) {
                if (ascii_lower(text[i + j]) != ascii_lower(needle[j])) {
                    ok = FALSE;
                    break;
                }
            }
            if (ok) return TRUE;
        }
        return FALSE;
    }

    static void copy_wide_ascii_bounded(const wchar_t* src, char* out, SIZE_T out_len) {
        if (!out || out_len == 0) return;
        out[0] = 0;
        if (!src) return;
        __try {
            if (!_MmIsAddressValid((PVOID)src)) return;
            SIZE_T j = 0;
            for (; j + 1 < out_len; ++j) {
                wchar_t wc = src[j];
                if (wc == 0) break;
                if (wc >= 32 && wc <= 126) {
                    out[j] = (char)wc;
                } else if (wc == L'\t' || wc == L'\r' || wc == L'\n') {
                    out[j] = ' ';
                } else {
                    out[j] = '?';
                }
            }
            out[j] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out[0] = 0;
        }
    }

    static void copy_display_name_ascii(const FWPM_DISPLAY_DATA0* display, char* out, SIZE_T out_len) {
        if (!out || out_len == 0) return;
        out[0] = 0;
        if (!display) return;
        __try {
            copy_wide_ascii_bounded(display->name, out, out_len);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out[0] = 0;
        }
    }

    static void copy_display_description_ascii(const FWPM_DISPLAY_DATA0* display, char* out, SIZE_T out_len) {
        if (!out || out_len == 0) return;
        out[0] = 0;
        if (!display) return;
        __try {
            copy_wide_ascii_bounded(display->description, out, out_len);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out[0] = 0;
        }
    }

    static BOOLEAN is_slop_owned_display_text(const char* text) {
        return text_contains_ascii_ci(text, "SLOPNet") ||
               text_contains_ascii_ci(text, "SLOP Network Monitor");
    }

    static BOOLEAN is_slop_candidate_text(const char* text) {
        return text_contains_ascii_ci(text, "SLOP") ||
               text_contains_ascii_ci(text, "reverse-slop") ||
               text_contains_ascii_ci(text, "slopdrvr");
    }

    static BOOLEAN is_slop_executable_text(const char* text) {
        return text_contains_ascii_ci(text, "sloptarget.exe") ||
               text_contains_ascii_ci(text, "reverse-slop.exe") ||
               text_contains_ascii_ci(text, "\\reverse-slop.exe") ||
               text_contains_ascii_ci(text, "/reverse-slop.exe");
    }

    static BOOLEAN is_slop_repo_build_path(const char* text) {
        if (!text) return FALSE;
        const BOOLEAN repo = text_contains_ascii_ci(text, "\\slopprivate\\") ||
                             text_contains_ascii_ci(text, "/slopprivate/");
        const BOOLEAN build = text_contains_ascii_ci(text, "\\build-ninja\\") ||
                              text_contains_ascii_ci(text, "/build-ninja/") ||
                              text_contains_ascii_ci(text, "\\build\\") ||
                              text_contains_ascii_ci(text, "/build/");
        return (repo && build && is_slop_executable_text(text)) ? TRUE : FALSE;
    }

    static UINT32 display_match_reason(const FWPM_DISPLAY_DATA0* display) {
        char name[96] = {};
        char desc[128] = {};
        copy_display_name_ascii(display, name, sizeof(name));
        copy_display_description_ascii(display, desc, sizeof(desc));
        if (is_slop_owned_display_text(name) || is_slop_owned_display_text(desc))
            return WFP_SLOP_MATCH_DISPLAY_DATA;
        return 0;
    }

    static BOOLEAN display_has_slop_candidate(const FWPM_DISPLAY_DATA0* display) {
        char name[96] = {};
        char desc[128] = {};
        copy_display_name_ascii(display, name, sizeof(name));
        copy_display_description_ascii(display, desc, sizeof(desc));
        return (is_slop_candidate_text(name) || is_slop_candidate_text(desc)) ? TRUE : FALSE;
    }

    typedef struct _WFP_APP_CONDITION_INFO {
        UINT32 found;
        UINT32 index;
        UINT32 value_type;
        UINT32 blob_size;
        UINT32 slop_candidate;
        UINT32 slop_repo_build_path;
        UINT32 original_app_id;
        char preview[128];
    } WFP_APP_CONDITION_INFO;

    static void copy_blob_ascii_preview(const FWP_BYTE_BLOB_COMPAT* blob, char* out, SIZE_T out_len, UINT32* blob_size) {
        if (blob_size) *blob_size = 0;
        if (!out || out_len == 0) return;
        out[0] = 0;
        if (!blob) return;
        __try {
            if (!_MmIsAddressValid((PVOID)blob)) return;
            if (blob_size) *blob_size = blob->size;
            if (!blob->data || blob->size == 0 || !_MmIsAddressValid((PVOID)blob->data)) return;
            const UINT8* data = blob->data;
            const UINT32 max_scan = blob->size > 512 ? 512 : blob->size;
            UINT32 zero_high = 0;
            UINT32 pairs = 0;
            for (UINT32 i = 1; i < max_scan && pairs < 16; i += 2, ++pairs) {
                if (data[i] == 0) ++zero_high;
            }
            BOOLEAN utf16 = (pairs >= 2 && zero_high >= (pairs / 2));
            SIZE_T j = 0;
            if (utf16) {
                for (UINT32 i = 0; i + 1 < max_scan && j + 1 < out_len; i += 2) {
                    UINT16 wc = (UINT16)data[i] | ((UINT16)data[i + 1] << 8);
                    if (wc == 0) break;
                    if (wc >= 32 && wc <= 126) {
                        out[j++] = (char)wc;
                    } else if (wc == L'\t' || wc == L'\r' || wc == L'\n') {
                        out[j++] = ' ';
                    } else {
                        out[j++] = '?';
                    }
                }
            } else {
                for (UINT32 i = 0; i < max_scan && j + 1 < out_len; ++i) {
                    UINT8 ch = data[i];
                    if (ch == 0) break;
                    out[j++] = (ch >= 32 && ch <= 126) ? (char)ch : '?';
                }
            }
            out[j] = 0;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            out[0] = 0;
            if (blob_size) *blob_size = 0;
        }
    }

    static void inspect_filter_app_condition(const FWPM_FILTER0_COMPAT* filter, WFP_APP_CONDITION_INFO* info) {
        if (!info) return;
        strong::kmemset(info, 0, sizeof(*info));
        if (!filter || !filter->filterCondition || filter->numFilterConditions == 0) return;
        UINT32 limit = filter->numFilterConditions > 64 ? 64 : filter->numFilterConditions;
        __try {
            if (!_MmIsAddressValid((PVOID)filter->filterCondition)) return;
            for (UINT32 i = 0; i < limit; ++i) {
                const FWPM_FILTER_CONDITION0_COMPAT* cond = &filter->filterCondition[i];
                if (guid_equal(&cond->fieldKey, &GUID_CONDITION_ALE_APP_ID) ||
                    guid_equal(&cond->fieldKey, &GUID_CONDITION_ALE_ORIGINAL_APP_ID)) {
                    info->found = 1;
                    info->index = i;
                    info->value_type = (UINT32)cond->conditionValue.type;
                    info->original_app_id = guid_equal(&cond->fieldKey, &GUID_CONDITION_ALE_ORIGINAL_APP_ID) ? 1u : 0u;
                    if (cond->conditionValue.type == FWP_BYTE_BLOB_TYPE) {
                        copy_blob_ascii_preview(cond->conditionValue.byteBlob, info->preview, sizeof(info->preview), &info->blob_size);
                    } else if (cond->conditionValue.type == FWP_UNICODE_STRING_TYPE) {
                        copy_wide_ascii_bounded(cond->conditionValue.unicodeString, info->preview, sizeof(info->preview));
                    }
                    info->slop_candidate = is_slop_candidate_text(info->preview) ? 1u : 0u;
                    info->slop_repo_build_path = is_slop_repo_build_path(info->preview) ? 1u : 0u;
                    return;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            strong::kmemset(info, 0, sizeof(*info));
        }
    }

    static UINT32 filter_match_reason(const FWPM_FILTER0_COMPAT* filter) {
        if (!filter) return 0;
        UINT32 reason = 0;
        if (is_slop_provider_key(filter->providerKey))
            reason |= 0x00000008u;
        if (guid_equal(&filter->subLayerKey, &GUID_SLOP_SUBLAYER))
            reason |= WFP_SLOP_MATCH_SUBLAYER;
        if (is_slop_callout_key(&filter->action.calloutKey))
            reason |= WFP_SLOP_MATCH_ACTION_CALLOUT;
        reason |= display_match_reason(&filter->displayData);
        return reason;
    }

    static UINT32 callout_match_reason(const FWPM_CALLOUT0_COMPAT* callout) {
        if (!callout) return 0;
        UINT32 reason = 0;
        if (is_slop_provider_key(callout->providerKey))
            reason |= 0x00000008u;
        if (is_slop_callout_key(&callout->calloutKey))
            reason |= WFP_SLOP_MATCH_ACTION_CALLOUT;
        reason |= display_match_reason(&callout->displayData);
        return reason;
    }

    static UINT32 legacy_repo_filter_match_reason(const FWPM_FILTER0_COMPAT* filter, const WFP_APP_CONDITION_INFO* app_info) {
        if (!filter || !app_info) return 0;
        char name[96] = {};
        char desc[128] = {};
        copy_display_name_ascii(&filter->displayData, name, sizeof(name));
        copy_display_description_ascii(&filter->displayData, desc, sizeof(desc));
        const BOOLEAN display_names_slop = is_slop_executable_text(name) || is_slop_executable_text(desc) ||
                                           is_slop_owned_display_text(name) || is_slop_owned_display_text(desc);
        if (app_info->slop_repo_build_path && (display_names_slop || app_info->slop_candidate))
            return 0x00000010u;
        return 0;
    }

    static BOOLEAN callout_has_slop_candidate(const FWPM_CALLOUT0_COMPAT* callout) {
        if (!callout) return FALSE;
        char name[96] = {};
        char desc[128] = {};
        copy_display_name_ascii(&callout->displayData, name, sizeof(name));
        copy_display_description_ascii(&callout->displayData, desc, sizeof(desc));
        return (is_slop_candidate_text(name) || is_slop_candidate_text(desc)) ? TRUE : FALSE;
    }

    static void log_guid3_filter(const char* tag, UINT64 id, const GUID* layer, const GUID* sublayer, const GUID* callout, const GUID* provider) {
        const GUID zero = {};
        const GUID* l = layer ? layer : &zero;
        const GUID* s = sublayer ? sublayer : &zero;
        const GUID* c = callout ? callout : &zero;
        const GUID* p = provider ? provider : &zero;
        SD_LOG("net_capture::orphan_cleanup %s filter_layer id=%llu layer=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X sublayer=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X",
            tag,
            (unsigned long long)id,
            l->Data1, l->Data2, l->Data3, l->Data4[0], l->Data4[1], l->Data4[2], l->Data4[3], l->Data4[4], l->Data4[5], l->Data4[6], l->Data4[7],
            s->Data1, s->Data2, s->Data3, s->Data4[0], s->Data4[1], s->Data4[2], s->Data4[3], s->Data4[4], s->Data4[5], s->Data4[6], s->Data4[7]);
        SD_LOG("net_capture::orphan_cleanup %s filter_action id=%llu callout=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X provider=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X",
            tag,
            (unsigned long long)id,
            c->Data1, c->Data2, c->Data3, c->Data4[0], c->Data4[1], c->Data4[2], c->Data4[3], c->Data4[4], c->Data4[5], c->Data4[6], c->Data4[7],
            p->Data1, p->Data2, p->Data3, p->Data4[0], p->Data4[1], p->Data4[2], p->Data4[3], p->Data4[4], p->Data4[5], p->Data4[6], p->Data4[7]);
    }

    static void log_filter_diagnostic(const char* tag, const FWPM_FILTER0_COMPAT* filter, UINT32 reason, const WFP_APP_CONDITION_INFO* app_info, const char* disposition) {
        if (!filter) return;
        char name[96] = {};
        char desc[128] = {};
        WFP_APP_CONDITION_INFO local_app = {};
        const WFP_APP_CONDITION_INFO* app = app_info;
        if (!app) {
            inspect_filter_app_condition(filter, &local_app);
            app = &local_app;
        }
        copy_display_name_ascii(&filter->displayData, name, sizeof(name));
        copy_display_description_ascii(&filter->displayData, desc, sizeof(desc));
        UINT32 provider_present = filter->providerKey ? 1u : 0u;
        UINT32 provider_match = is_slop_provider_key(filter->providerKey) ? 1u : 0u;
        SD_LOG("net_capture::orphan_cleanup %s filter id=%llu action=0x%08X flags=0x%08X weight_type=%u provider_present=%u provider_match=%u conditions=%u app_found=%u app_index=%u app_type=%u app_blob=%u app_original=%u app_slop=%u app_repo=%u reason=0x%08X disposition=%s",
            tag,
            (unsigned long long)filter->filterId,
            (UINT32)filter->action.type,
            filter->flags,
            (UINT32)filter->weight.type,
            provider_present,
            provider_match,
            filter->numFilterConditions,
            app->found,
            app->index,
            app->value_type,
            app->blob_size,
            app->original_app_id,
            app->slop_candidate,
            app->slop_repo_build_path,
            reason,
            disposition ? disposition : "");
        log_guid3_filter(tag, filter->filterId, &filter->layerKey, &filter->subLayerKey, &filter->action.calloutKey, filter->providerKey);
        SD_LOG("net_capture::orphan_cleanup %s filter_text id=%llu name='%s' desc='%s' app='%s'",
            tag,
            (unsigned long long)filter->filterId,
            name,
            desc,
            app->preview);
    }

    static void log_callout_diagnostic(const char* tag, const FWPM_CALLOUT0_COMPAT* callout, UINT32 reason, const char* disposition) {
        if (!callout) return;
        char name[96] = {};
        char desc[128] = {};
        copy_display_name_ascii(&callout->displayData, name, sizeof(name));
        copy_display_description_ascii(&callout->displayData, desc, sizeof(desc));
        const GUID zero = {};
        const GUID* provider = callout->providerKey ? callout->providerKey : &zero;
        SD_LOG("net_capture::orphan_cleanup %s callout id=%u flags=0x%08X provider_present=%u provider_match=%u reason=0x%08X disposition=%s",
            tag,
            callout->calloutId,
            callout->flags,
            callout->providerKey ? 1u : 0u,
            is_slop_provider_key(callout->providerKey) ? 1u : 0u,
            reason,
            disposition ? disposition : "");
        SD_LOG("net_capture::orphan_cleanup %s callout_key id=%u key=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X layer=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X",
            tag,
            callout->calloutId,
            callout->calloutKey.Data1, callout->calloutKey.Data2, callout->calloutKey.Data3, callout->calloutKey.Data4[0], callout->calloutKey.Data4[1], callout->calloutKey.Data4[2], callout->calloutKey.Data4[3], callout->calloutKey.Data4[4], callout->calloutKey.Data4[5], callout->calloutKey.Data4[6], callout->calloutKey.Data4[7],
            callout->applicableLayer.Data1, callout->applicableLayer.Data2, callout->applicableLayer.Data3, callout->applicableLayer.Data4[0], callout->applicableLayer.Data4[1], callout->applicableLayer.Data4[2], callout->applicableLayer.Data4[3], callout->applicableLayer.Data4[4], callout->applicableLayer.Data4[5], callout->applicableLayer.Data4[6], callout->applicableLayer.Data4[7]);
        SD_LOG("net_capture::orphan_cleanup %s callout_provider id=%u provider=%08lX-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X",
            tag,
            callout->calloutId,
            provider->Data1, provider->Data2, provider->Data3, provider->Data4[0], provider->Data4[1], provider->Data4[2], provider->Data4[3], provider->Data4[4], provider->Data4[5], provider->Data4[6], provider->Data4[7]);
        SD_LOG("net_capture::orphan_cleanup %s callout_text id=%u name='%s' desc='%s'",
            tag,
            callout->calloutId,
            name,
            desc);
    }

    static __forceinline ULONG status_to_win32_fallback(NTSTATUS status) {
        switch (status) {
        case STATUS_SUCCESS: return 0;
        case STATUS_PENDING: return 997;
        case STATUS_UNSUCCESSFUL: return 31;
        case STATUS_NOT_SUPPORTED: return 50;
        case STATUS_INSUFFICIENT_RESOURCES: return 8;
        case STATUS_INVALID_PARAMETER: return 87;
        case STATUS_NOT_FOUND: return 1168;
        case STATUS_OBJECT_NAME_NOT_FOUND: return 2;
        case STATUS_OBJECT_NAME_COLLISION: return 183;
        case STATUS_ACCESS_DENIED: return 5;
        case STATUS_BUFFER_TOO_SMALL: return 122;
        case STATUS_INFO_LENGTH_MISMATCH: return 24;
        case STATUS_INVALID_HANDLE: return 6;
        case STATUS_INVALID_ADDRESS: return 487;
        case STATUS_PROCEDURE_NOT_FOUND: return 127;
        case STATUS_NO_MEMORY: return 8;
        case STATUS_TIMEOUT: return 1460;
        case STATUS_CANCELLED: return 1223;
        default: return (ULONG)status;
        }
    }

    static ULONG status_to_win32(NTSTATUS status) {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            return status_to_win32_fallback(status);
        }
        return RtlNtStatusToDosError(status);
    }

    static NTSTATUS cleanup_startup_wfp_orphans(HANDLE engine) {
        if (!engine) return STATUS_INVALID_PARAMETER;
        if (!_FwpmFilterCreateEnumHandle0 || !_FwpmFilterDestroyEnumHandle0 ||
            !_FwpmFilterEnum0 || !_FwpmCalloutCreateEnumHandle0 ||
            !_FwpmCalloutDestroyEnumHandle0 || !_FwpmCalloutEnum0 ||
            !_FwpmFreeMemory0 || !_FwpmFilterDeleteById0 ||
            !_FwpmCalloutDeleteById0 || !_FwpmSubLayerDeleteByKey0) {
            SD_LOG("net_capture::orphan_cleanup missing_functions filter_create=%p filter_destroy=%p filter_enum=%p callout_create=%p callout_destroy=%p callout_enum=%p free=%p filter_delete=%p callout_delete=%p sublayer_delete=%p",
                _FwpmFilterCreateEnumHandle0,
                _FwpmFilterDestroyEnumHandle0,
                _FwpmFilterEnum0,
                _FwpmCalloutCreateEnumHandle0,
                _FwpmCalloutDestroyEnumHandle0,
                _FwpmCalloutEnum0,
                _FwpmFreeMemory0,
                _FwpmFilterDeleteById0,
                _FwpmCalloutDeleteById0,
                _FwpmSubLayerDeleteByKey0);
            return STATUS_PROCEDURE_NOT_FOUND;
        }

        NTSTATUS first_failure = STATUS_SUCCESS;
        UINT32 filters_seen = 0;
        UINT32 filters_matched = 0;
        UINT32 filters_deleted = 0;
        UINT32 filter_delete_failed = 0;
        UINT32 callouts_seen = 0;
        UINT32 callouts_matched = 0;
        UINT32 callouts_deleted = 0;
        UINT32 callout_delete_failed = 0;
        UINT32 block_filters_seen = 0;
        UINT32 block_filters_logged = 0;
        UINT32 block_filters_suppressed = 0;
        UINT32 slop_filter_candidates_seen = 0;
        UINT32 slop_filter_candidates_logged = 0;
        UINT32 slop_filter_candidates_suppressed = 0;
        UINT32 external_block_filters_seen = 0;
        UINT32 legacy_repo_filters_matched = 0;
        UINT32 legacy_repo_filters_deleted = 0;
        UINT32 legacy_repo_filter_delete_failed = 0;
        UINT32 callout_candidates_seen = 0;
        UINT32 callout_candidates_logged = 0;
        UINT32 callout_candidates_suppressed = 0;
        const UINT32 max_block_filter_logs = 32;
        const UINT32 max_slop_candidate_logs = 96;

        HANDLE filter_enum = nullptr;
        NTSTATUS status = _FwpmFilterCreateEnumHandle0(engine, nullptr, &filter_enum);
        SD_LOG("net_capture::orphan_cleanup filter_enum_create status=0x%08X win32=%lu handle=%p",
            status, status_to_win32(status), filter_enum);
        if (NT_SUCCESS(status) && filter_enum) {
            for (;;) {
                FWPM_FILTER0_COMPAT** entries = nullptr;
                UINT32 returned = 0;
                status = _FwpmFilterEnum0(engine, filter_enum, 64, &entries, &returned);
                SD_LOG("net_capture::orphan_cleanup filter_enum status=0x%08X win32=%lu returned=%u",
                    status, status_to_win32(status), returned);
                if (!NT_SUCCESS(status)) {
                    if (NT_SUCCESS(first_failure)) first_failure = status;
                    break;
                }
                if (returned == 0) {
                    if (entries) _FwpmFreeMemory0((VOID**)&entries);
                    break;
                }
                filters_seen += returned;
                for (UINT32 i = 0; i < returned; ++i) {
                    FWPM_FILTER0_COMPAT* filter = entries[i];
                    if (!filter) continue;
                    UINT32 reason = filter_match_reason(filter);
                    WFP_APP_CONDITION_INFO app_info = {};
                    inspect_filter_app_condition(filter, &app_info);
                    UINT32 legacy_reason = legacy_repo_filter_match_reason(filter, &app_info);
                    reason |= legacy_reason;
                    BOOLEAN block_filter = (filter->action.type == FWP_ACTION_BLOCK_) ? TRUE : FALSE;
                    BOOLEAN display_candidate = display_has_slop_candidate(&filter->displayData);
                    BOOLEAN slop_candidate = (reason != 0 || app_info.slop_candidate != 0 || display_candidate) ? TRUE : FALSE;
                    if (block_filter) ++block_filters_seen;
                    if (slop_candidate) ++slop_filter_candidates_seen;
                    if (reason == 0) {
                        if (block_filter && slop_candidate) {
                            ++external_block_filters_seen;
                            if (slop_filter_candidates_logged < max_slop_candidate_logs) {
                                ++slop_filter_candidates_logged;
                                log_filter_diagnostic("external_block_candidate", filter, reason, &app_info, "not_deleted_external_owner_no_slop_sublayer_callout_or_exact_display");
                            } else {
                                ++slop_filter_candidates_suppressed;
                            }
                        } else if (slop_candidate) {
                            if (slop_filter_candidates_logged < max_slop_candidate_logs) {
                                ++slop_filter_candidates_logged;
                                log_filter_diagnostic("slop_candidate", filter, reason, &app_info, "not_deleted_no_slop_ownership_key");
                            } else {
                                ++slop_filter_candidates_suppressed;
                            }
                        } else if (block_filter) {
                            if (block_filters_logged < max_block_filter_logs) {
                                ++block_filters_logged;
                                log_filter_diagnostic("block_summary", filter, reason, &app_info, "not_deleted_block_filter_sample");
                            } else {
                                ++block_filters_suppressed;
                            }
                        }
                        continue;
                    }
                    ++filters_matched;
                    if (legacy_reason != 0) ++legacy_repo_filters_matched;
                    if (slop_filter_candidates_logged < max_slop_candidate_logs) {
                        ++slop_filter_candidates_logged;
                        log_filter_diagnostic("owned_filter", filter, reason, &app_info,
                            legacy_reason != 0 ? "delete_slop_legacy_repo_filter" : "delete_slop_owned_stale");
                    } else {
                        ++slop_filter_candidates_suppressed;
                    }
                    NTSTATUS del_status = _FwpmFilterDeleteById0(engine, filter->filterId);
                    ULONG del_win32 = status_to_win32(del_status);
                    SD_LOG("net_capture::orphan_cleanup filter_delete id=%llu action=0x%08X provider=%u reason=0x%08X status=0x%08X win32=%lu",
                        (unsigned long long)filter->filterId,
                        (UINT32)filter->action.type,
                        filter->providerKey ? 1u : 0u,
                        reason,
                        del_status,
                        del_win32);
                    if (NT_SUCCESS(del_status)) {
                        ++filters_deleted;
                        if (legacy_reason != 0) ++legacy_repo_filters_deleted;
                    } else {
                        ++filter_delete_failed;
                        if (legacy_reason != 0) ++legacy_repo_filter_delete_failed;
                        if (NT_SUCCESS(first_failure)) first_failure = del_status;
                    }
                }
                _FwpmFreeMemory0((VOID**)&entries);
            }
            NTSTATUS destroy_status = _FwpmFilterDestroyEnumHandle0(engine, filter_enum);
            SD_LOG("net_capture::orphan_cleanup filter_enum_destroy status=0x%08X win32=%lu",
                destroy_status, status_to_win32(destroy_status));
            if (!NT_SUCCESS(destroy_status) && NT_SUCCESS(first_failure))
                first_failure = destroy_status;
        } else if (NT_SUCCESS(first_failure)) {
            first_failure = status ? status : STATUS_UNSUCCESSFUL;
        }

        HANDLE callout_enum = nullptr;
        status = _FwpmCalloutCreateEnumHandle0(engine, nullptr, &callout_enum);
        SD_LOG("net_capture::orphan_cleanup callout_enum_create status=0x%08X win32=%lu handle=%p",
            status, status_to_win32(status), callout_enum);
        if (NT_SUCCESS(status) && callout_enum) {
            for (;;) {
                FWPM_CALLOUT0_COMPAT** entries = nullptr;
                UINT32 returned = 0;
                status = _FwpmCalloutEnum0(engine, callout_enum, 64, &entries, &returned);
                SD_LOG("net_capture::orphan_cleanup callout_enum status=0x%08X win32=%lu returned=%u",
                    status, status_to_win32(status), returned);
                if (!NT_SUCCESS(status)) {
                    if (NT_SUCCESS(first_failure)) first_failure = status;
                    break;
                }
                if (returned == 0) {
                    if (entries) _FwpmFreeMemory0((VOID**)&entries);
                    break;
                }
                callouts_seen += returned;
                for (UINT32 i = 0; i < returned; ++i) {
                    FWPM_CALLOUT0_COMPAT* callout = entries[i];
                    if (!callout) continue;
                    UINT32 reason = callout_match_reason(callout);
                    BOOLEAN callout_candidate = (reason != 0 || callout_has_slop_candidate(callout)) ? TRUE : FALSE;
                    if (callout_candidate) ++callout_candidates_seen;
                    if (reason == 0) {
                        if (callout_candidate) {
                            if (callout_candidates_logged < max_slop_candidate_logs) {
                                ++callout_candidates_logged;
                                log_callout_diagnostic("callout_candidate", callout, reason, "not_deleted_no_slop_ownership_key");
                            } else {
                                ++callout_candidates_suppressed;
                            }
                        }
                        continue;
                    }
                    ++callouts_matched;
                    if (callout_candidates_logged < max_slop_candidate_logs) {
                        ++callout_candidates_logged;
                        log_callout_diagnostic("owned_callout", callout, reason, "delete_slop_owned_stale");
                    } else {
                        ++callout_candidates_suppressed;
                    }
                    NTSTATUS del_status = _FwpmCalloutDeleteById0(engine, callout->calloutId);
                    ULONG del_win32 = status_to_win32(del_status);
                    SD_LOG("net_capture::orphan_cleanup callout_delete id=%u provider=%u reason=0x%08X status=0x%08X win32=%lu",
                        callout->calloutId,
                        callout->providerKey ? 1u : 0u,
                        reason,
                        del_status,
                        del_win32);
                    if (NT_SUCCESS(del_status)) {
                        ++callouts_deleted;
                    } else {
                        ++callout_delete_failed;
                        if (NT_SUCCESS(first_failure)) first_failure = del_status;
                    }
                }
                _FwpmFreeMemory0((VOID**)&entries);
            }
            NTSTATUS destroy_status = _FwpmCalloutDestroyEnumHandle0(engine, callout_enum);
            SD_LOG("net_capture::orphan_cleanup callout_enum_destroy status=0x%08X win32=%lu",
                destroy_status, status_to_win32(destroy_status));
            if (!NT_SUCCESS(destroy_status) && NT_SUCCESS(first_failure))
                first_failure = destroy_status;
        } else if (NT_SUCCESS(first_failure)) {
            first_failure = status ? status : STATUS_UNSUCCESSFUL;
        }

        NTSTATUS sublayer_status = _FwpmSubLayerDeleteByKey0(engine, &GUID_SLOP_SUBLAYER);
        SD_LOG("net_capture::orphan_cleanup sublayer_delete status=0x%08X win32=%lu",
            sublayer_status, status_to_win32(sublayer_status));
        if (external_block_filters_seen != 0) {
            SD_LOG("net_capture::orphan_cleanup external_block_notice count=%u action=not_deleted reason=external_owner_without_slop_sublayer_callout_or_display next_run=filter_id_layer_sublayer_callout_provider_name_desc_app_condition_logged",
                external_block_filters_seen);
        }
        SD_LOG("net_capture::orphan_cleanup summary filters_seen=%u filters_matched=%u filters_deleted=%u filter_failed=%u legacy_repo_matched=%u legacy_repo_deleted=%u legacy_repo_failed=%u block_seen=%u block_logged=%u block_suppressed=%u slop_candidates_seen=%u slop_candidates_logged=%u slop_candidates_suppressed=%u external_blocks=%u callouts_seen=%u callouts_matched=%u callouts_deleted=%u callout_failed=%u callout_candidates_seen=%u callout_candidates_logged=%u callout_candidates_suppressed=%u final_status=0x%08X final_win32=%lu",
            filters_seen,
            filters_matched,
            filters_deleted,
            filter_delete_failed,
            legacy_repo_filters_matched,
            legacy_repo_filters_deleted,
            legacy_repo_filter_delete_failed,
            block_filters_seen,
            block_filters_logged,
            block_filters_suppressed,
            slop_filter_candidates_seen,
            slop_filter_candidates_logged,
            slop_filter_candidates_suppressed,
            external_block_filters_seen,
            callouts_seen,
            callouts_matched,
            callouts_deleted,
            callout_delete_failed,
            callout_candidates_seen,
            callout_candidates_logged,
            callout_candidates_suppressed,
            first_failure,
            status_to_win32(first_failure));
        return first_failure;
    }

    void unregister_wfp();

    static NTSTATUS abort_register_wfp(const char* step, NTSTATUS status) {
        NTSTATUS abort_status = STATUS_SUCCESS;
        if (g_engine_handle && _FwpmTransactionAbort0)
            abort_status = _FwpmTransactionAbort0(g_engine_handle);
        SD_LOG("KVALIDATE build=%lu kind=layout name=WFP.registration source=bfe_runtime value=%p validation=fail evidence=\"step=%s status=0x%08X win32=%lu engine=%p callouts=%u/%u/%u/%u/%u filters=%llu/%llu/%llu/%llu/%llu\" fail_closed=register_wfp_abort",
            sd_kernel_validation_build(),
            g_engine_handle,
            step ? step : "",
            status,
            status_to_win32(status),
            g_engine_handle,
            g_callout_id_inbound,
            g_callout_id_outbound,
            g_callout_id_datagram,
            g_callout_id_ale_connect,
            g_callout_id_ale_recv,
            (unsigned long long)g_filter_id_inbound,
            (unsigned long long)g_filter_id_outbound,
            (unsigned long long)g_filter_id_datagram,
            (unsigned long long)g_filter_id_ale_connect,
            (unsigned long long)g_filter_id_ale_recv);
        SD_LOG("net_capture::register_wfp abort step=%s status=0x%08X win32=%lu abort_status=0x%08X abort_win32=%lu",
            step ? step : "",
            status,
            status_to_win32(status),
            abort_status,
            status_to_win32(abort_status));
        unregister_wfp();
        return status;
    }


    NTSTATUS register_wfp(PDEVICE_OBJECT devObj) {
        NET_DBG("register_wfp: devObj=%p", devObj);
        if (!devObj) {
            NET_ERR("register_wfp: devObj is NULL");
            return STATUS_INVALID_PARAMETER;
        }
        g_device_object = devObj;

        NTSTATUS status;


        status = _FwpmEngineOpen0(nullptr, WFP_BFE_AUTH_SERVICE,
            nullptr, nullptr, &g_engine_handle);
        NET_DBG("register_wfp: FwpmEngineOpen0 status=0x%08x handle=%p", status, g_engine_handle);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmEngineOpen0 FAILED 0x%08x", status);
            return status;
        }

        status = cleanup_startup_wfp_orphans(g_engine_handle);
        SD_LOG("net_capture::register_wfp orphan_cleanup status=0x%08X win32=%lu",
            status, status_to_win32(status));
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: orphan cleanup FAILED 0x%08x", status);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        status = _FwpmTransactionBegin0(g_engine_handle, 0);
        NET_DBG("register_wfp: FwpmTransactionBegin0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmTransactionBegin0 FAILED 0x%08x", status);
            _FwpmEngineClose0(g_engine_handle);
            g_engine_handle = nullptr;
            return status;
        }


        FWPM_DISPLAY_DATA0 sublayer_display = {};
        wchar_t sl_name[] = L"SLOPNetSublayer";
        wchar_t sl_desc[] = L"SLOP Network Monitor Sublayer";
        sublayer_display.name = sl_name;
        sublayer_display.description = sl_desc;

        FWPM_SUBLAYER0_COMPAT sublayer = {};
        sublayer.subLayerKey = GUID_SLOP_SUBLAYER;
        sublayer.displayData = sublayer_display;
        sublayer.flags = 0;
        sublayer.weight = 0xFFFF;

        status = _FwpmSubLayerAdd0(g_engine_handle, &sublayer, nullptr);
        NET_DBG("register_wfp: FwpmSubLayerAdd0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmSubLayerAdd0 FAILED 0x%08x", status);
            return abort_register_wfp("sublayer_add", status);
        }


        FWPS_CALLOUT2_COMPAT callout_in = {};
        callout_in.calloutKey = GUID_SLOP_CALLOUT_INBOUND;
        callout_in.flags = 0;
        callout_in.classifyFn = (PVOID)classify_inbound;
        callout_in.notifyFn = (PVOID)callout_notify;
        callout_in.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_in, &g_callout_id_inbound);
        NET_DBG("register_wfp: inbound callout register status=0x%08x id=%u", status, g_callout_id_inbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: inbound callout register FAILED 0x%08x", status);
            return abort_register_wfp("fwps_inbound_register", status);
        }


        FWPS_CALLOUT2_COMPAT callout_out = {};
        callout_out.calloutKey = GUID_SLOP_CALLOUT_OUTBOUND;
        callout_out.flags = 0;
        callout_out.classifyFn = (PVOID)classify_outbound;
        callout_out.notifyFn = (PVOID)callout_notify;
        callout_out.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_out, &g_callout_id_outbound);
        NET_DBG("register_wfp: outbound callout register status=0x%08x id=%u", status, g_callout_id_outbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: outbound callout register FAILED 0x%08x", status);
            return abort_register_wfp("fwps_outbound_register", status);
        }

        FWPS_CALLOUT2_COMPAT callout_datagram = {};
        callout_datagram.calloutKey = GUID_SLOP_CALLOUT_DATAGRAM;
        callout_datagram.flags = 0;
        callout_datagram.classifyFn = (PVOID)classify_datagram_v4;
        callout_datagram.notifyFn = (PVOID)callout_notify;
        callout_datagram.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_datagram, &g_callout_id_datagram);
        NET_DBG("register_wfp: datagram callout register status=0x%08x id=%u", status, g_callout_id_datagram);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: datagram callout register FAILED 0x%08x", status);
            return abort_register_wfp("fwps_datagram_register", status);
        }


        FWPM_DISPLAY_DATA0 callout_display = {};
        wchar_t co_name[] = L"SLOPNetCallout";
        wchar_t co_desc[] = L"SLOP Network Monitor Callout";
        callout_display.name = co_name;
        callout_display.description = co_desc;

        FWPM_CALLOUT0_COMPAT fwpm_callout_in = {};
        fwpm_callout_in.calloutKey = GUID_SLOP_CALLOUT_INBOUND;
        fwpm_callout_in.displayData = callout_display;
        fwpm_callout_in.applicableLayer = GUID_LAYER_INBOUND_V4;

        status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_callout_in, nullptr, &g_fwpm_callout_id_inbound);
        NET_DBG("register_wfp: inbound FWPM callout add status=0x%08x id=%u", status, g_fwpm_callout_id_inbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: inbound FWPM callout add FAILED 0x%08x", status);
            return abort_register_wfp("fwpm_inbound_callout_add", status);
        }

        FWPM_CALLOUT0_COMPAT fwpm_callout_out = {};
        fwpm_callout_out.calloutKey = GUID_SLOP_CALLOUT_OUTBOUND;
        fwpm_callout_out.displayData = callout_display;
        fwpm_callout_out.applicableLayer = GUID_LAYER_OUTBOUND_V4;

        status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_callout_out, nullptr, &g_fwpm_callout_id_outbound);
        NET_DBG("register_wfp: outbound FWPM callout add status=0x%08x id=%u", status, g_fwpm_callout_id_outbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: outbound FWPM callout add FAILED 0x%08x", status);
            return abort_register_wfp("fwpm_outbound_callout_add", status);
        }

        FWPM_CALLOUT0_COMPAT fwpm_callout_datagram = {};
        fwpm_callout_datagram.calloutKey = GUID_SLOP_CALLOUT_DATAGRAM;
        fwpm_callout_datagram.displayData = callout_display;
        fwpm_callout_datagram.applicableLayer = GUID_LAYER_DATAGRAM_V4;

        status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_callout_datagram, nullptr, &g_fwpm_callout_id_datagram);
        NET_DBG("register_wfp: datagram FWPM callout add status=0x%08x id=%u", status, g_fwpm_callout_id_datagram);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: datagram FWPM callout add FAILED 0x%08x", status);
            return abort_register_wfp("fwpm_datagram_callout_add", status);
        }


        FWPM_DISPLAY_DATA0 filter_display = {};
        wchar_t fi_name[] = L"SLOPNetFilter";
        wchar_t fi_desc[] = L"SLOP Network Monitor Filter";
        filter_display.name = fi_name;
        filter_display.description = fi_desc;

        FWPM_FILTER0_COMPAT filter_in = {};
        strong::kmemset(&filter_in, 0, sizeof(filter_in));
        filter_in.displayData = filter_display;
        filter_in.layerKey = GUID_LAYER_INBOUND_V4;
        filter_in.subLayerKey = GUID_SLOP_SUBLAYER;

        filter_in.weight.type = FWP_EMPTY_;
        filter_in.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_in.action.calloutKey = GUID_SLOP_CALLOUT_INBOUND;
        filter_in.numFilterConditions = 0;
        status = _FwpmFilterAdd0(g_engine_handle, &filter_in, nullptr, &g_filter_id_inbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: inbound filter add FAILED 0x%08x", status);
            return abort_register_wfp("inbound_filter_add", status);
        }

        FWPM_FILTER0_COMPAT filter_out = {};
        strong::kmemset(&filter_out, 0, sizeof(filter_out));
        filter_out.displayData = filter_display;
        filter_out.layerKey = GUID_LAYER_OUTBOUND_V4;
        filter_out.subLayerKey = GUID_SLOP_SUBLAYER;
        filter_out.weight.type = FWP_EMPTY_;
        filter_out.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_out.action.calloutKey = GUID_SLOP_CALLOUT_OUTBOUND;
        filter_out.numFilterConditions = 0;
        status = _FwpmFilterAdd0(g_engine_handle, &filter_out, nullptr, &g_filter_id_outbound);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: outbound filter add FAILED 0x%08x", status);
            return abort_register_wfp("outbound_filter_add", status);
        }

        FWPM_FILTER0_COMPAT filter_datagram = {};
        strong::kmemset(&filter_datagram, 0, sizeof(filter_datagram));
        filter_datagram.displayData = filter_display;
        filter_datagram.layerKey = GUID_LAYER_DATAGRAM_V4;
        filter_datagram.subLayerKey = GUID_SLOP_SUBLAYER;
        filter_datagram.weight.type = FWP_EMPTY_;
        filter_datagram.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
        filter_datagram.action.calloutKey = GUID_SLOP_CALLOUT_DATAGRAM;
        filter_datagram.numFilterConditions = 0;
        status = _FwpmFilterAdd0(g_engine_handle, &filter_datagram, nullptr, &g_filter_id_datagram);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: datagram filter add FAILED 0x%08x", status);
            return abort_register_wfp("datagram_filter_add", status);
        }


        FWPS_CALLOUT2_COMPAT callout_ale_conn = {};
        callout_ale_conn.calloutKey = GUID_SLOP_CALLOUT_ALE_CONNECT;
        callout_ale_conn.flags = 0;
        callout_ale_conn.classifyFn = (PVOID)classify_ale_connect;
        callout_ale_conn.notifyFn = (PVOID)callout_notify;
        callout_ale_conn.flowDeleteFn = nullptr;

        status = _FwpsCalloutRegister2(devObj, &callout_ale_conn, &g_callout_id_ale_connect);
        if (!NT_SUCCESS(status)) {
            g_callout_id_ale_connect = 0;
            NET_ERR("register_wfp: ALE connect callout register FAILED 0x%08x", status);
            return abort_register_wfp("fwps_ale_connect_register", status);
        } else {
            FWPS_CALLOUT2_COMPAT callout_ale_recv_co = {};
            callout_ale_recv_co.calloutKey = GUID_SLOP_CALLOUT_ALE_RECV;
            callout_ale_recv_co.flags = 0;
            callout_ale_recv_co.classifyFn = (PVOID)classify_ale_recv;
            callout_ale_recv_co.notifyFn = (PVOID)callout_notify;
            callout_ale_recv_co.flowDeleteFn = nullptr;

            status = _FwpsCalloutRegister2(devObj, &callout_ale_recv_co, &g_callout_id_ale_recv);
            NET_DBG("register_wfp: ALE recv callout register status=0x%08x id=%u", status, g_callout_id_ale_recv);
            if (!NT_SUCCESS(status)) {
                NET_ERR("register_wfp: ALE recv callout register FAILED 0x%08x", status);
                g_callout_id_ale_recv = 0;
                return abort_register_wfp("fwps_ale_recv_register", status);
            }


            if (g_callout_id_ale_connect) {
                FWPM_CALLOUT0_COMPAT fwpm_ale_conn = {};
                fwpm_ale_conn.calloutKey = GUID_SLOP_CALLOUT_ALE_CONNECT;
                fwpm_ale_conn.displayData = callout_display;
                fwpm_ale_conn.applicableLayer = GUID_LAYER_ALE_CONNECT_V4;
                NTSTATUS ale_callout_status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_ale_conn, nullptr, &g_fwpm_callout_id_ale_connect);
                NET_DBG("register_wfp: ALE connect FWPM callout add status=0x%08x id=%u",
                    ale_callout_status, g_fwpm_callout_id_ale_connect);
                if (!NT_SUCCESS(ale_callout_status)) {
                    NET_ERR("register_wfp: ALE connect FWPM callout add FAILED 0x%08x", ale_callout_status);
                    g_fwpm_callout_id_ale_connect = 0;
                    return abort_register_wfp("fwpm_ale_connect_callout_add", ale_callout_status);
                }

                FWPM_FILTER0_COMPAT filter_ale_conn = {};
                strong::kmemset(&filter_ale_conn, 0, sizeof(filter_ale_conn));
                filter_ale_conn.displayData = filter_display;
                filter_ale_conn.layerKey = GUID_LAYER_ALE_CONNECT_V4;
                filter_ale_conn.subLayerKey = GUID_SLOP_SUBLAYER;
                filter_ale_conn.weight.type = FWP_EMPTY_;
                filter_ale_conn.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
                filter_ale_conn.action.calloutKey = GUID_SLOP_CALLOUT_ALE_CONNECT;
                filter_ale_conn.numFilterConditions = 0;

                status = _FwpmFilterAdd0(g_engine_handle, &filter_ale_conn, nullptr, &g_filter_id_ale_connect);
                NET_DBG("register_wfp: ALE connect filter add status=0x%08x filter_id=%llu", status, g_filter_id_ale_connect);
                if (!NT_SUCCESS(status)) {
                    NET_ERR("register_wfp: ALE connect filter add FAILED 0x%08x", status);
                    g_filter_id_ale_connect = 0;
                    return abort_register_wfp("ale_connect_filter_add", status);
                }
            }


            if (g_callout_id_ale_recv) {
                FWPM_CALLOUT0_COMPAT fwpm_ale_recv = {};
                fwpm_ale_recv.calloutKey = GUID_SLOP_CALLOUT_ALE_RECV;
                fwpm_ale_recv.displayData = callout_display;
                fwpm_ale_recv.applicableLayer = GUID_LAYER_ALE_RECV_V4;
                NTSTATUS ale_callout_status = _FwpmCalloutAdd0(g_engine_handle, &fwpm_ale_recv, nullptr, &g_fwpm_callout_id_ale_recv);
                NET_DBG("register_wfp: ALE recv FWPM callout add status=0x%08x id=%u",
                    ale_callout_status, g_fwpm_callout_id_ale_recv);
                if (!NT_SUCCESS(ale_callout_status)) {
                    NET_ERR("register_wfp: ALE recv FWPM callout add FAILED 0x%08x", ale_callout_status);
                    g_fwpm_callout_id_ale_recv = 0;
                    return abort_register_wfp("fwpm_ale_recv_callout_add", ale_callout_status);
                }

                FWPM_FILTER0_COMPAT filter_ale_recv = {};
                strong::kmemset(&filter_ale_recv, 0, sizeof(filter_ale_recv));
                filter_ale_recv.displayData = filter_display;
                filter_ale_recv.layerKey = GUID_LAYER_ALE_RECV_V4;
                filter_ale_recv.subLayerKey = GUID_SLOP_SUBLAYER;
                filter_ale_recv.weight.type = FWP_EMPTY_;
                filter_ale_recv.action.type = FWP_ACTION_CALLOUT_TERMINATING_;
                filter_ale_recv.action.calloutKey = GUID_SLOP_CALLOUT_ALE_RECV;
                filter_ale_recv.numFilterConditions = 0;

                status = _FwpmFilterAdd0(g_engine_handle, &filter_ale_recv, nullptr, &g_filter_id_ale_recv);
                NET_DBG("register_wfp: ALE recv filter add status=0x%08x filter_id=%llu", status, g_filter_id_ale_recv);
                if (!NT_SUCCESS(status)) {
                    NET_ERR("register_wfp: ALE recv filter add FAILED 0x%08x", status);
                    g_filter_id_ale_recv = 0;
                    return abort_register_wfp("ale_recv_filter_add", status);
                }
            }

        }


        status = STATUS_SUCCESS;


        status = _FwpmTransactionCommit0(g_engine_handle);
        NET_DBG("register_wfp: FwpmTransactionCommit0 status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("register_wfp: FwpmTransactionCommit0 FAILED 0x%08x", status);
            return abort_register_wfp("transaction_commit", status);
        }

        if (!g_callout_id_inbound || !g_callout_id_outbound || !g_callout_id_datagram ||
            !g_callout_id_ale_connect || !g_callout_id_ale_recv ||
            !g_fwpm_callout_id_inbound || !g_fwpm_callout_id_outbound || !g_fwpm_callout_id_datagram ||
            !g_fwpm_callout_id_ale_connect || !g_fwpm_callout_id_ale_recv ||
            !g_filter_id_inbound || !g_filter_id_outbound || !g_filter_id_datagram ||
            !g_filter_id_ale_connect || !g_filter_id_ale_recv) {
            SD_LOG("net_capture::register_wfp false_success inbound=%u outbound=%u datagram=%u ale_conn=%u ale_recv=%u fwpm_in=%u fwpm_out=%u fwpm_datagram=%u fwpm_ale_conn=%u fwpm_ale_recv=%u filter_in=%llu filter_out=%llu filter_datagram=%llu filter_ale_conn=%llu filter_ale_recv=%llu status=0x%08X",
                g_callout_id_inbound,
                g_callout_id_outbound,
                g_callout_id_datagram,
                g_callout_id_ale_connect,
                g_callout_id_ale_recv,
                g_fwpm_callout_id_inbound,
                g_fwpm_callout_id_outbound,
                g_fwpm_callout_id_datagram,
                g_fwpm_callout_id_ale_connect,
                g_fwpm_callout_id_ale_recv,
                (unsigned long long)g_filter_id_inbound,
                (unsigned long long)g_filter_id_outbound,
                (unsigned long long)g_filter_id_datagram,
                (unsigned long long)g_filter_id_ale_connect,
                (unsigned long long)g_filter_id_ale_recv,
                (UINT32)STATUS_UNSUCCESSFUL);
            unregister_wfp();
            return STATUS_UNSUCCESSFUL;
        }

        NET_DBG("register_wfp: SUCCESS — inbound_id=%u outbound_id=%u ale_conn_id=%u ale_recv_id=%u",
                g_callout_id_inbound, g_callout_id_outbound,
                g_callout_id_ale_connect, g_callout_id_ale_recv);
        SD_LOG("KVALIDATE build=%lu kind=layout name=WFP.registration source=bfe_runtime value=%p validation=pass evidence=\"engine=%p sublayer_weight=0xFFFF callouts=%u/%u/%u/%u/%u fwpm=%u/%u/%u/%u/%u filters=%llu/%llu/%llu/%llu/%llu layers=transport_v4,datagram_v4,ale_v4\" fail_closed=none",
            sd_kernel_validation_build(),
            g_engine_handle,
            g_engine_handle,
            g_callout_id_inbound,
            g_callout_id_outbound,
            g_callout_id_datagram,
            g_callout_id_ale_connect,
            g_callout_id_ale_recv,
            g_fwpm_callout_id_inbound,
            g_fwpm_callout_id_outbound,
            g_fwpm_callout_id_datagram,
            g_fwpm_callout_id_ale_connect,
            g_fwpm_callout_id_ale_recv,
            (unsigned long long)g_filter_id_inbound,
            (unsigned long long)g_filter_id_outbound,
            (unsigned long long)g_filter_id_datagram,
            (unsigned long long)g_filter_id_ale_connect,
            (unsigned long long)g_filter_id_ale_recv);
        return STATUS_SUCCESS;
    }

    void unregister_wfp() {
        if (g_engine_handle) {
            UINT64* filter_ids[] = {
                &g_filter_id_ale_recv,
                &g_filter_id_ale_connect,
                &g_filter_id_inbound,
                &g_filter_id_outbound,
                &g_filter_id_datagram
            };
            for (UINT32 i = 0; i < sizeof(filter_ids) / sizeof(filter_ids[0]); ++i) {
                if (*filter_ids[i] && _FwpmFilterDeleteById0) {
                    UINT64 id = *filter_ids[i];
                    NTSTATUS del_status = _FwpmFilterDeleteById0(g_engine_handle, id);
                    SD_LOG("net_capture::unregister_wfp filter_delete index=%u id=%llu status=0x%08X win32=%lu",
                        i,
                        (unsigned long long)id,
                        del_status,
                        status_to_win32(del_status));
                    *filter_ids[i] = 0;
                }
            }

            UINT32* fwpm_callout_ids[] = {
                &g_fwpm_callout_id_ale_recv,
                &g_fwpm_callout_id_ale_connect,
                &g_fwpm_callout_id_inbound,
                &g_fwpm_callout_id_outbound,
                &g_fwpm_callout_id_datagram
            };
            for (UINT32 i = 0; i < sizeof(fwpm_callout_ids) / sizeof(fwpm_callout_ids[0]); ++i) {
                if (*fwpm_callout_ids[i] && _FwpmCalloutDeleteById0) {
                    UINT32 id = *fwpm_callout_ids[i];
                    NTSTATUS del_status = _FwpmCalloutDeleteById0(g_engine_handle, id);
                    SD_LOG("net_capture::unregister_wfp fwpm_callout_delete index=%u id=%u status=0x%08X win32=%lu",
                        i,
                        id,
                        del_status,
                        status_to_win32(del_status));
                    *fwpm_callout_ids[i] = 0;
                }
            }

            if (_FwpmSubLayerDeleteByKey0) {
                NTSTATUS sublayer_status = _FwpmSubLayerDeleteByKey0(g_engine_handle, &GUID_SLOP_SUBLAYER);
                SD_LOG("net_capture::unregister_wfp sublayer_delete status=0x%08X win32=%lu",
                    sublayer_status,
                    status_to_win32(sublayer_status));
            }
            NTSTATUS close_status = _FwpmEngineClose0(g_engine_handle);
            SD_LOG("net_capture::unregister_wfp engine_close status=0x%08X win32=%lu",
                close_status,
                status_to_win32(close_status));
            g_engine_handle = nullptr;
        }

        UINT32* fwps_callout_ids[] = {
            &g_callout_id_ale_recv,
            &g_callout_id_ale_connect,
            &g_callout_id_inbound,
            &g_callout_id_outbound,
            &g_callout_id_datagram
        };
        // FwpsCalloutUnregisterById0 returns STATUS_DEVICE_BUSY while a
        // classify is executing on another CPU. Filters are already deleted,
        // so no NEW dispatch can happen — retry until the in-flight ones
        // drain, then proceed. Bounded: classifies complete in microseconds,
        // so 25 x 10 ms only expires under a system-wide network stall.
        for (UINT32 round = 0; round < 25; ++round) {
            BOOLEAN any_busy = FALSE;
            for (UINT32 i = 0; i < sizeof(fwps_callout_ids) / sizeof(fwps_callout_ids[0]); ++i) {
                if (*fwps_callout_ids[i] && _FwpsCalloutUnregisterById0) {
                    UINT32 id = *fwps_callout_ids[i];
                    NTSTATUS unreg_status = _FwpsCalloutUnregisterById0(id);
                    SD_LOG("net_capture::unregister_wfp fwps_callout_unregister index=%u id=%u status=0x%08X win32=%lu round=%lu",
                        i,
                        id,
                        unreg_status,
                        status_to_win32(unreg_status),
                        round);
                    if (NT_SUCCESS(unreg_status)) {
                        *fwps_callout_ids[i] = 0;
                    }
                    else if (unreg_status == STATUS_DEVICE_BUSY) {
                        any_busy = TRUE;
                    }
                }
            }
            if (!any_busy) break;
            LARGE_INTEGER pause;
            pause.QuadPart = -(10LL * 10000LL);   // 10 ms
            KeDelayExecutionThread(KernelMode, FALSE, &pause);
        }
        g_fwpm_callout_id_ale_recv = 0;
        g_fwpm_callout_id_ale_connect = 0;
        g_fwpm_callout_id_inbound = 0;
        g_fwpm_callout_id_outbound = 0;
        g_fwpm_callout_id_datagram = 0;
        g_filter_id_ale_recv = 0;
        g_filter_id_ale_connect = 0;
        g_filter_id_inbound = 0;
        g_filter_id_outbound = 0;
        g_filter_id_datagram = 0;
        g_device_object = nullptr;
    }


    NTSTATUS initialize(PDEVICE_OBJECT devObj) {
        NET_DBG("initialize: starting WFP init, devObj=%p", devObj);
        ULONG build = runtime_build_number();
        if (startup_wfp_degraded_for_build(build)) {
            g_device_object = devObj;
            KeInitializeSpinLock(&g_ring_lock);
            KeInitializeSpinLock(&g_dns_lock);
            KeInitializeSpinLock(&g_seq_delta_lock);
            KeInitializeSpinLock(&g_udp_flow_lock);
            KeInitializeSpinLock(&g_pid_path_lock);
            KeInitializeSpinLock(&net_fingerprint::g_fp_lock);
            _InterlockedExchange(&g_capture_active, 0);
            _InterlockedExchange(&g_wfp_degraded, 1);
            _InterlockedExchange(&g_wfp_initialized, 3);
            SD_LOG("net_capture::initialize DEGRADED build=%lu state=3 device=%p", build, devObj);
            return STATUS_SUCCESS;
        }
        LONG prev = _InterlockedCompareExchange(&g_wfp_initialized, 1, 0);
        if (prev == 2) {
            NET_DBG("initialize: already initialized (state=2)");
            return STATUS_SUCCESS;
        }
        if (prev == 3) {
            NET_DBG("initialize: degraded unsupported build state=3");
            return STATUS_NOT_SUPPORTED;
        }
        if (prev == 1) {
            NET_DBG("initialize: concurrent init detected, waiting...");
            for (UINT32 spin = 0; spin < 10000000u; spin++) {
                if (_InterlockedCompareExchange(&g_wfp_initialized, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return (g_wfp_initialized == 2) ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
        }

        NTSTATUS status = STATUS_SUCCESS;


        KeInitializeSpinLock(&g_ring_lock);
        KeInitializeSpinLock(&g_dns_lock);
        KeInitializeSpinLock(&g_seq_delta_lock);
        KeInitializeSpinLock(&g_udp_flow_lock);
        KeInitializeSpinLock(&g_pid_path_lock);
        KeInitializeSpinLock(&net_fingerprint::g_fp_lock);
        net_bw::init_lock();


        SIZE_T ring_size = (SIZE_T)RING_BUFFER_SIZE * sizeof(NET_PACKET_ENTRY);
        g_ring_buffer = (NET_PACKET_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, ring_size, 'pkNW');
        if (!g_ring_buffer) {
            NET_ERR("initialize: packet ring alloc FAILED (size=%llu)", (ULONGLONG)ring_size);
            _InterlockedExchange(&g_wfp_degraded, 0);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NET_DBG("initialize: packet ring allocated at %p (size=%llu, entries=%u)",
                g_ring_buffer, (ULONGLONG)ring_size, RING_BUFFER_SIZE);
        strong::kmemset(g_ring_buffer, 0, ring_size);

        SIZE_T dns_size = (SIZE_T)DNS_RING_SIZE * sizeof(NET_DNS_ENTRY);
        g_dns_ring = (NET_DNS_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, dns_size, 'dnNW');
        if (!g_dns_ring) {
            NET_ERR("initialize: DNS ring alloc FAILED (size=%llu)", (ULONGLONG)dns_size);
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            _InterlockedExchange(&g_wfp_degraded, 0);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        NET_DBG("initialize: DNS ring allocated at %p (size=%llu, entries=%u)",
                g_dns_ring, (ULONGLONG)dns_size, DNS_RING_SIZE);
        strong::kmemset(g_dns_ring, 0, dns_size);

        net_intercept::init_lock();
        net_redirect::init_lock();

        status = net_dpi::init();
        NET_DBG("initialize: net_dpi::init status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("initialize: DPI init FAILED 0x%08x", status);
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_degraded, 0);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return status;
        }


        if (!resolve_wfp_functions()) {
            NET_ERR("initialize: resolve_wfp_functions FAILED");
            net_dpi::cleanup();
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
            _InterlockedExchange(&g_wfp_degraded, 0);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return STATUS_NOT_SUPPORTED;
        }

        if (!net_inject::prepare_injection_runtime()) {
            NET_ERR("initialize: injection runtime prewarm FAILED; reinjection-only features will report not-supported instead of resolving inside WFP callouts");
        }


        status = register_wfp(devObj);
        NET_DBG("initialize: register_wfp status=0x%08x", status);
        if (!NT_SUCCESS(status)) {
            NET_ERR("initialize: register_wfp FAILED 0x%08x", status);
            SD_LOG("net_capture::initialize FAIL step=register_wfp status=0x%08X ring_ready=%u dns_ready=%u",
                status,
                g_ring_buffer != nullptr ? 1u : 0u,
                g_dns_ring != nullptr ? 1u : 0u);
            _InterlockedExchange(&g_capture_active, 0);
            g_filter_pid = 0;
            g_filter_port = 0;
            g_filter_protocol = 0;
            strong::kmemset(g_filter_ip, 0, sizeof(g_filter_ip));
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                _InterlockedExchange(&g_filter_rules[i].active, 0);
            }
            _InterlockedExchange(&g_active_rule_count, 0);
            net_intercept::cleanup();
            net_redirect::cleanup();
            net_dns_spoof::cleanup();
            net_bw::cleanup();
            net_inject::cleanup();
            net_fingerprint::cleanup();
            net_dpi::cleanup();
            if (g_ring_buffer) {
                ExFreePoolWithTag(g_ring_buffer, 'pkNW');
                g_ring_buffer = nullptr;
            }
            if (g_dns_ring) {
                ExFreePoolWithTag(g_dns_ring, 'dnNW');
                g_dns_ring = nullptr;
            }
            _InterlockedExchange(&g_wfp_degraded, 0);
            _InterlockedExchange(&g_wfp_initialized, 0);
            return status;
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_wfp_degraded, 0);
        _InterlockedExchange(&g_wfp_initialized, 2);
        NET_DBG("initialize: WFP fully initialized (state=2)");
        SD_LOG("net_capture::initialize OK state=2 ring_ready=%u dns_ready=%u max_payload=%u",
            g_ring_buffer != nullptr ? 1u : 0u,
            g_dns_ring != nullptr ? 1u : 0u,
            g_max_payload);


        NET_DBG("initialize: pre-resolving AFD offsets");
        afd_init_offsets();
        NET_DBG("initialize: AFD offsets resolved");

        return STATUS_SUCCESS;
    }

    void cleanup() {
        _InterlockedExchange(&g_capture_active, 0);
        _InterlockedExchange(&g_wfp_degraded, 0);
        g_filter_pid = 0;
        g_filter_port = 0;
        g_filter_protocol = 0;
        strong::kmemset(g_filter_ip, 0, sizeof(g_filter_ip));
        for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
            _InterlockedExchange(&g_filter_rules[i].active, 0);
        }
        _InterlockedExchange(&g_active_rule_count, 0);
        unregister_wfp();
        net_inject::cleanup();
        net_stream::cleanup();
        net_dpi::cleanup();
        net_intercept::cleanup();
        net_redirect::cleanup();
        net_dns_spoof::cleanup();
        net_fingerprint::cleanup();
        net_bw::cleanup();

        // A registered callout whose classify is still in flight can be
        // reading the rings. unregister_wfp() retried until drained; if any
        // callout refused to go, leak the rings instead of racing a classify
        // into freed memory (a bounded leak beats a BSOD on unload).
        const BOOLEAN callouts_quiesced =
            g_callout_id_inbound == 0 && g_callout_id_outbound == 0 &&
            g_callout_id_datagram == 0 && g_callout_id_ale_connect == 0 &&
            g_callout_id_ale_recv == 0;
        if (!callouts_quiesced) {
            SD_LOG("net_capture::cleanup callouts_still_registered — leaking rings (unload race guard)");
        }
        if (g_ring_buffer && callouts_quiesced) {
            ExFreePoolWithTag(g_ring_buffer, 'pkNW');
            g_ring_buffer = nullptr;
        }
        if (g_dns_ring && callouts_quiesced) {
            ExFreePoolWithTag(g_dns_ring, 'dnNW');
            g_dns_ring = nullptr;
        }

        _InterlockedExchange(&g_wfp_initialized, 0);
    }

}


typedef struct _SLOP_SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR  ObjectTypeIndex;
    UCHAR  HandleAttributes;
    USHORT HandleValue;
    PVOID  Object;
    ULONG  GrantedAccess;
} SLOP_SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SLOP_SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SLOP_SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SLOP_SYSTEM_HANDLE_INFORMATION, *PSLOP_SYSTEM_HANDLE_INFORMATION;

static NTSTATUS slop_query_system_handles(PSLOP_SYSTEM_HANDLE_INFORMATION* out_info) {
    if (!out_info) return STATUS_INVALID_PARAMETER;
    *out_info = nullptr;

    if (!slop_can_query_system_handles()) {
        NET_ERR("query_handles: blocked - not at PASSIVE_LEVEL");
        return STATUS_INVALID_DEVICE_STATE;
    }

    constexpr SYSTEM_INFORMATION_CLASS_INTERNAL system_handle_information_class =
        (SYSTEM_INFORMATION_CLASS_INTERNAL)16;

    NET_DBG("query_handles: ENTER initial_size=4MB");
    ULONG size = 0x400000;
    for (UINT32 attempt = 0; attempt < 4; attempt++) {
        NET_DBG("query_handles: attempt %u alloc_size=%lu", attempt, size);
        PSLOP_SYSTEM_HANDLE_INFORMATION info = (PSLOP_SYSTEM_HANDLE_INFORMATION)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, size, 'hANW');
        if (!info) {
            NET_ERR("query_handles: alloc FAILED size=%lu", size);
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ULONG required = 0;
        NET_DBG("query_handles: calling ZwQuerySystemInformation...");
        NTSTATUS status = ZwQuerySystemInformation(system_handle_information_class, info, size, &required);
        NET_DBG("query_handles: ZwQuery returned 0x%08x required=%lu", status, required);
        if (NT_SUCCESS(status)) {
            NET_DBG("query_handles: SUCCESS handle_count=%lu", info->NumberOfHandles);
            *out_info = info;
            return STATUS_SUCCESS;
        }

        ExFreePoolWithTag(info, 'hANW');
        if (status != STATUS_INFO_LENGTH_MISMATCH && status != STATUS_BUFFER_TOO_SMALL) {
            NET_ERR("query_handles: unexpected status 0x%08x", status);
            return status;
        }

        size = (required > size) ? (required + 0x4000) : (size << 1);
    }

    NET_ERR("query_handles: exhausted 4 attempts");
    return STATUS_INSUFFICIENT_RESOURCES;
}


static BOOLEAN slop_is_afd_file_object(PFILE_OBJECT fileObj) {
    if (!fileObj)
        return FALSE;

    BOOLEAN is_afd = FALSE;

    __try {

        PDEVICE_OBJECT devObj = fileObj->DeviceObject;
        if (!devObj)
            __leave;

        PDRIVER_OBJECT drvObj = devObj->DriverObject;
        if (!drvObj)
            __leave;

        PUNICODE_STRING drvName = &drvObj->DriverName;


        if (!drvName->Buffer || drvName->Length < 8)
            __leave;

        USHORT max_chars = (USHORT)(drvName->Length / sizeof(wchar_t));
        if (max_chars > 128) {
            max_chars = 128;
        }


        wchar_t* buf = drvName->Buffer;
        for (USHORT i = 0; i + 2 < max_chars; i++) {
            wchar_t c0 = buf[i];
            wchar_t c1 = buf[i + 1];
            wchar_t c2 = buf[i + 2];
            if (c0 >= 'a' && c0 <= 'z') c0 -= 32;
            if (c1 >= 'a' && c1 <= 'z') c1 -= 32;
            if (c2 >= 'a' && c2 <= 'z') c2 -= 32;
            if (c0 == 'A' && c1 == 'F' && c2 == 'D') {
                is_afd = TRUE;
                break;
            }
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        is_afd = FALSE;
    }

    return is_afd;
}

static BOOLEAN slop_ip_bytes_equal(const UINT8* left, const UINT8* right, UINT32 len) {
    if (!left || !right) return FALSE;
    for (UINT32 i = 0; i < len; i++) {
        if (left[i] != right[i]) {
            return FALSE;
        }
    }
    return TRUE;
}


struct afd_endpoint_offsets_t {
    ULONG transport_info;
    ULONG local_addr_size;
    ULONG local_addr_ptr;
};


static const afd_endpoint_offsets_t g_afd_fallback_win10 = { 0xF8,  0xDC,  0xE0  };
static const afd_endpoint_offsets_t g_afd_fallback_win11 = { 0x110, 0xEC,  0xF0  };

static afd_endpoint_offsets_t g_afd_offsets = {};
static volatile LONG g_afd_offsets_state = 0;

static __forceinline BOOLEAN afd_endpoint_signature_valid(USHORT sig) {
    return sig == 0xAFD0 || sig == 0xAAFD || sig == 0xAFD1 || sig == 0xAFD2;
}

static __forceinline WCHAR slop_upcase_wchar(WCHAR ch) {
    return (ch >= L'a' && ch <= L'z') ? static_cast<WCHAR>(ch - L'a' + L'A') : ch;
}

static BOOLEAN slop_unicode_ends_with_ascii(PWCH buf, USHORT chars, const char* suffix) {
    if (!buf || !suffix) return FALSE;
    USHORT suffix_len = 0;
    while (suffix[suffix_len] != 0) suffix_len++;
    if (suffix_len == 0 || chars < suffix_len) return FALSE;
    PWCH start = buf + chars - suffix_len;
    if (!_MmIsAddressValid(start) || !_MmIsAddressValid(start + suffix_len - 1)) return FALSE;
    for (USHORT i = 0; i < suffix_len; ++i) {
        WCHAR left = slop_upcase_wchar(start[i]);
        char r = suffix[i];
        if (r >= 'a' && r <= 'z') r = static_cast<char>(r - 'a' + 'A');
        if (left != static_cast<WCHAR>(r)) return FALSE;
    }
    return TRUE;
}

static BOOLEAN afd_classic_transport_name(UINT8* transport_info, UINT32* out_af, UINT32* out_proto) {
    if (!transport_info || !out_af || !out_proto) return FALSE;
    if (!_MmIsAddressValid(transport_info + 0x27)) return FALSE;
    UNICODE_STRING* name = reinterpret_cast<UNICODE_STRING*>(transport_info + 0x18);
    USHORT chars = static_cast<USHORT>(name->Length / sizeof(WCHAR));
    if (name->Length == 0 || (name->Length & 1) != 0 || chars > 128 || !name->Buffer) return FALSE;
    if (!_MmIsAddressValid(name->Buffer) || !_MmIsAddressValid(name->Buffer + chars - 1)) return FALSE;

    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "Tcp6")) {
        *out_af = AF_INET6;
        *out_proto = IPPROTO_TCP;
        return TRUE;
    }
    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "Udp6")) {
        *out_af = AF_INET6;
        *out_proto = IPPROTO_UDP;
        return TRUE;
    }
    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "RawIp6")) {
        *out_af = AF_INET6;
        *out_proto = 0;
        return TRUE;
    }
    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "Tcp")) {
        *out_af = AF_INET;
        *out_proto = IPPROTO_TCP;
        return TRUE;
    }
    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "Udp")) {
        *out_af = AF_INET;
        *out_proto = IPPROTO_UDP;
        return TRUE;
    }
    if (slop_unicode_ends_with_ascii(name->Buffer, chars, "RawIp")) {
        *out_af = AF_INET;
        *out_proto = 0;
        return TRUE;
    }
    return FALSE;
}


static BOOLEAN afd_resolve_offsets_by_scan() {
    NET_DBG("afd_resolve: ENTER");
    PVOID afd_base = net_capture::find_module_base("afd.sys");
    NET_DBG("afd_resolve: find_module_base('afd.sys') => %p", afd_base);
    if (!afd_base) afd_base = net_capture::find_module_base("afd.SYS");
    if (!afd_base) {
        NET_ERR("afd_resolve: afd.sys not found in module list");
        SD_KERNEL_PATTERN_LOG_PTR("AFD.endpoint_offsets", "semantic_scan", "afd.sys", nullptr, FALSE,
            "afd.sys module not present in loaded module list", "module_not_found");
        return FALSE;
    }

    NET_DBG("afd_resolve: afd_base=%p, starting pattern scan", afd_base);


    static const UCHAR pat_w11_rcx_a[] = {
        0x48, 0x89, 0x8F, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w11_rax_a[] = {
        0x48, 0x89, 0x87, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w11_rdx_a[] = {
        0x48, 0x89, 0x97, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w11_rdx_b[] = {
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x89, 0x97, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w11_r15_ebx_a[] = {
        0x4C, 0x89, 0xBF, 0x00, 0x00, 0x00, 0x00,
        0x89, 0x9F, 0x00, 0x00, 0x00, 0x00
    };

    static const UCHAR pat_w10_a[] = {
        0x4C, 0x89, 0xBF, 0x00, 0x00, 0x00, 0x00,
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00
    };
    static const UCHAR pat_w10_b[] = {
        0x44, 0x89, 0xA7, 0x00, 0x00, 0x00, 0x00,
        0x4C, 0x89, 0xBF, 0x00, 0x00, 0x00, 0x00
    };
    static const char mask_a[] = "xxx??xxxxx??xx";
    static const char mask_b[] = "xxx??xxxxx??xx";
    static const char mask_c[] = "xxx??xxxx??xx";
    static const UCHAR pat_ti_w11_110[] = { 0x48, 0x8D, 0x9F, 0x10, 0x01, 0x00, 0x00 };
    static const UCHAR pat_ti_w11_110_rax[] = { 0x48, 0x8D, 0x87, 0x10, 0x01, 0x00, 0x00 };
    static const UCHAR pat_ti_w11_108[] = { 0x48, 0x8D, 0x9F, 0x08, 0x01, 0x00, 0x00 };
    static const UCHAR pat_ti_w11_108_rax[] = { 0x48, 0x8D, 0x87, 0x08, 0x01, 0x00, 0x00 };
    static const UCHAR pat_ti_w10_f8_rax[] = { 0x48, 0x8D, 0x87, 0xF8, 0x00, 0x00, 0x00 };
    static const UCHAR pat_ti_w10_f8_rbx[] = { 0x48, 0x8D, 0x9F, 0xF8, 0x00, 0x00, 0x00 };
    static const char mask_ti[] = "xxxxxxx";

    ULONG local_addr_size = 0;
    ULONG local_addr_ptr  = 0;
    PVOID match = nullptr;
    BOOLEAN reversed = FALSE;
    BOOLEAN short_local_pair = FALSE;
    const char* pattern_name = "none";
    const char* fail_reason = "none";


    BOOLEAN is_win11 = slopdrvr_kernel_layout::is_windows_11_or_newer();

    if (is_win11) {
        NET_DBG("afd_resolve: Win11 detected, scanning Win11 patterns first...");
        match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rcx_a, mask_a);
        if (match) pattern_name = "win11_rcx_a";
        NET_DBG("afd_resolve: Win11 RCX pattern A result=%p", match);
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rax_a, mask_a);
            if (match) pattern_name = "win11_rax_a";
            NET_DBG("afd_resolve: Win11 RAX pattern A result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rdx_a, mask_a);
            if (match) pattern_name = "win11_rdx_a";
            NET_DBG("afd_resolve: Win11 RDX pattern A result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_r15_ebx_a, mask_c);
            if (match) {
                pattern_name = "win11_r15_ebx_a";
                short_local_pair = TRUE;
            }
            NET_DBG("afd_resolve: Win11 R15/EBX pattern A result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rdx_b, mask_b);
            if (match) pattern_name = "win11_rdx_b";
            NET_DBG("afd_resolve: Win11 RDX pattern B result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (!match) {
        NET_DBG("afd_resolve: scanning Win10 patterns...");
        match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w10_a, mask_a);
        if (match) pattern_name = "win10_a";
        NET_DBG("afd_resolve: Win10 pattern A result=%p", match);
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w10_b, mask_b);
            if (match) pattern_name = "win10_b";
            NET_DBG("afd_resolve: Win10 pattern B result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (!match && !is_win11) {
        NET_DBG("afd_resolve: scanning Win11 patterns as fallback...");
        match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rcx_a, mask_a);
        if (match) pattern_name = "win11_rcx_a_fallback";
        NET_DBG("afd_resolve: Win11 RCX pattern A fallback result=%p", match);
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rax_a, mask_a);
            if (match) pattern_name = "win11_rax_a_fallback";
            NET_DBG("afd_resolve: Win11 RAX pattern A fallback result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rdx_a, mask_a);
            if (match) pattern_name = "win11_rdx_a_fallback";
            NET_DBG("afd_resolve: Win11 RDX pattern A fallback result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_r15_ebx_a, mask_c);
            if (match) {
                pattern_name = "win11_r15_ebx_a_fallback";
                short_local_pair = TRUE;
            }
            NET_DBG("afd_resolve: Win11 R15/EBX pattern A fallback result=%p", match);
        }
        if (!match) {
            match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_w11_rdx_b, mask_b);
            if (match) pattern_name = "win11_rdx_b_fallback";
            NET_DBG("afd_resolve: Win11 RDX pattern B fallback result=%p", match);
            reversed = (match != nullptr);
        }
    }

    if (match) {
        UCHAR* p = static_cast<UCHAR*>(match);
        if (reversed) {
            local_addr_size = *reinterpret_cast<ULONG*>(p + 3);
            local_addr_ptr  = *reinterpret_cast<ULONG*>(p + 10);
        } else if (short_local_pair) {
            local_addr_ptr  = *reinterpret_cast<ULONG*>(p + 3);
            local_addr_size = *reinterpret_cast<ULONG*>(p + 9);
        } else {
            local_addr_ptr  = *reinterpret_cast<ULONG*>(p + 3);
            local_addr_size = *reinterpret_cast<ULONG*>(p + 10);
        }
    }

    if (!match) {
        NET_ERR("afd_resolve: no pattern match in afd.sys");
        SD_LOG("KVALIDATE build=%lu kind=pattern name=AFD.endpoint_offsets source=semantic_scan pattern=%s value=%p validation=fail evidence=\"afd_base=%p is_win11=%u masks=%s/%s\" fail_closed=pattern_not_found",
            sd_kernel_validation_build(),
            pattern_name,
            match,
            afd_base,
            is_win11 ? 1u : 0u,
            mask_a,
            mask_b);
        return FALSE;
    }

    if (local_addr_ptr != local_addr_size + 4) {
        fail_reason = "ptr_size_delta_invalid";
        SD_LOG("KVALIDATE build=%lu kind=pattern name=AFD.endpoint_offsets source=semantic_scan pattern=%s value=%p validation=fail evidence=\"transport=unresolved size=0x%X ptr=0x%X reversed=%u expected_delta=4 afd_base=%p\" fail_closed=%s",
            sd_kernel_validation_build(),
            pattern_name,
            match,
            local_addr_size,
            local_addr_ptr,
            reversed ? 1u : 0u,
            afd_base,
            fail_reason);
        NET_ERR("afd_resolve: validation failed size=0x%X ptr=0x%X (expected delta=4)",
                local_addr_size, local_addr_ptr);
        return FALSE;
    }

    if (local_addr_size < 0x80 || local_addr_size > 0x400) {
        fail_reason = "local_addr_size_out_of_range";
        SD_LOG("KVALIDATE build=%lu kind=pattern name=AFD.endpoint_offsets source=semantic_scan pattern=%s value=%p validation=fail evidence=\"size=0x%X ptr=0x%X reversed=%u range=0x80..0x400 afd_base=%p\" fail_closed=%s",
            sd_kernel_validation_build(),
            pattern_name,
            match,
            local_addr_size,
            local_addr_ptr,
            reversed ? 1u : 0u,
            afd_base,
            fail_reason);
        NET_ERR("afd_resolve: local_addr_size 0x%X out of expected range", local_addr_size);
        return FALSE;
    }

    ULONG transport_info = 0;
    PVOID transport_match = nullptr;
    const char* transport_pattern = "none";

    if (local_addr_size == 0xEC && local_addr_ptr == 0xF0) {
        transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w11_110, mask_ti);
        if (transport_match) {
            transport_info = 0x110;
            transport_pattern = "win11_ti_110";
        } else {
            transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w11_110_rax, mask_ti);
            if (transport_match) {
                transport_info = 0x110;
                transport_pattern = "win11_ti_110_rax";
            }
        }
        if (!transport_match) {
            transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w11_108, mask_ti);
            if (transport_match) {
                transport_info = 0x108;
                transport_pattern = "win11_ti_108";
            } else {
                transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w11_108_rax, mask_ti);
                if (transport_match) {
                    transport_info = 0x108;
                    transport_pattern = "win11_ti_108_rax";
                }
            }
        }
    } else if (local_addr_size == 0xDC && local_addr_ptr == 0xE0) {
        transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w10_f8_rax, mask_ti);
        if (transport_match) {
            transport_info = 0xF8;
            transport_pattern = "win10_ti_f8_rax";
        } else {
            transport_match = slopdrvr_kernel_layout::find_pattern_in_all_sections(afd_base, pat_ti_w10_f8_rbx, mask_ti);
            if (transport_match) {
                transport_info = 0xF8;
                transport_pattern = "win10_ti_f8_rbx";
            }
        }
    }

    if (transport_info == 0) {
        fail_reason = "transport_pattern_not_found";
        SD_LOG("KVALIDATE build=%lu kind=pattern name=AFD.endpoint_transport_info source=semantic_scan pattern=%s value=%p validation=fail evidence=\"transport_pattern=%s transport_match=%p size=0x%X ptr=0x%X afd_base=%p is_win11=%u\" fail_closed=%s",
            sd_kernel_validation_build(),
            pattern_name,
            match,
            transport_pattern,
            transport_match,
            local_addr_size,
            local_addr_ptr,
            afd_base,
            is_win11 ? 1u : 0u,
            fail_reason);
        NET_ERR("afd_resolve: transport_info pattern not found for size=0x%X ptr=0x%X",
                local_addr_size, local_addr_ptr);
        return FALSE;
    }

    if (transport_info < 0x80 || transport_info > 0x400 || (transport_info & 7) != 0) {
        fail_reason = "transport_info_out_of_range";
        SD_LOG("KVALIDATE build=%lu kind=pattern name=AFD.endpoint_offsets source=semantic_scan pattern=%s value=%p validation=fail evidence=\"transport_pattern=%s transport_match=%p transport=0x%X size=0x%X ptr=0x%X afd_base=%p\" fail_closed=%s",
            sd_kernel_validation_build(),
            pattern_name,
            match,
            transport_pattern,
            transport_match,
            transport_info,
            local_addr_size,
            local_addr_ptr,
            afd_base,
            fail_reason);
        NET_ERR("afd_resolve: transport_info 0x%X out of expected range", transport_info);
        return FALSE;
    }

    g_afd_offsets.transport_info  = transport_info;
    g_afd_offsets.local_addr_size = local_addr_size;
    g_afd_offsets.local_addr_ptr  = local_addr_ptr;

    NET_DBG("afd_resolve: SCAN OK transport=+0x%X size=+0x%X ptr=+0x%X (match=%p transport_match=%p)",
            transport_info, local_addr_size, local_addr_ptr, match, transport_match);
    SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.endpoint_offsets source=semantic_scan offset=0x%llx validation=pass evidence=\"pattern=%s match=%p reversed=%u transport_pattern=%s transport_match=%p afd_base=%p transport=0x%X local_size=0x%X local_ptr=0x%X\" fail_closed=none",
        sd_kernel_validation_build(),
        static_cast<unsigned long long>(transport_info),
        pattern_name,
        match,
        reversed ? 1u : 0u,
        transport_pattern,
        transport_match,
        afd_base,
        transport_info,
        local_addr_size,
        local_addr_ptr);
    return TRUE;
}

static void afd_init_offsets() {
    NET_DBG("afd_init_offsets: ENTER state=%ld", g_afd_offsets_state);
    LONG prev = _InterlockedCompareExchange(&g_afd_offsets_state, 1, 0);
    if (prev == 2) { NET_DBG("afd_init_offsets: already done"); return; }
    if (prev == 1) {
        NET_DBG("afd_init_offsets: another thread initializing, waiting...");
        volatile UINT32 spin = 0;
        while (g_afd_offsets_state != 2 && spin < 100000) { YieldProcessor(); spin++; }
        if (g_afd_offsets_state != 2) {
            NET_ERR("afd_init_offsets: SPIN TIMEOUT after 100K iterations, state=%ld", g_afd_offsets_state);
        } else {
            NET_DBG("afd_init_offsets: wait done after %u spins", spin);
        }
        return;
    }

    BOOLEAN scan_ok = afd_resolve_offsets_by_scan();
    const char* offset_source = "semantic_scan";
    if (!scan_ok) {
        if (slopdrvr_kernel_layout::is_windows_11_or_newer()) {
            g_afd_offsets = g_afd_fallback_win11;
            offset_source = "static_fallback_win11";
            NET_DBG("afd_init: fallback to Win11 offsets");
        } else {
            g_afd_offsets = g_afd_fallback_win10;
            offset_source = "static_fallback_win10";
            NET_DBG("afd_init: fallback to Win10 offsets (build < 26100)");
        }
    }

    _InterlockedExchange(&g_afd_offsets_state, 2);
    SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.endpoint_offsets.final source=%s offset=0x%llx validation=%s evidence=\"transport=0x%X local_size=0x%X local_ptr=0x%X scan_ok=%u state=%ld\" fail_closed=%s",
        sd_kernel_validation_build(),
        offset_source,
        static_cast<unsigned long long>(g_afd_offsets.transport_info),
        sd_kernel_validation_state((g_afd_offsets.transport_info != 0 &&
            g_afd_offsets.local_addr_size != 0 &&
            g_afd_offsets.local_addr_ptr == g_afd_offsets.local_addr_size + 4) ? TRUE : FALSE),
        g_afd_offsets.transport_info,
        g_afd_offsets.local_addr_size,
        g_afd_offsets.local_addr_ptr,
        scan_ok ? 1u : 0u,
        _InterlockedCompareExchange(&g_afd_offsets_state, 0, 0),
        scan_ok ? "none" : "scan_failed_static_table_selected");
}

static __forceinline const afd_endpoint_offsets_t& afd_get_offsets() {
    if (g_afd_offsets_state != 2) afd_init_offsets();
    return g_afd_offsets;
}

static BOOLEAN slop_parse_transport_address(const UINT8* ta_buf, UINT32 ta_size,
                                            UINT32* out_af, UINT32* out_port, UINT8* out_addr) {
    if (!ta_buf || !out_af || !out_port || !out_addr) return FALSE;
    if (ta_size < 4) return FALSE;

    if (!_MmIsAddressValid((PVOID)ta_buf) || !_MmIsAddressValid((PVOID)(ta_buf + 3)))
        return FALSE;

    strong::kmemset(out_addr, 0, 16);


    USHORT sa_family = *(const USHORT*)(ta_buf + 0);

    if (sa_family == AF_INET && ta_size >= 8 && ta_size <= 16) {
        if (!_MmIsAddressValid((PVOID)(ta_buf + 7)))
            return FALSE;
        USHORT port_be = *(const USHORT*)(ta_buf + 2);
        UINT32 port_he = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
        if (ta_size >= 8 && _MmIsAddressValid((PVOID)(ta_buf + 7)))
            strong::kmemcpy(out_addr, ta_buf + 4, 4);
        *out_af = AF_INET;
        *out_port = port_he;
        return TRUE;
    }

    if (sa_family == AF_INET6 && ta_size >= 8 && ta_size <= 28) {
        if (!_MmIsAddressValid((PVOID)(ta_buf + 7)))
            return FALSE;
        USHORT port_be = *(const USHORT*)(ta_buf + 2);
        UINT32 port_he = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);
        if (ta_size >= 24 && _MmIsAddressValid((PVOID)(ta_buf + 23)))
            strong::kmemcpy(out_addr, ta_buf + 8, 16);
        *out_af = AF_INET6;
        *out_port = port_he;
        return TRUE;
    }


    if (ta_size < 10 || !_MmIsAddressValid((PVOID)(ta_buf + 9)))
        return FALSE;

    LONG addr_count = *(const LONG*)(ta_buf + 0);
    if (addr_count < 1) return FALSE;

    USHORT addr_type = *(const USHORT*)(ta_buf + 6);
    USHORT port_be   = *(const USHORT*)(ta_buf + 8);
    UINT32 port_he   = ((port_be >> 8) & 0xFFu) | ((port_be & 0xFFu) << 8);

    if (addr_type == AF_INET) {
        if (ta_size < 14 || !_MmIsAddressValid((PVOID)(ta_buf + 13)))
            return FALSE;
        strong::kmemcpy(out_addr, ta_buf + 10, 4);
        *out_af = AF_INET;
        *out_port = port_he;
        return TRUE;
    }

    if (addr_type == AF_INET6) {
        if (ta_size < 30 || !_MmIsAddressValid((PVOID)(ta_buf + 29)))
            return FALSE;
        strong::kmemcpy(out_addr, ta_buf + 14, 16);
        *out_af = AF_INET6;
        *out_port = port_he;
        return TRUE;
    }

    return FALSE;
}

static BOOLEAN slop_extract_socket_info_from_fo(PFILE_OBJECT fo, SOCKET_HANDLE_ENTRY* out) {
    if (!fo || !out) return FALSE;

    BOOLEAN result = FALSE;

    __try {

        PVOID afd_endpoint = fo->FsContext;
        if (!afd_endpoint || !_MmIsAddressValid(afd_endpoint)) {
            result = FALSE;
            __leave;
        }

        out->afd_endpoint_addr = (UINT64)afd_endpoint;
        UINT8* ep = (UINT8*)afd_endpoint;
        if (!_MmIsAddressValid(ep + sizeof(USHORT) - 1)) {
            result = FALSE;
            __leave;
        }
        USHORT afd_sig = *(USHORT*)ep;
        if (!afd_endpoint_signature_valid(afd_sig)) {
            static volatile LONG s_bad_sig_count = 0;
            LONG cnt = _InterlockedIncrement(&s_bad_sig_count);
            if (cnt <= 16) {
                SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.endpoint_signature source=socket_extract value=%p validation=fail evidence=\"sig=0x%04X ep=%p count=%ld\" fail_closed=bad_afd_endpoint_signature",
                    sd_kernel_validation_build(),
                    afd_endpoint,
                    afd_sig,
                    afd_endpoint,
                    cnt);
            }
            result = FALSE;
            __leave;
        }

        out->address_family = 0;
        out->protocol = 0;
        out->state = 0;
        out->local_port = 0;
        out->remote_port = 0;
        strong::kmemset(out->local_addr, 0, 16);
        strong::kmemset(out->remote_addr, 0, 16);

        const auto& offsets = afd_get_offsets();
        UINT32 afd_flags = 0;
        if (_MmIsAddressValid(ep + 0x0B))
            afd_flags = *(UINT32*)(ep + 0x08);
        BOOLEAN tl_transport = (afd_flags & 0x100u) != 0;


        if (_MmIsAddressValid(ep + offsets.transport_info + sizeof(PVOID) - 1)) {
            UINT8* transport_info = *(UINT8**)(ep + offsets.transport_info);
            NET_DBG("socket_extract: ep=0x%llx sig=0x%04x flags=0x%x ti_offset=0x%x ti_ptr=0x%llx",
                    (UINT64)ep, afd_sig, afd_flags, offsets.transport_info, (UINT64)transport_info);
            if (transport_info && _MmIsAddressValid(transport_info) &&
                _MmIsAddressValid(transport_info + 0x1D)) {
                if (tl_transport) {
                    UINT16 raw_af = *(UINT16*)(transport_info + 0x16);
                    if (raw_af == 0 && _MmIsAddressValid(transport_info + 0x17)) {
                        DWORD dw_af = *(DWORD*)(transport_info + 0x14);
                        if (dw_af == AF_INET || dw_af == AF_INET6)
                            raw_af = static_cast<UINT16>(dw_af);
                    }
                    DWORD raw_proto = *(DWORD*)(transport_info + 0x18);
                    NET_DBG("socket_extract: tl ti raw af=%u proto=%u (at ti+0x16, ti+0x18)",
                            raw_af, raw_proto);
                    if (raw_af == AF_INET || raw_af == AF_INET6)
                        out->address_family = raw_af;
                    out->protocol = (raw_proto <= 256) ? raw_proto : 0;
                    static volatile LONG s_tl_af_source_count = 0;
                    LONG cnt = _InterlockedIncrement(&s_tl_af_source_count);
                    if (cnt <= 16) {
                        SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.address_family_source source=socket_extract value=%p validation=%s evidence=\"mode=tl ep=%p sig=0x%04X flags=0x%X ti=%p raw_af=%u raw_proto=%u af=%u proto=%u count=%ld\" fail_closed=%s",
                            sd_kernel_validation_build(),
                            transport_info,
                            sd_kernel_validation_state((out->address_family == AF_INET || out->address_family == AF_INET6) ? TRUE : FALSE),
                            afd_endpoint,
                            afd_sig,
                            afd_flags,
                            transport_info,
                            raw_af,
                            raw_proto,
                            out->address_family,
                            out->protocol,
                            cnt,
                            (out->address_family == AF_INET || out->address_family == AF_INET6) ? "none" : "tl_address_family_unresolved");
                    }
                } else {
                    UINT32 classic_af = 0;
                    UINT32 classic_proto = 0;
                    if (afd_classic_transport_name(transport_info, &classic_af, &classic_proto)) {
                        out->address_family = classic_af;
                        out->protocol = classic_proto;
                        NET_DBG("socket_extract: classic ti device resolved af=%u proto=%u",
                                classic_af, classic_proto);
                        static volatile LONG s_classic_af_source_count = 0;
                        LONG cnt = _InterlockedIncrement(&s_classic_af_source_count);
                        if (cnt <= 16) {
                            SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.address_family_source source=socket_extract value=%p validation=pass evidence=\"mode=classic ep=%p sig=0x%04X flags=0x%X ti=%p af=%u proto=%u count=%ld\" fail_closed=none",
                                sd_kernel_validation_build(),
                                transport_info,
                                afd_endpoint,
                                afd_sig,
                                afd_flags,
                                transport_info,
                                out->address_family,
                                out->protocol,
                                cnt);
                        }
                    } else {
                        static volatile LONG s_classic_name_fail_count = 0;
                        LONG cnt = _InterlockedIncrement(&s_classic_name_fail_count);
                        if (cnt <= 16) {
                            SD_LOG("KVALIDATE build=%lu kind=layout name=AFD.classic_transport_name source=socket_extract value=%p validation=fail evidence=\"ep=%p sig=0x%04X flags=0x%X ti=%p count=%ld\" fail_closed=classic_transport_name_unresolved",
                                sd_kernel_validation_build(),
                                transport_info,
                                afd_endpoint,
                                afd_sig,
                                afd_flags,
                                transport_info,
                                cnt);
                        }
                    }
                }
            }
        }


        if (_MmIsAddressValid(ep + 0x02)) {
            UINT8 afd_state = *(ep + 0x02);
            switch (afd_state) {
                case 2: out->state = 5; break;
                case 3: out->state = 2; break;
                case 4: out->state = 2; break;
                default: out->state = 0; break;
            }
        }


        if (_MmIsAddressValid(ep + offsets.local_addr_size + 3) && _MmIsAddressValid(ep + offsets.local_addr_ptr + sizeof(PVOID) - 1)) {
            UINT32 ta_size = *(UINT32*)(ep + offsets.local_addr_size);
            UINT8* ta_ptr  = *(UINT8**)(ep + offsets.local_addr_ptr);
            NET_DBG("socket_extract: la_size_off=0x%x la_ptr_off=0x%x ta_size=%u ta_ptr=0x%llx",
                    offsets.local_addr_size, offsets.local_addr_ptr, ta_size, (UINT64)ta_ptr);
            if (ta_ptr && ta_size >= 10 && ta_size <= 256 && _MmIsAddressValid(ta_ptr)) {
                UINT32 local_af = 0, local_port = 0;
                UINT8 local_addr[16] = {};
                if (slop_parse_transport_address(ta_ptr, ta_size, &local_af, &local_port, local_addr)) {
                    out->local_port = local_port;
                    strong::kmemcpy(out->local_addr, local_addr, (local_af == AF_INET6) ? 16u : 4u);
                    if (out->address_family == 0) {
                        out->address_family = local_af;
                    }
                }
            }
        }

        result = TRUE;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        result = FALSE;
    }

    if (result) {
        static volatile LONG s_dbg_count = 0;
        LONG cnt = _InterlockedIncrement(&s_dbg_count);
        if (cnt <= 5) {
            NET_DBG("socket_info[%ld]: af=%u proto=%u state=%u lport=%u rport=%u ep=0x%llx",
                    cnt, out->address_family, out->protocol, out->state,
                    out->local_port, out->remote_port, out->afd_endpoint_addr);
            NET_DBG("socket_info[%ld]: local=%u.%u.%u.%u remote=%u.%u.%u.%u",
                    cnt,
                    out->local_addr[0], out->local_addr[1], out->local_addr[2], out->local_addr[3],
                    out->remote_addr[0], out->remote_addr[1], out->remote_addr[2], out->remote_addr[3]);
        }
    }

    return result;
}


typedef struct _SLOP_ENDPOINT_PID_CACHE_ENTRY {
    volatile LONG active;
    UINT64 endpoint_handle;
    UINT32 pid;
    UINT32 protocol;
    UINT32 local_port;
} SLOP_ENDPOINT_PID_CACHE_ENTRY;

typedef struct _SLOP_PORT_PID_CACHE_ENTRY {
    volatile LONG active;
    UINT32 protocol;
    UINT32 port;
    UINT32 pid;
} SLOP_PORT_PID_CACHE_ENTRY;

inline SLOP_ENDPOINT_PID_CACHE_ENTRY g_endpoint_pid_cache[SLOP_ENDPOINT_PID_CACHE_SIZE] = {};
inline SLOP_PORT_PID_CACHE_ENTRY g_port_pid_cache[SLOP_ENDPOINT_PID_CACHE_SIZE] = {};
inline KSPIN_LOCK g_endpoint_pid_cache_lock;
inline volatile LONG g_endpoint_pid_cache_lock_state = 0;
inline volatile LONG g_handle_query_irql_warned = 0;

static VOID slop_ensure_endpoint_pid_cache_init() {
    LONG state = _InterlockedCompareExchange(&g_endpoint_pid_cache_lock_state, 1, 0);
    if (state == 0) {
        KeInitializeSpinLock(&g_endpoint_pid_cache_lock);
        KeMemoryBarrier();
        _InterlockedExchange(&g_endpoint_pid_cache_lock_state, 2);
        return;
    }

    for (UINT32 spin = 0; spin < 100000; spin++) {
        if (_InterlockedCompareExchange(&g_endpoint_pid_cache_lock_state, 2, 2) == 2)
            return;
        YieldProcessor();
    }
}

static UINT32 slop_lookup_cached_endpoint_pid(UINT64 endpoint_handle,
                                              UINT32 protocol,
                                              UINT32 local_port) {
    UNREFERENCED_PARAMETER(protocol);
    UNREFERENCED_PARAMETER(local_port);
    if (endpoint_handle == 0) return 0;

    slop_ensure_endpoint_pid_cache_init();


    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    for (UINT32 i = 0; i < SLOP_ENDPOINT_PID_CACHE_SIZE; i++) {
        const SLOP_ENDPOINT_PID_CACHE_ENTRY* entry = &g_endpoint_pid_cache[i];
        if (!entry->active) continue;
        if (entry->endpoint_handle != endpoint_handle) continue;

        UINT32 pid = entry->pid;
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return pid;
    }
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
    return 0;
}

static VOID slop_store_cached_endpoint_pid(UINT64 endpoint_handle,
                                           UINT32 protocol,
                                           UINT32 local_port,
                                           UINT32 pid) {
    if (endpoint_handle == 0 || pid == 0) return;

    slop_ensure_endpoint_pid_cache_init();

    UINT32 slot = (UINT32)(endpoint_handle % SLOP_ENDPOINT_PID_CACHE_SIZE);

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    UINT32 target = slot;
    UINT32 empty_slot = SLOP_ENDPOINT_PID_CACHE_SIZE;
    for (UINT32 probe = 0; probe < 4; probe++) {
        UINT32 idx = (slot + probe) % SLOP_ENDPOINT_PID_CACHE_SIZE;
        if (!g_endpoint_pid_cache[idx].active) {
            if (empty_slot == SLOP_ENDPOINT_PID_CACHE_SIZE) empty_slot = idx;
            continue;
        }
        if (g_endpoint_pid_cache[idx].endpoint_handle == endpoint_handle) {
            target = idx;
            goto store_endpoint;
        }
    }
    target = (empty_slot != SLOP_ENDPOINT_PID_CACHE_SIZE) ? empty_slot : slot;
store_endpoint:
    g_endpoint_pid_cache[target].endpoint_handle = endpoint_handle;
    g_endpoint_pid_cache[target].protocol = protocol;
    g_endpoint_pid_cache[target].local_port = local_port;
    g_endpoint_pid_cache[target].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_endpoint_pid_cache[target].active, 1);
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
}

static VOID slop_store_cached_port_pid(UINT32 protocol,
                                       UINT32 port,
                                       UINT32 pid) {
    if (port == 0 || pid == 0) return;

    slop_ensure_endpoint_pid_cache_init();

    UINT32 slot = ((protocol * 131u) ^ port) % SLOP_ENDPOINT_PID_CACHE_SIZE;

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    UINT32 target = slot;
    UINT32 empty_slot = SLOP_ENDPOINT_PID_CACHE_SIZE;
    for (UINT32 probe = 0; probe < 4; probe++) {
        UINT32 idx = (slot + probe) % SLOP_ENDPOINT_PID_CACHE_SIZE;
        if (!g_port_pid_cache[idx].active) {
            if (empty_slot == SLOP_ENDPOINT_PID_CACHE_SIZE) empty_slot = idx;
            continue;
        }
        if (g_port_pid_cache[idx].protocol == protocol && g_port_pid_cache[idx].port == port) {
            target = idx;
            goto store_port;
        }
    }
    target = (empty_slot != SLOP_ENDPOINT_PID_CACHE_SIZE) ? empty_slot : slot;
store_port:
    g_port_pid_cache[target].protocol = protocol;
    g_port_pid_cache[target].port = port;
    g_port_pid_cache[target].pid = pid;
    KeMemoryBarrier();
    _InterlockedExchange(&g_port_pid_cache[target].active, 1);
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
}

static UINT32 slop_lookup_cached_port_pid(UINT32 protocol,
                                          UINT32 local_port,
                                          UINT32 remote_port) {
    if (local_port == 0 && remote_port == 0)
        return 0;

    slop_ensure_endpoint_pid_cache_init();

    KIRQL old_irql;
    KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
    for (UINT32 i = 0; i < SLOP_ENDPOINT_PID_CACHE_SIZE; i++) {
        const SLOP_PORT_PID_CACHE_ENTRY* entry = &g_port_pid_cache[i];
        if (!entry->active) continue;
        if (entry->pid == 0) continue;
        if (entry->protocol != 0 && protocol != 0 && entry->protocol != protocol)
            continue;
        if (entry->port != local_port && entry->port != remote_port)
            continue;

        UINT32 pid = entry->pid;
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return pid;
    }
    KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
    return 0;
}

static VOID slop_cache_pid_from_socket_info(const SOCKET_HANDLE_ENTRY* socket_info,
                                            UINT32 pid) {
    if (!socket_info || pid == 0)
        return;

    if (socket_info->afd_endpoint_addr != 0) {
        slop_store_cached_endpoint_pid(socket_info->afd_endpoint_addr,
            socket_info->protocol,
            socket_info->local_port,
            pid);
    }

    slop_store_cached_port_pid(socket_info->protocol, socket_info->local_port, pid);
    slop_store_cached_port_pid(socket_info->protocol, socket_info->remote_port, pid);
}


static NTSTATUS slop_refresh_pid_cache_for_process(UINT32 target_pid,
                                                   UINT32 protocol_filter) {
    if (target_pid == 0)
        return STATUS_INVALID_PARAMETER;

    if (!slop_can_query_system_handles())
        return STATUS_INVALID_DEVICE_STATE;

    PSLOP_SYSTEM_HANDLE_INFORMATION handles = nullptr;
    NTSTATUS status = slop_query_system_handles(&handles);
    if (!NT_SUCCESS(status) || !handles)
        return status;


    constexpr UINT32 MAX_PID_HANDLES = 1024;
    USHORT* pid_handles = static_cast<USHORT*>(
        ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_PID_HANDLES * sizeof(USHORT), 'pcNW'));
    if (!pid_handles) {
        ExFreePoolWithTag(handles, 'hANW');
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    UINT32 pid_handle_count = 0;
    for (ULONG i = 0; i < handles->NumberOfHandles && pid_handle_count < MAX_PID_HANDLES; i++) {
        if (static_cast<UINT32>(handles->Handles[i].UniqueProcessId) == target_pid) {
            pid_handles[pid_handle_count++] = handles->Handles[i].HandleValue;
        }
    }
    ExFreePoolWithTag(handles, 'hANW');
    handles = nullptr;

    if (pid_handle_count == 0) {
        ExFreePoolWithTag(pid_handles, 'pcNW');
        return STATUS_NOT_FOUND;
    }


    PEPROCESS process = nullptr;
    status = PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &process);
    if (!NT_SUCCESS(status) || !process) {
        ExFreePoolWithTag(pid_handles, 'pcNW');
        return status;
    }


    (void)afd_get_offsets();

    UINT32 cached = 0;
    KAPC_STATE apc_state = {};
    KeStackAttachProcess(process, &apc_state);

    __try {
        for (UINT32 i = 0; i < pid_handle_count; i++) {
            HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));

            PVOID file_obj = nullptr;
            NTSTATUS ref_st = ObReferenceObjectByHandle(
                h, 0,
                (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                KernelMode, &file_obj, nullptr);
            if (!NT_SUCCESS(ref_st) || !file_obj)
                continue;

            PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);
            if (!slop_is_afd_file_object(fo)) {
                ObDereferenceObject(fo);
                continue;
            }

            SOCKET_HANDLE_ENTRY socket_info = {};
            BOOLEAN ok = slop_extract_socket_info_from_fo(fo, &socket_info);
            ObDereferenceObject(fo);
            if (!ok)
                continue;

            if (protocol_filter != 0 && socket_info.protocol != 0 &&
                socket_info.protocol != protocol_filter)
                continue;

            slop_cache_pid_from_socket_info(&socket_info, target_pid);
            cached++;
        }
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        status = STATUS_ACCESS_VIOLATION;
    }

    KeUnstackDetachProcess(&apc_state);
    ObDereferenceObject(process);
    ExFreePoolWithTag(pid_handles, 'pcNW');

    if (!NT_SUCCESS(status))
        return status;
    return (cached != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}


static volatile LONG64 g_last_handle_enum_tsc = 0;


static constexpr ULONG HANDLE_ENUM_MAX_ITER = 50000;


static constexpr LONG64 HANDLE_ENUM_COOLDOWN_TSC = 500000000LL;

static __forceinline BOOLEAN slop_can_query_system_handles() {
    KIRQL irql = KeGetCurrentIrql();
    if (irql == PASSIVE_LEVEL)
        return TRUE;

    if (_InterlockedCompareExchange(&g_handle_query_irql_warned, 1, 0) == 0) {
        NET_ERR("slop_can_query_system_handles: blocked at IRQL=%u (need PASSIVE_LEVEL), future warnings suppressed", (UINT32)irql);
    }
    return FALSE;
}


namespace net_enum {


    #define TCP_STATE_CLOSED       0
    #define TCP_STATE_LISTEN       1
    #define TCP_STATE_SYN_SENT     2
    #define TCP_STATE_SYN_RCVD     3
    #define TCP_STATE_ESTABLISHED  4
    #define TCP_STATE_FIN_WAIT1    5
    #define TCP_STATE_FIN_WAIT2    6
    #define TCP_STATE_CLOSE_WAIT   7
    #define TCP_STATE_CLOSING      8
    #define TCP_STATE_LAST_ACK     9
    #define TCP_STATE_TIME_WAIT    10
    #define TCP_STATE_DELETE_TCB   11


    typedef struct _MIB_TCPROW2 {
        UINT32 dwState;
        UINT32 dwLocalAddr;
        UINT32 dwLocalPort;
        UINT32 dwRemoteAddr;
        UINT32 dwRemotePort;
        UINT32 dwOwningPid;
        UINT32 dwOffloadState;
    } MIB_TCPROW2;

    typedef struct _MIB_UDPROW_OWNER_PID {
        UINT32 dwLocalAddr;
        UINT32 dwLocalPort;
        UINT32 dwOwningPid;
    } MIB_UDPROW_OWNER_PID;


    typedef NTSTATUS(NTAPI* fn_NsiEnumerateObjectsAllParameters)(
        UINT32 NsiQueryMode, UINT32 NsiStore, const PVOID NsiModule,
        UINT32 NsiType, PVOID KeyData, UINT32 KeySize,
        PVOID RwParamData, UINT32 RwParamSize,
        PVOID DynParamData, UINT32 DynParamSize,
        PVOID StaticParamData, UINT32 StaticParamSize,
        PUINT32 Count);


    inline constexpr UINT32 NSI_STORE_ACTIVE = 1;


    inline constexpr UINT32 NSI_QUERY_RUNTIME = 1;

    inline fn_NsiEnumerateObjectsAllParameters _NsiEnumerate = nullptr;
    inline volatile LONG g_nsi_resolved = 0;


    static const UINT8 NPI_MS_TCP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x03, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };


    static const UINT8 NPI_MS_UDP_MODULEID[24] = {
        0x18, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00,
        0x02, 0x4a, 0x00, 0xeb, 0x1a, 0x9b, 0xd4, 0x11,
        0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xbc
    };


    #pragma pack(push, 1)
    typedef struct _NSI_SOCKADDR_IN6 {
        UINT16 family;
        UINT16 port_be;
        UINT32 flowinfo;
        UINT8  addr[16];
        UINT32 scope_id;
    } NSI_SOCKADDR_IN6;

    typedef struct _NSI_TCP_KEY {
        NSI_SOCKADDR_IN6 local;
        NSI_SOCKADDR_IN6 remote;
    } NSI_TCP_KEY;

    typedef struct _NSI_TCP_DYNAMIC {
        UINT32 state;
        UINT8  _pad[44];
    } NSI_TCP_DYNAMIC;

    typedef struct _NSI_TCP_STATIC {
        UINT8  _pad0[12];
        UINT32 mod_pid;
        UINT64 create_time;
        UINT8  _pad1[8];
    } NSI_TCP_STATIC;

    typedef struct _NSI_UDP_KEY {
        NSI_SOCKADDR_IN6 local;
    } NSI_UDP_KEY;

    typedef struct _NSI_UDP_STATIC {
        UINT32 mod_pid;
        UINT32 _pad0;
        UINT64 create_time;
        UINT8  _pad1[16];
    } NSI_UDP_STATIC;
    #pragma pack(pop)

    BOOLEAN resolve_nsi() {
        NET_DBG("resolve_nsi: enter");
        LONG prev = _InterlockedCompareExchange(&g_nsi_resolved, 1, 0);
        if (prev == 2) {
            return _NsiEnumerate != nullptr;
        }
        if (prev == 1) {
            for (UINT32 spin = 0; spin < 100000; spin++) {
                if (_InterlockedCompareExchange(&g_nsi_resolved, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return _NsiEnumerate != nullptr;
        }


        PVOID netio = net_capture::find_module_base("netio.sys");
        if (!netio) netio = net_capture::find_module_base("NETIO.SYS");

        if (netio) {
            CHAR nsi_name[] = {'N','s','i','E','n','u','m','e','r','a','t','e',
                'O','b','j','e','c','t','s','A','l','l',
                'P','a','r','a','m','e','t','e','r','s',0};
            *(PVOID*)&_NsiEnumerate = GetProcAddress(netio, nsi_name);
        }

        KeMemoryBarrier();
        _InterlockedExchange(&g_nsi_resolved, 2);
        SD_LOG("KVALIDATE build=%lu kind=resolver name=NSI.NsiEnumerateObjectsAllParameters source=export_table value=%p validation=%s evidence=\"netio=%p tcp_key=%llu tcp_static=%llu udp_key=%llu udp_static=%llu query_runtime=%u store_active=%u\" fail_closed=%s",
            sd_kernel_validation_build(),
            _NsiEnumerate,
            sd_kernel_validation_state(_NsiEnumerate != nullptr),
            netio,
            static_cast<unsigned long long>(sizeof(NSI_TCP_KEY)),
            static_cast<unsigned long long>(sizeof(NSI_TCP_STATIC)),
            static_cast<unsigned long long>(sizeof(NSI_UDP_KEY)),
            static_cast<unsigned long long>(sizeof(NSI_UDP_STATIC)),
            NSI_QUERY_RUNTIME,
            NSI_STORE_ACTIVE,
            _NsiEnumerate ? "none" : (netio ? "export_missing" : "netio_module_not_found"));
        NET_DBG("resolve_nsi: NsiEnumerate=%p", _NsiEnumerate);
        return _NsiEnumerate != nullptr;
    }

    static void fill_process_path(NET_CONN_ENTRY* out, UINT32 pid) {
        out->process_path[0] = '\0';
        if (pid == 0 || pid == 4) return;


        BOOLEAN found_in_cache = FALSE;
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_pid_path_lock, &old_irql);
        for (UINT32 c = 0; c < PID_PATH_CACHE_SIZE; c++) {
            if (net_capture::g_pid_path_cache[c].pid == pid && net_capture::g_pid_path_cache[c].path[0] != '\0') {
                UINT32 plen = 0;
                while (plen < 259 && net_capture::g_pid_path_cache[c].path[plen] != '\0') {
                    out->process_path[plen] = net_capture::g_pid_path_cache[c].path[plen];
                    plen++;
                }
                out->process_path[plen] = '\0';
                found_in_cache = TRUE;
                break;
            }
        }
        KeReleaseSpinLock(&net_capture::g_pid_path_lock, old_irql);

        if (found_in_cache) return;

        PEPROCESS process = nullptr;
        NTSTATUS lookup_st = PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)pid, &process);
        if (!NT_SUCCESS(lookup_st) || !process) return;

        PUNICODE_STRING image_name = nullptr;
        lookup_st = SeLocateProcessImageName(process, &image_name);
        if (NT_SUCCESS(lookup_st) && image_name && image_name->Buffer && image_name->Length > 0) {
            UINT32 char_count = image_name->Length / sizeof(WCHAR);
            if (char_count > 259) char_count = 259;
            for (UINT32 ci = 0; ci < char_count; ci++) {
                WCHAR wc = image_name->Buffer[ci];
                out->process_path[ci] = (wc < 128) ? (char)wc : '?';
            }
            out->process_path[char_count] = '\0';
            ExFreePool(image_name);


            KeAcquireSpinLock(&net_capture::g_pid_path_lock, &old_irql);
            UINT32 cache_idx = PID_PATH_CACHE_SIZE;
            UINT64 oldest_ts = ~0ULL;
            for (UINT32 c = 0; c < PID_PATH_CACHE_SIZE; c++) {
                if (net_capture::g_pid_path_cache[c].pid == 0) {
                    cache_idx = c;
                    break;
                }
                if (net_capture::g_pid_path_cache[c].timestamp < oldest_ts) {
                    oldest_ts = net_capture::g_pid_path_cache[c].timestamp;
                    cache_idx = c;
                }
            }
            if (cache_idx < PID_PATH_CACHE_SIZE) {
                net_capture::g_pid_path_cache[cache_idx].pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                net_capture::g_pid_path_cache[cache_idx].timestamp = now.QuadPart;
                UINT32 plen = 0;
                while (plen < 259 && out->process_path[plen] != '\0') {
                    net_capture::g_pid_path_cache[cache_idx].path[plen] = out->process_path[plen];
                    plen++;
                }
                net_capture::g_pid_path_cache[cache_idx].path[plen] = '\0';
            }
            KeReleaseSpinLock(&net_capture::g_pid_path_lock, old_irql);
        } else if (image_name) {
            ExFreePool(image_name);
        }
        ObDereferenceObject(process);
    }


    static __forceinline UINT32 nsi_tcp_state_to_mib(UINT32 nsi_state) {

        return (nsi_state <= TCP_STATE_DELETE_TCB) ? nsi_state : 0;
    }

    NTSTATUS enumerate_connections(p_net_enum_conn request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        if (!resolve_nsi()) {
            NET_ERR("enumerate_connections: NsiEnumerate not resolved");
            return STATUS_NOT_SUPPORTED;
        }

        NET_DBG("enumerate_connections: NSI struct sizes KEY=%u DYN=%u STA=%u",
            (UINT32)sizeof(NSI_TCP_KEY), (UINT32)sizeof(NSI_TCP_DYNAMIC), (UINT32)sizeof(NSI_TCP_STATIC));


        {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;
            NSI_TCP_KEY*     keys = nullptr;
            NSI_TCP_DYNAMIC* dyns = nullptr;
            NSI_TCP_STATIC*  stats = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(NSI_TCP_KEY);
                ULONG dyn_sz = tcp_capacity * sizeof(NSI_TCP_DYNAMIC);
                ULONG sta_sz = tcp_capacity * sizeof(NSI_TCP_STATIC);
                ULONG total  = key_sz + dyn_sz + sta_sz;

                buf = static_cast<UINT8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'nsNW'));
                if (!buf) break;

                keys  = reinterpret_cast<NSI_TCP_KEY*>(buf);
                dyns  = reinterpret_cast<NSI_TCP_DYNAMIC*>(buf + key_sz);
                stats = reinterpret_cast<NSI_TCP_STATIC*>(buf + key_sz + dyn_sz);

                st = _NsiEnumerate(
                    NSI_QUERY_RUNTIME, NSI_STORE_ACTIVE, (PVOID)NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(NSI_TCP_KEY),
                    nullptr, 0,
                    dyns, sizeof(NSI_TCP_DYNAMIC),
                    stats, sizeof(NSI_TCP_STATIC),
                    &tcp_count);

                NET_DBG("enumerate_connections: TCP direct [cap=%u] st=0x%08x count=%u",
                        tcp_capacity, st, tcp_count);

                if (NT_SUCCESS(st)) break;

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == tcp_capacity) {
                        NET_ERR("enumerate_connections: TCP exhausted retries at cap=%u", tcp_capacity);
                        ExFreePoolWithTag(buf, 'nsNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'nsNW');
                    buf = nullptr;
                    tcp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'nsNW');
                buf = nullptr;
                break;
            }

            if (buf && NT_SUCCESS(st) && tcp_count > 0) {
                for (UINT32 i = 0; i < tcp_count && request->connection_count < MAX_NET_CONNECTIONS; i++) {
                    UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                    if (request->filter_pid != 0 && pid != request->filter_pid)
                        continue;
                    if (request->filter_protocol != 0 && request->filter_protocol != 6)
                        continue;

                    NET_CONN_ENTRY* out = &request->entries[request->connection_count];
                    strong::kmemset(out, 0, sizeof(NET_CONN_ENTRY));
                    out->pid = pid;
                    out->protocol = 6;
                    out->state = nsi_tcp_state_to_mib(dyns[i].state);
                    out->address_family = AF_INET;

                    out->local_port  = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    out->remote_port = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                    strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                    strong::kmemcpy(out->remote_addr, keys[i].remote.addr, 4);

                    fill_process_path(out, pid);
                    request->connection_count++;
                }
            } else if (buf) {
                NET_ERR("enumerate_connections: NSI TCP4 enum failed 0x%08x", st);
            }
            if (buf) ExFreePoolWithTag(buf, 'nsNW');
        }


        {
            UINT32 udp_capacity = 4096;
            UINT32 udp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;
            NSI_UDP_KEY*    keys  = nullptr;
            NSI_UDP_STATIC* stats = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                udp_count = udp_capacity;
                ULONG key_sz = udp_capacity * sizeof(NSI_UDP_KEY);
                ULONG sta_sz = udp_capacity * sizeof(NSI_UDP_STATIC);
                ULONG total  = key_sz + sta_sz;

                buf = static_cast<UINT8*>(ExAllocatePool2(POOL_FLAG_NON_PAGED, total, 'nsNW'));
                if (!buf) break;

                keys  = reinterpret_cast<NSI_UDP_KEY*>(buf);
                stats = reinterpret_cast<NSI_UDP_STATIC*>(buf + key_sz);

                st = _NsiEnumerate(
                    NSI_QUERY_RUNTIME, NSI_STORE_ACTIVE, (PVOID)NPI_MS_UDP_MODULEID,
                    1, keys, sizeof(NSI_UDP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(NSI_UDP_STATIC),
                    &udp_count);

                NET_DBG("enumerate_connections: UDP direct [cap=%u] st=0x%08x count=%u",
                        udp_capacity, st, udp_count);

                if (NT_SUCCESS(st)) break;

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == udp_capacity) {
                        NET_ERR("enumerate_connections: UDP exhausted retries at cap=%u", udp_capacity);
                        ExFreePoolWithTag(buf, 'nsNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'nsNW');
                    buf = nullptr;
                    udp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'nsNW');
                buf = nullptr;
                break;
            }

            if (buf && NT_SUCCESS(st) && udp_count > 0) {
                for (UINT32 i = 0; i < udp_count && request->connection_count < MAX_NET_CONNECTIONS; i++) {
                    UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                    if (request->filter_pid != 0 && pid != request->filter_pid)
                        continue;
                    if (request->filter_protocol != 0 && request->filter_protocol != 17)
                        continue;

                    NET_CONN_ENTRY* out = &request->entries[request->connection_count];
                    strong::kmemset(out, 0, sizeof(NET_CONN_ENTRY));
                    out->pid = pid;
                    out->protocol = 17;
                    out->state = 0;
                    out->address_family = AF_INET;

                    out->local_port = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    out->remote_port = 0;

                    strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);

                    fill_process_path(out, pid);
                    request->connection_count++;
                }
            } else if (buf) {
                NET_ERR("enumerate_connections: NSI UDP enum failed 0x%08x", st);
            }
            if (buf) ExFreePoolWithTag(buf, 'nsNW');
        }

        NET_DBG("enumerate_connections: found=%u connections (filter_pid=%u filter_proto=%u)",
                request->connection_count, request->filter_pid, request->filter_protocol);
        for (UINT32 dbg_i = 0; dbg_i < request->connection_count && dbg_i < 5; dbg_i++) {
            const NET_CONN_ENTRY* e = &request->entries[dbg_i];
            NET_DBG("  conn[%u]: pid=%u proto=%u state=%u af=%u lport=%u rport=%u",
                    dbg_i, e->pid, e->protocol, e->state, e->address_family,
                    e->local_port, e->remote_port);
            NET_DBG("  conn[%u]: local=%u.%u.%u.%u remote=%u.%u.%u.%u",
                    dbg_i,
                    e->local_addr[0], e->local_addr[1], e->local_addr[2], e->local_addr[3],
                    e->remote_addr[0], e->remote_addr[1], e->remote_addr[2], e->remote_addr[3]);
        }
        return STATUS_SUCCESS;
    }

}


NTSTATUS functions::handle_net_enum_conn(p_net_enum_conn request) {
    if (!request) { NET_ERR("handle_net_enum_conn: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_net_enum_conn: filter_pid=%u filter_proto=%u", request->filter_pid, request->filter_protocol);
    NTSTATUS st = net_enum::enumerate_connections(request);
    NET_DBG("handle_net_enum_conn: returned 0x%08x count=%u", st, request->connection_count);
    return st;
}

NTSTATUS functions::handle_net_cap_ctrl(p_net_cap_ctrl request) {
    if (!request) { NET_ERR("handle_net_cap_ctrl: NULL request"); return STATUS_INVALID_PARAMETER; }
    SD_LOG("net_capture::ctrl ENTER op=%u state=%ld active=%ld pid_filter=%u port_filter=%u proto_filter=%u max_bytes=%u",
        request->operation,
        net_capture::g_wfp_initialized,
        net_capture::g_capture_active,
        request->filter_pid,
        request->filter_port,
        request->filter_protocol,
        request->max_packet_bytes);

    if (net_capture::g_wfp_initialized == 3 || net_capture::g_wfp_degraded != 0) {
        SD_LOG("net_capture::ctrl FAIL step=wfp_degraded status=0x%08X state=%ld degraded=%ld build=%lu",
            STATUS_NOT_SUPPORTED,
            net_capture::g_wfp_initialized,
            net_capture::g_wfp_degraded,
            net_capture::runtime_build_number());
        return STATUS_NOT_SUPPORTED;
    }

    if (net_capture::g_wfp_initialized != 2) {


        if (net_capture::g_device_object != nullptr) {
            NET_DBG("handle_net_cap_ctrl: WFP not ready (state=%d), attempting lazy re-init", (int)net_capture::g_wfp_initialized);
            NTSTATUS reinit_status = net_capture::initialize(net_capture::g_device_object);
            if (!NT_SUCCESS(reinit_status)) {
                NET_ERR("handle_net_cap_ctrl: lazy WFP re-init FAILED status=0x%08lx", reinit_status);
                SD_LOG("net_capture::ctrl FAIL step=lazy_reinit status=0x%08X state=%ld",
                    reinit_status,
                    net_capture::g_wfp_initialized);
                return STATUS_DEVICE_NOT_READY;
            }
            NET_DBG("handle_net_cap_ctrl: lazy WFP re-init OK");
        } else {
            NET_ERR("handle_net_cap_ctrl: WFP not initialized (state=%d) and no device object", (int)net_capture::g_wfp_initialized);
            SD_LOG("net_capture::ctrl FAIL step=wfp_not_ready status=0x%08X state=%ld device_ready=0",
                STATUS_DEVICE_NOT_READY,
                net_capture::g_wfp_initialized);
            return STATUS_DEVICE_NOT_READY;
        }
    }

    switch (request->operation) {
        case 0: {
            net_capture::g_filter_pid = request->filter_pid;
            net_capture::g_filter_port = request->filter_port;
            net_capture::g_filter_protocol = request->filter_protocol;
            strong::kmemcpy(net_capture::g_filter_ip, request->filter_ip, 16);


            if (request->max_packet_bytes > 0 && request->max_packet_bytes <= NET_PKT_MAX_PAYLOAD)
                net_capture::g_max_payload = request->max_packet_bytes;
            else
                net_capture::g_max_payload = NET_PKT_MAX_PAYLOAD;


            KIRQL old_irql;
            KeAcquireSpinLock(&net_capture::g_ring_lock, &old_irql);
            net_capture::g_ring_head = 0;
            net_capture::g_ring_tail = 0;
            net_capture::g_ring_count = 0;
            KeReleaseSpinLock(&net_capture::g_ring_lock, old_irql);

            _InterlockedExchange(&net_capture::g_total_captured, 0);
            _InterlockedExchange(&net_capture::g_total_dropped, 0);
            _InterlockedExchange64(&net_capture::g_hot_filter_rejects, 0);
            NTSTATUS dpi_status = net_dpi::start();
            if (!NT_SUCCESS(dpi_status)) {
                NET_ERR("handle_net_cap_ctrl: DPI start FAILED status=0x%08lx", dpi_status);
                SD_LOG("net_capture::ctrl FAIL step=dpi_start status=0x%08X", dpi_status);
                return dpi_status;
            }
            _InterlockedExchange(&net_capture::g_capture_active, 1);

            NET_DBG("handle_net_cap_ctrl: capture STARTED pid=%u port=%u proto=%u max_bytes=%u",
                    request->filter_pid, request->filter_port, request->filter_protocol, net_capture::g_max_payload);
            SD_LOG("net_capture::ctrl STARTED pid_filter=%u port_filter=%u proto_filter=%u max_bytes=%u",
                request->filter_pid,
                request->filter_port,
                request->filter_protocol,
                net_capture::g_max_payload);
            request->capture_active = 1;
            break;
        }
        case 1: {
            _InterlockedExchange(&net_capture::g_capture_active, 0);
            net_dpi::stop();
            net_capture::g_filter_pid = 0;
            net_capture::g_filter_port = 0;
            net_capture::g_filter_protocol = 0;
            strong::kmemset(net_capture::g_filter_ip, 0, sizeof(net_capture::g_filter_ip));
            NET_DBG("handle_net_cap_ctrl: capture STOPPED");
            SD_LOG("net_capture::ctrl STOPPED captured=%ld dropped=%ld filter_rejects=%lld ring_count=%ld",
                net_capture::g_total_captured,
                net_capture::g_total_dropped,
                _InterlockedCompareExchange64(&net_capture::g_hot_filter_rejects, 0, 0),
                net_capture::g_ring_count);
            request->capture_active = 0;
            break;
        }
        case 2: {
            SD_LOG("net_capture::ctrl STATUS active=%ld captured=%ld dropped=%ld ring_count=%ld filter_rejects=%lld",
                net_capture::g_capture_active,
                net_capture::g_total_captured,
                net_capture::g_total_dropped,
                net_capture::g_ring_count,
                _InterlockedCompareExchange64(&net_capture::g_hot_filter_rejects, 0, 0));
            break;
        }
        default:
            SD_LOG("net_capture::ctrl FAIL step=invalid_operation op=%u status=0x%08X",
                request->operation,
                STATUS_INVALID_PARAMETER);
            return STATUS_INVALID_PARAMETER;
    }

    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->packets_captured = (UINT32)net_capture::g_total_captured;
    request->packets_dropped = (UINT32)net_capture::g_total_dropped;

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_cap_get(p_net_cap_get request) {
    if (!request) { NET_ERR("handle_net_cap_get: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (!net_capture::g_ring_buffer) {
        NET_ERR("handle_net_cap_get: ring buffer not allocated");
        return STATUS_DEVICE_NOT_READY;
    }

    UINT32 max_packets = request->max_packets;
    if (max_packets > NET_CAP_GET_MAX) max_packets = NET_CAP_GET_MAX;
    if (max_packets == 0) max_packets = NET_CAP_GET_MAX;

    request->packet_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&net_capture::g_ring_lock, &old_irql);

    UINT32 available = (UINT32)net_capture::g_ring_count;
    UINT32 to_read = (available < max_packets) ? available : max_packets;

    for (UINT32 i = 0; i < to_read; i++) {
        strong::kmemcpy(&request->packets[i],
            &net_capture::g_ring_buffer[net_capture::g_ring_tail],
            sizeof(NET_PACKET_ENTRY));
        net_capture::g_ring_tail = (net_capture::g_ring_tail + 1) % RING_BUFFER_SIZE;
        net_capture::g_ring_count--;
    }

    request->packet_count = to_read;

    KeReleaseSpinLock(&net_capture::g_ring_lock, old_irql);
    SD_LOG("net_capture::get packets=%u requested=%u available_before=%u active=%ld dropped=%ld filter_rejects=%lld",
        to_read,
        max_packets,
        available,
        net_capture::g_capture_active,
        net_capture::g_total_dropped,
        _InterlockedCompareExchange64(&net_capture::g_hot_filter_rejects, 0, 0));

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_dns_get(p_net_dns_get request) {
    if (!request) { NET_ERR("handle_net_dns_get: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (!net_capture::g_dns_ring) {
        NET_ERR("handle_net_dns_get: DNS ring not allocated");
        return STATUS_DEVICE_NOT_READY;
    }

    request->entry_count = 0;

    KIRQL old_irql;
    KeAcquireSpinLock(&net_capture::g_dns_lock, &old_irql);

    UINT32 available = (UINT32)net_capture::g_dns_count;
    LONG head_snapshot = net_capture::g_dns_head;
    LONG tail_snapshot = net_capture::g_dns_tail;
    UINT32 scanned = 0;
    UINT32 matched = 0;
    LONG first_slot = -1;
    LONG last_slot = -1;

    UINT32 out_idx = 0;
    LONG local_idx = (head_snapshot + DNS_RING_SIZE - 1) % DNS_RING_SIZE;
    for (UINT32 i = 0; i < available; i++) {
        NET_DNS_ENTRY* src = &net_capture::g_dns_ring[local_idx];
        scanned++;

        if (request->filter_pid == 0 || src->pid == request->filter_pid) {
            matched++;
            if (out_idx < NET_DNS_GET_MAX) {
                strong::kmemcpy(&request->entries[out_idx], src, sizeof(NET_DNS_ENTRY));
                if (first_slot < 0) first_slot = local_idx;
                last_slot = local_idx;
                out_idx++;
            }
        }

        local_idx = (local_idx + DNS_RING_SIZE - 1) % DNS_RING_SIZE;
    }

    request->entry_count = out_idx;

    KeReleaseSpinLock(&net_capture::g_dns_lock, old_irql);

    SD_LOG("handle_net_dns_get filter_pid=%u available=%u scanned=%u matched=%u returned=%u head=%ld tail=%ld newest_slot=%ld oldest_returned_slot=%ld total_dns=%ld",
        request->filter_pid,
        available,
        scanned,
        matched,
        out_idx,
        head_snapshot,
        tail_snapshot,
        first_slot,
        last_slot,
        net_capture::g_total_dns);

    return STATUS_SUCCESS;
}

NTSTATUS functions::handle_net_filter_rule(p_net_filter_rule request) {
    if (!request) { NET_ERR("handle_net_filter_rule: NULL request"); return STATUS_INVALID_PARAMETER; }

    switch (request->operation) {
        case 0: {
            if (request->pid == 0 && request->port == 0 &&
                request->protocol == 0 && net_capture::is_zero_ip(request->ip_addr)) {
                NET_ERR("filter_rule: rejecting wildcard rule with no pid/port/protocol/ip");
                return STATUS_INVALID_PARAMETER;
            }
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (_InterlockedCompareExchange(&net_capture::g_filter_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&net_capture::g_next_rule_id);
                    net_capture::g_filter_rules[i].rule_id = id;
                    net_capture::g_filter_rules[i].action = request->action;
                    net_capture::g_filter_rules[i].direction = request->direction;
                    net_capture::g_filter_rules[i].protocol = request->protocol;
                    net_capture::g_filter_rules[i].pid = request->pid;
                    net_capture::g_filter_rules[i].port = request->port;
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_addr, request->ip_addr, 16);
                    strong::kmemcpy(net_capture::g_filter_rules[i].ip_mask, request->ip_mask, 16);
                    KeMemoryBarrier();
                    _InterlockedExchange(&net_capture::g_filter_rules[i].active, 1);
                    _InterlockedIncrement(&net_capture::g_active_rule_count);

                    request->rule_id = id;
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
                    NET_DBG("filter_rule: ADDED id=%u action=%u dir=%u proto=%u pid=%u port=%u (total=%u)",
                            id, request->action, request->direction, request->protocol, request->pid, request->port,
                            request->rule_count);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                if (net_capture::g_filter_rules[i].active == 1 &&
                    net_capture::g_filter_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
                    _InterlockedDecrement(&net_capture::g_active_rule_count);
                    request->rule_count = (UINT32)net_capture::g_active_rule_count;
                    NET_DBG("filter_rule: REMOVED id=%u (remaining=%u)", request->rule_id, request->rule_count);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 2: {
            for (UINT32 i = 0; i < MAX_FILTER_RULES; i++) {
                _InterlockedExchange(&net_capture::g_filter_rules[i].active, 0);
            }
            _InterlockedExchange(&net_capture::g_active_rule_count, 0);
            request->rule_count = 0;
            NET_DBG("filter_rule: CLEARED all rules");
            return STATUS_SUCCESS;
        }
        case 3: {
            request->rule_count = (UINT32)net_capture::g_active_rule_count;
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
    }
}

NTSTATUS functions::handle_net_stats(p_net_stats request) {
    if (!request) { NET_ERR("handle_net_stats: NULL request"); return STATUS_INVALID_PARAMETER; }

    LARGE_INTEGER stats_freq = {};
    LARGE_INTEGER stats_start = KeQueryPerformanceCounter(&stats_freq);
    NTSTATUS active_status = STATUS_UNSUCCESSFUL;
    UINT32 active_count = 0;
    UINT32 active_degraded = 0;

    if (KeGetCurrentIrql() == PASSIVE_LEVEL) {
        p_net_enum_conn conn_request = static_cast<p_net_enum_conn>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(net_enum_conn), 'tSNW'));
        if (conn_request) {
            strong::kmemset(conn_request, 0, sizeof(net_enum_conn));
            conn_request->filter_pid = request->filter_pid;
            conn_request->filter_protocol = 0;
            active_status = net_enum::enumerate_connections(conn_request);
            if (NT_SUCCESS(active_status)) {
                active_count = conn_request->connection_count;
            } else {
                active_degraded = 1;
            }
            ExFreePoolWithTag(conn_request, 'tSNW');
        } else {
            active_status = STATUS_INSUFFICIENT_RESOURCES;
            active_degraded = 1;
        }
    } else {
        active_status = STATUS_INVALID_DEVICE_STATE;
        active_degraded = 1;
    }

    LARGE_INTEGER stats_end = KeQueryPerformanceCounter(nullptr);
    ULONGLONG active_elapsed_ms = 0;
    if (stats_freq.QuadPart > 0 && stats_end.QuadPart >= stats_start.QuadPart) {
        active_elapsed_ms = static_cast<ULONGLONG>(
            ((stats_end.QuadPart - stats_start.QuadPart) * 1000) / stats_freq.QuadPart);
    }

    request->bytes_sent = (UINT64)net_capture::g_global_bytes_sent;
    request->bytes_received = (UINT64)net_capture::g_global_bytes_recv;
    request->packets_sent = (UINT64)net_capture::g_global_pkts_sent;
    request->packets_received = (UINT64)net_capture::g_global_pkts_recv;
    request->active_connections = active_count;
    request->capture_active = (UINT32)net_capture::g_capture_active;
    request->total_captured = (UINT32)net_capture::g_total_captured;
    request->total_dropped = (UINT32)net_capture::g_total_dropped;
    request->total_dns_logged = (UINT32)net_capture::g_total_dns;
    request->active_filter_rules = (UINT32)net_capture::g_active_rule_count;

    NET_DBG("handle_net_stats: active_source=NCON status=0x%08x count=%u degraded=%u elapsed_ms=%llu filter_pid=%u irql=%u",
            active_status,
            active_count,
            active_degraded,
            active_elapsed_ms,
            request->filter_pid,
            (UINT32)KeGetCurrentIrql());
    NET_DBG("handle_net_stats: sent=%llu recv=%llu pkts_s=%llu pkts_r=%llu active=%u cap=%u captured=%u dropped=%u wfp_init=%d",
            request->bytes_sent, request->bytes_received,
            request->packets_sent, request->packets_received,
            request->active_connections,
            request->capture_active, request->total_captured, request->total_dropped,
            (int)net_capture::g_wfp_initialized);
    return STATUS_SUCCESS;
}


typedef NTSTATUS(NTAPI* fn_FwpmCalloutCreateEnumHandle0)(
    HANDLE engineHandle, const VOID* enumTemplate, HANDLE* enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutDestroyEnumHandle0)(
    HANDLE engineHandle, HANDLE enumHandle);
typedef NTSTATUS(NTAPI* fn_FwpmCalloutEnum0)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numEntriesRequested,
    FWPM_CALLOUT0_COMPAT*** entries, UINT32* numEntriesReturned);
typedef VOID(NTAPI* fn_FwpmFreeMemory0)(VOID** p);


typedef struct _FWPS_CALLOUT_ENUM_ENTRY {
    GUID   calloutKey;
    UINT32 calloutId;
    UINT32 flags;
    PVOID  classifyFn;
    PVOID  notifyFn;
    PVOID  flowDeleteFn;
} FWPS_CALLOUT_ENUM_ENTRY;

typedef NTSTATUS(NTAPI* fn_FwpsCalloutEnum0)(
    HANDLE engineHandle, HANDLE enumHandle, UINT32 numRequested,
    FWPS_CALLOUT_ENUM_ENTRY** entries, UINT32* numReturned);

namespace net_wfp_enum {

    static void get_module_name_for_address(UINT64 address, char* out_name, SIZE_T max_len);
    static const UINT32 WFP_ENUM_FALLBACK_REASON_MISSING_FUNCTIONS = 1;
    static const UINT32 WFP_ENUM_FALLBACK_REASON_ENGINE_OPEN_FAILED = 2;
    static const UINT32 WFP_ENUM_FALLBACK_REASON_BFE_ZERO_ENTRIES = 3;

    static const char* fallback_reason_name(UINT32 reason) {
        switch (reason) {
        case WFP_ENUM_FALLBACK_REASON_MISSING_FUNCTIONS: return "missing_bfe_enum_functions";
        case WFP_ENUM_FALLBACK_REASON_ENGINE_OPEN_FAILED: return "engine_open_failed";
        case WFP_ENUM_FALLBACK_REASON_BFE_ZERO_ENTRIES: return "bfe_returned_zero_entries";
        default: return "unknown";
        }
    }

    static BOOLEAN is_slop_classify_address(UINT64 address) {
        return address == (UINT64)net_capture::classify_inbound ||
               address == (UINT64)net_capture::classify_outbound ||
               address == (UINT64)net_capture::classify_datagram_v4 ||
               address == (UINT64)net_capture::classify_ale_connect ||
               address == (UINT64)net_capture::classify_ale_recv;
    }

    static void append_preview_part(char* out, SIZE_T max_len, const char* prefix, const char* value) {
        if (!out || max_len == 0 || !prefix || !value || value[0] == 0) return;
        SIZE_T pos = 0;
        while (pos + 1 < max_len && out[pos]) ++pos;
        for (SIZE_T i = 0; prefix[i] && pos + 1 < max_len; ++i) out[pos++] = prefix[i];
        for (SIZE_T i = 0; value[i] && pos + 1 < max_len; ++i) out[pos++] = value[i];
        out[pos] = 0;
    }

    static void copy_bfe_identity_preview(const FWPM_DISPLAY_DATA0* display,
                                          const net_capture::WFP_APP_CONDITION_INFO* app,
                                          char* out,
                                          SIZE_T max_len) {
        if (!out || max_len == 0) return;
        out[0] = 0;
        char name[48] = {};
        char desc[48] = {};
        net_capture::copy_display_name_ascii(display, name, sizeof(name));
        net_capture::copy_display_description_ascii(display, desc, sizeof(desc));
        append_preview_part(out, max_len, "n=", name);
        append_preview_part(out, max_len, ";d=", desc);
        if (app && app->found)
            append_preview_part(out, max_len, ";a=", app->preview);
    }

    static void append_registered_callout(p_wfp_callout_enum request,
                                          UINT32* total_filled,
                                          UINT32 callout_id,
                                          const GUID* callout_key,
                                          const GUID* applicable_layer,
                                          UINT64 classify_fn,
                                          UINT64 notify_fn,
                                          UINT64 flow_delete_fn,
                                          UINT32 fallback_reason,
                                          NTSTATUS fallback_status,
                                          ULONG fallback_win32,
                                          UINT32 auth_service) {
        if (!request || !total_filled || *total_filled >= MAX_WFP_CALLOUTS || callout_id == 0)
            return;

        WFP_CALLOUT_ENTRY* out = &request->entries[*total_filled];
        strong::kmemset(out, 0, sizeof(WFP_CALLOUT_ENTRY));
        out->callout_id = callout_id;
        out->callout_key = *callout_key;
        out->applicable_layer = *applicable_layer;
        out->classify_fn = classify_fn;
        out->notify_fn = notify_fn;
        out->flow_delete_fn = flow_delete_fn;
        out->owning_module_base = (UINT64)net_capture::find_module_base("slopdrvr.sys");
        out->entry_type = WFP_ENTRY_TYPE_CALLOUT;
        out->provider_present = 0;
        out->filter_id = ((UINT64)fallback_win32 << 32) | fallback_reason;
        out->flags = (UINT32)fallback_status;
        out->action_type = auth_service;
        out->slop_match_reason = (net_capture::is_slop_callout_key(callout_key) ? WFP_SLOP_MATCH_ACTION_CALLOUT : 0) |
            WFP_SLOP_MATCH_RUNTIME_FALLBACK;
        get_module_name_for_address(classify_fn, out->owning_module, sizeof(out->owning_module));
        (*total_filled)++;
    }

    static NTSTATUS enumerate_registered_callouts(p_wfp_callout_enum request,
                                                  UINT32 fallback_reason,
                                                  NTSTATUS fallback_status,
                                                  ULONG fallback_win32,
                                                  UINT32 auth_service) {
        if (!request) return STATUS_INVALID_PARAMETER;

        UINT32 total_filled = 0;
        append_registered_callout(request, &total_filled,
            net_capture::g_callout_id_inbound,
            &net_capture::GUID_SLOP_CALLOUT_INBOUND,
            &GUID_LAYER_INBOUND_V4,
            (UINT64)net_capture::classify_inbound,
            (UINT64)net_capture::callout_notify,
            0,
            fallback_reason,
            fallback_status,
            fallback_win32,
            auth_service);
        append_registered_callout(request, &total_filled,
            net_capture::g_callout_id_outbound,
            &net_capture::GUID_SLOP_CALLOUT_OUTBOUND,
            &GUID_LAYER_OUTBOUND_V4,
            (UINT64)net_capture::classify_outbound,
            (UINT64)net_capture::callout_notify,
            0,
            fallback_reason,
            fallback_status,
            fallback_win32,
            auth_service);
        append_registered_callout(request, &total_filled,
            net_capture::g_callout_id_datagram,
            &net_capture::GUID_SLOP_CALLOUT_DATAGRAM,
            &GUID_LAYER_DATAGRAM_V4,
            (UINT64)net_capture::classify_datagram_v4,
            (UINT64)net_capture::callout_notify,
            0,
            fallback_reason,
            fallback_status,
            fallback_win32,
            auth_service);
        request->callout_count = total_filled;
        UINT32 classify_available = 0;
        UINT32 slop_matches = 0;
        for (UINT32 i = 0; i < total_filled; ++i) {
            if (request->entries[i].classify_fn != 0) {
                ++classify_available;
                if (is_slop_classify_address(request->entries[i].classify_fn))
                    ++slop_matches;
            }
        }
        SD_LOG("net_wfp_enum::enumerate_registered_callouts source=runtime_registered_fallback degraded=1 reason=%s reason_code=%u status=0x%08X win32=%lu auth_service=0x%08X count=%u bfe_callouts=0 bfe_filters=0 classify_addresses_available=%u slop_callback_matches=%u filter_cleanup=0",
            fallback_reason_name(fallback_reason),
            fallback_reason,
            fallback_status,
            fallback_win32,
            auth_service,
            total_filled,
            classify_available,
            slop_matches);
        return (total_filled != 0) ? STATUS_SUCCESS : STATUS_NOT_FOUND;
    }


    static void get_module_name_for_address(UINT64 address, char* out_name, SIZE_T max_len) {
        out_name[0] = 0;
        if (address == 0) return;

        ULONG required = 0;
        NTSTATUS status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, nullptr, 0, &required);
        if (required == 0) return;

        required += sizeof(RTL_PROCESS_MODULE_INFORMATION) * 4;
        PRTL_PROCESS_MODULES mods = (PRTL_PROCESS_MODULES)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, required, 'wmNW');
        if (!mods) return;

        status = ZwQuerySystemInformation(
            SystemModuleInformationInternal, mods, required, nullptr);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(mods, 'wmNW');
            return;
        }

        for (ULONG i = 0; i < mods->NumberOfModules; i++) {
            UINT64 base = (UINT64)mods->Modules[i].ImageBase;
            UINT64 end = base + mods->Modules[i].ImageSize;
            if (address >= base && address < end) {
                const char* full_path = (const char*)mods->Modules[i].FullPathName;
                const char* name = full_path + mods->Modules[i].OffsetToFileName;
                SIZE_T j = 0;
                while (name[j] && j < max_len - 1) {
                    out_name[j] = name[j];
                    j++;
                }
                out_name[j] = 0;
                break;
            }
        }

        ExFreePoolWithTag(mods, 'wmNW');
    }

    static BOOLEAN text_contains_ci(const char* text, const char* needle) {
        if (!needle || needle[0] == 0) return TRUE;
        if (!text || text[0] == 0) return FALSE;
        SIZE_T nlen = 0;
        while (needle[nlen] && nlen < 63) ++nlen;
        SIZE_T tlen = 0;
        while (text[tlen] && tlen < 63) ++tlen;
        if (tlen < nlen) return FALSE;
        for (SIZE_T s = 0; s <= tlen - nlen; ++s) {
            BOOLEAN ok = TRUE;
            for (SIZE_T k = 0; k < nlen; ++k) {
                char a = text[s + k];
                char b = needle[k];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) { ok = FALSE; break; }
            }
            if (ok) return TRUE;
        }
        return FALSE;
    }

    static NTSTATUS enumerate_wfp_callouts(p_wfp_callout_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->callout_count = 0;
        const UINT32 auth_service = net_capture::WFP_BFE_AUTH_SERVICE;

        if (!net_capture::_FwpmEngineOpen0 || !net_capture::_FwpmEngineClose0) {
            if (!net_capture::resolve_wfp_functions()) {
                NTSTATUS fallback_status = STATUS_NOT_SUPPORTED;
                ULONG fallback_win32 = net_capture::status_to_win32(fallback_status);
                SD_LOG("net_wfp_enum::enumerate_wfp_callouts source=runtime_registered_fallback degraded=1 reason=resolve_wfp_functions_failed status=0x%08X win32=%lu auth_service=0x%08X filter_cleanup=0",
                    fallback_status,
                    fallback_win32,
                    auth_service);
                return enumerate_registered_callouts(request,
                    WFP_ENUM_FALLBACK_REASON_MISSING_FUNCTIONS,
                    fallback_status,
                    fallback_win32,
                    auth_service);
            }
        }

        if (!net_capture::_FwpmCalloutCreateEnumHandle0 ||
            !net_capture::_FwpmCalloutDestroyEnumHandle0 ||
            !net_capture::_FwpmCalloutEnum0 ||
            !net_capture::_FwpmFilterCreateEnumHandle0 ||
            !net_capture::_FwpmFilterDestroyEnumHandle0 ||
            !net_capture::_FwpmFilterEnum0 ||
            !net_capture::_FwpmFreeMemory0) {
            NTSTATUS fallback_status = STATUS_PROCEDURE_NOT_FOUND;
            ULONG fallback_win32 = net_capture::status_to_win32(fallback_status);
            SD_LOG("net_wfp_enum::enumerate_wfp_callouts source=runtime_registered_fallback degraded=1 reason=missing_bfe_enum_functions status=0x%08X win32=%lu auth_service=0x%08X filter_cleanup=0",
                fallback_status,
                fallback_win32,
                auth_service);
            return enumerate_registered_callouts(request,
                WFP_ENUM_FALLBACK_REASON_MISSING_FUNCTIONS,
                fallback_status,
                fallback_win32,
                auth_service);
        }

        HANDLE engine = nullptr;
        NTSTATUS status = net_capture::_FwpmEngineOpen0(nullptr, auth_service, nullptr, nullptr, &engine);
        NTSTATUS engine_open_status = status;
        ULONG engine_open_win32 = net_capture::status_to_win32(status);
        SD_LOG("net_wfp_enum::enumerate_wfp_callouts engine_open auth_service=0x%08X status=0x%08X win32=%lu engine=%p",
            auth_service,
            engine_open_status,
            engine_open_win32,
            engine);
        if (!NT_SUCCESS(status) || !engine) {
            SD_LOG("net_wfp_enum::enumerate_wfp_callouts source=runtime_registered_fallback degraded=1 reason=engine_open_failed status=0x%08X win32=%lu auth_service=0x%08X engine=%p filter_cleanup=0",
                engine_open_status,
                engine_open_win32,
                auth_service,
                engine);
            return enumerate_registered_callouts(request,
                WFP_ENUM_FALLBACK_REASON_ENGINE_OPEN_FAILED,
                engine_open_status,
                engine_open_win32,
                auth_service);
        }

        UINT32 total_filled = 0;
        UINT32 bfe_callouts_filled = 0;
        UINT32 bfe_filters_filled = 0;
        UINT32 bfe_callout_key_matches = 0;
        UINT32 bfe_filter_key_matches = 0;
        UINT32 bfe_filter_block_actions = 0;
        UINT32 bfe_filters_with_app = 0;
        UINT32 bfe_filter_details_logged = 0;
        UINT32 bfe_filter_details_suppressed = 0;
        UINT32 classify_addresses_available = 0;
        UINT32 slop_callback_matches = 0;
        NTSTATUS callout_enum_status = STATUS_SUCCESS;
        NTSTATUS filter_enum_status = STATUS_SUCCESS;
        BOOLEAN has_filter = (request->filter_module[0] != 0);
        HANDLE callout_enum = nullptr;
        status = net_capture::_FwpmCalloutCreateEnumHandle0(engine, nullptr, &callout_enum);
        callout_enum_status = status;
        SD_LOG("net_wfp_enum::enumerate_wfp_callouts callout_enum_create status=0x%08X win32=%lu handle=%p",
            status,
            net_capture::status_to_win32(status),
            callout_enum);
        if (NT_SUCCESS(status) && callout_enum) {
            for (;;) {
                FWPM_CALLOUT0_COMPAT** entries = nullptr;
                UINT32 returned = 0;
                status = net_capture::_FwpmCalloutEnum0(engine, callout_enum, 64, &entries, &returned);
                callout_enum_status = status;
                SD_LOG("net_wfp_enum::enumerate_wfp_callouts callout_enum status=0x%08X win32=%lu returned=%u total_before=%u",
                    status,
                    net_capture::status_to_win32(status),
                    returned,
                    bfe_callouts_filled);
                if (!NT_SUCCESS(status) || returned == 0) {
                    if (entries) net_capture::_FwpmFreeMemory0((VOID**)&entries);
                    break;
                }

                for (UINT32 i = 0; i < returned && total_filled < MAX_WFP_CALLOUTS; i++) {
                    FWPM_CALLOUT0_COMPAT* c = entries[i];
                    if (!c) continue;

                    WFP_CALLOUT_ENTRY candidate = {};
                    candidate.entry_type = WFP_ENTRY_TYPE_CALLOUT;
                    candidate.callout_id = c->calloutId;
                    candidate.callout_key = c->calloutKey;
                    candidate.applicable_layer = c->applicableLayer;
                    candidate.flags = c->flags;
                    candidate.provider_present = c->providerKey ? 1u : 0u;
                    candidate.slop_match_reason = net_capture::callout_match_reason(c);
                    if (candidate.slop_match_reason != 0) ++bfe_callout_key_matches;
                    copy_bfe_identity_preview(&c->displayData, nullptr, candidate.owning_module, sizeof(candidate.owning_module));
                    if (has_filter && !text_contains_ci(candidate.owning_module, request->filter_module))
                        continue;

                    strong::kmemcpy(&request->entries[total_filled], &candidate, sizeof(candidate));
                    ++total_filled;
                    ++bfe_callouts_filled;
                }
                net_capture::_FwpmFreeMemory0((VOID**)&entries);
            }
            net_capture::_FwpmCalloutDestroyEnumHandle0(engine, callout_enum);
        }

        HANDLE filter_enum = nullptr;
        status = net_capture::_FwpmFilterCreateEnumHandle0(engine, nullptr, &filter_enum);
        filter_enum_status = status;
        SD_LOG("net_wfp_enum::enumerate_wfp_callouts filter_enum_create status=0x%08X win32=%lu handle=%p",
            status,
            net_capture::status_to_win32(status),
            filter_enum);
        if (NT_SUCCESS(status) && filter_enum) {
            for (;;) {
                FWPM_FILTER0_COMPAT** entries = nullptr;
                UINT32 returned = 0;
                status = net_capture::_FwpmFilterEnum0(engine, filter_enum, 64, &entries, &returned);
                filter_enum_status = status;
                SD_LOG("net_wfp_enum::enumerate_wfp_callouts filter_enum status=0x%08X win32=%lu returned=%u total_before=%u",
                    status,
                    net_capture::status_to_win32(status),
                    returned,
                    bfe_filters_filled);
                if (!NT_SUCCESS(status) || returned == 0) {
                    if (entries) net_capture::_FwpmFreeMemory0((VOID**)&entries);
                    break;
                }

                for (UINT32 i = 0; i < returned && total_filled < MAX_WFP_CALLOUTS; i++) {
                    FWPM_FILTER0_COMPAT* f = entries[i];
                    if (!f) continue;

                    WFP_CALLOUT_ENTRY candidate = {};
                    net_capture::WFP_APP_CONDITION_INFO app_info = {};
                    net_capture::inspect_filter_app_condition(f, &app_info);
                    candidate.entry_type = WFP_ENTRY_TYPE_FILTER;
                    candidate.filter_id = f->filterId;
                    candidate.flags = f->flags;
                    candidate.applicable_layer = f->layerKey;
                    candidate.sublayer_key = f->subLayerKey;
                    candidate.action_type = (UINT32)f->action.type;
                    candidate.callout_key = f->action.calloutKey;
                    candidate.provider_present = f->providerKey ? 1u : 0u;
                    candidate.slop_match_reason = net_capture::filter_match_reason(f);
                    if (candidate.slop_match_reason != 0) ++bfe_filter_key_matches;
                    if (candidate.action_type == (UINT32)FWP_ACTION_BLOCK_) ++bfe_filter_block_actions;
                    if (app_info.found != 0) ++bfe_filters_with_app;
                    copy_bfe_identity_preview(&f->displayData, &app_info, candidate.owning_module, sizeof(candidate.owning_module));
                    if ((candidate.slop_match_reason != 0 || candidate.action_type == (UINT32)FWP_ACTION_BLOCK_ || app_info.found != 0) &&
                        bfe_filter_details_logged < 96) {
                        ++bfe_filter_details_logged;
                        SD_LOG("net_wfp_enum::filter_detail id=%llu action=0x%08X flags=0x%08X provider_present=%u conditions=%u app_found=%u app_index=%u app_type=%u app_blob=%u app_original=%u app_slop=%u reason=0x%08X preview='%s'",
                            (unsigned long long)f->filterId,
                            candidate.action_type,
                            candidate.flags,
                            candidate.provider_present,
                            f->numFilterConditions,
                            app_info.found,
                            app_info.index,
                            app_info.value_type,
                            app_info.blob_size,
                            app_info.original_app_id,
                            app_info.slop_candidate,
                            candidate.slop_match_reason,
                            candidate.owning_module);
                    } else if (candidate.slop_match_reason != 0 || candidate.action_type == (UINT32)FWP_ACTION_BLOCK_ || app_info.found != 0) {
                        ++bfe_filter_details_suppressed;
                    }
                    if (has_filter && !text_contains_ci(candidate.owning_module, request->filter_module))
                        continue;

                    strong::kmemcpy(&request->entries[total_filled], &candidate, sizeof(candidate));
                    ++total_filled;
                    ++bfe_filters_filled;
                }
                net_capture::_FwpmFreeMemory0((VOID**)&entries);
            }
            net_capture::_FwpmFilterDestroyEnumHandle0(engine, filter_enum);
        }

        NTSTATUS close_status = net_capture::_FwpmEngineClose0(engine);

        request->callout_count = total_filled;
        SD_LOG("net_wfp_enum::enumerate_wfp_callouts source=bfe_full degraded=0 auth_service=0x%08X engine_open_status=0x%08X engine_open_win32=%lu callout_enum_status=0x%08X filter_enum_status=0x%08X engine_close_status=0x%08X total=%u callouts=%u filters=%u callout_key_matches=%u filter_key_matches=%u block_filters=%u filters_with_app=%u detail_logged=%u detail_suppressed=%u classify_addresses_available=%u slop_callback_matches=%u filter_module_present=%u filter_cleanup=0",
            auth_service,
            engine_open_status,
            engine_open_win32,
            callout_enum_status,
            filter_enum_status,
            close_status,
            total_filled,
            bfe_callouts_filled,
            bfe_filters_filled,
            bfe_callout_key_matches,
            bfe_filter_key_matches,
            bfe_filter_block_actions,
            bfe_filters_with_app,
            bfe_filter_details_logged,
            bfe_filter_details_suppressed,
            classify_addresses_available,
            slop_callback_matches,
            has_filter ? 1u : 0u);
        if (total_filled == 0) {
            ULONG fallback_win32 = net_capture::status_to_win32(STATUS_NOT_FOUND);
            SD_LOG("net_wfp_enum::enumerate_wfp_callouts source=runtime_registered_fallback degraded=1 reason=bfe_returned_zero_entries status=0x%08X win32=%lu auth_service=0x%08X filter_cleanup=0",
                STATUS_NOT_FOUND,
                fallback_win32,
                auth_service);
            return enumerate_registered_callouts(request,
                WFP_ENUM_FALLBACK_REASON_BFE_ZERO_ENTRIES,
                STATUS_NOT_FOUND,
                fallback_win32,
                auth_service);
        }
        return STATUS_SUCCESS;
    }
}


static UINT32 slop_resolve_packet_pid(UINT64 endpoint_handle,
                                      UINT32 protocol,
                                      UINT32 local_port,
                                      UINT32 remote_port) {
    UINT32 cached_pid = slop_lookup_cached_endpoint_pid(endpoint_handle, protocol, local_port);
    if (cached_pid != 0) {
        return cached_pid;
    }

    cached_pid = slop_lookup_cached_port_pid(protocol, local_port, remote_port);
    if (cached_pid != 0) {
        return cached_pid;
    }

    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return 0;

    {
        LONG64 now_tsc = static_cast<LONG64>(__rdtsc());
        LONG64 last    = _InterlockedCompareExchange64(&g_last_handle_enum_tsc, 0, 0);
        if (last != 0 && (now_tsc - last) < HANDLE_ENUM_COOLDOWN_TSC)
            return 0;
        _InterlockedExchange64(&g_last_handle_enum_tsc, now_tsc);
    }

    if (!net_enum::resolve_nsi())
        return 0;


    if (protocol == 0 || protocol == IPPROTO_TCP) {
        UINT32 tcp_capacity = 4096;
        UINT32 tcp_count = 0;
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        UINT8* buf = nullptr;

        for (UINT32 attempt = 0; attempt < 8; attempt++) {
            tcp_count = tcp_capacity;
            ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
            ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

            buf = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'rpNW'));
            if (!buf) break;

            auto* keys = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
            auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz);


            st = net_enum::_NsiEnumerate(
                net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                3, keys, sizeof(net_enum::NSI_TCP_KEY),
                nullptr, 0,
                nullptr, 0,
                stats, sizeof(net_enum::NSI_TCP_STATIC),
                &tcp_count);


            if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                for (UINT32 i = 0; i < tcp_count; i++) {
                    UINT32 lp = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                    UINT32 rp = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                    BOOLEAN match = FALSE;
                    if (local_port != 0 && lp == local_port) match = TRUE;
                    if (!match && remote_port != 0 && rp == remote_port) match = TRUE;
                    if (!match && local_port != 0 && rp == local_port) match = TRUE;

                    if (match && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        slop_store_cached_port_pid(IPPROTO_TCP, local_port, pid);
                        slop_store_cached_port_pid(IPPROTO_TCP, remote_port, pid);
                        if (endpoint_handle != 0)
                            slop_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
                        ExFreePoolWithTag(buf, 'rpNW');
                        return pid;
                    }
                }
            }

            if (NT_SUCCESS(st)) {
                ExFreePoolWithTag(buf, 'rpNW');
                break;
            }

            ExFreePoolWithTag(buf, 'rpNW');
            buf = nullptr;
            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                st == static_cast<NTSTATUS>(0xC0000023)) {
                UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                if (next > 65536) next = 65536;
                if (next == tcp_capacity) break;
                tcp_capacity = next;
                continue;
            }
            break;
        }
    }


    if (protocol == 0 || protocol == IPPROTO_UDP) {
        UINT32 udp_capacity = 4096;
        UINT32 udp_count = 0;
        NTSTATUS st = STATUS_UNSUCCESSFUL;
        UINT8* buf = nullptr;

        for (UINT32 attempt = 0; attempt < 8; attempt++) {
            udp_count = udp_capacity;
            ULONG key_sz = udp_capacity * sizeof(net_enum::NSI_UDP_KEY);
            ULONG sta_sz = udp_capacity * sizeof(net_enum::NSI_UDP_STATIC);

            buf = static_cast<UINT8*>(
                ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'rpNW'));
            if (!buf) break;

            auto* keys = reinterpret_cast<net_enum::NSI_UDP_KEY*>(buf);
            auto* stats = reinterpret_cast<net_enum::NSI_UDP_STATIC*>(buf + key_sz);

            st = net_enum::_NsiEnumerate(
                net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_UDP_MODULEID,
                1, keys, sizeof(net_enum::NSI_UDP_KEY),
                nullptr, 0,
                nullptr, 0,
                stats, sizeof(net_enum::NSI_UDP_STATIC),
                &udp_count);


            if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                for (UINT32 i = 0; i < udp_count; i++) {
                    UINT32 lp = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);

                    if ((local_port != 0 && lp == local_port) && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        slop_store_cached_port_pid(IPPROTO_UDP, local_port, pid);
                        if (endpoint_handle != 0)
                            slop_store_cached_endpoint_pid(endpoint_handle, protocol, local_port, pid);
                        ExFreePoolWithTag(buf, 'rpNW');
                        return pid;
                    }
                }
            }

            if (NT_SUCCESS(st)) {
                ExFreePoolWithTag(buf, 'rpNW');
                break;
            }

            ExFreePoolWithTag(buf, 'rpNW');
            buf = nullptr;
            if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                st == static_cast<NTSTATUS>(0xC0000023)) {
                UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                if (next > 65536) next = 65536;
                if (next == udp_capacity) break;
                udp_capacity = next;
                continue;
            }
            break;
        }
    }

    return 0;
}


namespace net_socket_enum {
    typedef SLOP_SYSTEM_HANDLE_TABLE_ENTRY_INFO SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL;
    typedef SLOP_SYSTEM_HANDLE_INFORMATION SYSTEM_HANDLE_INFORMATION_LOCAL;
    typedef PSLOP_SYSTEM_HANDLE_INFORMATION PSYSTEM_HANDLE_INFORMATION_LOCAL;

    static NTSTATUS query_system_handles(PSYSTEM_HANDLE_INFORMATION_LOCAL* out_info) {
        return slop_query_system_handles(out_info);
    }


    static NTSTATUS enumerate_socket_handles(p_socket_handle_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->socket_count = 0;

        UINT32 target_pid = request->target_pid;
        NET_DBG("enum_sock: ENTER target_pid=%u IRQL=%u", target_pid, (UINT32)KeGetCurrentIrql());
        if (target_pid == 0) {
            NET_ERR("enum_sock: target_pid is 0, returning INVALID_PARAMETER");
            return STATUS_INVALID_PARAMETER;
        }

        if (!slop_can_query_system_handles()) {
            NET_ERR("enum_sock: cannot query handles (IRQL too high)");
            return STATUS_INVALID_DEVICE_STATE;
        }

        NET_DBG("enum_sock: calling query_system_handles...");
        PSYSTEM_HANDLE_INFORMATION_LOCAL handles = nullptr;
        NTSTATUS status = query_system_handles(&handles);
        NET_DBG("enum_sock: query_system_handles returned 0x%08x handles=%p", status, handles);
        if (!NT_SUCCESS(status) || !handles) {
            NET_ERR("enum_sock: query_system_handles FAILED 0x%08x", status);
            return status;
        }


        constexpr UINT32 MAX_PID_HANDLES = 1024;
        USHORT* pid_handles = static_cast<USHORT*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_PID_HANDLES * sizeof(USHORT), 'shNW'));
        if (!pid_handles) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        NET_DBG("enum_sock: total system handles=%lu, scanning for pid=%u", handles->NumberOfHandles, target_pid);
        UINT32 pid_handle_count = 0;
        for (ULONG i = 0; i < handles->NumberOfHandles && pid_handle_count < MAX_PID_HANDLES; i++) {
            const SYSTEM_HANDLE_TABLE_ENTRY_INFO_LOCAL* entry = &handles->Handles[i];
            if (static_cast<UINT32>(entry->UniqueProcessId) == target_pid) {
                pid_handles[pid_handle_count++] = entry->HandleValue;
            }
        }
        ExFreePoolWithTag(handles, 'hANW');
        handles = nullptr;

        NET_DBG("enum_sock: found %u handles for pid %u", pid_handle_count, target_pid);

        if (pid_handle_count == 0) {
            ExFreePoolWithTag(pid_handles, 'shNW');
            NET_DBG("enum_sock: no handles, returning SUCCESS with count=0");
            return STATUS_SUCCESS;
        }


        PEPROCESS process = nullptr;
        status = PsLookupProcessByProcessId(
            reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(target_pid)), &process);
        if (!NT_SUCCESS(status) || !process) {
            NET_ERR("enum_sock: PsLookupProcessByProcessId failed 0x%08x", status);
            ExFreePoolWithTag(pid_handles, 'shNW');
            return status;
        }


        NET_DBG("enum_sock: pre-initializing AFD offsets before attach");
        (void)afd_get_offsets();
        NET_DBG("enum_sock: AFD offsets ready, attaching to process %u, iterating %u handles", target_pid, pid_handle_count);
        UINT32 filled = 0;
        UINT32 ref_fail = 0, not_afd = 0, extract_fail = 0;
        KAPC_STATE apc_state = {};
        KeStackAttachProcess(process, &apc_state);

        __try {
            for (UINT32 i = 0; i < pid_handle_count && filled < MAX_SOCKET_HANDLES; i++) {
                HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));
                if (i < 3 || (i % 100 == 0))
                    NET_DBG("enum_sock: handle[%u/%u] val=0x%X", i, pid_handle_count, pid_handles[i]);


                PVOID file_obj = nullptr;
                NTSTATUS ref_st = ObReferenceObjectByHandle(
                    h, 0,
                    (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                    KernelMode, &file_obj, nullptr);
                if (!NT_SUCCESS(ref_st) || !file_obj) {
                    ref_fail++;
                    continue;
                }

                PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);


                if (!slop_is_afd_file_object(fo)) {
                    ObDereferenceObject(fo);
                    not_afd++;
                    continue;
                }

                if (i < 3 || (i % 100 == 0))
                    NET_DBG("enum_sock: handle[%u] is AFD, extracting info", i);

                SOCKET_HANDLE_ENTRY* out = &request->entries[filled];
                strong::kmemset(out, 0, sizeof(SOCKET_HANDLE_ENTRY));
                out->handle_value = static_cast<UINT64>(pid_handles[i]);
                out->pid = target_pid;

                BOOLEAN ok = slop_extract_socket_info_from_fo(fo, out);
                ObDereferenceObject(fo);

                if (!ok) {
                    extract_fail++;
                    continue;
                }

                slop_cache_pid_from_socket_info(out, target_pid);
                filled++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NET_ERR("enum_sock: EXCEPTION in handle loop at iteration, filled=%u", filled);
        }

        KeUnstackDetachProcess(&apc_state);
        ObDereferenceObject(process);
        ExFreePoolWithTag(pid_handles, 'shNW');

        NET_DBG("enum_sock: DONE filled=%u ref_fail=%u not_afd=%u extract_fail=%u", filled, ref_fail, not_afd, extract_fail);
        request->socket_count = filled;
        return STATUS_SUCCESS;
    }
}


namespace net_sniff {


    inline volatile LONG g_sniff_active = 0;
    inline KSPIN_LOCK g_sniff_lock;
    inline BOOLEAN g_sniff_lock_initialized = FALSE;

    inline UINT32 g_sniff_bp_index = 0;
    inline UINT32 g_sniff_tid = 0;
    inline UINT32 g_sniff_buf_reg = 0;
    inline UINT32 g_sniff_size_reg = 0;
    inline UINT32 g_sniff_max_captures = 1;
    inline volatile LONG g_sniff_capture_count = 0;
    inline SNIFF_CAPTURE* g_sniff_captures = nullptr;


    static NTSTATUS handle_sniff(p_sniff_net_buffers request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_sniff: op=%u target_addr=0x%llx buf_reg=%u size_reg=%u max_cap=%u tid=%u bp=%u",
                request->operation, request->target_address,
                request->buffer_reg_index, request->size_reg_index,
                request->max_captures, request->target_tid, request->bp_index);

        if (!g_sniff_lock_initialized) {
            KeInitializeSpinLock(&g_sniff_lock);
            g_sniff_lock_initialized = TRUE;
        }

        switch (request->operation) {
        case 0:
        {
            if (_InterlockedCompareExchange(&g_sniff_active, 1, 0) != 0) {

                request->active = 1;
                request->capture_count = (UINT32)g_sniff_capture_count;
                return STATUS_DEVICE_BUSY;
            }


            UINT32 max_cap = request->max_captures;
            if (max_cap == 0) max_cap = 1;
            if (max_cap > SNIFF_MAX_CAPTURES) max_cap = SNIFF_MAX_CAPTURES;

            SIZE_T alloc_size = (SIZE_T)max_cap * sizeof(SNIFF_CAPTURE);
            PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, alloc_size, 'fsNW');
            if (!buf) {
                _InterlockedExchange(&g_sniff_active, 0);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            strong::kmemset(buf, 0, alloc_size);

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            g_sniff_captures = (SNIFF_CAPTURE*)buf;
            g_sniff_max_captures = max_cap;
            g_sniff_capture_count = 0;
            g_sniff_bp_index = request->bp_index;
            g_sniff_tid = request->target_tid;
            g_sniff_buf_reg = request->buffer_reg_index;
            g_sniff_size_reg = request->size_reg_index;
            KeReleaseSpinLock(&g_sniff_lock, irql);


            request->active = 1;
            request->capture_count = 0;
            NET_DBG("handle_sniff[start]: SUCCESS max_cap=%u bp=%u tid=%u buf_reg=%u size_reg=%u",
                    max_cap, g_sniff_bp_index, g_sniff_tid, g_sniff_buf_reg, g_sniff_size_reg);
            return STATUS_SUCCESS;
        }
        case 1:
        {
            _InterlockedExchange(&g_sniff_active, 0);

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            if (g_sniff_captures) {
                ExFreePoolWithTag(g_sniff_captures, 'fsNW');
                g_sniff_captures = nullptr;
            }
            g_sniff_capture_count = 0;
            KeReleaseSpinLock(&g_sniff_lock, irql);

            request->active = 0;
            request->capture_count = 0;
            return STATUS_SUCCESS;
        }
        case 2:
        {
            request->active = (UINT32)g_sniff_active;
            UINT32 count = (UINT32)g_sniff_capture_count;
            if (count > SNIFF_MAX_CAPTURES) count = SNIFF_MAX_CAPTURES;
            request->capture_count = count;

            if (count > 0 && g_sniff_captures) {
                KIRQL irql;
                KeAcquireSpinLock(&g_sniff_lock, &irql);
                SIZE_T copy_size = (SIZE_T)count * sizeof(SNIFF_CAPTURE);
                strong::kmemcpy(request->captures, g_sniff_captures, copy_size);
                KeReleaseSpinLock(&g_sniff_lock, irql);
            }

            return STATUS_SUCCESS;
        }
        case 3:
        {
            if (!g_sniff_active) return STATUS_DEVICE_NOT_READY;

            UINT32 idx = (UINT32)_InterlockedIncrement(&g_sniff_capture_count) - 1;
            if (idx >= g_sniff_max_captures) {

                _InterlockedExchange(&g_sniff_active, 0);
                request->active = 0;
                request->capture_count = g_sniff_max_captures;
                return STATUS_SUCCESS;
            }

            KIRQL irql;
            KeAcquireSpinLock(&g_sniff_lock, &irql);
            if (g_sniff_captures && idx < g_sniff_max_captures) {

                strong::kmemcpy(&g_sniff_captures[idx], &request->captures[0], sizeof(SNIFF_CAPTURE));
            }
            KeReleaseSpinLock(&g_sniff_lock, irql);

            request->active = (UINT32)g_sniff_active;
            request->capture_count = idx + 1;


            if (idx + 1 >= g_sniff_max_captures) {
                _InterlockedExchange(&g_sniff_active, 0);
                request->active = 0;
            }

            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

}


namespace net_tcpip {


    #pragma pack(push, 1)
    typedef struct _NPI_MODULEID_TCPIP {
        USHORT Length;
        UCHAR  Type;
        UCHAR  padding;
        GUID   Id;
    } NPI_MODULEID_TCPIP;
    #pragma pack(pop)

    static const NPI_MODULEID_TCPIP NPI_TCP_MOD = {
        sizeof(NPI_MODULEID_TCPIP), 1, 0,
        { 0xEB004A03, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
    };

    static const NPI_MODULEID_TCPIP NPI_UDP_MOD = {
        sizeof(NPI_MODULEID_TCPIP), 1, 0,
        { 0xEB004A02, 0x9B1A, 0x11D4, { 0x91, 0x23, 0x00, 0x50, 0x04, 0x77, 0x59, 0xBC } }
    };


    typedef NTSTATUS(NTAPI* fn_NsiEnumObjectsAllParams)(
        ULONG Unknown0, ULONG Unknown1, PVOID ModuleId,
        ULONG InfoClass, PVOID KeyData, ULONG KeySize,
        PVOID RwData, ULONG RwSize,
        PVOID DynamicData, ULONG DynSize,
        PVOID StaticData, ULONG StaticSize,
        PULONG Count);


    #pragma pack(push, 1)
    typedef struct _TCP4_KEY {
        UINT8  local_addr[4];
        UINT32 pad1;
        UINT16 local_port_be;
        UINT16 pad2;
        UINT8  remote_addr[4];
        UINT32 pad3;
        UINT16 remote_port_be;
        UINT16 pad4;
    } TCP4_KEY;

    typedef struct _TCP4_DYNAMIC {
        UINT32 state;
        UINT8  _reserved[44];
    } TCP4_DYNAMIC;

    typedef struct _TCP4_STATIC {
        UINT8  _pad0[12];
        UINT32 mod_pid;
        UINT64 create_time;
        UINT8  _pad1[8];
    } TCP4_STATIC;

    typedef struct _UDP4_KEY {
        UINT8  local_addr[4];
        UINT32 pad1;
        UINT16 local_port_be;
        UINT16 pad2;
    } UDP4_KEY;

    typedef struct _UDP4_STATIC {
        UINT32 mod_pid;
        UINT32 _pad0;
        UINT64 create_time;
        UINT8  _pad1[16];
    } UDP4_STATIC;
    #pragma pack(pop)


    static NTSTATUS dump_connections(p_tcpip_conn_dump request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        request->connection_count = 0;

        if (!net_enum::resolve_nsi()) {
            NET_ERR("net_tcpip::dump_connections: NsiEnumerate not resolved");
            return STATUS_NOT_SUPPORTED;
        }

        UINT32 filled = 0;


        if (request->filter_protocol == 0 || request->filter_protocol == 6) {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
                ULONG dyn_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_DYNAMIC);
                ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + dyn_sz + sta_sz, 'tdNW'));
                if (!buf) break;

                auto* keys  = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
                auto* dyns  = reinterpret_cast<net_enum::NSI_TCP_DYNAMIC*>(buf + key_sz);
                auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz + dyn_sz);

                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(net_enum::NSI_TCP_KEY),
                    nullptr, 0,
                    dyns, sizeof(net_enum::NSI_TCP_DYNAMIC),
                    stats, sizeof(net_enum::NSI_TCP_STATIC),
                    &tcp_count);

                if (NT_SUCCESS(st)) {
                    for (UINT32 i = 0; i < tcp_count && filled < MAX_TCPIP_CONNECTIONS; i++) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        if (request->target_pid != 0 && pid != request->target_pid)
                            continue;

                        TCPIP_CONN_ENTRY* out = &request->entries[filled];
                        strong::kmemset(out, 0, sizeof(TCPIP_CONN_ENTRY));
                        out->pid = pid;
                        out->protocol = 6;
                        out->state = net_enum::nsi_tcp_state_to_mib(dyns[i].state);
                        out->address_family = AF_INET;
                        out->local_port  = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        out->remote_port = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);
                        strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                        strong::kmemcpy(out->remote_addr, keys[i].remote.addr, 4);
                        out->create_time = stats[i].create_time;
                        filled++;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    break;
                }

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == tcp_capacity) {
                        NET_ERR("dump_connections: TCP exhausted retries at cap=%u", tcp_capacity);
                        ExFreePoolWithTag(buf, 'tdNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    buf = nullptr;
                    tcp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'tdNW');
                buf = nullptr;
                break;
            }
        }


        if (request->filter_protocol == 0 || request->filter_protocol == 17) {
            UINT32 udp_capacity = 4096;
            UINT32 udp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                udp_count = udp_capacity;
                ULONG key_sz = udp_capacity * sizeof(net_enum::NSI_UDP_KEY);
                ULONG sta_sz = udp_capacity * sizeof(net_enum::NSI_UDP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'tdNW'));
                if (!buf) break;

                auto* keys  = reinterpret_cast<net_enum::NSI_UDP_KEY*>(buf);
                auto* stats = reinterpret_cast<net_enum::NSI_UDP_STATIC*>(buf + key_sz);

                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_UDP_MODULEID,
                    1, keys, sizeof(net_enum::NSI_UDP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(net_enum::NSI_UDP_STATIC),
                    &udp_count);

                if (NT_SUCCESS(st)) {
                    for (UINT32 i = 0; i < udp_count && filled < MAX_TCPIP_CONNECTIONS; i++) {
                        UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                        if (request->target_pid != 0 && pid != request->target_pid)
                            continue;

                        TCPIP_CONN_ENTRY* out = &request->entries[filled];
                        strong::kmemset(out, 0, sizeof(TCPIP_CONN_ENTRY));
                        out->pid = pid;
                        out->protocol = 17;
                        out->state = 0;
                        out->address_family = AF_INET;
                        out->local_port = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        out->remote_port = 0;
                        strong::kmemcpy(out->local_addr, keys[i].local.addr, 4);
                        out->create_time = stats[i].create_time;
                        filled++;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    break;
                }

                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (udp_count > udp_capacity) ? udp_count + 64 : udp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (attempt == 7 || next == udp_capacity) {
                        NET_ERR("dump_connections: UDP exhausted retries at cap=%u", udp_capacity);
                        ExFreePoolWithTag(buf, 'tdNW');
                        buf = nullptr;
                        break;
                    }
                    ExFreePoolWithTag(buf, 'tdNW');
                    buf = nullptr;
                    udp_capacity = next;
                    continue;
                }
                ExFreePoolWithTag(buf, 'tdNW');
                buf = nullptr;
                break;
            }
        }

        request->connection_count = filled;
        return STATUS_SUCCESS;
    }
}


namespace net_inject {


    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleCreate0)(
        UINT16 addressFamily, UINT32 flags, HANDLE* injectionHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectionHandleDestroy0)(HANDLE injectionHandle);
    typedef UINT32(NTAPI* fn_FwpsQueryPacketInjectionState0)(
        HANDLE injectionHandle, PVOID netBufferList, HANDLE* injectionContext);
    typedef PVOID(NTAPI* fn_NdisAllocateNetBufferListPool)(
        NDIS_HANDLE ndisHandle, PNET_BUFFER_LIST_POOL_PARAMETERS parameters);
    typedef VOID(NTAPI* fn_NdisFreeNetBufferListPool)(PVOID poolHandle);
    typedef NTSTATUS(NTAPI* fn_FwpsAllocateNetBufferAndNetBufferList0)(
        HANDLE poolHandle, UINT16 contextSize, UINT16 contextBackfill,
        PMDL mdlChain, ULONG dataOffset, SIZE_T dataLength, PVOID* netBufferList);
    typedef void(NTAPI* fn_FwpsFreeNetBufferList0)(PVOID netBufferList);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectTransportSendAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT64 endpointHandle, UINT32 flags,
        PVOID sendArgs, UINT16 addressFamily,
        UINT32 compartmentId, PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectTransportReceiveAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        PVOID reserved, UINT32 flags,
        UINT16 addressFamily, UINT32 compartmentId,
        UINT32 interfaceIndex, UINT32 subInterfaceIndex,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectNetworkSendAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT32 flags, UINT32 compartmentId,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);
    typedef NTSTATUS(NTAPI* fn_FwpsInjectNetworkReceiveAsync0)(
        HANDLE injectionHandle, HANDLE injectionContext,
        UINT32 flags, UINT32 compartmentId,
        UINT32 interfaceIndex, UINT32 subInterfaceIndex,
        PVOID netBufferList,
        PVOID completionFn, PVOID completionContext);

    inline fn_FwpsInjectionHandleCreate0         _FwpsInjectionHandleCreate0   = nullptr;
    inline fn_FwpsInjectionHandleDestroy0        _FwpsInjectionHandleDestroy0  = nullptr;
    inline fn_FwpsQueryPacketInjectionState0     _FwpsQueryPacketInjectionState0 = nullptr;
    inline fn_NdisAllocateNetBufferListPool      _NdisAllocateNetBufferListPool = nullptr;
    inline fn_NdisFreeNetBufferListPool          _NdisFreeNetBufferListPool     = nullptr;
    inline fn_FwpsAllocateNetBufferAndNetBufferList0 _FwpsAllocateNBL0         = nullptr;
    inline fn_FwpsFreeNetBufferList0             _FwpsFreeNBL0                 = nullptr;
    inline fn_FwpsInjectTransportSendAsync0      _FwpsInjectSend0              = nullptr;
    inline fn_FwpsInjectTransportReceiveAsync0   _FwpsInjectRecv0              = nullptr;
    inline fn_FwpsInjectNetworkSendAsync0        _FwpsInjectNetSend0           = nullptr;
    inline fn_FwpsInjectNetworkReceiveAsync0     _FwpsInjectNetRecv0           = nullptr;

    inline HANDLE g_inject_handle_v4 = nullptr;
    inline HANDLE g_inject_handle_net_v4 = nullptr;
    inline NDIS_HANDLE g_inject_nbl_pool = nullptr;
    inline volatile LONG g_inject_resolved = 0;

    typedef struct _INJECT_COMPLETION_CONTEXT {
        PVOID buffer;
        PMDL mdl;
        FWPS_TRANSPORT_SEND_PARAMS0_COMPAT send_args;
        UINT8 remote_addr[16];
        UINT8 src_addr[16];
        UINT8 dst_addr[16];
        UINT32 direction;
        UINT32 protocol;
        UINT32 src_port;
        UINT32 dst_port;
        UINT32 packet_size;
        UINT32 path;
        UINT16 checksum;
        UINT64 start_tsc;
    } INJECT_COMPLETION_CONTEXT;

    typedef struct _DEFERRED_INJECT_CONTEXT {
        KDPC dpc;
        packet_inject_request request;
        inject_metadata metadata;
        BOOLEAN has_metadata;
    } DEFERRED_INJECT_CONTEXT;

    static __forceinline void write_be16(UINT8* dst, UINT16 value) {
        dst[0] = (UINT8)(value >> 8);
        dst[1] = (UINT8)(value & 0xFF);
    }

    static __forceinline void write_be32(UINT8* dst, UINT32 value) {
        dst[0] = (UINT8)(value >> 24);
        dst[1] = (UINT8)((value >> 16) & 0xFF);
        dst[2] = (UINT8)((value >> 8) & 0xFF);
        dst[3] = (UINT8)(value & 0xFF);
    }

    static UINT32 checksum_accumulate(UINT32 sum, const UINT8* data, UINT32 len) {
        if (!data) {
            return sum;
        }

        UINT32 i = 0;
        while (i + 1 < len) {
            sum += ((UINT32)data[i] << 8) | data[i + 1];
            i += 2;
        }

        if (i < len) {
            sum += ((UINT32)data[i] << 8);
        }

        return sum;
    }

    static UINT16 finalize_checksum(UINT32 sum) {
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFFu) + (sum >> 16);
        }
        return (UINT16)(~sum & 0xFFFFu);
    }

    static UINT16 transport_checksum_ipv4(const UINT8* src_addr,
                                          const UINT8* dst_addr,
                                          UINT8 protocol,
                                          const UINT8* segment,
                                          UINT32 segment_len) {
        UINT32 sum = 0;
        sum = checksum_accumulate(sum, src_addr, 4);
        sum = checksum_accumulate(sum, dst_addr, 4);
        sum += protocol;
        sum += (segment_len >> 16) & 0xFFFFu;
        sum += segment_len & 0xFFFFu;
        sum = checksum_accumulate(sum, segment, segment_len);
        return finalize_checksum(sum);
    }

    static __forceinline BOOLEAN is_loopback_ipv4_addr(const UINT8* addr) {
        return addr != nullptr && addr[0] == 127;
    }

    static UINT32 build_transport_packet(const packet_inject_request* request, UINT8* out_buf, UINT32 out_cap) {
        if (!request || !out_buf || out_cap == 0)
            return 0;

        if (request->tcp_flags & INJECT_FLAG_RAW_TRANSPORT) {
            if (request->payload_size > out_cap) return 0;
            strong::kmemcpy(out_buf, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                if (request->protocol == IPPROTO_TCP && request->payload_size >= 20) {
                    write_be16(out_buf + 16, 0);
                    UINT16 checksum = transport_checksum_ipv4(
                        request->src_addr, request->dst_addr,
                        IPPROTO_TCP, out_buf, request->payload_size);
                    write_be16(out_buf + 16, checksum);
                } else if (request->protocol == IPPROTO_UDP && request->payload_size >= 8) {
                    write_be16(out_buf + 6, 0);
                    UINT16 checksum = transport_checksum_ipv4(
                        request->src_addr, request->dst_addr,
                        IPPROTO_UDP, out_buf, request->payload_size);
                    if (checksum == 0) checksum = 0xFFFFu;
                    write_be16(out_buf + 6, checksum);
                }
            }
            return request->payload_size;
        }

        if (request->protocol == IPPROTO_UDP) {
            UINT32 total = request->payload_size + 8;
            if (total > out_cap) return 0;
            strong::kmemset(out_buf, 0, total);
            write_be16(out_buf, (UINT16)request->src_port);
            write_be16(out_buf + 2, (UINT16)request->dst_port);
            write_be16(out_buf + 4, (UINT16)total);
            strong::kmemcpy(out_buf + 8, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                UINT16 checksum = transport_checksum_ipv4(
                    request->src_addr,
                    request->dst_addr,
                    IPPROTO_UDP,
                    out_buf,
                    total);
                if (checksum == 0) {
                    checksum = 0xFFFFu;
                }
                write_be16(out_buf + 6, checksum);
            }
            return total;
        }

        if (request->protocol == IPPROTO_TCP) {
            UINT32 total = request->payload_size + 20;
            if (total > out_cap) return 0;
            strong::kmemset(out_buf, 0, total);
            write_be16(out_buf, (UINT16)request->src_port);
            write_be16(out_buf + 2, (UINT16)request->dst_port);
            write_be32(out_buf + 4, request->tcp_seq);
            write_be32(out_buf + 8, request->tcp_ack);
            out_buf[12] = 0x50;
            out_buf[13] = (UINT8)(request->tcp_flags & 0xFF);
            out_buf[14] = 0xFF;
            out_buf[15] = 0xFF;
            strong::kmemcpy(out_buf + 20, request->payload, request->payload_size);
            if (request->address_family == AF_INET) {
                UINT16 checksum = transport_checksum_ipv4(
                    request->src_addr,
                    request->dst_addr,
                    IPPROTO_TCP,
                    out_buf,
                    total);
                write_be16(out_buf + 16, checksum);
            }
            return total;
        }

        if (request->payload_size > out_cap) {
            return 0;
        }

        strong::kmemcpy(out_buf, request->payload, request->payload_size);
        return request->payload_size;
    }

    BOOLEAN resolve_inject_functions() {
        NET_DBG("resolve_inject_functions: enter");
        LONG state = _InterlockedCompareExchange(&g_inject_resolved, 0, 0);
        if (state == 2) {
            NET_DBG("resolve_inject_functions: already resolved, handle_v4=%p handle_net_v4=%p",
                    g_inject_handle_v4, g_inject_handle_net_v4);
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("resolve_inject_functions: blocked at IRQL=%u before first-time export resolution",
                    (UINT32)KeGetCurrentIrql());
            return FALSE;
        }
        if (state == 1) {
            for (UINT32 spin = 0; spin < 100000; spin++) {
                if (_InterlockedCompareExchange(&g_inject_resolved, 0, 0) != 1)
                    break;
                YieldProcessor();
            }
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }

        LONG prev = _InterlockedCompareExchange(&g_inject_resolved, 1, 0);
        if (prev == 2) {
            return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        }
        if (prev != 0) {
            return FALSE;
        }

        PVOID fwp_base = net_capture::find_module_base("FWPKCLNT.SYS");
        if (!fwp_base) fwp_base = net_capture::find_module_base("fwpkclnt.sys");
        if (!fwp_base) {
            NET_ERR("resolve_inject_functions: FWPKCLNT.SYS not found");
            _InterlockedExchange(&g_inject_resolved, 2);
            SD_KERNEL_RESOLVER_LOG_PTR("WFP.injection.exports", "export_table", nullptr, FALSE,
                "FWPKCLNT.SYS not found before injection export resolution", "fwpkclnt_module_not_found");
            return FALSE;
        }
        NET_DBG("resolve_inject_functions: FWPKCLNT.SYS base=%p", fwp_base);

        CHAR f1[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','C','r','e','a','t','e','0',0};
        CHAR f2[] = {'F','w','p','s','I','n','j','e','c','t','i','o','n','H','a','n','d','l','e','D','e','s','t','r','o','y','0',0};
        CHAR f3[] = {'F','w','p','s','A','l','l','o','c','a','t','e','N','e','t','B','u','f','f','e','r','A','n','d','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f4[] = {'F','w','p','s','F','r','e','e','N','e','t','B','u','f','f','e','r','L','i','s','t','0',0};
        CHAR f5[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f6[] = {'F','w','p','s','I','n','j','e','c','t','T','r','a','n','s','p','o','r','t','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
        CHAR f7[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','S','e','n','d','A','s','y','n','c','0',0};
        CHAR f8[] = {'F','w','p','s','I','n','j','e','c','t','N','e','t','w','o','r','k','R','e','c','e','i','v','e','A','s','y','n','c','0',0};
        CHAR f9[] = {'F','w','p','s','Q','u','e','r','y','P','a','c','k','e','t','I','n','j','e','c','t','i','o','n','S','t','a','t','e','0',0};
        CHAR n1[] = {'N','d','i','s','A','l','l','o','c','a','t','e','N','e','t','B','u','f','f','e','r','L','i','s','t','P','o','o','l',0};
        CHAR n2[] = {'N','d','i','s','F','r','e','e','N','e','t','B','u','f','f','e','r','L','i','s','t','P','o','o','l',0};

        PVOID ndis_base = net_capture::find_module_base("NDIS.SYS");
        if (!ndis_base) ndis_base = net_capture::find_module_base("ndis.sys");

        *(PVOID*)&_FwpsInjectionHandleCreate0 = GetProcAddress(fwp_base, f1);
        *(PVOID*)&_FwpsInjectionHandleDestroy0 = GetProcAddress(fwp_base, f2);
        *(PVOID*)&_FwpsAllocateNBL0 = GetProcAddress(fwp_base, f3);
        *(PVOID*)&_FwpsFreeNBL0 = GetProcAddress(fwp_base, f4);
        *(PVOID*)&_FwpsInjectSend0 = GetProcAddress(fwp_base, f5);
        *(PVOID*)&_FwpsInjectRecv0 = GetProcAddress(fwp_base, f6);
        *(PVOID*)&_FwpsInjectNetSend0 = GetProcAddress(fwp_base, f7);
        *(PVOID*)&_FwpsInjectNetRecv0 = GetProcAddress(fwp_base, f8);
        *(PVOID*)&_FwpsQueryPacketInjectionState0 = GetProcAddress(fwp_base, f9);
        if (ndis_base) {
            *(PVOID*)&_NdisAllocateNetBufferListPool = GetProcAddress(ndis_base, n1);
            *(PVOID*)&_NdisFreeNetBufferListPool = GetProcAddress(ndis_base, n2);
        }

        NTSTATUS transport_handle_status = STATUS_PROCEDURE_NOT_FOUND;
        NTSTATUS network_handle_status = STATUS_PROCEDURE_NOT_FOUND;
        if (_FwpsInjectionHandleCreate0) {
            transport_handle_status = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_TRANSPORT, &g_inject_handle_v4);
            NET_DBG("resolve_inject_functions: transport inject handle create st=0x%08x handle=%p", transport_handle_status, g_inject_handle_v4);
            if (!NT_SUCCESS(transport_handle_status)) g_inject_handle_v4 = nullptr;

            network_handle_status = _FwpsInjectionHandleCreate0(AF_INET, FWPS_INJECTION_TYPE_NETWORK, &g_inject_handle_net_v4);
            NET_DBG("resolve_inject_functions: network inject handle create st=0x%08x handle=%p", network_handle_status, g_inject_handle_net_v4);
            if (!NT_SUCCESS(network_handle_status)) g_inject_handle_net_v4 = nullptr;
        } else {
            NET_ERR("resolve_inject_functions: FwpsInjectionHandleCreate0 not found");
        }

        NET_DBG("resolve_inject_functions: InjectSend=%p InjectRecv=%p NetSend=%p NetRecv=%p NBLPool=%p",
                _FwpsInjectSend0, _FwpsInjectRecv0, _FwpsInjectNetSend0, _FwpsInjectNetRecv0,
                _NdisAllocateNetBufferListPool);
        KeMemoryBarrier();
        _InterlockedExchange(&g_inject_resolved, 2);
        ULONG missing_mask = 0;
        if (!_FwpsInjectionHandleCreate0) missing_mask |= 0x0001u;
        if (!_FwpsInjectionHandleDestroy0) missing_mask |= 0x0002u;
        if (!_FwpsAllocateNBL0) missing_mask |= 0x0004u;
        if (!_FwpsFreeNBL0) missing_mask |= 0x0008u;
        if (!_FwpsInjectSend0) missing_mask |= 0x0010u;
        if (!_FwpsInjectRecv0) missing_mask |= 0x0020u;
        if (!_FwpsInjectNetSend0) missing_mask |= 0x0040u;
        if (!_FwpsInjectNetRecv0) missing_mask |= 0x0080u;
        if (!_FwpsQueryPacketInjectionState0) missing_mask |= 0x0100u;
        if (!_NdisAllocateNetBufferListPool) missing_mask |= 0x0200u;
        if (!_NdisFreeNetBufferListPool) missing_mask |= 0x0400u;
        BOOLEAN valid = (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
        SD_LOG("KVALIDATE build=%lu kind=resolver name=WFP.injection.exports source=export_table value=%p validation=%s evidence=\"fwpkclnt=%p ndis=%p missing_mask=0x%04lX transport_status=0x%08X network_status=0x%08X handles=%p/%p nbl_pool_fns=%p/%p query_state=%p\" fail_closed=%s",
            sd_kernel_validation_build(),
            _FwpsInjectionHandleCreate0,
            sd_kernel_validation_state(valid),
            fwp_base,
            ndis_base,
            missing_mask,
            transport_handle_status,
            network_handle_status,
            g_inject_handle_v4,
            g_inject_handle_net_v4,
            _NdisAllocateNetBufferListPool,
            _NdisFreeNetBufferListPool,
            _FwpsQueryPacketInjectionState0,
            valid ? "none" : "no_injection_handle");
        return (g_inject_handle_v4 != nullptr) || (g_inject_handle_net_v4 != nullptr);
    }

    void NTAPI inject_completion(PVOID context, PVOID nbl, BOOLEAN dispatch_level) {
        INJECT_COMPLETION_CONTEXT* completion = (INJECT_COMPLETION_CONTEXT*)context;
        UINT32 nbl_status = 0;
        if (nbl) {
            __try {
                nbl_status = (UINT32)NET_BUFFER_LIST_STATUS((PNET_BUFFER_LIST)nbl);
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                nbl_status = (UINT32)STATUS_ACCESS_VIOLATION;
            }
        }
        if (completion) {
            UINT64 elapsed = completion->start_tsc != 0 ? (__rdtsc() - completion->start_tsc) : 0;
            SD_LOG("net_inject::completion path=%u direction=%u protocol=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u packet_size=%u checksum=0x%04X nbl_status=0x%08X win32=%lu dispatch_level=%u elapsed_tsc=%llu irql=%u cpu=%lu",
                completion->path,
                completion->direction,
                completion->protocol,
                completion->src_addr[0], completion->src_addr[1], completion->src_addr[2], completion->src_addr[3], completion->src_port,
                completion->dst_addr[0], completion->dst_addr[1], completion->dst_addr[2], completion->dst_addr[3], completion->dst_port,
                completion->packet_size,
                completion->checksum,
                nbl_status,
                net_capture::status_to_win32((NTSTATUS)nbl_status),
                dispatch_level ? 1u : 0u,
                (unsigned long long)elapsed,
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
        }
        if (nbl && _FwpsFreeNBL0) _FwpsFreeNBL0(nbl);
        if (completion) {
            if (completion->mdl) IoFreeMdl(completion->mdl);
            if (completion->buffer) ExFreePoolWithTag(completion->buffer, 'jiNW');
            ExFreePoolWithTag(completion, 'jcNW');
        }
    }

    static BOOLEAN ensure_inject_nbl_pool() {
        if (g_inject_nbl_pool) {
            return TRUE;
        }

        NET_BUFFER_LIST_POOL_PARAMETERS params = {};
        params.Header.Type = NDIS_OBJECT_TYPE_DEFAULT;
        params.Header.Revision = NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.Header.Size = NDIS_SIZEOF_NET_BUFFER_LIST_POOL_PARAMETERS_REVISION_1;
        params.ProtocolId = 0;
        params.fAllocateNetBuffer = TRUE;
        params.ContextSize = 0;
        params.PoolTag = 'jnNW';
        params.DataSize = 0;

        if (!_NdisAllocateNetBufferListPool || !_NdisFreeNetBufferListPool) {
            SD_KERNEL_RESOLVER_LOG_PTR("WFP.injection.nbl_pool", "ndis_runtime", nullptr, FALSE,
                "NDIS NBL pool allocation/free exports missing", "ndis_pool_exports_missing");
            return FALSE;
        }

        g_inject_nbl_pool = _NdisAllocateNetBufferListPool(nullptr, &params);
        if (!g_inject_nbl_pool) {
            SD_KERNEL_RESOLVER_LOG_PTR("WFP.injection.nbl_pool", "ndis_runtime", nullptr, FALSE,
                "NdisAllocateNetBufferListPool returned null for SLOP injection pool", "pool_allocation_failed");
            return FALSE;
        }

        SD_KERNEL_RESOLVER_LOG_PTR("WFP.injection.nbl_pool", "ndis_runtime", g_inject_nbl_pool, TRUE,
            "NET_BUFFER_LIST_POOL_PARAMETERS revision=1 fAllocateNetBuffer=1 pool_tag=jnNW", "none");
        return TRUE;
    }

    BOOLEAN prepare_injection_runtime() {
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("prepare_injection_runtime: blocked at IRQL=%u", (UINT32)KeGetCurrentIrql());
            return FALSE;
        }
        if (!resolve_inject_functions()) {
            return FALSE;
        }
        return ensure_inject_nbl_pool();
    }

    static UINT64 lookup_endpoint_handle_by_port(UINT32 protocol, UINT32 src_port) {
        slop_ensure_endpoint_pid_cache_init();
        KIRQL old_irql;
        KeAcquireSpinLock(&g_endpoint_pid_cache_lock, &old_irql);
        for (UINT32 i = 0; i < SLOP_ENDPOINT_PID_CACHE_SIZE; i++) {
            const SLOP_ENDPOINT_PID_CACHE_ENTRY* entry = &g_endpoint_pid_cache[i];
            if (!entry->active) continue;
            if (protocol != 0 && entry->protocol != 0 && entry->protocol != protocol) continue;
            if (src_port != 0 && entry->local_port != 0 && entry->local_port != src_port) continue;
            UINT64 handle = entry->endpoint_handle;
            KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
            return handle;
        }
        KeReleaseSpinLock(&g_endpoint_pid_cache_lock, old_irql);
        return 0;
    }

#pragma pack(push, 1)
    typedef struct _IPV4_HEADER {
        UINT8  ver_ihl;
        UINT8  tos;
        UINT16 total_length;
        UINT16 identification;
        UINT16 flags_fragoffset;
        UINT8  ttl;
        UINT8  protocol;
        UINT16 checksum;
        UINT8  src_addr[4];
        UINT8  dst_addr[4];
    } IPV4_HEADER;
#pragma pack(pop)

    static UINT16 ip_checksum(const UINT8* data, UINT32 len) {
        UINT32 sum = 0;
        for (UINT32 i = 0; i + 1 < len; i += 2)
            sum += (UINT16)((data[i] << 8) | data[i + 1]);
        if (len & 1)
            sum += (UINT16)(data[len - 1] << 8);
        while (sum >> 16)
            sum = (sum & 0xFFFF) + (sum >> 16);
        return (UINT16)(~sum & 0xFFFF);
    }

    static UINT32 build_ip_wrapped_packet(const p_packet_inject_request request,
                                          const UINT8* transport_data, UINT32 transport_len,
                                          UINT8* out_buf, UINT32 out_cap) {
        UINT32 total_len = sizeof(IPV4_HEADER) + transport_len;
        if (total_len > out_cap) return 0;

        IPV4_HEADER* ip = (IPV4_HEADER*)out_buf;
        strong::kmemset(ip, 0, sizeof(IPV4_HEADER));
        ip->ver_ihl = 0x45;
        ip->tos = 0;
        ip->total_length = _byteswap_ushort((UINT16)total_len);
        ip->identification = _byteswap_ushort((UINT16)(KeQueryTimeIncrement() & 0xFFFF));
        ip->flags_fragoffset = 0;
        ip->ttl = 128;
        ip->protocol = (UINT8)request->protocol;
        ip->checksum = 0;
        strong::kmemcpy(ip->src_addr, request->src_addr, 4);
        strong::kmemcpy(ip->dst_addr, request->dst_addr, 4);

        ip->checksum = _byteswap_ushort(ip_checksum((const UINT8*)ip, sizeof(IPV4_HEADER)));

        strong::kmemcpy(out_buf + sizeof(IPV4_HEADER), transport_data, transport_len);
        return total_len;
    }

    static NTSTATUS inject_packet_now(p_packet_inject_request request, const inject_metadata* metadata) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->status = 1;

        NET_DBG("inject_packet: dir=%u proto=%u af=%u src_port=%u dst_port=%u payload=%u",
                request->direction, request->protocol, request->address_family,
                request->src_port, request->dst_port, request->payload_size);
        NET_DBG("inject_packet: src=%u.%u.%u.%u dst=%u.%u.%u.%u",
                request->src_addr[0], request->src_addr[1], request->src_addr[2], request->src_addr[3],
                request->dst_addr[0], request->dst_addr[1], request->dst_addr[2], request->dst_addr[3]);
        SD_LOG_PACKET("net_inject::packet ENTER direction=%u protocol=%u af=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u payload=%u flags=0x%08X irql=%u",
            request->direction,
            request->protocol,
            request->address_family,
            request->src_addr[0], request->src_addr[1], request->src_addr[2], request->src_addr[3], request->src_port,
            request->dst_addr[0], request->dst_addr[1], request->dst_addr[2], request->dst_addr[3], request->dst_port,
            request->payload_size,
            request->tcp_flags,
            (UINT32)KeGetCurrentIrql());

        if (!resolve_inject_functions()) {
            NET_ERR("inject_packet: resolve_inject_functions FAILED");
            SD_LOG_PACKET("net_inject::packet ABORT step=resolve_functions status=0x%08X win32=%lu",
                STATUS_NOT_SUPPORTED,
                net_capture::status_to_win32(STATUS_NOT_SUPPORTED));
            return STATUS_NOT_SUPPORTED;
        }

        if (!g_inject_nbl_pool && KeGetCurrentIrql() != PASSIVE_LEVEL) {
            NET_ERR("inject_packet: NBL pool unavailable at IRQL=%u; injection runtime was not prewarmed",
                    (UINT32)KeGetCurrentIrql());
            SD_LOG_PACKET("net_inject::packet ABORT step=nbl_pool_unavailable_irql irql=%u status=0x%08X win32=%lu",
                (UINT32)KeGetCurrentIrql(),
                STATUS_INSUFFICIENT_RESOURCES,
                net_capture::status_to_win32(STATUS_INSUFFICIENT_RESOURCES));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        if (!ensure_inject_nbl_pool()) {
            NET_ERR("inject_packet: ensure_inject_nbl_pool FAILED");
            SD_LOG_PACKET("net_inject::packet ABORT step=ensure_nbl_pool status=0x%08X win32=%lu",
                STATUS_INSUFFICIENT_RESOURCES,
                net_capture::status_to_win32(STATUS_INSUFFICIENT_RESOURCES));
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        BOOLEAN have_transport = (g_inject_handle_v4 != nullptr && _FwpsInjectSend0 && _FwpsInjectRecv0);
        BOOLEAN have_network = (g_inject_handle_net_v4 != nullptr && (_FwpsInjectNetSend0 || _FwpsInjectNetRecv0));
        NET_DBG("inject_packet: have_transport=%d have_network=%d handle_v4=%p handle_net_v4=%p",
                (int)have_transport, (int)have_network, g_inject_handle_v4, g_inject_handle_net_v4);
        if (!have_transport && !have_network) {
            SD_LOG_PACKET("net_inject::packet ABORT step=no_inject_path have_transport=0 have_network=0 status=0x%08X win32=%lu",
                STATUS_NOT_SUPPORTED,
                net_capture::status_to_win32(STATUS_NOT_SUPPORTED));
            return STATUS_NOT_SUPPORTED;
        }

        if (request->payload_size > INJECT_MAX_PAYLOAD) {
            SD_LOG_PACKET("net_inject::packet ABORT step=payload_too_large payload=%u max=%u status=0x%08X win32=%lu",
                request->payload_size,
                INJECT_MAX_PAYLOAD,
                STATUS_INVALID_PARAMETER,
                net_capture::status_to_win32(STATUS_INVALID_PARAMETER));
            return STATUS_INVALID_PARAMETER;
        }
        if (request->payload_size == 0 &&
            request->protocol != IPPROTO_TCP && request->protocol != IPPROTO_UDP) {
            SD_LOG_PACKET("net_inject::packet ABORT step=empty_payload_bad_protocol protocol=%u status=0x%08X win32=%lu",
                request->protocol,
                STATUS_INVALID_PARAMETER,
                net_capture::status_to_win32(STATUS_INVALID_PARAMETER));
            return STATUS_INVALID_PARAMETER;
        }

        UINT8 packet_buf[INJECT_MAX_PAYLOAD + 32] = {};
        UINT32 packet_size = build_transport_packet(request, packet_buf, sizeof(packet_buf));
        if (packet_size == 0) {
            NET_ERR("inject_packet: build_transport_packet returned 0");
            SD_LOG_PACKET("net_inject::packet ABORT step=build_transport_packet payload=%u flags=0x%08X status=0x%08X win32=%lu",
                request->payload_size,
                request->tcp_flags,
                STATUS_INVALID_PARAMETER,
                net_capture::status_to_win32(STATUS_INVALID_PARAMETER));
            return STATUS_INVALID_PARAMETER;
        }
        UINT16 transport_checksum_value = 0;
        if (request->protocol == IPPROTO_TCP && packet_size >= 18) {
            transport_checksum_value = ((UINT16)packet_buf[16] << 8) | packet_buf[17];
        } else if (request->protocol == IPPROTO_UDP && packet_size >= 8) {
            transport_checksum_value = ((UINT16)packet_buf[6] << 8) | packet_buf[7];
        }

        BOOLEAN loopback_v4 =
            request->address_family == AF_INET &&
            is_loopback_ipv4_addr(request->src_addr) &&
            is_loopback_ipv4_addr(request->dst_addr);
        UINT32 recv_interface_index = loopback_v4 ? 1u : 0u;
        UINT32 recv_sub_interface_index = 0;
        UINT32 compartment_id = 0;
        UINT32 remote_scope_id = 0;
        if (metadata) {
            if (metadata->interface_index != 0) {
                recv_interface_index = metadata->interface_index;
            }
            recv_sub_interface_index = metadata->sub_interface_index;
            compartment_id = metadata->compartment_id;
            remote_scope_id = metadata->remote_scope_id;
        }

        UINT64 endpoint_handle = (metadata && metadata->endpoint_handle != 0)
            ? metadata->endpoint_handle
            : lookup_endpoint_handle_by_port(request->protocol, request->src_port);
        NET_DBG("inject_packet: packet_size=%u loopback=%d endpoint_handle=0x%llx",
                packet_size, (int)loopback_v4, endpoint_handle);
        SD_LOG_PACKET("net_inject::packet prepared transport_size=%u checksum=0x%04X checksum_recompute=%u loopback=%u recv_if=%u recv_sub_if=%u endpoint=0x%llX compartment=%u scope=%u have_transport=%u have_network=%u",
            packet_size,
            transport_checksum_value,
            request->protocol == IPPROTO_TCP || request->protocol == IPPROTO_UDP ? 1u : 0u,
            loopback_v4 ? 1u : 0u,
            recv_interface_index,
            recv_sub_interface_index,
            (unsigned long long)endpoint_handle,
            compartment_id,
            remote_scope_id,
            have_transport ? 1u : 0u,
            have_network ? 1u : 0u);

        NTSTATUS st = STATUS_UNSUCCESSFUL;
        BOOLEAN transport_attempted = FALSE;

        if (have_transport && (endpoint_handle != 0 || !have_network)) {
            PVOID buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, packet_size, 'jiNW');
            if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
            strong::kmemcpy(buf, packet_buf, packet_size);

            INJECT_COMPLETION_CONTEXT* completion = (INJECT_COMPLETION_CONTEXT*)
                ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_COMPLETION_CONTEXT), 'jcNW');
            if (!completion) {
                ExFreePoolWithTag(buf, 'jiNW');
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            strong::kmemset(completion, 0, sizeof(*completion));
            completion->buffer = buf;
            completion->direction = request->direction;
            completion->protocol = request->protocol;
            completion->src_port = request->src_port;
            completion->dst_port = request->dst_port;
            completion->packet_size = packet_size;
            completion->path = 1;
            completion->checksum = transport_checksum_value;
            completion->start_tsc = __rdtsc();
            strong::kmemcpy(completion->src_addr, request->src_addr, 16);
            strong::kmemcpy(completion->dst_addr, request->dst_addr, 16);
            UINT32 remote_addr_len = request->address_family == AF_INET6 ? 16u : 4u;
            strong::kmemcpy(completion->remote_addr, request->dst_addr, remote_addr_len);
            completion->send_args.remoteAddress = completion->remote_addr;
            completion->send_args.remoteScopeId = remote_scope_id;
            completion->send_args.controlData = nullptr;
            completion->send_args.controlDataLength = 0;

            PMDL mdl = IoAllocateMdl(buf, packet_size, FALSE, FALSE, nullptr);
            if (!mdl) {
                ExFreePoolWithTag(completion, 'jcNW');
                ExFreePoolWithTag(buf, 'jiNW');
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            completion->mdl = mdl;
            MmBuildMdlForNonPagedPool(mdl);

            PVOID nbl = nullptr;
            st = _FwpsAllocateNBL0(g_inject_nbl_pool, 0, 0, mdl, 0, packet_size, &nbl);
            if (!NT_SUCCESS(st) || !nbl) {
                IoFreeMdl(mdl);
                ExFreePoolWithTag(completion, 'jcNW');
                ExFreePoolWithTag(buf, 'jiNW');
                return st;
            }

            transport_attempted = TRUE;
            NET_DBG("inject_packet: trying transport path, dir=%u", request->direction);
            SD_LOG_PACKET("net_inject::packet transport_attempt direction=%u endpoint=0x%llX packet_size=%u loopback=%u recv_if=%u",
                request->direction,
                (unsigned long long)endpoint_handle,
                packet_size,
                loopback_v4 ? 1u : 0u,
                recv_interface_index);

            if (request->direction == 1) {
                if (loopback_v4 && _FwpsInjectRecv0) {
                    SD_LOG("net_inject::loopback_redirect_recv_preferred direction=1 endpoint=0x%llX loopback=1 recv_if=%u packet_size=%u",
                        (unsigned long long)endpoint_handle,
                        recv_interface_index,
                        packet_size);
                    st = _FwpsInjectRecv0(g_inject_handle_v4, nullptr, nullptr, 0,
                        (UINT16)request->address_family, compartment_id, recv_interface_index, recv_sub_interface_index, nbl,
                        (PVOID)inject_completion, completion);
                    SD_LOG_PACKET("net_inject::packet transport_recv_preferred status=0x%08X win32=%lu recv_if=%u packet_size=%u",
                        st,
                        net_capture::status_to_win32(st),
                        recv_interface_index,
                        packet_size);
                    if (NT_SUCCESS(st)) {
                        NET_DBG("inject_packet: loopback recv inject SUCCESS st=0x%08x", st);
                        SD_LOG_PACKET("net_inject::packet SUCCESS path=transport_loopback_recv status=0x%08X win32=%lu packet_size=%u",
                            st,
                            net_capture::status_to_win32(st),
                            packet_size);
                        request->status = 0;
                        return STATUS_SUCCESS;
                    }
                    SD_LOG("net_inject::loopback_redirect_recv_failed status=0x%08X win32=%lu fallback_to_send=1 endpoint=0x%llX packet_size=%u",
                        st,
                        net_capture::status_to_win32(st),
                        (unsigned long long)endpoint_handle,
                        packet_size);
                }
                st = _FwpsInjectSend0(g_inject_handle_v4, nullptr, endpoint_handle, 0,
                    &completion->send_args, (UINT16)request->address_family, compartment_id, nbl,
                    (PVOID)inject_completion, completion);
                SD_LOG_PACKET("net_inject::packet transport_send status=0x%08X win32=%lu endpoint=0x%llX packet_size=%u",
                    st,
                    net_capture::status_to_win32(st),
                    (unsigned long long)endpoint_handle,
                    packet_size);
            } else {
                st = _FwpsInjectRecv0(g_inject_handle_v4, nullptr, nullptr, 0,
                    (UINT16)request->address_family, compartment_id, recv_interface_index, recv_sub_interface_index, nbl,
                    (PVOID)inject_completion, completion);
                SD_LOG_PACKET("net_inject::packet transport_recv status=0x%08X win32=%lu recv_if=%u packet_size=%u",
                    st,
                    net_capture::status_to_win32(st),
                    recv_interface_index,
                    packet_size);

                if (!NT_SUCCESS(st) && _FwpsInjectSend0 && loopback_v4) {
                    st = _FwpsInjectSend0(g_inject_handle_v4, nullptr, endpoint_handle, 0,
                        &completion->send_args, (UINT16)request->address_family, compartment_id, nbl,
                        (PVOID)inject_completion, completion);
                    SD_LOG_PACKET("net_inject::packet transport_send_fallback status=0x%08X win32=%lu endpoint=0x%llX packet_size=%u",
                        st,
                        net_capture::status_to_win32(st),
                        (unsigned long long)endpoint_handle,
                        packet_size);
                }
            }

            if (NT_SUCCESS(st)) {
                NET_DBG("inject_packet: transport inject SUCCESS st=0x%08x", st);
                SD_LOG_PACKET("net_inject::packet SUCCESS path=transport status=0x%08X win32=%lu packet_size=%u",
                    st,
                    net_capture::status_to_win32(st),
                    packet_size);
                request->status = 0;
                return STATUS_SUCCESS;
            }

            NET_ERR("inject_packet: transport inject FAILED 0x%08x", st);
            SD_LOG_PACKET("net_inject::packet transport_failed status=0x%08X win32=%lu fallback_network=%u",
                st,
                net_capture::status_to_win32(st),
                have_network ? 1u : 0u);
            _FwpsFreeNBL0(nbl);
            IoFreeMdl(mdl);
            ExFreePoolWithTag(completion, 'jcNW');
            ExFreePoolWithTag(buf, 'jiNW');
        }

        if (!have_network) {
            NET_ERR("inject_packet: no network inject path available, returning 0x%08x", st);
            SD_LOG_PACKET("net_inject::packet ABORT step=no_network_after_transport status=0x%08X win32=%lu transport_attempted=%u",
                st,
                net_capture::status_to_win32(st),
                transport_attempted ? 1u : 0u);
            return st;
        }

        UINT8 ip_packet_buf[INJECT_MAX_PAYLOAD + 64] = {};
        UINT32 ip_packet_size = build_ip_wrapped_packet(request, packet_buf, packet_size,
            ip_packet_buf, sizeof(ip_packet_buf));
        if (ip_packet_size == 0) {
            SD_LOG_PACKET("net_inject::packet ABORT step=build_ip_wrapped_packet transport_size=%u status=0x%08X win32=%lu",
                packet_size,
                STATUS_INVALID_PARAMETER,
                net_capture::status_to_win32(STATUS_INVALID_PARAMETER));
            return STATUS_INVALID_PARAMETER;
        }

        PVOID net_buf = ExAllocatePool2(POOL_FLAG_NON_PAGED, ip_packet_size, 'jiNW');
        if (!net_buf) return STATUS_INSUFFICIENT_RESOURCES;
        strong::kmemcpy(net_buf, ip_packet_buf, ip_packet_size);

        INJECT_COMPLETION_CONTEXT* net_completion = (INJECT_COMPLETION_CONTEXT*)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(INJECT_COMPLETION_CONTEXT), 'jcNW');
        if (!net_completion) {
            ExFreePoolWithTag(net_buf, 'jiNW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        strong::kmemset(net_completion, 0, sizeof(*net_completion));
        net_completion->buffer = net_buf;
        net_completion->direction = request->direction;
        net_completion->protocol = request->protocol;
        net_completion->src_port = request->src_port;
        net_completion->dst_port = request->dst_port;
        net_completion->packet_size = ip_packet_size;
        net_completion->path = 2;
        net_completion->checksum = transport_checksum_value;
        net_completion->start_tsc = __rdtsc();
        strong::kmemcpy(net_completion->src_addr, request->src_addr, 16);
        strong::kmemcpy(net_completion->dst_addr, request->dst_addr, 16);

        PMDL net_mdl = IoAllocateMdl(net_buf, ip_packet_size, FALSE, FALSE, nullptr);
        if (!net_mdl) {
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        net_completion->mdl = net_mdl;
        MmBuildMdlForNonPagedPool(net_mdl);

        PVOID net_nbl = nullptr;
        st = _FwpsAllocateNBL0(g_inject_nbl_pool, 0, 0, net_mdl, 0, ip_packet_size, &net_nbl);
        if (!NT_SUCCESS(st) || !net_nbl) {
            IoFreeMdl(net_mdl);
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return st;
        }

        if (request->direction == 1 && _FwpsInjectNetSend0) {
            NET_DBG("inject_packet: trying network send path ip_size=%u", ip_packet_size);
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, compartment_id,
                net_nbl, (PVOID)inject_completion, net_completion);
            SD_LOG_PACKET("net_inject::packet network_send status=0x%08X win32=%lu ip_size=%u compartment=%u",
                st,
                net_capture::status_to_win32(st),
                ip_packet_size,
                compartment_id);
        } else if (_FwpsInjectNetRecv0) {
            NET_DBG("inject_packet: trying network recv path ip_size=%u if_idx=%u", ip_packet_size, recv_interface_index);
            st = _FwpsInjectNetRecv0(g_inject_handle_net_v4, nullptr, 0, compartment_id,
                recv_interface_index, recv_sub_interface_index, net_nbl,
                (PVOID)inject_completion, net_completion);
            SD_LOG_PACKET("net_inject::packet network_recv status=0x%08X win32=%lu ip_size=%u recv_if=%u recv_sub_if=%u compartment=%u",
                st,
                net_capture::status_to_win32(st),
                ip_packet_size,
                recv_interface_index,
                recv_sub_interface_index,
                compartment_id);
        } else if (_FwpsInjectNetSend0) {
            NET_DBG("inject_packet: fallback network send path");
            st = _FwpsInjectNetSend0(g_inject_handle_net_v4, nullptr, 0, compartment_id,
                net_nbl, (PVOID)inject_completion, net_completion);
            SD_LOG_PACKET("net_inject::packet network_send_fallback status=0x%08X win32=%lu ip_size=%u compartment=%u",
                st,
                net_capture::status_to_win32(st),
                ip_packet_size,
                compartment_id);
        } else {
            st = STATUS_NOT_SUPPORTED;
            SD_LOG_PACKET("net_inject::packet network_no_callable status=0x%08X win32=%lu ip_size=%u",
                st,
                net_capture::status_to_win32(st),
                ip_packet_size);
        }

        if (!NT_SUCCESS(st)) {
            NET_ERR("inject_packet: network inject FAILED 0x%08x", st);
            SD_LOG_PACKET("net_inject::packet FAILED path=network status=0x%08X win32=%lu ip_size=%u transport_attempted=%u",
                st,
                net_capture::status_to_win32(st),
                ip_packet_size,
                transport_attempted ? 1u : 0u);
            _FwpsFreeNBL0(net_nbl);
            IoFreeMdl(net_mdl);
            ExFreePoolWithTag(net_completion, 'jcNW');
            ExFreePoolWithTag(net_buf, 'jiNW');
            return st;
        }

        NET_DBG("inject_packet: network inject SUCCESS");
        SD_LOG_PACKET("net_inject::packet SUCCESS path=network status=0x%08X win32=%lu ip_size=%u transport_attempted=%u",
            st,
            net_capture::status_to_win32(st),
            ip_packet_size,
            transport_attempted ? 1u : 0u);
        request->status = 0;
        return STATUS_SUCCESS;
    }

    static VOID NTAPI inject_dpc(PKDPC dpc, PVOID deferred_context, PVOID system_argument1, PVOID system_argument2) {
        UNREFERENCED_PARAMETER(dpc);
        UNREFERENCED_PARAMETER(system_argument1);
        UNREFERENCED_PARAMETER(system_argument2);
        DEFERRED_INJECT_CONTEXT* ctx = (DEFERRED_INJECT_CONTEXT*)deferred_context;
        if (!ctx) {
            return;
        }
        UINT64 start_tsc = __rdtsc();
        const inject_metadata* metadata = ctx->has_metadata ? &ctx->metadata : nullptr;
        NTSTATUS st = inject_packet_now(&ctx->request, metadata);
        SD_LOG("net_inject::dpc EXIT status=0x%08X win32=%lu request_status=%u direction=%u protocol=%u endpoint=0x%llX compartment=%u elapsed_tsc=%llu irql=%u cpu=%lu",
            st,
            net_capture::status_to_win32(st),
            ctx->request.status,
            ctx->request.direction,
            ctx->request.protocol,
            metadata ? (unsigned long long)metadata->endpoint_handle : 0ull,
            metadata ? metadata->compartment_id : 0u,
            (unsigned long long)(__rdtsc() - start_tsc),
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());
        ExFreePoolWithTag(ctx, 'qdNW');
    }

    static NTSTATUS queue_tcp_transport_injection(p_packet_inject_request request, const inject_metadata* metadata) {
        if (!request) {
            return STATUS_INVALID_PARAMETER;
        }
        if ((!g_inject_nbl_pool || (!g_inject_handle_v4 && !g_inject_handle_net_v4)) &&
            KeGetCurrentIrql() == PASSIVE_LEVEL) {
            prepare_injection_runtime();
        }
        if (!g_inject_nbl_pool) {
            request->status = 1;
            SD_LOG_PACKET("net_inject::queue_tcp ABORT reason=nbl_pool_missing direction=%u protocol=%u irql=%u status=0x%08X",
                request->direction,
                request->protocol,
                (UINT32)KeGetCurrentIrql(),
                STATUS_INSUFFICIENT_RESOURCES);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        if (!g_inject_handle_v4 && !g_inject_handle_net_v4) {
            request->status = 1;
            SD_LOG_PACKET("net_inject::queue_tcp ABORT reason=no_inject_handle direction=%u protocol=%u irql=%u status=0x%08X",
                request->direction,
                request->protocol,
                (UINT32)KeGetCurrentIrql(),
                STATUS_NOT_SUPPORTED);
            return STATUS_NOT_SUPPORTED;
        }

        DEFERRED_INJECT_CONTEXT* ctx = (DEFERRED_INJECT_CONTEXT*)
            ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(DEFERRED_INJECT_CONTEXT), 'qdNW');
        if (!ctx) {
            request->status = 1;
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        strong::kmemset(ctx, 0, sizeof(*ctx));
        strong::kmemcpy(&ctx->request, request, sizeof(ctx->request));
        if (metadata) {
            strong::kmemcpy(&ctx->metadata, metadata, sizeof(ctx->metadata));
            ctx->has_metadata = TRUE;
        }

        KeInitializeDpc(&ctx->dpc, inject_dpc, ctx);
        BOOLEAN queued = KeInsertQueueDpc(&ctx->dpc, nullptr, nullptr);
        if (!queued) {
            ExFreePoolWithTag(ctx, 'qdNW');
            request->status = 1;
            SD_LOG_PACKET("net_inject::queue_tcp ABORT reason=dpc_queue_rejected direction=%u protocol=%u endpoint=0x%llX compartment=%u irql=%u status=0x%08X",
                request->direction,
                request->protocol,
                metadata ? (unsigned long long)metadata->endpoint_handle : 0ull,
                metadata ? metadata->compartment_id : 0u,
                (UINT32)KeGetCurrentIrql(),
                STATUS_UNSUCCESSFUL);
            return STATUS_UNSUCCESSFUL;
        }

        request->status = 0;
        SD_LOG_PACKET("net_inject::queue_tcp QUEUED direction=%u protocol=%u payload=%u flags=0x%08X endpoint=0x%llX compartment=%u irql=%u cpu=%lu",
            request->direction,
            request->protocol,
            request->payload_size,
            request->tcp_flags,
            metadata ? (unsigned long long)metadata->endpoint_handle : 0ull,
            metadata ? metadata->compartment_id : 0u,
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());
        return STATUS_SUCCESS;
    }

    NTSTATUS inject_packet(p_packet_inject_request request, const inject_metadata* metadata) {
        if (!request) {
            return STATUS_INVALID_PARAMETER;
        }
        if (request->protocol == IPPROTO_TCP) {
            return queue_tcp_transport_injection(request, metadata);
        }
        return inject_packet_now(request, metadata);
    }

    NTSTATUS inject_packet(p_packet_inject_request request) {
        return inject_packet(request, nullptr);
    }

    void cleanup() {
        if (g_inject_handle_v4 && _FwpsInjectionHandleDestroy0) {
            _FwpsInjectionHandleDestroy0(g_inject_handle_v4);
            g_inject_handle_v4 = nullptr;
        }
        if (g_inject_handle_net_v4 && _FwpsInjectionHandleDestroy0) {
            _FwpsInjectionHandleDestroy0(g_inject_handle_net_v4);
            g_inject_handle_net_v4 = nullptr;
        }
        if (g_inject_nbl_pool && _NdisFreeNetBufferListPool) {
            _NdisFreeNetBufferListPool(g_inject_nbl_pool);
            g_inject_nbl_pool = nullptr;
        }
    }
}


namespace net_checksum {

    static UINT32 accumulate(UINT32 sum, const UINT8* data, UINT32 len) {
        if (!data) return sum;
        UINT32 i = 0;
        while (i + 1 < len) {
            sum += ((UINT32)data[i] << 8) | data[i + 1];
            i += 2;
        }
        if (i < len) {
            sum += ((UINT32)data[i] << 8);
        }
        return sum;
    }

    static UINT16 finalize(UINT32 sum) {
        while ((sum >> 16) != 0)
            sum = (sum & 0xFFFFu) + (sum >> 16);
        return (UINT16)(~sum & 0xFFFFu);
    }

    UINT16 ip_checksum(const UINT8* ip_header, UINT32 header_len) {
        if (!ip_header || header_len < 20) return 0;
        return finalize(accumulate(0, ip_header, header_len));
    }

    UINT16 tcp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* tcp_data, UINT32 tcp_len) {
        if (!tcp_data || tcp_len < 20) return 0;
        UINT32 sum = 0;

        UINT8 pseudo[12];
        pseudo[0] = (UINT8)(src_ip >> 24); pseudo[1] = (UINT8)(src_ip >> 16);
        pseudo[2] = (UINT8)(src_ip >> 8);  pseudo[3] = (UINT8)(src_ip);
        pseudo[4] = (UINT8)(dst_ip >> 24); pseudo[5] = (UINT8)(dst_ip >> 16);
        pseudo[6] = (UINT8)(dst_ip >> 8);  pseudo[7] = (UINT8)(dst_ip);
        pseudo[8] = 0; pseudo[9] = IPPROTO_TCP;
        pseudo[10] = (UINT8)(tcp_len >> 8); pseudo[11] = (UINT8)(tcp_len);
        sum = accumulate(sum, pseudo, 12);
        sum = accumulate(sum, tcp_data, tcp_len);
        return finalize(sum);
    }

    UINT16 udp_checksum_ipv4(UINT32 src_ip, UINT32 dst_ip, const UINT8* udp_data, UINT32 udp_len) {
        if (!udp_data || udp_len < 8) return 0;
        UINT32 sum = 0;
        UINT8 pseudo[12];
        pseudo[0] = (UINT8)(src_ip >> 24); pseudo[1] = (UINT8)(src_ip >> 16);
        pseudo[2] = (UINT8)(src_ip >> 8);  pseudo[3] = (UINT8)(src_ip);
        pseudo[4] = (UINT8)(dst_ip >> 24); pseudo[5] = (UINT8)(dst_ip >> 16);
        pseudo[6] = (UINT8)(dst_ip >> 8);  pseudo[7] = (UINT8)(dst_ip);
        pseudo[8] = 0; pseudo[9] = IPPROTO_UDP;
        pseudo[10] = (UINT8)(udp_len >> 8); pseudo[11] = (UINT8)(udp_len);
        sum = accumulate(sum, pseudo, 12);
        sum = accumulate(sum, udp_data, udp_len);
        UINT16 result = finalize(sum);
        if (result == 0) result = 0xFFFFu;
        return result;
    }

    void recalculate_transport_checksums(UINT8* ip_header, UINT32 total_len) {
        if (!ip_header || total_len < 20) return;

        UINT8 ver_ihl = ip_header[0];
        if ((ver_ihl >> 4) != 4) return;

        UINT32 ihl = (ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > total_len) return;

        UINT8 protocol = ip_header[9];
        UINT32 src_ip = ((UINT32)ip_header[12] << 24) | ((UINT32)ip_header[13] << 16) |
                        ((UINT32)ip_header[14] << 8) | ip_header[15];
        UINT32 dst_ip = ((UINT32)ip_header[16] << 24) | ((UINT32)ip_header[17] << 16) |
                        ((UINT32)ip_header[18] << 8) | ip_header[19];


        ip_header[10] = 0;
        ip_header[11] = 0;
        UINT16 ip_cksum = ip_checksum(ip_header, ihl);
        ip_header[10] = (UINT8)(ip_cksum >> 8);
        ip_header[11] = (UINT8)(ip_cksum);

        UINT8* transport = ip_header + ihl;
        UINT32 transport_len = total_len - ihl;

        if (protocol == IPPROTO_TCP && transport_len >= 20) {

            transport[16] = 0;
            transport[17] = 0;
            UINT16 cksum = tcp_checksum_ipv4(src_ip, dst_ip, transport, transport_len);
            transport[16] = (UINT8)(cksum >> 8);
            transport[17] = (UINT8)(cksum);
        } else if (protocol == IPPROTO_UDP && transport_len >= 8) {

            transport[6] = 0;
            transport[7] = 0;
            UINT16 cksum = udp_checksum_ipv4(src_ip, dst_ip, transport, transport_len);
            transport[6] = (UINT8)(cksum >> 8);
            transport[7] = (UINT8)(cksum);
        }
    }
}


namespace net_seq_delta {

    static __forceinline UINT32 hash_5tuple(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        UINT32 h = src_ip ^ dst_ip ^ ((UINT32)src_port << 16) ^ dst_port;
        h = (h ^ (h >> 16)) * 0x45d9f3b;
        h = (h ^ (h >> 16));
        return h % MAX_SEQ_DELTA_ENTRIES;
    }

    SEQ_DELTA_ENTRY* find_or_create(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);


        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
                e->src_port == src_port && e->dst_port == dst_port) {
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }

            if (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                e->src_port == dst_port && e->dst_port == src_port) {
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }
        }


        UINT32 start = hash_5tuple(src_ip, dst_ip, src_port, dst_port);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            UINT32 idx = (start + i) % MAX_SEQ_DELTA_ENTRIES;
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[idx];
            if (!e->active) {
                e->src_ip = src_ip;
                e->dst_ip = dst_ip;
                e->src_port = src_port;
                e->dst_port = dst_port;
                e->outbound_delta = 0;
                e->inbound_delta = 0;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeMemoryBarrier();
                _InterlockedExchange(&e->active, 1);
                KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
                return e;
            }
        }

        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
        return nullptr;
    }

    BOOLEAN apply_delta(UINT8* tcp_header, UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound) {
        if (!tcp_header) return FALSE;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);

        SEQ_DELTA_ENTRY* entry = nullptr;
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                entry = e;
                break;
            }
        }

        if (!entry || (entry->outbound_delta == 0 && entry->inbound_delta == 0)) {
            KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
            return FALSE;
        }


        LONG32 seq_adjust = is_outbound ? entry->outbound_delta : entry->inbound_delta;
        if (seq_adjust != 0) {
            UINT32 seq = ((UINT32)tcp_header[4] << 24) | ((UINT32)tcp_header[5] << 16) |
                         ((UINT32)tcp_header[6] << 8) | tcp_header[7];
            seq = (UINT32)((INT64)seq + seq_adjust);
            tcp_header[4] = (UINT8)(seq >> 24);
            tcp_header[5] = (UINT8)(seq >> 16);
            tcp_header[6] = (UINT8)(seq >> 8);
            tcp_header[7] = (UINT8)(seq);
        }


        LONG32 ack_adjust = is_outbound ? entry->inbound_delta : entry->outbound_delta;
        if (ack_adjust != 0) {
            UINT32 ack = ((UINT32)tcp_header[8] << 24) | ((UINT32)tcp_header[9] << 16) |
                         ((UINT32)tcp_header[10] << 8) | tcp_header[11];
            ack = (UINT32)((INT64)ack + ack_adjust);
            tcp_header[8] = (UINT8)(ack >> 24);
            tcp_header[9] = (UINT8)(ack >> 16);
            tcp_header[10] = (UINT8)(ack >> 8);
            tcp_header[11] = (UINT8)(ack);
        }

        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
        return TRUE;
    }

    void record_size_change(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, BOOLEAN is_outbound, LONG32 delta) {
        if (delta == 0) return;
        SEQ_DELTA_ENTRY* entry = find_or_create(src_ip, dst_ip, src_port, dst_port);
        if (!entry) return;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        if (is_outbound) {
            entry->outbound_delta += delta;
        } else {
            entry->inbound_delta += delta;
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }

    void cleanup_expired() {
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 120;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->last_activity) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }

    void handle_fin_rst(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_seq_delta_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_SEQ_DELTA_ENTRIES; i++) {
            SEQ_DELTA_ENTRY* e = &net_capture::g_seq_delta[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                _InterlockedExchange(&e->active, 0);
                break;
            }
        }
        KeReleaseSpinLock(&net_capture::g_seq_delta_lock, old_irql);
    }
}


namespace net_fragment {

    void init() {
        KeInitializeSpinLock(&net_capture::g_fragment_lock);
        SIZE_T alloc_size = (SIZE_T)MAX_FRAGMENT_ENTRIES * sizeof(FRAGMENT_ENTRY);
        net_capture::g_fragment_entries = (FRAGMENT_ENTRY*)ExAllocatePool2(
            POOL_FLAG_NON_PAGED, alloc_size, 'frNW');
        if (net_capture::g_fragment_entries) {
            strong::kmemset(net_capture::g_fragment_entries, 0, alloc_size);
        }
        NET_DBG("net_fragment::init: allocated %p (%llu bytes)", net_capture::g_fragment_entries, (ULONGLONG)alloc_size);
    }

    void cleanup() {
        if (net_capture::g_fragment_entries) {
            ExFreePoolWithTag(net_capture::g_fragment_entries, 'frNW');
            net_capture::g_fragment_entries = nullptr;
        }
    }

    void cleanup_expired() {
        if (!net_capture::g_fragment_entries) return;
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 30;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_fragment_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_FRAGMENT_ENTRIES; i++) {
            FRAGMENT_ENTRY* e = &net_capture::g_fragment_entries[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->first_seen) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
    }

    UINT8* process_fragment(const UINT8* ip_header, UINT32 total_packet_len, UINT32* out_reassembled_len) {
        if (!ip_header || total_packet_len < 20 || !out_reassembled_len) return nullptr;
        if (!net_capture::g_fragment_entries) return nullptr;

        *out_reassembled_len = 0;

        UINT8 ver_ihl = ip_header[0];
        if ((ver_ihl >> 4) != 4) return nullptr;
        UINT32 ihl = (ver_ihl & 0x0F) * 4;
        if (ihl < 20 || ihl > total_packet_len) return nullptr;

        UINT16 total_length = ((UINT16)ip_header[2] << 8) | ip_header[3];
        UINT16 ip_id = ((UINT16)ip_header[4] << 8) | ip_header[5];
        UINT16 flags_frag = ((UINT16)ip_header[6] << 8) | ip_header[7];
        UINT16 frag_offset = (flags_frag & 0x1FFF) * 8;
        BOOLEAN more_fragments = (flags_frag & 0x2000) != 0;
        UINT8 protocol = ip_header[9];
        UINT32 src_ip = ((UINT32)ip_header[12] << 24) | ((UINT32)ip_header[13] << 16) |
                        ((UINT32)ip_header[14] << 8) | ip_header[15];
        UINT32 dst_ip = ((UINT32)ip_header[16] << 24) | ((UINT32)ip_header[17] << 16) |
                        ((UINT32)ip_header[18] << 8) | ip_header[19];

        UINT32 payload_len = total_length - ihl;
        if (payload_len == 0) return nullptr;
        if (frag_offset + payload_len > FRAGMENT_MAX_SIZE) return nullptr;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_fragment_lock, &old_irql);


        FRAGMENT_ENTRY* entry = nullptr;
        UINT32 free_idx = MAX_FRAGMENT_ENTRIES;
        for (UINT32 i = 0; i < MAX_FRAGMENT_ENTRIES; i++) {
            FRAGMENT_ENTRY* e = &net_capture::g_fragment_entries[i];
            if (e->active && e->ip_id == ip_id && e->src_ip == src_ip &&
                e->dst_ip == dst_ip && e->protocol == protocol) {
                entry = e;
                break;
            }
            if (!e->active && free_idx == MAX_FRAGMENT_ENTRIES) {
                free_idx = i;
            }
        }

        if (!entry) {
            if (free_idx >= MAX_FRAGMENT_ENTRIES) {
                KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
                return nullptr;
            }
            entry = &net_capture::g_fragment_entries[free_idx];
            strong::kmemset(entry, 0, sizeof(FRAGMENT_ENTRY));
            entry->ip_id = ip_id;
            entry->protocol = protocol;
            entry->src_ip = src_ip;
            entry->dst_ip = dst_ip;
            LARGE_INTEGER now;
            now = KeQueryPerformanceCounter(nullptr);
            entry->first_seen = now.QuadPart;
            _InterlockedExchange(&entry->active, 1);
        }


        strong::kmemcpy(entry->data + frag_offset, ip_header + ihl, payload_len);


        for (UINT32 b = frag_offset; b < frag_offset + payload_len; b++) {
            entry->received_map[b / 8] |= (1 << (b % 8));
        }

        UINT32 end_offset = frag_offset + payload_len;
        if (end_offset > entry->highest_offset)
            entry->highest_offset = end_offset;
        entry->total_received += payload_len;

        if (!more_fragments) {
            entry->last_fragment_seen = TRUE;
        }


        BOOLEAN complete = FALSE;
        if (entry->last_fragment_seen && entry->highest_offset > 0) {
            complete = TRUE;
            for (UINT32 b = 0; b < entry->highest_offset; b++) {
                if (!(entry->received_map[b / 8] & (1 << (b % 8)))) {
                    complete = FALSE;
                    break;
                }
            }
        }

        if (complete) {
            UINT32 reassembled_len = entry->highest_offset;
            UINT8* result = (UINT8*)ExAllocatePool2(POOL_FLAG_NON_PAGED, reassembled_len, 'rfNW');
            if (result) {
                strong::kmemcpy(result, entry->data, reassembled_len);
                *out_reassembled_len = reassembled_len;
            }
            _InterlockedExchange(&entry->active, 0);
            KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
            return result;
        }

        KeReleaseSpinLock(&net_capture::g_fragment_lock, old_irql);
        return nullptr;
    }
}


namespace net_udp_cache {

    static __forceinline UINT32 hash_flow(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        UINT32 h = src_ip ^ dst_ip ^ ((UINT32)src_port << 16) ^ dst_port;
        h = (h ^ (h >> 16)) * 0x45d9f3b;
        return (h ^ (h >> 16)) % MAX_UDP_FLOW_ENTRIES;
    }

    UINT32 lookup(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port) {
        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if (e->src_ip == src_ip && e->dst_ip == dst_ip &&
                e->src_port == src_port && e->dst_port == dst_port) {
                UINT32 pid = e->pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return pid;
            }

            if (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                e->src_port == dst_port && e->dst_port == src_port) {
                UINT32 pid = e->pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return pid;
            }
        }
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
        return 0;
    }

    void store(UINT32 src_ip, UINT32 dst_ip, UINT16 src_port, UINT16 dst_port, UINT32 pid) {
        if (pid == 0) return;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);


        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if ((e->src_ip == src_ip && e->dst_ip == dst_ip &&
                 e->src_port == src_port && e->dst_port == dst_port) ||
                (e->src_ip == dst_ip && e->dst_ip == src_ip &&
                 e->src_port == dst_port && e->dst_port == src_port)) {
                e->pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return;
            }
        }


        UINT32 start = hash_flow(src_ip, dst_ip, src_port, dst_port);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UINT32 idx = (start + i) % MAX_UDP_FLOW_ENTRIES;
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[idx];
            if (!e->active) {
                e->src_ip = src_ip;
                e->dst_ip = dst_ip;
                e->src_port = src_port;
                e->dst_port = dst_port;
                e->pid = pid;
                LARGE_INTEGER now;
                now = KeQueryPerformanceCounter(nullptr);
                e->last_activity = now.QuadPart;
                KeMemoryBarrier();
                _InterlockedExchange(&e->active, 1);
                KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
                return;
            }
        }


        UINT64 oldest_time = ~0ULL;
        UINT32 oldest_idx = 0;
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            if (net_capture::g_udp_flow[i].last_activity < oldest_time) {
                oldest_time = net_capture::g_udp_flow[i].last_activity;
                oldest_idx = i;
            }
        }
        UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[oldest_idx];
        e->src_ip = src_ip;
        e->dst_ip = dst_ip;
        e->src_port = src_port;
        e->dst_port = dst_port;
        e->pid = pid;
        LARGE_INTEGER now;
        now = KeQueryPerformanceCounter(nullptr);
        e->last_activity = now.QuadPart;
        KeMemoryBarrier();
        _InterlockedExchange(&e->active, 1);
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
    }

    void cleanup_expired() {
        LARGE_INTEGER now;
        LARGE_INTEGER freq;
        now = KeQueryPerformanceCounter(&freq);
        UINT64 threshold = (UINT64)freq.QuadPart * 60;

        KIRQL old_irql;
        KeAcquireSpinLock(&net_capture::g_udp_flow_lock, &old_irql);
        for (UINT32 i = 0; i < MAX_UDP_FLOW_ENTRIES; i++) {
            UDP_FLOW_ENTRY* e = &net_capture::g_udp_flow[i];
            if (!e->active) continue;
            if ((now.QuadPart - e->last_activity) > threshold) {
                _InterlockedExchange(&e->active, 0);
            }
        }
        KeReleaseSpinLock(&net_capture::g_udp_flow_lock, old_irql);
    }
}


namespace net_mod {

    typedef struct _ACTIVE_MOD_RULE {
        volatile LONG active;
        UINT32 rule_id;
        UINT32 direction;
        UINT32 protocol;
        UINT32 port;
        UINT32 pid;
        UINT32 pattern_size;
        UINT32 replace_size;
        UINT8  pattern[MOD_MAX_PATTERN];
        UINT8  replacement[MOD_MAX_REPLACE];
        volatile LONG match_count;
    } ACTIVE_MOD_RULE;

    inline ACTIVE_MOD_RULE g_mod_rules[MOD_MAX_RULES] = {};
    inline volatile LONG g_next_mod_id = 1;
    inline volatile LONG g_active_mod_count = 0;
    inline volatile LONG64 g_mod_generation = 0;

    BOOLEAN has_active_rules() {
        return (g_active_mod_count != 0);
    }

    LONG active_rule_count() {
        return _InterlockedCompareExchange(&g_active_mod_count, 0, 0);
    }

    LONG64 current_generation() {
        return _InterlockedCompareExchange64(&g_mod_generation, 0, 0);
    }

    BOOLEAN apply_modifications(UINT8* data, UINT32* data_len, UINT32 max_len,
                                UINT32 direction, UINT32 protocol,
                                UINT32 port, UINT32 pid) {
        if (!data || !data_len) {
            SD_LOG("net_mod::apply DROP reason=invalid_buffer irql=%u cpu=%lu direction=%u protocol=%u port=%u pid=%u active_rules=%ld generation=%lld",
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber(),
                direction,
                protocol,
                port,
                pid,
                active_rule_count(),
                current_generation());
            return FALSE;
        }
        LONG active_start = active_rule_count();
        if (active_start == 0) return FALSE;
        UINT64 start_tsc = __rdtsc();
        LONG64 generation = current_generation();
        UINT32 len_before = *data_len;
        UINT32 skip_inactive = 0;
        UINT32 skip_direction = 0;
        UINT32 skip_protocol = 0;
        UINT32 skip_port = 0;
        UINT32 skip_pid = 0;
        UINT32 skip_pattern_bounds = 0;
        UINT32 skip_too_large = 0;
        UINT32 no_match = 0;
        UINT32 matched_rules = 0;
        UINT32 last_rule_id = 0;
        LONG last_match_before = 0;
        LONG last_match_after = 0;
        BOOLEAN modified = FALSE;

        for (UINT32 r = 0; r < MOD_MAX_RULES; r++) {
            if (g_mod_rules[r].active != 1) { ++skip_inactive; continue; }
            ACTIVE_MOD_RULE* rule = &g_mod_rules[r];
            if (rule->direction != 2 && rule->direction != direction) { ++skip_direction; continue; }
            if (rule->protocol != 0 && rule->protocol != protocol) { ++skip_protocol; continue; }
            if (rule->port != 0 && rule->port != port) { ++skip_port; continue; }
            if (rule->pid != 0 && rule->pid != pid) { ++skip_pid; continue; }
            if (rule->pattern_size == 0 || rule->pattern_size > *data_len) { ++skip_pattern_bounds; continue; }

            BOOLEAN rule_matched = FALSE;

            for (UINT32 i = 0; i + rule->pattern_size <= *data_len; i++) {
                BOOLEAN match = TRUE;
                for (UINT32 j = 0; j < rule->pattern_size; j++) {
                    if (data[i + j] != rule->pattern[j]) { match = FALSE; break; }
                }
                if (match) {
                    rule_matched = TRUE;

                    INT32 diff = (INT32)rule->replace_size - (INT32)rule->pattern_size;
                    UINT32 new_len = *data_len + diff;
                    if (new_len > max_len) {
                        ++skip_too_large;
                        SD_LOG("net_mod::apply SKIP reason=max_len rule_id=%u generation=%lld offset=%u len_before=%u pattern=%u replacement=%u new_len=%u max_len=%u direction=%u protocol=%u port=%u pid=%u irql=%u cpu=%lu",
                            rule->rule_id,
                            generation,
                            i,
                            *data_len,
                            rule->pattern_size,
                            rule->replace_size,
                            new_len,
                            max_len,
                            direction,
                            protocol,
                            port,
                            pid,
                            (UINT32)KeGetCurrentIrql(),
                            KeGetCurrentProcessorNumber());
                        continue;
                    }

                    if (diff != 0) {

                        UINT32 tail_start = i + rule->pattern_size;
                        UINT32 tail_len = *data_len - tail_start;
                        if (tail_len > 0) {

                            for (INT32 k = (diff > 0 ? (INT32)tail_len - 1 : 0);
                                 diff > 0 ? k >= 0 : (UINT32)k < tail_len;
                                 diff > 0 ? k-- : k++) {
                                data[tail_start + diff + k] = data[tail_start + k];
                            }
                        }
                    }
                    strong::kmemcpy(&data[i], rule->replacement, rule->replace_size);
                    *data_len = new_len;
                    LONG before = _InterlockedCompareExchange(&rule->match_count, 0, 0);
                    LONG after = _InterlockedIncrement(&rule->match_count);
                    ++matched_rules;
                    last_rule_id = rule->rule_id;
                    last_match_before = before;
                    last_match_after = after;
                    SD_LOG("net_mod::apply MATCH rule_id=%u generation=%lld slot=%u offset=%u match_before=%ld match_after=%ld direction=%u protocol=%u port=%u pid=%u len_before=%u len_after=%u pattern=%u replacement=%u diff=%ld irql=%u cpu=%lu active_rules_start=%ld",
                        rule->rule_id,
                        generation,
                        r,
                        i,
                        before,
                        after,
                        direction,
                        protocol,
                        port,
                        pid,
                        len_before,
                        *data_len,
                        rule->pattern_size,
                        rule->replace_size,
                        diff,
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber(),
                        active_start);
                    modified = TRUE;
                    if (rule->replace_size > 0) i += rule->replace_size - 1;
                }
            }
            if (!rule_matched) ++no_match;
        }
        SD_LOG("net_mod::apply EXIT modified=%u matched_rules=%u last_rule_id=%u generation=%lld last_match_before=%ld last_match_after=%ld direction=%u protocol=%u port=%u pid=%u len_before=%u len_after=%u max_len=%u active_start=%ld active_end=%ld skip_inactive=%u skip_direction=%u skip_protocol=%u skip_port=%u skip_pid=%u skip_pattern=%u skip_too_large=%u no_match=%u elapsed_tsc=%llu irql=%u cpu=%lu",
            modified ? 1u : 0u,
            matched_rules,
            last_rule_id,
            generation,
            last_match_before,
            last_match_after,
            direction,
            protocol,
            port,
            pid,
            len_before,
            *data_len,
            max_len,
            active_start,
            active_rule_count(),
            skip_inactive,
            skip_direction,
            skip_protocol,
            skip_port,
            skip_pid,
            skip_pattern_bounds,
            skip_too_large,
            no_match,
            (unsigned long long)(__rdtsc() - start_tsc),
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());
        return modified;
    }

    NTSTATUS handle_mod_rule(p_packet_mod_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_mod_rule: op=%u rule_id=%u dir=%u proto=%u port=%u pid=%u pat_sz=%u rep_sz=%u",
                request->operation, request->rule_id, request->direction,
                request->protocol, request->port, request->pid,
                request->pattern_size, request->replace_size);
        LONG active_before = active_rule_count();
        LONG64 generation_before = current_generation();
        UINT64 start_tsc = __rdtsc();
        SD_LOG("net_mod::rule ENTER op=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u active_before=%ld generation_before=%lld irql=%u cpu=%lu",
            request->operation,
            request->rule_id,
            request->direction,
            request->protocol,
            request->port,
            request->pid,
            request->pattern_size,
            request->replace_size,
            active_before,
            generation_before,
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_mod_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_mod_id);
                    g_mod_rules[i].rule_id = id;
                    g_mod_rules[i].direction = request->direction;
                    g_mod_rules[i].protocol = request->protocol;
                    g_mod_rules[i].port = request->port;
                    g_mod_rules[i].pid = request->pid;
                    g_mod_rules[i].pattern_size = request->pattern_size;
                    g_mod_rules[i].replace_size = request->replace_size;
                    if (request->pattern_size > 0 && request->pattern_size <= MOD_MAX_PATTERN)
                        strong::kmemcpy(g_mod_rules[i].pattern, request->pattern, request->pattern_size);
                    if (request->replace_size > 0 && request->replace_size <= MOD_MAX_REPLACE)
                        strong::kmemcpy(g_mod_rules[i].replacement, request->replacement, request->replace_size);
                    g_mod_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_mod_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_mod_count);
                    LONG64 generation_after = _InterlockedIncrement64(&g_mod_generation);
                    request->rule_id = id;
                    request->active = 1;
                    NET_DBG("handle_mod_rule: ADDED rule slot=%u id=%u dir=%u proto=%u port=%u",
                            i, id, request->direction, request->protocol, request->port);
                    SD_LOG("net_mod::rule ADD slot=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                        i,
                        id,
                        request->direction,
                        request->protocol,
                        request->port,
                        request->pid,
                        request->pattern_size,
                        request->replace_size,
                        active_before,
                        active_rule_count(),
                        generation_after,
                        STATUS_SUCCESS,
                        (unsigned long long)(__rdtsc() - start_tsc),
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber());
                    return STATUS_SUCCESS;
                }
            }
            SD_LOG("net_mod::rule ADD_FAIL reason=no_slot active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                active_before,
                active_rule_count(),
                current_generation(),
                STATUS_INSUFFICIENT_RESOURCES,
                (unsigned long long)(__rdtsc() - start_tsc),
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (g_mod_rules[i].active == 1 && g_mod_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_mod_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_mod_count);
                    LONG64 generation_after = _InterlockedIncrement64(&g_mod_generation);
                    request->active = 0;
                    SD_LOG("net_mod::rule REMOVE slot=%u rule_id=%u active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                        i,
                        request->rule_id,
                        active_before,
                        active_rule_count(),
                        generation_after,
                        STATUS_SUCCESS,
                        (unsigned long long)(__rdtsc() - start_tsc),
                        (UINT32)KeGetCurrentIrql(),
                        KeGetCurrentProcessorNumber());
                    return STATUS_SUCCESS;
                }
            }
            SD_LOG("net_mod::rule REMOVE_FAIL rule_id=%u reason=not_found active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                request->rule_id,
                active_before,
                active_rule_count(),
                current_generation(),
                STATUS_NOT_FOUND,
                (unsigned long long)(__rdtsc() - start_tsc),
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_NOT_FOUND;
        }
        case 3: {
            UINT32 cleared = 0;
            for (UINT32 i = 0; i < MOD_MAX_RULES; i++) {
                if (g_mod_rules[i].active == 1) {
                    _InterlockedExchange(&g_mod_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_mod_count);
                    ++cleared;
                }
            }
            LONG64 generation_after = _InterlockedIncrement64(&g_mod_generation);
            SD_LOG("net_mod::rule CLEAR cleared=%u active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                cleared,
                active_before,
                active_rule_count(),
                generation_after,
                STATUS_SUCCESS,
                (unsigned long long)(__rdtsc() - start_tsc),
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_SUCCESS;
        }
        default:
            SD_LOG("net_mod::rule INVALID op=%u active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
                request->operation,
                active_before,
                active_rule_count(),
                current_generation(),
                STATUS_INVALID_PARAMETER,
                (unsigned long long)(__rdtsc() - start_tsc),
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_mod_rule_list(p_packet_mod_rule_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        UINT64 start_tsc = __rdtsc();
        LONG active_before = active_rule_count();
        LONG64 generation = current_generation();
        request->rule_count = 0;
        for (UINT32 i = 0; i < MOD_MAX_RULES && request->rule_count < MOD_MAX_RULES; i++) {
            if (g_mod_rules[i].active == 1) {
                PACKET_MOD_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_mod_rules[i].rule_id;
                out->direction = g_mod_rules[i].direction;
                out->protocol = g_mod_rules[i].protocol;
                out->port = g_mod_rules[i].port;
                out->pid = g_mod_rules[i].pid;
                out->pattern_size = g_mod_rules[i].pattern_size;
                out->replace_size = g_mod_rules[i].replace_size;
                strong::kmemcpy(out->pattern, g_mod_rules[i].pattern, g_mod_rules[i].pattern_size);
                strong::kmemcpy(out->replacement, g_mod_rules[i].replacement, g_mod_rules[i].replace_size);
                out->match_count = g_mod_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        SD_LOG("net_mod::rule LIST requested_op=%u returned=%u active_before=%ld active_after=%ld generation=%lld status=0x%08X elapsed_tsc=%llu irql=%u cpu=%lu",
            request->operation,
            request->rule_count,
            active_before,
            active_rule_count(),
            generation,
            STATUS_SUCCESS,
            (unsigned long long)(__rdtsc() - start_tsc),
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());
        return STATUS_SUCCESS;
    }
}


namespace net_redirect {

    typedef struct _ACTIVE_REDIR_RULE {
        volatile LONG active;
        UINT32 rule_id;
        UINT32 protocol;
        UINT32 match_port;
        UINT8  match_addr[16];
        UINT32 redirect_port;
        UINT8  redirect_addr[16];
        UINT32 address_family;
        volatile LONG match_count;
        UINT32 exclude_pid;
    } ACTIVE_REDIR_RULE;

    inline ACTIVE_REDIR_RULE g_redir_rules[REDIR_MAX_RULES] = {};
    inline volatile LONG g_next_redir_id = 1;
    inline volatile LONG g_active_redir_count = 0;

    #define REDIR_MAX_FLOWS 256
    #define REDIR_FLOW_TTL_100NS 3000000000ULL

    typedef struct _ACTIVE_REDIR_FLOW {
        volatile LONG active;
        UINT32 rule_id;
        UINT32 protocol;
        UINT32 address_family;
        UINT32 pid;
        UINT32 local_port;
        UINT32 original_remote_port;
        UINT32 redirected_remote_port;
        UINT32 injected_local_port;
        UINT32 injected_remote_port;
        UINT32 compartment_id;
        UINT32 interface_index;
        UINT32 sub_interface_index;
        UINT8  local_addr[16];
        UINT8  original_remote_addr[16];
        UINT8  redirected_remote_addr[16];
        UINT8  injected_local_addr[16];
        UINT8  injected_remote_addr[16];
        UINT64 endpoint_handle;
        UINT64 last_seen;
    } ACTIVE_REDIR_FLOW;

    inline ACTIVE_REDIR_FLOW g_redir_flows[REDIR_MAX_FLOWS] = {};
    inline volatile LONG g_active_redir_flow_count = 0;
    inline KSPIN_LOCK g_redir_flow_lock;

    void init_lock() {
        KeInitializeSpinLock(&g_redir_flow_lock);
    }

    static __forceinline BOOLEAN addr_equal_for_af(const UINT8* a, const UINT8* b, UINT32 af) {
        if (!a || !b) return FALSE;
        UINT32 len = (af == AF_INET6) ? 16u : 4u;
        for (UINT32 i = 0; i < len; ++i) {
            if (a[i] != b[i]) return FALSE;
        }
        return TRUE;
    }

    static __forceinline BOOLEAN metadata_value_compatible_uint32(UINT32 recorded, UINT32 observed) {
        return recorded == 0 || observed == 0 || recorded == observed;
    }

    static __forceinline BOOLEAN metadata_value_compatible_uint64(UINT64 recorded, UINT64 observed) {
        return recorded == 0 || observed == 0 || recorded == observed;
    }

    static __forceinline UINT64 redir_now_100ns() {
        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        return (UINT64)now.QuadPart;
    }

    static __forceinline BOOLEAN redir_flow_expired(const ACTIVE_REDIR_FLOW* flow, UINT64 now) {
        if (!flow || flow->last_seen == 0) return TRUE;
        return now > flow->last_seen && now - flow->last_seen > REDIR_FLOW_TTL_100NS;
    }

    static void clear_flow_slot_locked(UINT32 index) {
        if (index >= REDIR_MAX_FLOWS) return;
        if (g_redir_flows[index].active == 1) {
            _InterlockedDecrement(&g_active_redir_flow_count);
        }
        strong::kmemset(&g_redir_flows[index], 0, sizeof(g_redir_flows[index]));
    }

    void record_redirect_flow(UINT32 rule_id, UINT32 protocol, UINT32 af, UINT32 pid,
                              const UINT8* local_addr, UINT32 local_port,
                              const UINT8* original_remote_addr, UINT32 original_remote_port,
                              const UINT8* redirected_remote_addr, UINT32 redirected_remote_port,
                              const UINT8* injected_local_addr, UINT32 injected_local_port,
                              const UINT8* injected_remote_addr, UINT32 injected_remote_port,
                              UINT64 endpoint_handle, UINT32 compartment_id,
                              UINT32 interface_index, UINT32 sub_interface_index) {
        if (rule_id == 0 || protocol == 0 || !local_addr || !original_remote_addr || !redirected_remote_addr || !injected_local_addr || !injected_remote_addr)
            return;
        UINT64 now = redir_now_100ns();
        UINT32 selected = REDIR_MAX_FLOWS;
        UINT32 expired = 0;
        UINT32 reused = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_redir_flow_lock, &irql);
        for (UINT32 i = 0; i < REDIR_MAX_FLOWS; ++i) {
            ACTIVE_REDIR_FLOW* flow = &g_redir_flows[i];
            if (flow->active == 1 && redir_flow_expired(flow, now)) {
                clear_flow_slot_locked(i);
                ++expired;
            }
            if (flow->active != 1) {
                if (selected == REDIR_MAX_FLOWS) selected = i;
                continue;
            }
            if (flow->protocol == protocol &&
                flow->address_family == af &&
                flow->injected_local_port == injected_local_port &&
                flow->injected_remote_port == injected_remote_port &&
                addr_equal_for_af(flow->injected_local_addr, injected_local_addr, af) &&
                addr_equal_for_af(flow->injected_remote_addr, injected_remote_addr, af) &&
                metadata_value_compatible_uint32(flow->compartment_id, compartment_id) &&
                metadata_value_compatible_uint64(flow->endpoint_handle, endpoint_handle)) {
                selected = i;
                reused = 1;
                break;
            }
        }
        if (selected == REDIR_MAX_FLOWS) {
            UINT64 oldest = 0xFFFFFFFFFFFFFFFFull;
            for (UINT32 i = 0; i < REDIR_MAX_FLOWS; ++i) {
                if (g_redir_flows[i].last_seen < oldest) {
                    oldest = g_redir_flows[i].last_seen;
                    selected = i;
                }
            }
            if (selected != REDIR_MAX_FLOWS) {
                clear_flow_slot_locked(selected);
            }
        }
        LONG active_after = g_active_redir_flow_count;
        if (selected != REDIR_MAX_FLOWS) {
            ACTIVE_REDIR_FLOW* flow = &g_redir_flows[selected];
            if (flow->active != 1) {
                _InterlockedIncrement(&g_active_redir_flow_count);
            }
            flow->active = 1;
            flow->rule_id = rule_id;
            flow->protocol = protocol;
            flow->address_family = af;
            flow->pid = pid;
            flow->local_port = local_port;
            flow->original_remote_port = original_remote_port;
            flow->redirected_remote_port = redirected_remote_port;
            flow->injected_local_port = injected_local_port;
            flow->injected_remote_port = injected_remote_port;
            flow->endpoint_handle = endpoint_handle;
            flow->compartment_id = compartment_id;
            flow->interface_index = interface_index;
            flow->sub_interface_index = sub_interface_index;
            strong::kmemcpy(flow->local_addr, local_addr, 16);
            strong::kmemcpy(flow->original_remote_addr, original_remote_addr, 16);
            strong::kmemcpy(flow->redirected_remote_addr, redirected_remote_addr, 16);
            strong::kmemcpy(flow->injected_local_addr, injected_local_addr, 16);
            strong::kmemcpy(flow->injected_remote_addr, injected_remote_addr, 16);
            flow->last_seen = now;
            active_after = g_active_redir_flow_count;
        }
        KeReleaseSpinLock(&g_redir_flow_lock, irql);
        SD_LOG("net_redirect::flow_record rule_id=%u selected=%u reused=%u expired=%u active_after=%ld protocol=%u pid=%u local=%u.%u.%u.%u:%u original=%u.%u.%u.%u:%u redirected=%u.%u.%u.%u:%u injected=%u.%u.%u.%u:%u->%u.%u.%u.%u:%u endpoint=0x%llX compartment=%u iface=%u sub_iface=%u",
            rule_id,
            selected == REDIR_MAX_FLOWS ? 0xFFFFFFFFu : selected,
            reused,
            expired,
            active_after,
            protocol,
            pid,
            local_addr[0], local_addr[1], local_addr[2], local_addr[3], local_port,
            original_remote_addr[0], original_remote_addr[1], original_remote_addr[2], original_remote_addr[3], original_remote_port,
            redirected_remote_addr[0], redirected_remote_addr[1], redirected_remote_addr[2], redirected_remote_addr[3], redirected_remote_port,
            injected_local_addr[0], injected_local_addr[1], injected_local_addr[2], injected_local_addr[3], injected_local_port,
            injected_remote_addr[0], injected_remote_addr[1], injected_remote_addr[2], injected_remote_addr[3], injected_remote_port,
            endpoint_handle,
            compartment_id,
            interface_index,
            sub_interface_index);
    }

    BOOLEAN find_reverse_redirect(UINT32 protocol, UINT32 af, UINT32 pid,
                                  const UINT8* local_addr, UINT32 local_port,
                                  const UINT8* remote_addr, UINT32 remote_port,
                                  UINT64 endpoint_handle, UINT32 compartment_id,
                                  UINT32 interface_index, UINT32 sub_interface_index,
                                  UINT32* rule_id, UINT8* original_remote_addr,
                                  UINT32* original_remote_port, UINT32* flow_pid,
                                  LONG* active_flow_count) {
        if (rule_id) *rule_id = 0;
        if (original_remote_port) *original_remote_port = 0;
        if (flow_pid) *flow_pid = 0;
        if (active_flow_count) *active_flow_count = g_active_redir_flow_count;
        if (!local_addr || !remote_addr || !original_remote_addr)
            return FALSE;
        UINT64 now = redir_now_100ns();
        BOOLEAN matched = FALSE;
        UINT32 matched_slot = 0xFFFFFFFFu;
        UINT32 matched_rule = 0;
        UINT32 matched_pid = 0;
        UINT32 matched_original_port = 0;
        UINT8 matched_original_addr[16] = {};
        UINT32 matched_score = 0;
        UINT64 matched_endpoint = 0;
        UINT32 matched_compartment = 0;
        UINT32 matched_interface = 0;
        UINT32 matched_sub_interface = 0;
        UINT32 protocol_candidates = 0;
        UINT32 pid_rejects = 0;
        UINT32 local_rejects = 0;
        UINT32 remote_rejects = 0;
        UINT32 metadata_rejects = 0;
        UINT32 best_slot = 0xFFFFFFFFu;
        UINT32 best_rule = 0;
        UINT32 best_pid = 0;
        UINT32 best_local_port = 0;
        UINT32 best_remote_port = 0;
        UINT32 best_compartment = 0;
        UINT32 best_interface = 0;
        UINT32 best_sub_interface = 0;
        UINT64 best_endpoint = 0;
        UINT8 best_local_addr[16] = {};
        UINT8 best_remote_addr[16] = {};
        UINT32 expired = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_redir_flow_lock, &irql);
        for (UINT32 i = 0; i < REDIR_MAX_FLOWS; ++i) {
            ACTIVE_REDIR_FLOW* flow = &g_redir_flows[i];
            if (flow->active == 1 && redir_flow_expired(flow, now)) {
                clear_flow_slot_locked(i);
                ++expired;
                continue;
            }
            if (flow->active != 1) continue;
            if (flow->protocol != protocol || flow->address_family != af) continue;
            ++protocol_candidates;
            if (best_slot == 0xFFFFFFFFu) {
                best_slot = i;
                best_rule = flow->rule_id;
                best_pid = flow->pid;
                best_local_port = flow->injected_local_port;
                best_remote_port = flow->injected_remote_port;
                best_endpoint = flow->endpoint_handle;
                best_compartment = flow->compartment_id;
                best_interface = flow->interface_index;
                best_sub_interface = flow->sub_interface_index;
                strong::kmemcpy(best_local_addr, flow->injected_local_addr, 16);
                strong::kmemcpy(best_remote_addr, flow->injected_remote_addr, 16);
            }
            if (pid != 0 && flow->pid != 0 && pid != flow->pid) {
                ++pid_rejects;
                continue;
            }
            if (flow->injected_local_port != local_port || !addr_equal_for_af(flow->injected_local_addr, local_addr, af)) {
                ++local_rejects;
                continue;
            }
            if (flow->injected_remote_port != remote_port || !addr_equal_for_af(flow->injected_remote_addr, remote_addr, af)) {
                ++remote_rejects;
                continue;
            }
            if (!metadata_value_compatible_uint32(flow->compartment_id, compartment_id) ||
                !metadata_value_compatible_uint64(flow->endpoint_handle, endpoint_handle)) {
                ++metadata_rejects;
                continue;
            }
            UINT32 score = 1;
            if (flow->compartment_id != 0 && flow->compartment_id == compartment_id) score += 4;
            if (flow->endpoint_handle != 0 && flow->endpoint_handle == endpoint_handle) score += 4;
            if (flow->interface_index != 0 && flow->interface_index == interface_index) score += 1;
            if (flow->sub_interface_index != 0 && flow->sub_interface_index == sub_interface_index) score += 1;
            if (matched && score < matched_score) continue;
            matched = TRUE;
            matched_slot = i;
            matched_rule = flow->rule_id;
            matched_pid = flow->pid;
            matched_original_port = flow->original_remote_port;
            matched_score = score;
            matched_endpoint = flow->endpoint_handle;
            matched_compartment = flow->compartment_id;
            matched_interface = flow->interface_index;
            matched_sub_interface = flow->sub_interface_index;
            strong::kmemcpy(matched_original_addr, flow->original_remote_addr, 16);
            flow->last_seen = now;
        }
        LONG active_after = g_active_redir_flow_count;
        KeReleaseSpinLock(&g_redir_flow_lock, irql);
        if (active_flow_count) *active_flow_count = active_after;
        SD_LOG("net_redirect::reverse_lookup protocol=%u pid=%u tuple=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u endpoint=0x%llX compartment=%u iface=%u sub_iface=%u matched=%u slot=%u rule_id=%u score=%u original=%u.%u.%u.%u:%u matched_endpoint=0x%llX matched_compartment=%u matched_iface=%u matched_sub_iface=%u expired=%u active_flows=%ld candidates=%u pid_rejects=%u local_rejects=%u remote_rejects=%u metadata_rejects=%u best_slot=%u best_rule=%u best_pid=%u best_tuple=%u.%u.%u.%u:%u<-%u.%u.%u.%u:%u best_endpoint=0x%llX best_compartment=%u best_iface=%u best_sub_iface=%u",
            protocol,
            pid,
            local_addr[0], local_addr[1], local_addr[2], local_addr[3], local_port,
            remote_addr[0], remote_addr[1], remote_addr[2], remote_addr[3], remote_port,
            endpoint_handle,
            compartment_id,
            interface_index,
            sub_interface_index,
            matched ? 1u : 0u,
            matched_slot,
            matched_rule,
            matched_score,
            matched_original_addr[0], matched_original_addr[1], matched_original_addr[2], matched_original_addr[3], matched_original_port,
            matched_endpoint,
            matched_compartment,
            matched_interface,
            matched_sub_interface,
            expired,
            active_after,
            protocol_candidates,
            pid_rejects,
            local_rejects,
            remote_rejects,
            metadata_rejects,
            best_slot,
            best_rule,
            best_pid,
            best_local_addr[0], best_local_addr[1], best_local_addr[2], best_local_addr[3], best_local_port,
            best_remote_addr[0], best_remote_addr[1], best_remote_addr[2], best_remote_addr[3], best_remote_port,
            best_endpoint,
            best_compartment,
            best_interface,
            best_sub_interface);
        if (!matched) return FALSE;
        if (rule_id) *rule_id = matched_rule;
        if (original_remote_port) *original_remote_port = matched_original_port;
        if (flow_pid) *flow_pid = matched_pid;
        strong::kmemcpy(original_remote_addr, matched_original_addr, 16);
        return TRUE;
    }

    void clear_flows_for_rule(UINT32 rule_id) {
        UINT32 cleared = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_redir_flow_lock, &irql);
        for (UINT32 i = 0; i < REDIR_MAX_FLOWS; ++i) {
            if (g_redir_flows[i].active == 1 && (rule_id == 0 || g_redir_flows[i].rule_id == rule_id)) {
                clear_flow_slot_locked(i);
                ++cleared;
            }
        }
        LONG active_after = g_active_redir_flow_count;
        KeReleaseSpinLock(&g_redir_flow_lock, irql);
        SD_LOG("net_redirect::flow_clear rule_id=%u cleared=%u active_after=%ld", rule_id, cleared, active_after);
    }

    static BOOLEAN is_valid_redirect_add_request(p_traffic_redirect_rule request) {
        if (!request) return FALSE;
        if (request->address_family != AF_INET && request->address_family != AF_INET6) return FALSE;
        if (request->redirect_port == 0) return FALSE;
        if (net_capture::is_zero_ip(request->redirect_addr)) return FALSE;

        const BOOLEAN wildcard_match =
            request->protocol == 0 &&
            request->match_port == 0 &&
            net_capture::is_zero_ip(request->match_addr);
        if (wildcard_match) return FALSE;

        return TRUE;
    }

    BOOLEAN has_active_rules() {
        return (g_active_redir_count != 0);
    }


    BOOLEAN check_redirect(UINT32 protocol, UINT32 dst_port, const UINT8* dst_addr,
                           UINT32 af, UINT32 pid, UINT32* new_port, UINT8* new_addr,
                           UINT32* matched_rule_id, LONG* match_before, LONG* match_after) {
        if (matched_rule_id) *matched_rule_id = 0;
        if (match_before) *match_before = 0;
        if (match_after) *match_after = 0;
        if (g_active_redir_count == 0) return FALSE;
        for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
            if (g_redir_rules[i].active != 1) continue;
            ACTIVE_REDIR_RULE* r = &g_redir_rules[i];
            if (r->exclude_pid != 0 && r->exclude_pid == pid) continue;
            if (r->protocol != 0 && r->protocol != protocol) continue;
            if (r->match_port != 0 && r->match_port != dst_port) continue;
            if (!net_capture::is_zero_ip(r->match_addr)) {
                UINT8 mask[16];
                strong::kmemset(mask, 0xFF, sizeof(mask));
                if (!net_capture::ip_matches(dst_addr, r->match_addr, mask, af)) continue;
            }
            *new_port = r->redirect_port;
            strong::kmemcpy(new_addr, r->redirect_addr, 16);
            LONG before = _InterlockedCompareExchange(&r->match_count, 0, 0);
            LONG after = _InterlockedIncrement(&r->match_count);
            if (matched_rule_id) *matched_rule_id = r->rule_id;
            if (match_before) *match_before = before;
            if (match_after) *match_after = after;
            return TRUE;
        }
        return FALSE;
    }

    NTSTATUS handle_redirect_rule(p_traffic_redirect_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_redirect_rule: op=%u rule_id=%u proto=%u match_port=%u redir_port=%u af=%u excl_pid=%u",
                request->operation, request->rule_id, request->protocol,
                request->match_port, request->redirect_port,
                request->address_family, request->exclude_pid);

        switch (request->operation) {
        case 0: {
            if (!is_valid_redirect_add_request(request)) {
                NET_ERR("handle_redirect_rule: reject invalid add proto=%u match_port=%u redir_port=%u af=%u",
                        request->protocol, request->match_port,
                        request->redirect_port, request->address_family);
                return STATUS_INVALID_PARAMETER;
            }
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_redir_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_redir_id);
                    g_redir_rules[i].rule_id = id;
                    g_redir_rules[i].protocol = request->protocol;
                    g_redir_rules[i].match_port = request->match_port;
                    strong::kmemcpy(g_redir_rules[i].match_addr, request->match_addr, 16);
                    g_redir_rules[i].redirect_port = request->redirect_port;
                    strong::kmemcpy(g_redir_rules[i].redirect_addr, request->redirect_addr, 16);
                    g_redir_rules[i].address_family = request->address_family;
                    g_redir_rules[i].exclude_pid = request->exclude_pid;
                    g_redir_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_redir_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_redir_count);
                    request->rule_id = id;
                    request->active = 1;
                    NET_DBG("handle_redirect_rule: ADDED rule slot=%u id=%u proto=%u match_port=%u redir_port=%u",
                            i, id, request->protocol, request->match_port, request->redirect_port);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (g_redir_rules[i].active == 1 && g_redir_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_redir_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_redir_count);
                    request->active = 0;
                    clear_flows_for_rule(request->rule_id);
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            for (UINT32 i = 0; i < REDIR_MAX_RULES; i++) {
                if (g_redir_rules[i].active == 1) {
                    _InterlockedExchange(&g_redir_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_redir_count);
                }
            }
            clear_flows_for_rule(0);
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_redirect_list(p_traffic_redirect_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->rule_count = 0;
        for (UINT32 i = 0; i < REDIR_MAX_RULES && request->rule_count < REDIR_MAX_RULES; i++) {
            if (g_redir_rules[i].active == 1) {
                TRAFFIC_REDIRECT_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_redir_rules[i].rule_id;
                out->protocol = g_redir_rules[i].protocol;
                out->match_port = g_redir_rules[i].match_port;
                strong::kmemcpy(out->match_addr, g_redir_rules[i].match_addr, 16);
                out->redirect_port = g_redir_rules[i].redirect_port;
                strong::kmemcpy(out->redirect_addr, g_redir_rules[i].redirect_addr, 16);
                out->address_family = g_redir_rules[i].address_family;
                out->match_count = g_redir_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        return STATUS_SUCCESS;
    }

    void cleanup() {
        for (UINT32 i = 0; i < REDIR_MAX_RULES; ++i) {
            _InterlockedExchange(&g_redir_rules[i].active, 0);
            strong::kmemset(&g_redir_rules[i], 0, sizeof(g_redir_rules[i]));
        }
        _InterlockedExchange(&g_active_redir_count, 0);
        clear_flows_for_rule(0);
    }
}


namespace net_stream {


    #define MAX_TRACKED_STREAMS 1024

    typedef struct _TRACKED_STREAM {
        volatile LONG active;
        UINT32 src_port;
        UINT32 dst_port;
        UINT32 pid;
        UINT8  src_addr[16];
        UINT8  dst_addr[16];
        UINT32 stream_size;
        UINT32 total_packets;
        UINT32 truncated;
        UINT8* stream_data;
        KSPIN_LOCK lock;
    } TRACKED_STREAM;

    inline TRACKED_STREAM g_streams[MAX_TRACKED_STREAMS] = {};
    inline volatile LONG g_active_stream_count = 0;

    BOOLEAN has_active_streams() {
        return (g_active_stream_count != 0);
    }


    void feed_packet(UINT32 src_port, UINT32 dst_port, UINT32 pid,
                     const UINT8* src_addr, const UINT8* dst_addr,
                     const UINT8* data, UINT32 data_len) {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            if (g_streams[i].active != 1) continue;

            BOOLEAN match = FALSE;
            BOOLEAN src_addr_wildcard = net_capture::is_zero_ip(g_streams[i].src_addr);
            BOOLEAN dst_addr_wildcard = net_capture::is_zero_ip(g_streams[i].dst_addr);

            BOOLEAN forward_port_match =
                (g_streams[i].src_port == 0 || g_streams[i].src_port == src_port) &&
                (g_streams[i].dst_port == 0 || g_streams[i].dst_port == dst_port);
            if (forward_port_match) {
                BOOLEAN addr_match = TRUE;
                if (!src_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].src_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].dst_addr[j] != dst_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match) match = TRUE;
            }

            BOOLEAN reverse_port_match =
                (g_streams[i].src_port == 0 || g_streams[i].src_port == dst_port) &&
                (g_streams[i].dst_port == 0 || g_streams[i].dst_port == src_port);
            if (!match && reverse_port_match) {
                BOOLEAN addr_match = TRUE;
                if (!src_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].src_addr[j] != dst_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match && !dst_addr_wildcard) {
                    for (int j = 0; j < 16; j++) {
                        if (g_streams[i].dst_addr[j] != src_addr[j]) {
                            addr_match = FALSE;
                            break;
                        }
                    }
                }
                if (addr_match) match = TRUE;
            }
            if (g_streams[i].pid != 0 && g_streams[i].pid != pid) match = FALSE;

            if (match && g_streams[i].stream_data && data_len > 0) {
                KIRQL irql;
                KeAcquireSpinLock(&g_streams[i].lock, &irql);
                if (g_streams[i].stream_data) {
                    UINT32 avail = STREAM_MAX_SIZE - g_streams[i].stream_size;
                    if (avail > 0) {
                        UINT32 copy = data_len < avail ? data_len : avail;
                        strong::kmemcpy(g_streams[i].stream_data + g_streams[i].stream_size, data, copy);
                        g_streams[i].stream_size += copy;
                        if (copy < data_len) g_streams[i].truncated = 1;
                    } else {
                        g_streams[i].truncated = 1;
                    }
                    g_streams[i].total_packets++;
                }
                KeReleaseSpinLock(&g_streams[i].lock, irql);
            }
        }
    }

    NTSTATUS handle_stream(p_stream_reassemble_request request) {
        if (!request) {
            SD_LOG("netaction::net_stream::handle_stream NULL_REQUEST");
            return STATUS_INVALID_PARAMETER;
        }

        SD_LOG("netaction::net_stream::handle_stream op=%u src_port=%u dst_port=%u pid=%u active_count=%ld",
            request->operation, request->src_port, request->dst_port, request->pid,
            _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
        NET_DBG("handle_stream: op=%u src_port=%u dst_port=%u pid=%u",
                request->operation, request->src_port, request->dst_port, request->pid);

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (_InterlockedCompareExchange(&g_streams[i].active, 2, 0) == 0) {
                    g_streams[i].src_port = request->src_port;
                    g_streams[i].dst_port = request->dst_port;
                    g_streams[i].pid = request->pid;
                    strong::kmemcpy(g_streams[i].src_addr, request->src_addr, 16);
                    strong::kmemcpy(g_streams[i].dst_addr, request->dst_addr, 16);
                    g_streams[i].stream_size = 0;
                    g_streams[i].total_packets = 0;
                    g_streams[i].truncated = 0;
                    if (!g_streams[i].stream_data) {
                        g_streams[i].stream_data = (UINT8*)ExAllocatePool2(
                            POOL_FLAG_NON_PAGED, STREAM_MAX_SIZE, 'stNW');
                        if (!g_streams[i].stream_data) {
                            SD_LOG("netaction::net_stream::handle_stream[start] alloc_failed slot=%u status=STATUS_INSUFFICIENT_RESOURCES", i);
                            _InterlockedExchange(&g_streams[i].active, 0);
                            return STATUS_INSUFFICIENT_RESOURCES;
                        }
                    }
                    strong::kmemset(g_streams[i].stream_data, 0, STREAM_MAX_SIZE);
                    KeInitializeSpinLock(&g_streams[i].lock);
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_streams[i].active, 1);
                    _InterlockedIncrement(&g_active_stream_count);
                    SD_LOG("netaction::net_stream::handle_stream[start] OK slot=%u src_port=%u dst_port=%u pid=%u",
                        i, request->src_port, request->dst_port, request->pid);
                    NET_DBG("handle_stream[start]: slot=%u src_port=%u dst_port=%u pid=%u",
                            i, request->src_port, request->dst_port, request->pid);
                    return STATUS_SUCCESS;
                }
            }
            SD_LOG("netaction::net_stream::handle_stream[start] no_free_slot active=%ld status=STATUS_INSUFFICIENT_RESOURCES",
                _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1 &&
                    g_streams[i].src_port == request->src_port &&
                    g_streams[i].dst_port == request->dst_port) {
                    _InterlockedExchange(&g_streams[i].active, 0);
                    _InterlockedDecrement(&g_active_stream_count);
                    SD_LOG("netaction::net_stream::handle_stream[stop] OK slot=%u src_port=%u dst_port=%u",
                        i, request->src_port, request->dst_port);
                    return STATUS_SUCCESS;
                }
            }
            SD_LOG("netaction::net_stream::handle_stream[stop] not_found src_port=%u dst_port=%u status=STATUS_NOT_FOUND",
                request->src_port, request->dst_port);
            return STATUS_NOT_FOUND;
        }
        case 2: {
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1 &&
                    g_streams[i].src_port == request->src_port &&
                    g_streams[i].dst_port == request->dst_port) {
                    KIRQL irql;
                    KeAcquireSpinLock(&g_streams[i].lock, &irql);
                    UINT32 copy = g_streams[i].stream_size;
                    if (copy > STREAM_MAX_SIZE) copy = STREAM_MAX_SIZE;
                    strong::kmemcpy(request->stream_data, g_streams[i].stream_data, copy);
                    request->stream_size = g_streams[i].stream_size;
                    request->total_packets = g_streams[i].total_packets;
                    request->truncated = g_streams[i].truncated;
                    KeReleaseSpinLock(&g_streams[i].lock, irql);
                    SD_LOG("netaction::net_stream::handle_stream[get] OK slot=%u stream_size=%u total_packets=%u truncated=%u",
                        i, request->stream_size, request->total_packets, request->truncated);
                    return STATUS_SUCCESS;
                }
            }
            SD_LOG("netaction::net_stream::handle_stream[get] not_found src_port=%u dst_port=%u active_count=%ld status=STATUS_NOT_FOUND",
                request->src_port, request->dst_port,
                _InterlockedCompareExchange(&g_active_stream_count, 0, 0));
            return STATUS_NOT_FOUND;
        }
        case 3: {
            request->stream_count = 0;
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (g_streams[i].active == 1) request->stream_count++;
            }
            SD_LOG("netaction::net_stream::handle_stream[count] OK count=%u", request->stream_count);
            return STATUS_SUCCESS;
        }
        case 4: {
            UINT32 cleared = 0;
            for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
                if (_InterlockedExchange(&g_streams[i].active, 0) == 1)
                    cleared++;
                g_streams[i].src_port = 0;
                g_streams[i].dst_port = 0;
                g_streams[i].pid = 0;
                g_streams[i].stream_size = 0;
                g_streams[i].total_packets = 0;
                g_streams[i].truncated = 0;
                strong::kmemset(g_streams[i].src_addr, 0, sizeof(g_streams[i].src_addr));
                strong::kmemset(g_streams[i].dst_addr, 0, sizeof(g_streams[i].dst_addr));
            }
            _InterlockedExchange(&g_active_stream_count, 0);
            request->stream_count = 0;
            SD_LOG("netaction::net_stream::handle_stream[clear] OK cleared=%u", cleared);
            return STATUS_SUCCESS;
        }
        default:
            SD_LOG("netaction::net_stream::handle_stream invalid_operation op=%u status=STATUS_INVALID_PARAMETER",
                request->operation);
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        for (UINT32 i = 0; i < MAX_TRACKED_STREAMS; i++) {
            _InterlockedExchange(&g_streams[i].active, 0);
            if (g_streams[i].stream_data) {
                KIRQL irql;
                KeAcquireSpinLock(&g_streams[i].lock, &irql);
                UINT8* data = g_streams[i].stream_data;
                g_streams[i].stream_data = nullptr;
                KeReleaseSpinLock(&g_streams[i].lock, irql);
                if (data) {
                    ExFreePoolWithTag(data, 'stNW');
                }
            }
        }
        _InterlockedExchange(&g_active_stream_count, 0);
    }
}


namespace net_dpi {


    inline DPI_HEADER_INFO* g_dpi_ring = nullptr;
    inline volatile LONG g_dpi_head = 0;
    inline volatile LONG g_dpi_tail = 0;
    inline volatile LONG g_dpi_count = 0;
    inline KSPIN_LOCK g_dpi_lock;
    inline volatile LONG g_dpi_active = 0;
    inline volatile LONG64 g_dpi_total_enqueued = 0;
    inline volatile LONG64 g_dpi_total_overwritten = 0;
    inline volatile LONG64 g_dpi_drop_inactive = 0;
    inline volatile LONG64 g_dpi_drop_no_ring = 0;
    inline volatile LONG64 g_dpi_drop_capture_filter = 0;
    inline volatile LONG64 g_dpi_http_hits = 0;
    inline volatile LONG64 g_dpi_tls_hits = 0;
    inline volatile LONG64 g_dpi_dns_hits = 0;
    inline volatile LONG64 g_dpi_tcp_bounds_rejects = 0;

    BOOLEAN is_active() {
        return (g_dpi_active != 0);
    }

    #define DPI_RING_SIZE 256

    NTSTATUS init() {
        if (g_dpi_ring) return STATUS_SUCCESS;
        SIZE_T sz = (SIZE_T)DPI_RING_SIZE * sizeof(DPI_HEADER_INFO);
        g_dpi_ring = (DPI_HEADER_INFO*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sz, 'dpNW');
        if (!g_dpi_ring) return STATUS_INSUFFICIENT_RESOURCES;
        strong::kmemset(g_dpi_ring, 0, sz);
        KeInitializeSpinLock(&g_dpi_lock);
        return STATUS_SUCCESS;
    }

    NTSTATUS start() {
        NTSTATUS st = init();
        if (!NT_SUCCESS(st)) return st;

        KIRQL irql;
        KeAcquireSpinLock(&g_dpi_lock, &irql);
        g_dpi_head = 0;
        g_dpi_tail = 0;
        g_dpi_count = 0;
        strong::kmemset(g_dpi_ring, 0, (SIZE_T)DPI_RING_SIZE * sizeof(DPI_HEADER_INFO));
        KeReleaseSpinLock(&g_dpi_lock, irql);

        _InterlockedExchange64(&g_dpi_total_enqueued, 0);
        _InterlockedExchange64(&g_dpi_total_overwritten, 0);
        _InterlockedExchange64(&g_dpi_drop_inactive, 0);
        _InterlockedExchange64(&g_dpi_drop_no_ring, 0);
        _InterlockedExchange64(&g_dpi_drop_capture_filter, 0);
        _InterlockedExchange64(&g_dpi_http_hits, 0);
        _InterlockedExchange64(&g_dpi_tls_hits, 0);
        _InterlockedExchange64(&g_dpi_dns_hits, 0);
        _InterlockedExchange64(&g_dpi_tcp_bounds_rejects, 0);
        _InterlockedExchange(&g_dpi_active, 1);
        NET_DBG("net_dpi::start active=1");
        SD_LOG("net_dpi::start active=1 ring=%p capacity=%u head=%ld tail=%ld count=%ld",
            g_dpi_ring,
            DPI_RING_SIZE,
            g_dpi_head,
            g_dpi_tail,
            g_dpi_count);
        return STATUS_SUCCESS;
    }

    void stop() {
        _InterlockedExchange(&g_dpi_active, 0);
        NET_DBG("net_dpi::stop count=%ld", g_dpi_count);
        SD_LOG("net_dpi::stop active=0 ring_count=%ld head=%ld tail=%ld enqueued=%lld overwritten=%lld http_hits=%lld tls_hits=%lld dns_hits=%lld tcp_bounds_rejects=%lld drop_inactive=%lld drop_no_ring=%lld drop_capture_filter=%lld",
            g_dpi_count,
            g_dpi_head,
            g_dpi_tail,
            _InterlockedCompareExchange64(&g_dpi_total_enqueued, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_total_overwritten, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_http_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_tls_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_dns_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_tcp_bounds_rejects, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_inactive, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_no_ring, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_capture_filter, 0, 0));
    }

    LONG entry_count() {
        return g_dpi_count;
    }


    static UINT32 detect_http_method(const UINT8* data, UINT32 len) {
        if (len < 4) return 0;
        if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
        if (len >= 5 && data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T' && data[4] == ' ') return 2;
        if (len >= 4 && data[0] == 'P' && data[1] == 'U' && data[2] == 'T' && data[3] == ' ') return 3;
        if (len >= 7 && data[0] == 'D' && data[1] == 'E' && data[2] == 'L') return 4;
        if (len >= 5 && data[0] == 'H' && data[1] == 'E' && data[2] == 'A' && data[3] == 'D' && data[4] == ' ') return 5;
        if (len >= 5 && data[0] == 'H' && data[1] == 'T' && data[2] == 'T' && data[3] == 'P' && data[4] == '/') return 6;
        return 0;
    }


    static void extract_http_host(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;

        for (UINT32 i = 0; i + 6 < len; i++) {
            if ((data[i] == 'H' || data[i] == 'h') &&
                (data[i+1] == 'o' || data[i+1] == 'O') &&
                (data[i+2] == 's' || data[i+2] == 'S') &&
                (data[i+3] == 't' || data[i+3] == 'T') &&
                data[i+4] == ':' && data[i+5] == ' ') {
                UINT32 j = i + 6;
                UINT32 k = 0;
                while (j < len && data[j] != '\r' && data[j] != '\n' && k < out_size - 1) {
                    out[k++] = (char)data[j++];
                }
                out[k] = 0;
                return;
            }
        }
    }


    static void extract_http_path(const UINT8* data, UINT32 len, char* out, UINT32 out_size) {
        out[0] = 0;

        UINT32 i = 0;
        while (i < len && data[i] != ' ') i++;
        if (i >= len) return;
        i++;
        UINT32 k = 0;
        while (i < len && data[i] != ' ' && data[i] != '\r' && data[i] != '\n' && k < out_size - 1) {
            out[k++] = (char)data[i++];
        }
        out[k] = 0;
    }


    static void detect_tls(const UINT8* data, UINT32 len, DPI_HEADER_INFO* info) {
        if (len < 5) return;

        UINT8 content_type = data[0];
        if (content_type < 20 || content_type > 23) return;

        UINT16 version = ((UINT16)data[1] << 8) | data[2];

        if (version < 0x0300 || version > 0x0304) return;

        info->is_tls = 1;
        info->tls_version = version;
        info->tls_content_type = content_type;


        if (content_type == 22 && len > 43) {
            UINT8 handshake_type = data[5];
            if (handshake_type == 1) {

                UINT32 pos = 43;
                if (pos >= len) return;
                UINT8 session_id_len = data[pos];
                pos += 1 + session_id_len;
                if (pos + 2 >= len) return;

                UINT16 cs_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2 + cs_len;
                if (pos + 1 >= len) return;

                UINT8 comp_len = data[pos];
                pos += 1 + comp_len;
                if (pos + 2 >= len) return;

                UINT16 ext_len = ((UINT16)data[pos] << 8) | data[pos + 1];
                pos += 2;
                UINT32 ext_end = pos + ext_len;
                while (pos + 4 <= ext_end && pos + 4 <= len) {
                    UINT16 ext_type = ((UINT16)data[pos] << 8) | data[pos + 1];
                    UINT16 elen = ((UINT16)data[pos + 2] << 8) | data[pos + 3];
                    pos += 4;
                    if (ext_type == 0 && elen > 5 && pos + elen <= len) {

                        UINT32 sni_pos = pos + 2 + 1;
                        if (sni_pos + 2 >= len) break;
                        UINT16 name_len = ((UINT16)data[sni_pos] << 8) | data[sni_pos + 1];
                        sni_pos += 2;
                        if (sni_pos + name_len <= len && name_len < 128) {
                            for (UINT16 s = 0; s < name_len; s++)
                                info->tls_sni[s] = (char)data[sni_pos + s];
                            info->tls_sni[name_len] = 0;
                        }
                        break;
                    }
                    pos += elen;
                }
            }
        }
    }


    void analyze_packet(UINT64 timestamp, UINT32 direction, UINT32 protocol,
                        UINT32 src_port, UINT32 dst_port,
                        const UINT8* src_addr, const UINT8* dst_addr,
                        UINT32 af, UINT32 pid,
                        const UINT8* payload, UINT32 payload_len) {
        if (!g_dpi_active) {
            _InterlockedIncrement64(&g_dpi_drop_inactive);
            return;
        }
        if (!g_dpi_ring) {
            _InterlockedIncrement64(&g_dpi_drop_no_ring);
            return;
        }
        if (net_capture::g_capture_active &&
            !net_capture::packet_matches_capture_filters(protocol, pid, src_port, dst_port, af, dst_addr)) {
            _InterlockedIncrement64(&g_dpi_drop_capture_filter);
            return;
        }

        DPI_HEADER_INFO info;
        strong::kmemset(&info, 0, sizeof(info));
        info.timestamp = timestamp;
        info.direction = direction;
        info.protocol = protocol;
        info.src_port = src_port;
        info.dst_port = dst_port;
        info.address_family = af;
        info.pid = pid;
        info.payload_size = payload_len;
        strong::kmemcpy(info.src_addr, src_addr, (af == 23) ? 16 : 4);
        strong::kmemcpy(info.dst_addr, dst_addr, (af == 23) ? 16 : 4);


        if (protocol == 6 && payload_len >= 20) {
            info.tcp_seq = ((UINT32)payload[4] << 24) | ((UINT32)payload[5] << 16) |
                           ((UINT32)payload[6] << 8) | payload[7];
            info.tcp_ack = ((UINT32)payload[8] << 24) | ((UINT32)payload[9] << 16) |
                           ((UINT32)payload[10] << 8) | payload[11];
            info.tcp_flags = payload[13];
            info.tcp_window = ((UINT32)payload[14] << 8) | payload[15];

            UINT32 tcp_hdr_len = ((payload[12] >> 4) & 0xF) * 4;
            if (tcp_hdr_len >= 20 && tcp_hdr_len <= payload_len) {
                const UINT8* app_data = payload + tcp_hdr_len;
                UINT32 app_len = payload_len - tcp_hdr_len;


                info.http_method = detect_http_method(app_data, app_len);
                if (info.http_method) {
                    info.is_http = 1;
                    extract_http_host(app_data, app_len, info.http_host, sizeof(info.http_host));
                    extract_http_path(app_data, app_len, info.http_path, sizeof(info.http_path));
                }


                detect_tls(app_data, app_len, &info);


                if ((src_port == 53 || dst_port == 53) && app_len > 0) {
                    info.is_dns = 1;
                }
            } else {
                _InterlockedIncrement64(&g_dpi_tcp_bounds_rejects);
            }
        }


        if (protocol == 17 && (src_port == 53 || dst_port == 53) && payload_len > 0) {
            info.is_dns = 1;
        }


        if (protocol == 17 && payload_len >= 13) {
            UINT8 ct = payload[0];
            if (ct >= 20 && ct <= 25) {
                UINT16 ver = ((UINT16)payload[1] << 8) | payload[2];
                if (ver == 0xFEFF || ver == 0xFEFD) {
                    info.is_tls = 1;
                    info.tls_content_type = ct;
                    info.tls_version = ver;
                }
            }
        }
        if (info.is_http) _InterlockedIncrement64(&g_dpi_http_hits);
        if (info.is_tls) _InterlockedIncrement64(&g_dpi_tls_hits);
        if (info.is_dns) _InterlockedIncrement64(&g_dpi_dns_hits);

        KIRQL irql;
        KeAcquireSpinLock(&g_dpi_lock, &irql);
        BOOLEAN overwritten = FALSE;
        if (g_dpi_count >= DPI_RING_SIZE) {
            g_dpi_tail = (g_dpi_tail + 1) % DPI_RING_SIZE;
            g_dpi_count--;
            overwritten = TRUE;
        }
        strong::kmemcpy(&g_dpi_ring[g_dpi_head], &info, sizeof(info));
        g_dpi_head = (g_dpi_head + 1) % DPI_RING_SIZE;
        g_dpi_count++;
        KeReleaseSpinLock(&g_dpi_lock, irql);
        _InterlockedIncrement64(&g_dpi_total_enqueued);
        if (overwritten) _InterlockedIncrement64(&g_dpi_total_overwritten);
    }

    NTSTATUS get_results(p_dpi_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        if (!g_dpi_ring) {
            NTSTATUS st = init();
            if (!NT_SUCCESS(st)) return st;
        }
        UINT32 requested_pid = request->filter_pid;
        UINT32 requested_protocol = request->filter_protocol;
        UINT32 requested_port = request->filter_port;
        UINT32 requested_flags = request->flags;
        request->result_count = 0;
        KIRQL irql;
        KeAcquireSpinLock(&g_dpi_lock, &irql);

        LONG entries_to_scan = g_dpi_count;
        UINT32 idx = g_dpi_tail;
        LONG scanned = 0;
        UINT32 reject_pid = 0;
        UINT32 reject_protocol = 0;
        UINT32 reject_port = 0;
        UINT32 reject_http = 0;
        UINT32 reject_tls = 0;
        UINT32 reject_dns = 0;
        while (scanned < entries_to_scan && request->result_count < DPI_MAX_RESULTS) {
            DPI_HEADER_INFO* src = &g_dpi_ring[idx];


            if (request->filter_pid != 0 && src->pid != request->filter_pid) { ++reject_pid; goto next; }
            if (request->filter_protocol != 0 && src->protocol != request->filter_protocol) { ++reject_protocol; goto next; }
            if (request->filter_port != 0 && src->src_port != request->filter_port &&
                src->dst_port != request->filter_port) { ++reject_port; goto next; }
            if (request->flags & 1) { if (!src->is_http) { ++reject_http; goto next; } }
            if (request->flags & 2) { if (!src->is_tls) { ++reject_tls; goto next; } }
            if (request->flags & 4) { if (!src->is_dns) { ++reject_dns; goto next; } }

            strong::kmemcpy(&request->results[request->result_count], src, sizeof(DPI_HEADER_INFO));
            request->result_count++;

        next:
            idx = (idx + 1) % DPI_RING_SIZE;
            scanned++;
        }
        KeReleaseSpinLock(&g_dpi_lock, irql);
        SD_LOG("net_dpi::query filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X active=%ld ring_count_before=%ld scanned=%ld returned=%u reject_pid=%u reject_protocol=%u reject_port=%u reject_http=%u reject_tls=%u reject_dns=%u head=%ld tail=%ld enqueued=%lld overwritten=%lld http_hits=%lld tls_hits=%lld dns_hits=%lld tcp_bounds_rejects=%lld drop_inactive=%lld drop_no_ring=%lld drop_capture_filter=%lld",
            requested_pid,
            requested_protocol,
            requested_port,
            requested_flags,
            g_dpi_active,
            entries_to_scan,
            scanned,
            request->result_count,
            reject_pid,
            reject_protocol,
            reject_port,
            reject_http,
            reject_tls,
            reject_dns,
            g_dpi_head,
            g_dpi_tail,
            _InterlockedCompareExchange64(&g_dpi_total_enqueued, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_total_overwritten, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_http_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_tls_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_dns_hits, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_tcp_bounds_rejects, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_inactive, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_no_ring, 0, 0),
            _InterlockedCompareExchange64(&g_dpi_drop_capture_filter, 0, 0));
        return STATUS_SUCCESS;
    }

    void cleanup() {
        _InterlockedExchange(&g_dpi_active, 0);
        if (g_dpi_ring) {
            ExFreePoolWithTag(g_dpi_ring, 'dpNW');
            g_dpi_ring = nullptr;
        }
    }
}


namespace net_intercept {

    inline HELD_PACKET g_held[INTERCEPT_MAX_HELD] = {};
    inline volatile LONG g_held_count = 0;
    inline volatile LONG g_intercepting = 0;
    inline volatile LONG g_next_hold_id = 1;
    inline volatile LONG g_reject_inactive = 0;
    inline volatile LONG g_reject_pid = 0;
    inline volatile LONG g_reject_port = 0;
    inline volatile LONG g_reject_protocol = 0;
    inline volatile LONG g_reject_full = 0;
    inline volatile LONG g_reject_no_slot = 0;
    inline UINT32 g_filter_pid = 0;
    inline UINT32 g_filter_port = 0;
    inline UINT32 g_filter_protocol = 0;
    inline KSPIN_LOCK g_intercept_lock;

    BOOLEAN is_active() {
        return (g_intercepting != 0);
    }

    void init_lock() {
        KeInitializeSpinLock(&g_intercept_lock);
    }


    BOOLEAN try_hold_packet(UINT32 direction, UINT32 protocol,
                            UINT32 src_port, UINT32 dst_port,
                            const UINT8* src_addr, const UINT8* dst_addr,
                            UINT32 af, UINT32 pid,
                            const UINT8* payload, UINT32 payload_len,
                            UINT32 payload_flags) {
        if (!g_intercepting) {
            _InterlockedIncrement(&g_reject_inactive);
            return FALSE;
        }
        if (g_filter_pid != 0 && pid != g_filter_pid) {
            LONG reject_after = _InterlockedIncrement(&g_reject_pid);
            SD_LOG_PACKET("net_intercept::try_hold reject=pid direction=%u protocol=%u pid=%u filter_pid=%u src_port=%u dst_port=%u payload_len=%u reject_pid=%ld",
                direction, protocol, pid, g_filter_pid, src_port, dst_port, payload_len, reject_after);
            return FALSE;
        }
        if (g_filter_port != 0 && src_port != g_filter_port && dst_port != g_filter_port) {
            LONG reject_after = _InterlockedIncrement(&g_reject_port);
            SD_LOG_PACKET("net_intercept::try_hold reject=port direction=%u protocol=%u pid=%u filter_port=%u src_port=%u dst_port=%u payload_len=%u reject_port=%ld",
                direction, protocol, pid, g_filter_port, src_port, dst_port, payload_len, reject_after);
            return FALSE;
        }
        if (g_filter_protocol != 0 && protocol != g_filter_protocol) {
            LONG reject_after = _InterlockedIncrement(&g_reject_protocol);
            SD_LOG_PACKET("net_intercept::try_hold reject=protocol direction=%u protocol=%u filter_protocol=%u pid=%u src_port=%u dst_port=%u payload_len=%u reject_protocol=%ld",
                direction, protocol, g_filter_protocol, pid, src_port, dst_port, payload_len, reject_after);
            return FALSE;
        }

        KIRQL irql;
        KeAcquireSpinLock(&g_intercept_lock, &irql);

        if (g_held_count >= INTERCEPT_MAX_HELD) {
            LONG held_before = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            LONG reject_after = _InterlockedIncrement(&g_reject_full);
            SD_LOG_PACKET("net_intercept::try_hold reject=full direction=%u protocol=%u pid=%u src_port=%u dst_port=%u payload_len=%u held_before=%ld reject_full=%ld",
                direction, protocol, pid, src_port, dst_port, payload_len, held_before, reject_after);
            return FALSE;
        }


        for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
            if (g_held[i].hold_id == 0) {
                LONG held_before = g_held_count;
                g_held[i].hold_id = (UINT64)_InterlockedIncrement(&g_next_hold_id);
                LARGE_INTEGER ts;
                KeQuerySystemTime(&ts);
                g_held[i].timestamp = ts.QuadPart;
                g_held[i].direction = direction;
                g_held[i].protocol = protocol;
                g_held[i].src_port = src_port;
                g_held[i].dst_port = dst_port;
                strong::kmemcpy(g_held[i].src_addr, src_addr, 16);
                strong::kmemcpy(g_held[i].dst_addr, dst_addr, 16);
                g_held[i].pid = pid;
                g_held[i].address_family = af;
                UINT32 cap = payload_len < INTERCEPT_MAX_PAYLOAD ? payload_len : INTERCEPT_MAX_PAYLOAD;
                g_held[i].payload_size = cap;
                if (payload && cap > 0)
                    strong::kmemcpy(g_held[i].payload, payload, cap);
                g_held[i].padding = payload_flags;
                g_held_count++;
                UINT64 hold_id = g_held[i].hold_id;
                LONG held_after = g_held_count;
                KeReleaseSpinLock(&g_intercept_lock, irql);
                SD_LOG_PACKET("net_intercept::try_hold held hold_id=%llu slot=%u direction=%u protocol=%u pid=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u payload_len=%u stored_len=%u flags=0x%08X held_before=%ld held_after=%ld",
                    (unsigned long long)hold_id,
                    i,
                    direction,
                    protocol,
                    pid,
                    src_addr ? src_addr[0] : 0, src_addr ? src_addr[1] : 0, src_addr ? src_addr[2] : 0, src_addr ? src_addr[3] : 0, src_port,
                    dst_addr ? dst_addr[0] : 0, dst_addr ? dst_addr[1] : 0, dst_addr ? dst_addr[2] : 0, dst_addr ? dst_addr[3] : 0, dst_port,
                    payload_len,
                    cap,
                    payload_flags,
                    held_before,
                    held_after);
                return TRUE;
            }
        }

        KeReleaseSpinLock(&g_intercept_lock, irql);
        LONG reject_after = _InterlockedIncrement(&g_reject_no_slot);
        SD_LOG_PACKET("net_intercept::try_hold reject=no_slot direction=%u protocol=%u pid=%u src_port=%u dst_port=%u payload_len=%u reject_no_slot=%ld",
            direction, protocol, pid, src_port, dst_port, payload_len, reject_after);
        return FALSE;
    }

    static BOOLEAN build_inject_from_held(const HELD_PACKET* held, packet_inject_request* inj,
                                          const UINT8* override_payload, UINT32 override_size) {
        if (!held || !inj) return FALSE;
        UINT32 payload_size = override_payload ? override_size : held->payload_size;
        if (payload_size == 0 || payload_size > INTERCEPT_MAX_PAYLOAD)
            return FALSE;
        strong::kmemset(inj, 0, sizeof(*inj));
        inj->direction = held->direction;
        inj->protocol = held->protocol;
        inj->address_family = held->address_family;
        inj->src_port = held->src_port;
        inj->dst_port = held->dst_port;
        strong::kmemcpy(inj->src_addr, held->src_addr, 16);
        strong::kmemcpy(inj->dst_addr, held->dst_addr, 16);
        inj->tcp_flags = held->padding;
        inj->payload_size = payload_size;
        strong::kmemcpy(inj->payload, override_payload ? override_payload : held->payload, payload_size);
        return TRUE;
    }

    static NTSTATUS release_held_packet(const HELD_PACKET* held, const char* reason) {
        if (!held || held->hold_id == 0)
            return STATUS_INVALID_PARAMETER;

        LARGE_INTEGER now;
        KeQuerySystemTime(&now);
        ULONGLONG age_ms = 0;
        if (now.QuadPart >= (LONGLONG)held->timestamp)
            age_ms = (ULONGLONG)((now.QuadPart - (LONGLONG)held->timestamp) / 10000);

        packet_inject_request inj = {};
        BOOLEAN inject_ready = build_inject_from_held(held, &inj, nullptr, 0);
        NTSTATUS inject_status = inject_ready ? net_inject::inject_packet(&inj) : STATUS_INVALID_PARAMETER;
        SD_LOG("net_intercept::release_held reason=%s hold_id=%llu pid=%u direction=%u protocol=%u src_port=%u dst_port=%u payload_size=%u flags=0x%08X age_ms=%llu inject_ready=%u inject_status=0x%08X request_status=%u",
            reason ? reason : "",
            (unsigned long long)held->hold_id,
            held->pid,
            held->direction,
            held->protocol,
            held->src_port,
            held->dst_port,
            held->payload_size,
            held->padding,
            age_ms,
            inject_ready ? 1u : 0u,
            inject_status,
            inj.status);
        return inject_status;
    }

    NTSTATUS handle_intercept(p_intercept_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            if (request->filter_pid == 0 && request->filter_port == 0 &&
                request->filter_protocol == 0) {
                SD_LOG("net_intercept::handle op=0 rejected wildcard status=0x%08X held_count=%ld intercepting=%ld",
                    (UINT32)STATUS_INVALID_PARAMETER,
                    g_held_count,
                    g_intercepting);
                return STATUS_INVALID_PARAMETER;
            }
            g_filter_pid = request->filter_pid;
            g_filter_port = request->filter_port;
            g_filter_protocol = request->filter_protocol;
            _InterlockedExchange(&g_reject_inactive, 0);
            _InterlockedExchange(&g_reject_pid, 0);
            _InterlockedExchange(&g_reject_port, 0);
            _InterlockedExchange(&g_reject_protocol, 0);
            _InterlockedExchange(&g_reject_full, 0);
            _InterlockedExchange(&g_reject_no_slot, 0);
            _InterlockedExchange(&g_intercepting, 1);
            request->intercepting = 1;
            request->held_count = g_held_count;
            SD_LOG("net_intercept::handle op=0 start filter_pid=%u filter_protocol=%u filter_port=%u held_count=%u intercepting=%u status=0x%08X",
                request->filter_pid,
                request->filter_protocol,
                request->filter_port,
                request->held_count,
                request->intercepting,
                (UINT32)STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }
        case 1: {
            LONG held_before = g_held_count;
            SIZE_T release_bytes = sizeof(HELD_PACKET) * INTERCEPT_MAX_HELD;
            HELD_PACKET* release_list = (HELD_PACKET*)ExAllocatePool2(POOL_FLAG_NON_PAGED, release_bytes, 'lhNW');
            if (!release_list) {
                SD_LOG("net_intercept::handle op=1 stop allocation_failed bytes=%llu held_before=%ld status=0x%08X",
                    (ULONGLONG)release_bytes,
                    held_before,
                    (UINT32)STATUS_INSUFFICIENT_RESOURCES);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            strong::kmemset(release_list, 0, release_bytes);
            UINT32 release_count = 0;
            _InterlockedExchange(&g_intercepting, 0);
            g_filter_pid = 0;
            g_filter_port = 0;
            g_filter_protocol = 0;

            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id != 0 && release_count < INTERCEPT_MAX_HELD) {
                    strong::kmemcpy(&release_list[release_count], &g_held[i], sizeof(HELD_PACKET));
                    ++release_count;
                }
                strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
            }
            g_held_count = 0;
            KeReleaseSpinLock(&g_intercept_lock, irql);

            UINT32 release_success = 0;
            UINT32 release_failed = 0;
            for (UINT32 i = 0; i < release_count; ++i) {
                NTSTATUS release_status = release_held_packet(&release_list[i], "disable");
                if (NT_SUCCESS(release_status)) ++release_success;
                else ++release_failed;
            }
            ExFreePoolWithTag(release_list, 'lhNW');
            request->intercepting = 0;
            request->held_count = 0;
            SD_LOG("net_intercept::handle op=1 stop held_before=%ld copied=%u released_ok=%u released_failed=%u held_after=%u intercepting=%u status=0x%08X rejects inactive=%ld pid=%ld port=%ld protocol=%ld full=%ld no_slot=%ld",
                held_before,
                release_count,
                release_success,
                release_failed,
                request->held_count,
                request->intercepting,
                (UINT32)STATUS_SUCCESS,
                g_reject_inactive,
                g_reject_pid,
                g_reject_port,
                g_reject_protocol,
                g_reject_full,
                g_reject_no_slot);
            return STATUS_SUCCESS;
        }
        case 2: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            LONG held_before = g_held_count;
            request->held_count = 0;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id != 0 && request->held_count < INTERCEPT_MAX_HELD) {
                    strong::kmemcpy(&request->held_packets[request->held_count],
                                    &g_held[i], sizeof(HELD_PACKET));
                    request->held_count++;
                }
            }
            request->intercepting = g_intercepting;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            SD_LOG("net_intercept::handle op=2 list filter_pid=%u filter_protocol=%u filter_port=%u held_before=%ld output_count=%u intercepting=%u status=0x%08X rejects inactive=%ld pid=%ld port=%ld protocol=%ld full=%ld no_slot=%ld",
                g_filter_pid,
                g_filter_protocol,
                g_filter_port,
                held_before,
                request->held_count,
                request->intercepting,
                (UINT32)STATUS_SUCCESS,
                g_reject_inactive,
                g_reject_pid,
                g_reject_port,
                g_reject_protocol,
                g_reject_full,
                g_reject_no_slot);
            return STATUS_SUCCESS;
        }
        case 3: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            packet_inject_request inj = {};
            BOOLEAN do_inject = FALSE;
            BOOLEAN found = FALSE;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    found = TRUE;

                    if (net_inject::g_inject_handle_v4 && g_held[i].payload_size > 0) {
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.tcp_flags = g_held[i].padding;
                        inj.payload_size = g_held[i].payload_size;
                        strong::kmemcpy(inj.payload, g_held[i].payload, g_held[i].payload_size);
                        do_inject = TRUE;
                    }
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            NTSTATUS inject_status = STATUS_NOT_FOUND;
            if (do_inject) {
                inject_status = net_inject::inject_packet(&inj);
            }
            SD_LOG("net_intercept::handle op=3 forward hold_id=%llu found=%u injected=%u inject_status=0x%08X request_status=%u flags=0x%08X held_count=%u status=0x%08X",
                (ULONGLONG)request->hold_id,
                found ? 1u : 0u,
                do_inject ? 1u : 0u,
                (UINT32)inject_status,
                inj.status,
                inj.tcp_flags,
                request->held_count,
                (UINT32)STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }
        case 4: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            BOOLEAN found = FALSE;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    found = TRUE;
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            SD_LOG("net_intercept::handle op=4 drop hold_id=%llu found=%u held_count=%u status=0x%08X",
                (ULONGLONG)request->hold_id,
                found ? 1u : 0u,
                request->held_count,
                (UINT32)STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }
        case 5: {
            KIRQL irql;
            KeAcquireSpinLock(&g_intercept_lock, &irql);
            packet_inject_request inj = {};
            BOOLEAN do_inject = FALSE;
            BOOLEAN found = FALSE;
            for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
                if (g_held[i].hold_id == request->hold_id) {
                    found = TRUE;

                    if (net_inject::g_inject_handle_v4 && request->modify_payload_size > 0 &&
                        request->modify_payload_size <= INTERCEPT_MAX_PAYLOAD) {
                        inj.direction = g_held[i].direction;
                        inj.protocol = g_held[i].protocol;
                        inj.address_family = g_held[i].address_family;
                        inj.src_port = g_held[i].src_port;
                        inj.dst_port = g_held[i].dst_port;
                        strong::kmemcpy(inj.src_addr, g_held[i].src_addr, 16);
                        strong::kmemcpy(inj.dst_addr, g_held[i].dst_addr, 16);
                        inj.tcp_flags = g_held[i].padding;
                        inj.payload_size = request->modify_payload_size;
                        strong::kmemcpy(inj.payload, request->modify_payload, request->modify_payload_size);
                        do_inject = TRUE;
                    }
                    g_held[i].hold_id = 0;
                    strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
                    if (g_held_count > 0) g_held_count--;
                    break;
                }
            }
            request->held_count = g_held_count;
            KeReleaseSpinLock(&g_intercept_lock, irql);
            NTSTATUS inject_status = STATUS_NOT_FOUND;
            if (do_inject) {
                inject_status = net_inject::inject_packet(&inj);
            }
            SD_LOG("net_intercept::handle op=5 modify hold_id=%llu found=%u injected=%u inject_status=0x%08X request_status=%u flags=0x%08X modify_size=%u held_count=%u status=0x%08X",
                (ULONGLONG)request->hold_id,
                found ? 1u : 0u,
                do_inject ? 1u : 0u,
                (UINT32)inject_status,
                inj.status,
                inj.tcp_flags,
                request->modify_payload_size,
                request->held_count,
                (UINT32)STATUS_SUCCESS);
            return STATUS_SUCCESS;
        }
        default:
            SD_LOG("net_intercept::handle invalid op=%u status=0x%08X held_count=%ld intercepting=%ld",
                request->operation,
                (UINT32)STATUS_INVALID_PARAMETER,
                g_held_count,
                g_intercepting);
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_intercepting, 0);
        g_filter_pid = 0;
        g_filter_port = 0;
        g_filter_protocol = 0;
        _InterlockedExchange(&g_reject_inactive, 0);
        _InterlockedExchange(&g_reject_pid, 0);
        _InterlockedExchange(&g_reject_port, 0);
        _InterlockedExchange(&g_reject_protocol, 0);
        _InterlockedExchange(&g_reject_full, 0);
        _InterlockedExchange(&g_reject_no_slot, 0);

        KIRQL irql;
        KeAcquireSpinLock(&g_intercept_lock, &irql);
        for (UINT32 i = 0; i < INTERCEPT_MAX_HELD; i++) {
            strong::kmemset(&g_held[i], 0, sizeof(HELD_PACKET));
        }
        g_held_count = 0;
        KeReleaseSpinLock(&g_intercept_lock, irql);
    }
}


namespace net_kill {

    typedef struct _TCP_RESET_CANDIDATES {
        BOOLEAN have_forward;
        BOOLEAN have_reverse;
        DPI_HEADER_INFO forward;
        DPI_HEADER_INFO reverse;
    } TCP_RESET_CANDIDATES;

    static __forceinline UINT32 tuple_addr_len(UINT32 address_family) {
        return (address_family == AF_INET6) ? 16u : 4u;
    }

    static BOOLEAN request_ip_is_zero(const UINT8* ip, UINT32 address_family) {
        UINT32 len = tuple_addr_len(address_family);
        for (UINT32 i = 0; i < len; i++) {
            if (ip[i] != 0) {
                return FALSE;
            }
        }
        return TRUE;
    }

    static BOOLEAN tuple_ip_matches(const UINT8* actual,
                                    const UINT8* expected,
                                    UINT32 address_family) {
        if (!actual || !expected) {
            return FALSE;
        }

        if (request_ip_is_zero(expected, address_family)) {
            return TRUE;
        }

        UINT32 len = tuple_addr_len(address_family);
        if (slop_ip_bytes_equal(actual, expected, len)) {
            return TRUE;
        }

        if (address_family == AF_INET && len == 4) {
            UINT8 swapped[4] = { actual[3], actual[2], actual[1], actual[0] };
            return slop_ip_bytes_equal(swapped, expected, 4);
        }

        return FALSE;
    }

    static BOOLEAN dpi_tuple_matches_request(const DPI_HEADER_INFO* info,
                                             const conn_kill_request* request,
                                             BOOLEAN reverse) {
        if (!info || !request || info->protocol != IPPROTO_TCP) {
            return FALSE;
        }

        UINT32 address_family = request->address_family != 0 ? request->address_family : info->address_family;
        if (!reverse) {
            if (request->src_port != 0 && info->src_port != request->src_port) return FALSE;
            if (request->dst_port != 0 && info->dst_port != request->dst_port) return FALSE;
            if (!tuple_ip_matches(info->src_addr, request->src_addr, address_family)) return FALSE;
            if (!tuple_ip_matches(info->dst_addr, request->dst_addr, address_family)) return FALSE;
        } else {
            if (request->src_port != 0 && info->dst_port != request->src_port) return FALSE;
            if (request->dst_port != 0 && info->src_port != request->dst_port) return FALSE;
            if (!tuple_ip_matches(info->dst_addr, request->src_addr, address_family)) return FALSE;
            if (!tuple_ip_matches(info->src_addr, request->dst_addr, address_family)) return FALSE;
        }

        return TRUE;
    }

    static BOOLEAN find_recent_reset_candidates(p_conn_kill_request request,
                                                TCP_RESET_CANDIDATES* out) {
        if (!request || !out || !net_dpi::g_dpi_ring || net_dpi::g_dpi_count <= 0) {
            return FALSE;
        }

        strong::kmemset(out, 0, sizeof(*out));

        KIRQL irql;
        KeAcquireSpinLock(&net_dpi::g_dpi_lock, &irql);

        LONG entries = net_dpi::g_dpi_count;
        LONG idx = net_dpi::g_dpi_head;
        for (LONG scanned = 0; scanned < entries && (!out->have_forward || !out->have_reverse); scanned++) {
            if (idx == 0) {
                idx = DPI_RING_SIZE;
            }
            idx--;

            const DPI_HEADER_INFO* info = &net_dpi::g_dpi_ring[idx];
            if (!out->have_forward && dpi_tuple_matches_request(info, request, FALSE)) {
                strong::kmemcpy(&out->forward, info, sizeof(*info));
                out->have_forward = TRUE;
            }
            if (!out->have_reverse && dpi_tuple_matches_request(info, request, TRUE)) {
                strong::kmemcpy(&out->reverse, info, sizeof(*info));
                out->have_reverse = TRUE;
            }
        }

        KeReleaseSpinLock(&net_dpi::g_dpi_lock, irql);

        if (!out->have_forward && !out->have_reverse) {
            KIRQL dbg_irql;
            KeAcquireSpinLock(&net_dpi::g_dpi_lock, &dbg_irql);
            LONG dbg_entries = net_dpi::g_dpi_count;
            LONG dbg_idx = net_dpi::g_dpi_head;
            UINT32 dumped = 0;
            for (LONG scanned = 0; scanned < dbg_entries && dumped < 6; scanned++) {
                if (dbg_idx == 0) {
                    dbg_idx = DPI_RING_SIZE;
                }
                dbg_idx--;

                const DPI_HEADER_INFO* info = &net_dpi::g_dpi_ring[dbg_idx];
                if (info->protocol != IPPROTO_TCP) {
                    continue;
                }

                if (info->address_family == AF_INET) {
                } else {
                }

                dumped++;
            }
            KeReleaseSpinLock(&net_dpi::g_dpi_lock, dbg_irql);
        }

        return out->have_forward || out->have_reverse;
    }

    static NTSTATUS inject_reset_from_dpi_entry(const DPI_HEADER_INFO* info,
                                                UINT32 direction) {
        if (!info || (info->tcp_flags & 0x10u) == 0 || info->tcp_ack == 0) {
            return STATUS_NOT_FOUND;
        }

        packet_inject_request inj = {};
        inj.direction = direction;
        inj.protocol = IPPROTO_TCP;
        inj.address_family = info->address_family;
        inj.src_port = info->dst_port;
        inj.dst_port = info->src_port;
        inj.payload_size = 0;
        inj.tcp_flags = 0x04;
        inj.tcp_seq = info->tcp_ack;
        inj.tcp_ack = 0;
        strong::kmemcpy(inj.src_addr, info->dst_addr, 16);
        strong::kmemcpy(inj.dst_addr, info->src_addr, 16);
        return net_inject::inject_packet(&inj);
    }

    static NTSTATUS inject_tcp_reset_fallback(p_conn_kill_request request) {
        TCP_RESET_CANDIDATES candidates = {};
        if (!find_recent_reset_candidates(request, &candidates)) {
            return STATUS_NOT_FOUND;
        }

        NTSTATUS last_status = STATUS_NOT_FOUND;
        BOOLEAN injected = FALSE;

        if (candidates.have_forward) {
            last_status = inject_reset_from_dpi_entry(&candidates.forward, 0);
            if (NT_SUCCESS(last_status)) {
                injected = TRUE;
            } else {
            }
        }

        if (candidates.have_reverse) {
            NTSTATUS reverse_status = inject_reset_from_dpi_entry(&candidates.reverse, 1);
            if (NT_SUCCESS(reverse_status)) {
                injected = TRUE;
            } else {
                if (!NT_SUCCESS(last_status)) {
                    last_status = reverse_status;
                }
            }
        }

        return injected ? STATUS_SUCCESS : last_status;
    }

    static BOOLEAN socket_matches_kill_request(const SOCKET_HANDLE_ENTRY* socket_info,
                                               const conn_kill_request* request) {
        if (!socket_info || !request)
            return FALSE;

        if (request->protocol != 0 && socket_info->protocol != 0 && socket_info->protocol != request->protocol)
            return FALSE;

        BOOLEAN src_match = FALSE;
        BOOLEAN dst_match = FALSE;
        if (request->src_port != 0) {
            src_match = (socket_info->local_port == request->src_port) ||
                        (socket_info->remote_port == request->src_port);
        }
        if (request->dst_port != 0) {
            dst_match = (socket_info->local_port == request->dst_port) ||
                        (socket_info->remote_port == request->dst_port);
        }

        if (request->src_port != 0 && request->dst_port != 0) {
            if (socket_info->local_port == 0)
                return FALSE;

            if (socket_info->remote_port != 0)
                return (src_match && dst_match) ? TRUE : FALSE;

            return socket_info->local_port == request->src_port ? TRUE : FALSE;
        }

        if (request->src_port != 0)
            return src_match;
        if (request->dst_port != 0)
            return dst_match;

        return TRUE;
    }


    static UINT32 resolve_owner_pid_by_tuple(p_conn_kill_request request) {
        if (!request)
            return 0;


        if (request->protocol == 6 && net_enum::resolve_nsi()) {
            UINT32 tcp_capacity = 4096;
            UINT32 tcp_count = 0;
            NTSTATUS st = STATUS_UNSUCCESSFUL;
            UINT8* buf = nullptr;

            for (UINT32 attempt = 0; attempt < 8; attempt++) {
                tcp_count = tcp_capacity;
                ULONG key_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_KEY);
                ULONG sta_sz = tcp_capacity * sizeof(net_enum::NSI_TCP_STATIC);

                buf = static_cast<UINT8*>(
                    ExAllocatePool2(POOL_FLAG_NON_PAGED, key_sz + sta_sz, 'klNW'));
                if (!buf) break;

                auto* keys = reinterpret_cast<net_enum::NSI_TCP_KEY*>(buf);
                auto* stats = reinterpret_cast<net_enum::NSI_TCP_STATIC*>(buf + key_sz);


                st = net_enum::_NsiEnumerate(
                    net_enum::NSI_QUERY_RUNTIME, net_enum::NSI_STORE_ACTIVE, (PVOID)net_enum::NPI_MS_TCP_MODULEID,
                    3, keys, sizeof(net_enum::NSI_TCP_KEY),
                    nullptr, 0,
                    nullptr, 0,
                    stats, sizeof(net_enum::NSI_TCP_STATIC),
                    &tcp_count);


                if (NT_SUCCESS(st) || st == STATUS_BUFFER_OVERFLOW ||
                    st == STATUS_BUFFER_TOO_SMALL || st == static_cast<NTSTATUS>(0xC0000023)) {
                    for (UINT32 i = 0; i < tcp_count; i++) {
                        UINT32 lport = ((keys[i].local.port_be >> 8) & 0xFF) | ((keys[i].local.port_be & 0xFF) << 8);
                        UINT32 rport = ((keys[i].remote.port_be >> 8) & 0xFF) | ((keys[i].remote.port_be & 0xFF) << 8);

                        BOOLEAN match = TRUE;
                        if (request->src_port != 0 && lport != request->src_port) match = FALSE;
                        if (match && request->dst_port != 0 && rport != request->dst_port) match = FALSE;

                        if (match && static_cast<UINT32>(stats[i].mod_pid) != 0) {
                            UINT32 pid = static_cast<UINT32>(stats[i].mod_pid);
                            ExFreePoolWithTag(buf, 'klNW');
                            return pid;
                        }
                    }
                }

                if (NT_SUCCESS(st)) {
                    ExFreePoolWithTag(buf, 'klNW');
                    break;
                }

                ExFreePoolWithTag(buf, 'klNW');
                buf = nullptr;
                if (st == STATUS_BUFFER_OVERFLOW || st == STATUS_BUFFER_TOO_SMALL ||
                    st == static_cast<NTSTATUS>(0xC0000023)) {
                    UINT32 next = (tcp_count > tcp_capacity) ? tcp_count + 64 : tcp_capacity * 2;
                    if (next > 65536) next = 65536;
                    if (next == tcp_capacity) break;
                    tcp_capacity = next;
                    continue;
                }
                break;
            }
        }

        return 0;
    }


    static NTSTATUS close_matching_socket(UINT32 owner_pid, p_conn_kill_request request) {
        if (!slop_can_query_system_handles())
            return STATUS_INVALID_DEVICE_STATE;

        PSLOP_SYSTEM_HANDLE_INFORMATION handles = nullptr;
        NTSTATUS status = slop_query_system_handles(&handles);
        if (!NT_SUCCESS(status) || !handles) {
            return status;
        }


        constexpr UINT32 MAX_HANDLES_TO_CHECK = 4096;
        USHORT* pid_handles = static_cast<USHORT*>(
            ExAllocatePool2(POOL_FLAG_NON_PAGED, MAX_HANDLES_TO_CHECK * sizeof(USHORT), 'khNW'));
        if (!pid_handles) {
            ExFreePoolWithTag(handles, 'hANW');
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        UINT32 count = 0;
        for (ULONG i = 0; i < handles->NumberOfHandles && count < MAX_HANDLES_TO_CHECK; i++) {
            if (static_cast<UINT32>(handles->Handles[i].UniqueProcessId) == owner_pid) {
                pid_handles[count++] = handles->Handles[i].HandleValue;
            }
        }
        ExFreePoolWithTag(handles, 'hANW');

        if (count == 0) {
            ExFreePoolWithTag(pid_handles, 'khNW');
            return STATUS_NOT_FOUND;
        }

        PEPROCESS process = nullptr;
        status = _PsLookupProcessByProcessId
            ? _PsLookupProcessByProcessId(
                reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(owner_pid)), &process)
            : STATUS_NOT_SUPPORTED;
        if (!NT_SUCCESS(status) || !process) {
            ExFreePoolWithTag(pid_handles, 'khNW');
            return status;
        }


        (void)afd_get_offsets();

        NTSTATUS close_status = STATUS_NOT_FOUND;
        KAPC_STATE apc = {};
        KeStackAttachProcess(process, &apc);

        __try {
            for (UINT32 i = 0; i < count; i++) {
                HANDLE h = reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid_handles[i]));

                PVOID file_obj = nullptr;
                NTSTATUS ref_st = ObReferenceObjectByHandle(
                    h, 0,
                    (_IoFileObjectType && *_IoFileObjectType) ? *_IoFileObjectType : nullptr,
                    KernelMode, &file_obj, nullptr);
                if (!NT_SUCCESS(ref_st) || !file_obj)
                    continue;

                PFILE_OBJECT fo = static_cast<PFILE_OBJECT>(file_obj);
                if (!slop_is_afd_file_object(fo)) {
                    ObDereferenceObject(fo);
                    continue;
                }

                SOCKET_HANDLE_ENTRY socket_info = {};
                BOOLEAN ok = slop_extract_socket_info_from_fo(fo, &socket_info);
                ObDereferenceObject(fo);
                if (!ok)
                    continue;

                BOOLEAN match = socket_matches_kill_request(&socket_info, request);
                SD_LOG("netaction::net_kill::close_matching_socket candidate pid=%u handle=0x%llX proto=%u state=%u local_port=%u remote_port=%u req_src=%u req_dst=%u match=%u",
                    owner_pid,
                    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(h)),
                    socket_info.protocol,
                    socket_info.state,
                    socket_info.local_port,
                    socket_info.remote_port,
                    request->src_port,
                    request->dst_port,
                    match ? 1u : 0u);

                if (!match)
                    continue;

                close_status = ZwClose(h);
                SD_LOG("netaction::net_kill::close_matching_socket close pid=%u handle=0x%llX status=0x%08X",
                    owner_pid,
                    static_cast<unsigned long long>(reinterpret_cast<ULONG_PTR>(h)),
                    close_status);
                if (NT_SUCCESS(close_status))
                    break;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            close_status = STATUS_ACCESS_VIOLATION;
        }

        KeUnstackDetachProcess(&apc);
        if (_ObfDereferenceObject) _ObfDereferenceObject(process);
        ExFreePoolWithTag(pid_handles, 'khNW');
        return close_status;
    }


    static NTSTATUS resolve_and_close_socket(p_conn_kill_request request) {
        UINT32 owner_pid = resolve_owner_pid_by_tuple(request);
        if (owner_pid == 0)
            return STATUS_NOT_FOUND;

        return close_matching_socket(owner_pid, request);
    }

    NTSTATUS kill_connection(p_conn_kill_request request) {
        if (!request) {
            SD_LOG("netaction::net_kill::kill_connection NULL_REQUEST status=STATUS_INVALID_PARAMETER");
            return STATUS_INVALID_PARAMETER;
        }
        request->status = 1;

        SD_LOG("netaction::net_kill::kill_connection ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u",
            request->protocol, request->address_family,
            request->src_port, request->dst_port, request->pid);

        if (request->protocol != 6) {
            SD_LOG("netaction::net_kill::kill_connection unsupported_protocol protocol=%u status=STATUS_INVALID_PARAMETER",
                request->protocol);
            return STATUS_INVALID_PARAMETER;
        }

        UINT32 owner_pid = request->pid;
        if (owner_pid != 0) {
            SD_LOG("netaction::net_kill::kill_connection path=pid_provided owner_pid=%u", owner_pid);
            NTSTATUS st = close_matching_socket(owner_pid, request);
            SD_LOG("netaction::net_kill::kill_connection close_matching_socket(pid=%u) returned=0x%08X",
                owner_pid, st);
            if (NT_SUCCESS(st)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            NTSTATUS rst_status = inject_tcp_reset_fallback(request);
            SD_LOG("netaction::net_kill::kill_connection inject_tcp_reset_fallback returned=0x%08X",
                rst_status);
            if (NT_SUCCESS(rst_status)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
            NTSTATUS final_st = NT_SUCCESS(st) ? rst_status : st;
            SD_LOG("netaction::net_kill::kill_connection EXIT final_status=0x%08X", final_st);
            return final_st;
        }

        SD_LOG("netaction::net_kill::kill_connection path=tuple_resolve");
        owner_pid = resolve_owner_pid_by_tuple(request);
        SD_LOG("netaction::net_kill::kill_connection resolve_owner_pid_by_tuple returned=%u", owner_pid);
        if (owner_pid != 0) {
            NTSTATUS st_close = close_matching_socket(owner_pid, request);
            SD_LOG("netaction::net_kill::kill_connection close_matching_socket(resolved_pid=%u) returned=0x%08X",
                owner_pid, st_close);
            if (NT_SUCCESS(st_close)) {
                request->status = 0;
                return STATUS_SUCCESS;
            }
        }

        NTSTATUS st = resolve_and_close_socket(request);
        SD_LOG("netaction::net_kill::kill_connection resolve_and_close_socket returned=0x%08X", st);
        if (NT_SUCCESS(st)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }

        NTSTATUS rst_status = inject_tcp_reset_fallback(request);
        SD_LOG("netaction::net_kill::kill_connection inject_tcp_reset_fallback returned=0x%08X",
            rst_status);
        if (NT_SUCCESS(rst_status)) {
            request->status = 0;
            return STATUS_SUCCESS;
        }
        NTSTATUS final_st = NT_SUCCESS(st) ? rst_status : st;
        SD_LOG("netaction::net_kill::kill_connection EXIT final_status=0x%08X", final_st);
        return final_st;
    }
}


namespace net_dns_spoof {

    typedef struct _DNS_SPOOF_ACTIVE {
        volatile LONG active;
        UINT32 rule_id;
        char domain[DNS_SPOOF_MAX_DOMAIN];
        UINT8 spoof_addr[16];
        UINT32 address_family;
        UINT32 ttl;
        volatile LONG match_count;
    } DNS_SPOOF_ACTIVE;

    inline DNS_SPOOF_ACTIVE g_spoof_rules[DNS_SPOOF_MAX_RULES] = {};
    inline volatile LONG g_next_spoof_id = 1;
    inline volatile LONG g_active_spoof_count = 0;

    BOOLEAN has_active_rules() {
        return (g_active_spoof_count != 0);
    }


    static BOOLEAN domain_matches(const char* pattern, const char* domain) {
        if (!pattern || !domain) return FALSE;
        if (pattern[0] == '*' && pattern[1] == '.') {

            const char* suffix = pattern + 1;
            UINT32 slen = 0, dlen = 0;
            while (suffix[slen]) slen++;
            while (domain[dlen]) dlen++;
            if (dlen < slen) return FALSE;

            for (UINT32 i = 0; i < slen; i++) {
                char a = suffix[slen - 1 - i];
                char b = domain[dlen - 1 - i];
                if (a >= 'A' && a <= 'Z') a += 32;
                if (b >= 'A' && b <= 'Z') b += 32;
                if (a != b) return FALSE;
            }
            return TRUE;
        }

        UINT32 i = 0;
        while (pattern[i] && domain[i]) {
            char a = pattern[i], b = domain[i];
            if (a >= 'A' && a <= 'Z') a += 32;
            if (b >= 'A' && b <= 'Z') b += 32;
            if (a != b) return FALSE;
            i++;
        }
        return (pattern[i] == 0 && domain[i] == 0);
    }


    BOOLEAN inspect_spoof_rule(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl,
                               UINT32* out_rule_id, char* out_rule_domain, UINT32 out_rule_domain_len,
                               LONG* match_before, LONG* match_after, BOOLEAN increment_match) {
        if (out_rule_id) *out_rule_id = 0;
        if (out_rule_domain && out_rule_domain_len != 0) out_rule_domain[0] = '\0';
        if (match_before) *match_before = 0;
        if (match_after) *match_after = 0;
        if (g_active_spoof_count == 0) return FALSE;
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
            if (g_spoof_rules[i].active != 1) continue;
            if (domain_matches(g_spoof_rules[i].domain, domain)) {
                if (out_addr) strong::kmemcpy(out_addr, g_spoof_rules[i].spoof_addr, 16);
                if (out_af) *out_af = g_spoof_rules[i].address_family;
                if (out_ttl) *out_ttl = g_spoof_rules[i].ttl;
                if (out_rule_id) *out_rule_id = g_spoof_rules[i].rule_id;
                if (out_rule_domain && out_rule_domain_len != 0) {
                    UINT32 j = 0;
                    while (j + 1 < out_rule_domain_len && j < DNS_SPOOF_MAX_DOMAIN && g_spoof_rules[i].domain[j]) {
                        out_rule_domain[j] = g_spoof_rules[i].domain[j];
                        ++j;
                    }
                    out_rule_domain[j] = '\0';
                }
                LONG before = _InterlockedCompareExchange(&g_spoof_rules[i].match_count, 0, 0);
                LONG after = before;
                if (increment_match) {
                    after = _InterlockedIncrement(&g_spoof_rules[i].match_count);
                }
                if (match_before) *match_before = before;
                if (match_after) *match_after = after;
                return TRUE;
            }
        }
        return FALSE;
    }

    BOOLEAN check_spoof(const char* domain, UINT8* out_addr, UINT32* out_af, UINT32* out_ttl) {
        return inspect_spoof_rule(domain, out_addr, out_af, out_ttl,
            nullptr, nullptr, 0, nullptr, nullptr, TRUE);
    }

    NTSTATUS handle_spoof_rule(p_dns_spoof_rule request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (_InterlockedCompareExchange(&g_spoof_rules[i].active, 2, 0) == 0) {
                    UINT32 id = (UINT32)_InterlockedIncrement(&g_next_spoof_id);
                    g_spoof_rules[i].rule_id = id;
                    strong::kmemcpy(g_spoof_rules[i].domain, request->domain, DNS_SPOOF_MAX_DOMAIN);
                    strong::kmemcpy(g_spoof_rules[i].spoof_addr, request->spoof_addr, 16);
                    g_spoof_rules[i].address_family = request->address_family;
                    g_spoof_rules[i].ttl = request->ttl ? request->ttl : 300;
                    g_spoof_rules[i].match_count = 0;
                    KeMemoryBarrier();
                    _InterlockedExchange(&g_spoof_rules[i].active, 1);
                    _InterlockedIncrement(&g_active_spoof_count);
                    request->rule_id = id;
                    request->active = 1;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        case 1: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (g_spoof_rules[i].active == 1 && g_spoof_rules[i].rule_id == request->rule_id) {
                    _InterlockedExchange(&g_spoof_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_spoof_count);
                    request->active = 0;
                    return STATUS_SUCCESS;
                }
            }
            return STATUS_NOT_FOUND;
        }
        case 3: {
            for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
                if (g_spoof_rules[i].active == 1) {
                    _InterlockedExchange(&g_spoof_rules[i].active, 0);
                    _InterlockedDecrement(&g_active_spoof_count);
                }
            }
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    NTSTATUS handle_spoof_list(p_dns_spoof_list request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->rule_count = 0;
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES && request->rule_count < DNS_SPOOF_MAX_RULES; i++) {
            if (g_spoof_rules[i].active == 1) {
                DNS_SPOOF_RULE* out = &request->rules[request->rule_count];
                out->rule_id = g_spoof_rules[i].rule_id;
                strong::kmemcpy(out->domain, g_spoof_rules[i].domain, DNS_SPOOF_MAX_DOMAIN);
                strong::kmemcpy(out->spoof_addr, g_spoof_rules[i].spoof_addr, 16);
                out->address_family = g_spoof_rules[i].address_family;
                out->ttl = g_spoof_rules[i].ttl;
                out->match_count = g_spoof_rules[i].match_count;
                out->active = 1;
                request->rule_count++;
            }
        }
        return STATUS_SUCCESS;
    }

    void cleanup() {
        for (UINT32 i = 0; i < DNS_SPOOF_MAX_RULES; i++) {
            _InterlockedExchange(&g_spoof_rules[i].active, 0);
            g_spoof_rules[i].rule_id = 0;
            strong::kmemset(g_spoof_rules[i].domain, 0, sizeof(g_spoof_rules[i].domain));
            strong::kmemset(g_spoof_rules[i].spoof_addr, 0, sizeof(g_spoof_rules[i].spoof_addr));
            g_spoof_rules[i].address_family = 0;
            g_spoof_rules[i].ttl = 0;
            _InterlockedExchange(&g_spoof_rules[i].match_count, 0);
        }
        _InterlockedExchange(&g_active_spoof_count, 0);
    }
}


namespace net_bw {

    typedef struct _BW_PID_ENTRY {
        volatile LONG active;
        UINT32 pid;
        volatile LONG64 bytes_sent;
        volatile LONG64 bytes_recv;
        volatile LONG64 packets_sent;
        volatile LONG64 packets_recv;
        UINT64 last_activity;
    } BW_PID_ENTRY;

    inline BW_PID_ENTRY g_bw_entries[BW_MAX_PROCESSES] = {};
    inline volatile LONG g_bw_active = 0;
    inline volatile LONG64 g_bw_total_sent = 0;
    inline volatile LONG64 g_bw_total_recv = 0;
    inline volatile LONG64 g_bw_total_pkts_sent = 0;
    inline volatile LONG64 g_bw_total_pkts_recv = 0;
    inline volatile LONG64 g_bw_last_sample_sent = 0;
    inline volatile LONG64 g_bw_last_sample_recv = 0;
    inline volatile LONG64 g_bw_last_sample_pkts_sent = 0;
    inline volatile LONG64 g_bw_last_sample_pkts_recv = 0;
    inline volatile LONG64 g_bw_last_sample_time = 0;
    inline volatile LONG64 g_bw_generation = 0;
    inline volatile LONG64 g_bw_unattributed_events = 0;
    inline volatile LONG64 g_bw_no_slot_events = 0;
    inline volatile LONG64 g_bw_slot_race_events = 0;
    inline volatile LONG64 g_bw_duplicate_race_events = 0;
    inline KSPIN_LOCK g_bw_lock;
    inline volatile LONG g_bw_lock_state = 0;

    static constexpr UINT64 BW_TICKS_PER_SECOND = 10000000ULL;
    static constexpr UINT64 BW_TICKS_PER_MILLISECOND = 10000ULL;
    static constexpr LONG64 BW_COUNTER_MAX = 0x7fffffffffffffffLL;

    void init_lock() {
        LONG state = _InterlockedCompareExchange(&g_bw_lock_state, 1, 0);
        if (state == 0) {
            KeInitializeSpinLock(&g_bw_lock);
            KeMemoryBarrier();
            _InterlockedExchange(&g_bw_lock_state, 2);
            return;
        }
        for (UINT32 spin = 0; spin < 100000; spin++) {
            if (_InterlockedCompareExchange(&g_bw_lock_state, 2, 2) == 2) return;
            YieldProcessor();
        }
    }

    static BOOLEAN ensure_lock_ready() {
        init_lock();
        return _InterlockedCompareExchange(&g_bw_lock_state, 2, 2) == 2;
    }

    BOOLEAN is_active() {
        return (g_bw_active != 0);
    }

    static LONG64 read_i64(volatile LONG64* value) {
        return _InterlockedCompareExchange64(value, 0, 0);
    }

    static UINT64 counter_to_u64(LONG64 value) {
        return value > 0 ? static_cast<UINT64>(value) : 0;
    }

    static LONG64 counter_add_saturated_value(LONG64 current, UINT64 delta) {
        if (current < 0) return BW_COUNTER_MAX;
        UINT64 current_u = static_cast<UINT64>(current);
        UINT64 max_u = static_cast<UINT64>(BW_COUNTER_MAX);
        if (delta >= max_u - current_u) return BW_COUNTER_MAX;
        return static_cast<LONG64>(current_u + delta);
    }

    static LONG64 add_counter_saturated(volatile LONG64* value, UINT64 delta, LONG64* previous) {
        for (UINT32 attempt = 0; attempt < 64; attempt++) {
            LONG64 current = read_i64(value);
            LONG64 next = counter_add_saturated_value(current, delta);
            LONG64 observed = _InterlockedCompareExchange64(value, next, current);
            if (observed == current) {
                if (previous) *previous = current;
                return next;
            }
            YieldProcessor();
        }
        LONG64 current = read_i64(value);
        if (previous) *previous = current;
        return current;
    }

    static LONG64 add_counter_locked(volatile LONG64* value, UINT64 delta, LONG64* previous) {
        LONG64 current = *value;
        LONG64 next = counter_add_saturated_value(current, delta);
        *value = next;
        if (previous) *previous = current;
        return next;
    }

    static UINT64 counter_delta(LONG64 current, LONG64 previous, BOOLEAN* regressed) {
        if (current < 0 || previous < 0 || current < previous) {
            if (regressed) *regressed = TRUE;
            return 0;
        }
        if (regressed) *regressed = FALSE;
        return static_cast<UINT64>(current) - static_cast<UINT64>(previous);
    }

    static UINT64 divide_u128_by_u64(UINT64 high, UINT64 low, UINT64 divisor) {
        UINT64 quotient = 0;
        UINT64 remainder = high;
        for (int bit = 63; bit >= 0; --bit) {
            const UINT64 carry = remainder >> 63;
            remainder = (remainder << 1) | ((low >> bit) & 1ULL);
            if (carry != 0 || remainder >= divisor) {
                remainder -= divisor;
                quotient |= (1ULL << bit);
            }
        }
        return quotient;
    }

    static UINT64 bytes_per_second(UINT64 byte_delta, UINT64 elapsed_ticks, BOOLEAN* clamped) {
        if (clamped) *clamped = FALSE;
        if (byte_delta == 0 || elapsed_ticks == 0) return 0;
        UINT64 high = 0;
        UINT64 low = _umul128(byte_delta, BW_TICKS_PER_SECOND, &high);
        if (high >= elapsed_ticks) {
            if (clamped) *clamped = TRUE;
            return ~0ULL;
        }
        return divide_u128_by_u64(high, low, elapsed_ticks);
    }

    static const char* direction_name(UINT32 direction) {
        return direction == 0 ? "in" : "out";
    }

    static const char* attribution_name(UINT32 source) {
        switch (source) {
        case PID_SOURCE_METADATA: return "metadata";
        case PID_SOURCE_ENDPOINT: return "endpoint";
        case PID_SOURCE_PORT_CACHE: return "port_cache";
        case PID_SOURCE_UDP_CACHE: return "udp_cache";
        default: return "none";
        }
    }

    static const char* layer_name(UINT32 layer) {
        switch (layer) {
        case LAYER_INBOUND_TRANSPORT: return "inbound_transport";
        case LAYER_OUTBOUND_TRANSPORT: return "outbound_transport";
        case LAYER_DATAGRAM: return "datagram";
        default: return "unknown";
        }
    }

    static const char* rate_reason(UINT64 delta, UINT64 rate,
                                   BOOLEAN regressed, BOOLEAN clamped, BOOLEAN has_previous,
                                   BOOLEAN elapsed_valid, UINT32 direction) {
        if (!has_previous) return direction == 0 ? "in_no_previous_sample" : "out_no_previous_sample";
        if (!elapsed_valid) return direction == 0 ? "in_elapsed_zero_or_reversed" : "out_elapsed_zero_or_reversed";
        if (regressed) return direction == 0 ? "in_counter_regressed" : "out_counter_regressed";
        if (delta == 0) return direction == 0 ? "in_no_delta" : "out_no_delta";
        if (clamped) return direction == 0 ? "in_clamped" : "out_clamped";
        if (rate == 0) return direction == 0 ? "in_below_one_bps" : "out_below_one_bps";
        return direction == 0 ? "in_nonzero" : "out_nonzero";
    }

    static void log_traffic_update(const char* branch, UINT32 pid, UINT32 direction, UINT32 bytes,
                                   UINT32 attribution_source, UINT32 layer, UINT32 protocol,
                                   UINT32 local_port, UINT32 remote_port, LONG slot,
                                   LONG64 row_bytes_before, LONG64 row_bytes_after,
                                   LONG64 row_packets_after, LONG64 aggregate_bytes_before,
                                   LONG64 aggregate_bytes_after, LONG64 aggregate_packets_after) {
        SD_LOG("netaction::BWMN traffic branch=%s pid=%u direction=%s direction_id=%u attribution=%s attribution_id=%u layer=%s layer_id=%u protocol=%u local_port=%u remote_port=%u bytes=%u slot=%ld row_bytes_before=%lld row_bytes_after=%lld row_packets_after=%lld aggregate_bytes_before=%lld aggregate_bytes_after=%lld aggregate_packets_after=%lld no_pid=%lld no_slot=%lld slot_race=%lld duplicate_race=%lld capture_dropped=%ld active=%ld irql=%u cpu=%lu",
            branch,
            pid,
            direction_name(direction),
            direction,
            attribution_name(attribution_source),
            attribution_source,
            layer_name(layer),
            layer,
            protocol,
            local_port,
            remote_port,
            bytes,
            slot,
            row_bytes_before,
            row_bytes_after,
            row_packets_after,
            aggregate_bytes_before,
            aggregate_bytes_after,
            aggregate_packets_after,
            read_i64(&g_bw_unattributed_events),
            read_i64(&g_bw_no_slot_events),
            read_i64(&g_bw_slot_race_events),
            read_i64(&g_bw_duplicate_race_events),
            net_capture::g_total_dropped,
            g_bw_active,
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());
    }

    static void clear_process_entries_unlocked() {
        for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
            g_bw_entries[i].active = 0;
            g_bw_entries[i].pid = 0;
            g_bw_entries[i].bytes_sent = 0;
            g_bw_entries[i].bytes_recv = 0;
            g_bw_entries[i].packets_sent = 0;
            g_bw_entries[i].packets_recv = 0;
            g_bw_entries[i].last_activity = 0;
        }
    }

    static void update_rate_sample(p_bw_monitor_request request, UINT32 operation, UINT64 now_100ns,
                                   LONG64 total_sent, LONG64 total_recv,
                                   LONG64 packets_sent, LONG64 packets_recv) {
        request->bytes_per_second_out = 0;
        request->bytes_per_second_in = 0;

        LONG64 last_time_i64 = read_i64(&g_bw_last_sample_time);
        LONG64 last_sent = read_i64(&g_bw_last_sample_sent);
        LONG64 last_recv = read_i64(&g_bw_last_sample_recv);
        LONG64 last_pkts_sent = read_i64(&g_bw_last_sample_pkts_sent);
        LONG64 last_pkts_recv = read_i64(&g_bw_last_sample_pkts_recv);
        BOOLEAN has_previous = last_time_i64 > 0;
        BOOLEAN elapsed_valid = FALSE;
        BOOLEAN sent_regressed = FALSE;
        BOOLEAN recv_regressed = FALSE;
        BOOLEAN pkts_sent_regressed = FALSE;
        BOOLEAN pkts_recv_regressed = FALSE;
        BOOLEAN out_clamped = FALSE;
        BOOLEAN in_clamped = FALSE;
        UINT64 elapsed_ticks = 0;
        UINT64 delta_sent = 0;
        UINT64 delta_recv = 0;
        UINT64 delta_pkts_sent = 0;
        UINT64 delta_pkts_recv = 0;
        UINT64 rate_out = 0;
        UINT64 rate_in = 0;

        if (has_previous && now_100ns > static_cast<UINT64>(last_time_i64)) {
            elapsed_valid = TRUE;
            elapsed_ticks = now_100ns - static_cast<UINT64>(last_time_i64);
            delta_sent = counter_delta(total_sent, last_sent, &sent_regressed);
            delta_recv = counter_delta(total_recv, last_recv, &recv_regressed);
            delta_pkts_sent = counter_delta(packets_sent, last_pkts_sent, &pkts_sent_regressed);
            delta_pkts_recv = counter_delta(packets_recv, last_pkts_recv, &pkts_recv_regressed);
            rate_out = bytes_per_second(delta_sent, elapsed_ticks, &out_clamped);
            rate_in = bytes_per_second(delta_recv, elapsed_ticks, &in_clamped);
            request->bytes_per_second_out = rate_out;
            request->bytes_per_second_in = rate_in;
        }

        SD_LOG("netaction::BWMN rate op=%u generation=%lld active=%ld now_100ns=%llu last_100ns=%lld elapsed_ticks=%llu elapsed_ms=%llu total_sent=%lld total_recv=%lld total_pkts_sent=%lld total_pkts_recv=%lld last_sent=%lld last_recv=%lld delta_sent=%llu delta_recv=%llu delta_pkts_sent=%llu delta_pkts_recv=%llu rate_out=%llu rate_in=%llu out_reason=%s in_reason=%s out_clamped=%u in_clamped=%u pkts_sent_regressed=%u pkts_recv_regressed=%u no_pid=%lld no_slot=%lld slot_race=%lld duplicate_race=%lld capture_dropped=%ld irql=%u cpu=%lu",
            operation,
            read_i64(&g_bw_generation),
            g_bw_active,
            now_100ns,
            last_time_i64,
            elapsed_ticks,
            elapsed_ticks / BW_TICKS_PER_MILLISECOND,
            total_sent,
            total_recv,
            packets_sent,
            packets_recv,
            last_sent,
            last_recv,
            delta_sent,
            delta_recv,
            delta_pkts_sent,
            delta_pkts_recv,
            rate_out,
            rate_in,
            rate_reason(delta_sent, rate_out, sent_regressed, out_clamped, has_previous, elapsed_valid, 1),
            rate_reason(delta_recv, rate_in, recv_regressed, in_clamped, has_previous, elapsed_valid, 0),
            out_clamped ? 1u : 0u,
            in_clamped ? 1u : 0u,
            pkts_sent_regressed ? 1u : 0u,
            pkts_recv_regressed ? 1u : 0u,
            read_i64(&g_bw_unattributed_events),
            read_i64(&g_bw_no_slot_events),
            read_i64(&g_bw_slot_race_events),
            read_i64(&g_bw_duplicate_race_events),
            net_capture::g_total_dropped,
            (UINT32)KeGetCurrentIrql(),
            KeGetCurrentProcessorNumber());

        _InterlockedExchange64(&g_bw_last_sample_sent, total_sent);
        _InterlockedExchange64(&g_bw_last_sample_recv, total_recv);
        _InterlockedExchange64(&g_bw_last_sample_pkts_sent, packets_sent);
        _InterlockedExchange64(&g_bw_last_sample_pkts_recv, packets_recv);
        _InterlockedExchange64(&g_bw_last_sample_time, static_cast<LONG64>(now_100ns));
    }

    void record_traffic(UINT32 pid, UINT32 direction, UINT32 bytes,
                        UINT32 attribution_source, UINT32 layer,
                        UINT32 protocol, UINT32 local_port, UINT32 remote_port) {
        if (!g_bw_active) return;

        LONG64 aggregate_bytes_before = 0;
        LONG64 aggregate_bytes_after = 0;
        LONG64 aggregate_packets_after = 0;
        if (direction == 0) {
            aggregate_bytes_after = add_counter_saturated(&g_bw_total_recv, bytes, &aggregate_bytes_before);
            aggregate_packets_after = add_counter_saturated(&g_bw_total_pkts_recv, 1, nullptr);
        } else {
            aggregate_bytes_after = add_counter_saturated(&g_bw_total_sent, bytes, &aggregate_bytes_before);
            aggregate_packets_after = add_counter_saturated(&g_bw_total_pkts_sent, 1, nullptr);
        }

        if (pid == 0) {
            _InterlockedIncrement64(&g_bw_unattributed_events);
            log_traffic_update("unattributed", pid, direction, bytes, attribution_source, layer,
                protocol, local_port, remote_port, -1, 0, 0, 0,
                aggregate_bytes_before, aggregate_bytes_after, aggregate_packets_after);
            return;
        }

        if (!ensure_lock_ready()) {
            _InterlockedIncrement64(&g_bw_slot_race_events);
            log_traffic_update("lock_unavailable", pid, direction, bytes, attribution_source, layer,
                protocol, local_port, remote_port, -1, 0, 0, 0,
                aggregate_bytes_before, aggregate_bytes_after, aggregate_packets_after);
            return;
        }

        const char* branch = "no_slot";
        LONG slot = -1;
        LONG64 row_bytes_before = 0;
        LONG64 row_bytes_after = 0;
        LONG64 row_packets_after = 0;
        LARGE_INTEGER ts;
        KeQuerySystemTime(&ts);

        KIRQL old_irql;
        KeAcquireSpinLock(&g_bw_lock, &old_irql);
        INT32 free_slot = -1;
        for (UINT32 i = 0; i < BW_MAX_PROCESSES; i++) {
            if (g_bw_entries[i].active == 1 && g_bw_entries[i].pid == pid) {
                if (direction == 0) {
                    row_bytes_after = add_counter_locked(&g_bw_entries[i].bytes_recv, bytes, &row_bytes_before);
                    row_packets_after = add_counter_locked(&g_bw_entries[i].packets_recv, 1, nullptr);
                } else {
                    row_bytes_after = add_counter_locked(&g_bw_entries[i].bytes_sent, bytes, &row_bytes_before);
                    row_packets_after = add_counter_locked(&g_bw_entries[i].packets_sent, 1, nullptr);
                }
                g_bw_entries[i].last_activity = ts.QuadPart;
                branch = "existing";
                slot = static_cast<LONG>(i);
                KeReleaseSpinLock(&g_bw_lock, old_irql);
                log_traffic_update(branch, pid, direction, bytes, attribution_source, layer,
                    protocol, local_port, remote_port, slot, row_bytes_before, row_bytes_after,
                    row_packets_after, aggregate_bytes_before, aggregate_bytes_after,
                    aggregate_packets_after);
                return;
            }
            if (!g_bw_entries[i].active && free_slot == -1) free_slot = i;
        }
        if (free_slot >= 0) {
            g_bw_entries[free_slot].pid = pid;
            g_bw_entries[free_slot].bytes_sent = 0;
            g_bw_entries[free_slot].bytes_recv = 0;
            g_bw_entries[free_slot].packets_sent = 0;
            g_bw_entries[free_slot].packets_recv = 0;
            row_bytes_after = static_cast<LONG64>(bytes);
            row_packets_after = 1;
            if (direction == 0) {
                g_bw_entries[free_slot].bytes_recv = row_bytes_after;
                g_bw_entries[free_slot].packets_recv = row_packets_after;
            } else {
                g_bw_entries[free_slot].bytes_sent = row_bytes_after;
                g_bw_entries[free_slot].packets_sent = row_packets_after;
            }
            g_bw_entries[free_slot].last_activity = ts.QuadPart;
            KeMemoryBarrier();
            g_bw_entries[free_slot].active = 1;
            branch = "new_slot";
            slot = static_cast<LONG>(free_slot);
        } else {
            _InterlockedIncrement64(&g_bw_no_slot_events);
        }
        KeReleaseSpinLock(&g_bw_lock, old_irql);
        log_traffic_update(branch, pid, direction, bytes, attribution_source, layer,
            protocol, local_port, remote_port, slot, row_bytes_before, row_bytes_after,
            row_packets_after, aggregate_bytes_before, aggregate_bytes_after,
            aggregate_packets_after);
    }

    NTSTATUS handle_bw(p_bw_monitor_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        NET_DBG("handle_bw: op=%u filter_pid=%u bw_active=%d",
                request->operation, request->filter_pid, (int)g_bw_active);

        switch (request->operation) {
        case 0: {
            LONG64 generation = _InterlockedIncrement64(&g_bw_generation);
            _InterlockedExchange(&g_bw_active, 1);
            request->monitoring_active = 1;
            LONG64 total_sent = read_i64(&g_bw_total_sent);
            LONG64 total_recv = read_i64(&g_bw_total_recv);
            LONG64 packets_sent = read_i64(&g_bw_total_pkts_sent);
            LONG64 packets_recv = read_i64(&g_bw_total_pkts_recv);
            request->total_bytes_sent = counter_to_u64(total_sent);
            request->total_bytes_recv = counter_to_u64(total_recv);
            request->total_packets_sent = counter_to_u64(packets_sent);
            request->total_packets_recv = counter_to_u64(packets_recv);
            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            update_rate_sample(request, request->operation, static_cast<UINT64>(now.QuadPart),
                total_sent, total_recv, packets_sent, packets_recv);
            SD_LOG("netaction::BWMN start op=0 generation=%lld filter_pid=%u active=1 total_sent=%lld total_recv=%lld packets_sent=%lld packets_recv=%lld irql=%u cpu=%lu",
                generation,
                request->filter_pid,
                total_sent,
                total_recv,
                packets_sent,
                packets_recv,
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_SUCCESS;
        }
        case 1: {
            LONG active_before = _InterlockedExchange(&g_bw_active, 0);
            LONG64 generation = _InterlockedIncrement64(&g_bw_generation);
            request->monitoring_active = 0;
            SD_LOG("netaction::BWMN stop op=1 generation=%lld filter_pid=%u active_before=%ld total_sent=%lld total_recv=%lld packets_sent=%lld packets_recv=%lld no_pid=%lld no_slot=%lld slot_race=%lld duplicate_race=%lld capture_dropped=%ld irql=%u cpu=%lu",
                generation,
                request->filter_pid,
                active_before,
                read_i64(&g_bw_total_sent),
                read_i64(&g_bw_total_recv),
                read_i64(&g_bw_total_pkts_sent),
                read_i64(&g_bw_total_pkts_recv),
                read_i64(&g_bw_unattributed_events),
                read_i64(&g_bw_no_slot_events),
                read_i64(&g_bw_slot_race_events),
                read_i64(&g_bw_duplicate_race_events),
                net_capture::g_total_dropped,
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_SUCCESS;
        }
        case 2: {
            LONG64 total_sent = read_i64(&g_bw_total_sent);
            LONG64 total_recv = read_i64(&g_bw_total_recv);
            LONG64 packets_sent = read_i64(&g_bw_total_pkts_sent);
            LONG64 packets_recv = read_i64(&g_bw_total_pkts_recv);
            request->total_bytes_sent = counter_to_u64(total_sent);
            request->total_bytes_recv = counter_to_u64(total_recv);
            request->total_packets_sent = counter_to_u64(packets_sent);
            request->total_packets_recv = counter_to_u64(packets_recv);
            request->monitoring_active = g_bw_active;

            NET_DBG("handle_bw[get]: total_sent=%lld total_recv=%lld pkts_s=%lld pkts_r=%lld active=%d",
                    total_sent, total_recv, packets_sent, packets_recv, (int)g_bw_active);


            LARGE_INTEGER now;
            KeQuerySystemTime(&now);
            update_rate_sample(request, request->operation, static_cast<UINT64>(now.QuadPart),
                total_sent, total_recv, packets_sent, packets_recv);
            return STATUS_SUCCESS;
        }
        case 3: {
            LONG64 generation = _InterlockedIncrement64(&g_bw_generation);
            LONG64 sent_before = _InterlockedExchange64(&g_bw_total_sent, 0);
            LONG64 recv_before = _InterlockedExchange64(&g_bw_total_recv, 0);
            LONG64 pkts_sent_before = _InterlockedExchange64(&g_bw_total_pkts_sent, 0);
            LONG64 pkts_recv_before = _InterlockedExchange64(&g_bw_total_pkts_recv, 0);
            LONG64 no_pid_before = _InterlockedExchange64(&g_bw_unattributed_events, 0);
            LONG64 no_slot_before = _InterlockedExchange64(&g_bw_no_slot_events, 0);
            LONG64 slot_race_before = _InterlockedExchange64(&g_bw_slot_race_events, 0);
            LONG64 duplicate_race_before = _InterlockedExchange64(&g_bw_duplicate_race_events, 0);
            _InterlockedExchange64(&g_bw_last_sample_sent, 0);
            _InterlockedExchange64(&g_bw_last_sample_recv, 0);
            _InterlockedExchange64(&g_bw_last_sample_pkts_sent, 0);
            _InterlockedExchange64(&g_bw_last_sample_pkts_recv, 0);
            _InterlockedExchange64(&g_bw_last_sample_time, 0);
            if (ensure_lock_ready()) {
                KIRQL old_irql;
                KeAcquireSpinLock(&g_bw_lock, &old_irql);
                clear_process_entries_unlocked();
                KeReleaseSpinLock(&g_bw_lock, old_irql);
            } else {
                clear_process_entries_unlocked();
            }
            request->total_bytes_sent = 0;
            request->total_bytes_recv = 0;
            request->total_packets_sent = 0;
            request->total_packets_recv = 0;
            request->bytes_per_second_out = 0;
            request->bytes_per_second_in = 0;
            request->process_count = 0;
            request->monitoring_active = g_bw_active;
            SD_LOG("netaction::BWMN reset op=3 generation=%lld filter_pid=%u active=%ld sent_before=%lld recv_before=%lld pkts_sent_before=%lld pkts_recv_before=%lld no_pid_before=%lld no_slot_before=%lld slot_race_before=%lld duplicate_race_before=%lld capture_dropped=%ld irql=%u cpu=%lu",
                generation,
                request->filter_pid,
                g_bw_active,
                sent_before,
                recv_before,
                pkts_sent_before,
                pkts_recv_before,
                no_pid_before,
                no_slot_before,
                slot_race_before,
                duplicate_race_before,
                net_capture::g_total_dropped,
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_SUCCESS;
        }
        case 4: {
            request->process_count = 0;
            UINT32 row_slots[BW_MAX_PROCESSES] = {};
            if (ensure_lock_ready()) {
                KIRQL old_irql;
                KeAcquireSpinLock(&g_bw_lock, &old_irql);
                for (UINT32 i = 0; i < BW_MAX_PROCESSES && request->process_count < BW_MAX_PROCESSES; i++) {
                    if (g_bw_entries[i].active != 1) continue;
                    if (request->filter_pid != 0 && g_bw_entries[i].pid != request->filter_pid) continue;
                    UINT32 out_index = request->process_count;
                    for (UINT32 row = 0; row < out_index; row++) {
                        if (request->processes[row].pid == g_bw_entries[i].pid) {
                            _InterlockedIncrement64(&g_bw_duplicate_race_events);
                            break;
                        }
                    }
                    BW_PROCESS_ENTRY* out = &request->processes[out_index];
                    out->pid = g_bw_entries[i].pid;
                    out->bytes_sent = counter_to_u64(g_bw_entries[i].bytes_sent);
                    out->bytes_recv = counter_to_u64(g_bw_entries[i].bytes_recv);
                    out->packets_sent = counter_to_u64(g_bw_entries[i].packets_sent);
                    out->packets_recv = counter_to_u64(g_bw_entries[i].packets_recv);
                    out->last_activity_time = g_bw_entries[i].last_activity;
                    row_slots[out_index] = i;
                    request->process_count++;
                }
                KeReleaseSpinLock(&g_bw_lock, old_irql);
            } else {
                _InterlockedIncrement64(&g_bw_slot_race_events);
            }
            for (UINT32 row = 0; row < request->process_count; row++) {
                BW_PROCESS_ENTRY* out = &request->processes[row];
                SD_LOG("netaction::BWMN process row slot=%u out_index=%u filter_pid=%u pid=%u bytes_sent=%llu bytes_recv=%llu packets_sent=%llu packets_recv=%llu last_activity=%llu active=%ld generation=%lld",
                    row_slots[row],
                    row,
                    request->filter_pid,
                    out->pid,
                    out->bytes_sent,
                    out->bytes_recv,
                    out->packets_sent,
                    out->packets_recv,
                    out->last_activity_time,
                    g_bw_active,
                    read_i64(&g_bw_generation));
            }
            request->monitoring_active = g_bw_active;
            SD_LOG("netaction::BWMN process_list op=4 filter_pid=%u returned=%u active=%ld generation=%lld no_pid=%lld no_slot=%lld slot_race=%lld duplicate_race=%lld capture_dropped=%ld irql=%u cpu=%lu",
                request->filter_pid,
                request->process_count,
                g_bw_active,
                read_i64(&g_bw_generation),
                read_i64(&g_bw_unattributed_events),
                read_i64(&g_bw_no_slot_events),
                read_i64(&g_bw_slot_race_events),
                read_i64(&g_bw_duplicate_race_events),
                net_capture::g_total_dropped,
                (UINT32)KeGetCurrentIrql(),
                KeGetCurrentProcessorNumber());
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_bw_active, 0);
        _InterlockedExchange64(&g_bw_total_sent, 0);
        _InterlockedExchange64(&g_bw_total_recv, 0);
        _InterlockedExchange64(&g_bw_total_pkts_sent, 0);
        _InterlockedExchange64(&g_bw_total_pkts_recv, 0);
        _InterlockedExchange64(&g_bw_last_sample_sent, 0);
        _InterlockedExchange64(&g_bw_last_sample_recv, 0);
        _InterlockedExchange64(&g_bw_last_sample_pkts_sent, 0);
        _InterlockedExchange64(&g_bw_last_sample_pkts_recv, 0);
        _InterlockedExchange64(&g_bw_last_sample_time, 0);
        _InterlockedExchange64(&g_bw_unattributed_events, 0);
        _InterlockedExchange64(&g_bw_no_slot_events, 0);
        _InterlockedExchange64(&g_bw_slot_race_events, 0);
        _InterlockedExchange64(&g_bw_duplicate_race_events, 0);
        if (ensure_lock_ready()) {
            KIRQL old_irql;
            KeAcquireSpinLock(&g_bw_lock, &old_irql);
            clear_process_entries_unlocked();
            KeReleaseSpinLock(&g_bw_lock, old_irql);
        } else {
            clear_process_entries_unlocked();
        }
    }
}


namespace net_if_enum {


    typedef NTSTATUS(NTAPI* fn_GetIfTable2)(PVOID* Table);
    typedef void(NTAPI* fn_FreeMibTable)(PVOID Table);


    typedef struct _SLOP_MIB_IF_ROW2 {
        UINT64 InterfaceLuid;
        UINT32 InterfaceIndex;
        GUID   InterfaceGuid;
        WCHAR  Alias[257];
        WCHAR  Description[257];
        UINT32 PhysicalAddressLength;
        UINT8  PhysicalAddress[32];
        UINT8  PermanentPhysicalAddress[32];
        UINT32 Mtu;
        UINT32 Type;
        UINT32 TunnelType;
        UINT32 MediaType;
        UINT32 PhysicalMediumType;
        UINT32 AccessType;
        UINT32 DirectionType;
        struct {
            BOOLEAN HardwareInterface  : 1;
            BOOLEAN FilterInterface    : 1;
            BOOLEAN ConnectorPresent   : 1;
            BOOLEAN NotAuthenticated   : 1;
            BOOLEAN NotMediaConnected  : 1;
            BOOLEAN Paused             : 1;
            BOOLEAN LowPower           : 1;
            BOOLEAN EndPointInterface  : 1;
        } InterfaceAndOperStatusFlags;
        UINT32 OperStatus;
        UINT32 AdminStatus;
        UINT32 MediaConnectState;
        GUID   NetworkGuid;
        UINT32 ConnectionType;
        UINT64 TransmitLinkSpeed;
        UINT64 ReceiveLinkSpeed;
        UINT64 InOctets;
        UINT64 InUcastPkts;
        UINT64 InNUcastPkts;
        UINT64 InDiscards;
        UINT64 InErrors;
        UINT64 InUnknownProtos;
        UINT64 InUcastOctets;
        UINT64 InMulticastOctets;
        UINT64 InBroadcastOctets;
        UINT64 OutOctets;
        UINT64 OutUcastPkts;
        UINT64 OutNUcastPkts;
        UINT64 OutDiscards;
        UINT64 OutErrors;
        UINT64 OutUcastOctets;
        UINT64 OutMulticastOctets;
        UINT64 OutBroadcastOctets;
        UINT64 OutQLen;
    } SLOP_MIB_IF_ROW2;

    typedef struct _SLOP_MIB_IF_TABLE2 {
        UINT32 NumEntries;
        SLOP_MIB_IF_ROW2 Table[1];
    } SLOP_MIB_IF_TABLE2;

    static_assert(sizeof(SLOP_MIB_IF_ROW2) == 1352,
        "SLOP_MIB_IF_ROW2 layout mismatch — must be 1352 bytes to match MIB_IF_ROW2");

    NTSTATUS enumerate_interfaces(p_net_interface_enum request) {
        if (!request) return STATUS_INVALID_PARAMETER;
        request->interface_count = 0;

        NET_DBG("enumerate_interfaces: enter");

        PVOID netio = net_capture::find_module_base("netio.sys");
        if (!netio) netio = net_capture::find_module_base("NETIO.SYS");
        if (!netio) return STATUS_NOT_SUPPORTED;

        CHAR gt2[] = {'G','e','t','I','f','T','a','b','l','e','2',0};
        CHAR fmt[] = {'F','r','e','e','M','i','b','T','a','b','l','e',0};

        fn_GetIfTable2 _GetIfTable2 = (fn_GetIfTable2)GetProcAddress(netio, gt2);
        fn_FreeMibTable _FreeMibTable = (fn_FreeMibTable)GetProcAddress(netio, fmt);

        if (!_GetIfTable2 || !_FreeMibTable) return STATUS_NOT_SUPPORTED;

        PVOID table = nullptr;
        NTSTATUS st = _GetIfTable2(&table);
        if (!NT_SUCCESS(st) || !table) {
            NET_ERR("enumerate_interfaces: GetIfTable2 failed 0x%08x table=%p", st, table);
            return st;
        }

        __try {
            const SLOP_MIB_IF_TABLE2* if_table = static_cast<const SLOP_MIB_IF_TABLE2*>(table);
            NET_DBG("enumerate_interfaces: NumEntries=%u", if_table->NumEntries);

            for (ULONG i = 0; i < if_table->NumEntries && request->interface_count < NET_IF_MAX; i++) {
                const SLOP_MIB_IF_ROW2* row = &if_table->Table[i];
                if (!_MmIsAddressValid(const_cast<SLOP_MIB_IF_ROW2*>(row))) break;

                NET_INTERFACE_ENTRY* e = &request->interfaces[request->interface_count];
                strong::kmemset(e, 0, sizeof(NET_INTERFACE_ENTRY));

                e->if_index = row->InterfaceIndex;
                e->mtu = row->Mtu;
                e->if_type = row->Type;
                e->speed = row->TransmitLinkSpeed;
                e->oper_status = row->OperStatus;

                if (row->PhysicalAddressLength >= 6) {
                    strong::kmemcpy(e->mac_addr, row->PhysicalAddress, 6);
                }

                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && row->Alias[j]; j++) {
                    e->name[j] = static_cast<char>(row->Alias[j] & 0x7F);
                }

                for (UINT32 j = 0; j < NET_IF_NAME_LEN - 1 && row->Description[j]; j++) {
                    e->description[j] = static_cast<char>(row->Description[j] & 0x7F);
                }

                e->in_octets = row->InOctets;
                e->out_octets = row->OutOctets;

                request->interface_count++;
            }
        } __except(EXCEPTION_EXECUTE_HANDLER) {
            NET_ERR("enumerate_interfaces: exception during enumeration");
        }

        NET_DBG("enumerate_interfaces: returned %u interfaces", request->interface_count);
        for (UINT32 dbg_i = 0; dbg_i < request->interface_count && dbg_i < 3; dbg_i++) {
            const NET_INTERFACE_ENTRY* e = &request->interfaces[dbg_i];
            NET_DBG("  iface[%u]: idx=%u type=%u mtu=%u oper=%u speed=%llu mac=%02x:%02x:%02x:%02x:%02x:%02x",
                    dbg_i, e->if_index, e->if_type, e->mtu, e->oper_status, e->speed,
                    e->mac_addr[0], e->mac_addr[1], e->mac_addr[2],
                    e->mac_addr[3], e->mac_addr[4], e->mac_addr[5]);
            NET_DBG("  iface[%u]: name='%.32s' desc='%.32s'",
                    dbg_i, e->name, e->description);
        }

        _FreeMibTable(table);
        return STATUS_SUCCESS;
    }
}


namespace net_pcap {

    NTSTATUS export_pcap(p_pcap_export_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;


        request->header.magic_number = 0xa1b2c3d4;
        request->header.version_major = 2;
        request->header.version_minor = 4;
        request->header.thiszone = 0;
        request->header.sigfigs = 0;
        request->header.snaplen = PCAP_RECORD_MAX_SIZE;
        request->header.network = 101;

        UINT32 max_pkts = request->max_packets;
        if (max_pkts == 0 || max_pkts > PCAP_MAX_EXPORT_PACKETS)
            max_pkts = PCAP_MAX_EXPORT_PACKETS;

        request->packet_count = 0;
        request->data_size = sizeof(PCAP_GLOBAL_HEADER);


        if (!net_capture::g_ring_buffer) return STATUS_NOT_SUPPORTED;

        KIRQL irql;
        KeAcquireSpinLock(&net_capture::g_ring_lock, &irql);

        LONG idx = 0;
        LONG total_scan = RING_BUFFER_SIZE;

        while (total_scan > 0 && request->packet_count < max_pkts) {
            NET_PACKET_ENTRY* pkt = &net_capture::g_ring_buffer[idx];

            if (pkt->timestamp == 0) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }

            if (request->filter_pid != 0 && pkt->pid != 0 && pkt->pid != request->filter_pid) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }
            if (request->filter_protocol != 0 && pkt->protocol != request->filter_protocol) {
                idx = (idx + 1) % RING_BUFFER_SIZE;
                total_scan--;
                continue;
            }

            PCAP_RECORD* rec = &request->records[request->packet_count];
            strong::kmemset(rec, 0, sizeof(PCAP_RECORD));


            UINT64 unix_100ns = pkt->timestamp - 116444736000000000ULL;
            rec->ts_sec = (UINT32)(unix_100ns / 10000000ULL);
            rec->ts_usec = (UINT32)((unix_100ns % 10000000ULL) / 10);


            UINT32 ip_header_len = 20;
            UINT32 total_len = ip_header_len + pkt->payload_size;
            if (total_len > PCAP_RECORD_MAX_SIZE) total_len = PCAP_RECORD_MAX_SIZE;


            rec->data[0] = 0x45;
            rec->data[1] = 0x00;
            rec->data[2] = (UINT8)(total_len >> 8);
            rec->data[3] = (UINT8)(total_len & 0xFF);
            rec->data[4] = 0; rec->data[5] = 0;
            rec->data[6] = 0x40; rec->data[7] = 0;
            rec->data[8] = 64;
            rec->data[9] = (UINT8)pkt->protocol;


            strong::kmemcpy(&rec->data[12], pkt->local_addr, 4);

            strong::kmemcpy(&rec->data[16], pkt->remote_addr, 4);


            if (pkt->direction == 0) {
                strong::kmemcpy(&rec->data[12], pkt->remote_addr, 4);
                strong::kmemcpy(&rec->data[16], pkt->local_addr, 4);
            }

            {
                UINT16 cksum = net_checksum::ip_checksum(rec->data, ip_header_len);
                rec->data[10] = (UINT8)(cksum >> 8);
                rec->data[11] = (UINT8)(cksum & 0xFF);
            }


            UINT32 payload_copy = pkt->payload_size;
            if (ip_header_len + payload_copy > PCAP_RECORD_MAX_SIZE)
                payload_copy = PCAP_RECORD_MAX_SIZE - ip_header_len;
            strong::kmemcpy(&rec->data[ip_header_len], pkt->payload, payload_copy);

            rec->incl_len = ip_header_len + payload_copy;
            rec->orig_len = total_len;
            request->data_size += sizeof(UINT32) * 4 + rec->incl_len;

            request->packet_count++;
            idx = (idx + 1) % RING_BUFFER_SIZE;
            total_scan--;
        }

        KeReleaseSpinLock(&net_capture::g_ring_lock, irql);

        return STATUS_SUCCESS;
    }
}


namespace net_fingerprint {

    inline NET_FINGERPRINT_ENTRY g_fp_entries[FINGERPRINT_MAX] = {};
    inline volatile LONG g_fp_count = 0;
    inline volatile LONG g_fp_active = 0;

    BOOLEAN is_active() {
        return (g_fp_active != 0);
    }


    void analyze_tcp_syn(const UINT8* src_addr, UINT32 af,
                         const UINT8* tcp_data, UINT32 tcp_len,
                         UINT32 ip_ttl) {
        if (!g_fp_active || tcp_len < 20) return;

        UINT8 flags = tcp_data[13];
        if (!(flags & 0x02)) return;

        UINT32 window = ((UINT32)tcp_data[14] << 8) | tcp_data[15];
        UINT32 data_offset = ((tcp_data[12] >> 4) & 0xF) * 4;


        UINT32 mss = 0;
        UINT32 ws = 0;
        UINT32 sack = 0;
        UINT32 nops = 0;
        UINT32 opt_order = 0;

        if (data_offset > 20 && data_offset <= tcp_len) {
            UINT32 pos = 20;
            UINT32 opt_idx = 0;
            while (pos < data_offset && pos < tcp_len) {
                UINT8 kind = tcp_data[pos];
                if (kind == 0) break;
                if (kind == 1) { nops++; pos++; continue; }
                if (pos + 1 >= tcp_len) break;
                UINT8 olen = tcp_data[pos + 1];
                if (olen < 2 || pos + olen > tcp_len) break;

                if (kind == 2 && olen == 4) {
                    mss = ((UINT32)tcp_data[pos + 2] << 8) | tcp_data[pos + 3];
                    opt_order |= (2 << (opt_idx * 4));
                }
                else if (kind == 3 && olen == 3) {
                    ws = tcp_data[pos + 2];
                    opt_order |= (3 << (opt_idx * 4));
                }
                else if (kind == 4 && olen == 2) {
                    sack = 1;
                    opt_order |= (4 << (opt_idx * 4));
                }
                else if (kind == 8 && olen == 10) {
                    opt_order |= (8 << (opt_idx * 4));
                }
                opt_idx++;
                pos += olen;
            }
        }


        char os[64] = {};


        UINT32 ttl_bucket = (ip_ttl > 96) ? 128 : (ip_ttl > 48 ? 64 : 32);

        if (ttl_bucket == 128) {
            if (window == 65535 || window == 64240) {

                const char* s = "Windows 10/11";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            } else if (window == 8192) {
                const char* s = "Windows 7/8";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            } else {
                const char* s = "Windows (unknown)";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            }
        } else if (ttl_bucket == 64) {
            if (ws > 0 && sack) {
                if (mss == 1460 && window >= 29200) {
                    const char* s = "Linux 4.x/5.x";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                } else if (mss == 1460 && window == 65535) {
                    const char* s = "macOS / FreeBSD";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                } else {
                    const char* s = "Linux/Unix";
                    for (int i = 0; s[i]; i++) os[i] = s[i];
                }
            } else {
                const char* s = "Unix-like";
                for (int i = 0; s[i]; i++) os[i] = s[i];
            }
        } else {
            const char* s = "Unknown";
            for (int i = 0; s[i]; i++) os[i] = s[i];
        }


        KIRQL irql;
        KeAcquireSpinLock(&g_fp_lock, &irql);


        for (UINT32 i = 0; i < FINGERPRINT_MAX; i++) {
            if (g_fp_entries[i].address_family == af) {
                UINT32 len = (af == 23) ? 16 : 4;
                BOOLEAN same = TRUE;
                for (UINT32 j = 0; j < len; j++) {
                    if (g_fp_entries[i].remote_addr[j] != src_addr[j]) {
                        same = FALSE; break;
                    }
                }
                if (same) {

                    g_fp_entries[i].ttl = ip_ttl;
                    g_fp_entries[i].window_size = window;
                    g_fp_entries[i].mss = mss;
                    g_fp_entries[i].window_scale = ws;
                    g_fp_entries[i].sack_permitted = sack;
                    g_fp_entries[i].nop_count = nops;
                    g_fp_entries[i].tcp_options_order = opt_order;
                    strong::kmemcpy(g_fp_entries[i].os_guess, os, 64);
                    KeReleaseSpinLock(&g_fp_lock, irql);
                    return;
                }
            }
        }


        if (g_fp_count < FINGERPRINT_MAX) {
            UINT32 idx = g_fp_count;
            strong::kmemset(&g_fp_entries[idx], 0, sizeof(NET_FINGERPRINT_ENTRY));
            strong::kmemcpy(g_fp_entries[idx].remote_addr, src_addr, (af == 23) ? 16 : 4);
            g_fp_entries[idx].address_family = af;
            g_fp_entries[idx].ttl = ip_ttl;
            g_fp_entries[idx].window_size = window;
            g_fp_entries[idx].mss = mss;
            g_fp_entries[idx].window_scale = ws;
            g_fp_entries[idx].sack_permitted = sack;
            g_fp_entries[idx].nop_count = nops;
            g_fp_entries[idx].tcp_options_order = opt_order;
            g_fp_entries[idx].df_flag = 0;
            strong::kmemcpy(g_fp_entries[idx].os_guess, os, 64);
            _InterlockedIncrement(&g_fp_count);
        }
        KeReleaseSpinLock(&g_fp_lock, irql);
    }

    NTSTATUS handle_fingerprint(p_net_fingerprint_request request) {
        if (!request) return STATUS_INVALID_PARAMETER;

        switch (request->operation) {
        case 0:
            _InterlockedExchange(&g_fp_active, 1);
            return STATUS_SUCCESS;
        case 1:
            _InterlockedExchange(&g_fp_active, 0);
            return STATUS_SUCCESS;
        case 2: {
            KIRQL irql;
            KeAcquireSpinLock(&g_fp_lock, &irql);
            request->result_count = (UINT32)g_fp_count;
            UINT32 copy = g_fp_count;
            if (copy > FINGERPRINT_MAX) copy = FINGERPRINT_MAX;
            strong::kmemcpy(request->entries, g_fp_entries, copy * sizeof(NET_FINGERPRINT_ENTRY));
            KeReleaseSpinLock(&g_fp_lock, irql);
            return STATUS_SUCCESS;
        }
        default:
            return STATUS_INVALID_PARAMETER;
        }
    }

    void cleanup() {
        _InterlockedExchange(&g_fp_active, 0);
        KIRQL irql;
        KeAcquireSpinLock(&g_fp_lock, &irql);
        strong::kmemset(g_fp_entries, 0, sizeof(g_fp_entries));
        _InterlockedExchange(&g_fp_count, 0);
        KeReleaseSpinLock(&g_fp_lock, irql);
    }
}


NTSTATUS functions::handle_wfp_callout_enum(p_wfp_callout_enum request) {
    if (!request) { NET_ERR("handle_wfp_callout_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_wfp_enum::enumerate_wfp_callouts(request);
}

NTSTATUS functions::handle_socket_handle_enum(p_socket_handle_enum request) {
    if (!request) { NET_ERR("handle_socket_handle_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_socket_handle_enum: ENTER target_pid=%u", request->target_pid);
    NTSTATUS st = net_socket_enum::enumerate_socket_handles(request);
    NET_DBG("handle_socket_handle_enum: EXIT status=0x%08x socket_count=%u", st, request->socket_count);
    return st;
}

NTSTATUS functions::handle_sniff_net_buffers(p_sniff_net_buffers request) {
    if (!request) { NET_ERR("handle_sniff_net_buffers: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_sniff_net_buffers: op=%u", request->operation);
    NTSTATUS st = net_sniff::handle_sniff(request);
    NET_DBG("handle_sniff_net_buffers: returned 0x%08x active=%u capture_count=%u",
            st, request->active, request->capture_count);
    return st;
}

NTSTATUS functions::handle_tcpip_conn_dump(p_tcpip_conn_dump request) {
    if (!request) { NET_ERR("handle_tcpip_conn_dump: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_tcpip::dump_connections(request);
}


NTSTATUS functions::handle_packet_inject(p_packet_inject_request request) {
    if (!request) { NET_ERR("handle_packet_inject: NULL request"); return STATUS_INVALID_PARAMETER; }
    UINT64 start_tsc = __rdtsc();
    SD_LOG("netaction::PINJ ENTER direction=%u protocol=%u af=%u src_port=%u dst_port=%u payload_size=%u tcp_flags=0x%08X active_mod_rules=%ld mod_generation=%lld irql=%u cpu=%lu",
        request->direction,
        request->protocol,
        request->address_family,
        request->src_port,
        request->dst_port,
        request->payload_size,
        request->tcp_flags,
        net_mod::active_rule_count(),
        net_mod::current_generation(),
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    NTSTATUS st = net_inject::inject_packet(request);
    if (!NT_SUCCESS(st)) {
        NET_ERR("handle_packet_inject: FAILED dir=%u proto=%u af=%u payload=%u status=0x%08x",
                request->direction, request->protocol, request->address_family, request->payload_size, st);
    }
    SD_LOG("netaction::PINJ EXIT status=0x%08X win32=%lu request_status=%u direction=%u protocol=%u af=%u payload_size=%u elapsed_tsc=%llu active_mod_rules=%ld mod_generation=%lld irql=%u cpu=%lu",
        st,
        net_capture::status_to_win32(st),
        request->status,
        request->direction,
        request->protocol,
        request->address_family,
        request->payload_size,
        (unsigned long long)(__rdtsc() - start_tsc),
        net_mod::active_rule_count(),
        net_mod::current_generation(),
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    return st;
}

NTSTATUS functions::handle_packet_mod_rule(p_packet_mod_rule request) {
    if (!request) { NET_ERR("handle_packet_mod_rule: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_packet_mod_rule: op=%u rule_id=%u", request->operation, request->rule_id);
    UINT64 start_tsc = __rdtsc();
    LONG active_before = net_mod::active_rule_count();
    LONG64 generation_before = net_mod::current_generation();
    SD_LOG("netaction::PMOD ENTER op=%u rule_id=%u direction=%u protocol=%u port=%u pid=%u pattern_size=%u replace_size=%u active_before=%ld generation_before=%lld irql=%u cpu=%lu",
        request->operation,
        request->rule_id,
        request->direction,
        request->protocol,
        request->port,
        request->pid,
        request->pattern_size,
        request->replace_size,
        active_before,
        generation_before,
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    NTSTATUS st = net_mod::handle_mod_rule(request);
    NET_DBG("handle_packet_mod_rule: returned 0x%08x rule_id=%u active=%u",
            st, request->rule_id, request->active);
    SD_LOG("netaction::PMOD EXIT status=0x%08X win32=%lu op=%u rule_id=%u active=%u active_before=%ld active_after=%ld generation_before=%lld generation_after=%lld elapsed_tsc=%llu irql=%u cpu=%lu",
        st,
        net_capture::status_to_win32(st),
        request->operation,
        request->rule_id,
        request->active,
        active_before,
        net_mod::active_rule_count(),
        generation_before,
        net_mod::current_generation(),
        (unsigned long long)(__rdtsc() - start_tsc),
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    return st;
}

NTSTATUS functions::handle_packet_mod_rule_list(p_packet_mod_rule_list request) {
    if (!request) { NET_ERR("handle_packet_mod_rule_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    UINT64 start_tsc = __rdtsc();
    LONG active_before = net_mod::active_rule_count();
    LONG64 generation_before = net_mod::current_generation();
    SD_LOG("netaction::PMOD_LIST ENTER op=%u active_before=%ld generation_before=%lld irql=%u cpu=%lu",
        request->operation,
        active_before,
        generation_before,
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    NTSTATUS st = net_mod::handle_mod_rule_list(request);
    SD_LOG("netaction::PMOD_LIST EXIT status=0x%08X win32=%lu returned=%u active_before=%ld active_after=%ld generation_before=%lld generation_after=%lld elapsed_tsc=%llu irql=%u cpu=%lu",
        st,
        net_capture::status_to_win32(st),
        request->rule_count,
        active_before,
        net_mod::active_rule_count(),
        generation_before,
        net_mod::current_generation(),
        (unsigned long long)(__rdtsc() - start_tsc),
        (UINT32)KeGetCurrentIrql(),
        KeGetCurrentProcessorNumber());
    return st;
}

NTSTATUS functions::handle_traffic_redirect(p_traffic_redirect_rule request) {
    if (!request) { NET_ERR("handle_traffic_redirect: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_traffic_redirect: op=%u rule_id=%u", request->operation, request->rule_id);
    NTSTATUS st = net_redirect::handle_redirect_rule(request);
    NET_DBG("handle_traffic_redirect: returned 0x%08x rule_id=%u active=%u",
            st, request->rule_id, request->active);
    return st;
}

NTSTATUS functions::handle_traffic_redirect_list(p_traffic_redirect_list request) {
    if (!request) { NET_ERR("handle_traffic_redirect_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_redirect::handle_redirect_list(request);
}

NTSTATUS functions::handle_stream_reassemble(p_stream_reassemble_request request) {
    if (!request) {
        SD_LOG("netaction::handle_stream_reassemble NULL_REQUEST status=STATUS_INVALID_PARAMETER");
        NET_ERR("handle_stream_reassemble: NULL request");
        return STATUS_INVALID_PARAMETER;
    }
    SD_LOG("netaction::handle_stream_reassemble ENTER op=%u src_port=%u dst_port=%u pid=%u",
        request->operation, request->src_port, request->dst_port, request->pid);
    NET_DBG("handle_stream_reassemble: op=%u src_port=%u dst_port=%u pid=%u",
            request->operation, request->src_port, request->dst_port, request->pid);
    if (request->operation == 0 && request->pid != 0) {
        slop_refresh_pid_cache_for_process(request->pid, IPPROTO_TCP);
    }
    NTSTATUS st = net_stream::handle_stream(request);
    SD_LOG("netaction::handle_stream_reassemble EXIT status=0x%08X stream_size=%u total_packets=%u stream_count=%u truncated=%u",
        st, request->stream_size, request->total_packets, request->stream_count, request->truncated);
    NET_DBG("handle_stream_reassemble: returned 0x%08x stream_size=%u total_pkts=%u",
            st, request->stream_size, request->total_packets);
    return st;
}

NTSTATUS functions::handle_deep_inspect(p_dpi_request request) {
    if (!request) { NET_ERR("handle_deep_inspect: NULL request"); return STATUS_INVALID_PARAMETER; }
    SD_LOG("netaction::DPIN ENTER filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X active=%u ring_count=%ld",
        request->filter_pid,
        request->filter_protocol,
        request->filter_port,
        request->flags,
        net_dpi::is_active() ? 1u : 0u,
        net_dpi::entry_count());
    if (request->filter_pid != 0) {
        slop_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    const LONG before = net_dpi::entry_count();
    const BOOLEAN active = net_dpi::is_active();
    NTSTATUS st = net_dpi::get_results(request);
    NET_DBG("netaction::DPIN active=%u ring_count=%ld filter_pid=%u filter_proto=%u filter_port=%u flags=0x%08x results=%u status=0x%08lx",
        active ? 1u : 0u,
        before,
        request->filter_pid,
        request->filter_protocol,
        request->filter_port,
        request->flags,
        request->result_count,
        st);
    SD_LOG("netaction::DPIN EXIT status=0x%08X win32=%lu active_before=%u ring_before=%ld result_count=%u filter_pid=%u filter_protocol=%u filter_port=%u flags=0x%08X",
        st,
        net_capture::status_to_win32(st),
        active ? 1u : 0u,
        before,
        request->result_count,
        request->filter_pid,
        request->filter_protocol,
        request->filter_port,
        request->flags);
    return st;
}

NTSTATUS functions::handle_intercept_hold(p_intercept_request request) {
    if (!request) { NET_ERR("handle_intercept_hold: NULL request"); return STATUS_INVALID_PARAMETER; }
    if (request->operation == 0 && request->filter_pid != 0) {
        slop_refresh_pid_cache_for_process(request->filter_pid, request->filter_protocol);
    }
    return net_intercept::handle_intercept(request);
}

NTSTATUS functions::handle_conn_kill(p_conn_kill_request request) {
    if (!request) {
        SD_LOG("netaction::handle_conn_kill NULL_REQUEST status=STATUS_INVALID_PARAMETER");
        NET_ERR("handle_conn_kill: NULL request");
        return STATUS_INVALID_PARAMETER;
    }
    SD_LOG("netaction::handle_conn_kill ENTER protocol=%u af=%u src_port=%u dst_port=%u pid=%u src=%u.%u.%u.%u dst=%u.%u.%u.%u",
        request->protocol, request->address_family,
        request->src_port, request->dst_port, request->pid,
        request->src_addr[0], request->src_addr[1], request->src_addr[2], request->src_addr[3],
        request->dst_addr[0], request->dst_addr[1], request->dst_addr[2], request->dst_addr[3]);
    NTSTATUS st = net_kill::kill_connection(request);
    SD_LOG("netaction::handle_conn_kill EXIT status=0x%08X request_status=%u",
        st, request->status);
    if (!NT_SUCCESS(st)) {
        NET_ERR("handle_conn_kill: FAILED status=0x%08x", st);
    }
    return st;
}

NTSTATUS functions::handle_dns_spoof(p_dns_spoof_rule request) {
    if (!request) { NET_ERR("handle_dns_spoof: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_dns_spoof::handle_spoof_rule(request);
}

NTSTATUS functions::handle_dns_spoof_list(p_dns_spoof_list request) {
    if (!request) { NET_ERR("handle_dns_spoof_list: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_dns_spoof::handle_spoof_list(request);
}

NTSTATUS functions::handle_bw_monitor(p_bw_monitor_request request) {
    if (!request) { NET_ERR("handle_bw_monitor: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_bw_monitor: op=%u filter_pid=%u", request->operation, request->filter_pid);
    NTSTATUS st = net_bw::handle_bw(request);
    NET_DBG("handle_bw_monitor: returned 0x%08x active=%u total_sent=%llu total_recv=%llu",
            st, request->monitoring_active, request->total_bytes_sent, request->total_bytes_recv);
    return st;
}

NTSTATUS functions::handle_net_iface_enum(p_net_interface_enum request) {
    if (!request) { NET_ERR("handle_net_iface_enum: NULL request"); return STATUS_INVALID_PARAMETER; }
    NET_DBG("handle_net_iface_enum: enter");
    NTSTATUS st = net_if_enum::enumerate_interfaces(request);
    NET_DBG("handle_net_iface_enum: returned 0x%08x count=%u", st, request->interface_count);
    return st;
}

NTSTATUS functions::handle_pcap_export(p_pcap_export_request request) {
    if (!request) { NET_ERR("handle_pcap_export: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_pcap::export_pcap(request);
}

NTSTATUS functions::handle_net_fingerprint(p_net_fingerprint_request request) {
    if (!request) { NET_ERR("handle_net_fingerprint: NULL request"); return STATUS_INVALID_PARAMETER; }
    return net_fingerprint::handle_fingerprint(request);
}
