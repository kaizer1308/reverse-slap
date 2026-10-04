#include "../Functions.h"
#include "../../imports/Defs.h"
#include "../Struct.h"

namespace token_impl {

    typedef PACCESS_TOKEN(NTAPI* pfn_PsReferencePrimaryToken)(PEPROCESS Process);
    typedef VOID(NTAPI* pfn_PsDereferencePrimaryToken)(PACCESS_TOKEN PrimaryToken);
    typedef NTSTATUS(NTAPI* pfn_SeQueryInformationToken)(
        PACCESS_TOKEN Token, ULONG TokenInformationClass, PVOID* TokenInformation);
    typedef ULONG(NTAPI* pfn_PsGetProcessSessionId)(PEPROCESS Process);

    inline pfn_PsReferencePrimaryToken g_PsReferencePrimaryToken = nullptr;
    inline pfn_PsDereferencePrimaryToken g_PsDereferencePrimaryToken = nullptr;
    inline pfn_SeQueryInformationToken g_SeQueryInformationToken = nullptr;
    inline pfn_PsGetProcessSessionId g_PsGetProcessSessionId = nullptr;
    inline volatile LONG g_resolved = 0;

    __forceinline void resolve() {
        if (_InterlockedCompareExchange(&g_resolved, 0, 0) != 0) return;
        if (KeGetCurrentIrql() != PASSIVE_LEVEL) return;
        UNICODE_STRING name;

        RtlInitUnicodeString(&name, L"PsReferencePrimaryToken");
        g_PsReferencePrimaryToken = reinterpret_cast<pfn_PsReferencePrimaryToken>(
            MmGetSystemRoutineAddress(&name));

        RtlInitUnicodeString(&name, L"PsDereferencePrimaryToken");
        g_PsDereferencePrimaryToken = reinterpret_cast<pfn_PsDereferencePrimaryToken>(
            MmGetSystemRoutineAddress(&name));

        RtlInitUnicodeString(&name, L"SeQueryInformationToken");
        g_SeQueryInformationToken = reinterpret_cast<pfn_SeQueryInformationToken>(
            MmGetSystemRoutineAddress(&name));

        RtlInitUnicodeString(&name, L"PsGetProcessSessionId");
        g_PsGetProcessSessionId = reinterpret_cast<pfn_PsGetProcessSessionId>(
            MmGetSystemRoutineAddress(&name));

        _InterlockedExchange(&g_resolved, 1);
    }

    constexpr ULONG TokenPrivileges_class = 3;
    constexpr ULONG TokenElevation_class = 20;
    constexpr ULONG TokenIntegrityLevel_class = 25;

    struct SID_AND_ATTRIBUTES_K {
        PVOID Sid;
        ULONG Attributes;
    };

    struct TOKEN_MANDATORY_LABEL_K {
        SID_AND_ATTRIBUTES_K Label;
    };

    struct TOKEN_ELEVATION_K {
        ULONG TokenIsElevated;
    };

    struct LUID_AND_ATTRIBUTES_K {
        ULONG LowPart;
        LONG HighPart;
        ULONG Attributes;
    };

    struct TOKEN_PRIVILEGES_K {
        ULONG PrivilegeCount;
        LUID_AND_ATTRIBUTES_K Privileges[1];
    };
}

NTSTATUS functions::handle_token_query(p_token_query request) {
    if (!request) return STATUS_INVALID_PARAMETER;

    UINT32 pid = request->pid;
    request->integrity_level = 0;
    request->session_id = 0;
    request->elevated = 0;
    request->privilege_count = 0;

    token_impl::resolve();
    if (!token_impl::g_PsReferencePrimaryToken ||
        !token_impl::g_PsDereferencePrimaryToken ||
        !token_impl::g_SeQueryInformationToken)
        return STATUS_NOT_SUPPORTED;

    if (!_PsLookupProcessByProcessId) return STATUS_NOT_SUPPORTED;

    PEPROCESS process = nullptr;
    NTSTATUS st = _PsLookupProcessByProcessId(
        reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(pid)), &process);
    if (!NT_SUCCESS(st) || !process) return st;

    PACCESS_TOKEN token = token_impl::g_PsReferencePrimaryToken(process);
    if (!token) {
        _ObfDereferenceObject(process);
        return STATUS_UNSUCCESSFUL;
    }

    __try {
        token_impl::TOKEN_MANDATORY_LABEL_K* label = nullptr;
        st = token_impl::g_SeQueryInformationToken(
            token, token_impl::TokenIntegrityLevel_class,
            reinterpret_cast<PVOID*>(&label));
        if (NT_SUCCESS(st) && label) {
            PUCHAR sid = static_cast<PUCHAR>(label->Label.Sid);
            if (sid && sid[0] == 1 && sid[1] >= 1) {
                PULONG sub_auths = reinterpret_cast<PULONG>(sid + 8);
                request->integrity_level = sub_auths[sid[1] - 1];
            }
            ExFreePool(label);
        }

        token_impl::TOKEN_ELEVATION_K* elev = nullptr;
        st = token_impl::g_SeQueryInformationToken(
            token, token_impl::TokenElevation_class,
            reinterpret_cast<PVOID*>(&elev));
        if (NT_SUCCESS(st) && elev) {
            request->elevated = elev->TokenIsElevated;
            ExFreePool(elev);
        }

        token_impl::TOKEN_PRIVILEGES_K* privs = nullptr;
        st = token_impl::g_SeQueryInformationToken(
            token, token_impl::TokenPrivileges_class,
            reinterpret_cast<PVOID*>(&privs));
        if (NT_SUCCESS(st) && privs) {
            ULONG pcnt = privs->PrivilegeCount;
            if (pcnt > MAX_TOKEN_PRIVILEGES) pcnt = MAX_TOKEN_PRIVILEGES;
            request->privilege_count = pcnt;
            for (ULONG i = 0; i < pcnt; ++i) {
                request->privileges[i].luid_low = privs->Privileges[i].LowPart;
                request->privileges[i].luid_high = static_cast<UINT32>(privs->Privileges[i].HighPart);
                request->privileges[i].attributes = privs->Privileges[i].Attributes;
                request->privileges[i].padding = 0;
            }
            ExFreePool(privs);
        }

        if (token_impl::g_PsGetProcessSessionId)
            request->session_id = token_impl::g_PsGetProcessSessionId(process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
    }

    token_impl::g_PsDereferencePrimaryToken(token);
    _ObfDereferenceObject(process);
    return STATUS_SUCCESS;
}
