#include <ntifs.h>
#include <imports/Defs.h>
#include <function/Dispatcher.h>
#include <function/KernelDebugCapture.h>

namespace net_capture {
    NTSTATUS initialize(PDEVICE_OBJECT devObj);
    void cleanup();
}

static UINT64 sd_handle_to_u64(HANDLE value)
{
    return static_cast<UINT64>(reinterpret_cast<ULONG_PTR>(value));
}

static ULONG sd_elapsed_us(const LARGE_INTEGER& start, const LARGE_INTEGER& freq)
{
    LARGE_INTEGER now = KeQueryPerformanceCounter(nullptr);
    if (freq.QuadPart <= 0 || now.QuadPart < start.QuadPart)
        return 0;
    return static_cast<ULONG>(((now.QuadPart - start.QuadPart) * 1000000ULL) / static_cast<ULONGLONG>(freq.QuadPart));
}

static ULONG sd_read_kuser_u32(ULONG offset)
{
    ULONG value = 0;
    __try {
        volatile ULONG* ptr = reinterpret_cast<volatile ULONG*>(0xFFFFF78000000000ULL + offset);
        value = *ptr;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        value = 0;
    }
    return value;
}

static void sd_log_driverentry_phase(const char* phase, const LARGE_INTEGER& start, const LARGE_INTEGER& freq)
{
    ULONG build = sd_read_kuser_u32(0x260) & 0xFFFFu;
    ULONG ci_options = sd_read_kuser_u32(0x3A8);
    SD_LOG("DriverEntryPhase phase=%s elapsed_us=%lu pid=%llu tid=%llu irql=%lu cpu=%lu build=%lu ci_options=0x%08lx initialized_log=%u",
        phase ? phase : "unknown",
        sd_elapsed_us(start, freq),
        sd_handle_to_u64(PsGetCurrentProcessId()),
        sd_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()),
        KeGetCurrentProcessorNumber(),
        build,
        ci_options,
        1u);
}

static void ZeroUninitializedSectionsSelf(PVOID self_anchor)
{
    if (!self_anchor) {
        return;
    }

    ULONG_PTR cursor = reinterpret_cast<ULONG_PTR>(self_anchor) & ~(static_cast<ULONG_PTR>(0xFFF));
    PIMAGE_DOS_HEADER dos = nullptr;
    for (ULONG steps = 0; steps < 0x4000; ++steps) {
        PIMAGE_DOS_HEADER candidate = reinterpret_cast<PIMAGE_DOS_HEADER>(cursor);
        if (candidate->e_magic == IMAGE_DOS_SIGNATURE) {
            LONG nt_offset = candidate->e_lfanew;
            if (nt_offset > 0 && nt_offset < 0x1000) {
                PIMAGE_NT_HEADERS64 nt_check = reinterpret_cast<PIMAGE_NT_HEADERS64>(
                    reinterpret_cast<UCHAR*>(candidate) + nt_offset);
                if (nt_check->Signature == IMAGE_NT_SIGNATURE &&
                    nt_check->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
                    dos = candidate;
                    break;
                }
            }
        }
        if (cursor < 0x1000) {
            return;
        }
        cursor -= 0x1000;
    }

    if (!dos) {
        return;
    }

    UCHAR* base = reinterpret_cast<UCHAR*>(dos);
    PIMAGE_NT_HEADERS64 nt = reinterpret_cast<PIMAGE_NT_HEADERS64>(base + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    USHORT count = nt->FileHeader.NumberOfSections;
    for (USHORT i = 0; i < count; ++i) {
        ULONG vsize = sec[i].Misc.VirtualSize;
        ULONG rsize = sec[i].SizeOfRawData;
        if (vsize > rsize) {
            UCHAR* dst = base + sec[i].VirtualAddress + rsize;
            ULONG diff = vsize - rsize;
            RtlZeroMemory(dst, diff);
        }
    }
}

namespace slopdrvr_build_identity {
    constexpr unsigned long long fnv1a64(const char* text) {
        unsigned long long h = 14695981039346656037ull;
        while (*text) {
            h ^= static_cast<unsigned char>(*text);
            h *= 1099511628211ull;
            ++text;
        }
        return h;
    }

    constexpr unsigned long long kHash = fnv1a64("slopdrvr|" __DATE__ "|" __TIME__ "|" __FILE__);
}

// Teardown order mirrors creation in reverse. Runs at PASSIVE_LEVEL on the
// NtUnloadDriver thread; the dispatcher has already refused new IOCTLs since
// the SHUTDOWN ioctl (or this routine's own quiesce arm) set g_unloading.
static VOID NTAPI DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);

    LARGE_INTEGER freq = {};
    LARGE_INTEGER start = KeQueryPerformanceCounter(&freq);
    dbg_capture::write_immediate_formatted("[SD-EARLY] DriverUnload entered pid=%llu tid=%llu irql=%lu\n",
        sd_handle_to_u64(PsGetCurrentProcessId()),
        sd_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()));

    // 1. Quiesce: reject new IOCTLs from here on.
    _InterlockedExchange(&sd_state::g_unloading, 1);

    // 2. Wait (bounded) for in-flight IOCTLs to complete so teardown never
    //    races a concurrent dispatcher call into freed state.
    for (ULONG spin = 0; spin < 100; ++spin) {
        if (_InterlockedCompareExchange(&sd_state::g_active_ioctls, 0, 0) == 0)
            break;
        LARGE_INTEGER pause;
        pause.QuadPart = -(10LL * 10000LL);   // 10 ms
        KeDelayExecutionThread(KernelMode, FALSE, &pause);
    }
    SD_LOG("DriverUnload: quiesced active_ioctls=%ld",
        _InterlockedCompareExchange(&sd_state::g_active_ioctls, 0, 0));

    // 3. Subsystem teardown, reverse of DriverEntry: network (WFP callouts,
    //    filters, sublayer, rings) -> debug events (notify callbacks, ring)
    //    -> malware-safe (process/registry callbacks, sandbox rings).
    net_capture::cleanup();
    debug_events::cleanup();
    malware_safe::cleanup();

    // 4. Symbolic link + device object. Callouts are gone, so nothing can
    //    reference the device anymore.
    UNICODE_STRING symLink = {};
    _RtlInitUnicodeString(&symLink, device_names::get_symlink_name());
    NTSTATUS sym_status = _IoDeleteSymbolicLink(&symLink);
    SD_LOG("DriverUnload: IoDeleteSymbolicLink status=0x%08lx", sym_status);

    if (DriverObject && DriverObject->DeviceObject) {
        _IoDeleteDevice(DriverObject->DeviceObject);
    }

    // 5. dbg_capture last — the teardown logging above needs it. shutdown()
    //    stops the drain thread after one final flush.
    dbg_capture::shutdown();

    dbg_capture::write_immediate_formatted("[SD-EARLY] DriverUnload complete elapsed_us=%lu\n",
        sd_elapsed_us(start, freq));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {

    LARGE_INTEGER entry_freq = {};
    LARGE_INTEGER entry_start = KeQueryPerformanceCounter(&entry_freq);
    dbg_capture::configure_log_path(RegistryPath);
    service_identity::capture(RegistryPath);
    ULONG early_build = sd_read_kuser_u32(0x260) & 0xFFFFu;
    ULONG early_ci_options = sd_read_kuser_u32(0x3A8);
    dbg_capture::write_immediate_formatted("[SD-EARLY] DriverEntry entered driver_object_present=%u registry_path_present=%u pid=%llu tid=%llu irql=%lu cpu=%lu build=%lu ci_options=0x%08lx\n",
        DriverObject != nullptr ? 1u : 0u,
        RegistryPath != nullptr ? 1u : 0u,
        sd_handle_to_u64(PsGetCurrentProcessId()),
        sd_handle_to_u64(PsGetCurrentThreadId()),
        static_cast<ULONG>(KeGetCurrentIrql()),
        KeGetCurrentProcessorNumber(),
        early_build,
        early_ci_options);
    dbg_capture::write_immediate_formatted("[SD-EARLY] build_identity hash=0x%llX date=%s time=%s msc=%u cpp=%lu entry=%p\n",
        slopdrvr_build_identity::kHash,
        __DATE__,
        __TIME__,
        (unsigned)_MSC_VER,
        (unsigned long)__cplusplus,
        reinterpret_cast<PVOID>(&DriverEntry));
    ZeroUninitializedSectionsSelf(reinterpret_cast<PVOID>(&DriverEntry));
    dbg_capture::write_immediate_formatted("[SD-EARLY] SetupFunctions begin\n");

    if (!SetupFunctions()) {
        dbg_capture::write_immediate_formatted("[SD-EARLY] SetupFunctions FAILED elapsed_us=%lu\n",
            sd_elapsed_us(entry_start, entry_freq));
        return STATUS_UNSUCCESSFUL;
    }

    dbg_capture::write_immediate_formatted("[SD-EARLY] SetupFunctions OK elapsed_us=%lu\n",
        sd_elapsed_us(entry_start, entry_freq));

    NTSTATUS dbg_status = dbg_capture::initialize();
    dbg_capture::write_immediate_formatted("[SD-EARLY] dbg_capture::initialize status=0x%08lx elapsed_us=%lu\n",
        static_cast<ULONG>(dbg_status),
        sd_elapsed_us(entry_start, entry_freq));

    SD_LOG("DriverEntry: SetupFunctions OK");
    SD_LOG("DriverEntry: build_identity hash=0x%llX date=%s time=%s msc=%u cpp=%lu entry=%p driver_object=%p registry_path_present=%u",
        slopdrvr_build_identity::kHash,
        __DATE__,
        __TIME__,
        (unsigned)_MSC_VER,
        (unsigned long)__cplusplus,
        reinterpret_cast<PVOID>(&DriverEntry),
        DriverObject,
        RegistryPath != nullptr ? 1u : 0u);
    sd_log_driverentry_phase("post_setup", entry_start, entry_freq);

    if (!device_names::initialize_names()) {
        SD_LOG("DriverEntry: initialize_names FAILED elapsed_us=%lu", sd_elapsed_us(entry_start, entry_freq));
        dbg_capture::shutdown();   // drain thread must not outlive a failed entry
        return STATUS_UNSUCCESSFUL;
    }

    SD_LOG("DriverEntry: device names initialized device=%ws symlink=%ws elapsed_us=%lu",
        device_names::get_device_name(),
        device_names::get_symlink_name(),
        sd_elapsed_us(entry_start, entry_freq));

    UNICODE_STRING deviceName = {};
    _RtlInitUnicodeString(&deviceName, device_names::get_device_name());

    PDEVICE_OBJECT deviceObject = nullptr;

    NTSTATUS status = _IoCreateDevice(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject
    );

    if (!NT_SUCCESS(status)) {
        SD_LOG("DriverEntry: IoCreateDevice FAILED status=0x%08lx device=%wZ elapsed_us=%lu irql=%lu",
            status,
            &deviceName,
            sd_elapsed_us(entry_start, entry_freq),
            static_cast<ULONG>(KeGetCurrentIrql()));
        dbg_capture::shutdown();
        return status;
    }

    SD_LOG("DriverEntry: device created present=%u device_object=%p device=%wZ flags=0x%lx elapsed_us=%lu",
        deviceObject != nullptr ? 1u : 0u,
        deviceObject,
        &deviceName,
        deviceObject ? deviceObject->Flags : 0,
        sd_elapsed_us(entry_start, entry_freq));

    UNICODE_STRING symLink = {};
    _RtlInitUnicodeString(&symLink, device_names::get_symlink_name());

    _IoDeleteSymbolicLink(&symLink);

    status = _IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        SD_LOG("DriverEntry: IoCreateSymbolicLink FAILED status=0x%08lx device=%wZ symlink=%wZ elapsed_us=%lu",
            status,
            &deviceName,
            &symLink,
            sd_elapsed_us(entry_start, entry_freq));
        _IoDeleteDevice(deviceObject);
        dbg_capture::shutdown();
        return status;
    }

    SD_LOG("DriverEntry: symlink created device=%wZ symlink=%wZ elapsed_us=%lu",
        &deviceName,
        &symLink,
        sd_elapsed_us(entry_start, entry_freq));

    SetFlag(deviceObject->Flags, DO_BUFFERED_IO);

    DriverObject->MajorFunction[IRP_MJ_CREATE]         = dispatcher::Pilot;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = dispatcher::Pilot;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = dispatcher::Controller;

    DriverObject->DriverUnload = DriverUnload;
    SD_LOG("DriverEntry: dispatch table assigned create=%p close=%p ioctl=%p unload=%p device_flags=0x%lx driver_object=%p elapsed_us=%lu",
        DriverObject->MajorFunction[IRP_MJ_CREATE],
        DriverObject->MajorFunction[IRP_MJ_CLOSE],
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
        DriverObject->DriverUnload,
        deviceObject->Flags,
        DriverObject,
        sd_elapsed_us(entry_start, entry_freq));
    SD_LOG("DriverEntry: service_identity captured=%u path=%ws",
        service_identity::is_captured() ? 1u : 0u,
        service_identity::get());

    if (DriverObject->DriverSection) {
        auto ldrEntry = static_cast<PLDR_DATA_TABLE_ENTRY>(DriverObject->DriverSection);
        ldrEntry->Flags |= 0x20u;
        SD_LOG("DriverEntry: DriverSection flag set ldr=%p flags=0x%lx base=%p size=0x%lx elapsed_us=%lu",
            ldrEntry,
            ldrEntry->Flags,
            ldrEntry->DllBase,
            ldrEntry->SizeOfImage,
            sd_elapsed_us(entry_start, entry_freq));
    }

    ClearFlag(deviceObject->Flags, DO_DEVICE_INITIALIZING);
    SD_LOG("DriverEntry: device initialization cleared flags=0x%lx elapsed_us=%lu",
        deviceObject->Flags,
        sd_elapsed_us(entry_start, entry_freq));
    dbg_capture::write_immediate_formatted("[SD-EARLY] device initialization cleared flags=0x%lx elapsed_us=%lu\n",
        deviceObject->Flags,
        sd_elapsed_us(entry_start, entry_freq));

    dbg_capture::write_immediate_formatted("[SD-EARLY] net_capture::initialize enter device=%p elapsed_us=%lu\n",
        deviceObject,
        sd_elapsed_us(entry_start, entry_freq));
    status = net_capture::initialize(deviceObject);
    dbg_capture::write_immediate_formatted("[SD-EARLY] net_capture::initialize exit status=0x%08lx elapsed_us=%lu\n",
        static_cast<ULONG>(status),
        sd_elapsed_us(entry_start, entry_freq));
    if (!NT_SUCCESS(status)) {
        SD_LOG("DriverEntry: net_capture::initialize FAILED status=0x%08lx device_object=%p elapsed_us=%lu",
            status,
            deviceObject,
            sd_elapsed_us(entry_start, entry_freq));
        _IoDeleteSymbolicLink(&symLink);
        _IoDeleteDevice(deviceObject);
        dbg_capture::shutdown();
        return status;
    }

    SD_LOG("DriverEntry: net_capture initialized elapsed_us=%lu", sd_elapsed_us(entry_start, entry_freq));
    dbg_capture::write_immediate_formatted("[SD-EARLY] net_capture initialized elapsed_us=%lu\n",
        sd_elapsed_us(entry_start, entry_freq));

    NTSTATUS dbe_status = debug_events::initialize();
    SD_LOG("DriverEntry: debug_events::initialize returned 0x%08lx elapsed_us=%lu", dbe_status, sd_elapsed_us(entry_start, entry_freq));

    SD_LOG("DriverEntry: invoking malware_safe::init ...");
    NTSTATUS ms_status = malware_safe::init(DriverObject);
    if (!NT_SUCCESS(ms_status) && ms_status != STATUS_ALREADY_REGISTERED) {
        SD_LOG("DriverEntry: malware_safe::init FAILED 0x%08lx - continuing with malware-safe gating DISABLED",
            ms_status);
    } else {
        SD_LOG("DriverEntry: malware_safe::init OK status=0x%08lx callback_registered=%d create_notify_registered=%d",
            ms_status,
            malware_safe::g_registry_callback_registered,
            malware_safe::g_create_notify_registered);
    }

    SD_LOG("DriverEntry: COMPLETE elapsed_us=%lu device=%p driver=%p",
        sd_elapsed_us(entry_start, entry_freq),
        deviceObject,
        DriverObject);

    return STATUS_SUCCESS;
}
