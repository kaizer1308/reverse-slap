// src/core/runtime/ptwalk.hpp
// page table utilities over the winotify kernel primitives. the pte self map
// base comes from ntoskrnl's MmGetVirtualForPhysical export, and the physical
// window lives at a kernel va inside the driver's own image slack, so mapping
// a foreign frame never creates a user space alias in our process. on top of
// that: ghost chain linking (fresh or vad covered placement), page orphaning,
// pfn attribution forging for backing and table pages, and table enumeration

#pragma once

#include "core/runtime/winotify_driver.hpp"

#include <cstdint>
#include <vector>

namespace slop::core::runtime::ptwalk {

constexpr std::uint64_t kPtePresent = 1ull << 0;
constexpr std::uint64_t kPteWrite   = 1ull << 1;
constexpr std::uint64_t kPteUser    = 1ull << 2;
constexpr std::uint64_t kPteNx      = 1ull << 63;
constexpr std::uint64_t kPhysMask   = 0x000FFFFFFFFFF000ull;

struct table_entry_t {
    std::uint64_t raw = 0;
    bool present() const noexcept { return (raw & kPtePresent) != 0; }
    bool write() const noexcept { return (raw & kPteWrite) != 0; }
    bool user() const noexcept { return (raw & kPteUser) != 0; }
    bool large() const noexcept { return (raw & (1ull << 7)) != 0; }
    bool nx() const noexcept { return (raw & kPteNx) != 0; }
    std::uint64_t frame() const noexcept { return raw & kPhysMask; }
};

// derive (once) and cache the pte self map base
bool ensure_pte_base(winotify::driver_t& dev);
std::uint64_t pte_base() noexcept;

std::uint64_t kernel_export_va(winotify::driver_t& dev, const char* name);
std::uint64_t kernel_module_size(winotify::driver_t& dev, std::uint64_t base);

// self map slots for any va
std::uint64_t pte_slot_va(std::uint64_t va) noexcept;
std::uint64_t pde_slot_va(std::uint64_t va) noexcept;
std::uint64_t pdpte_slot_va(std::uint64_t va) noexcept;
std::uint64_t pml4e_slot_va(std::uint64_t va) noexcept;

bool read_pte_va(winotify::driver_t& dev, std::uint64_t va, table_entry_t& out);
bool write_pte_va(winotify::driver_t& dev, std::uint64_t va, std::uint64_t raw);
std::uint64_t translate_own(winotify::driver_t& dev, std::uint64_t va);

// physical window over a kernel va inside the driver image slack: the scratch
// pte is forged through the self map and all access happens through the kernel
// read/write ioctls, so no user mapping of a foreign frame ever exists.
// window(va).read/write helpers below are the only supported accessors
struct window_t {
    winotify::driver_t* dev = nullptr;
    std::uint64_t kva = 0;       // kernel va of the mapped frame
    bool kernel = false;         // false = user scratch fallback active
    bool valid() const noexcept { return dev != nullptr && kva != 0; }
    bool read(std::uint64_t pa_off, void* buf, std::size_t len);
    bool write(std::uint64_t pa_off, const void* buf, std::size_t len);
};

bool window_open(winotify::driver_t& dev, std::uint64_t pa, window_t& out);
void window_close(window_t& w);

// a dtb (cr3 or a solved table) that can translate kernel vas for phys writes
std::uint64_t kernel_write_dtb(winotify::driver_t& dev);

// walk a foreign table to a raw pte/pde without any self map assumption
bool read_foreign_pte(winotify::driver_t& dev, std::uint64_t pml4_pa,
                      std::uint64_t va, std::uint64_t& raw_out);
bool write_foreign_pte(winotify::driver_t& dev, std::uint64_t pml4_pa,
                       std::uint64_t va, std::uint64_t raw);

enum class placement_t { fresh, vad_covered };

// fresh: chain a brand new pml4 slot. vad_covered: reuse an absent pte inside
// a page table that already serves the target's own image mappings, so the
// present pte falls inside an existing vad and coverage checks pass (collides
// only if the target later commits that exact page)
std::uint64_t find_free_pml4_slot(winotify::driver_t& dev, std::uint64_t pml4_pa,
                                  std::uint32_t first, std::uint32_t last);
std::uint64_t find_vad_covered_slot(winotify::driver_t& dev, std::uint64_t pml4_pa);

// find the kernel va of our own device object by walking our process's
// handle table: eprocess -> objecttable -> tablecode -> entry for the
// device handle. validates via Type==3 (IO_TYPE_DEVICE) and the
// driverobject backlink to our driver base. returns 0 on failure
std::uint64_t find_own_device_object(winotify::driver_t& dev, void* device_handle,
                                     std::uint32_t own_pid);

// wipe the "WinNotify" name from the OBJECT_HEADER_NAME_INFO that
// precedes the device object in kernel pool: scan backwards from the
// object header for the UNICODE_STRING matching "WinNotify", then zero
// the string characters via kernel_write (pool is rw)
bool wipe_object_name_info(winotify::driver_t& dev, std::uint64_t device_va);

// insert working set list entries for the ghost pages so ws enumeration
// (NtQueryInformationProcess / ProcessWorkingSetInfo) sees them as part
// of the target's working set. eprocess vm.WorkingSetPagedPoolVa is
// read, the wsle array is located, and free slots are populated with
// the ghost vas + valid protection attributes. best effort - the mm
// manages the wsle free list, so we only add to slots that are already
// free (zero entries in the array beyond the current count)
bool insert_working_set_entries(winotify::driver_t& dev, std::uint64_t eprocess,
                                std::uint64_t base, std::size_t page_count);

// link the ghost chain; exec_map is per backing page (true = executable, nx
// clear), false gets the nx bit set. mirrors into our own table for reads.
// out_table_pas/out_table_vas receive the pdpt/pd/pt physical addresses and
// our vas for orphaning
bool ghost_link(winotify::driver_t& dev, std::uint64_t backing_va,
                std::size_t page_count, const std::vector<bool>& exec_map,
                std::uint64_t chosen_base, std::uint64_t target_pml4_pa,
                std::uint64_t own_pml4_pa, std::uint64_t eprocess_va,
                std::vector<std::uint64_t>& out_table_pas,
                std::vector<void*>& out_table_vas);

// drop our own mappings of backing + table pages so exactly one pte (the
// ghost chain) maps each frame; run after pfn forging for the backing pages
bool orphan_sources(winotify::driver_t& dev, std::uint64_t backing_va,
                    std::size_t backing_count,
                    const std::vector<void*>& table_vas);

// zero ghost ptes in the target's page table on shutdown to prevent
// dangling ptes pointing at recycled physical memory after our exit
bool cleanup_ghost_ptes(winotify::driver_t& dev, std::uint64_t target_pml4_pa,
                        std::uint64_t chosen_base, std::size_t page_count);
// rewrite pfn PteAddress so pfn cross checks attribute the frames to the
// target's ghost vas; run the backing variant before orphaning and the table
// variant (with the captured pas) after
bool forge_pfn_backing(winotify::driver_t& dev, std::uint64_t backing_va,
                       std::size_t page_count, std::uint64_t chosen_base);
bool forge_pfn_tables(winotify::driver_t& dev,
                      const std::vector<std::uint64_t>& table_pas,
                      std::uint64_t chosen_base);

bool own_table_has_kernel_half(winotify::driver_t& dev);

// enumerate present user mappings of a target straight from its tables
struct mapping_t {
    std::uint64_t base = 0;
    std::uint64_t size = 0;
    bool write = false;
    bool nx = false;
    bool large = false;
};
std::vector<mapping_t> enumerate_user_mappings(winotify::driver_t& dev,
                                               std::uint64_t pml4_pa);

// rewrite inter-function cc padding in the loaded driver image so in-memory
// byte pattern scans against the published driver hash stop matching
bool mutate_driver_text(winotify::driver_t& dev);

// resolve the target's EPROCESS by walking PsActiveProcessHead and matching
// the pid; offsets are build-aware (>=26100 vs >=19041)
std::uint64_t find_eprocess(winotify::driver_t& dev, std::uint32_t pid);

// insert a fake MMVAD_SHORT covering [base, base+size) into the target's vad
// tree as a private committed region. the node lives in driver image slack.
// returns the kernel va of the inserted node (0 on failure) for later removal
std::uint64_t insert_fake_vad(winotify::driver_t& dev, std::uint64_t eprocess,
                              std::uint64_t base, std::uint64_t size,
                              std::uint32_t protect);
bool remove_fake_vad(winotify::driver_t& dev, std::uint64_t eprocess,
                     std::uint64_t node_va);

// ═══════════════════════════════════════════════════════════════════════════════
// ANTI-CHEAT EVASION LAYER — PiDDB, MmUnloadedDrivers, handle table, ETW,
// callstack spoofing, InstrumentationCallback, BigPool tag scrub
// ═══════════════════════════════════════════════════════════════════════════════

// clean our entry from PiDDB cache (PnP Driver DataBase)
// EAC / Vanguard / BattlEye enumerate PiDDB to find recently loaded drivers.
// locates PiDDBCacheTable via ntoskrnl sig scan, walks the AVL tree, unlinks
// and zeros our entry, decrements the element count
bool clean_piddb_cache(winotify::driver_t& dev);

// wipe our entry from MmUnloadedDrivers (circular buffer of last 50 unloads)
// called after NtUnloadDriver to remove the unload trace
bool clean_mm_unloaded_drivers(winotify::driver_t& dev);

// unlink our device handle from the target process's handle table so
// EAC's ObQueryNameString enumeration doesn't see \\Device\\WinNotify.
// the handle stays functionally valid (IOCTL routing uses the file object's
// DeviceObject pointer, not the handle table entry) but becomes invisible
// to NtQuerySystemInformation(SystemHandleInformation)
bool cloak_handle_table_entry(winotify::driver_t& dev, void* device_handle,
                              std::uint32_t own_pid);

// restore a previously cloaked handle table entry (for clean shutdown)
bool uncloak_handle_table_entry(winotify::driver_t& dev);

// blind the ETW Threat Intelligence provider (EtwThreatIntProvRegHandle)
// by patching the provider's GuidEntry->Enabled to 0, preventing
// EAC/Vanguard kernel callbacks from receiving ETW TI events about our ops
bool blind_etw_ti_provider(winotify::driver_t& dev);

// spoof our worker threads' callstacks: walk the active threads of our
// process, find any whose RIP is inside the engine module, and forge
// their trap frame return addresses to point into ntdll/kernel32
bool spoof_thread_callstacks(winotify::driver_t& dev, std::uint32_t own_pid);

// clear InstrumentationCallback in the target's EPROCESS/KPROCESS so
// Vanguard's syscall interception hook doesn't fire for the target
bool clear_instrumentation_callback(winotify::driver_t& dev, std::uint64_t eprocess);

// scrub BigPool allocations: walk BigPoolInformation and zero the Tag
// field of any entry whose Tag matches the driver's known pool tags
bool scrub_bigpool_tags(winotify::driver_t& dev);

// combined: run the full stealth sequence (all of the above) in order.
// returns a bitmask of which steps succeeded (0xFF = all)
struct stealth_result_t {
    bool piddb_clean       = false;
    bool unloaded_clean    = false;
    bool handle_cloaked    = false;
    bool etw_blinded       = false;
    bool callstacks_spoofed = false;
    bool bigpool_scrubbed  = false;
    bool headers_wiped     = false;
    bool text_mutated      = false;
    bool module_hidden     = false;
    bool device_renamed    = false;
    bool name_wiped        = false;
};
stealth_result_t run_full_stealth(winotify::driver_t& dev, void* device_handle,
                                  std::uint32_t own_pid);

} // namespace slop::core::runtime::ptwalk
