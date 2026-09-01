<p align="center">
  <img src="app/src-tauri/icons/256x256.png" width="144" alt="reverse-slop" />
</p>

# reverse-slop

Windows reverse-engineering workbench with desktop interfaces, live process and
kernel inspection, static analysis and decompilation, dynamic instrumentation,
network analysis, and a built-in Model Context Protocol (MCP) server for agent
control.

> [!WARNING]
> Use reverse-slop only on systems and software you own or are authorized to
> test. Live memory writes, debugging, network manipulation, and the optional
> kernel bridge can destabilize processes or Windows. The mapper loads a kernel
> driver and requires administrator privileges. Start with the user-mode engine
> when kernel access is unnecessary.

## Inspiration and attribution

reverse-slop is heavily inspired by [AiDA Private](https://github.com/sigwl/AiDAPrivate),
created by [sigwl](https://github.com/sigwl) (ruarridh). Most, if not almost all,
of reverse-slop's feature set and feature concepts are based on that project.

## Highlights

- **Two desktop interfaces, one core:** native ImGui/DX11 shell and Tauri v2 +
  React shell both drive the same C++ engine.
- **Headless operation:** run the engine without a window for MCP or HTTP clients.
- **Live process analysis:** processes, modules, threads, regions, handles,
  module dumping, memory scans, watchlists, snapshots, pointer scans, and AOB
  searches.
- **Static analysis:** PE parsing, x86/x64 assembly and disassembly, function and
  cross-reference indexes, strings, globals, vtables, RTTI, signatures, binary
  diffing, packer detection, and security-focused reconnaissance.
- **Decompiler:** Hyperion p-code lifting, SSA, dead-code elimination, type
  inference, control-flow structuring, and C-like output with source addresses.
- **Debugging:** Win32 debugging plus optional kernel-assisted VEH debugging,
  breakpoints, stepping, registers, call stacks, SEH, watchpoints, tracepoints,
  and bounded instruction traces.
- **Instrumentation:** embedded Frida Core 17.17.0 for local and remote devices,
  spawning, attaching, scripts, messages, RPC, compile, and snapshots.
- **Emulation:** isolated x86-64 Unicorn execution with register/memory setup,
  tracing, byte-level taint propagation, and watched output ranges.
- **Network tooling:** WFP capture and manipulation through the optional driver,
  PCAP export, stream reconstruction, connection inspection, and an independent
  localhost HTTP inspection proxy.
- **Unpacking and devirtualization:** Magicmida Themida sidecars, VM handler and
  opcode-map recovery, trace/lift/pseudocode flows, CFG recovery, predicate
  proofs, invariants, and IAT auditing.
- **Agent-native control:** 22 MCP-visible domain tools with consolidated
  `action` parameters, plus an `/api`-only application-control tool and SSE
  events.

## Platform and requirements

### Required for the C++ build

- Windows 10 or 11, x64
- Visual Studio 2022 with **Desktop development with C++** and the
  `Microsoft.VisualStudio.Component.VC.Tools.x86.x64` component
- CMake 3.25 or newer
- Ninja
- PowerShell
- Git and internet access during first configure

`tools/build.ps1` locates Visual Studio with `vswhere`, then uses Visual
Studio's bundled CMake and Ninja. CMake downloads pinned dependencies into
`_ext/`, including ImGui, FreeType, Zydis, Capstone, Unicorn, nlohmann/json,
cpp-httplib, SQLite, Lua, fmt, spdlog, and zlib. It also downloads and verifies
the Frida Core 17.17.0 Windows x86-64 devkit (about 53 MB) on first configure.

### Additional requirements by component

| Component | Additional requirements |
|---|---|
| Tauri desktop shell | Node.js/npm, Rust toolchain with Cargo, WebView2 runtime |
| Kernel driver and mapper | Visual Studio C++ tools, Windows Driver Kit 10.0.26100.0, administrator rights |
| Themida unpacking | Separately installed Magicmida x86/x64 sidecars |
| Frida TypeScript project bundling | A usable `frida-compile` setup for the requested project |

The main CMake build currently expects the WDK 10.0.26100.0 `ntdll.lib` when
linking `slop_mapper`. If that exact WDK library is absent, CMake warns and the
mapper target will not link. The app and headless engine still support a
user-mode backend without the driver.

## Build

Run commands from a PowerShell prompt at repository root.

### Standard build

```powershell
powershell -File tools/build.ps1
```

This configures and builds the `ninja-msvc-release` preset into `build/`, then
builds the Tauri app (portable folder plus installer). Incremental builds reuse
both directories. Add `-NoFrontend` for the C++ targets alone.

Useful build-script switches:

```powershell
# Delete build/ before configuring
powershell -File tools/build.ps1 -FullClean

# Configure only; do not compile
powershell -File tools/build.ps1 -PlanOnly

# Select another preset if one has been added to CMakePresets.json
powershell -File tools/build.ps1 -Preset ninja-msvc-release
```

Default CMake options are all enabled:

| Option | Default | Output |
|---|---:|---|
| `SLOP_BUILD_ENGINE` | `ON` | Headless engine host |
| `SLOP_BUILD_TEST_TARGET` | `ON` | `SlopTarget.exe` fixture |
| `SLOP_BUILD_TESTS` | `ON` | Core test harness |
| `SLOP_BUILD_MAPPER` | `ON` | Kernel-driver loader utility |

For manual configuration, first enter an x64 Visual Studio developer shell:

```powershell
cmake --preset ninja-msvc-release -S .
cmake --build --preset ninja-msvc-release
```

Example user-mode-only configuration when mapper artifacts are not needed:

```powershell
cmake --preset ninja-msvc-release -S . -DSLOP_BUILD_MAPPER=OFF
cmake --build --preset ninja-msvc-release
```

### Tauri + React desktop build

The Tauri UI is the app that ships; `reverse-slop.exe` (ImGui) is the legacy
shell kept for parity work. The frontend build needs the C++ engine first
because Tauri bundles `reverse-slop-engine.exe` and `slop_frida.dll` as
resources.

```powershell
powershell -File tools/build.ps1
```

That performs the C++ build, runs `npm install` if `app/node_modules` is
missing, builds the React app, and produces two standalone outputs:

```text
dist\reverse-slop\reverse-slop.exe                          portable folder
app\src-tauri\target\release\bundle\nsis\...-setup.exe       per-machine installer
```

The portable folder carries its own `engine\` directory, so it runs from a copy
with no installer and no build tree. It needs the Microsoft Edge WebView2
runtime, which ships with Windows 11 and current Windows 10; the NSIS installer
downloads it when missing.

Use `-NoFrontend` for a fast C++-only loop (skips Rust, npm, and the bundle).

Release Tauri builds request administrator elevation so the engine sidecar can
use the kernel bridge. Debug Tauri builds run as the invoking user and can use
the user-mode backend.

Frontend development:

```powershell
# Terminal 1: build or refresh the C++ engine
powershell -File tools/build.ps1 -NoFrontend

# Terminal 2
cd app
npm install
npm run tauri -- dev
```

Vite uses fixed port `1420`; the engine's CORS allow-list depends on it.
Additional frontend checks:

```powershell
cd app
npm run typecheck
npm run build

# Requires a running engine; validates frontend calls against tools/list
npm run check:api -- 8765
```

### Kernel driver

The CMake build creates `slop_mapper.exe`, but `slopdrvr.sys` has a separate WDK
build script:

```powershell
powershell -File tools/build_slopdrvr.ps1
```

Outputs:

```text
build\mapper\slop_mapper.exe
build\driver\slopdrvr.sys
```

Clean driver objects before rebuilding:

```powershell
powershell -File tools/build_slopdrvr.ps1 -Clean
```

Use another installed WDK version only if corresponding headers and libraries
exist and the mapper link configuration is updated consistently:

```powershell
powershell -File tools/build_slopdrvr.ps1 -WdkVersion 10.0.26100.0
```

The driver script currently assumes Visual Studio at `E:\PRODUCT VS22`, while
the main build script also supports normal `vswhere` discovery. Adjust
`$vsRoot` in `tools/build_slopdrvr.ps1` if Visual Studio is elsewhere.

On startup, an elevated shell searches for mapper and driver artifacts beside
the executable or in the build-tree layout. It loads `slopdrvr`, probes
`\\.\slopdrvr`, selects the kernel backend when available, and falls back to
user mode on failure. Normal shutdown quiesces and unloads the driver and
removes its service key. Avoid force-killing the process while kernel work is
active.

### Magicmida Themida sidecars

Magicmida and its ScyllaHide dependency are separate GPLv3 programs, not linked
into reverse-slop. Install the pinned, SHA-256-verified `2026-05-14` release:

```powershell
powershell -File tools/install_magicmida.ps1
```

Default destination:

```text
%LOCALAPPDATA%\reverse-slop\tools\magicmida\2026-05-14\x86
%LOCALAPPDATA%\reverse-slop\tools\magicmida\2026-05-14\x64
```

Overrides:

- `SLOP_MAGICMIDA_ROOT` — root containing `x86` and `x64` directories
- `SLOP_MAGICMIDA_X86` — direct path to x86 executable
- `SLOP_MAGICMIDA_X64` — direct path to x64 executable

## Run

### Tauri app (primary)

```powershell
.\dist\reverse-slop\reverse-slop.exe
```

Requests administrator elevation once, spawns `engine\reverse-slop-engine.exe`
as a sidecar in a kill-on-close job object, and drives it over `/api` +
`/events`. Installed builds behave the same from `%ProgramFiles%`.

### Native ImGui shell (legacy)

```powershell
.\build\src\app\reverse-slop.exe
```

The executable requests administrator elevation. It owns a Win32 window with a
DX11 composition swapchain, docking, FreeType fonts, keyboard navigation, and
DWM styling. Built-in views and shortcuts:

| View | Shortcut |
|---|---|
| Targets | `Ctrl+1` |
| Inspector | `Ctrl+2` |
| Disassembly | `Ctrl+3` |
| Memory | `Ctrl+4` |
| Output | `Ctrl+5` |
| Scanner/watchlist | `Ctrl+6` |
| Strings | `Ctrl+7` |
| PE Browser | `Ctrl+8` |
| Debugger | `Ctrl+9` |
| Pseudocode | `Ctrl+0` |
| Unpacker | No default shortcut |
| Frame Metrics | `F12` |

### Headless engine

Safest development path, with no driver loading or client-config changes:

```powershell
.\build\src\engine\reverse-slop-engine.exe --no-driver --no-onboard
```

Full engine:

```powershell
.\build\src\engine\reverse-slop-engine.exe
```

Options:

| Option | Effect |
|---|---|
| `--no-driver` | Skip kernel-driver loading; use user-mode backend |
| `--no-onboard` | Do not register MCP endpoint in supported AI clients |
| `--quiet` | Suppress mirrored engine output on stderr |
| `--port <n>` | Override MCP/API port for this process |
| `--parent-pid <pid>` | Exit through clean teardown when parent exits |
| `--headless` | Accepted for supervisor compatibility; engine is always headless |

Successful startup writes this machine-readable line to stdout:

```text
SLOP_ENGINE_READY <port> <token>
```

If another live reverse-slop endpoint is advertised, a new engine reports that
endpoint with `SLOP_ENGINE_EXISTING <pid>` and exits rather than competing for
the driver and port.

### Tauri shell

Launch installed `reverse-slop`, or during development:

```powershell
cd app
npm run tauri -- dev
```

The Rust supervisor starts the C++ engine, waits up to 180 seconds for its
handshake, places it in a kill-on-close job object, and lets it perform clean
shutdown when the UI exits. The React shell exposes targets, modules, scripts,
Frida, scanner/watchlist, disassembly, strings, memory, debugger, PE browser,
output, inspector, theme/motion settings, and backend selection.

## Feature reference

### Process and live-memory workspace

- Enumerate processes with icons and architecture/elevation metadata.
- Attach/detach a shared target session.
- Enumerate modules, threads, virtual-memory regions, heaps, heap blocks, and
  handles.
- Reconstruct a conventional PE from a mapped module; strict mode rejects
  unreadable spans, while best-effort mode zero-fills them.
- Read/write memory in hex, UTF-8, integer, and floating-point formats.
- Allocate, free, and change page protection.
- Cheat Engine-style initial and refined numeric scans with exact/range/change,
  signed/unsigned/floating widths, rounding, region/protection, address,
  alignment, worker, chunk, and result-cap filters.
- AOB wildcard search, pointer-chain scans, signature generation, and live
  cryptographic-constant search.
- Snapshot memory, compare snapshots, list/free snapshot state.
- Shared watchlist sampled around 10 Hz, including freeze writes; UI and MCP
  changes appear in both surfaces.

### Static analysis and decompilation

- PE headers, sections, data directories, imports, exports, and runtime-base
  rebasing.
- Fast synchronous Zydis function, xref, string, and PE indexes.
- Background Hyperion recursive analysis with CFGs, globals, vtables, RTTI,
  names, PDB/FLIRT support, and progress/cancellation state.
- x86/x64 disassembly and assembly; Hyperion also contains Capstone decoders and
  loaders for additional architectures/formats, but the current shared app load
  path is PE-based.
- Structured decompilation pipeline: instruction lifting to p-code, SSA,
  propagation, dead-code elimination, type inference, control-flow structuring,
  and C-like emission.
- Per-line virtual-address mappings, optional address annotations, reconstructed
  stack variables, signatures, and persisted user names.
- Binary-to-binary function diff with added/removed/modified functions and
  similarity scores.
- Packer/protector indicators: signatures, entropy, import anomalies, W+X
  sections, TLS, overlay, and crypto constants.
- RTTI class/vtable recovery, dangerous-import callsites, library byte
  signatures, user structs/enums, typed formatting, comments, and bookmarks.
- Per-binary metadata persists by file hash and remaps across different runtime
  bases.

### Xray and patching

Read-only Xray passes include:

- CFG and cyclomatic complexity
- Control-flow flattening and general obfuscation scoring
- String reconstruction and indirect-call recovery
- Anti-analysis patterns
- Hook checks and direct-syscall discovery
- Imported API hash resolution
- Entropy windows and executable-page classification
- Crypto constants and ROP gadget search

File-image patching includes:

- Junk-NOP cleanup and opaque-predicate resolution
- Anti-debug patching
- XOR unpacking and string decoding
- Explicit byte writes
- Patch journal and full revert
- Combined full pass
- Function re-decode/index invalidation after edits

Patches affect the loaded analysis image, not live process memory. Use the memory
suite for live writes.

### Debugger

- Classic Win32 debug loop in user mode.
- Kernel-assisted stealth VEH mode when `slopdrvr` is available.
- Software and hardware breakpoints, conditional expressions, log messages,
  auto-continue tracepoints, and one-shot breakpoints.
- Continue, step into, step over, step out, and bounded wait-for-halt.
- Register inspection/mutation, event history, call stacks, and SEH chains.
- Page-guard access watchpoints and bounded instruction traces.
- Suspend/resume all target threads.
- Driver-assisted DR0–DR3 hardware breakpoints and handle-free thread control.

### Kernel bridge

When available, `slopdrvr` adds:

- DTB-aware process memory access and region enumeration
- Kernel module enumeration, driver dumping, memory read/write/search, and
  virtual-to-physical translation
- Kernel calls and deferred-call queues
- SSDT, PEB, TEB, loader-module, window, heap, and reference inspection
- Export and symbol lookup through DbgHelp-backed symbol state
- Integrity checks, anti-debug spoofing, sandbox controls, and driver logging
- WFP capture/manipulation and network-buffer sniffing
- Hidden-kernel callback inspection and clean shutdown identity/handshake

Every caller should query backend/driver status rather than assume kernel
capabilities. Many core process, memory, debugger, and static-analysis features
continue in user mode.

### Dynamic instrumentation with Frida

Embedded Frida Core supports:

- Local and remote-device discovery
- Process, application, and frontmost-application enumeration
- Spawn, piped stdio, resume, kill, and input
- Spawn and child gating with pending-spawn/child inspection
- Attach/detach and session resume
- JavaScript creation/load/unload/destroy/post and debugger endpoint
- `send()`/console message draining with binary payload support
- `rpc.exports` calls with arguments and timeout
- `frida-compile` project bundling
- Script bytecode compilation and snapshot generation
- QuickJS and V8 runtime selection where supported by Frida

### Emulation and devirtualization

- Isolated x86-64 Unicorn execution from explicit bytes, loaded-file addresses,
  or attached-target addresses.
- Custom register, stack, and memory-map initialization.
- Instruction-count, target-address, and timeout stopping conditions.
- Bounded instruction traces and byte-granular taint tracking.
- VM identification, handler discovery, opcode maps, execution traces, lifting,
  and pseudocode.
- CFG recovery, multi-run predicate proofs and invariant discovery, plus IAT
  audits.
- Supervised Magicmida jobs with architecture validation, cancellation,
  timeouts, output selection, and optional loading into analysis session.

### Network and proxy

Driver-backed network features include:

- Capture start/stop, packets, DNS, statistics, filtering, and PCAP export
- Stream listing, payload reads, and reassembly
- Packet injection and byte-pattern replacement rules
- Redirect and DNS-spoof rules
- Connection termination
- Hold/inspect/modify/release interception
- Per-process bandwidth monitoring/control and traffic fingerprinting
- Connection, interface, WFP callout, socket-handle, TCB, and deep-packet
  inspection
- IP, port, and process blocking by direction

Independent HTTP/1.1 proxy features include start/stop, captured entries,
exchange detail, and request replay. CONNECT tunnels record metadata/SNI but do
not decrypt tunnel bodies; replay applies to captured plain HTTP.

### Automation, persistence, filesystem, and web access

- Lua 5.4 scripts with bounded execution, covering the whole static-analysis
  surface the way IDAPython covers IDA (see "Lua scripting" below), plus APIs
  for logging, targets, memory, live disassembly, and packer analysis.
- SQLite session snapshots and key/value storage.
- Hyperion `.hdb` project export/import for names and comments.
- Host filesystem read/write/list/create/delete/name-search/content-search.
- Outbound WinHTTP GET/POST requests without browser-cookie inheritance.
- Host security inspection for hidden modules, minifilters, ETW sessions, and
  driver-assisted kernel callbacks.

### Lua scripting

Scripts run through the `script` MCP tool (`action=run`, `code`, `timeout_ms`)
or the engine API and execute against the same shared binary session as the
UI and every other MCP tool — loads, renames, and comments made from one
surface appear in all of them. Returned values are serialized into the
captured output as `return: <value>`.

```lua
-- Load a binary, wait for the Hyperion analysis, and walk the functions.
assert(slop.image.load([[C:\bin\target.exe]]))
assert(slop.image.wait_ready(30000))

for _, f in ipairs(slop.disasm.functions()) do
    slop.log(string.format("%X  %s (%d bytes)", f.va, f.name, f.size))
end

-- Cross-references, decompilation, and annotation all interoperate:
local refs = slop.disasm.xrefs_to(0x140001000)     -- { {from=..., kind=...}, ... }
local d    = slop.decomp.decompile(0x140001000)   -- pseudo-C lines + signature
slop.disasm.set_name(d.va, "entry_handler")        -- persisted rename
slop.disasm.set_comment(d.va, "called on startup") -- persisted comment
```

The static-analysis surface:

| Group | Functions |
|---|---|
| Session | `slop.image.load(path[, base])`, `load_from_target`, `unload`, `status`, `wait_ready([ms])` |
| Instructions | `slop.disasm.decode(addr[, count])`, `slop.disasm.bytes(addr[, len])` |
| Functions | `slop.disasm.functions([limit])`, `slop.disasm.function_at(va)` |
| Cross-refs | `slop.disasm.xrefs_to(va)` |
| Data | `slop.disasm.strings([min[, limit]])`, `slop.disasm.pe()` |
| Annotation | `slop.disasm.name/set_name/comment/set_comment`, `bookmark_toggle`, `bookmarks` |
| Decompiler | `slop.decomp.decompile(va)` (pseudo-C + signature), `blocks(va)` (CFG) |
| Rich DB | `slop.decomp.vtables()`, `globals()`, `rtti()` |

`decomp.*` requires the Hyperion analysis to be ready — call
`slop.image.wait_ready()` after loading. Live-process scripting keeps the
legacy surface: `slop.target.*`, `slop.mem.*`, `slop.disasm.disassemble`,
and `slop.analyze.packer`.

## MCP and HTTP API

### Endpoints

Default listener: `127.0.0.1:8765`. It never binds to a non-loopback address.

| Endpoint | Purpose |
|---|---|
| `GET /health` | Liveness and version |
| `POST /mcp` | MCP JSON-RPC 2.0 (`initialize`, `ping`, `tools/list`, `tools/call`) |
| `GET /mcp` | MCP SSE endpoint/keepalive |
| `POST /api` | Direct frontend RPC; accepts one request or an array |
| `GET /events` | Frontend SSE event stream |

Protocol version: `2025-06-18`.

`initialize` returns two agent-facing fields beyond the standard handshake:
`instructions` (a short server-level usage preamble clients surface to the
model) and `state` — the live session context: active backend badge, attached
target (`pid`/`name`/`arch`), debugger state, and the loaded-image summary
including Hyperion analysis readiness (`image.hype.ready`). The same context
is available mid-session through `target.status` and `disasm.loaded`.

Configure `%LOCALAPPDATA%\reverse-slop\settings.json`:

```json
{
  "mcp_enabled": true,
  "mcp_port": 8765,
  "mcp_token": "",
  "mcp_onboarded": false
}
```

`SLOP_MCP_PORT` or engine `--port` overrides configured port for that process.
When configured port is busy, reverse-slop uses an ephemeral port and skips
onboarding so existing clients remain pointed at owner of well-known port.
Set `mcp_token` to require `Authorization: Bearer <token>` on MCP/API routes.
The `/events` route also accepts a token query parameter because browser
`EventSource` cannot set custom headers.

Request bodies are capped at 32 MiB. Tool calls share core state and are
serialized where required; cancellation notifications propagate to supported
long-running operations.

### MCP examples

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8765/health
```

List tools:

```powershell
$body = @{
  jsonrpc = '2.0'
  id = 1
  method = 'tools/list'
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/mcp `
  -ContentType 'application/json' `
  -Body $body
```

List processes through MCP:

```powershell
$body = @{
  jsonrpc = '2.0'
  id = 2
  method = 'tools/call'
  params = @{
    name = 'target'
    arguments = @{ action = 'list' }
  }
} | ConvertTo-Json -Depth 8

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/mcp `
  -ContentType 'application/json' `
  -Body $body
```

Direct `/api` request:

```powershell
$body = @{
  tool = 'disasm'
  action = 'loaded'
  params = @{}
} | ConvertTo-Json

Invoke-RestMethod -Method Post `
  -Uri http://127.0.0.1:8765/api `
  -ContentType 'application/json' `
  -Body $body
```

### MCP tool/action index

All MCP tools accept an `action` string. Exact parameter schemas and detailed
operational guidance are returned by `tools/list`.

| Tool | Actions |
|---|---|
| `target` | `list`, `attach`, `detach`, `status`, `modules`, `dump_module`, `threads`, `regions`, `handles`, `icon` |
| `memory` | `read`, `write`, `scan`, `rescan`, `scan_state`, `scan_reset`, `aob`, `pointerscan`, `snapshot`, `snapshots`, `diff`, `snapshot_free`, `protect`, `alloc`, `free`, `siggen`, `live_crypto`, `watch_list`, `watch_add`, `watch_remove`, `watch_clear`, `watch_set` |
| `disasm` | `assemble`, `disassemble`, `loaded`, `pe`, `functions`, `xrefs`, `strings`, `symbols`, `symbol_set`, `blocks`, `globals`, `vtables`, `load`, `unload`, `analyze_stop` |
| `debugger` | `attach`, `detach`, `status`, `suspend_all`, `resume_all`, `bp_set`, `bp_clear`, `continue`, `step_into`, `step_over`, `step_out`, `wait_halt`, `regs`, `events`, `callstack`, `seh`, `set_register`, `watchpoint_set`, `watchpoint_clear`, `watchpoints`, `trace_run` |
| `driver` | `status`, `backend`, `kernel_modules`, `dump_driver`, `kernel_read`, `kernel_write`, `kernel_search`, `call`, `v2p`, `ssdt`, `peb`, `resolve_export`, `windows`, `find_references`, `heap_walk`, `heap_blocks`, `defer_call`, `defer_list`, `defer_execute`, `defer_results`, `defer_cancel`, `symbols_load`, `symbols_lookup`, `symbols_nearest`, `anti_debug_spoof`, `sandbox_protect`, `sandbox_unprotect`, `log_config`, `read_teb`, `peb_modules`, `integrity_checks`, `sniff_buffers` |
| `xray` | `cfg`, `complexity`, `cff`, `obfuscation`, `strings_recon`, `indirect_calls`, `anti_analysis`, `hooks`, `syscalls`, `apihash`, `entropy`, `pages`, `crypto_range`, `gadgets` |
| `patch` | `nop_junk`, `resolve_opaque`, `patch_antidebug`, `unpack_xor`, `decode_strings`, `write_bytes`, `revert_all`, `journal`, `full_pass`, `rebuild` |
| `devirt` | `themida_status`, `themida_start`, `themida_job`, `themida_cancel`, `identify`, `handlers`, `opcode_map`, `trace`, `lift`, `pseudocode`, `recover_cfg`, `prove_predicates`, `invariants`, `iat_audit` |
| `types` | `declare`, `create_struct`, `get_struct`, `list_structs`, `add_member`, `remove_struct`, `create_enum`, `get_enum`, `list_enums`, `remove_enum`, `read_field`, `format_at` |
| `notes` | `set_comment`, `get_comment`, `comments`, `bookmark_toggle`, `bookmarks` |
| `emulate` | `run` |
| `analyze` | `packer`, `signatures`, `diff` |
| `network` | `status`, `capture_start`, `capture_stop`, `packets`, `dns`, `rules_add`, `rules_remove`, `rules_clear`, `stats`, `export_pcap`, `streams`, `stream_data`, `inject`, `mod_rule_add`, `mod_rule_remove`, `mod_rules_list`, `redirect_add`, `redirect_remove`, `redirect_rules_list`, `dns_spoof_add`, `dns_spoof_remove`, `dns_spoof_list`, `kill_conn`, `intercept_start`, `intercept_stop`, `intercept_list`, `intercept_release`, `bw_start`, `bw_stop`, `bw_stats`, `bw_processes`, `fingerprint_run`, `fingerprint_results`, `reassemble_stream`, `connections`, `deep_inspect`, `wfp_callouts`, `socket_handles`, `tcpip_dump`, `interfaces`, `block_ip`, `block_port`, `block_process` |
| `proxy` | `start`, `stop`, `status`, `entries`, `entry`, `replay` |
| `persist` | `save`, `list`, `load`, `delete`, `kv_set`, `kv_get`, `hype_save`, `hype_load` |
| `re` | `rtti_scan`, `vftable`, `danger`, `libsig` |
| `decomp` | `function` |
| `detect` | `hidden_modules`, `minifilters`, `etw_sessions`, `kernel_callbacks` |
| `fs` | `read_file`, `write_file`, `list_directory`, `create_directory`, `delete_path`, `search_files`, `grep_in_files` |
| `web` | `fetch`, `post` |
| `script` | `run` |
| `frida` | `status`, `devices`, `remote_add`, `remote_remove`, `ps`, `find_process`, `applications`, `frontmost`, `spawn`, `spawn_output`, `resume`, `kill`, `input`, `spawn_gating`, `pending_spawn`, `pending_children`, `attach`, `detach`, `session_resume`, `child_gating`, `script_create`, `script_load`, `script_unload`, `script_destroy`, `script_post`, `script_debugger`, `messages`, `rpc`, `compile`, `compile_script`, `snapshot_script` |

`app` is intentionally omitted from MCP `tools/list`; it is frontend plumbing
available only through `/api`: `status`, `ping`, `output`, `output_clear`, `log`,
`diag`, and `shutdown`.

### Events

`GET /events` sends `hello` with an output revision cursor, then events such as:

- `output`
- `boot.stage`
- `target.changed`
- `backend.changed`
- `hype.progress`
- `watch.list`
- `watch.values`
- `app.quitting`

On reconnect, frontend can replay missed output with `app.output` and the last
revision.

### Automatic MCP client registration

On first successful startup at configured port, reverse-slop adds a
`reverse-slop` HTTP MCP entry without replacing existing entries in:

- Claude Code: `%USERPROFILE%\.claude.json` (user scope; the entry needs
  `"type": "http"`, server definitions do not live in `settings.json`)
- Cursor: `%USERPROFILE%\.cursor\mcp.json`
- Windsurf: `%USERPROFILE%\.codeium\windsurf\mcp_config.json`
- VS Code: `%APPDATA%\Code\User\settings.json` (under `mcp.servers`)
- OpenCode: `%USERPROFILE%\.config\opencode\config.json`

Claude Desktop is not auto-registered: `claude_desktop_config.json` supports
stdio servers only, so a remote HTTP entry cannot work there — add it through
Claude Desktop's Connectors UI instead. Unparseable client config files are
left untouched rather than overwritten.

Use `--no-onboard` for a headless run that must not edit client configuration.
Set `mcp_onboarded` to `false` to request another onboarding pass after removing
or changing entries.

## Architecture

```text
                       +----------------------+
                       | ImGui / DX11 shell   |
                       | src/app + src/ui     |
                       +----------+-----------+
                                  |
                                  | in-process calls
                                  |
+---------------------+   HTTP    v    +--------------------------+
| Tauri / React shell |<-------------->| shared C++ core          |
| app/                |  /api,/events  | src/core                 |
+----------+----------+                +------------+-------------+
           |                                        |
           | supervises                             +-- process/memory/debugger
           v                                        +-- disasm/analysis/decomp
+--------------------------+                        +-- driver/network/frida
| headless engine          |                        +-- MCP/API/event bus
| src/engine               |
+--------------------------+
```

Both native and headless hosts drive the shared lifecycle in
`src/core/infra/lifecycle.cpp`:

1. Initialize application paths and worker/job queues.
2. Start process and target services.
3. Load/probe optional kernel bridge on a background thread.
4. Load settings and persistence state.
5. Bind MCP/API server and optionally onboard clients.
6. Publish capabilities and enter periodic target/watch/event servicing.
7. On shutdown, stop server/jobs/watches/targets, save settings, then quiesce and
   unload driver if this instance owns it.

Key directories:

```text
src/
├── app/          Win32 entry point and DX11 loop
├── engine/       Headless lifecycle host and parent-process contract
├── ui/           ImGui chrome, docking, theme, fonts, and views
├── hyperion/     Vendored analysis/decompiler engine (`hype` namespace)
├── core/
│   ├── infra/    Lifecycle, jobs, settings, paths, events, onboarding
│   ├── process/  Targets, processes, modules, threads, heaps, handles, dumps
│   ├── memory/   Scanner, AOB, pointers, snapshots, watch service
│   ├── disasm/   PE/Zydis indexes and Hyperion session bridge
│   ├── debugger/ Debug loops, stepping, breakpoints, call stacks
│   ├── runtime/  User/kernel backends, driver loading and communication
│   ├── analysis/ Packer, signatures, xray, patches, devirt, Magicmida
│   ├── emu/      Unicorn execution and taint propagation
│   ├── network/  WFP capture, traffic store, proxy, WinHTTP
│   ├── frida/    Isolated Frida Core DLL boundary
│   ├── mcp/      MCP schemas, tool dispatcher, `/api`, `/events`
│   └── ...       Types, RTTI, persistence, scripting, filesystem, detection
├── target/       Deterministic live-analysis fixture
├── tests/        Core test harness
└── live/         Live probes and integration utilities
app/              Tauri v2 supervisor and React/TypeScript frontend
mapper/           Driver loader utility
driver/slopdrvr/  Kernel driver sources
tools/            Build, driver, Magicmida, and live-test scripts
```

Frida lives in `slop_frida.dll` rather than `slop_core` because Frida's bundled
GLib symbols conflict with Unicorn's compatibility layer. Tauri supervises a
separate C++ engine instead of linking it into Rust, avoiding static/dynamic CRT
mixing and providing crash isolation.

## Runtime data

Application state lives under `%LOCALAPPDATA%\reverse-slop`:

| Path | Purpose |
|---|---|
| `settings.json` | MCP and runtime settings |
| `engine.json` | Live engine PID/port/token advertisement; removed on clean exit |
| `dock.ini` | ImGui layout |
| `sessions.db` | SQLite snapshots and key/value state |
| `symbols\<hash>.json` | Per-binary names, comments, and bookmarks |
| `sessions\` | Session artifacts |
| `crashes\` | Crash artifacts |
| `tools\magicmida\...` | Optional Magicmida installation |
| `DriverRuntime\` | Temporary kernel-loader runtime files |

Do not publish `engine.json` if bearer token is configured.

## Tests

Build includes deterministic `SlopTarget.exe` and `slop_tests.exe` by default.
Run full suite:

```powershell
.\build\tests\slop_tests.exe
```

Or through CTest:

```powershell
ctest --test-dir build --output-on-failure
```

Filter tests by case-name substring:

```powershell
$env:SLOP_TEST_FILTER = 'decomp'
.\build\tests\slop_tests.exe
Remove-Item Env:SLOP_TEST_FILTER
```

Test coverage includes infrastructure, memory, disassembly, debugger, MCP,
analysis, emulation, network, persistence, RTTI/types, Lua, kernel abstractions,
module dumping, Hyperion/decompilation, detection/filesystem, driver autoload,
Xray/patching, Magicmida supervision, and Frida.

`tools/mcp_live_test.py` is a destructive-capable integration battery intended
for a controlled local fixture with a running engine and loaded `SlopTarget`.
Review paths and actions before running it; it exercises writes, patches,
filesystem operations, and kernel/network calls.

## Troubleshooting

### Configure cannot download dependencies

First configure requires HTTPS access to pinned upstream archives/repositories
and the Frida devkit. Retry with network/proxy access available. Once populated,
CMake uses `_ext/` with disconnected updates.

### `Visual Studio 2022 with C++ tools not found`

Install Desktop development with C++, verify `vswhere.exe` exists under Visual
Studio Installer, and ensure x64 C++ tools are selected.

### `slop_mapper` does not link

Install WDK 10.0.26100.0 or disable mapper for a user-mode build:

```powershell
cmake --preset ninja-msvc-release -S . -DSLOP_BUILD_MAPPER=OFF
cmake --build --preset ninja-msvc-release
```

### Driver stays unavailable

Check these files exist:

```text
build\mapper\slop_mapper.exe
build\driver\slopdrvr.sys
```

Run elevated, inspect `build\mapper\slop_mapper_last.log`, and query
`driver.status`. User-mode fallback is expected when mapper, driver, privilege,
or compatible kernel support is unavailable.

### Port 8765 is busy

Engine falls back to an ephemeral port and records it in `engine.json`. Use
`--port <n>`, change `mcp_port`, or stop the process owning 8765. Automatic
onboarding is skipped on fallback ports.

### Tauri cannot find engine

Build C++ target first:

```powershell
powershell -File tools/build.ps1
```

Expected development path:

```text
build\src\engine\reverse-slop-engine.exe
```

### Hyperion-dependent calls fail

Call `disasm.loaded` and wait until `image.hype.ready` is true. Use
`image.hype.progress` and `image.hype.error` for state. Reload image to restart
analysis after `disasm.analyze_stop`.

### Magicmida unavailable

Run installer or set path overrides, then call `devirt.themida_status` before
starting a job.

## Security notes

- HTTP services bind only to `127.0.0.1`.
- Empty MCP token means no authentication; any local process can then invoke
  mutation-capable tools. Configure a bearer token on shared or untrusted
  workstations.
- `/api` browser origins are restricted to Tauri and fixed Vite development
  origins. Non-browser local clients are still governed by loopback and bearer
  authentication.
- Filesystem, web, script, debugger, patch, Frida, network, driver, and memory
  tools can change host or target state. Expose MCP only to trusted clients.
- Driver loading modifies kernel state and can trigger endpoint-security or
  Windows protections. Prefer `--no-driver` unless kernel features are needed.
- Keep analysis isolated from production and personal systems; use disposable
  virtual machines and snapshots for untrusted samples.

## Project status

reverse-slop is version `0.1.0` and Windows-only. APIs and analysis output may
change. No root project license file is currently present; do not assume a
license for reverse-slop itself. Third-party components retain their own
licenses, and separately downloaded Magicmida/ScyllaHide components are GPLv3.
