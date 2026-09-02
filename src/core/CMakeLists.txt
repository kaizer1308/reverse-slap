# frida service DLL
# frida-core's statically bundled GLib collides with unicorn's glib_compat
# shim (duplicate g_* symbols) if both are linked into the same binary, so
# the whole frida embed is isolated in its own DLL. Only the exported
# frida_service_t API crosses the boundary
add_library(slop_frida SHARED
    frida/frida_service.hpp
    frida/frida_service.cpp
)
target_include_directories(slop_frida PUBLIC "${CMAKE_SOURCE_DIR}/src")
target_compile_definitions(slop_frida PRIVATE
    SLOP_FRIDA_BUILD
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)
# frida-core.h emits #pragma comment(lib, ...) defaultlib records, give the
# linker a search path so the bare "frida-core.lib" name resolves
target_link_directories(slop_frida PRIVATE "${SLOP_FRIDA_DIR}")
target_link_libraries(slop_frida PRIVATE frida::core setupapi nlohmann_json::nlohmann_json)
if(MSVC)
    target_compile_options(slop_frida PRIVATE /W4 /EHsc)
endif()
# The DLL must sit next to every consumer exe (Windows loads from the exe's
# directory, not the DLL's build dir)
add_custom_command(TARGET slop_frida POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/src/app"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/tests"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/live"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:slop_frida> "${CMAKE_BINARY_DIR}/src/app"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:slop_frida> "${CMAKE_BINARY_DIR}/tests"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:slop_frida> "${CMAKE_BINARY_DIR}/live"
    COMMENT "copying slop_frida.dll next to consumer exes"
)

add_library(slop_core STATIC
    infra/capability.hpp
    infra/published.hpp
    infra/cancel.hpp
    infra/clock.hpp
    infra/limits.hpp
    infra/diag.hpp
    infra/diag.cpp
    infra/paths.hpp
    infra/paths.cpp
    infra/settings.hpp
    infra/settings.cpp
    infra/work_queue.hpp
    infra/work_queue.cpp
    infra/jobs.hpp
    infra/jobs.cpp
    infra/text_format.hpp
    infra/text_format.cpp
    infra/event_bus.hpp
    infra/event_bus.cpp
    infra/app_control.hpp
    infra/app_control.cpp
    infra/lifecycle.hpp
    infra/lifecycle.cpp
    memory/reader.hpp
    memory/read_util.hpp
    memory/read_util.cpp
    memory/memscan.hpp
    memory/memscan.cpp
    memory/watch_service.hpp
    memory/watch_service.cpp
    memory/aob.hpp
    memory/aob.cpp
    memory/pointer_scan.hpp
    memory/pointer_scan.cpp
    memory/snapshot.hpp
    memory/snapshot.cpp
    analysis/packer.hpp
    analysis/packer.cpp
    analysis/signatures.hpp
    analysis/signatures.cpp
    analysis/danger.hpp
    analysis/danger.cpp
    analysis/libsig.hpp
    analysis/libsig.cpp
    analysis/xray.hpp
    analysis/xray.cpp
    analysis/imgpatch.hpp
    analysis/imgpatch.cpp
    analysis/recover.hpp
    analysis/recover.cpp
    analysis/devirt.hpp
    analysis/devirt.cpp
    analysis/magicmida.hpp
    analysis/magicmida.cpp
    network/traffic_store.hpp
    network/traffic_store.cpp
    network/capture_service.hpp
    network/capture_service.cpp
    network/http_proxy.hpp
    network/http_proxy.cpp
    persist/session_store.hpp
    persist/session_store.cpp
    re/rtti.hpp
    re/rtti.cpp
    re/type_catalog.hpp
    re/type_catalog.cpp
    detect/security.hpp
    detect/security.cpp
    process/heap_list.hpp
    process/heap_list.cpp
    infra/deferred.hpp
    infra/deferred.cpp
    util/fs_tools.hpp
    util/fs_tools.cpp
    network/web_fetch.hpp
    network/web_fetch.cpp
    network/mitm_pki.hpp
    network/mitm_pki.cpp
    runtime/kernel_symbols.hpp
    runtime/kernel_symbols.cpp
    runtime/driver_autoload.hpp
    runtime/driver_autoload.cpp
    runtime/kernel_service.hpp
    runtime/kernel_service.cpp
    runtime/kernel_injector.hpp
    runtime/kernel_injector.cpp
    script/lua_engine.hpp
    script/lua_engine.cpp
    emu/taint.hpp
    emu/taint.cpp
    emu/unicorn.hpp
    emu/unicorn.cpp
    emu/session.hpp
    emu/session.cpp
    disasm/engine.hpp
    disasm/engine.cpp
    disasm/pe_parser.hpp
    disasm/pe_parser.cpp
    disasm/strings.hpp
    disasm/strings.cpp
    disasm/function_index.hpp
    disasm/function_index.cpp
    disasm/xrefs.hpp
    disasm/xrefs.cpp
    disasm/binary_state.hpp
    disasm/binary_state.cpp
    disasm/hyperion_session.hpp
    disasm/hyperion_session.cpp
    debugger/debugger.hpp
    debugger/debugger.cpp
    debugger/callstack.hpp
    debugger/callstack.cpp
    runtime/context.hpp
    runtime/nt_api.hpp
    runtime/nt_api.cpp
    runtime/backend.hpp
    runtime/backend_usermode.hpp
    runtime/backend_usermode.cpp
    runtime/backend_registry.hpp
    runtime/backend_registry.cpp
    runtime/backend_kernel.hpp
    runtime/backend_kernel.cpp
    runtime/scan_bridge.hpp
    runtime/scan_bridge.cpp
    runtime/voyager_comm.cpp
    runtime/voyager_syscall.asm
    runtime/identity.hpp
    runtime/identity.cpp
    runtime/session.hpp
    runtime/session.cpp
    runtime/privilege.hpp
    runtime/privilege.cpp
    process/process_list.hpp
    process/process_list.cpp
    process/process_icon.hpp
    process/process_icon.cpp
    process/target_service.hpp
    process/target_service.cpp
    process/module_table.hpp
    process/module_table.cpp
    process/module_dump.hpp
    process/module_dump.cpp
    process/thread_table.hpp
    process/thread_table.cpp
    process/handle_table.hpp
    process/handle_table.cpp
    mcp/mcp_server.hpp
    mcp/mcp_server.cpp
    mcp/mcp_tools.hpp
    mcp/mcp_tools.cpp
    infra/mcp_onboard.hpp
    infra/mcp_onboard.cpp
)

set_source_files_properties(runtime/voyager_syscall.asm PROPERTIES
    COMPILE_OPTIONS ""
    COMPILE_DEFINITIONS ""
)

target_include_directories(slop_core PUBLIC "${CMAKE_SOURCE_DIR}/src")

# Deliberately NOT slop_imgui, core must never see ImGui headers
target_link_libraries(slop_core PUBLIC
    nlohmann_json::nlohmann_json
    Zydis
    httplib::httplib
    slop_hyperion
)

# Win32 system libs (static link, no import lib needed for ntdll, resolved at runtime)
target_link_libraries(slop_core PRIVATE
    psapi advapi32 shlwapi ole32 shell32 crypt32 winhttp dbghelp setupapi
    unicorn
    slop_sqlite
    slop_lua
    ws2_32
    slop_frida
)

target_compile_definitions(slop_core PUBLIC
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(slop_core PRIVATE /W4 /EHsc)
endif()
