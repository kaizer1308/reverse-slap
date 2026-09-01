# Vendored hyperion engine (github.com/Sidenai/hyperion-disassembler)
#
# Only core/ (disasm, loaders, analyzer, decompiler, types, database) and
# threading/ are ported, hyperion's own ui/, debugger/, scripting/ and mcp/
# are replaced by reverse-slop's. The `hype` namespace is kept verbatim so
# upstream changes stay diffable
#
# Include root is `src/hyperion/` so the vendored sources keep their original
# `#include "core/..."` / `#include "threading/..."` paths without colliding
# with reverse-slop's own `src/`-rooted `core/...` includes

file(GLOB_RECURSE SLOP_HYPERION_SOURCES
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/core/*.h"
    "${CMAKE_CURRENT_SOURCE_DIR}/threading/*.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/threading/*.h"
)

add_library(slop_hyperion STATIC ${SLOP_HYPERION_SOURCES})

target_include_directories(slop_hyperion PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(slop_hyperion PUBLIC
    Zydis             # x86/x64 decode (same vendored v4.1.1 as slop_core)
    fmt::fmt
    spdlog::spdlog
    capstone          # ARM/ARM64/MIPS/PPC decode
    ZLIB::ZLIB        # FLIRT signature decompression
)

if(WIN32)
    # PdbLoader walks symbol streams via DbgHelp
    target_link_libraries(slop_hyperion PRIVATE dbghelp)
endif()

if(MSVC)
    # Vendored engine: keep the build quiet, we do not own its warnings
    target_compile_options(slop_hyperion PRIVATE /W0 /permissive-)
    target_compile_definitions(slop_hyperion PRIVATE
        _CRT_SECURE_NO_WARNINGS NOMINMAX
    )
endif()

# Upstream hyperion compiled with this PCH; several sources rely on it for
# <algorithm>/<functional>/<filesystem>/<thread>/<mutex>/<atomic>/<span>
target_precompile_headers(slop_hyperion PRIVATE
    <cstdint>
    <string>
    <vector>
    <unordered_map>
    <unordered_set>
    <memory>
    <algorithm>
    <functional>
    <thread>
    <mutex>
    <atomic>
    <filesystem>
    <fstream>
    <optional>
    <cstring>
    <cstdio>
    <span>
)
