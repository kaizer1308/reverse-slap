include_guard(GLOBAL)
include(FetchContent)

set(FETCHCONTENT_BASE_DIR "${CMAKE_SOURCE_DIR}/_ext" CACHE PATH "" FORCE)
set(FETCHCONTENT_QUIET OFF)
set(FETCHCONTENT_UPDATES_DISCONNECTED ON)

set(SLOP_IMGUI_VERSION "v1.92.1-docking")
set(SLOP_IMGUI_COMMIT "44aa9a4b3a6f27d09a4eb5770d095cbd376dfc4b")

set(ZYDIS_BUILD_TOOLS OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_SHARED_LIB OFF CACHE BOOL "" FORCE)
set(ZYDIS_BUILD_DOXYGEN OFF CACHE BOOL "" FORCE)
set(ZYDIS_FEATURE_ENCODER ON CACHE BOOL "" FORCE)

set(JSON_BuildTests OFF CACHE BOOL "" FORCE)
set(JSON_Install OFF CACHE BOOL "" FORCE)

set(FT_DISABLE_ZLIB TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_BROTLI TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_BZIP2 TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_PNG TRUE CACHE BOOL "" FORCE)
set(FT_DISABLE_HARFBUZZ TRUE CACHE BOOL "" FORCE)
set(SKIP_INSTALL_ALL ON CACHE BOOL "" FORCE)

set(UNICORN_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(UNICORN_ARCH "x86" CACHE STRING "" FORCE)

# hyperion engine deps
set(SPDLOG_FMT_EXTERNAL ON CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_EXAMPLE OFF CACHE BOOL "" FORCE)
set(SPDLOG_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(SPDLOG_INSTALL OFF CACHE BOOL "" FORCE)
set(SPDLOG_ENABLE_PCH OFF CACHE BOOL "" FORCE)

# capstone only for the architectures hyperion decodes beyond x86 and x64,
# keep the tool set small so builds stay quick (was all 16 arches: single
# biggest C++ configure/compile saving, ~1-3 min on CI)
set(CAPSTONE_BUILD_STATIC_RUNTIME ON CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_ARM64_SUPPORT ON CACHE BOOL "" FORCE)

FetchContent_Declare(fmt
    URL https://github.com/fmtlib/fmt/archive/refs/tags/11.1.4.zip
)

FetchContent_Declare(spdlog
    URL https://github.com/gabime/spdlog/archive/refs/tags/v1.15.3.zip
)

FetchContent_Declare(capstone
    URL https://github.com/capstone-engine/capstone/archive/refs/tags/5.0.6.zip
)

FetchContent_Declare(zlib_kr
    URL https://github.com/madler/zlib/archive/refs/tags/v1.3.1.zip
)

FetchContent_Declare(freetype
    URL https://github.com/freetype/freetype/archive/refs/tags/VER-2-13-3.zip
)

FetchContent_Declare(nlohmann_json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.12.0
    GIT_SHALLOW TRUE
)

FetchContent_Declare(zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG v4.1.1
    GIT_SHALLOW TRUE
    GIT_SUBMODULES_RECURSE TRUE
)

FetchContent_Declare(imgui
    GIT_REPOSITORY https://github.com/ocornut/imgui.git
    GIT_TAG ${SLOP_IMGUI_VERSION}
    GIT_SHALLOW TRUE
)

FetchContent_Declare(httplib
    URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.18.7.zip
)

FetchContent_Declare(unicorn
    URL https://github.com/unicorn-engine/unicorn/archive/refs/tags/2.1.4.zip
)

FetchContent_Declare(sqlite
    URL https://www.sqlite.org/2025/sqlite-amalgamation-3500400.zip
)

FetchContent_Declare(lua
    URL https://www.lua.org/ftp/lua-5.4.7.tar.gz
)

# httplib grabs openssl or zlib off the host when they happen to be installed,
# which dragged libssl and libcrypto runtime dlls into the engine on the ci
# runner, we serve plain loopback http so none of that is ever wanted
set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(freetype nlohmann_json zydis imgui httplib unicorn sqlite lua fmt spdlog capstone zlib_kr)

# frida-core devkit
# frida core ships a prebuilt static lib plus one self contained header, the
# upstream tree needs their forked vala toolchain so we link the release
# devkit instead, same 17.17.0 as the cloned tree
set(SLOP_FRIDA_VERSION "17.17.0")
set(SLOP_FRIDA_DIR "${CMAKE_SOURCE_DIR}/_ext/frida-devkit")
set(SLOP_FRIDA_MARKER "${SLOP_FRIDA_DIR}/.version")
set(SLOP_FRIDA_READY FALSE)
if(EXISTS "${SLOP_FRIDA_DIR}/frida-core.lib" AND EXISTS "${SLOP_FRIDA_MARKER}")
    file(READ "${SLOP_FRIDA_MARKER}" SLOP_FRIDA_INSTALLED_VERSION)
    string(STRIP "${SLOP_FRIDA_INSTALLED_VERSION}" SLOP_FRIDA_INSTALLED_VERSION)
    if(SLOP_FRIDA_INSTALLED_VERSION STREQUAL SLOP_FRIDA_VERSION)
        set(SLOP_FRIDA_READY TRUE)
    endif()
elseif(EXISTS "${SLOP_FRIDA_DIR}/frida-core.lib")
    # adopt an existing matching checkout once, version changes force a verified
    # refresh
    file(WRITE "${SLOP_FRIDA_MARKER}" "${SLOP_FRIDA_VERSION}\n")
    set(SLOP_FRIDA_READY TRUE)
endif()
if(NOT SLOP_FRIDA_READY)
    set(SLOP_FRIDA_SFX "${SLOP_FRIDA_DIR}/frida-core-devkit-${SLOP_FRIDA_VERSION}.exe")
    file(MAKE_DIRECTORY "${SLOP_FRIDA_DIR}")
    message(STATUS "frida: downloading core devkit ${SLOP_FRIDA_VERSION} (~53 MB, one-time)")
    file(DOWNLOAD
        "https://github.com/frida/frida/releases/download/${SLOP_FRIDA_VERSION}/frida-core-devkit-${SLOP_FRIDA_VERSION}-windows-x86_64.exe"
        "${SLOP_FRIDA_SFX}"
        EXPECTED_HASH SHA256=92479d971d722ff21e933af856952027e6935a79f7d2eaa3484efa92c85790e3
        SHOW_PROGRESS
        STATUS SLOP_FRIDA_DL)
    list(GET SLOP_FRIDA_DL 0 SLOP_FRIDA_DL_RC)
    if(NOT SLOP_FRIDA_DL_RC EQUAL 0)
        message(FATAL_ERROR "frida: devkit download failed (${SLOP_FRIDA_DL})")
    endif()
    execute_process(COMMAND "${SLOP_FRIDA_SFX}" "-o${SLOP_FRIDA_DIR}" "-y"
                    RESULT_VARIABLE SLOP_FRIDA_X)
    if(NOT SLOP_FRIDA_X EQUAL 0)
        message(FATAL_ERROR "frida: devkit self-extractor failed (${SLOP_FRIDA_X})")
    endif()
    file(REMOVE "${SLOP_FRIDA_SFX}")
    if(NOT EXISTS "${SLOP_FRIDA_DIR}/frida-core.lib")
        message(FATAL_ERROR "frida: devkit extracted but frida-core.lib is missing")
    endif()
    file(WRITE "${SLOP_FRIDA_MARKER}" "${SLOP_FRIDA_VERSION}\n")
endif()
if(NOT TARGET frida::core)
    add_library(frida::core UNKNOWN IMPORTED)
    set_target_properties(frida::core PROPERTIES
        IMPORTED_LOCATION "${SLOP_FRIDA_DIR}/frida-core.lib"
        INTERFACE_INCLUDE_DIRECTORIES "${SLOP_FRIDA_DIR}")
endif()

# zlib builds both a shared and a static lib, we only want the static one so
# the exes stay freestanding
if(NOT TARGET ZLIB::ZLIB)
    add_library(ZLIB::ZLIB ALIAS zlibstatic)
endif()

# vendored c sources with no cmake build of their own
add_library(slop_sqlite STATIC
    "${sqlite_SOURCE_DIR}/sqlite3.c"
)
target_include_directories(slop_sqlite PUBLIC "${sqlite_SOURCE_DIR}")
target_compile_definitions(slop_sqlite PRIVATE
    SQLITE_OMIT_LOAD_EXTENSION
    SQLITE_THREADSAFE=1
)
if(MSVC)
    target_compile_options(slop_sqlite PRIVATE /W0)
endif()

add_library(slop_lua STATIC
    "${lua_SOURCE_DIR}/src/lapi.c"
    "${lua_SOURCE_DIR}/src/lauxlib.c"
    "${lua_SOURCE_DIR}/src/lbaselib.c"
    "${lua_SOURCE_DIR}/src/lcode.c"
    "${lua_SOURCE_DIR}/src/lcorolib.c"
    "${lua_SOURCE_DIR}/src/lctype.c"
    "${lua_SOURCE_DIR}/src/ldblib.c"
    "${lua_SOURCE_DIR}/src/ldebug.c"
    "${lua_SOURCE_DIR}/src/ldo.c"
    "${lua_SOURCE_DIR}/src/ldump.c"
    "${lua_SOURCE_DIR}/src/lfunc.c"
    "${lua_SOURCE_DIR}/src/lgc.c"
    "${lua_SOURCE_DIR}/src/linit.c"
    "${lua_SOURCE_DIR}/src/liolib.c"
    "${lua_SOURCE_DIR}/src/llex.c"
    "${lua_SOURCE_DIR}/src/lmathlib.c"
    "${lua_SOURCE_DIR}/src/lmem.c"
    "${lua_SOURCE_DIR}/src/loadlib.c"
    "${lua_SOURCE_DIR}/src/lobject.c"
    "${lua_SOURCE_DIR}/src/lopcodes.c"
    "${lua_SOURCE_DIR}/src/loslib.c"
    "${lua_SOURCE_DIR}/src/lparser.c"
    "${lua_SOURCE_DIR}/src/lstate.c"
    "${lua_SOURCE_DIR}/src/lstring.c"
    "${lua_SOURCE_DIR}/src/lstrlib.c"
    "${lua_SOURCE_DIR}/src/ltable.c"
    "${lua_SOURCE_DIR}/src/ltablib.c"
    "${lua_SOURCE_DIR}/src/ltm.c"
    "${lua_SOURCE_DIR}/src/lundump.c"
    "${lua_SOURCE_DIR}/src/lutf8lib.c"
    "${lua_SOURCE_DIR}/src/lvm.c"
    "${lua_SOURCE_DIR}/src/lzio.c"
)
target_include_directories(slop_lua PUBLIC "${lua_SOURCE_DIR}/src")
target_compile_definitions(slop_lua PRIVATE
    LUA_USE_WINDOWS
)
if(MSVC)
    target_compile_options(slop_lua PRIVATE /W0)
endif()

if(MSVC)
    foreach(_slop_dep_target freetype Zydis Zycore nlohmann_json_schema_validator
                             unicorn unicorn-common fmt spdlog capstone)
        if(TARGET ${_slop_dep_target})
            target_compile_options(${_slop_dep_target} PRIVATE /W0)
        endif()
    endforeach()
endif()

add_library(slop_imgui STATIC
    "${imgui_SOURCE_DIR}/imgui.cpp"
    "${imgui_SOURCE_DIR}/imgui_draw.cpp"
    "${imgui_SOURCE_DIR}/imgui_tables.cpp"
    "${imgui_SOURCE_DIR}/imgui_widgets.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_win32.cpp"
    "${imgui_SOURCE_DIR}/backends/imgui_impl_dx11.cpp"
    "${imgui_SOURCE_DIR}/misc/freetype/imgui_freetype.cpp"
)

target_include_directories(slop_imgui PUBLIC
    "${imgui_SOURCE_DIR}"
    "${imgui_SOURCE_DIR}/backends"
    "${imgui_SOURCE_DIR}/misc/freetype"
)

target_compile_definitions(slop_imgui PUBLIC IMGUI_ENABLE_FREETYPE)
target_link_libraries(slop_imgui PUBLIC freetype d3d11 dxgi)

if(MSVC)
    target_compile_options(slop_imgui PRIVATE /W0)
endif()
