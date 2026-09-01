cmake_minimum_required(VERSION 3.25)

set(CMAKE_POLICY_DEFAULT_CMP0091 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0090 NEW)
set(CMAKE_POLICY_DEFAULT_CMP0141 NEW)

project(reverse-slop VERSION 0.1.0 LANGUAGES C CXX ASM_MASM)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_MSVC_DEBUG_INFORMATION_FORMAT "$<$<CONFIG:Debug,RelWithDebInfo,Release>:Embedded>")

if(MSVC)
    add_compile_definitions(UNICODE _UNICODE)
    # scoped to c and cxx so the vendored asm sources never see compiler switches
    add_compile_options(
        "$<$<COMPILE_LANGUAGE:C,CXX>:/permissive->"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/Zc:__cplusplus>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/utf-8>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/GS>"
        "$<$<COMPILE_LANGUAGE:C,CXX>:/guard:cf>"
    )
    add_link_options(
        /DYNAMICBASE
        /HIGHENTROPYVA
        /NXCOMPAT
    )
endif()

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(deps)

option(SLOP_BUILD_TEST_TARGET "Build SlopTarget.exe test target" ON)
option(SLOP_BUILD_TESTS "Build the core logic test harness" ON)
option(SLOP_BUILD_ENGINE "Build the headless engine host (Tauri front end backend)" ON)

enable_testing()

add_subdirectory(src/hyperion)
add_subdirectory(src/core)
add_subdirectory(src/ui)
add_subdirectory(src/app)

if(SLOP_BUILD_ENGINE)
    add_subdirectory(src/engine)
endif()

if(SLOP_BUILD_TEST_TARGET)
    add_subdirectory(src/target)
endif()

if(SLOP_BUILD_TESTS)
    add_subdirectory(src/tests)
endif()

option(SLOP_BUILD_MAPPER "Build slop_mapper loader utility" ON)

if(SLOP_BUILD_MAPPER)
    add_subdirectory(mapper)
endif()

add_subdirectory(src/live)
