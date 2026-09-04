option(SLOP_BUILD_TESTS "Build the core logic test harness" ON)

if(NOT SLOP_BUILD_TESTS)
    return()
endif()

add_executable(slop_tests
    test_main.cpp
    test_infra.cpp
    test_memory.cpp
    test_disasm.cpp
    test_debugger.cpp
    test_mcp.cpp
    test_analysis.cpp
    test_emu.cpp
    test_network.cpp
    test_persist.cpp
    test_re.cpp
    test_script.cpp
    test_kernel.cpp
    test_module_dump.cpp
    test_decomp.cpp
    test_hyperion.cpp
    test_detect_fs.cpp
    test_autoload.cpp
    test_xray.cpp
    test_magicmida.cpp
    test_driver.cpp
    test_driver_abi.cpp
)

# Real-world PE fixture: the built SlopTarget.exe itself
if(TARGET slop_target)
    target_sources(slop_tests PRIVATE test_frida.cpp)
    target_compile_definitions(slop_tests PRIVATE
        SLOP_TARGET_EXE_PATH="$<TARGET_FILE:slop_target>"
    )
    add_dependencies(slop_tests slop_target)
endif()

target_include_directories(slop_tests PRIVATE "${CMAKE_SOURCE_DIR}/src/tests")
target_include_directories(slop_tests PRIVATE "${CMAKE_SOURCE_DIR}/src")

target_link_libraries(slop_tests PRIVATE slop_core httplib::httplib)

if(MSVC)
    target_compile_options(slop_tests PRIVATE /W4 /EHsc)
endif()

set_target_properties(slop_tests PROPERTIES
    OUTPUT_NAME "slop_tests"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
)

foreach(filter IN ITEMS decomp hyperion mcp driver abi)
    add_test(NAME "slop_tests_${filter}" COMMAND slop_tests)
    set_tests_properties("slop_tests_${filter}" PROPERTIES
        ENVIRONMENT "SLOP_TEST_FILTER=${filter}"
    )
endforeach()

if(TARGET slop_decomp_target_o0 AND TARGET slop_decomp_target_o2)
    add_executable(slop_bench bench_hyperion.cpp)
    target_include_directories(slop_bench PRIVATE "${CMAKE_SOURCE_DIR}/src")
    target_link_libraries(slop_bench PRIVATE slop_core nlohmann_json::nlohmann_json psapi)
    target_compile_definitions(slop_bench PRIVATE
        SLOP_DECOMP_TARGET_O0_PATH="$<TARGET_FILE:slop_decomp_target_o0>"
        SLOP_DECOMP_TARGET_O2_PATH="$<TARGET_FILE:slop_decomp_target_o2>"
    )
    add_dependencies(slop_bench slop_decomp_target_o0 slop_decomp_target_o2)
    if(MSVC)
        target_compile_options(slop_bench PRIVATE /W4 /EHsc)
    endif()
    set_target_properties(slop_bench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/tests"
    )
endif()
