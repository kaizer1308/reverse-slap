add_executable(slop_live
    live_drive.cpp
)

add_executable(probe_kernel
    probe_kernel.cpp
)

target_include_directories(probe_kernel PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(probe_kernel PRIVATE slop_core)

if(MSVC)
    target_compile_options(probe_kernel PRIVATE /W4 /EHsc /O2)
endif()

set_target_properties(probe_kernel PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/live"
)

target_include_directories(slop_live PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(slop_live PRIVATE slop_core nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(slop_live PRIVATE /W4 /EHsc /O2)
endif()

set_target_properties(slop_live PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/live"
)

add_executable(veh_probe
    veh_probe.cpp
)
target_include_directories(veh_probe PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(veh_probe PRIVATE slop_core)

if(MSVC)
    target_compile_options(veh_probe PRIVATE /W4 /EHsc /O2)
endif()

set_target_properties(veh_probe PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/live"
)
