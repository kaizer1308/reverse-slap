add_executable(slop_mapper
    src/MapperCore.cpp
    src/DriverLoader.cpp
    src/KernelUtils.cpp
    src/VulnDriver.cpp
    src/EmbeddedDriver.cpp
)

target_include_directories(slop_mapper PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_compile_definitions(slop_mapper PRIVATE
    UNICODE _UNICODE _CRT_SECURE_NO_WARNINGS
)

if(MSVC)
    target_compile_options(slop_mapper PRIVATE /W3 /EHsc /O2)
endif()

set(_wdk_ntdll "C:/Program Files (x86)/Windows Kits/10/Lib/10.0.26100.0/um/x64/ntdll.lib")
if(EXISTS "${_wdk_ntdll}")
    target_link_libraries(slop_mapper PRIVATE "${_wdk_ntdll}")
else()
    message(WARNING "WDK ntdll.lib not found — slop_mapper will not link")
endif()

set_target_properties(slop_mapper PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/mapper"
)
