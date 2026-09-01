add_executable(slop_target
    main.cpp
    known_values.hpp
    known_values.cpp
    pointer_chain.hpp
    pointer_chain.cpp
    aob_fixtures.hpp
    aob_fixtures.cpp
    region_zoo.hpp
    region_zoo.cpp
    mutator.hpp
    mutator.cpp
    report.hpp
    report.cpp
)

target_compile_definitions(slop_target PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _CRT_SECURE_NO_WARNINGS)

if(MSVC)
    target_compile_options(slop_target PRIVATE /W4 /EHsc /O2)
    target_link_options(slop_target PRIVATE /DEBUG:FULL)
endif()

set_target_properties(slop_target PROPERTIES
    OUTPUT_NAME "SlopTarget"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src/app"
)

target_link_libraries(slop_target PRIVATE nlohmann_json::nlohmann_json)

foreach(opt IN ITEMS O0 O2)
    string(TOLOWER "${opt}" opt_lower)
    add_executable(slop_decomp_target_${opt_lower} decomp_target.cpp)
    target_compile_definitions(slop_decomp_target_${opt_lower} PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
    if(MSVC)
        target_compile_options(slop_decomp_target_${opt_lower} PRIVATE /W4 /EHsc)
        if(opt STREQUAL "O0")
            target_compile_options(slop_decomp_target_${opt_lower} PRIVATE /Od)
        else()
            target_compile_options(slop_decomp_target_${opt_lower} PRIVATE /O2)
        endif()
        target_link_options(slop_decomp_target_${opt_lower} PRIVATE /DEBUG:FULL)
    endif()
    set_target_properties(slop_decomp_target_${opt_lower} PROPERTIES
        OUTPUT_NAME "DecompTarget-${opt}"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/src/app"
    )
endforeach()
