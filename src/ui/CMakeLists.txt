add_library(slop_ui STATIC
    tokens.hpp
    theme.hpp
    theme.cpp
    fonts.hpp
    fonts.cpp
    chrome.hpp
    chrome.cpp
    dockspace.hpp
    dockspace.cpp
    command_palette.hpp
    command_palette.cpp
    view_registry.hpp
    view_registry.cpp
    panels.hpp
    panels.cpp
    views_core.hpp
    view_targets.cpp
    view_memory.cpp
    view_scanner.cpp
    view_disasm.cpp
    view_pseudocode.cpp
    view_strings.cpp
    view_pe.cpp
    view_debugger.cpp
    view_unpacker.cpp
)

target_link_libraries(slop_ui PRIVATE comdlg32)

target_include_directories(slop_ui PUBLIC "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(slop_ui PUBLIC slop_imgui slop_core)

if(MSVC)
    target_compile_options(slop_ui PRIVATE /W4)
endif()
