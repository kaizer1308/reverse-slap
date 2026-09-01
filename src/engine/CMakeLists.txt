# Console-subsystem host for the core. Links slop_core only, never slop_ui,
# so the ImGui/DX11 stack cannot creep back in through this target
add_executable(reverse-slop-engine
    engine_main.cpp
    engine.rc
)

# The manifest is embedded as an RT_MANIFEST resource by engine.rc, keep the
# linker's own manifest machinery out of it entirely (CMP0090 NEW)
target_link_options(reverse-slop-engine PRIVATE "/MANIFEST:NO")

target_include_directories(reverse-slop-engine PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(reverse-slop-engine PRIVATE slop_core)

if(MSVC)
    target_compile_options(reverse-slop-engine PRIVATE /W4)
endif()

# slop_frida.dll is loaded from the exe's own directory, so every consumer exe
# needs a copy beside it (same rule as src/app and tests)
add_custom_command(TARGET reverse-slop-engine POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:slop_frida> $<TARGET_FILE_DIR:reverse-slop-engine>
    COMMENT "copying slop_frida.dll next to reverse-slop-engine"
)
