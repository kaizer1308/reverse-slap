# Console-subsystem host for the core. Links slop_core only, never slop_ui,
# so the ImGui/DX11 stack cannot creep back in through this target
add_executable(svchost-helper
    engine_main.cpp
    engine.rc
)
set_target_properties(svchost-helper PROPERTIES OUTPUT_NAME "RuntimeBroker")

# The manifest is embedded as an RT_MANIFEST resource by engine.rc, keep the
# linker's own manifest machinery out of it entirely (CMP0090 NEW)
target_link_options(svchost-helper PRIVATE "/MANIFEST:NO")

target_include_directories(svchost-helper PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(svchost-helper PRIVATE slop_core)

if(MSVC)
    target_compile_options(svchost-helper PRIVATE /W4 /guard:cf)
    target_link_options(svchost-helper PRIVATE /guard:cf /PDBALTPATH:none /DEBUG:NONE)
endif()

# Post-build: strip Rich header, IAT hint-names, PDB path, compiler strings
add_custom_command(TARGET svchost-helper POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "stripping PE artifacts..."
    COMMAND python "${CMAKE_SOURCE_DIR}/tools/pe_strip.py"
            "$<TARGET_FILE:svchost-helper>" --inplace
    COMMENT "hardening engine binary (Rich header, IAT hints, PDB, compiler strings)"
)

# slop_frida.dll is loaded from the exe's own directory, so every consumer exe
# needs a copy beside it (same rule as src/app and tests)
add_custom_command(TARGET svchost-helper POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:slop_frida> $<TARGET_FILE_DIR:svchost-helper>
    COMMENT "copying slop_frida.dll next to svchost-helper"
)

# signeddrv.sys must sit in a driver\ subdirectory of the exe for the
# winotify transport to find it (find_source_driver probes exe_dir\driver\
# before the E: fallback). copy from the repo on every build so the
# signed path never depends on an external drive
add_custom_command(TARGET svchost-helper POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:svchost-helper>/driver"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/driver/signeddrv.sys"
            "$<TARGET_FILE_DIR:svchost-helper>/driver/signeddrv.sys"
    COMMENT "copying signeddrv.sys to engine driver\\ subdir"
)
