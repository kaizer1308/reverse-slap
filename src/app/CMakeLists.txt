add_executable(reverse-slop WIN32
    main.cpp
    app.rc
)

# The manifest is embedded as an RT_MANIFEST resource by app.rc, keep the
# linker's own manifest machinery out of it entirely (CMP0090 NEW)
target_link_options(reverse-slop PRIVATE "/MANIFEST:NO")

target_include_directories(reverse-slop PRIVATE "${CMAKE_SOURCE_DIR}/src")
target_link_libraries(reverse-slop PRIVATE slop_ui)

if(MSVC)
    target_compile_options(reverse-slop PRIVATE /W4)
endif()

# signeddrv.sys for the winotify kernel transport (same layout the engine
# uses: driver\ subdir of the exe)
add_custom_command(TARGET reverse-slop POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory
            "$<TARGET_FILE_DIR:reverse-slop>/driver"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/driver/signeddrv.sys"
            "$<TARGET_FILE_DIR:reverse-slop>/driver/signeddrv.sys"
    COMMENT "copying signeddrv.sys to app driver\\ subdir"
)
