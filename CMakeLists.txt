cmake_minimum_required(VERSION 3.20)
project(SandboxTracer LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options
option(BUILD_GUI "Build Graphical User Interface (Dear ImGui)" ON)
option(BUILD_TOOLS "Build Memory Inspector & Reverse Engineering Tools" ON)
option(BUILD_TESTS "Build standalone test harnesses" ON)

# ─── Include directories ────────────────────────────────────────────────────
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
)

# ─── Core Library Sources (Malware Sandbox & Analysis Engine) ───────────────
set(CORE_SOURCES
    src/common/config.cpp
    src/core/dynamic_vm_analyzer.cpp
    src/core/unicorn_analyzer.cpp
    src/core/entropy_analyzer.cpp
    src/core/threat_evaluator.cpp
    src/core/c_api.cpp
    src/host/qemu_manager.cpp
    src/host/live_tcp_server.cpp
    src/host/report_writer.cpp
    src/host/console_ui.cpp
    src/host/process_inspector.cpp
)

# Core static library
add_library(SandboxCore STATIC ${CORE_SOURCES})
target_include_directories(SandboxCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
)

# Link Unicorn static library
target_link_libraries(SandboxCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lib/libunicorn.a
)

if(WIN32)
    target_link_libraries(SandboxCore PUBLIC ws2_32 iphlpapi psapi)
endif()

if(MINGW OR MSYS)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

# ─── Injectable DLL (Tools) ─────────────────────────────────────────────────
if(BUILD_TOOLS)
    set(INJECTABLE_DLL_SOURCES
        src/tools/injectable/injectable_dll.cpp
    )

    add_library(InjectableDLL SHARED ${INJECTABLE_DLL_SOURCES})
    target_include_directories(InjectableDLL PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    )
    target_link_libraries(InjectableDLL PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lib/libunicorn.a
        psapi
    )
    if(MINGW OR MSYS)
        target_link_options(InjectableDLL PRIVATE
            -static -static-libgcc -static-libstdc++
        )
    endif()
    set_target_properties(InjectableDLL PROPERTIES
        OUTPUT_NAME "InjectableDLL"
        PREFIX ""
        SUFFIX ".dll"
    )

    # Copy DLL to the resource directory so windres can link it into HostController
    add_custom_command(TARGET InjectableDLL POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
            $<TARGET_FILE:InjectableDLL>
            ${CMAKE_CURRENT_SOURCE_DIR}/src/tools/injectable/InjectableDLL.dll
        COMMENT "Copying InjectableDLL.dll to resource directory for embedding"
    )
endif()

# ─── Host Controller EXE (Main CLI Orchestrator) ────────────────────────────
set(HOST_SOURCES
    src/host/main.cpp
)

if(BUILD_TOOLS)
    list(APPEND HOST_SOURCES src/tools/injectable/injectable_resource.rc)
endif()

add_executable(HostController ${HOST_SOURCES})
if(BUILD_TOOLS)
    add_dependencies(HostController InjectableDLL)
endif()
target_link_libraries(HostController PRIVATE SandboxCore)

if(WIN32)
    if(MSVC)
        set_target_properties(HostController PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")
    elseif(MINGW OR MSYS)
        target_link_options(HostController PRIVATE -Wl,--enable-auto-import)
    endif()
endif()

# Copy DLL alongside HostController.exe
if(BUILD_TOOLS)
    add_custom_command(TARGET HostController POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            $<TARGET_FILE:InjectableDLL>
            $<TARGET_FILE_DIR:HostController>/InjectableDLL.dll
        COMMENT "Copying InjectableDLL.dll alongside HostController.exe"
    )
endif()

# ─── Guest Agent Executable (Runs inside Windows VM) ────────────────────────
set(GUEST_SOURCES
    src/guest/main.cpp
    src/guest/process_spawner.cpp
    src/guest/system_tracer.cpp
    src/guest/tcp_emitter.cpp
)
add_executable(GuestAgent ${GUEST_SOURCES})
if(WIN32)
    target_link_libraries(GuestAgent PRIVATE ws2_32 iphlpapi)
endif()

# ─── External Tools (Memory Inspector / Offset Verifier) ────────────────────
if(BUILD_TOOLS)
    add_executable(external_verifier src/tools/external_offset_verifier.cpp)
    target_include_directories(external_verifier PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    )
    target_link_libraries(external_verifier PRIVATE SandboxCore psapi)
endif()

# ─── Test Harness ─────────────────────────────────────────────────────────────
if(BUILD_TESTS)
    add_executable(test_emulate_buffer tests/test_emulate_buffer.cpp)
    target_link_libraries(test_emulate_buffer PRIVATE SandboxCore)

    enable_testing()
    add_test(NAME EmulateBuffer COMMAND test_emulate_buffer)
endif()

# ─── Graphical User Interface (Dear ImGui + DX11) ───────────────────────────
if(BUILD_GUI)
    include_directories(
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui/backends
    )

    set(IMGUI_SOURCES
        third_party/imgui/imgui.cpp
        third_party/imgui/imgui_draw.cpp
        third_party/imgui/imgui_tables.cpp
        third_party/imgui/imgui_widgets.cpp
        third_party/imgui/backends/imgui_impl_win32.cpp
        third_party/imgui/backends/imgui_impl_dx11.cpp
    )

    set(GUI_SOURCES
        src/gui/glass_theme.cpp
        src/gui/gui_app.cpp
        src/gui/main_gui.cpp
        ${IMGUI_SOURCES}
    )

    add_executable(SandboxGUI WIN32 ${GUI_SOURCES})
    target_include_directories(SandboxGUI PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui
        ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui/backends
    )

    target_link_libraries(SandboxGUI PRIVATE
        SandboxCore
        d3d11
        d3dcompiler
        dwmapi
        imm32
        comdlg32
        gdi32
    )

    # ─── External ESP Overlay ─────────────────────────────────────────────────
    if(BUILD_TOOLS)
        add_executable(ExternalOverlay WIN32
            src/tools/external_overlay.cpp
            ${IMGUI_SOURCES}
        )
        target_include_directories(ExternalOverlay PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/imgui/backends
        )
        target_link_libraries(ExternalOverlay PRIVATE
            ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lib/libunicorn.a
            d3d11
            d3dcompiler
            dwmapi
            imm32
            psapi
            gdi32
            ws2_32
        )
        if(MINGW OR MSYS)
            target_link_options(ExternalOverlay PRIVATE
                -static -static-libgcc -static-libstdc++
            )
        endif()
    endif()
endif()
