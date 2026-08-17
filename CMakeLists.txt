cmake_minimum_required(VERSION 3.20)
project(Dracula LANGUAGES C CXX RC)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build comprehensive test suites" ON)

# ─── Capstone Disassembly Engine ────────────────────────────────────────────
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC ON CACHE BOOL "" FORCE)
set(CAPSTONE_INSTALL OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT ON CACHE BOOL "" FORCE)

add_subdirectory(third_party/capstone EXCLUDE_FROM_ALL)

# ─── Include directories ────────────────────────────────────────────────────
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include
)

# ─── Core Source Files ──────────────────────────────────────────────────────
set(DRACULA_CORE_SOURCES
    src/common/config.cpp
    src/common/findings.cpp
    src/core/analysis_orchestrator.cpp
    src/core/pe_inspector.cpp
    src/core/entropy_analyzer.cpp
    src/core/strings_analyzer.cpp
    src/core/disassembler.cpp
    src/core/cfg_analyzer.cpp
    src/core/xref_analyzer.cpp
    src/core/pattern_scanner.cpp
    src/core/win32_hle.cpp
    src/core/unicorn_analyzer.cpp
    src/core/threat_evaluator.cpp
    src/core/dynamic_vm_analyzer.cpp
    src/core/c_api.cpp
    src/host/qemu_manager.cpp
    src/host/live_tcp_server.cpp
    src/host/report_writer.cpp
    src/host/console_ui.cpp
    src/host/process_inspector.cpp
    src/cli/dracula_shell.cpp
    src/mcp/mcp_server.cpp
)

# Static Core Library for tests and embedding
add_library(DraculaCore STATIC ${DRACULA_CORE_SOURCES})
target_include_directories(DraculaCore PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include
)
target_link_libraries(DraculaCore PUBLIC
    capstone
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lib/libunicorn.a
)

if(WIN32)
    target_link_libraries(DraculaCore PUBLIC ws2_32 iphlpapi psapi crypt32)
endif()

if(MINGW OR MSYS)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++")
endif()

# Backward compatibility alias
add_library(SandboxCore ALIAS DraculaCore)

# ─── Dracula Primary Executable (Unified Host Frontend) ─────────────────────
add_executable(Dracula src/main_dracula.cpp)
target_link_libraries(Dracula PRIVATE DraculaCore)

if(WIN32)
    if(MSVC)
        set_target_properties(Dracula PROPERTIES
            LINK_FLAGS "/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\"")
    elseif(MINGW OR MSYS)
        target_link_options(Dracula PRIVATE -Wl,--enable-auto-import)
    endif()
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

# ─── Comprehensive Test Suite ────────────────────────────────────────────────
if(BUILD_TESTS)
    enable_testing()

    # 1. Legacy buffer emulation test
    add_executable(test_emulate_buffer tests/test_emulate_buffer.cpp)
    target_link_libraries(test_emulate_buffer PRIVATE DraculaCore)
    add_test(NAME EmulateBuffer COMMAND test_emulate_buffer)

    # 2. Comprehensive Dracula Intelligence Test Suite
    add_executable(test_dracula_suite tests/test_dracula_suite.cpp)
    target_link_libraries(test_dracula_suite PRIVATE DraculaCore)
    add_test(NAME DraculaTestSuite COMMAND test_dracula_suite)
endif()
