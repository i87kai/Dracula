cmake_minimum_required(VERSION 3.20)

# ─── SINGLE SOURCE OF TRUTH FOR THE DRACULA VERSION ─────────────────────────
# include/common/version.h is GENERATED from this declaration. Never hard-code
# a version anywhere else in the tree.
project(Dracula VERSION 1.3.0 LANGUAGES C CXX RC)

set(DRACULA_RELEASE_DATE "2026-08-18")
set(DRACULA_BUILD_TARGET "x86_64-w64-mingw32")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/common/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/common/version.h
    @ONLY
)

# ─── SINGLE SOURCE OF TRUTH FOR THE DRACULA ARTWORK ─────────────────────────
# The .txt below is the editable asset; it is embedded into the executable at
# build time, so a released binary never reads it from disk.
include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/EmbedArt.cmake)
dracula_embed_art(
    "${CMAKE_CURRENT_SOURCE_DIR}/Vampire Dracula ASCII Art.txt"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/cli/dracula_art_data.h"
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Encoding options
if(MSVC)
    add_compile_options(/utf-8)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-finput-charset=UTF-8 -fexec-charset=UTF-8)
endif()

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
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zstd
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zstd/common
)

file(GLOB ZSTD_SOURCES
    "third_party/zstd/common/*.c"
    "third_party/zstd/compress/*.c"
    "third_party/zstd/decompress/*.c"
)

# ─── Core Source Files ──────────────────────────────────────────────────────
set(DRACULA_CORE_SOURCES
    third_party/sqlite/sqlite3.c
    ${ZSTD_SOURCES}
    src/common/config.cpp
    src/common/findings.cpp
    src/common/paths.cpp
    src/common/input_validator.cpp
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
    src/core/environment_profile.cpp
    src/core/virtual_time.cpp
    src/core/branch_influence.cpp
    src/core/evasion_artifact_rules.cpp
    src/core/anti_evasion_engine.cpp
    src/core/anti_evasion_report.cpp
    src/core/c_api.cpp
    src/app/json.cpp
    src/app/project.cpp
    src/app/project_manager.cpp
    src/app/settings.cpp
    src/app/html_report.cpp
    src/app/target_binding.cpp
    src/app/project_service.cpp
    src/app/memory_service.cpp
    src/app/analysis_services.cpp
    src/app/runtime_service.cpp
    src/app/hasher.cpp
    src/app/dracula_image.cpp
    src/app/sandbox_service.cpp
    src/utr/evidence_graph.cpp
    src/utr/memory_intelligence.cpp
    src/utr/function_intelligence.cpp
    src/utr/session_manager.cpp
    src/utr/artifact_manager.cpp
    src/utr/managed_backend.cpp
    src/utr/dll_harness.cpp
    src/utr/external_observer.cpp
    src/utr/dbgeng_backend.cpp
    src/utr/target_manager.cpp
    src/utr/file_target.cpp
    src/utr/process_target.cpp
    src/utr/managed_target.cpp
    src/utr/service_target.cpp
    src/utr/driver_target.cpp
    src/utr/analysis_orchestrator.cpp
    src/host/sandbox_fingerprint.cpp
    src/host/qemu_manager.cpp
    src/host/port_allocator.cpp
    src/host/guest_session_handoff.cpp
    src/host/live_tcp_server.cpp
    src/host/report_writer.cpp
    src/host/console_ui.cpp
    src/host/process_inspector.cpp
    src/cli/terminal.cpp
    src/cli/text_layout.cpp
    src/cli/ui.cpp
    src/cli/ascii_art.cpp
    src/cli/startup_card.cpp
    src/cli/startup_picker.cpp
    src/cli/screen.cpp
    src/cli/command_registry.cpp
    src/cli/line_editor.cpp
    src/cli/dracula_shell.cpp
    src/mcp/mcp_server.cpp
)

# Static Core Library for tests and embedding
add_library(DraculaCore STATIC ${DRACULA_CORE_SOURCES})
target_include_directories(DraculaCore PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/generated
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/capstone/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zstd
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/zstd/common
)
target_link_libraries(DraculaCore PUBLIC
    capstone
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/lib/libunicorn.a
)

if(WIN32)
    target_link_libraries(DraculaCore PUBLIC ws2_32 iphlpapi psapi crypt32 bcrypt dbghelp ole32 oleaut32)
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

# ─── Dracula In-Process Telemetry Agent DLL ─────────────────────────────────
add_library(DraculaAgent64 SHARED src/agent/dracula_agent.cpp)
target_compile_definitions(DraculaAgent64 PRIVATE DRACULA_AGENT_EXPORTS)
target_include_directories(DraculaAgent64 PUBLIC include)
if(WIN32)
    target_link_libraries(DraculaAgent64 PRIVATE psapi)
endif()

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
    src/host/guest_session_handoff.cpp
)
add_executable(GuestAgent ${GUEST_SOURCES})
if(WIN32)
    target_link_libraries(GuestAgent PRIVATE ws2_32 iphlpapi bcrypt)
endif()

# ─── Benign Anti-Evasion Probe Samples ──────────────────────────────────────
#
# Deterministic, payload-free programs that inspect one environment property
# and then take one of two harmless code paths. They are built freestanding so
# the entry point is the first thing that runs and every call they make is a
# Win32 import Dracula's HLE layer models.
#
set(DRACULA_AE_SAMPLES
    ae_cpuid_gate
    ae_timing_gate
    ae_resource_gate
    ae_debug_gate
    ae_combined_gate
    ae_benign_sysinfo
)
set(DRACULA_AE_SAMPLE_DIR "${CMAKE_CURRENT_BINARY_DIR}/samples/antievasion")
file(MAKE_DIRECTORY ${DRACULA_AE_SAMPLE_DIR})

set(DRACULA_AE_SAMPLE_OUTPUTS "")
foreach(sample ${DRACULA_AE_SAMPLES})
    set(sample_out "${DRACULA_AE_SAMPLE_DIR}/${sample}.exe")
    add_custom_command(
        OUTPUT ${sample_out}
        COMMAND ${CMAKE_C_COMPILER}
                -O1 -fno-asynchronous-unwind-tables
                -nostdlib -nostartfiles
                -Wl,-e,entry -Wl,--subsystem,console
                -o ${sample_out}
                ${CMAKE_CURRENT_SOURCE_DIR}/samples/antievasion/${sample}.c
                -lkernel32
        DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/samples/antievasion/${sample}.c
                ${CMAKE_CURRENT_SOURCE_DIR}/samples/antievasion/ae_common.h
        COMMENT "Building benign anti-evasion probe ${sample}.exe"
        VERBATIM
    )
    list(APPEND DRACULA_AE_SAMPLE_OUTPUTS ${sample_out})
endforeach()

# The environment probe is an ordinary console program rather than a
# freestanding one: it has to print, and it is meant to run natively, inside
# QEMU, and anywhere else a ground-truth reading of the environment is wanted.
set(DRACULA_ENV_PROBE "${DRACULA_AE_SAMPLE_DIR}/environment_probe.exe")
add_custom_command(
    OUTPUT ${DRACULA_ENV_PROBE}
    COMMAND ${CMAKE_C_COMPILER}
            -O1 -Wall
            -o ${DRACULA_ENV_PROBE}
            ${CMAKE_CURRENT_SOURCE_DIR}/samples/antievasion/environment_probe.c
            -ladvapi32 -lkernel32 -luser32
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/samples/antievasion/environment_probe.c
    COMMENT "Building the benign environment probe"
    VERBATIM
)
list(APPEND DRACULA_AE_SAMPLE_OUTPUTS ${DRACULA_ENV_PROBE})

add_custom_target(AntiEvasionSamples ALL DEPENDS ${DRACULA_AE_SAMPLE_OUTPUTS})

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

    # 3. Terminal layout / startup card / palette rendering suite
    add_executable(test_terminal_ui tests/test_terminal_ui.cpp)
    target_link_libraries(test_terminal_ui PRIVATE DraculaCore)
    add_test(NAME TerminalUi COMMAND test_terminal_ui)

    # 4. Anti-Evasion Intelligence Engine suite
    add_executable(test_anti_evasion tests/test_anti_evasion.cpp)
    target_link_libraries(test_anti_evasion PRIVATE DraculaCore)
    target_compile_definitions(test_anti_evasion PRIVATE
        DRACULA_AE_SAMPLE_DIR="${DRACULA_AE_SAMPLE_DIR}")
    add_dependencies(test_anti_evasion AntiEvasionSamples)
    add_test(NAME AntiEvasion COMMAND test_anti_evasion)

    # 5. Sandbox networking: port allocation, conflict handling, handoff, framing
    add_executable(test_sandbox_network tests/test_sandbox_network.cpp)
    target_link_libraries(test_sandbox_network PRIVATE DraculaCore)
    add_test(NAME SandboxNetwork COMMAND test_sandbox_network)

    # 6. Dependency Qualification POC Suite
    add_executable(test_poc_qualification tests/poc_qualification.cpp)
    target_link_libraries(test_poc_qualification PRIVATE DraculaCore)
    add_test(NAME PocQualification COMMAND test_poc_qualification)

    # 7. UTR Targets Abstraction Suite
    add_executable(test_utr_targets tests/test_utr_targets.cpp)
    target_link_libraries(test_utr_targets PRIVATE DraculaCore)
    add_test(NAME UtrTargets COMMAND test_utr_targets)

    # 8. Memory Intelligence & Transformation Suite
    add_executable(test_memory_intelligence tests/test_memory_intelligence.cpp)
    target_link_libraries(test_memory_intelligence PRIVATE DraculaCore)
    add_test(NAME MemoryIntelligence COMMAND test_memory_intelligence)

    # 9. Function Intelligence & Ranking Suite
    add_executable(test_function_intelligence tests/test_function_intelligence.cpp)
    target_link_libraries(test_function_intelligence PRIVATE DraculaCore)
    add_test(NAME FunctionIntelligence COMMAND test_function_intelligence)

    # 10. SQLite Session Persistence Suite
    add_executable(test_session_persistence tests/test_session_persistence.cpp)
    target_link_libraries(test_session_persistence PRIVATE DraculaCore)
    add_test(NAME SessionPersistence COMMAND test_session_persistence)

    # 10b. Project Workspace Suite (v1.3.0 project-centric architecture)
    add_executable(test_project_workspace tests/test_project_workspace.cpp)
    target_link_libraries(test_project_workspace PRIVATE DraculaCore)
    add_test(NAME ProjectWorkspace COMMAND test_project_workspace)

    # 10c. Command Registry Consistency Suite (palette == handlers)
    add_executable(test_command_registry tests/test_command_registry.cpp)
    target_link_libraries(test_command_registry PRIVATE DraculaCore)
    add_test(NAME CommandRegistry COMMAND test_command_registry)

    # 10d. Command Regression Suite (section 41: PID is never a path)
    add_executable(test_command_regressions tests/test_command_regressions.cpp)
    target_link_libraries(test_command_regressions PRIVATE DraculaCore)
    add_test(NAME CommandRegressions COMMAND test_command_regressions)

    # 10e. .draculaimg Package Format Suite (synthetic fixtures only)
    add_executable(test_dracula_image tests/test_dracula_image.cpp)
    target_link_libraries(test_dracula_image PRIVATE DraculaCore)
    add_test(NAME DraculaImage COMMAND test_dracula_image)

    # 10f. LIVE QEMU acceptance. Built, but deliberately NOT registered with
    # ctest: it needs a real imported VM base and boots an actual guest. It
    # reports BLOCKED and exits zero when that environment is absent, so it can
    # never be mistaken for a simulated pass.
    add_executable(live_qemu_acceptance tests/live_qemu_acceptance.cpp)
    target_link_libraries(live_qemu_acceptance PRIVATE DraculaCore)

    # 11. ManagedHost .NET 10 Out-of-Process Backend Suite
    add_executable(test_managed_backend tests/test_managed_backend.cpp)
    target_link_libraries(test_managed_backend PRIVATE DraculaCore)
    add_test(NAME ManagedBackend COMMAND test_managed_backend)

    # 12. Evidence Graph & Behavior Chains Suite
    add_executable(test_evidence_graph tests/test_evidence_graph.cpp)
    target_link_libraries(test_evidence_graph PRIVATE DraculaCore)
    add_test(NAME EvidenceGraph COMMAND test_evidence_graph)

    # 13. MCP Protocol UTR Suite
    add_executable(test_mcp_utr tests/test_mcp_utr.cpp)
    target_link_libraries(test_mcp_utr PRIVATE DraculaCore)
    add_test(NAME McpUtr COMMAND test_mcp_utr)

    # 14. Dracula In-Process Telemetry Agent Suite
    add_executable(test_dracula_agent tests/test_dracula_agent.cpp)
    target_link_libraries(test_dracula_agent PRIVATE DraculaCore)
    add_dependencies(test_dracula_agent DraculaAgent64)
    add_test(NAME DraculaAgent COMMAND test_dracula_agent)

    # 15. Real QEMU UTR End-to-End & Escalation Suite
    add_executable(test_qemu_utr_e2e tests/test_qemu_utr_e2e.cpp)
    target_link_libraries(test_qemu_utr_e2e PRIVATE DraculaCore)
    add_test(NAME QemuUtrE2E COMMAND test_qemu_utr_e2e)
endif()

message(STATUS "")
message(STATUS "─── Dracula Universal Target Runtime (UTR) Configuration Summary ───")
message(STATUS "  Target Abstractions: Native EXE, Native DLL, Process PID, Service, .NET, Driver, VM")
message(STATUS "  Vendored SQLite:     ENABLED (v3.46.1 amalgamation)")
message(STATUS "  Vendored Zstd:       ENABLED (v1.5.6)")
message(STATUS "  Capstone / Unicorn:  ENABLED (x86/x64 disassembly & CPU emulation)")
message(STATUS "  ManagedHost (.NET):  ENABLED (Out-of-Process .NET 10 host)")
message(STATUS "  DbgEng / DIA / ETW:  ENABLED (Windows SDK dynamic adapters)")
message(STATUS "  In-Process Agent:    DraculaAgent64.dll")
message(STATUS "  Data Directory:      %LOCALAPPDATA%\\Dracula (Clean Git repo)")
message(STATUS "────────────────────────────────────────────────────────────────────")
message(STATUS "")
