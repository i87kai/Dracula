#pragma once

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _WIN32
    #ifdef SANDBOX_CORE_EXPORTS
        #define SANDBOX_API __declspec(dllexport)
    #else
        #define SANDBOX_API
    #endif
#else
    #define SANDBOX_API
#endif

// Opaque handle to an analyzer instance
typedef void* SandboxAnalyzerHandle;

// C-compatible event structure for FFI (Tauri / Rust)
typedef struct {
    uint32_t event_type;
    uint64_t timestamp_ms;
    const char* category;
    const char* message;
    const char* details;
} CSandboxEvent;

// C-compatible callback definition
typedef void (*CSandboxEventCallback)(const CSandboxEvent* event, void* user_data);

// C-compatible configuration
typedef struct {
    const char* vm_name;
    const char* snapshot_name;
    const char* guest_user;
    const char* guest_password;
    const char* guest_target_dir;
    uint16_t host_port;
    bool headless;
    
    // Trace filters
    bool monitor_stdout;
    bool monitor_processes;
    bool monitor_files;
    bool monitor_registry;
    bool monitor_network;
    uint32_t timeout_seconds;
} CSandboxConfig;

// Initialize Dynamic VM Analyzer instance
SANDBOX_API SandboxAnalyzerHandle sandbox_create_vm_analyzer(const CSandboxConfig* config);

// Initialize Unicorn Static/Emulation Analyzer instance (TODO skeleton)
SANDBOX_API SandboxAnalyzerHandle sandbox_create_unicorn_analyzer(const CSandboxConfig* config);

// Set real-time event callback for GUI / CLI integration
SANDBOX_API void sandbox_set_event_callback(SandboxAnalyzerHandle handle, CSandboxEventCallback callback, void* user_data);

// Start analysis on target executable (Blocking or run in thread)
SANDBOX_API bool sandbox_run_analysis(SandboxAnalyzerHandle handle, const char* target_exe_path);

// Stop or interrupt running analysis
SANDBOX_API void sandbox_stop_analysis(SandboxAnalyzerHandle handle);

// Get formatted analysis report as a text string (Caller must free with sandbox_free_string)
SANDBOX_API const char* sandbox_get_report_text(SandboxAnalyzerHandle handle);

// Free string allocated by Sandbox library
SANDBOX_API void sandbox_free_string(const char* str);

// Destroy analyzer instance
SANDBOX_API void sandbox_destroy_analyzer(SandboxAnalyzerHandle handle);

#ifdef __cplusplus
}
#endif
