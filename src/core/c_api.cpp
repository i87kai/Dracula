#include "core/c_api.h"
#include "core/dynamic_vm_analyzer.h"
#include "core/unicorn_analyzer.h"
#include "host/report_writer.h"
#include <cstring>
#include <string>
#include <memory>

static Sandbox::VMConfig ConvertConfig(const CSandboxConfig* c_cfg, Sandbox::TraceOptions& outOptions) {
    Sandbox::VMConfig vm;
    if (c_cfg) {
        if (c_cfg->vm_name) vm.vmName = c_cfg->vm_name;
        if (c_cfg->snapshot_name) vm.snapshotName = c_cfg->snapshot_name;
        if (c_cfg->guest_user) vm.guestUsername = c_cfg->guest_user;
        if (c_cfg->guest_password) vm.guestPassword = c_cfg->guest_password;
        if (c_cfg->guest_target_dir) vm.guestTargetDir = c_cfg->guest_target_dir;
        if (c_cfg->host_port > 0) vm.hostPort = c_cfg->host_port;
        vm.headlessMode = c_cfg->headless;

        outOptions.monitorConsoleOutput = c_cfg->monitor_stdout;
        outOptions.monitorProcesses = c_cfg->monitor_processes;
        outOptions.monitorFiles = c_cfg->monitor_files;
        outOptions.monitorRegistry = c_cfg->monitor_registry;
        outOptions.monitorNetwork = c_cfg->monitor_network;
        outOptions.executionTimeoutSeconds = c_cfg->timeout_seconds > 0 ? c_cfg->timeout_seconds : 60;
    }
    return vm;
}

SandboxAnalyzerHandle sandbox_create_vm_analyzer(const CSandboxConfig* config) {
    Sandbox::TraceOptions options;
    Sandbox::VMConfig vmConfig = ConvertConfig(config, options);

    auto analyzer = new Sandbox::DynamicVMAnalyzer();
    analyzer->Initialize(vmConfig, options);
    return static_cast<SandboxAnalyzerHandle>(analyzer);
}

SandboxAnalyzerHandle sandbox_create_unicorn_analyzer(const CSandboxConfig* config) {
    Sandbox::TraceOptions options;
    Sandbox::VMConfig vmConfig = ConvertConfig(config, options);

    auto analyzer = new Sandbox::UnicornAnalyzer();
    analyzer->Initialize(vmConfig, options);
    return static_cast<SandboxAnalyzerHandle>(analyzer);
}

void sandbox_set_event_callback(SandboxAnalyzerHandle handle, CSandboxEventCallback callback, void* user_data) {
    if (!handle) return;
    auto analyzer = static_cast<Sandbox::IAnalyzer*>(handle);

    if (callback) {
        analyzer->SetEventCallback([callback, user_data](const Sandbox::TraceEvent& evt) {
            CSandboxEvent c_evt;
            c_evt.event_type = static_cast<uint32_t>(evt.type);
            c_evt.timestamp_ms = evt.timestampMs;
            c_evt.category = evt.category.c_str();
            c_evt.message = evt.message.c_str();
            c_evt.details = evt.details.c_str();
            callback(&c_evt, user_data);
        });
    } else {
        analyzer->SetEventCallback(nullptr);
    }
}

bool sandbox_run_analysis(SandboxAnalyzerHandle handle, const char* target_exe_path) {
    if (!handle || !target_exe_path) return false;
    auto analyzer = static_cast<Sandbox::IAnalyzer*>(handle);
    return analyzer->RunAnalysis(target_exe_path);
}

void sandbox_stop_analysis(SandboxAnalyzerHandle handle) {
    if (!handle) return;
    auto analyzer = static_cast<Sandbox::IAnalyzer*>(handle);
    analyzer->StopAnalysis();
}

const char* sandbox_get_report_text(SandboxAnalyzerHandle handle) {
    if (!handle) return nullptr;
    auto analyzer = static_cast<Sandbox::IAnalyzer*>(handle);
    Sandbox::AnalysisReport rep = analyzer->GetReport();
    std::string text = Sandbox::ReportWriter::GenerateTextReport(rep);

    char* result = new char[text.length() + 1];
    std::memcpy(result, text.c_str(), text.length() + 1);
    return result;
}

void sandbox_free_string(const char* str) {
    delete[] str;
}

void sandbox_destroy_analyzer(SandboxAnalyzerHandle handle) {
    if (!handle) return;
    auto analyzer = static_cast<Sandbox::IAnalyzer*>(handle);
    delete analyzer;
}
