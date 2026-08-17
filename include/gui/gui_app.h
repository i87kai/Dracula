#pragma once

#include "common/types.h"
#include "core/analyzer_interface.h"
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <memory>
#include <thread>
#include <atomic>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif

namespace Sandbox::GUI {

    enum class AppState {
        Idle,
        Running,
        Completed,
        Error
    };

    struct PESectionInfo {
        std::string name;
        uint64_t virtualAddress = 0;
        uint32_t virtualSize = 0;
        uint32_t rawSize = 0;
    };

    struct GuiOffsetEntry {
        std::string name;
        std::string signature;
        uint64_t    rva = 0;
        std::string type;           // "ptr64", "matrix4x4", "code_routine", "float", "uint32"
        std::string description;
        std::string liveValue = "N/A";
        std::string status = "UNCHECKED";
        bool        isCommitted = false;
        uint64_t    resolvedVa = 0;
    };

    struct ProcessItem {
        uint32_t pid = 0;
        std::string name;
    };

    class GuiApp {
    public:
        GuiApp();
        ~GuiApp();

        // Initialize state and load default configs
        void Initialize();

        // Render full UI frame
        void Render();

    private:
        // UI Sections
        void RenderHeader();
        void RenderMetrics();
        void RenderTelemetryTab();
        void RenderOffsetsVerifierTab();
        void RenderRegistersTab();
        void RenderSectionsTab();
        void RenderSettingsTab();

        // Live Process Operations
        void RefreshProcessList();
        void AttachToSelectedProcess();
        void DetachProcess();
        void PollLiveOffsets();
        void RunUnicornOnOffset(size_t index);
        void InjectDllIntoProcess();

        // Analysis Actions
        void StartAnalysis();
        void StopAnalysis();
        void ClearLogs();
        void ExportReport();
        void ParseRegistersFromEvent(const TraceEvent& evt);

        // State variables
        AppState m_state = AppState::Idle;
        char m_targetExeBuffer[512] = "RainbowSix.exe";
        int m_selectedEngine = 1; // 0 = VM, 1 = Unicorn
        bool m_autoScroll = true;
        char m_searchFilter[128] = "";
        int m_selectedCategoryFilter = 0;

        // Process Attachment State
        std::vector<ProcessItem> m_processList;
        int m_selectedProcessIndex = 0;
        uint32_t m_attachedPid = 0;
        std::string m_attachedProcessName;
        uint64_t m_attachedModuleBase = 0;
        void* m_hAttachedProcess = nullptr;
        bool m_isProcessAttached = false;
        std::string m_injectionStatusText;

        // Live Offsets & Verification
        std::vector<GuiOffsetEntry> m_offsets;
        float m_viewMatrix[16] = {};
        char m_hexViewAddress[64] = "0x1177A350";
        uint8_t m_hexViewBytes[128] = {};
        bool m_hasHexData = false;

        // Unicorn Live Modal state
        bool m_showUnicornModal = false;
        std::string m_unicornModalTitle;
        std::string m_unicornModalRegs;
        uint64_t m_unicornModalInstrCount = 0;
        uint64_t m_unicornModalStopRip = 0;

        // Configurations
        TraceOptions m_options;
        VMConfig m_vmConfig;

        // Telemetry & Statistics
        std::vector<TraceEvent> m_events;
        size_t m_instructionsTraced = 0;
        size_t m_processesCreated = 0;
        size_t m_filesModified = 0;
        size_t m_networkConnections = 0;

        // CPU & Disassembly state
        std::map<std::string, std::string> m_liveRegisters;
        std::vector<PESectionInfo> m_peSections;
        uint64_t m_imageEntry = 0;
        uint64_t m_imageBase = 0;

        // Background worker
        std::unique_ptr<IAnalyzer> m_analyzer;
        std::thread m_workerThread;
        std::atomic<bool> m_isAnalyzing{false};
        mutable std::mutex m_eventMutex;
    };

} // namespace Sandbox::GUI
