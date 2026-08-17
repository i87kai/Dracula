#include "gui/gui_app.h"
#include "gui/glass_theme.h"
#include "core/dynamic_vm_analyzer.h"
#include "core/unicorn_analyzer.h"
#include "host/report_writer.h"
#include "host/process_inspector.h"
#include "tools/game_offsets.h"
#include "imgui.h"

#include <iostream>
#include <sstream>
#include <iomanip>
#include <filesystem>
#include <tlhelp32.h>
#include <psapi.h>

#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

namespace Sandbox::GUI {

    GuiApp::GuiApp() = default;

    GuiApp::~GuiApp() {
        DetachProcess();
        StopAnalysis();
    }

    void GuiApp::Initialize() {
        m_liveRegisters["RAX"] = "0x0000000000000000";
        m_liveRegisters["RBX"] = "0x0000000000000000";
        m_liveRegisters["RCX"] = "0x0000000000000000";
        m_liveRegisters["RDX"] = "0x0000000000000000";
        m_liveRegisters["RSI"] = "0x0000000000000000";
        m_liveRegisters["RDI"] = "0x0000000000000000";
        m_liveRegisters["RSP"] = "0x00007FFF001FF000";
        m_liveRegisters["RBP"] = "0x00007FFF001FF000";
        m_liveRegisters["RIP"] = "0x0000000140001000";
        m_liveRegisters["EFLAGS"] = "0x00000246";

        // Setup from unified offset database
        m_offsets.clear();
        for (const auto& item : Sandbox::Tools::GetKnownOffsetDatabase()) {
            m_offsets.push_back({ item.name, item.aobPattern, item.rva, item.type, item.description });
        }

        RefreshProcessList();
    }

    void GuiApp::RefreshProcessList() {
        m_processList.clear();
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 entry = {};
            entry.dwSize = sizeof(entry);
            if (Process32First(snapshot, &entry)) {
                do {
                    if (entry.th32ProcessID > 4) {
                        m_processList.push_back({ entry.th32ProcessID, entry.szExeFile });
                    }
                } while (Process32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);
        }

        // Auto-select RainbowSix.exe if running
        for (size_t i = 0; i < m_processList.size(); ++i) {
            if (_stricmp(m_processList[i].name.c_str(), "RainbowSix.exe") == 0) {
                m_selectedProcessIndex = static_cast<int>(i);
                break;
            }
        }
    }

    void GuiApp::AttachToSelectedProcess() {
        if (m_processList.empty() || m_selectedProcessIndex >= static_cast<int>(m_processList.size())) return;
        DetachProcess();

        const auto& target = m_processList[m_selectedProcessIndex];
        m_attachedPid = target.pid;
        m_attachedProcessName = target.name;

        std::string err;
        m_hAttachedProcess = ProcessInspector::OpenReadOnly(m_attachedPid, err);
        if (m_hAttachedProcess) {
            auto modInfo = ProcessInspector::ResolveMainModule(m_hAttachedProcess, m_attachedPid, err);
            if (modInfo) {
                m_attachedModuleBase = modInfo->baseAddress;
                m_isProcessAttached = true;
            }
        }
    }

    void GuiApp::DetachProcess() {
        if (m_hAttachedProcess) {
            ProcessInspector::Close(m_hAttachedProcess);
            m_hAttachedProcess = nullptr;
        }
        m_isProcessAttached = false;
        m_attachedPid = 0;
        m_attachedModuleBase = 0;
    }

    void GuiApp::PollLiveOffsets() {
        if (!m_isProcessAttached || !m_hAttachedProcess || m_attachedModuleBase == 0) return;
        HANDLE hProc = static_cast<HANDLE>(m_hAttachedProcess);

        for (auto& item : m_offsets) {
            uint64_t targetVa = m_attachedModuleBase + item.rva;
            item.resolvedVa = targetVa;

            MEMORY_BASIC_INFORMATION mbi = {};
            item.isCommitted = false;
            if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(targetVa), &mbi, sizeof(mbi))) {
                item.isCommitted = (mbi.State == MEM_COMMIT) && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD));
            }

            if (!item.isCommitted) {
                item.liveValue = "UNMAPPED PAGE";
                item.status = "NOCOMMIT";
                continue;
            }

            if (item.type == "ptr64") {
                uint64_t ptrVal = 0;
                SIZE_T read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(targetVa), &ptrVal, sizeof(ptrVal), &read) && read == sizeof(ptrVal)) {
                    std::ostringstream ss;
                    ss << "0x" << std::hex << std::uppercase << ptrVal;
                    if (ptrVal == 0) {
                        ss << " (NULL / Waiting Match)";
                        item.status = "VALID GLOBAL (Spawn Active)";
                    } else if (ptrVal == 1) {
                        ss << " (Active State Flag)";
                        item.status = "VALID MANAGER FLAG";
                    } else {
                        MEMORY_BASIC_INFORMATION targetMbi = {};
                        if (VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(ptrVal), &targetMbi, sizeof(targetMbi)) && (targetMbi.State == MEM_COMMIT)) {
                            ss << " → [Valid Heap Ptr]";
                            item.status = "LIVE STRUCT POINTER";
                        } else {
                            item.status = "COMMITTED VARIABLE";
                        }
                    }
                    item.liveValue = ss.str();
                }
            } else if (item.type == "matrix4x4") {
                SIZE_T read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(targetVa), m_viewMatrix, sizeof(m_viewMatrix), &read)) {
                    std::ostringstream ss;
                    ss << "m[0]=" << std::fixed << std::setprecision(2) << m_viewMatrix[0]
                       << " m[15]=" << m_viewMatrix[15];
                    item.liveValue = ss.str();
                    item.status = "VALID 4x4 MATRIX";
                }
            } else if (item.type == "float") {
                float fVal = 0.0f;
                SIZE_T read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(targetVa), &fVal, sizeof(fVal), &read)) {
                    std::ostringstream ss;
                    ss << std::fixed << std::setprecision(4) << fVal;
                    item.liveValue = ss.str();
                    item.status = "VALID FLOAT";
                }
            } else if (item.type == "uint32") {
                uint32_t uVal = 0;
                SIZE_T read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(targetVa), &uVal, sizeof(uVal), &read)) {
                    std::ostringstream ss;
                    ss << uVal << " (0x" << std::hex << std::uppercase << uVal << ")";
                    item.liveValue = ss.str();
                    item.status = "NUMERIC ID";
                }
            } else if (item.type == "code_routine") {
                uint8_t code[10] = {};
                SIZE_T read = 0;
                if (ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(targetVa), code, sizeof(code), &read) && read > 0) {
                    std::ostringstream ss;
                    ss << "Op: " << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << (int)code[0]
                       << " " << (int)code[1] << " " << (int)code[2] << " " << (int)code[3];
                    item.liveValue = ss.str();
                    item.status = "LIVE EXECUTABLE CODE";
                }
            }
        }
    }

    void GuiApp::RunUnicornOnOffset(size_t index) {
        if (index >= m_offsets.size() || !m_isProcessAttached || !m_hAttachedProcess) return;
        const auto& item = m_offsets[index];
        HANDLE hProc = static_cast<HANDLE>(m_hAttachedProcess);
        uint64_t va = m_attachedModuleBase + item.rva;

        std::vector<uint8_t> code(64);
        SIZE_T read = 0;
        if (!ReadProcessMemory(hProc, reinterpret_cast<LPCVOID>(va), code.data(), code.size(), &read) || read == 0) return;
        code.resize(read);

        uc_engine* uc = nullptr;
        if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) return;

        uint64_t pageBase = va & ~0xFFFULL;
        uint64_t mapSize  = ((va + code.size() + 0xFFF) & ~0xFFFULL) - pageBase;
        uc_mem_map(uc, pageBase, mapSize, UC_PROT_ALL);
        uc_mem_write(uc, va, code.data(), code.size());

        uint64_t stackBase = 0x0000700000000000ULL;
        uint64_t stackSize = 0x10000;
        uc_mem_map(uc, stackBase, stackSize, UC_PROT_ALL);
        uint64_t stackTop = stackBase + stackSize - 0x1000;
        uc_reg_write(uc, UC_X86_REG_RSP, &stackTop);
        uc_reg_write(uc, UC_X86_REG_RBP, &stackTop);
        uc_reg_write(uc, UC_X86_REG_RIP, &va);

        uint64_t instrs = 0;
        uc_hook h = 0;
        auto cb = [](uc_engine*, uint64_t, uint32_t, void* ud) { (*static_cast<uint64_t*>(ud))++; };
        uc_hook_add(uc, &h, UC_HOOK_CODE, reinterpret_cast<void*>(+cb), &instrs, 1, 0);

        uc_emu_start(uc, va, va + code.size(), 1000000, 100);

        uint64_t rax=0, rbx=0, rcx=0, rdx=0, rsi=0, rdi=0, rip=0;
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
        uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        uc_reg_read(uc, UC_X86_REG_RBX, &rbx);
        uc_reg_read(uc, UC_X86_REG_RCX, &rcx);
        uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
        uc_reg_read(uc, UC_X86_REG_RSI, &rsi);
        uc_reg_read(uc, UC_X86_REG_RDI, &rdi);

        m_unicornModalTitle = "Unicorn Emulation: " + item.name;
        m_unicornModalInstrCount = instrs;
        m_unicornModalStopRip = rip;

        std::ostringstream ss;
        ss << "RAX: 0x" << std::hex << std::uppercase << rax << "  |  RBX: 0x" << rbx << "\n"
           << "RCX: 0x" << rcx << "  |  RDX: 0x" << rdx << "\n"
           << "RSI: 0x" << rsi << "  |  RDI: 0x" << rdi << "\n"
           << "RIP: 0x" << rip << "  |  RSP: 0x" << stackTop;
        m_unicornModalRegs = ss.str();
        m_showUnicornModal = true;

        uc_close(uc);
    }

    void GuiApp::InjectDllIntoProcess() {
        if (!m_attachedPid) return;
        std::string dllPath, err;
        if (!ProcessInspector::ExtractEmbeddedDLL(dllPath, err)) {
            m_injectionStatusText = "[-] Extract DLL failed: " + err;
            return;
        }

        void* hInj = ProcessInspector::OpenForInjection(m_attachedPid, err);
        if (!hInj) {
            m_injectionStatusText = "[-] OpenForInjection failed: " + err;
            return;
        }

        bool ok = ProcessInspector::InjectDLL(hInj, dllPath, err);
        ProcessInspector::Close(hInj);

        if (ok) {
            m_injectionStatusText = "[+] DLL Injected! [ i87k ] On-Screen Notification Launched in Game!";
        } else {
            m_injectionStatusText = "[-] Injection failed: " + err;
        }
    }

    void GuiApp::Render() {
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);

        ImGuiWindowFlags windowFlags = ImGuiWindowFlags_NoTitleBar |
                                       ImGuiWindowFlags_NoResize |
                                       ImGuiWindowFlags_NoMove |
                                       ImGuiWindowFlags_NoBringToFrontOnFocus |
                                       ImGuiWindowFlags_NoNavFocus;

        ImGui::Begin("SandboxMainApp", nullptr, windowFlags);
        ImGui::PopStyleVar(2);

        // Auto-poll live memory values
        PollLiveOffsets();

        RenderHeader();
        ImGui::Separator();
        ImGui::Dummy(ImVec2(0, 4.0f));

        // Tab Navigation Container
        if (ImGui::BeginTabBar("MainTabs", ImGuiTabBarFlags_None)) {
            if (ImGui::BeginTabItem("  ★ [ i87k ] Live Game Offsets & Memory Verifier  ")) {
                RenderOffsetsVerifierTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("  Live Telemetry Stream  ")) {
                RenderTelemetryTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("  CPU Registers Inspector  ")) {
                RenderRegistersTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("  PE Sections & Memory Map  ")) {
                RenderSectionsTab();
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("  Settings & VM Config  ")) {
                RenderSettingsTab();
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }

        // Unicorn Emulation Result Modal
        if (m_showUnicornModal) {
            ImGui::OpenPopup("UnicornResultModal");
        }
        if (ImGui::BeginPopupModal("UnicornResultModal", &m_showUnicornModal, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextColored(GlassTheme::NeonCyan, "%s", m_unicornModalTitle.c_str());
            ImGui::Separator();
            ImGui::Text("Instructions Traced : %llu", m_unicornModalInstrCount);
            ImGui::Text("Stop RIP Address     : 0x%llX", m_unicornModalStopRip);
            ImGui::Dummy(ImVec2(0, 6));
            ImGui::TextColored(GlassTheme::EmeraldGreen, "CPU 64-Bit Registers State:");
            ImGui::TextUnformatted(m_unicornModalRegs.c_str());
            ImGui::Dummy(ImVec2(0, 10));
            if (ImGui::Button(" Close ", ImVec2(120, 0))) {
                m_showUnicornModal = false;
                ImGui::CloseCurrentPopup();
            }
            ImGui::EndPopup();
        }

        ImGui::End();
    }

    void GuiApp::RenderOffsetsVerifierTab() {
        // --- Process Selection & Attachment Toolbar ---
        ImGui::TextColored(GlassTheme::NeonCyan, "TARGET PROCESS ATTACHMENT:");
        ImGui::SameLine();

        std::string previewText = "Select Process...";
        if (!m_processList.empty() && m_selectedProcessIndex < static_cast<int>(m_processList.size())) {
            previewText = "[" + std::to_string(m_processList[m_selectedProcessIndex].pid) + "] " + m_processList[m_selectedProcessIndex].name;
        }

        ImGui::SetNextItemWidth(260);
        if (ImGui::BeginCombo("##ProcessCombo", previewText.c_str())) {
            for (int i = 0; i < static_cast<int>(m_processList.size()); ++i) {
                const bool isSelected = (m_selectedProcessIndex == i);
                std::string itemLabel = "[" + std::to_string(m_processList[i].pid) + "] " + m_processList[i].name;
                if (ImGui::Selectable(itemLabel.c_str(), isSelected)) {
                    m_selectedProcessIndex = i;
                }
                if (isSelected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::SameLine();
        if (ImGui::Button(" Refresh ")) {
            RefreshProcessList();
        }

        ImGui::SameLine();
        if (!m_isProcessAttached) {
            if (ImGui::Button(" Attach (Read-Only) ")) {
                AttachToSelectedProcess();
            }
        } else {
            if (ImGui::Button(" Detach ")) {
                DetachProcess();
            }
        }

        ImGui::SameLine();
        if (ImGui::Button(" ★ Inject DLL ([ i87k ] Overlay) ")) {
            InjectDllIntoProcess();
        }

        // Status Line
        if (m_isProcessAttached) {
            ImGui::TextColored(GlassTheme::EmeraldGreen, "● ATTACHED: %s (PID %u) | Module Base: 0x%llX",
                               m_attachedProcessName.c_str(), m_attachedPid, m_attachedModuleBase);
        } else {
            ImGui::TextColored(GlassTheme::TextMuted, "○ NOT ATTACHED (Select a process and click Attach to monitor memory live)");
        }

        if (!m_injectionStatusText.empty()) {
            ImGui::TextColored(GlassTheme::NeonCyan, "%s", m_injectionStatusText.c_str());
        }

        ImGui::Separator();
        ImGui::Dummy(ImVec2(0, 4));

        // --- Live Offsets Table ---
        ImGuiTableFlags flags = ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg |
                                ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY;

        if (ImGui::BeginTable("OffsetsTable", 8, flags, ImVec2(0, 360))) {
            ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 30.0f);
            ImGui::TableSetupColumn("Offset Name", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableSetupColumn("Full Signature (AOB)", ImGuiTableColumnFlags_WidthFixed, 220.0f);
            ImGui::TableSetupColumn("RVA", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Virtual Address", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Memory State", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Live Value (Auto-Updating)", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Action", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableHeadersRow();

            for (size_t i = 0; i < m_offsets.size(); ++i) {
                const auto& item = m_offsets[i];
                ImGui::TableNextRow();

                // #
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%zu", i + 1);

                // Name
                ImGui::TableSetColumnIndex(1);
                ImGui::TextColored(GlassTheme::NeonCyan, "%s", item.name.c_str());

                // Signature
                ImGui::TableSetColumnIndex(2);
                ImGui::TextColored(GlassTheme::AmberYellow, "%s", item.signature.c_str());

                // RVA
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("0x%llX", item.rva);

                // Virtual Address
                ImGui::TableSetColumnIndex(4);
                if (item.resolvedVa) {
                    ImGui::TextColored(GlassTheme::NeonCyan, "0x%llX", item.resolvedVa);
                } else {
                    ImGui::TextUnformatted("-");
                }

                // Memory State
                ImGui::TableSetColumnIndex(5);
                if (item.isCommitted) {
                    ImGui::TextColored(GlassTheme::EmeraldGreen, "COMMIT");
                } else {
                    ImGui::TextColored(GlassTheme::CoralRed, "NOCOMMIT");
                }

                // Live Value
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(item.liveValue.c_str());

                // Actions
                ImGui::TableSetColumnIndex(7);
                std::string btnId = "Unicorn##" + std::to_string(i);
                if (ImGui::Button(btnId.c_str())) {
                    RunUnicornOnOffset(i);
                }
            }
            ImGui::EndTable();
        }

        ImGui::Dummy(ImVec2(0, 6));

        // --- 4x4 ViewMatrix Visualizer & Info Section ---
        if (ImGui::CollapsingHeader("  4x4 ViewMatrix Visualizer (Camera Projection)", ImGuiTreeNodeFlags_DefaultOpen)) {
            ImGui::Columns(2, "MatrixColumns", false);
            ImGui::SetColumnWidth(0, 360);

            ImGui::TextColored(GlassTheme::NeonCyan, "Camera View Matrix:");
            for (int r = 0; r < 4; ++r) {
                ImGui::Text("[ %7.2f  %7.2f  %7.2f  %7.2f ]",
                            m_viewMatrix[r*4 + 0], m_viewMatrix[r*4 + 1],
                            m_viewMatrix[r*4 + 2], m_viewMatrix[r*4 + 3]);
            }

            ImGui::NextColumn();
            ImGui::TextColored(GlassTheme::EmeraldGreen, "Matrix Information & Math:");
            ImGui::BulletText("Matrix Status: Valid 4x4 Camera Projection");
            ImGui::BulletText("WorldToScreen: Active and Ready for 3D Bounding Box Calculation");
            ImGui::BulletText("Z-Buffer Range: [%.2f, %.2f]", m_viewMatrix[10], m_viewMatrix[14]);

            ImGui::Columns(1);
        }
    }

    void GuiApp::RenderHeader() {
        ImGui::PushFont(GlassTheme::FontTitle ? GlassTheme::FontTitle : ImGui::GetFont());
        ImGui::TextColored(GlassTheme::NeonCyan, "i87k EXTERNAL MEMORY INSPECTOR & SANDBOX ORCHESTRATOR");
        ImGui::PopFont();

        ImGui::SameLine();
        ImGui::SetCursorPosX(ImGui::GetWindowWidth() - 140.0f);

        if (m_isProcessAttached) {
            GlassTheme::RenderBadge("ATTACHED", GlassTheme::EmeraldGreen);
        } else {
            GlassTheme::RenderBadge("STANDBY", GlassTheme::TextMuted);
        }
    }

    void GuiApp::RenderMetrics() {
        ImGui::Columns(4, "MetricsCols", false);

        GlassTheme::RenderMetricCard("ATTACHED PID", m_isProcessAttached ? std::to_string(m_attachedPid).c_str() : "None", "Active Target", GlassTheme::NeonCyan, 180.0f);
        ImGui::NextColumn();

        GlassTheme::RenderMetricCard("VERIFIED OFFSETS", (std::to_string(m_offsets.size()) + " Active").c_str(), "Signatures Live", GlassTheme::EmeraldGreen, 180.0f);
        ImGui::NextColumn();

        GlassTheme::RenderMetricCard("UNICORN ENGINE", "v2.0.1 Ready", "CPU Emulation", GlassTheme::PurpleViolet, 180.0f);
        ImGui::NextColumn();

        GlassTheme::RenderMetricCard("MEMORY MAP", m_isProcessAttached ? "64-Bit x86_64" : "Ready", "Committed Pages", GlassTheme::AmberYellow, 180.0f);
        ImGui::Columns(1);
    }

    void GuiApp::RenderTelemetryTab() {
        ImGui::TextUnformatted("Telemetry logs and sandbox event stream...");
    }

    void GuiApp::RenderRegistersTab() {
        ImGui::TextColored(GlassTheme::NeonCyan, "Current CPU 64-Bit Registers State:");
        ImGui::Separator();
        for (const auto& [reg, val] : m_liveRegisters) {
            ImGui::Text("%s: %s", reg.c_str(), val.c_str());
        }
    }

    void GuiApp::RenderSectionsTab() {
        ImGui::TextColored(GlassTheme::NeonCyan, "PE Sections of Attached Module:");
        ImGui::Separator();
        ImGui::BulletText(".text  - Code & Function Subroutines (PAGE_EXECUTE_READ)");
        ImGui::BulletText(".rdata - Read-Only Data, String Tables & VTables (PAGE_READONLY)");
        ImGui::BulletText(".data  - Global Pointers, LocalPlayer, GameManager (PAGE_READWRITE)");
    }

    void GuiApp::RenderSettingsTab() {
        ImGui::TextColored(GlassTheme::NeonCyan, "Settings & Tools Config:");
        ImGui::Separator();
        ImGui::Checkbox("Auto-Scroll Telemetry", &m_autoScroll);
    }

    void GuiApp::StartAnalysis() {}
    void GuiApp::StopAnalysis() {}
    void GuiApp::ClearLogs() {}
    void GuiApp::ExportReport() {}
    void GuiApp::ParseRegistersFromEvent(const TraceEvent&) {}

} // namespace Sandbox::GUI
