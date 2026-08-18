#include "utr/function_intelligence.h"
#include "utr/managed_backend.h"

#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cmath>

namespace Dracula {
namespace UTR {

    static std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else o << c;
        }
        return o.str();
    }

    void FunctionIntelligenceManager::IndexStaticFunctions(
        const std::vector<FunctionGraph>& graphs,
        const std::vector<XRefEntry>& xrefs,
        const std::vector<ExtractedString>& strings,
        const std::vector<ImportEntry>& imports,
        const std::string& moduleName)
    {
        for (const auto& g : graphs) {
            FunctionIntelligenceItem item;
            item.rva = g.entryRva;
            item.address = g.entryAddress;
            item.moduleName = moduleName.empty() ? "main" : moduleName;
            item.name = g.name.empty() ? ("sub_" + std::to_string(g.entryRva)) : g.name;
            item.instructionCount = g.totalInstructions;
            item.basicBlockCount = static_cast<uint32_t>(g.blocks.size());

            // Estimate cyclomatic complexity: E - N + 2P
            uint32_t edges = 0;
            for (const auto& kv : g.blocks) {
                edges += static_cast<uint32_t>(kv.second.successorAddresses.size());
            }
            uint32_t nodes = static_cast<uint32_t>(g.blocks.size());
            item.cyclomaticComplexity = (edges >= nodes) ? (edges - nodes + 2) : 1;

            // Correlate XRefs
            for (const auto& x : xrefs) {
                if (x.toRva == g.entryRva && (x.type == XRefType::CodeCall || x.type == XRefType::CodeJump)) {
                    item.callerCount++;
                }
                if (x.fromRva >= g.entryRva && x.fromRva < g.entryRva + g.totalInstructions * 4) {
                    if (x.type == XRefType::CodeCall || x.type == XRefType::CodeJump) {
                        item.calleeCount++;
                    }
                    if (x.type == XRefType::StringRef) {
                        item.stringCount++;
                        item.referencedStrings.push_back(x.targetName);
                    }
                    if (x.type == XRefType::ImportCall) {
                        item.calledApis.push_back(x.targetName);
                    }
                }
            }

            // Check dangerous APIs
            static const std::set<std::string> kHighRiskApis = {
                "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
                "NtUnmapViewOfSection", "QueueUserAPC", "SetWindowsHookExA", "SetWindowsHookExW",
                "InternetOpenA", "HttpSendRequestA", "WinExec", "ShellExecuteA"
            };

            for (const auto& api : item.calledApis) {
                if (kHighRiskApis.find(api) != kHighRiskApis.end()) {
                    item.callsHighRiskApis = true;
                    break;
                }
            }

            m_functions.push_back(item);
        }

        ComputeRanking();
    }

    void FunctionIntelligenceManager::IndexManagedMethods(
        const std::vector<ManagedMethodInfo>& methods,
        const std::vector<ManagedPInvokeInfo>& pinvokes,
        const std::string& assemblyName)
    {
        (void)pinvokes;
        for (const auto& m : methods) {
            FunctionIntelligenceItem item;
            item.name = m.type + "." + m.method;
            item.moduleName = assemblyName.empty() ? "ManagedAssembly" : assemblyName;
            item.instructionCount = m.ilSize;
            item.basicBlockCount = (m.ilSize > 20) ? (m.ilSize / 15 + 1) : 1;
            item.cyclomaticComplexity = (m.ilSize > 50) ? 4 : 1;

            uint64_t rvaVal = 0;
            try {
                if (m.rva.rfind("0x", 0) == 0 || m.rva.rfind("0X", 0) == 0) {
                    rvaVal = std::stoull(m.rva.substr(2), nullptr, 16);
                } else if (!m.rva.empty()) {
                    rvaVal = std::stoull(m.rva);
                }
            } catch (...) {}
            item.rva = rvaVal;

            item.tags.push_back("Managed");
            item.tags.push_back(".NET");
            item.tags.push_back(m.type);

            if (m.isPInvoke) {
                item.tags.push_back("PInvoke");
                std::string api = m.pinvokeDll + "!" + m.pinvokeEntryPoint;
                item.calledApis.push_back(api);
                item.callsHighRiskApis = true;
                item.interestScore += 35.0;
                item.interestReasoning += "[P/Invoke Native Interop: " + api + "] ";
            }

            if (m.ilSize > 100) {
                item.interestScore += 20.0;
                item.interestReasoning += "[Substantial IL Body (" + std::to_string(m.ilSize) + " bytes)] ";
            }

            item.truthLevel = EvidenceTruthLevel::Observed;
            item.confidence = FindingConfidence::High;
            m_functions.push_back(item);
        }

        ComputeRanking();
    }

    void FunctionIntelligenceManager::CorrelateRuntimeExecutions(
        const std::vector<uint64_t>& executedAddresses,
        const std::vector<HleCallRecord>& hleCalls)
    {
        for (auto& fn : m_functions) {
            for (uint64_t addr : executedAddresses) {
                if (addr == fn.address || addr == fn.rva) {
                    fn.wasExecutedInRuntime = true;
                    fn.runtimeExecutionCount++;
                    fn.executionCount++;
                }
            }
            for (const auto& hle : hleCalls) {
                if (hle.callerRva == fn.rva || hle.callerAddress == fn.address) {
                    fn.apiEventsTriggered++;
                }
            }
        }

        ComputeRanking();
    }

    void FunctionIntelligenceManager::AddFunction(const FunctionIntelligenceItem& fn) {
        m_functions.push_back(fn);
        ComputeRanking();
    }

    void FunctionIntelligenceManager::ComputeRanking(const FunctionRankingWeights& weights) {
        for (auto& fn : m_functions) {
            double score = 0.0;
            std::string reason;

            // 1. High Risk APIs (max 30 pts)
            if (fn.callsHighRiskApis) {
                score += weights.weightRiskApis;
                reason += "[High-Risk APIs] ";
            } else if (!fn.calledApis.empty()) {
                score += std::min(15.0, static_cast<double>(fn.calledApis.size()) * 3.0);
                reason += "[API References] ";
            }

            // 2. Runtime Execution (max 25 pts)
            if (fn.executionCount > 0 || fn.wasExecutedInRuntime) {
                score += weights.weightRuntimeExecution;
                reason += "[Runtime Executed] ";
            }

            // 3. Runtime Transformations (max 25 pts)
            if (fn.triggeredRuntimeTransformation) {
                score += weights.weightMemoryTransformation;
                reason += "[Memory Transformation Trigger] ";
            }

            // 4. Control Flow Complexity (max 10 pts)
            if (fn.cyclomaticComplexity > 10) {
                score += weights.weightControlFlowComplexity;
                reason += "[High Cyclomatic Complexity] ";
            } else if (fn.cyclomaticComplexity > 4) {
                score += weights.weightControlFlowComplexity * 0.5;
            }

            // 5. Instruction Count (max 15 pts)
            if (fn.instructionCount > 100) {
                score += 15.0;
                reason += "[Substantial Body (" + std::to_string(fn.instructionCount) + " instrs)] ";
            } else if (fn.instructionCount > 30) {
                score += 5.0;
            }

            // 6. Cross-reference centrality (max 10 pts)
            if (fn.callerCount > 5 || fn.calleeCount > 10) {
                score += weights.weightXrefCentrality;
                reason += "[Central Call Graph Node] ";
            }

            fn.interestScore = std::min(100.0, score);
            fn.interestReasoning = reason.empty() ? "Standard function" : reason;
        }

        // Sort descending by interest score
        std::sort(m_functions.begin(), m_functions.end(), [](const FunctionIntelligenceItem& a, const FunctionIntelligenceItem& b) {
            return a.interestScore > b.interestScore;
        });
    }

    std::vector<FunctionIntelligenceItem> FunctionIntelligenceManager::GetTopInteresting(size_t count) const {
        std::vector<FunctionIntelligenceItem> top;
        for (size_t i = 0; i < std::min(count, m_functions.size()); ++i) {
            top.push_back(m_functions[i]);
        }
        return top;
    }

    const FunctionIntelligenceItem* FunctionIntelligenceManager::FindByRva(uint64_t rva) const {
        for (const auto& f : m_functions) {
            if (f.rva == rva) return &f;
        }
        return nullptr;
    }

    const FunctionIntelligenceItem* FunctionIntelligenceManager::FindByName(const std::string& name) const {
        for (const auto& f : m_functions) {
            if (f.name == name) return &f;
        }
        return nullptr;
    }

    size_t FunctionIntelligenceManager::InterestingCount(double threshold) const {
        size_t count = 0;
        for (const auto& f : m_functions) {
            if (f.interestScore >= threshold) count++;
        }
        return count;
    }

    size_t FunctionIntelligenceManager::HighInterestCount(double threshold) const {
        size_t count = 0;
        for (const auto& f : m_functions) {
            if (f.interestScore >= threshold) count++;
        }
        return count;
    }

    void FunctionIntelligenceManager::Clear() {
        m_functions.clear();
    }

    std::string FunctionIntelligenceManager::ToJson() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"total_functions\": " << m_functions.size() << ",\n";
        oss << "  \"interesting_count\": " << InterestingCount() << ",\n";
        oss << "  \"high_interest_count\": " << HighInterestCount() << ",\n";
        oss << "  \"functions\": [\n";
        for (size_t i = 0; i < m_functions.size(); ++i) {
            const auto& f = m_functions[i];
            oss << "    {\n";
            oss << "      \"rva\": \"0x" << std::hex << f.rva << std::dec << "\",\n";
            oss << "      \"address\": \"0x" << std::hex << f.address << std::dec << "\",\n";
            oss << "      \"name\": \"" << EscapeJson(f.name) << "\",\n";
            oss << "      \"module\": \"" << EscapeJson(f.moduleName) << "\",\n";
            oss << "      \"interest_score\": " << std::fixed << std::setprecision(1) << f.interestScore << ",\n";
            oss << "      \"threat_score\": " << std::fixed << std::setprecision(1) << f.threatScore << ",\n";
            oss << "      \"reasoning\": \"" << EscapeJson(f.interestReasoning) << "\",\n";
            oss << "      \"instructions\": " << f.instructionCount << ",\n";
            oss << "      \"basic_blocks\": " << f.basicBlockCount << ",\n";
            oss << "      \"callers\": " << f.callerCount << ",\n";
            oss << "      \"callees\": " << f.calleeCount << ",\n";
            oss << "      \"executions\": " << f.executionCount << "\n";
            oss << "    }" << (i + 1 < m_functions.size() ? "," : "") << "\n";
        }
        oss << "  ]\n";
        oss << "}\n";
        return oss.str();
    }

    std::string FunctionIntelligenceManager::ToMarkdownSummary(size_t topN) const {
        std::ostringstream oss;
        oss << "### Discovered Functions Summary\n\n";
        oss << "- **Total Discovered**: " << m_functions.size() << "\n";
        oss << "- **Interesting (Score >= 40)**: " << InterestingCount() << "\n";
        oss << "- **High-Interest (Score >= 70)**: " << HighInterestCount() << "\n\n";

        oss << "| RVA | Name | Interest | Threat | Blocks | Callers | Callees | Executions | Rationale |\n";
        oss << "|---|---|---|---|---|---|---|---|---|\n";

        for (size_t i = 0; i < std::min(topN, m_functions.size()); ++i) {
            const auto& f = m_functions[i];
            oss << "| `0x" << std::hex << f.rva << std::dec << "` | `" << f.name << "` | "
                << std::fixed << std::setprecision(1) << f.interestScore << " | "
                << std::fixed << std::setprecision(1) << f.threatScore << " | "
                << f.basicBlockCount << " | " << f.callerCount << " | " << f.calleeCount << " | "
                << f.executionCount << " | " << f.interestReasoning << " |\n";
        }

        return oss.str();
    }

} // namespace UTR
} // namespace Dracula
