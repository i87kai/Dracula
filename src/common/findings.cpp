#include "common/findings.h"
#include <iomanip>
#include <sstream>
#include <algorithm>

namespace Dracula {

    static std::string EscapeJson(const std::string& s) {
        std::ostringstream o;
        for (char c : s) {
            if (c == '"') o << "\\\"";
            else if (c == '\\') o << "\\\\";
            else if (c == '\b') o << "\\b";
            else if (c == '\f') o << "\\f";
            else if (c == '\n') o << "\\n";
            else if (c == '\r') o << "\\r";
            else if (c == '\t') o << "\\t";
            else if (static_cast<unsigned char>(c) <= 0x1f) {
                o << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c);
            } else {
                o << c;
            }
        }
        return o.str();
    }

    std::string UnifiedAnalysisResult::ToJson() const {
        std::ostringstream ss;
        ss << "{\n";
        ss << "  \"dracula_version\": \"2.0.0\",\n";
        ss << "  \"timestamp\": \"" << EscapeJson(timestampIso) << "\",\n";
        ss << "  \"duration_ms\": " << analysisDurationMs << ",\n";

        // Sample
        ss << "  \"sample\": {\n";
        ss << "    \"file_path\": \"" << EscapeJson(sample.filePath) << "\",\n";
        ss << "    \"file_name\": \"" << EscapeJson(sample.fileName) << "\",\n";
        ss << "    \"file_size\": " << sample.fileSize << ",\n";
        ss << "    \"sha256\": \"" << EscapeJson(sample.sha256) << "\",\n";
        ss << "    \"md5\": \"" << EscapeJson(sample.md5) << "\",\n";
        ss << "    \"magic\": \"" << EscapeJson(sample.magic) << "\",\n";
        ss << "    \"architecture\": \"" << EscapeJson(sample.architecture) << "\",\n";
        ss << "    \"subsystem\": \"" << EscapeJson(sample.subsystem) << "\",\n";
        ss << "    \"entrypoint_rva\": \"0x" << std::hex << sample.entryPointRva << std::dec << "\",\n";
        ss << "    \"image_base\": \"0x" << std::hex << sample.imageBase << std::dec << "\",\n";
        ss << "    \"is_64bit\": " << (sample.is64Bit ? "true" : "false") << ",\n";
        ss << "    \"is_dll\": " << (sample.isDll ? "true" : "false") << "\n";
        ss << "  },\n";

        // Security Mitigations
        ss << "  \"security_mitigations\": {\n";
        ss << "    \"aslr\": " << (mitigations.hasAslr ? "true" : "false") << ",\n";
        ss << "    \"high_entropy_aslr\": " << (mitigations.hasHighEntropyAslr ? "true" : "false") << ",\n";
        ss << "    \"dep\": " << (mitigations.hasDep ? "true" : "false") << ",\n";
        ss << "    \"cfg\": " << (mitigations.hasCfg ? "true" : "false") << ",\n";
        ss << "    \"seh\": " << (mitigations.hasSeh ? "true" : "false") << ",\n";
        ss << "    \"tls\": " << (mitigations.hasTls ? "true" : "false") << ",\n";
        ss << "    \"authenticode\": " << (mitigations.hasAuthenticode ? "true" : "false") << ",\n";
        ss << "    \"rwx_sections\": " << (mitigations.hasRwxSections ? "true" : "false") << ",\n";
        ss << "    \"is_dotnet\": " << (mitigations.isDotNet ? "true" : "false") << "\n";
        ss << "  },\n";

        // Sections
        ss << "  \"sections\": [\n";
        for (size_t i = 0; i < sections.size(); ++i) {
            const auto& s = sections[i];
            ss << "    {\n";
            ss << "      \"name\": \"" << EscapeJson(s.name) << "\",\n";
            ss << "      \"virtual_address\": \"0x" << std::hex << s.virtualAddress << std::dec << "\",\n";
            ss << "      \"virtual_size\": " << s.virtualSize << ",\n";
            ss << "      \"raw_size\": " << s.rawSize << ",\n";
            ss << "      \"entropy\": " << std::fixed << std::setprecision(4) << s.entropy << ",\n";
            ss << "      \"executable\": " << (s.isExecutable ? "true" : "false") << ",\n";
            ss << "      \"writable\": " << (s.isWritable ? "true" : "false") << ",\n";
            ss << "      \"high_entropy\": " << (s.isHighEntropy ? "true" : "false") << "\n";
            ss << "    }" << (i + 1 < sections.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Threat Assessment
        ss << "  \"threat_assessment\": {\n";
        ss << "    \"score\": " << threatScore << ",\n";
        ss << "    \"level\": \"" << EscapeJson(threatLevel) << "\",\n";
        ss << "    \"is_packed\": " << (isPacked ? "true" : "false") << ",\n";
        ss << "    \"detected_packer\": \"" << EscapeJson(detectedPacker) << "\",\n";
        ss << "    \"reasoning\": [\n";
        for (size_t i = 0; i < threatReasoning.size(); ++i) {
            ss << "      \"" << EscapeJson(threatReasoning[i]) << "\"" << (i + 1 < threatReasoning.size() ? "," : "") << "\n";
        }
        ss << "    ],\n";
        ss << "    \"mitre_techniques\": [\n";
        for (size_t i = 0; i < mitreAttackTechniques.size(); ++i) {
            ss << "      \"" << EscapeJson(mitreAttackTechniques[i]) << "\"" << (i + 1 < mitreAttackTechniques.size() ? "," : "") << "\n";
        }
        ss << "    ]\n";
        ss << "  },\n";

        // Findings
        ss << "  \"findings\": [\n";
        for (size_t i = 0; i < findings.size(); ++i) {
            const auto& f = findings[i];
            ss << "    {\n";
            ss << "      \"id\": \"" << EscapeJson(f.id) << "\",\n";
            ss << "      \"category\": \"" << EscapeJson(f.category) << "\",\n";
            ss << "      \"severity\": \"" << SeverityToString(f.severity) << "\",\n";
            ss << "      \"confidence\": \"" << ConfidenceToString(f.confidence) << "\",\n";
            ss << "      \"title\": \"" << EscapeJson(f.title) << "\",\n";
            ss << "      \"description\": \"" << EscapeJson(f.description) << "\",\n";
            ss << "      \"evidence\": \"" << EscapeJson(f.evidence) << "\",\n";
            ss << "      \"source\": \"" << EscapeJson(f.source) << "\",\n";
            ss << "      \"rva\": \"0x" << std::hex << f.rva << std::dec << "\"\n";
            ss << "    }" << (i + 1 < findings.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Imports summary
        ss << "  \"imports_count\": " << imports.size() << ",\n";
        ss << "  \"exports_count\": " << exports.size() << ",\n";
        ss << "  \"strings_count\": " << strings.size() << ",\n";
        ss << "  \"yara_matches\": [\n";
        for (size_t i = 0; i < yaraMatches.size(); ++i) {
            ss << "    \"" << EscapeJson(yaraMatches[i]) << "\"" << (i + 1 < yaraMatches.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Emulation summary
        ss << "  \"emulation\": {\n";
        ss << "    \"executed\": " << (emulation.instructionsExecuted > 0 ? "true" : "false") << ",\n";
        ss << "    \"instructions_executed\": " << emulation.instructionsExecuted << ",\n";
        ss << "    \"stop_reason\": \"" << StopReasonToString(emulation.stopReason) << "\",\n";
        ss << "    \"hle_calls_count\": " << emulation.hleCalls.size() << "\n";
        ss << "  }\n";

        ss << "}\n";
        return ss.str();
    }

    std::string UnifiedAnalysisResult::ToMarkdown() const {
        std::ostringstream md;
        md << "# 🧛 Dracula Binary Intelligence Report\n\n";
        md << "**File:** `" << sample.fileName << "`  \n";
        md << "**Path:** `" << sample.filePath << "`  \n";
        md << "**SHA-256:** `" << sample.sha256 << "`  \n";
        md << "**Architecture:** " << sample.architecture << " | **Subsystem:** " << sample.subsystem << "  \n";
        md << "**Analysis Duration:** " << analysisDurationMs << " ms  \n";
        md << "**Threat Score:** **" << threatScore << " / 100** (" << threatLevel << ")  \n\n";

        md << "## 🛡️ Security Mitigations\n\n";
        md << "| Mitigation | Status |\n";
        md << "|---|---|\n";
        md << "| ASLR (Dynamic Base) | " << (mitigations.hasAslr ? "✅ Enabled" : "❌ Disabled") << " |\n";
        md << "| High Entropy ASLR | " << (mitigations.hasHighEntropyAslr ? "✅ Enabled" : "❌ Disabled") << " |\n";
        md << "| DEP / NX Compatibility | " << (mitigations.hasDep ? "✅ Enabled" : "❌ Disabled") << " |\n";
        md << "| Control Flow Guard (CFG) | " << (mitigations.hasCfg ? "✅ Enabled" : "❌ Disabled") << " |\n";
        md << "| Structured Exception Handling | " << (mitigations.hasSeh ? "✅ Enabled" : "❌ Disabled") << " |\n";
        md << "| Authenticode Signature | " << (mitigations.hasAuthenticode ? "✅ Signed" : "❌ Unsigned") << " |\n";
        md << "| RWX Sections Present | " << (mitigations.hasRwxSections ? "⚠️ YES (Suspicious)" : "✅ None") << " |\n\n";

        md << "## 📊 Section & Entropy Audit\n\n";
        md << "| Section | Virtual Addr | Virtual Size | Raw Size | Entropy | Permissions |\n";
        md << "|---|---|---|---|---|---|\n";
        for (const auto& s : sections) {
            std::string perms = "";
            if (s.isReadable) perms += "R";
            if (s.isWritable) perms += "W";
            if (s.isExecutable) perms += "X";
            md << "| `" << s.name << "` | 0x" << std::hex << s.virtualAddress << std::dec
               << " | " << s.virtualSize << " B | " << s.rawSize << " B | "
               << std::fixed << std::setprecision(2) << s.entropy << (s.isHighEntropy ? " 🔥" : "")
               << " | " << perms << " |\n";
        }
        md << "\n";

        if (!findings.empty()) {
            md << "## 🚨 Key Findings (" << findings.size() << ")\n\n";
            md << "| Severity | ID | Category | Description | Evidence |\n";
            md << "|---|---|---|---|---|\n";
            for (const auto& f : findings) {
                std::string sevBadge;
                switch (f.severity) {
                    case FindingSeverity::Critical: sevBadge = "🔴 CRITICAL"; break;
                    case FindingSeverity::High:     sevBadge = "🟠 HIGH"; break;
                    case FindingSeverity::Medium:   sevBadge = "🟡 MEDIUM"; break;
                    case FindingSeverity::Low:      sevBadge = "🔵 LOW"; break;
                    default:                        sevBadge = "⚪ INFO"; break;
                }
                md << "| " << sevBadge << " | `" << f.id << "` | " << f.category << " | "
                   << f.title << " | `" << f.evidence << "` |\n";
            }
            md << "\n";
        }

        if (emulation.instructionsExecuted > 0) {
            md << "## ⚙️ Unicorn 2 CPU Emulation Trace\n\n";
            md << "* **Instructions Executed:** " << emulation.instructionsExecuted << "\n";
            md << "* **Termination Reason:** `" << StopReasonToString(emulation.stopReason) << "`\n";
            md << "* **Win32 HLE Calls:** " << emulation.hleCalls.size() << "\n\n";
            if (!emulation.hleCalls.empty()) {
                md << "| API Name | Library | Caller RVA | Handled | Details |\n";
                md << "|---|---|---|---|---|\n";
                for (const auto& c : emulation.hleCalls) {
                    md << "| `" << c.apiName << "` | `" << c.library << "` | 0x"
                       << std::hex << c.callerRva << std::dec << " | "
                       << (c.wasHandled ? "✅" : "⚠️") << " | " << c.details << " |\n";
                }
                md << "\n";
            }
        }

        return md.str();
    }

    std::string UnifiedAnalysisResult::ToAnsiSummary() const {
        std::ostringstream out;
        out << "\033[1;36m======================================================================\033[0m\n";
        out << "\033[1;31m 🧛 DRACULA BINARY ANALYSIS REPORT\033[0m\n";
        out << "\033[1;36m======================================================================\033[0m\n";
        out << " \033[1mSample:\033[0m       " << sample.fileName << " (" << sample.fileSize << " bytes)\n";
        out << " \033[1mArchitecture:\033[0m " << sample.architecture << " | \033[1mSubsystem:\033[0m " << sample.subsystem << "\n";
        out << " \033[1mSHA-256:\033[0m      " << sample.sha256 << "\n";
        out << " \033[1mEntropy:\033[0m      " << std::fixed << std::setprecision(2) << overallEntropy << "/8.00 "
            << (isPacked ? "\033[1;33m[PACKED / ENCRYPTED]\033[0m" : "\033[32m[NORMAL]\033[0m") << "\n";

        out << " \033[1mThreat Score:\033[0m ";
        if (threatScore >= 75) {
            out << "\033[1;91m" << threatScore << "/100 [CRITICAL]\033[0m\n";
        } else if (threatScore >= 45) {
            out << "\033[1;93m" << threatScore << "/100 [SUSPICIOUS]\033[0m\n";
        } else {
            out << "\033[1;92m" << threatScore << "/100 [CLEAN / BENIGN]\033[0m\n";
        }

        out << "\n \033[1;35m--- Security Mitigations ---\033[0m\n";
        out << "   ASLR: " << (mitigations.hasAslr ? "\033[32mON\033[0m" : "\033[31mOFF\033[0m")
            << " | DEP: " << (mitigations.hasDep ? "\033[32mON\033[0m" : "\033[31mOFF\033[0m")
            << " | CFG: " << (mitigations.hasCfg ? "\033[32mON\033[0m" : "\033[33mOFF\033[0m")
            << " | SEH: " << (mitigations.hasSeh ? "\033[32mON\033[0m" : "\033[33mOFF\033[0m")
            << " | Signature: " << (mitigations.hasAuthenticode ? "\033[32mSIGNED\033[0m" : "\033[33mUNSIGNED\033[0m") << "\n";

        if (!findings.empty()) {
            out << "\n \033[1;33m--- Key Findings (" << findings.size() << ") ---\033[0m\n";
            for (const auto& f : findings) {
                std::string col = "\033[37m";
                if (f.severity == FindingSeverity::Critical) col = "\033[1;91m";
                else if (f.severity == FindingSeverity::High) col = "\033[91m";
                else if (f.severity == FindingSeverity::Medium) col = "\033[93m";
                else if (f.severity == FindingSeverity::Low) col = "\033[94m";

                out << "   " << col << "[" << SeverityToString(f.severity) << "]\033[0m "
                    << "\033[1m" << f.title << "\033[0m (" << f.id << ")\n"
                    << "       Evidence: " << f.evidence << "\n";
            }
        }

        out << "\033[1;36m======================================================================\033[0m\n";
        return out.str();
    }

} // namespace Dracula
