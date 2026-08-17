#include "common/findings.h"
#include "common/version.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"
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
        ss << "  \"dracula_version\": \"" << Version::String << "\",\n";
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
        ss << "  \"xrefs_count\": " << xrefs.size() << ",\n";
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
        // Rendered through the semantic theme and the shared layout primitives.
        // Previously this emitted hard-coded ANSI unconditionally, which leaked
        // escape sequences into redirected files and ignored --no-color.
        const std::string accent = Terminal::Color(ColorRole::Accent);
        const std::string second = Terminal::Color(ColorRole::Secondary);
        const std::string muted  = Terminal::Color(ColorRole::Muted);
        const std::string body   = Terminal::Color(ColorRole::Text);
        const std::string reset  = Terminal::Color(ColorRole::Reset);
        const std::string border = Terminal::Color(ColorRole::Border);

        const size_t ruleWidth = std::min<size_t>(72,
            static_cast<size_t>(std::max(Terminal::GetWidth() - 2, 30)));
        const size_t keyWidth = 22;

        auto row = [&](const std::string& key, const std::string& value,
                       const std::string& valueColor) {
            return "  " + muted + Text::PadRight(key, keyWidth) + reset +
                   valueColor + value + reset + "\n";
        };

        std::ostringstream out;
        out << "\n" << accent << "Analysis Summary" << reset
            << muted << "   " << sample.fileName << reset << "\n"
            << border << Text::HorizontalRule(ruleWidth) << reset << "\n";

        out << row("Sample", sample.filePath.empty() ? sample.fileName : sample.filePath, body);
        out << row("Size", std::to_string(sample.fileSize) + " bytes", body);
        out << row("Architecture", sample.architecture + "   " + sample.subsystem, body);
        out << row("SHA-256", sample.sha256, body);

        std::ostringstream entropyText;
        entropyText << std::fixed << std::setprecision(2) << overallEntropy << " / 8.00";
        out << row("Entropy", entropyText.str(), body);
        out << row("Packing", isPacked ? "Packed or encrypted" : "Normal",
                   Terminal::Color(isPacked ? ColorRole::Warning : ColorRole::Success));

        ColorRole scoreRole = ColorRole::Success;
        std::string verdict = "Benign";
        if (threatScore >= 75)      { scoreRole = ColorRole::Error;   verdict = "Critical"; }
        else if (threatScore >= 45) { scoreRole = ColorRole::Warning; verdict = "Suspicious"; }
        out << row("Threat score",
                   std::to_string(threatScore) + " / 100   " + verdict,
                   Terminal::Color(scoreRole));

        out << "\n  " << second << "Mitigations" << reset << "\n";
        auto mitigation = [&](const char* name, bool enabled, bool criticalWhenOff) {
            ColorRole role = enabled ? ColorRole::Success
                                     : (criticalWhenOff ? ColorRole::Error : ColorRole::Warning);
            return "  " + muted + Text::PadRight(name, keyWidth) + reset +
                   Terminal::Color(role) + (enabled ? "Enabled" : "Disabled") + reset + "\n";
        };
        out << mitigation("ASLR", mitigations.hasAslr, true);
        out << mitigation("DEP / NX", mitigations.hasDep, true);
        out << mitigation("Control Flow Guard", mitigations.hasCfg, false);
        out << mitigation("SEH", mitigations.hasSeh, false);
        out << row("Authenticode", mitigations.hasAuthenticode ? "Signed" : "Unsigned",
                   Terminal::Color(mitigations.hasAuthenticode ? ColorRole::Success
                                                               : ColorRole::Warning));

        if (!findings.empty()) {
            out << "\n  " << second << "Findings (" << findings.size() << ")" << reset << "\n";
            for (const auto& f : findings) {
                ColorRole role = ColorRole::Muted;
                switch (f.severity) {
                    case FindingSeverity::Critical:
                    case FindingSeverity::High:   role = ColorRole::Error;   break;
                    case FindingSeverity::Medium: role = ColorRole::Warning; break;
                    case FindingSeverity::Low:    role = ColorRole::Info;    break;
                    default:                      role = ColorRole::Muted;   break;
                }
                out << "  " << Terminal::Color(role)
                    << Text::PadRight(SeverityToString(f.severity), 10) << reset
                    << Terminal::Color(ColorRole::Command) << f.title << reset << "\n"
                    << "  " << std::string(keyWidth - 12, ' ') << muted
                    << f.evidence << reset << "\n";
            }
        }

        out << "\n";
        return out.str();
    }

} // namespace Dracula
