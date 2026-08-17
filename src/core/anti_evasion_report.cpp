//
// Anti-Evasion presentation: machine-readable JSON, Markdown, and the terminal
// report. Structured data goes into JSON as structured data; terminal-formatted
// text never does.
//

#include "core/anti_evasion_engine.h"
#include "cli/terminal.h"
#include "cli/text_layout.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace Dracula {

    namespace {

        std::string Esc(const std::string& s) {
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
                } else o << c;
            }
            return o.str();
        }

        std::string HexStr(uint64_t v) {
            std::ostringstream ss;
            ss << "0x" << std::hex << std::uppercase << v;
            return ss.str();
        }

        // "Very High" is what a differentially proven technique deserves, and
        // the shared FindingConfidence enum stops at High. The distinction is
        // real, so it is drawn here from the evidence rather than by inflating
        // the enum used by every other analyzer.
        std::string ConfidenceLabel(const EvasionTechnique& t) {
            if (t.StrongestEvidence() == EvidenceKind::VerifiedDifferential &&
                t.confidence == FindingConfidence::High) {
                return "Very High";
            }
            switch (t.confidence) {
                case FindingConfidence::High:   return "High";
                case FindingConfidence::Medium: return "Medium";
                default:                        return "Low";
            }
        }

        std::string OverallConfidenceLabel(const AntiEvasionResult& r) {
            for (const auto& t : r.techniques) {
                if (t.StrongestEvidence() == EvidenceKind::VerifiedDifferential) return "Very High";
            }
            switch (r.overallConfidence) {
                case FindingConfidence::High:   return "High";
                case FindingConfidence::Medium: return "Medium";
                default:                        return "Low";
            }
        }

        std::string JsonArray(const std::vector<uint64_t>& v, size_t limit = 64) {
            std::ostringstream ss;
            ss << "[";
            const size_t n = std::min(v.size(), limit);
            for (size_t i = 0; i < n; ++i) {
                ss << "\"" << HexStr(v[i]) << "\"" << (i + 1 < n ? ", " : "");
            }
            ss << "]";
            return ss.str();
        }

        std::string JsonStrArray(const std::vector<std::string>& v) {
            std::ostringstream ss;
            ss << "[";
            for (size_t i = 0; i < v.size(); ++i) {
                ss << "\"" << Esc(v[i]) << "\"" << (i + 1 < v.size() ? ", " : "");
            }
            ss << "]";
            return ss.str();
        }

    } // namespace

    // ─── JSON ───────────────────────────────────────────────────────────────

    std::string AntiEvasionResult::ToJson() const {
        std::ostringstream ss;
        ss << "{\n";
        ss << "  \"status\": \"" << AntiEvasionStatusToString(status) << "\",\n";
        ss << "  \"sample\": \"" << Esc(sampleName) << "\",\n";
        ss << "  \"sample_path\": \"" << Esc(samplePath) << "\",\n";
        ss << "  \"duration_ms\": " << durationMs << ",\n";
        ss << "  \"environment_sensitivity_score\": " << environmentSensitivityScore << ",\n";
        ss << "  \"environment_sensitivity_label\": \"" << Esc(sensitivityLabel) << "\",\n";
        ss << "  \"confidence\": \"" << Esc(OverallConfidenceLabel(*this)) << "\",\n";
        ss << "  \"comparison_performed\": " << (comparePerformed ? "true" : "false") << ",\n";
        ss << "  \"conclusion\": \"" << Esc(conclusion) << "\",\n";

        // Profiles
        ss << "  \"profiles\": [\n";
        for (size_t i = 0; i < profileCoherence.size(); ++i) {
            const auto& g = profileCoherence[i];
            ss << "    {\n";
            ss << "      \"name\": \"" << Esc(g.profileName) << "\",\n";
            ss << "      \"coherent\": " << (g.IsCoherent() ? "true" : "false") << ",\n";
            ss << "      \"fingerprintability\": " << g.fingerprintability << ",\n";
            ss << "      \"fingerprintability_label\": \"" << Esc(g.fingerprintabilityLabel) << "\",\n";
            ss << "      \"contradictions\": [\n";
            for (size_t c = 0; c < g.contradictions.size(); ++c) {
                const auto& x = g.contradictions[c];
                ss << "        {\n";
                ss << "          \"property\": \"" << Esc(x.property) << "\",\n";
                ss << "          \"severity\": \"" << SeverityToString(x.severity) << "\",\n";
                ss << "          \"first_channel\": \"" << ClaimChannelToString(x.first.channel) << "\",\n";
                ss << "          \"first_value\": \"" << Esc(x.first.value) << "\",\n";
                ss << "          \"second_channel\": \"" << ClaimChannelToString(x.second.channel) << "\",\n";
                ss << "          \"second_value\": \"" << Esc(x.second.value) << "\",\n";
                ss << "          \"explanation\": \"" << Esc(x.explanation) << "\"\n";
                ss << "        }" << (c + 1 < g.contradictions.size() ? "," : "") << "\n";
            }
            ss << "      ]\n";
            ss << "    }" << (i + 1 < profileCoherence.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Techniques
        ss << "  \"techniques\": [\n";
        for (size_t i = 0; i < techniques.size(); ++i) {
            const auto& t = techniques[i];
            ss << "    {\n";
            ss << "      \"id\": \"" << Esc(t.id) << "\",\n";
            ss << "      \"category\": \"" << EvasionCategoryId(t.category) << "\",\n";
            ss << "      \"label\": \"" << EvasionCategoryLabel(t.category) << "\",\n";
            ss << "      \"title\": \"" << Esc(t.title) << "\",\n";
            ss << "      \"description\": \"" << Esc(t.description) << "\",\n";
            ss << "      \"severity\": \"" << SeverityToString(t.severity) << "\",\n";
            ss << "      \"confidence\": \"" << Esc(ConfidenceLabel(t)) << "\",\n";
            ss << "      \"evidence_kind\": \"" << EvidenceKindToString(t.StrongestEvidence()) << "\",\n";
            ss << "      \"rva\": \"" << HexStr(t.rva) << "\",\n";
            ss << "      \"virtual_address\": \"" << HexStr(t.virtualAddress) << "\",\n";
            ss << "      \"function\": \"" << Esc(t.functionName) << "\",\n";
            ss << "      \"basic_block\": \"" << HexStr(t.basicBlockStart) << "\",\n";
            ss << "      \"environment_property\": \"" << Esc(t.environmentProperty) << "\",\n";
            ss << "      \"observed_value\": \"" << Esc(t.observedValue) << "\",\n";
            ss << "      \"supplied_value\": \"" << Esc(t.suppliedValue) << "\",\n";
            ss << "      \"profile\": \"" << Esc(t.profile) << "\",\n";
            ss << "      \"controls_flow\": " << (t.controlsFlow ? "true" : "false") << ",\n";
            ss << "      \"branch_rva\": \"" << HexStr(t.branchRva) << "\",\n";
            ss << "      \"control_flow_consequence\": \"" << Esc(t.controlFlowConsequence) << "\",\n";
            ss << "      \"corroborating_analyzers\": " << JsonStrArray(t.corroboratingAnalyzers) << ",\n";
            ss << "      \"tags\": " << JsonStrArray(t.tags) << ",\n";
            ss << "      \"evidence\": [\n";
            for (size_t e = 0; e < t.evidence.size(); ++e) {
                const auto& ev = t.evidence[e];
                ss << "        {\n";
                ss << "          \"kind\": \"" << EvidenceKindToString(ev.kind) << "\",\n";
                ss << "          \"source\": \"" << Esc(ev.source) << "\",\n";
                ss << "          \"rva\": \"" << HexStr(ev.rva) << "\",\n";
                ss << "          \"instruction\": \"" << Esc(ev.instruction) << "\",\n";
                ss << "          \"detail\": \"" << Esc(ev.detail) << "\"\n";
                ss << "        }" << (e + 1 < t.evidence.size() ? "," : "") << "\n";
            }
            ss << "      ]\n";
            ss << "    }" << (i + 1 < techniques.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Differential runs
        ss << "  \"differential_runs\": [\n";
        for (size_t i = 0; i < runs.size(); ++i) {
            const auto& r = runs[i];
            ss << "    {\n";
            ss << "      \"profile\": \"" << Esc(r.profileName) << "\",\n";
            ss << "      \"completed\": " << (r.completed ? "true" : "false") << ",\n";
            ss << "      \"blocks_reached\": " << r.fingerprint.blocksReached << ",\n";
            ss << "      \"functions_reached\": " << r.fingerprint.functionsReached << ",\n";
            ss << "      \"instructions_executed\": " << r.fingerprint.instructionsExecuted << ",\n";
            ss << "      \"hle_calls\": " << r.fingerprint.hleCallCount << ",\n";
            ss << "      \"termination\": \"" << Esc(r.fingerprint.terminationReason) << "\",\n";
            ss << "      \"logical_elapsed_ms\": " << r.emulation.logicalElapsedMs << ",\n";
            ss << "      \"time_normalized\": " << (r.emulation.timeWasNormalized ? "true" : "false") << ",\n";
            ss << "      \"environment_observations\": " << r.emulation.environmentObservations.size() << ",\n";
            ss << "      \"fingerprint\": \"" << Esc(r.fingerprint.digest) << "\",\n";
            ss << "      \"coverage_digest\": \"" << Esc(r.fingerprint.coverageDigest) << "\",\n";
            ss << "      \"api_sequence_digest\": \"" << Esc(r.fingerprint.apiSequenceDigest) << "\"\n";
            ss << "    }" << (i + 1 < runs.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Deltas
        ss << "  \"execution_deltas\": [\n";
        for (size_t i = 0; i < deltas.size(); ++i) {
            const auto& d = deltas[i];
            ss << "    {\n";
            ss << "      \"reference_profile\": \"" << Esc(d.baselineProfile) << "\",\n";
            ss << "      \"alternate_profile\": \"" << Esc(d.alternateProfile) << "\",\n";
            ss << "      \"diverged\": " << (d.Diverged() ? "true" : "false") << ",\n";
            ss << "      \"instruction_delta\": " << d.instructionDelta << ",\n";
            ss << "      \"termination_changed\": " << (d.terminationChanged ? "true" : "false") << ",\n";
            ss << "      \"reference_termination\": \"" << Esc(d.baselineTermination) << "\",\n";
            ss << "      \"alternate_termination\": \"" << Esc(d.alternateTermination) << "\",\n";
            ss << "      \"blocks_only_in_reference\": " << JsonArray(d.blocksOnlyInBaseline) << ",\n";
            ss << "      \"blocks_only_in_alternate\": " << JsonArray(d.blocksOnlyInAlternate) << ",\n";
            ss << "      \"functions_only_in_reference\": " << JsonArray(d.functionsOnlyInBaseline) << ",\n";
            ss << "      \"functions_only_in_alternate\": " << JsonArray(d.functionsOnlyInAlternate) << ",\n";
            ss << "      \"apis_only_in_reference\": " << JsonStrArray(d.apisOnlyInBaseline) << ",\n";
            ss << "      \"apis_only_in_alternate\": " << JsonStrArray(d.apisOnlyInAlternate) << "\n";
            ss << "    }" << (i + 1 < deltas.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Branch divergences
        ss << "  \"branch_divergences\": [\n";
        for (size_t i = 0; i < branchDivergences.size(); ++i) {
            const auto& b = branchDivergences[i];
            ss << "    {\n";
            ss << "      \"rva\": \"" << HexStr(b.rva) << "\",\n";
            ss << "      \"virtual_address\": \"" << HexStr(b.virtualAddress) << "\",\n";
            ss << "      \"instruction\": \"" << Esc(b.mnemonic) << "\",\n";
            ss << "      \"reference_profile\": \"" << Esc(b.baselineProfile) << "\",\n";
            ss << "      \"alternate_profile\": \"" << Esc(b.alternateProfile) << "\",\n";
            ss << "      \"reference_taken\": " << (b.baselineTaken ? "true" : "false") << ",\n";
            ss << "      \"alternate_taken\": " << (b.alternateTaken ? "true" : "false") << ",\n";
            ss << "      \"reference_target\": \"" << HexStr(b.baselineTarget) << "\",\n";
            ss << "      \"alternate_target\": \"" << HexStr(b.alternateTarget) << "\",\n";
            ss << "      \"reference_consequence\": \"" << Esc(b.baselineConsequence) << "\",\n";
            ss << "      \"alternate_consequence\": \"" << Esc(b.alternateConsequence) << "\",\n";
            ss << "      \"influence_origin\": \"" << Esc(b.influenceOrigin) << "\",\n";
            ss << "      \"influence_property\": \"" << Esc(b.influenceProperty) << "\",\n";
            ss << "      \"confidence\": \"" << ConfidenceToString(b.confidence) << "\"\n";
            ss << "    }" << (i + 1 < branchDivergences.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";

        // Normalization audit trail: what Dracula supplied, and why.
        ss << "  \"normalizations\": [\n";
        for (size_t i = 0; i < normalizations.size(); ++i) {
            const auto& n = normalizations[i];
            ss << "    {\n";
            ss << "      \"property\": \"" << Esc(n.property) << "\",\n";
            ss << "      \"baseline_value\": \"" << Esc(n.observedValue) << "\",\n";
            ss << "      \"supplied_value\": \"" << Esc(n.suppliedValue) << "\",\n";
            ss << "      \"profile\": \"" << Esc(n.profile) << "\",\n";
            ss << "      \"source\": \"" << Esc(n.source) << "\",\n";
            ss << "      \"reason\": \"" << Esc(n.reason) << "\"\n";
            ss << "    }" << (i + 1 < normalizations.size() ? "," : "") << "\n";
        }
        ss << "  ],\n";
        ss << "  \"notes\": " << JsonStrArray(notes) << "\n";
        ss << "}\n";
        return ss.str();
    }

    // ─── Markdown ───────────────────────────────────────────────────────────

    std::string AntiEvasionResult::ToMarkdown() const {
        std::ostringstream md;
        md << "## Anti-Evasion Analysis\n\n";
        md << "**Sample:** `" << sampleName << "`  \n";
        md << "**Status:** `" << AntiEvasionStatusToString(status) << "`  \n";
        md << "**Environment sensitivity:** **" << environmentSensitivityScore << " / 100** ("
           << sensitivityLabel << ")  \n";
        md << "**Confidence:** " << OverallConfidenceLabel(*this) << "  \n";
        md << "**Comparison performed:** " << (comparePerformed ? "yes" : "no") << "\n\n";
        md << conclusion << "\n\n";

        if (!techniques.empty()) {
            md << "### Detected techniques (" << techniques.size() << ")\n\n";
            md << "| Category | RVA | Confidence | Evidence | Controls flow |\n";
            md << "|---|---|---|---|---|\n";
            for (const auto& t : techniques) {
                md << "| `" << EvasionCategoryId(t.category) << "` | `" << HexStr(t.rva)
                   << "` | " << ConfidenceLabel(t) << " | "
                   << EvidenceKindToString(t.StrongestEvidence()) << " | "
                   << (t.controlsFlow ? "yes" : "no") << " |\n";
            }
            md << "\n";
        }

        if (!runs.empty()) {
            md << "### Differential execution\n\n";
            md << "| Profile | Blocks | Functions | Instructions | HLE calls | Termination |\n";
            md << "|---|---|---|---|---|---|\n";
            for (const auto& r : runs) {
                md << "| " << r.profileName << " | " << r.fingerprint.blocksReached
                   << " | " << r.fingerprint.functionsReached
                   << " | " << r.fingerprint.instructionsExecuted
                   << " | " << r.fingerprint.hleCallCount
                   << " | `" << r.fingerprint.terminationReason << "` |\n";
            }
            md << "\n";
        }

        if (!branchDivergences.empty()) {
            md << "### Environment-sensitive branches\n\n";
            for (const auto& b : branchDivergences) {
                md << "* **RVA `" << HexStr(b.rva) << "`** (`" << b.mnemonic << "`)\n";
                md << "  * " << b.baselineProfile << ": " << b.baselineConsequence << "\n";
                md << "  * " << b.alternateProfile << ": " << b.alternateConsequence << "\n";
                if (!b.influenceOrigin.empty()) {
                    md << "  * Attributed to " << b.influenceOrigin << " (" << b.influenceProperty << ")\n";
                }
            }
            md << "\n";
        }

        if (!normalizations.empty()) {
            md << "### Normalized environment values\n\n";
            md << "Every value below is something Dracula supplied that differs from the "
                  "Baseline environment. Nothing is changed silently.\n\n";
            md << "| Property | Baseline | Supplied | Profile | Source |\n";
            md << "|---|---|---|---|---|\n";
            for (const auto& n : normalizations) {
                md << "| `" << n.property << "` | " << n.observedValue << " | " << n.suppliedValue
                   << " | " << n.profile << " | " << n.source << " |\n";
            }
            md << "\n";
        }

        if (!profileCoherence.empty()) {
            md << "### Environment coherence\n\n";
            md << "| Profile | Coherent | Fingerprintability | Contradictions |\n";
            md << "|---|---|---|---|\n";
            for (const auto& g : profileCoherence) {
                md << "| " << g.profileName << " | " << (g.IsCoherent() ? "yes" : "**no**")
                   << " | " << g.fingerprintability << " / 100 (" << g.fingerprintabilityLabel << ")"
                   << " | " << g.contradictions.size() << " |\n";
            }
            md << "\n";
        }

        md << "> Detecting a virtual environment is not by itself malicious, and no virtual "
              "environment can be made indistinguishable from physical hardware.\n\n";
        return md.str();
    }

    // ─── Terminal ───────────────────────────────────────────────────────────

    std::string AntiEvasionResult::ToAnsiReport(bool detailed) const {
        const std::string accent = Terminal::Color(ColorRole::Accent);
        const std::string second = Terminal::Color(ColorRole::Secondary);
        const std::string muted  = Terminal::Color(ColorRole::Muted);
        const std::string body   = Terminal::Color(ColorRole::Text);
        const std::string cmd    = Terminal::Color(ColorRole::Command);
        const std::string tech   = Terminal::Color(ColorRole::Technical);
        const std::string border = Terminal::Color(ColorRole::Border);
        const std::string reset  = Terminal::Color(ColorRole::Reset);

        const size_t ruleWidth = std::min<size_t>(72,
            static_cast<size_t>(std::max(Terminal::ContentWidth(), 30)));
        const size_t keyWidth = 26;

        auto row = [&](const std::string& key, const std::string& value,
                       const std::string& colour) {
            return "  " + muted + Text::PadRight(key, keyWidth) + reset + colour + value + reset + "\n";
        };

        std::ostringstream out;
        out << "\n" << accent << "Anti-Evasion Analysis" << reset
            << muted << "   " << sampleName << reset << "\n"
            << border << Text::HorizontalRule(ruleWidth) << reset << "\n";

        ColorRole scoreRole = ColorRole::Success;
        if (environmentSensitivityScore >= 70)      scoreRole = ColorRole::Error;
        else if (environmentSensitivityScore >= 35) scoreRole = ColorRole::Warning;

        out << row("Environment sensitivity",
                   std::to_string(environmentSensitivityScore) + " / 100   " + sensitivityLabel,
                   Terminal::Color(scoreRole));
        out << row("Confidence", OverallConfidenceLabel(*this), body);
        out << row("Status", AntiEvasionStatusToString(status), body);
        out << row("Comparison", comparePerformed ? "performed" : "not requested", body);

        // ── Techniques ──
        if (techniques.empty()) {
            out << "\n  " << muted << "No environment inspection detected." << reset << "\n";
        } else {
            out << "\n  " << second << "Detected techniques (" << techniques.size() << ")" << reset << "\n\n";
            size_t shown = 0;
            const size_t limit = detailed ? techniques.size() : std::min<size_t>(techniques.size(), 12);
            for (const auto& t : techniques) {
                if (shown++ >= limit) break;

                ColorRole role = ColorRole::Muted;
                switch (t.severity) {
                    case FindingSeverity::Critical:
                    case FindingSeverity::High:   role = ColorRole::Error;   break;
                    case FindingSeverity::Medium: role = ColorRole::Warning; break;
                    case FindingSeverity::Low:    role = ColorRole::Info;    break;
                    default:                      role = ColorRole::Muted;   break;
                }

                out << "  " << Terminal::Color(role) << EvasionCategoryLabel(t.category) << reset << "\n";
                out << "    " << muted << Text::PadRight("RVA", 14) << reset
                    << tech << HexStr(t.rva) << reset << "\n";
                if (!t.functionName.empty()) {
                    out << "    " << muted << Text::PadRight("Function", 14) << reset
                        << body << t.functionName << reset << "\n";
                }
                out << "    " << muted << Text::PadRight("Confidence", 14) << reset
                    << body << ConfidenceLabel(t) << reset << "\n";
                out << "    " << muted << Text::PadRight("Evidence", 14) << reset
                    << body << EvidenceKindToString(t.StrongestEvidence()) << reset << "\n";
                if (!t.environmentProperty.empty()) {
                    out << "    " << muted << Text::PadRight("Property", 14) << reset
                        << body << t.environmentProperty << reset << "\n";
                }
                if (t.controlsFlow && !t.controlFlowConsequence.empty()) {
                    out << "    " << muted << Text::PadRight("Control flow", 14) << reset
                        << body << t.controlFlowConsequence << reset << "\n";
                }

                if (detailed) {
                    if (!t.suppliedValue.empty()) {
                        out << "    " << muted << Text::PadRight("Supplied", 14) << reset
                            << body << t.suppliedValue << reset << "\n";
                    }
                    if (!t.profile.empty()) {
                        out << "    " << muted << Text::PadRight("Profile", 14) << reset
                            << body << t.profile << reset << "\n";
                    }
                    for (const auto& e : t.evidence) {
                        out << "    " << muted << Text::PadRight("", 14) << reset
                            << muted << "- [" << EvidenceKindToString(e.kind) << "] "
                            << e.detail << reset << "\n";
                    }
                } else if (!t.evidence.empty()) {
                    out << "    " << muted << Text::PadRight("", 14) << t.evidence.front().detail
                        << reset << "\n";
                }
                out << "\n";
            }
            if (!detailed && techniques.size() > limit) {
                out << "  " << muted << "Showing " << limit << " of " << techniques.size()
                    << " techniques. Use --details for the rest." << reset << "\n\n";
            }
        }

        // ── Differential execution ──
        if (!runs.empty()) {
            out << "  " << second << "Differential execution" << reset << "\n\n";
            for (const auto& r : runs) {
                out << "    " << cmd << r.profileName << reset << "\n";
                out << "      " << muted << Text::PadRight("Blocks reached", 22) << reset
                    << tech << r.fingerprint.blocksReached << reset << "\n";
                out << "      " << muted << Text::PadRight("Functions reached", 22) << reset
                    << tech << r.fingerprint.functionsReached << reset << "\n";
                out << "      " << muted << Text::PadRight("Instructions", 22) << reset
                    << tech << r.fingerprint.instructionsExecuted << reset << "\n";
                out << "      " << muted << Text::PadRight("Termination", 22) << reset
                    << body << r.fingerprint.terminationReason << reset << "\n";
                if (detailed) {
                    out << "      " << muted << Text::PadRight("Logical elapsed", 22) << reset
                        << body << r.emulation.logicalElapsedMs << " ms" << reset << "\n";
                    out << "      " << muted << Text::PadRight("Fingerprint", 22) << reset
                        << tech << r.fingerprint.digest << reset << "\n";
                }
                out << "\n";
            }
        }

        // ── Key divergence ──
        if (!branchDivergences.empty()) {
            out << "  " << second << "Key divergence" << reset << "\n\n";
            size_t shown = 0;
            for (const auto& b : branchDivergences) {
                if (!detailed && shown++ >= 5) break;
                out << "    " << tech << "RVA " << HexStr(b.rva) << reset
                    << muted << "   " << b.mnemonic << reset << "\n";
                out << "      " << muted << Text::PadRight(b.baselineProfile, 20) << reset
                    << body << b.baselineConsequence << reset << "\n";
                out << "      " << muted << Text::PadRight(b.alternateProfile, 20) << reset
                    << body << b.alternateConsequence << reset << "\n";
                if (!b.influenceOrigin.empty()) {
                    out << "      " << muted << Text::PadRight("Attributed to", 20) << reset
                        << body << b.influenceOrigin << " (" << b.influenceProperty << ")" << reset << "\n";
                }
                out << "\n";
            }
        }

        // ── Normalization audit trail ──
        if (!normalizations.empty() && detailed) {
            out << "  " << second << "Normalized environment values" << reset << "\n";
            out << "  " << muted << "Everything Dracula supplied that differs from Baseline." << reset << "\n\n";
            for (const auto& n : normalizations) {
                out << "    " << tech << n.property << reset << "\n";
                out << "      " << muted << Text::PadRight("Baseline", 14) << reset
                    << body << n.observedValue << reset << "\n";
                out << "      " << muted << Text::PadRight("Supplied", 14) << reset
                    << body << n.suppliedValue << reset << "\n";
                out << "      " << muted << Text::PadRight("Profile", 14) << reset
                    << body << n.profile << "  (" << n.source << ")" << reset << "\n";
            }
            out << "\n";
        }

        // ── Environment coherence ──
        if (!profileCoherence.empty()) {
            out << "  " << second << "Environment coherence" << reset << "\n\n";
            for (const auto& g : profileCoherence) {
                const bool ok = g.IsCoherent();
                out << "    " << Terminal::Color(ok ? ColorRole::Success : ColorRole::Warning)
                    << Text::PadRight(g.profileName, 20) << reset
                    << muted << "fingerprintability " << g.fingerprintability << " / 100 ("
                    << g.fingerprintabilityLabel << ")" << reset << "\n";
                for (const auto& c : g.contradictions) {
                    out << "      " << Terminal::Color(ColorRole::Warning) << "contradiction" << reset
                        << muted << "   " << c.property << ": " << c.explanation << reset << "\n";
                }
            }
            out << "\n";
        }

        // ── Conclusion ──
        out << "  " << second << "Conclusion" << reset << "\n";
        for (const auto& line : Text::Wrap(conclusion, ruleWidth - 2)) {
            out << "  " << body << line << reset << "\n";
        }
        for (const auto& note : notes) {
            out << "  " << muted << note << reset << "\n";
        }
        out << "\n";
        return out.str();
    }

} // namespace Dracula
