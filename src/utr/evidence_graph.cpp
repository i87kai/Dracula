#include "utr/evidence_graph.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

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

    void EvidenceGraph::AddEvidence(const EvidenceNode& node) {
        // Prevent duplicate node IDs
        for (auto& existing : m_nodes) {
            if (existing.id == node.id) {
                existing = node;
                return;
            }
        }
        m_nodes.push_back(node);
    }

    void EvidenceGraph::AddBehaviorChain(const BehaviorChain& chain) {
        for (auto& existing : m_chains) {
            if (existing.chainId == chain.chainId) {
                existing = chain;
                return;
            }
        }
        m_chains.push_back(chain);
    }

    std::vector<EvidenceNode> EvidenceGraph::GetByTruthLevel(EvidenceTruthLevel level) const {
        std::vector<EvidenceNode> result;
        for (const auto& node : m_nodes) {
            if (node.truthLevel == level) {
                result.push_back(node);
            }
        }
        return result;
    }

    std::vector<EvidenceNode> EvidenceGraph::GetByCategory(const std::string& category) const {
        std::vector<EvidenceNode> result;
        for (const auto& node : m_nodes) {
            if (node.category == category) {
                result.push_back(node);
            }
        }
        return result;
    }

    void EvidenceGraph::Clear() {
        m_nodes.clear();
        m_chains.clear();
    }

    std::string EvidenceGraph::ToJson() const {
        std::ostringstream oss;
        oss << "{\n";
        oss << "  \"total_nodes\": " << m_nodes.size() << ",\n";
        oss << "  \"total_chains\": " << m_chains.size() << ",\n";
        oss << "  \"nodes\": [\n";
        for (size_t i = 0; i < m_nodes.size(); ++i) {
            const auto& n = m_nodes[i];
            oss << "    {\n";
            oss << "      \"id\": \"" << EscapeJson(n.id) << "\",\n";
            oss << "      \"category\": \"" << EscapeJson(n.category) << "\",\n";
            oss << "      \"severity\": \"" << SeverityToString(n.severity) << "\",\n";
            oss << "      \"confidence\": \"" << ConfidenceToString(n.confidence) << "\",\n";
            oss << "      \"truth_level\": \"" << TruthLevelToString(n.truthLevel) << "\",\n";
            oss << "      \"title\": \"" << EscapeJson(n.title) << "\",\n";
            oss << "      \"description\": \"" << EscapeJson(n.description) << "\",\n";
            oss << "      \"evidence\": \"" << EscapeJson(n.evidenceData) << "\",\n";
            oss << "      \"provenance\": {\n";
            oss << "        \"engine\": \"" << EscapeJson(n.provenance.engine) << "\",\n";
            oss << "        \"backend\": \"" << EscapeJson(n.provenance.backend) << "\",\n";
            oss << "        \"module\": \"" << EscapeJson(n.provenance.moduleName) << "\",\n";
            oss << "        \"rva\": \"0x" << std::hex << n.provenance.rva << std::dec << "\"\n";
            oss << "      }\n";
            oss << "    }" << (i + 1 < m_nodes.size() ? "," : "") << "\n";
        }
        oss << "  ],\n";
        oss << "  \"chains\": [\n";
        for (size_t i = 0; i < m_chains.size(); ++i) {
            const auto& c = m_chains[i];
            oss << "    {\n";
            oss << "      \"chain_id\": \"" << EscapeJson(c.chainId) << "\",\n";
            oss << "      \"name\": \"" << EscapeJson(c.name) << "\",\n";
            oss << "      \"description\": \"" << EscapeJson(c.description) << "\",\n";
            oss << "      \"origin_function\": \"" << EscapeJson(c.originFunction) << "\",\n";
            oss << "      \"origin_rva\": \"0x" << std::hex << c.originRva << std::dec << "\",\n";
            oss << "      \"truth_level\": \"" << TruthLevelToString(c.truthLevel) << "\",\n";
            oss << "      \"confidence\": \"" << ConfidenceToString(c.confidence) << "\",\n";
            oss << "      \"steps\": [";
            for (size_t j = 0; j < c.steps.size(); ++j) {
                oss << "\"" << EscapeJson(c.steps[j]) << "\"" << (j + 1 < c.steps.size() ? ", " : "");
            }
            oss << "]\n";
            oss << "    }" << (i + 1 < m_chains.size() ? "," : "") << "\n";
        }
        oss << "  ]\n";
        oss << "}\n";
        return oss.str();
    }

    std::string EvidenceGraph::ToMarkdown() const {
        std::ostringstream oss;
        oss << "### Evidence Graph Summary\n\n";
        oss << "| Truth Level | Count |\n";
        oss << "|---|---|\n";
        oss << "| **Observed** | " << GetByTruthLevel(EvidenceTruthLevel::Observed).size() << " |\n";
        oss << "| **Inferred** | " << GetByTruthLevel(EvidenceTruthLevel::Inferred).size() << " |\n";
        oss << "| **Suspected** | " << GetByTruthLevel(EvidenceTruthLevel::Suspected).size() << " |\n";
        oss << "| **Unknown** | " << GetByTruthLevel(EvidenceTruthLevel::Unknown).size() << " |\n\n";

        if (!m_chains.empty()) {
            oss << "#### Correlated Behavior Chains\n\n";
            for (const auto& c : m_chains) {
                oss << "**" << c.name << "** (`" << TruthLevelToString(c.truthLevel) << "`, Confidence: `"
                    << ConfidenceToString(c.confidence) << "`)\n";
                oss << "*Origin*: `" << (c.originFunction.empty() ? "Unknown" : c.originFunction)
                    << "` (RVA: 0x" << std::hex << c.originRva << std::dec << ")\n";
                for (const auto& step : c.steps) {
                    oss << "  - " << step << "\n";
                }
                oss << "\n";
            }
        }

        return oss.str();
    }

} // namespace UTR
} // namespace Dracula
