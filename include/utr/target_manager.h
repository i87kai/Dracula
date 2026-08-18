#pragma once

#include <string>
#include <vector>
#include <memory>
#include <optional>
#include <mutex>

#include "utr/types.h"
#include "utr/target.h"
#include "utr/session_manager.h"
#include "utr/evidence_graph.h"

namespace Dracula {
namespace UTR {

    class TargetManager {
    public:
        static TargetManager& Instance();

        TargetManager() = default;
        ~TargetManager();

        // Target opening & acquisition entrypoints:
        // - File path (EXE, DLL, SYS)
        // - PID (e.g. "--pid 4820" or "4820")
        // - Service name (e.g. "--service MyService")
        // - VM guest (e.g. "--vm")
        Result<std::shared_ptr<ITarget>> OpenTarget(const std::string& targetSpecifier,
                                                    const std::string& typeHint = "");

        std::shared_ptr<ITarget> GetActiveTarget() const;
        TargetInfo GetActiveTargetInfo() const;
        TargetCapabilities GetActiveCapabilities() const;

        void CloseActiveTarget();

        // Fingerprinting
        static TargetInfo Fingerprint(const std::string& targetSpecifier, const std::string& typeHint = "");

        // Active Evidence Graph
        EvidenceGraph& GetEvidenceGraph() { return m_evidenceGraph; }
        const EvidenceGraph& GetEvidenceGraph() const { return m_evidenceGraph; }

    private:
        std::shared_ptr<ITarget> m_activeTarget;
        EvidenceGraph            m_evidenceGraph;
        mutable std::mutex       m_mutex;
    };

} // namespace UTR
} // namespace Dracula
