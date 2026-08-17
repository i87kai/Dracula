#pragma once

//
// Data-driven virtualization / analysis artifact knowledge.
//
// The alternative to this table is a wall of `if (s.find("VMware") != npos)`,
// which is unreviewable and impossible to weight. Here every artifact carries
// its provider, what kind of thing it is, where it would legitimately appear,
// and how much a bare occurrence of it is actually worth.
//
// A raw string match is weak evidence and is scored as such. The same string
// compared against firmware or device data, or feeding a branch, is what makes
// it strong — and that strength comes from the correlation stage, not here.
//

#include "common/findings.h"
#include "core/anti_evasion_engine.h"
#include <string>
#include <vector>

namespace Dracula {

    enum class ArtifactType {
        Vendor,        // a virtualization vendor name
        Process,       // guest tooling process
        Driver,        // guest driver / .sys
        Service,       // guest service name
        DeviceName,    // device or disk identifier
        RegistryKey,
        FirmwareString,
        MacPrefix,
        AnalysisTool,  // debugger / sandbox / instrumentation tooling
        Username,      // sandbox-typical account or machine name
        FilePath
    };

    const char* ArtifactTypeToString(ArtifactType type);

    struct ArtifactRule {
        std::string       pattern;        // matched case-insensitively
        std::string       provider;       // "VMware", "QEMU", "Generic"
        ArtifactType      type = ArtifactType::Vendor;
        EvasionCategory   category = EvasionCategory::AntiVmProcess;
        FindingConfidence baseConfidence = FindingConfidence::Low;
        std::string       note;           // why this is (or is not) meaningful
    };

    // The rule set. Static, immutable, shared.
    const std::vector<ArtifactRule>& EvasionArtifactRules();

    struct ArtifactMatch {
        const ArtifactRule* rule = nullptr;
        std::string         matchedText;
        uint64_t            rva = 0;
        std::string         where;   // "string table", "import", "registry key"
    };

    // Match one candidate string against the rule set. Returns nullptr when it
    // is not a known artifact.
    const ArtifactRule* MatchArtifact(const std::string& candidate);

    // Whether an imported API is one commonly used to inspect the environment.
    // Being on this list is NOT by itself evidence of evasion: these are
    // ordinary Windows APIs that inventory tools, installers and games call for
    // entirely legitimate reasons.
    struct EnvironmentApiRule {
        std::string     api;
        std::string     library;
        EvasionCategory category;
        std::string     property;      // what environment property it reveals
        bool            strongIndicator = false; // rarely called except to fingerprint
    };

    const std::vector<EnvironmentApiRule>& EnvironmentApiRules();
    const EnvironmentApiRule* MatchEnvironmentApi(const std::string& apiName);

} // namespace Dracula
