#include "core/threat_evaluator.h"
#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace Dracula {

    static bool ContainsCaseInsensitive(const std::string& str, const std::string& sub) {
        if (sub.empty() || str.empty() || sub.size() > str.size()) return false;
        auto it = std::search(
            str.begin(), str.end(),
            sub.begin(), sub.end(),
            [](char ch1, char ch2) {
                return std::tolower(static_cast<unsigned char>(ch1)) ==
                       std::tolower(static_cast<unsigned char>(ch2));
            }
        );
        return it != str.end();
    }

    ThreatEvaluator::ThreatEvaluator() = default;
    ThreatEvaluator::~ThreatEvaluator() = default;

    ThreatScoreResult ThreatEvaluator::Evaluate(
        const std::vector<Finding>& findings,
        const SampleMetadata& meta,
        const SecurityMitigations& mitigations,
        double overallEntropy,
        bool isPacked
    ) {
        ThreatScoreResult res;
        int rawScore = 0;
        std::set<std::string> mitreSet;
        std::set<std::string> uniqueCategories;
        std::set<std::string> seenFindings;

        // Anti-VM is not malware. Development tools, games, licensing systems
        // and enterprise software all inspect their environment for entirely
        // legitimate reasons, so evasion evidence is weighted by CONTEXT:
        //
        //   * on its own it is heavily discounted and hard-capped, so no amount
        //     of virtualization detection can carry a verdict by itself;
        //   * alongside genuinely malicious evidence it counts in full, because
        //     that is precisely when evading analysis is meaningful.
        //
        // It remains a corroborating signal either way, never a deciding one.
        int evasionScore = 0;
        bool hasOtherMaliciousEvidence = false;
        auto isEvasionFinding = [](const Finding& f) {
            return f.source == "Anti-Evasion Engine" ||
                   f.source == "Environment Coherence Validator" ||
                   f.category.rfind("AntiAnalysis", 0) == 0;
        };

        for (const auto& f : findings) {
            // Deduplicate identical findings to prevent multiple normalization paths from inflating score
            std::string findingKey = f.id + "|" + f.category + "|" + f.title + "|" + f.evidence + "|" + std::to_string(static_cast<int>(f.severity));
            if (!seenFindings.insert(findingKey).second) {
                continue;
            }

            const bool evasion = isEvasionFinding(f);
            // Only count categories with actionable severity (Low or higher) towards multi-category bonus
            if (f.severity >= FindingSeverity::Low) {
                uniqueCategories.insert(f.category);
            }
            if (!evasion && f.severity >= FindingSeverity::Medium) {
                hasOtherMaliciousEvidence = true;
            }

            int weight = 0;
            switch (f.severity) {
                case FindingSeverity::Critical: weight = 30; break;
                case FindingSeverity::High:     weight = 20; break;
                case FindingSeverity::Medium:   weight = 10; break;
                case FindingSeverity::Low:      weight = 4;  break;
                case FindingSeverity::Info:     weight = 0;  break;
            }
            if (evasion) {
                evasionScore += weight;
            } else {
                rawScore += weight;
            }

            for (const auto& tag : f.tags) {
                if (tag.rfind("MITRE:", 0) == 0) {
                    mitreSet.insert(tag.substr(6));
                }
            }

            if (f.severity >= FindingSeverity::Medium) {
                res.reasoning.push_back("[" + std::string(SeverityToString(f.severity)) + "] " + f.title + " (" + f.evidence + ")");
            }
        }

        if (evasionScore > 0) {
            constexpr int kEvasionCapCorroborated = 25;
            constexpr int kEvasionCapAlone        = 15;

            int applied;
            if (hasOtherMaliciousEvidence) {
                applied = std::min(evasionScore, kEvasionCapCorroborated);
                res.reasoning.push_back(
                    "[ANTI-ANALYSIS] Environment-sensitive behaviour contributed " +
                    std::to_string(applied) + " points, corroborated by independent "
                    "malicious evidence.");
            } else {
                applied = std::min(evasionScore / 2, kEvasionCapAlone);
                res.reasoning.push_back(
                    "[ANTI-ANALYSIS] Environment-sensitive behaviour contributed " +
                    std::to_string(applied) + " points (discounted and capped at " +
                    std::to_string(kEvasionCapAlone) + "): with no other malicious evidence, "
                    "detecting a virtual environment is not by itself suspicious.");
            }
            rawScore += applied;
        }

        // Multi-signal corroboration bonus: if multiple distinct categories flagged, add corroboration weight
        if (uniqueCategories.size() >= 3) {
            rawScore += 10;
            res.reasoning.push_back("[CORROBORATION] Multiple independent attack categories flagged (" + std::to_string(uniqueCategories.size()) + " categories)");
        }

        // Mitigation penalties
        if (!mitigations.hasDep && !mitigations.hasAslr) {
            rawScore += 5;
            res.reasoning.push_back("[SECURITY] Lacks both ASLR and DEP memory exploit mitigations");
        }

        if (mitigations.hasRwxSections) {
            rawScore += 15;
            res.reasoning.push_back("[PACKING] Section header contains writable and executable (RWX) memory pages");
        }

        if (isPacked || overallEntropy >= 7.5) {
            rawScore += 10;
            res.reasoning.push_back("[ENTROPY] High file entropy (> 7.50) indicating encrypted payload or obfuscation");
        }

        res.score = std::clamp(rawScore, 0, 100);

        if (res.score >= 75) {
            res.level = "Critical Threat";
        } else if (res.score >= 45) {
            res.level = "Suspicious";
        } else if (res.score >= 25) {
            res.level = "Low Risk";
        } else {
            res.level = "Clean / Benign";
        }

        res.mitreTechniques.assign(mitreSet.begin(), mitreSet.end());
        return res;
    }

    std::vector<Finding> ThreatEvaluator::NormalizeSandboxEvents(const std::vector<Sandbox::TraceEvent>& events) {
        std::vector<Finding> findings;

        auto isProcess = [](Sandbox::EventType t) {
            return t == Sandbox::EventType::Process ||
                   t == Sandbox::EventType::ProcessCreated;
        };
        auto isFile = [](Sandbox::EventType t) {
            return t == Sandbox::EventType::File ||
                   t == Sandbox::EventType::FileCreated ||
                   t == Sandbox::EventType::FileModified ||
                   t == Sandbox::EventType::FileDeleted;
        };
        auto isRegistry = [](Sandbox::EventType t) {
            return t == Sandbox::EventType::Registry ||
                   t == Sandbox::EventType::RegistryKeyCreated ||
                   t == Sandbox::EventType::RegistryValueSet;
        };
        auto isNetwork = [](Sandbox::EventType t) {
            return t == Sandbox::EventType::Network ||
                   t == Sandbox::EventType::NetworkConnect;
        };

        // Pass 1: Identify the target PID and collect session context for corroboration
        uint32_t targetPid = 0;
        std::set<uint32_t> pidsWithNetwork;
        std::set<uint32_t> pidsWithRegistry;
        std::set<uint32_t> pidsWithDroppedFiles;
        std::map<uint32_t, uint32_t> parentMap;

        for (const auto& e : events) {
            if (isProcess(e.type)) {
                if (e.pid != 0 && e.parentPid != 0) {
                    parentMap[e.pid] = e.parentPid;
                }
                if (e.role == Sandbox::ProcessRole::Target && e.pid != 0) {
                    targetPid = e.pid;
                } else if (targetPid == 0) {
                    if (e.message.find("Target Process") != std::string::npos && e.pid != 0) {
                        targetPid = e.pid;
                    }
                }
            } else if (isNetwork(e.type) && e.pid != 0) {
                pidsWithNetwork.insert(e.pid);
            } else if (isRegistry(e.type) && e.pid != 0) {
                pidsWithRegistry.insert(e.pid);
            } else if (isFile(e.type) && e.pid != 0) {
                pidsWithDroppedFiles.insert(e.pid);
            }
        }

        // If targetPid is still not identified, fallback to the first process event
        if (targetPid == 0) {
            for (const auto& e : events) {
                if (isProcess(e.type) && e.pid != 0) {
                    targetPid = e.pid;
                    break;
                }
            }
        }

        // Deduplication sets using stable identities
        std::set<std::string> seenProcessIdentities;
        std::set<std::string> seenFileIdentities;
        std::set<std::string> seenRegistryIdentities;
        std::set<std::string> seenNetworkIdentities;

        for (const auto& e : events) {
            if (isProcess(e.type)) {
                uint32_t pid = e.pid;
                uint32_t parentPid = e.parentPid;
                std::string procName = e.processName;
                std::string cmdLine = e.commandLine;
                Sandbox::ProcessRole role = e.role;

                // Recover fields from message/details if missing (e.g. legacy events)
                if (pid == 0) {
                    size_t pPos = e.message.find("PID: ");
                    if (pPos != std::string::npos) {
                        try { pid = static_cast<uint32_t>(std::stoul(e.message.substr(pPos + 5))); } catch (...) {}
                    }
                }
                if (parentPid == 0) {
                    size_t ppPos = e.details.find("Parent PID: ");
                    if (ppPos != std::string::npos) {
                        try { parentPid = static_cast<uint32_t>(std::stoul(e.details.substr(ppPos + 12))); } catch (...) {}
                    }
                }
                if (procName.empty()) {
                    if (e.message.find("Child Process") != std::string::npos) {
                        size_t nameStart = e.message.find("Child Process Spawned: ");
                        if (nameStart == std::string::npos) nameStart = e.message.find("Child Process Created: ");
                        if (nameStart == std::string::npos) nameStart = e.message.find("Child Process: ");
                        if (nameStart != std::string::npos) {
                            size_t p = e.message.find(" (PID:", nameStart);
                            if (p != std::string::npos) {
                                size_t prefixLen = (e.message.find("Child Process Spawned: ") != std::string::npos) ? 23 :
                                                   (e.message.find("Child Process Created: ") != std::string::npos) ? 23 : 15;
                                procName = e.message.substr(nameStart + prefixLen, p - (nameStart + prefixLen));
                            }
                        }
                    } else if (e.message.find("Target Process") != std::string::npos) {
                        size_t nameStart = e.message.find("Target Process Started: ");
                        if (nameStart == std::string::npos) nameStart = e.message.find("Target Process Spawned: ");
                        if (nameStart != std::string::npos) {
                            size_t p = e.message.find(" (PID:", nameStart);
                            if (p != std::string::npos) {
                                size_t prefixLen = (e.message.find("Target Process Started: ") != std::string::npos) ? 24 : 24;
                                procName = e.message.substr(nameStart + prefixLen, p - (nameStart + prefixLen));
                            }
                        }
                    }
                }

                // Determine effective process role
                if (role == Sandbox::ProcessRole::Unspecified) {
                    if (pid != 0 && pid == targetPid) {
                        role = Sandbox::ProcessRole::Target;
                    } else if (e.message.find("Target Process") != std::string::npos) {
                        role = Sandbox::ProcessRole::Target;
                    } else if (parentPid != 0 && parentPid == targetPid) {
                        role = Sandbox::ProcessRole::Child;
                    } else if (parentPid != 0 && parentMap.count(parentPid) && parentMap[parentPid] == targetPid) {
                        role = Sandbox::ProcessRole::Descendant;
                    } else if (e.message.find("Child Process") != std::string::npos) {
                        role = Sandbox::ProcessRole::Child;
                    } else {
                        role = (pid == targetPid) ? Sandbox::ProcessRole::Target : Sandbox::ProcessRole::Child;
                    }
                }

                // Stable process identity deduplication key
                std::string identityKey = std::to_string(static_cast<uint32_t>(e.type)) + "|" +
                                          std::to_string(static_cast<uint32_t>(role)) + "|" +
                                          std::to_string(pid) + "|" +
                                          std::to_string(parentPid) + "|" +
                                          procName;

                if (!seenProcessIdentities.insert(identityKey).second) {
                    continue; // Duplicate process event ignored
                }

                if (role == Sandbox::ProcessRole::Target) {
                    Finding f;
                    f.id = "SBX_TARGET_PROCESS_STARTED";
                    f.category = "Runtime Execution";
                    f.severity = FindingSeverity::Info;
                    f.confidence = FindingConfidence::High;
                    f.title = "Target Process Started: " + (procName.empty() ? ("PID " + std::to_string(pid)) : procName);
                    f.description = "The sandbox target process was initialized and started execution.";
                    f.evidence = (procName.empty() ? "" : (procName + " ")) +
                                 "(PID: " + std::to_string(pid) +
                                 (parentPid > 0 ? (", Parent PID: " + std::to_string(parentPid)) : "") + ")" +
                                 (cmdLine.empty() ? "" : (", Command: " + cmdLine));
                    f.source = "QEMU Sandbox Tracer";
                    f.tags = {"Execution", "SandboxTarget", "ProcessStart"};
                    findings.push_back(f);
                } else {
                    // Child / Descendant process evaluation
                    std::vector<std::string> suspiciousIndicators;
                    std::string fullText = procName + " " + cmdLine + " " + e.message + " " + e.details;

                    if (ContainsCaseInsensitive(fullText, "-enc") ||
                        ContainsCaseInsensitive(fullText, "-encodedcommand") ||
                        ContainsCaseInsensitive(fullText, "frombase64string")) {
                        suspiciousIndicators.push_back("Encoded command line arguments");
                    }
                    if (ContainsCaseInsensitive(fullText, "-w hidden") ||
                        ContainsCaseInsensitive(fullText, "-windowstyle hidden")) {
                        suspiciousIndicators.push_back("Hidden window execution flag");
                    }
                    if (ContainsCaseInsensitive(fullText, "-nop") ||
                        ContainsCaseInsensitive(fullText, "-noprofile") ||
                        ContainsCaseInsensitive(fullText, "-exec bypass") ||
                        ContainsCaseInsensitive(fullText, "-executionpolicy bypass")) {
                        suspiciousIndicators.push_back("Execution policy / profile bypass");
                    }
                    if (ContainsCaseInsensitive(fullText, "downloadstring") ||
                        ContainsCaseInsensitive(fullText, "downloaddata") ||
                        ContainsCaseInsensitive(fullText, "webclient") ||
                        ContainsCaseInsensitive(fullText, "certutil -urlcache") ||
                        ContainsCaseInsensitive(fullText, "bitsadmin")) {
                        suspiciousIndicators.push_back("Downloader / payload fetch command");
                    }
                    if (ContainsCaseInsensitive(fullText, "vssadmin delete shadows") ||
                        ContainsCaseInsensitive(fullText, "shadowcopy delete") ||
                        ContainsCaseInsensitive(fullText, "bcedit /set") ||
                        ContainsCaseInsensitive(fullText, "wbadmin delete")) {
                        suspiciousIndicators.push_back("System recovery / shadow volume tampering");
                    }
                    if (ContainsCaseInsensitive(fullText, "mshta") ||
                        ContainsCaseInsensitive(fullText, "regsvr32 /s /u") ||
                        ContainsCaseInsensitive(fullText, "cscript") ||
                        ContainsCaseInsensitive(fullText, "wscript")) {
                        suspiciousIndicators.push_back("Script host utility execution");
                    }

                    // Corroboration with session network activity
                    if (pid != 0 && pidsWithNetwork.count(pid)) {
                        suspiciousIndicators.push_back("Child process initiated outbound network connection");
                    }
                    // Corroboration with session registry persistence activity
                    if (pid != 0 && pidsWithRegistry.count(pid)) {
                        suspiciousIndicators.push_back("Child process modified persistence registry key");
                    }
                    // Corroboration with session file drops
                    if (pid != 0 && pidsWithDroppedFiles.count(pid)) {
                        suspiciousIndicators.push_back("Child process dropped executable / script file");
                    }
                    // Chaining corroboration: nested descendant shell execution
                    if (role == Sandbox::ProcessRole::Descendant &&
                        (ContainsCaseInsensitive(fullText, "cmd.exe") || ContainsCaseInsensitive(fullText, "powershell.exe"))) {
                        suspiciousIndicators.push_back("Nested descendant shell execution");
                    }

                    if (!suspiciousIndicators.empty()) {
                        Finding f;
                        f.id = "SBX_SUSPICIOUS_CHILD_PROCESS";
                        f.category = "Runtime Execution";
                        f.severity = (suspiciousIndicators.size() >= 2) ? FindingSeverity::High : FindingSeverity::Medium;
                        f.confidence = FindingConfidence::High;
                        f.title = "Suspicious Child Process Created: " + (procName.empty() ? ("PID " + std::to_string(pid)) : procName);
                        f.description = "The target binary launched a suspicious child process during dynamic VM execution.";

                        std::string evidenceStr = (procName.empty() ? "" : (procName + " ")) +
                                                 "(PID: " + std::to_string(pid) +
                                                 ", Parent PID: " + std::to_string(parentPid) + ")" +
                                                 (cmdLine.empty() ? "" : (", Command: " + cmdLine)) +
                                                 "; Corroborated by: ";
                        for (size_t i = 0; i < suspiciousIndicators.size(); ++i) {
                            if (i > 0) evidenceStr += ", ";
                            evidenceStr += suspiciousIndicators[i];
                        }
                        f.evidence = evidenceStr;
                        f.source = "QEMU Sandbox Tracer";
                        f.tags = {"Execution", "SuspiciousProcess", "MITRE:T1059"};
                        findings.push_back(f);
                    } else {
                        Finding f;
                        f.id = "SBX_CHILD_PROCESS_CREATED";
                        f.category = "Runtime Execution";
                        f.severity = FindingSeverity::Low;
                        f.confidence = FindingConfidence::High;
                        f.title = "Child Process Created in Sandbox: " + (procName.empty() ? ("PID " + std::to_string(pid)) : procName);
                        f.description = "The target binary launched a child process during dynamic VM execution.";
                        f.evidence = (procName.empty() ? "" : (procName + " ")) +
                                     "(PID: " + std::to_string(pid) +
                                     ", Parent PID: " + std::to_string(parentPid) + ")" +
                                     (cmdLine.empty() ? "" : (", Command: " + cmdLine));
                        f.source = "QEMU Sandbox Tracer";
                        f.tags = {"Execution", "ProcessCreation", "MITRE:T1059"};
                        findings.push_back(f);
                    }
                }
            } else if (isNetwork(e.type)) {
                std::string key = std::to_string(static_cast<uint32_t>(e.type)) + "|" + e.message + "|" + e.details + "|" + std::to_string(e.pid);
                if (seenNetworkIdentities.insert(key).second) {
                    Finding f;
                    f.id = "SBX_NETWORK_ACTIVITY";
                    f.category = "Runtime Network";
                    f.severity = FindingSeverity::High;
                    f.confidence = FindingConfidence::High;
                    f.title = "Outbound Network Socket Connection: " + e.message;
                    f.description = "Observed outbound socket connection initiated from guest VM.";
                    f.evidence = e.message + " " + e.details;
                    f.source = "QEMU Sandbox Tracer";
                    f.tags = {"Network", "C2", "MITRE:T1071"};
                    findings.push_back(f);
                }
            } else if (isFile(e.type)) {
                std::string key = std::to_string(static_cast<uint32_t>(e.type)) + "|" + e.message + "|" + e.details;
                if (seenFileIdentities.insert(key).second) {
                    Finding f;
                    f.id = "SBX_FILE_ACTIVITY";
                    f.category = "Persistence / Dropper";
                    f.severity = FindingSeverity::Medium;
                    f.confidence = FindingConfidence::High;
                    f.title = "File System Modification: " + e.message;
                    f.description = "Observed file creation or drop inside guest environment.";
                    f.evidence = e.message + " " + e.details;
                    f.source = "QEMU Sandbox Tracer";
                    f.tags = {"FileDrop", "Dropper", "MITRE:T1105"};
                    findings.push_back(f);
                }
            } else if (isRegistry(e.type)) {
                std::string key = std::to_string(static_cast<uint32_t>(e.type)) + "|" + e.message + "|" + e.details;
                if (seenRegistryIdentities.insert(key).second) {
                    Finding f;
                    f.id = "SBX_REGISTRY_MODIFIED";
                    f.category = "Persistence";
                    f.severity = FindingSeverity::High;
                    f.confidence = FindingConfidence::High;
                    f.title = "Registry Key Modification: " + e.message;
                    f.description = "Observed persistent Windows registry key modification.";
                    f.evidence = e.message + " " + e.details;
                    f.source = "QEMU Sandbox Tracer";
                    f.tags = {"Persistence", "Registry", "MITRE:T1547"};
                    findings.push_back(f);
                }
            }
        }

        return findings;
    }

} // namespace Dracula
