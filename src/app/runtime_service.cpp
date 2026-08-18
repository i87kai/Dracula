#include "app/services.h"
#include "app/html_report.h"
#include "app/json.h"
#include "common/paths.h"
#include "common/config.h"
#include "utr/external_observer.h"
#include "host/process_inspector.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    RuntimeService& RuntimeService::Instance() {
        static RuntimeService instance;
        return instance;
    }

    // --- Backend probes -------------------------------------------------------
    //
    // Each probe answers a specific question and reports the weakest state it
    // can actually prove. "The binary exists" yields Installed, never Ready --
    // the v1.2.4 shell claimed "QEMU GuestAgent: Ready" with no VM running at
    // all, which is exactly what section 18 forbids.

    static BackendStatus ProbeAgent(const char* label, const char* fileName) {
        BackendStatus s;
        s.name = label;

        // MinGW emits "libFoo.dll" while MSVC emits "Foo.dll"; accept either
        // rather than reporting a present agent as missing.
        const std::string names[] = {fileName, std::string("lib") + fileName};

        std::error_code ec;
        for (const std::string& dir : {Paths::BinDir(), Paths::ExecutableDir(), Paths::ResourceRoot()}) {
            if (dir.empty()) continue;
            for (const std::string& name : names) {
                fs::path candidate = fs::path(dir) / name;
                if (fs::exists(candidate, ec)) {
                    s.state = BackendState::Available;
                    s.detail = candidate.string();
                    return s;
                }
            }
        }

        s.state = BackendState::Unsupported;
        s.reason = std::string(fileName) + " was not found alongside Dracula";
        return s;
    }

    static BackendStatus ProbeEtw() {
        BackendStatus s;
        s.name = "ETW Observer";

        // The observer is only Active while it is actually observing a PID.
        // Absent that, it is merely available to be started.
        auto project = ProjectManager::Instance().Active();
        if (project && project->Target().IsLiveProcess()) {
            s.state = BackendState::Available;
            s.detail = "ready to observe PID " + std::to_string(project->Target().pid);
        } else {
            s.state = BackendState::Available;
            s.detail = "no live target to observe";
        }
        return s;
    }

    static BackendStatus ProbeDbgEng() {
        BackendStatus s;
        s.name = "DbgEng Adapter";

        UTR::DbgEngBackend backend;
        std::string error;
        if (backend.Initialize(error)) {
            // DbgHelp gives symbols and memory reads but not full debugger
            // control, so this is honestly reported as partial.
            s.state = BackendState::Partial;
            s.detail = "symbols and memory reads (no execution control)";
        } else {
            s.state = BackendState::Unsupported;
            s.reason = error.empty() ? "dbghelp.dll could not be initialized" : error;
        }
        return s;
    }

    static BackendStatus ProbeQemu() {
        BackendStatus s;
        s.name = "QEMU";

        const auto& cfg = ConfigManager::Instance().GetQemuConfig();
        std::error_code ec;
        if (cfg.qemuExecutable.empty() || !fs::exists(cfg.qemuExecutable, ec)) {
            s.state = BackendState::Unsupported;
            s.reason = "qemu-system-x86_64 not found at " +
                       (cfg.qemuExecutable.empty() ? std::string("<unconfigured>") : cfg.qemuExecutable);
            return s;
        }

        // Installed, and explicitly Stopped -- Dracula does not boot a VM just
        // because a project was opened (section 27).
        s.state = BackendState::Stopped;
        s.detail = "installed, not running";
        return s;
    }

    static BackendStatus ProbeGuestAgent() {
        BackendStatus s;
        s.name = "GuestAgent";

        // A guest agent can only be Connected when a VM is running. Since
        // Dracula keeps QEMU lazy, the truthful default is "not connected".
        BackendStatus qemu = ProbeQemu();
        if (qemu.state == BackendState::Unsupported) {
            s.state = BackendState::NotRequired;
            s.reason = "QEMU is not installed, so no guest session is possible";
            return s;
        }

        s.state = BackendState::Stopped;
        s.detail = "not connected (VM stopped)";
        return s;
    }

    RuntimeStatus RuntimeService::QueryStatus() const {
        RuntimeStatus status;

        status.backends.push_back(ProbeAgent("Agent x64", "DraculaAgent64.dll"));
        status.backends.push_back(ProbeAgent("Agent x86", "DraculaAgent32.dll"));
        status.backends.push_back(ProbeEtw());
        status.backends.push_back(ProbeDbgEng());
        status.backends.push_back(ProbeQemu());
        status.backends.push_back(ProbeGuestAgent());

        auto project = ProjectManager::Instance().Active();
        if (project && project->Target().IsLiveProcess()) {
            const uint32_t pid = project->Target().pid;
            // "Running" is asserted only after actually acquiring a handle.
            std::string openError;
            void* handle = Sandbox::ProcessInspector::OpenReadOnly(pid, openError);
            if (handle) {
                status.livePid = pid;
                status.runtimeActive = true;
                Sandbox::ProcessInspector::Close(handle);
            }
        }

        status.eventCount = static_cast<uint32_t>(LoadEvents().size());
        return status;
    }

    CommandResult RuntimeService::Status() const {
        RuntimeStatus status = QueryStatus();

        CommandResult r = CommandResult::Success("Runtime status");
        for (const auto& b : status.backends) {
            std::ostringstream line;
            line << std::left << std::setw(20) << b.name
                 << std::setw(16) << BackendStateToString(b.state);
            if (!b.detail.empty()) line << " " << b.detail;
            if (!b.reason.empty()) line << " (" << b.reason << ")";
            r.Line(line.str());
        }

        r.Line("");
        if (status.runtimeActive) {
            r.Line("Live target:  PID " + std::to_string(status.livePid) + " (handle acquired)");
        } else {
            auto project = ProjectManager::Instance().Active();
            if (project && project->Target().IsLiveProcess()) {
                r.Line("Live target:  PID " + std::to_string(project->Target().pid) +
                       " recorded, but not currently accessible");
            } else {
                r.Line("Live target:  none");
            }
        }
        r.Line("Runtime events recorded: " + std::to_string(status.eventCount));
        return r;
    }

    // --- Event log ------------------------------------------------------------
    // Events live in <project>/runtime/events.jsonl -- one JSON object per line,
    // so appending is cheap and a truncated tail costs at most one event.

    static std::string EventLogPath(const Project& project) {
        return (fs::path(project.RuntimeDir()) / "events.jsonl").string();
    }

    void RuntimeService::RecordEvent(const std::string& category,
                                     const std::string& message,
                                     const std::string& severity,
                                     const std::string& detail) {
        auto project = ProjectManager::Instance().Active();
        if (!project) return;

        Json j = Json::Object();
        j.Set("ts", Json(NowIso8601()));
        j.Set("category", Json(category));
        j.Set("severity", Json(severity));
        j.Set("message", Json(message));
        j.Set("detail", Json(detail));

        try {
            fs::create_directories(project->RuntimeDir());
            std::ofstream out(EventLogPath(*project), std::ios::binary | std::ios::app);
            if (out.is_open()) out << j.Dump(0) << "\n";
        } catch (...) {
            // Telemetry must never take down the operation it is describing.
        }
    }

    std::vector<RuntimeEvent> RuntimeService::LoadEvents() const {
        std::vector<RuntimeEvent> events;

        auto project = ProjectManager::Instance().Active();
        if (!project) return events;

        const std::string path = EventLogPath(*project);
        std::error_code ec;
        if (!fs::exists(path, ec)) return events;

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) return events;

        std::string line;
        uint64_t sequence = 0;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            Json j;
            if (!Json::Parse(line, j, nullptr)) continue;  // skip a torn tail

            RuntimeEvent e;
            e.sequence = ++sequence;
            e.timestamp = j["ts"].AsString();
            e.category = j["category"].AsString();
            e.severity = j["severity"].AsString("info");
            e.message = j["message"].AsString();
            e.detail = j["detail"].AsString();
            events.push_back(e);
        }
        return events;
    }

    CommandResult RuntimeService::Events() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto events = LoadEvents();

        // The v1.2.4 bug was returning a usage hint for this valid command.
        // An empty log is a legitimate answer, not a usage error.
        if (events.empty()) {
            CommandResult r = CommandResult::Success("No runtime events recorded for this project.");
            r.Line("Events are recorded when a runtime or sandbox operation runs.");
            return r;
        }

        CommandResult r = CommandResult::Success(
            std::to_string(events.size()) + " runtime event" + (events.size() == 1 ? "" : "s") + ".");

        std::map<std::string, size_t> byCategory;
        size_t errors = 0, warnings = 0;
        for (const auto& e : events) {
            ++byCategory[e.category];
            if (e.severity == "error") ++errors;
            else if (e.severity == "warn") ++warnings;
        }
        for (const auto& kv : byCategory) {
            r.Line("  " + kv.first + "  (" + std::to_string(kv.second) + ")");
        }
        if (errors > 0)   r.Line("Errors:   " + std::to_string(errors));
        if (warnings > 0) r.Line("Warnings: " + std::to_string(warnings));

        r.Line("");
        r.Line("Most recent:");
        const size_t tail = events.size() > 12 ? events.size() - 12 : 0;
        for (size_t i = tail; i < events.size(); ++i) {
            const auto& e = events[i];
            std::ostringstream line;
            line << "  " << e.timestamp << "  "
                 << std::left << std::setw(9) << e.category << "  " << e.message;
            r.Line(line.str());
        }

        // Only large logs earn a full artifact; a dozen events read fine inline.
        if (events.size() > 12) {
            HtmlReport report("Runtime Events", project->DisplayName());
            report.AddSummary("Events", std::to_string(events.size()));
            report.AddSummary("Errors", std::to_string(errors));
            report.AddSummary("Warnings", std::to_string(warnings));
            report.SetColumns({
                {"#",         HtmlReport::Align::Right, true,  true},
                {"Timestamp", HtmlReport::Align::Left,  true,  false},
                {"Category",  HtmlReport::Align::Left,  false, false},
                {"Severity",  HtmlReport::Align::Left,  false, false},
                {"Message",   HtmlReport::Align::Left,  false, false},
                {"Detail",    HtmlReport::Align::Left,  false, false},
            });
            for (const auto& e : events) {
                std::string badge;
                if (e.severity == "error") badge = "error";
                else if (e.severity == "warn") badge = "warn";
                else badge = "ok";

                report.AddRow(std::vector<HtmlReport::Cell>{
                    {std::to_string(e.sequence), ""},
                    {e.timestamp, ""},
                    {e.category, ""},
                    {e.severity, badge},
                    {e.message, ""},
                    {e.detail, ""},
                });
            }

            const std::string out = project->NextArtifactPath("runtime", "events", "html");
            std::string writeError;
            if (report.Write(out, writeError)) {
                auto ref = PublishArtifact(*project, out, "runtime-events", "html",
                                           "Runtime Events", events.size());
                r.artifacts.push_back(ref);
                r.Line("Full timeline: " + ref.projectRelative);
                MaybeAutoOpen(out);
            }
        }
        return r;
    }

} // namespace App
} // namespace Dracula
