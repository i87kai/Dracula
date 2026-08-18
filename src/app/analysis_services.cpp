#include "app/services.h"
#include "app/html_report.h"
#include "core/pe_inspector.h"
#include "core/strings_analyzer.h"
#include "host/process_inspector.h"

#include <filesystem>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    static std::string HexAddr(uint64_t v, int width = 0) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase;
        if (width > 0) oss << std::setw(width) << std::setfill('0');
        oss << v;
        return oss.str();
    }

    static std::string ToLower(const std::string& s) {
        std::string out = s;
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }

    // --- StaticService --------------------------------------------------------

    StaticService& StaticService::Instance() {
        static StaticService instance;
        return instance;
    }

    UTR::Result<std::string> StaticService::ResolveStaticPath() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            return UTR::Result<std::string>::Fail("no active project");
        }

        // For a process project this returns the resolved backing executable
        // (or the project's copy of it). The PID is never consulted as a path.
        const std::string path = project->StaticAnalysisPath();
        if (path.empty()) {
            if (project->Target().IsLiveProcess()) {
                return UTR::Result<std::string>::Fail(
                    "the live process backing executable could not be resolved");
            }
            return UTR::Result<std::string>::Fail("the project's sample is no longer on disk");
        }
        return UTR::Result<std::string>::Success(path);
    }

    // Loads the project's static image, or returns the capability-aware error
    // every static subcommand should surface.
    static bool LoadStaticImage(PeInspector& inspector, std::string& pathOut, CommandResult& errorOut) {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            errorOut = CommandResult::Failure(NoActiveProjectError());
            return false;
        }

        auto resolved = StaticService::Instance().ResolveStaticPath();
        if (!resolved.Ok()) {
            errorOut = CommandResult::Failure(CapabilityError(
                *project, "Static analysis", resolved.Error()));
            return false;
        }

        pathOut = resolved.Value();
        std::string peError;
        if (!inspector.LoadFromFile(pathOut, peError)) {
            errorOut = CommandResult::Failure("pe_parse_failed",
                                              "Could not parse the target image.",
                                              peError,
                                              "The file may be packed, corrupt, or not a PE image.");
            return false;
        }
        return true;
    }

    // Prepends the "resolved via backing image" note that makes a PID-backed
    // static analysis self-explanatory rather than surprising (section 15).
    static void NoteBackingResolution(CommandResult& r, const std::string& path) {
        auto project = ProjectManager::Instance().Active();
        if (project && project->Target().IsLiveProcess()) {
            r.Line("Resolved from the process backing image:");
            r.Line("  " + path);
        }
    }

    CommandResult StaticService::Info() const {
        PeInspector inspector;
        std::string path;
        CommandResult error;
        if (!LoadStaticImage(inspector, path, error)) return error;

        const auto& meta = inspector.GetMetadata();
        const auto& mit = inspector.GetMitigations();

        CommandResult r = CommandResult::Success("Static analysis");
        NoteBackingResolution(r, path);
        r.Line("File:          " + fs::path(path).filename().string());
        r.Line("Architecture:  " + meta.architecture);
        r.Line("Image base:    " + HexAddr(meta.imageBase));
        r.Line("Entry point:   " + HexAddr(meta.entryPointRva) + " (RVA)");
        r.Line("Sections:      " + std::to_string(inspector.GetSections().size()));
        r.Line("Imports:       " + std::to_string(inspector.GetImports().size()));
        r.Line("Exports:       " + std::to_string(inspector.GetExports().size()));
        r.Line("SHA-256:       " + meta.sha256);
        r.Line("Mitigations:   " +
               std::string(mit.hasAslr ? "ASLR " : "") +
               std::string(mit.hasDep ? "DEP " : "") +
               std::string(mit.hasCfg ? "CFG " : "") +
               std::string(mit.isDotNet ? ".NET " : ""));
        return r;
    }

    CommandResult StaticService::Sections() const {
        PeInspector inspector;
        std::string path;
        CommandResult error;
        if (!LoadStaticImage(inspector, path, error)) return error;

        const auto& sections = inspector.GetSections();
        CommandResult r = CommandResult::Success(
            std::to_string(sections.size()) + " section" + (sections.size() == 1 ? "" : "s") + ".");
        NoteBackingResolution(r, path);

        for (const auto& s : sections) {
            std::ostringstream line;
            line << "  " << std::left << std::setw(10) << s.name
                 << std::setw(14) << HexAddr(s.virtualAddress)
                 << std::setw(12) << s.virtualSize
                 << std::setw(10) << (std::string(s.isReadable ? "R" : "-") +
                                      (s.isWritable ? "W" : "-") +
                                      (s.isExecutable ? "X" : "-"))
                 << std::fixed << std::setprecision(2) << s.entropy;
            if (s.isHighEntropy) line << "  (high entropy - possibly packed)";
            r.Line(line.str());
        }
        return r;
    }

    CommandResult StaticService::Imports() const {
        PeInspector inspector;
        std::string path;
        CommandResult error;
        if (!LoadStaticImage(inspector, path, error)) return error;

        auto project = ProjectManager::Instance().Active();
        const auto& imports = inspector.GetImports();

        CommandResult r = CommandResult::Success(
            std::to_string(imports.size()) + " imported symbol" + (imports.size() == 1 ? "" : "s") + ".");
        NoteBackingResolution(r, path);

        // Group by DLL for the terminal summary; the full table goes to HTML.
        std::map<std::string, size_t> byDll;
        size_t dangerous = 0;
        for (const auto& i : imports) {
            ++byDll[i.dllName];
            if (i.isDangerous) ++dangerous;
        }
        for (const auto& kv : byDll) {
            r.Line("  " + kv.first + "  (" + std::to_string(kv.second) + ")");
        }
        if (dangerous > 0) {
            r.Line("Flagged as security-relevant: " + std::to_string(dangerous));
        }

        if (project && imports.size() > 40) {
            HtmlReport report("Imports", project->DisplayName());
            report.AddSummary("Symbols", std::to_string(imports.size()));
            report.AddSummary("Modules", std::to_string(byDll.size()));
            report.AddSummary("Flagged", std::to_string(dangerous));
            report.SetColumns({
                {"Module",   HtmlReport::Align::Left,  false, false},
                {"Function", HtmlReport::Align::Left,  false, false},
                {"IAT RVA",  HtmlReport::Align::Left,  true,  true},
                {"Risk",     HtmlReport::Align::Left,  false, false},
            });
            for (const auto& i : imports) {
                report.AddRow(std::vector<HtmlReport::Cell>{
                    {i.dllName, ""},
                    {i.functionName.empty() ? ("#" + std::to_string(i.ordinal)) : i.functionName, ""},
                    {HexAddr(i.iatRva), ""},
                    {i.riskDescription, i.isDangerous ? "warn" : ""},
                });
            }
            const std::string out = project->NextArtifactPath("static", "imports", "html");
            std::string writeError;
            if (report.Write(out, writeError)) {
                auto ref = PublishArtifact(*project, out, "imports", "html", "Imports", imports.size());
                r.artifacts.push_back(ref);
                r.Line("Full report: " + ref.projectRelative);
                MaybeAutoOpen(out);
            }
        }
        return r;
    }

    CommandResult StaticService::Exports() const {
        PeInspector inspector;
        std::string path;
        CommandResult error;
        if (!LoadStaticImage(inspector, path, error)) return error;

        const auto& exports = inspector.GetExports();
        CommandResult r = CommandResult::Success(
            std::to_string(exports.size()) + " exported symbol" + (exports.size() == 1 ? "" : "s") + ".");
        NoteBackingResolution(r, path);

        for (size_t i = 0; i < std::min<size_t>(exports.size(), 25); ++i) {
            const auto& e = exports[i];
            std::ostringstream line;
            line << "  #" << std::left << std::setw(6) << e.ordinal
                 << std::setw(14) << HexAddr(e.rva) << "  "
                 << (e.functionName.empty() ? "<unnamed>" : e.functionName);
            if (!e.forwarderName.empty()) line << "  -> " << e.forwarderName;
            r.Line(line.str());
        }
        if (exports.size() > 25) {
            r.Line("  ... " + std::to_string(exports.size() - 25) +
                   " more (use /dll exports for the full correlated table).");
        }
        return r;
    }

    CommandResult StaticService::Strings(size_t minLength) const {
        PeInspector inspector;
        std::string path;
        CommandResult error;
        if (!LoadStaticImage(inspector, path, error)) return error;

        auto project = ProjectManager::Instance().Active();

        StringsAnalyzer analyzer;
        auto strings = analyzer.ExtractStrings(inspector.GetBuffer(), inspector.GetBufferSize(), minLength);

        CommandResult r = CommandResult::Success(
            std::to_string(strings.size()) + " string" + (strings.size() == 1 ? "" : "s") + " extracted.");
        NoteBackingResolution(r, path);

        // Anything Dracula could classify beyond Generic is worth surfacing:
        // URLs, IPs, registry keys and suspicious API names.
        auto isInteresting = [](const ExtractedString& s) {
            return s.category != StringCategory::Generic;
        };

        size_t interesting = 0;
        for (const auto& s : strings) {
            if (isInteresting(s)) ++interesting;
        }
        r.Line("Flagged as interesting: " + std::to_string(interesting));

        for (size_t i = 0, shown = 0; i < strings.size() && shown < 20; ++i) {
            if (!isInteresting(strings[i])) continue;
            r.Line("  " + HexAddr(strings[i].fileOffset) + "  " +
                   std::string(StringCategoryToString(strings[i].category)) + "  " +
                   strings[i].value.substr(0, 80));
            ++shown;
        }

        if (project && strings.size() > 50) {
            HtmlReport report("Strings", project->DisplayName());
            report.AddSummary("Strings", std::to_string(strings.size()));
            report.AddSummary("Flagged", std::to_string(interesting));
            report.SetColumns({
                {"Offset",   HtmlReport::Align::Left,  true,  true},
                {"Encoding", HtmlReport::Align::Left,  false, false},
                {"Length",   HtmlReport::Align::Right, true,  true},
                {"Value",    HtmlReport::Align::Left,  false, false},
                {"Category", HtmlReport::Align::Left,  false, false},
            });
            for (const auto& s : strings) {
                report.AddRow(std::vector<HtmlReport::Cell>{
                    HtmlReport::Cell{HexAddr(s.fileOffset), ""},
                    HtmlReport::Cell{s.isWide ? "UTF-16" : "ASCII", ""},
                    HtmlReport::Cell{std::to_string(s.value.size()), ""},
                    HtmlReport::Cell{s.value.substr(0, 300), ""},
                    HtmlReport::Cell{StringCategoryToString(s.category), isInteresting(s) ? "warn" : ""},
                });
            }
            const std::string out = project->NextArtifactPath("static", "strings", "html");
            std::string writeError;
            if (report.Write(out, writeError)) {
                auto ref = PublishArtifact(*project, out, "strings", "html", "Strings", strings.size());
                r.artifacts.push_back(ref);
                r.Line("Full report: " + ref.projectRelative);
                MaybeAutoOpen(out);
            }
        }
        return r;
    }

    // --- ProcessService -------------------------------------------------------

    ProcessService& ProcessService::Instance() {
        static ProcessService instance;
        return instance;
    }

    CommandResult ProcessService::List() const {
        auto processes = Sandbox::ProcessInspector::ListAllProcesses();
        CommandResult r = CommandResult::Success(
            std::to_string(processes.size()) + " accessible process" +
            (processes.size() == 1 ? "" : "es") + ".");

        for (size_t i = 0; i < std::min<size_t>(processes.size(), 30); ++i) {
            std::ostringstream line;
            line << "  PID " << std::right << std::setw(6) << processes[i].pid
                 << "  " << processes[i].exeName;
            r.Line(line.str());
        }
        if (processes.size() > 30) {
            r.Line("  ... " + std::to_string(processes.size() - 30) + " more.");
        }
        r.Line("Attach with /process attach <pid>.");
        return r;
    }

    CommandResult ProcessService::Info() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        const TargetIdentity& t = project->Target();
        if (!t.IsLiveProcess()) {
            return CommandResult::Failure(CapabilityError(
                *project, "Process inspection",
                "This project is backed by a file, not a running process."));
        }

        CommandResult r = CommandResult::Success("Process " + t.name);
        r.Line("PID:      " + std::to_string(t.pid));
        r.Line("Image:    " + (t.backingExecutable.empty() ? std::string("<unresolved>")
                                                           : t.backingExecutable));
        r.Line("Arch:     " + t.architecture);

        // Report whether the recorded PID is still alive, rather than implying
        // liveness from the fact that a project exists.
        std::string openError;
        void* handle = Sandbox::ProcessInspector::OpenReadOnly(t.pid, openError);
        if (handle) {
            r.Line("State:    Running (handle acquired)");
            std::string moduleError;
            auto mods = Sandbox::ProcessInspector::ResolveAllModules(handle, t.pid, moduleError);
            r.Line("Modules:  " + std::to_string(mods.size()));
            Sandbox::ProcessInspector::Close(handle);
        } else {
            r.Line("State:    Not accessible (" +
                   (openError.empty() ? std::string("process has exited or access denied") : openError) + ")");
        }
        return r;
    }

    CommandResult ProcessService::Modules() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);
        if (!caps.modules) {
            return CommandResult::Failure(CapabilityError(
                *project, "Module enumeration",
                "Loaded modules exist only inside a running process."));
        }

        auto bound = TargetBinding::Instance().Resolve();
        if (!bound.Ok()) {
            return CommandResult::Failure("target_unavailable",
                                          "Could not access the process.", bound.Error());
        }

        auto mods = bound.Value()->EnumerateModules();
        if (!mods.Ok()) {
            return CommandResult::Failure("modules_failed",
                                          "Could not enumerate modules.", mods.Error());
        }

        const auto& modules = mods.Value();
        CommandResult r = CommandResult::Success(
            std::to_string(modules.size()) + " loaded module" + (modules.size() == 1 ? "" : "s") + ".");

        for (size_t i = 0; i < std::min<size_t>(modules.size(), 25); ++i) {
            const auto& m = modules[i];
            std::ostringstream line;
            line << "  " << std::left << std::setw(20) << HexAddr(m.baseAddress, 16) << m.name;
            r.Line(line.str());
        }
        if (modules.size() > 25) {
            r.Line("  ... " + std::to_string(modules.size() - 25) + " more.");
        }

        HtmlReport report("Loaded Modules", project->DisplayName() +
                          " - PID " + std::to_string(project->Target().pid));
        report.AddSummary("Modules", std::to_string(modules.size()));
        report.AddSummary("PID", std::to_string(project->Target().pid));
        report.SetColumns({
            {"Base Address", HtmlReport::Align::Left,  true,  true},
            {"Size",         HtmlReport::Align::Right, true,  true},
            {"Name",         HtmlReport::Align::Left,  false, false},
            {"Path",         HtmlReport::Align::Left,  false, false},
        });
        for (const auto& m : modules) {
            report.AddRow(std::vector<HtmlReport::Cell>{
                {HexAddr(m.baseAddress, 16), ""},
                {std::to_string(m.size), ""},
                {m.name, m.isMainModule ? "ok" : ""},
                {m.path, ""},
            });
        }

        const std::string out = project->NextArtifactPath("modules", "modules", "html");
        std::string writeError;
        if (report.Write(out, writeError)) {
            auto ref = PublishArtifact(*project, out, "modules", "html", "Loaded Modules", modules.size());
            r.artifacts.push_back(ref);
            r.Line("Full report: " + ref.projectRelative);
            MaybeAutoOpen(out);
        }
        return r;
    }

    CommandResult ProcessService::Threads() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);
        if (!caps.threads) {
            return CommandResult::Failure(CapabilityError(
                *project, "Thread enumeration",
                "Threads exist only inside a running process."));
        }

        auto bound = TargetBinding::Instance().Resolve();
        if (!bound.Ok()) {
            return CommandResult::Failure("target_unavailable",
                                          "Could not access the process.", bound.Error());
        }

        auto thrs = bound.Value()->EnumerateThreads();
        if (!thrs.Ok()) {
            return CommandResult::Failure("threads_failed",
                                          "Could not enumerate threads.", thrs.Error());
        }

        const auto& threads = thrs.Value();
        CommandResult r = CommandResult::Success(
            std::to_string(threads.size()) + " thread" + (threads.size() == 1 ? "" : "s") + ".");

        for (size_t i = 0; i < std::min<size_t>(threads.size(), 30); ++i) {
            const auto& t = threads[i];
            std::ostringstream line;
            line << "  TID " << std::right << std::setw(6) << t.tid
                 << "  start " << std::left << std::setw(20) << HexAddr(t.startAddress, 16)
                 << " prio " << t.priority;
            if (!t.state.empty()) line << "  " << t.state;
            r.Line(line.str());
        }
        if (threads.size() > 30) {
            r.Line("  ... " + std::to_string(threads.size() - 30) + " more.");
        }
        return r;
    }

    // --- DllService -----------------------------------------------------------

    DllService& DllService::Instance() {
        static DllService instance;
        return instance;
    }

    UTR::Result<DllService::ResolvedModule> DllService::ResolveModule(const std::string& nameOrPath) const {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            return UTR::Result<ResolvedModule>::Fail("no active project");
        }

        ResolvedModule out;
        const std::string wanted = ToLower(nameOrPath);

        // 1. Prefer a module actually loaded in the project's live process.
        //    This is what makes /dll correlate rather than replace the target.
        if (project->Target().IsLiveProcess()) {
            auto bound = TargetBinding::Instance().Resolve();
            if (bound.Ok()) {
                auto mods = bound.Value()->EnumerateModules();
                if (mods.Ok()) {
                    for (const auto& m : mods.Value()) {
                        const std::string name = ToLower(m.name);
                        const std::string path = ToLower(m.path);
                        if (name == wanted || path == wanted ||
                            name == wanted + ".dll" ||
                            fs::path(path).filename().string() == wanted) {
                            out.name = m.name;
                            out.backingPath = m.path;
                            out.loadedBase = m.baseAddress;
                            out.imageSize = m.size;
                            out.isLoaded = true;
                            return UTR::Result<ResolvedModule>::Success(out);
                        }
                    }
                }
            }
        }

        // 2. An explicit path on disk.
        std::error_code ec;
        if (fs::exists(nameOrPath, ec) && fs::is_regular_file(nameOrPath, ec)) {
            out.name = fs::path(nameOrPath).filename().string();
            out.backingPath = fs::absolute(nameOrPath, ec).string();
            return UTR::Result<ResolvedModule>::Success(out);
        }

        // 3. The project's own sample, when the user just typed its name.
        const std::string samplePath = project->StaticAnalysisPath();
        if (!samplePath.empty()) {
            const std::string sampleName = ToLower(fs::path(samplePath).filename().string());
            if (sampleName == wanted || sampleName == wanted + ".dll" || nameOrPath.empty()) {
                out.name = fs::path(samplePath).filename().string();
                out.backingPath = samplePath;
                return UTR::Result<ResolvedModule>::Success(out);
            }
        }

        return UTR::Result<ResolvedModule>::Fail(
            "no module named '" + nameOrPath + "' is loaded in this project, and no such file exists");
    }

    // Shared front half of every /dll subcommand: resolve the module and parse
    // its on-disk image.
    static bool PrepareDll(const std::string& nameOrPath,
                           DllService::ResolvedModule& module,
                           PeInspector& inspector,
                           CommandResult& errorOut) {
        auto project = ProjectManager::Instance().Active();
        if (!project) {
            errorOut = CommandResult::Failure(NoActiveProjectError());
            return false;
        }

        auto resolved = DllService::Instance().ResolveModule(nameOrPath);
        if (!resolved.Ok()) {
            ErrorDetail e;
            e.code = "module_not_found";
            e.message = "Could not resolve module '" + nameOrPath + "'.";
            e.reason = resolved.Error();
            e.remediation = project->Target().IsLiveProcess()
                ? "List loaded modules with /process modules."
                : "Pass a path to a DLL, or attach to a process that has it loaded.";
            errorOut = CommandResult::Failure(e);
            return false;
        }

        module = resolved.Value();
        if (module.backingPath.empty()) {
            errorOut = CommandResult::Failure("no_backing_image",
                                              "Module '" + module.name + "' has no on-disk image.",
                                              "The module is loaded but its backing file could not be resolved.");
            return false;
        }

        std::string peError;
        if (!inspector.LoadFromFile(module.backingPath, peError)) {
            errorOut = CommandResult::Failure("pe_parse_failed",
                                              "Could not parse '" + module.name + "'.",
                                              peError);
            return false;
        }
        return true;
    }

    CommandResult DllService::Info(const std::string& nameOrPath) const {
        ResolvedModule module;
        PeInspector inspector;
        CommandResult error;
        if (!PrepareDll(nameOrPath, module, inspector, error)) return error;

        const auto& meta = inspector.GetMetadata();
        CommandResult r = CommandResult::Success("Module " + module.name);
        r.Line("Backing image: " + module.backingPath);
        r.Line("Architecture:  " + meta.architecture);
        r.Line("Preferred base:" + HexAddr(meta.imageBase));

        if (module.isLoaded) {
            r.Line("Loaded base:   " + HexAddr(module.loadedBase));
            r.Line("Image size:    " + FormatBytes(module.imageSize));
            // Distinguishing "loaded in this process" from "a file we parsed"
            // is the whole point of section 10.
            r.Line("Status:        LOADED in PID " +
                   std::to_string(ProjectManager::Instance().Active()->Target().pid));
        } else {
            r.Line("Status:        Not loaded (static analysis only)");
        }

        r.Line("Sections:      " + std::to_string(inspector.GetSections().size()));
        r.Line("Exports:       " + std::to_string(inspector.GetExports().size()));
        r.Line("Imports:       " + std::to_string(inspector.GetImports().size()));
        r.Line("SHA-256:       " + meta.sha256);
        return r;
    }

    CommandResult DllService::Imports(const std::string& nameOrPath) const {
        ResolvedModule module;
        PeInspector inspector;
        CommandResult error;
        if (!PrepareDll(nameOrPath, module, inspector, error)) return error;

        auto project = ProjectManager::Instance().Active();
        const auto& imports = inspector.GetImports();

        CommandResult r = CommandResult::Success(
            module.name + " imports " + std::to_string(imports.size()) + " symbol" +
            (imports.size() == 1 ? "" : "s") + ".");

        std::map<std::string, size_t> byDll;
        for (const auto& i : imports) ++byDll[i.dllName];
        for (const auto& kv : byDll) {
            r.Line("  " + kv.first + "  (" + std::to_string(kv.second) + ")");
        }

        if (project && imports.size() > 40) {
            HtmlReport report("Imports - " + module.name, module.backingPath);
            report.AddSummary("Symbols", std::to_string(imports.size()));
            report.AddSummary("Modules", std::to_string(byDll.size()));
            report.SetColumns({
                {"Module",   HtmlReport::Align::Left, false, false},
                {"Function", HtmlReport::Align::Left, false, false},
                {"IAT RVA",  HtmlReport::Align::Left, true,  true},
            });
            for (const auto& i : imports) {
                report.AddRow(std::vector<HtmlReport::Cell>{
                    {i.dllName, ""},
                    {i.functionName.empty() ? ("#" + std::to_string(i.ordinal)) : i.functionName, ""},
                    {HexAddr(i.iatRva), ""},
                });
            }
            const std::string out = project->NextArtifactPath("modules", "imports", "html");
            std::string writeError;
            if (report.Write(out, writeError)) {
                auto ref = PublishArtifact(*project, out, "dll-imports", "html",
                                           "Imports - " + module.name, imports.size());
                r.artifacts.push_back(ref);
                r.Line("Full report: " + ref.projectRelative);
                MaybeAutoOpen(out);
            }
        }
        return r;
    }

    // Builds the export table with static->live address correlation. This is
    // the core of section 10: a static RVA becomes a live VA only when the
    // module is actually loaded, and the distinction is reported honestly.
    static CommandResult BuildExportTable(const DllService::ResolvedModule& module,
                                          const PeInspector& inspector,
                                          const std::string& reportTitle,
                                          const std::string& artifactKind,
                                          const std::string& artifactStem) {
        auto project = ProjectManager::Instance().Active();
        const auto& exports = inspector.GetExports();
        const uint64_t preferredBase = inspector.GetMetadata().imageBase;

        CommandResult r = CommandResult::Success(
            module.name + " exports " + std::to_string(exports.size()) + " symbol" +
            (exports.size() == 1 ? "" : "s") + ".");

        // Verify a handful of resolved addresses by actually reading them, so
        // "LIVE-READ VERIFIED" is never claimed without a real read.
        void* handle = nullptr;
        uint32_t pid = project ? project->Target().pid : 0;
        if (module.isLoaded && pid != 0) {
            std::string openError;
            handle = Sandbox::ProcessInspector::OpenReadOnly(pid, openError);
        }

        size_t verifiedCount = 0;
        std::vector<std::vector<HtmlReport::Cell>> rows;
        rows.reserve(exports.size());

        for (const auto& e : exports) {
            const uint64_t preferredVa = preferredBase + e.rva;
            const uint64_t liveVa = module.isLoaded ? (module.loadedBase + e.rva) : 0;

            std::string level = "STATIC";
            std::string badge = "static";
            bool verified = false;

            if (module.isLoaded) {
                level = "RESOLVED";
                badge = "resolved";

                // Verify only a bounded sample: probing 20k exports would be
                // slow and would add nothing.
                if (handle && verifiedCount < 64) {
                    size_t bytesRead = 0;
                    std::string readError;
                    auto data = Sandbox::ProcessInspector::ReadMemory(handle, liveVa, 1, bytesRead, readError);
                    if (bytesRead == 1) {
                        level = "LIVE-READ VERIFIED";
                        badge = "live";
                        verified = true;
                        ++verifiedCount;
                    }
                }
            }

            rows.push_back({
                {e.functionName.empty() ? ("#" + std::to_string(e.ordinal)) : e.functionName, ""},
                {std::to_string(e.ordinal), ""},
                {HexAddr(e.rva), ""},
                {HexAddr(preferredVa), ""},
                {module.isLoaded ? HexAddr(module.loadedBase) : "-", ""},
                {liveVa ? HexAddr(liveVa) : "-", ""},
                {level, badge},
            });

            if (verified && r.evidence.size() < 8) {
                EvidenceReference ev;
                ev.kind = "export-correlation";
                ev.level = "LIVE-READ VERIFIED";
                ev.summary = e.functionName + " static RVA " + HexAddr(e.rva) +
                             " -> live VA " + HexAddr(liveVa);
                ev.source = module.name + " @ " + HexAddr(module.loadedBase);
                r.evidence.push_back(ev);
            }
        }

        if (handle) Sandbox::ProcessInspector::Close(handle);

        if (module.isLoaded) {
            r.Line("Loaded base:  " + HexAddr(module.loadedBase));
            r.Line("Correlation:  static RVA + loaded base = live VA");
            r.Line("Live-read verified: " + std::to_string(verifiedCount) + " of " +
                   std::to_string(exports.size()) + " sampled addresses");
        } else {
            r.Line("Module is not loaded; addresses are static (preferred base " +
                   HexAddr(preferredBase) + ").");
        }

        // Show a few worked examples in the terminal, full table in HTML.
        for (size_t i = 0; i < std::min<size_t>(exports.size(), 8); ++i) {
            const auto& e = exports[i];
            r.Line("  " + (e.functionName.empty() ? ("#" + std::to_string(e.ordinal)) : e.functionName));
            r.Line("      Static RVA   " + HexAddr(e.rva));
            r.Line("      Preferred VA " + HexAddr(preferredBase + e.rva));
            if (module.isLoaded) {
                r.Line("      Loaded base  " + HexAddr(module.loadedBase));
                r.Line("      Live VA      " + HexAddr(module.loadedBase + e.rva));
            }
        }
        if (exports.size() > 8) {
            r.Line("  ... " + std::to_string(exports.size() - 8) + " more in the full report.");
        }

        if (project) {
            HtmlReport report(reportTitle, module.backingPath);
            report.AddSummary("Exports", std::to_string(exports.size()));
            report.AddSummary("Loaded", module.isLoaded ? "yes" : "no");
            if (module.isLoaded) {
                report.AddSummary("Loaded base", HexAddr(module.loadedBase));
                report.AddSummary("Verified", std::to_string(verifiedCount));
            }
            report.AddSummary("Preferred base", HexAddr(preferredBase));
            report.SetColumns({
                {"Function",     HtmlReport::Align::Left,  false, false},
                {"Ordinal",      HtmlReport::Align::Right, true,  true},
                {"Static RVA",   HtmlReport::Align::Left,  true,  true},
                {"Preferred VA", HtmlReport::Align::Left,  true,  true},
                {"Loaded Base",  HtmlReport::Align::Left,  true,  true},
                {"Live VA",      HtmlReport::Align::Left,  true,  true},
                {"Evidence",     HtmlReport::Align::Left,  false, false},
            });
            for (const auto& row : rows) report.AddRow(row);

            const std::string out = project->NextArtifactPath("modules", artifactStem, "html");
            std::string writeError;
            if (report.Write(out, writeError)) {
                auto ref = PublishArtifact(*project, out, artifactKind, "html",
                                           reportTitle, exports.size());
                r.artifacts.push_back(ref);
                r.Line("Full report:  " + ref.projectRelative);
                MaybeAutoOpen(out);
            } else {
                r.Line("Detailed report could not be written: " + writeError);
            }
        }
        return r;
    }

    CommandResult DllService::Exports(const std::string& nameOrPath) const {
        ResolvedModule module;
        PeInspector inspector;
        CommandResult error;
        if (!PrepareDll(nameOrPath, module, inspector, error)) return error;
        return BuildExportTable(module, inspector, "Exports - " + module.name,
                                "dll-exports", "exports");
    }

    CommandResult DllService::Functions(const std::string& nameOrPath) const {
        ResolvedModule module;
        PeInspector inspector;
        CommandResult error;
        if (!PrepareDll(nameOrPath, module, inspector, error)) return error;
        // Discovered DLL functions are its exported entry points correlated
        // with their runtime addresses.
        return BuildExportTable(module, inspector, "Functions - " + module.name,
                                "dll-functions", "functions");
    }

} // namespace App
} // namespace Dracula
