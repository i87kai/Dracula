#include "app/services.h"
#include "app/html_report.h"
#include "app/json.h"
#include "app/settings.h"
#include "utr/memory_intelligence.h"

#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstdlib>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#endif

namespace fs = std::filesystem;

namespace Dracula {
namespace App {

    // --- Shared artifact helpers ---------------------------------------------

    ArtifactReference PublishArtifact(Project& project,
                                      const std::string& absolutePath,
                                      const std::string& kind,
                                      const std::string& format,
                                      const std::string& title,
                                      uint64_t rowCount) {
        ArtifactReference ref;
        ref.kind = kind;
        ref.format = format;
        ref.path = absolutePath;
        ref.title = title;
        ref.rowCount = rowCount;
        ref.createdAt = NowIso8601();

        std::error_code ec;
        ref.sizeBytes = fs::exists(absolutePath, ec) ? fs::file_size(absolutePath, ec) : 0;
        if (ec) ref.sizeBytes = 0;

        // Store the project-relative form for display; it is far more readable
        // than a full path and identifies the artifact's home unambiguously.
        ref.projectRelative = fs::relative(absolutePath, project.Root(), ec).generic_string();
        if (ec || ref.projectRelative.empty()) ref.projectRelative = absolutePath;

        ArtifactRecord rec;
        rec.id = kind + "_" + std::to_string(project.Artifacts().size() + 1);
        rec.kind = kind;
        rec.format = format;
        rec.relativePath = ref.projectRelative;
        rec.title = title;
        rec.createdAt = ref.createdAt;
        rec.sizeBytes = ref.sizeBytes;
        rec.rowCount = rowCount;
        project.AddArtifact(rec);

        ref.id = rec.id;

        std::string error;
        project.Save(error);
        return ref;
    }

    bool MaybeAutoOpen(const std::string& path) {
        // Default off: a batch of reports must never spawn a browser storm.
        if (!Settings::Instance().GetBool("reports.auto_open", false)) return false;
#ifdef _WIN32
        HINSTANCE result = ShellExecuteA(nullptr, "open", path.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
        return reinterpret_cast<intptr_t>(result) > 32;
#else
        (void)path;
        return false;
#endif
    }

    // --- Snapshot persistence -------------------------------------------------
    // Snapshot region metadata is written next to the project so /memory compare
    // works across restarts. Region CONTENTS are not retained here -- only the
    // structural fingerprint needed for diffing -- which keeps a 1700-region
    // snapshot in the tens of KB rather than gigabytes.

    static std::string SnapshotFileName(uint32_t id) {
        std::ostringstream oss;
        oss << "snapshot_" << std::setw(4) << std::setfill('0') << id << ".json";
        return oss.str();
    }

    static bool WriteSnapshotData(const Project& project,
                                  uint32_t id,
                                  const std::vector<UTR::MemoryRegion>& regions,
                                  std::string& relativePathOut,
                                  std::string& error) {
        Json arr = Json::Array();
        for (const auto& r : regions) {
            Json j = Json::Object();
            j.Set("base", Json(r.baseAddress));
            j.Set("size", Json(r.size));
            j.Set("protect", Json(static_cast<uint64_t>(r.currentProtect)));
            j.Set("state", Json(static_cast<uint64_t>(r.state)));
            j.Set("type", Json(static_cast<uint64_t>(r.type)));
            j.Set("entropy", Json(r.entropy));
            j.Set("module", Json(r.moduleName));
            j.Set("sha256", Json(r.sha256));
            j.Set("x", Json(r.isExecutable));
            j.Set("w", Json(r.isWritable));
            arr.Push(j);
        }

        Json root = Json::Object();
        root.Set("snapshot_id", Json(id));
        root.Set("captured_at", Json(NowIso8601()));
        root.Set("regions", arr);

        const std::string name = SnapshotFileName(id);
        const fs::path target = fs::path(project.MemorySnapshotsDir()) / name;
        const std::string text = root.Dump(0);

        try {
            fs::create_directories(target.parent_path());
            std::ofstream out(target, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) {
                error = "could not write snapshot data";
                return false;
            }
            out.write(text.data(), static_cast<std::streamsize>(text.size()));
            out.flush();
            if (!out.good()) {
                error = "snapshot write failed";
                return false;
            }
        } catch (const std::exception& e) {
            error = std::string("snapshot write failed: ") + e.what();
            return false;
        }

        relativePathOut = (fs::path("memory/snapshots") / name).generic_string();
        return true;
    }

    static bool ReadSnapshotData(const Project& project,
                                 const SnapshotRecord& rec,
                                 std::vector<UTR::MemoryRegion>& regionsOut,
                                 std::string& error) {
        fs::path path = rec.dataRelativePath.empty()
            ? (fs::path(project.MemorySnapshotsDir()) / SnapshotFileName(rec.id))
            : (fs::path(project.Root()) / rec.dataRelativePath);

        std::error_code ec;
        if (!fs::exists(path, ec)) {
            error = "snapshot data for #" + std::to_string(rec.id) + " is no longer on disk";
            return false;
        }

        std::ifstream in(path, std::ios::binary);
        if (!in.is_open()) {
            error = "could not read snapshot #" + std::to_string(rec.id);
            return false;
        }
        std::stringstream ss;
        ss << in.rdbuf();

        Json root;
        std::string parseError;
        if (!Json::Parse(ss.str(), root, &parseError)) {
            error = "snapshot #" + std::to_string(rec.id) + " is corrupted: " + parseError;
            return false;
        }

        for (const auto& j : root["regions"].Items()) {
            UTR::MemoryRegion r;
            r.baseAddress = j["base"].AsUInt();
            r.size = j["size"].AsUInt();
            r.currentProtect = static_cast<uint32_t>(j["protect"].AsUInt());
            r.state = static_cast<uint32_t>(j["state"].AsUInt());
            r.type = static_cast<uint32_t>(j["type"].AsUInt());
            r.entropy = j["entropy"].AsNumber();
            r.moduleName = j["module"].AsString();
            r.sha256 = j["sha256"].AsString();
            r.isExecutable = j["x"].AsBool();
            r.isWritable = j["w"].AsBool();
            regionsOut.push_back(r);
        }
        return true;
    }

    static std::string Hex(uint64_t v, int width = 0) {
        std::ostringstream oss;
        oss << "0x" << std::hex << std::uppercase;
        if (width > 0) oss << std::setw(width) << std::setfill('0');
        oss << v;
        return oss.str();
    }

    // --- MemoryService --------------------------------------------------------

    MemoryService& MemoryService::Instance() {
        static MemoryService instance;
        return instance;
    }

    static MemoryMapSummary SummarizeRegions(const std::vector<UTR::MemoryRegion>& regions) {
        MemoryMapSummary s;
        s.regionCount = regions.size();
        for (const auto& r : regions) {
            // MEM_COMMIT == 0x1000
            if (r.state == 0x1000) s.committedBytes += r.size;
            if (r.isExecutable) ++s.executableRegions;
            else if (r.isWritable) ++s.readWriteRegions;
            else ++s.readOnlyRegions;

            if (r.currentProtect & 0x100) ++s.guardRegions;  // PAGE_GUARD
            if (r.type == 0x1000000) ++s.imageRegions;       // MEM_IMAGE
            if (r.type == 0x20000)   ++s.privateRegions;     // MEM_PRIVATE
        }
        return s;
    }

    CommandResult MemoryService::Map() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);
        if (!caps.memoryRead) {
            return CommandResult::Failure(CapabilityError(
                *project, "Memory mapping",
                "A memory map requires a live target. This project is backed by a file on disk, "
                "which has no address space until it is executed or emulated."));
        }

        auto bound = TargetBinding::Instance().Resolve();
        if (!bound.Ok()) {
            return CommandResult::Failure("target_unavailable",
                                          "Could not access the target.", bound.Error());
        }

        auto mapRes = bound.Value()->GetMemoryMap();
        if (!mapRes.Ok()) {
            return CommandResult::Failure("memory_map_failed",
                                          "Could not read the memory map.", mapRes.Error());
        }

        const auto& regions = mapRes.Value();
        MemoryMapSummary summary = SummarizeRegions(regions);

        // Terminal output stays a concise summary; the full table becomes an
        // HTML artifact rather than thousands of scrolled rows (section 20).
        CommandResult r = CommandResult::Success("Memory map");
        r.Line("Regions indexed:  " + std::to_string(summary.regionCount));
        r.Line("Committed:        " + FormatBytes(summary.committedBytes));
        r.Line("Executable:       " + std::to_string(summary.executableRegions));
        r.Line("Read/Write:       " + std::to_string(summary.readWriteRegions));
        r.Line("Read-only:        " + std::to_string(summary.readOnlyRegions));
        r.Line("Guard:            " + std::to_string(summary.guardRegions));
        r.Line("Image / Private:  " + std::to_string(summary.imageRegions) + " / " +
                                      std::to_string(summary.privateRegions));

        HtmlReport report("Memory Map",
                          project->DisplayName() + " - " + std::to_string(summary.regionCount) + " regions");
        report.AddSummary("Regions", std::to_string(summary.regionCount));
        report.AddSummary("Committed", FormatBytes(summary.committedBytes));
        report.AddSummary("Executable", std::to_string(summary.executableRegions));
        report.AddSummary("Guard", std::to_string(summary.guardRegions));
        if (project->Target().pid != 0) {
            report.AddSummary("PID", std::to_string(project->Target().pid));
        }

        report.SetColumns({
            {"Base Address", HtmlReport::Align::Left,  true,  true},
            {"Size",         HtmlReport::Align::Right, true,  true},
            {"Protection",   HtmlReport::Align::Left,  false, false},
            {"Type",         HtmlReport::Align::Left,  false, false},
            {"Entropy",      HtmlReport::Align::Right, true,  true},
            {"Module",       HtmlReport::Align::Left,  false, false},
        });

        for (const auto& reg : regions) {
            std::ostringstream ent;
            ent << std::fixed << std::setprecision(2) << reg.entropy;

            std::string typeLabel = "-";
            if (reg.type == 0x1000000) typeLabel = "IMAGE";
            else if (reg.type == 0x40000) typeLabel = "MAPPED";
            else if (reg.type == 0x20000) typeLabel = "PRIVATE";

            // Highlight RWX, the classic self-modifying-code signal.
            const bool rwx = reg.isExecutable && reg.isWritable;
            HtmlReport::Cell prot{UTR::ProtectionToString(reg.currentProtect), rwx ? "warn" : ""};

            report.AddRow(std::vector<HtmlReport::Cell>{
                {Hex(reg.baseAddress, 16), ""},
                {std::to_string(reg.size), ""},
                prot,
                {typeLabel, ""},
                {ent.str(), ""},
                {reg.moduleName.empty() ? "-" : reg.moduleName, ""},
            });
        }

        const std::string path = project->NextArtifactPath("memory/maps", "map", "html");
        std::string writeError;
        if (report.Write(path, writeError)) {
            ArtifactReference ref = PublishArtifact(*project, path, "memory-map", "html",
                                                    "Memory Map", summary.regionCount);
            r.artifacts.push_back(ref);
            r.Line("Full report:      " + ref.projectRelative);
            if (MaybeAutoOpen(path)) r.Line("Opened detailed report.");
        } else {
            r.Line("Detailed report could not be written: " + writeError);
        }
        return r;
    }

    CommandResult MemoryService::Read(uint64_t address, size_t size) const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);
        if (!caps.memoryRead) {
            return CommandResult::Failure(CapabilityError(
                *project, "Memory read",
                "Reading virtual memory requires a live target with an address space."));
        }
        if (size == 0) {
            return CommandResult::Failure("invalid_argument", "Read size must be greater than zero.");
        }

        // Bound the read so a mistyped size cannot try to materialize gigabytes.
        constexpr size_t kMaxRead = 1024 * 1024;
        std::string truncationNote;
        if (size > kMaxRead) {
            truncationNote = "Requested " + FormatBytes(size) + "; truncated to " + FormatBytes(kMaxRead) + ".";
            size = kMaxRead;
        }

        auto bound = TargetBinding::Instance().Resolve();
        if (!bound.Ok()) {
            return CommandResult::Failure("target_unavailable",
                                          "Could not access the target.", bound.Error());
        }

        auto readRes = bound.Value()->ReadMemory(address, size);
        if (!readRes.Ok()) {
            return CommandResult::Failure("memory_read_failed",
                                          "Could not read " + FormatBytes(size) + " at " + Hex(address) + ".",
                                          readRes.Error(),
                                          "Check the address is mapped; /memory map lists valid regions.");
        }

        const auto& data = readRes.Value();
        CommandResult r = CommandResult::Success(
            "Read " + std::to_string(data.size()) + " bytes at " + Hex(address) + ".");
        if (!truncationNote.empty()) r.Line(truncationNote);

        // Classic 16-byte hex dump with an ASCII gutter.
        const size_t previewLimit = std::min<size_t>(data.size(), 512);
        for (size_t off = 0; off < previewLimit; off += 16) {
            std::ostringstream line;
            line << std::hex << std::uppercase << std::setw(16) << std::setfill('0')
                 << (address + off) << "  ";

            std::string ascii;
            for (size_t i = 0; i < 16; ++i) {
                if (off + i < previewLimit) {
                    line << std::setw(2) << std::setfill('0')
                         << static_cast<unsigned>(data[off + i]) << ' ';
                    unsigned char c = data[off + i];
                    ascii += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
                } else {
                    line << "   ";
                }
                if (i == 7) line << ' ';
            }
            line << " |" << ascii << "|";
            r.Line(line.str());
        }

        if (data.size() > previewLimit) {
            r.Line("... " + std::to_string(data.size() - previewLimit) + " further bytes not shown.");
        }

        EvidenceReference ev;
        ev.kind = "memory-read";
        ev.level = "LIVE-READ VERIFIED";
        ev.summary = "Read " + std::to_string(data.size()) + " bytes at " + Hex(address);
        ev.source = "process " + std::to_string(project->Target().pid);
        r.evidence.push_back(ev);
        return r;
    }

    CommandResult MemoryService::Snapshot(const std::string& label) {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        auto caps = TargetBinding::DeriveCapabilities(*project);
        if (!caps.memorySnapshots) {
            return CommandResult::Failure(CapabilityError(
                *project, "Memory snapshots",
                "Snapshots capture a live address space; this project has no running target."));
        }

        auto bound = TargetBinding::Instance().Resolve();
        if (!bound.Ok()) {
            return CommandResult::Failure("target_unavailable",
                                          "Could not access the target.", bound.Error());
        }

        auto mapRes = bound.Value()->GetMemoryMap();
        if (!mapRes.Ok()) {
            return CommandResult::Failure("snapshot_failed",
                                          "Could not capture the memory map.", mapRes.Error());
        }

        const auto& regions = mapRes.Value();
        MemoryMapSummary summary = SummarizeRegions(regions);

        // The ID comes from the PROJECT's persisted counter, which is why two
        // consecutive captures now read #1 then #2 rather than #1 twice.
        const uint32_t id = project->AllocateSnapshotId();

        SnapshotRecord rec;
        rec.id = id;
        rec.label = label;
        rec.capturedAt = NowIso8601();
        rec.pid = project->Target().pid;
        rec.regionCount = summary.regionCount;
        rec.committedBytes = summary.committedBytes;
        rec.status = "Complete";

        std::string dataError;
        if (!WriteSnapshotData(*project, id, regions, rec.dataRelativePath, dataError)) {
            rec.status = "Failed";
            rec.truncationReason = dataError;
        }

        std::error_code ec;
        if (!rec.dataRelativePath.empty()) {
            fs::path p = fs::path(project->Root()) / rec.dataRelativePath;
            rec.retainedBytes = fs::exists(p, ec) ? fs::file_size(p, ec) : 0;
        }

        project->AddSnapshot(rec);
        std::string saveError;
        project->Save(saveError);

        if (rec.status == "Failed") {
            return CommandResult::Failure("snapshot_persist_failed",
                                          "Snapshot #" + std::to_string(id) + " could not be persisted.",
                                          dataError);
        }

        CommandResult r = CommandResult::Success(
            "Snapshot #" + std::to_string(id) + (label.empty() ? "" : " \"" + label + "\"") + " captured.");
        r.Line("Regions:    " + std::to_string(rec.regionCount));
        r.Line("Committed:  " + FormatBytes(rec.committedBytes));
        r.Line("Retained:   " + FormatBytes(rec.retainedBytes));
        if (rec.pid != 0) r.Line("PID:        " + std::to_string(rec.pid));

        if (project->Snapshots().size() >= 2) {
            const auto& snaps = project->Snapshots();
            const std::string prev = snaps[snaps.size() - 2].label.empty()
                ? std::to_string(snaps[snaps.size() - 2].id)
                : snaps[snaps.size() - 2].label;
            const std::string cur = label.empty() ? std::to_string(id) : label;
            r.Line("Compare with: /memory compare " + prev + " " + cur);
        }
        return r;
    }

    CommandResult MemoryService::ListSnapshots() const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        const auto& snaps = project->Snapshots();
        if (snaps.empty()) {
            CommandResult r = CommandResult::Success("No memory snapshots in this project.");
            r.Line("Capture one with /memory snapshot [name].");
            return r;
        }

        CommandResult r = CommandResult::Success(
            std::to_string(snaps.size()) + " snapshot" + (snaps.size() == 1 ? "" : "s") + ".");
        for (const auto& s : snaps) {
            std::ostringstream line;
            line << "#" << std::left << std::setw(4) << s.id
                 << std::setw(16) << (s.label.empty() ? "-" : s.label)
                 << std::setw(10) << s.regionCount << " regions  "
                 << std::setw(12) << FormatBytes(s.committedBytes) << "  "
                 << s.capturedAt;
            if (s.status != "Complete") line << "  [" << s.status << "]";
            r.Line(line.str());
        }
        return r;
    }

    CommandResult MemoryService::Compare(const std::string& fromIdOrLabel,
                                         const std::string& toIdOrLabel) const {
        auto project = ProjectManager::Instance().Active();
        if (!project) return CommandResult::Failure(NoActiveProjectError());

        const SnapshotRecord* from = project->FindSnapshot(fromIdOrLabel);
        const SnapshotRecord* to = project->FindSnapshot(toIdOrLabel);

        if (!from || !to) {
            const std::string missing = !from ? fromIdOrLabel : toIdOrLabel;
            ErrorDetail e;
            e.code = "unknown_snapshot";
            e.message = "No snapshot matches '" + missing + "'.";
            e.reason = "Snapshots are addressed by their project-local ID or their label.";
            e.remediation = "List them with /memory snapshots.";
            for (const auto& s : project->Snapshots()) {
                e.availableInstead.push_back("#" + std::to_string(s.id) +
                                             (s.label.empty() ? "" : " \"" + s.label + "\""));
            }
            return CommandResult::Failure(e);
        }
        if (from->id == to->id) {
            return CommandResult::Failure("invalid_argument",
                                          "Cannot compare a snapshot with itself.",
                                          "Both identifiers resolved to snapshot #" + std::to_string(from->id) + ".");
        }

        std::vector<UTR::MemoryRegion> fromRegions, toRegions;
        std::string error;
        if (!ReadSnapshotData(*project, *from, fromRegions, error) ||
            !ReadSnapshotData(*project, *to, toRegions, error)) {
            return CommandResult::Failure("snapshot_unreadable",
                                          "Could not load snapshot data.", error);
        }

        // Reuse the verified UTR diff engine rather than reimplementing it.
        UTR::MemoryIntelligenceManager mgr;
        mgr.CaptureSnapshot(fromRegions, from->label);
        mgr.CaptureSnapshot(toRegions, to->label);
        UTR::MemoryComparison comp = mgr.CompareSnapshots(1, 2);

        const std::string fromName = "#" + std::to_string(from->id) +
                                     (from->label.empty() ? "" : " \"" + from->label + "\"");
        const std::string toName = "#" + std::to_string(to->id) +
                                   (to->label.empty() ? "" : " \"" + to->label + "\"");

        CommandResult r = CommandResult::Success("Snapshot comparison " + fromName + " -> " + toName);
        r.Line("Regions:              " + std::to_string(from->regionCount) + " -> " +
                                          std::to_string(to->regionCount));
        r.Line("Allocated:            " + std::to_string(comp.newRegionsCount));
        r.Line("Freed:                " + std::to_string(comp.freedRegionsCount));
        r.Line("Modified:             " + std::to_string(comp.modifiedRegionsCount));
        r.Line("Protection changes:   " + std::to_string(comp.protectionTransitionsCount));
        if (comp.rwxTransitionsCount > 0) {
            r.Line("RWX transitions:      " + std::to_string(comp.rwxTransitionsCount) + "  (self-modifying code signal)");
        }

        HtmlReport report("Snapshot Comparison",
                          project->DisplayName() + " - " + fromName + " to " + toName);
        report.AddSummary("Allocated", std::to_string(comp.newRegionsCount));
        report.AddSummary("Freed", std::to_string(comp.freedRegionsCount));
        report.AddSummary("Modified", std::to_string(comp.modifiedRegionsCount));
        report.AddSummary("Prot. changes", std::to_string(comp.protectionTransitionsCount));
        report.AddSummary("RWX", std::to_string(comp.rwxTransitionsCount));

        report.SetColumns({
            {"Address",     HtmlReport::Align::Left,  true,  true},
            {"Size",        HtmlReport::Align::Right, true,  true},
            {"Change",      HtmlReport::Align::Left,  false, false},
            {"Old Protect", HtmlReport::Align::Left,  false, false},
            {"New Protect", HtmlReport::Align::Left,  false, false},
            {"Entropy",     HtmlReport::Align::Right, true,  true},
        });

        for (const auto& d : comp.deltas) {
            std::string badge;
            if (d.changeType == "ALLOCATED") badge = "ok";
            else if (d.changeType == "FREED") badge = "warn";
            else if (d.changeType == "PROTECTION_CHANGED") badge = "warn";
            else if (d.changeType == "MODIFIED") badge = "resolved";

            std::ostringstream ent;
            ent << std::fixed << std::setprecision(2) << d.oldEntropy << " -> " << d.newEntropy;

            report.AddRow(std::vector<HtmlReport::Cell>{
                {Hex(d.baseAddress, 16), ""},
                {std::to_string(d.size), ""},
                {d.changeType, badge},
                {UTR::ProtectionToString(d.oldProtect), ""},
                {UTR::ProtectionToString(d.newProtect), ""},
                {ent.str(), ""},
            });
        }

        const std::string path = project->NextArtifactPath("memory/maps", "compare", "html");
        std::string writeError;
        if (report.Write(path, writeError)) {
            ArtifactReference ref = PublishArtifact(*project, path, "snapshot-compare", "html",
                                                    "Snapshot Comparison", comp.deltas.size());
            r.artifacts.push_back(ref);
            r.Line("Full report:          " + ref.projectRelative);
            if (MaybeAutoOpen(path)) r.Line("Opened detailed report.");
        } else {
            r.Line("Detailed report could not be written: " + writeError);
        }
        return r;
    }

} // namespace App
} // namespace Dracula
