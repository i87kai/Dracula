#include "cli/command_registry.h"
#include "cli/dracula_shell.h"
#include <algorithm>

namespace Dracula {

    CommandRegistry& CommandRegistry::Instance() {
        static CommandRegistry instance;
        if (!instance.m_initialized) {
            instance.InitializeDefaultCommands();
        }
        return instance;
    }

    void CommandRegistry::Register(const CommandDefinition& cmd) {
        m_commands.push_back(cmd);
    }

    const CommandDefinition* CommandRegistry::Find(const std::string& nameOrAlias) const {
        std::string query = nameOrAlias;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        for (const auto& cmd : m_commands) {
            if (cmd.name == query) return &cmd;
            for (const auto& alias : cmd.aliases) {
                if (alias == query) return &cmd;
            }
        }
        return nullptr;
    }

    const CommandDefinition* CommandRegistry::FindExact(const std::string& name) const {
        std::string query = name;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        for (const auto& cmd : m_commands) {
            if (cmd.name == query) return &cmd;
        }
        return nullptr;
    }

    std::vector<const CommandDefinition*> CommandRegistry::FilterByPrefix(const std::string& prefix) const {
        std::string query = prefix;
        if (!query.empty() && query.front() == '/') {
            query = query.substr(1);
        }
        std::transform(query.begin(), query.end(), query.begin(), ::tolower);

        std::vector<const CommandDefinition*> matches;
        for (const auto& cmd : m_commands) {
            if (query.empty() || cmd.name.rfind(query, 0) == 0) {
                matches.push_back(&cmd);
            }
        }
        return matches;
    }

    const std::vector<CommandDefinition>& CommandRegistry::GetAllCommands() const {
        return m_commands;
    }

    std::vector<std::string> CommandRegistry::GetCategories() const {
        std::vector<std::string> categories;
        for (const auto& cmd : m_commands) {
            if (std::find(categories.begin(), categories.end(), cmd.category) == categories.end()) {
                categories.push_back(cmd.category);
            }
        }
        return categories;
    }

    std::vector<const CommandDefinition*> CommandRegistry::GetCommandsByCategory(const std::string& category) const {
        std::vector<const CommandDefinition*> result;
        for (const auto& cmd : m_commands) {
            if (cmd.category == category) {
                result.push_back(&cmd);
            }
        }
        return result;
    }

    void CommandRegistry::InitializeDefaultCommands() {
        if (m_initialized) return;
        m_commands.clear();

        // 1. /analyze
        Register({
            .name = "analyze",
            .aliases = {"a"},
            .description = "Analyze a PE using the complete Dracula pipeline",
            .usage = "/analyze <file>",
            .category = "Analysis",
            .detailedHelp = "Runs complete static inspection, entropy profiling, Capstone disassembly, CFG generation, and Unicorn 2 CPU emulation on target PE.",
            .examples = {"/analyze samples\\test_sample.exe", "/analyze target.dll"},
            .takesFilePath = true,
            .requiresArgs = true,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleAnalyze(args);
            }
        });

        // 2. /disasm
        Register({
            .name = "disasm",
            .aliases = {"dis", "d"},
            .description = "Disassemble executable code using Capstone",
            .usage = "/disasm [file] [rva] [count]",
            .category = "Inspection",
            .detailedHelp = "Disassembles x86/x64 instructions at the entrypoint or specified target RVA using Capstone 5.0.1 engine.",
            .examples = {"/disasm", "/disasm samples\\test_sample.exe", "/disasm samples\\test_sample.exe 0x1000 50"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleDisasm(args);
            }
        });

        // 3. /headers
        Register({
            .name = "headers",
            .aliases = {"hdr"},
            .description = "Inspect PE headers, metadata, and section tables",
            .usage = "/headers [file]",
            .category = "Inspection",
            .detailedHelp = "Parses and displays DOS header, NT headers, Optional header fields, entry point, and section table permissions.",
            .examples = {"/headers", "/headers sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleHeaders(args);
            }
        });

        // 4. /security
        Register({
            .name = "security",
            .aliases = {"sec"},
            .description = "Audit PE security mitigations (ASLR, DEP, CFG, SEH)",
            .usage = "/security [file]",
            .category = "Inspection",
            .detailedHelp = "Audits exploit mitigations including Dynamic Base (ASLR), High Entropy ASLR, DEP/NX, Control Flow Guard (CFG), SEH, and Authenticode.",
            .examples = {"/security", "/security sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleSecurity(args);
            }
        });

        // 5. /imports
        Register({
            .name = "imports",
            .aliases = {"imp"},
            .description = "Show imported DLLs and sensitive API calls",
            .usage = "/imports [file]",
            .category = "Inspection",
            .detailedHelp = "Inspects the Import Address Table (IAT) and flags high-risk APIs (process injection, memory manipulation, evasion).",
            .examples = {"/imports", "/imports sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleImports(args);
            }
        });

        // 6. /exports
        Register({
            .name = "exports",
            .aliases = {"exp"},
            .description = "Show exported functions and symbol RVAs",
            .usage = "/exports [file]",
            .category = "Inspection",
            .detailedHelp = "Lists exported symbols, ordinal numbers, RVAs, and forwarders from the Export Address Table (EAT).",
            .examples = {"/exports", "/exports target.dll"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleExports(args);
            }
        });

        // 7. /strings
        Register({
            .name = "strings",
            .aliases = {"str"},
            .description = "Extract and classify ASCII & UTF-16 strings",
            .usage = "/strings [file] [min_length]",
            .category = "Inspection",
            .detailedHelp = "Extracts strings with category classification (URLs, IPs, file paths, registry keys, DLLs, suspicious commands).",
            .examples = {"/strings", "/strings sample.exe 6"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleStrings(args);
            }
        });

        // 8. /entropy
        Register({
            .name = "entropy",
            .aliases = {"ent"},
            .description = "Analyze Shannon entropy & detect packers",
            .usage = "/entropy [file]",
            .category = "Analysis",
            .detailedHelp = "Calculates mathematical Shannon entropy per section to detect packing, encryption, or compression (UPX, ASPack, Themida, etc.).",
            .examples = {"/entropy", "/entropy sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleEntropy(args);
            }
        });

        // 9. /emulate
        Register({
            .name = "emulate",
            .aliases = {"emu", "e"},
            .description = "Run lightweight Unicorn 2 CPU emulation with Win32 HLE",
            .usage = "/emulate [file] [--policy bypass|realistic|neutral]",
            .category = "Emulation",
            .detailedHelp = "Emulates CPU instructions in isolated memory with synthetic Win32 HLE thunks, mock TEB/PEB, and register inspection.",
            .examples = {"/emulate", "/emulate sample.exe", "/emulate sample.exe --policy bypass"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {"--policy", "bypass", "realistic", "neutral"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleEmulate(args);
            }
        });

        // 10. /sandbox
        Register({
            .name = "sandbox",
            .aliases = {"vm"},
            .description = "Run the full QEMU hardware sandbox",
            .usage = "/sandbox [file]",
            .category = "Emulation",
            .detailedHelp = "Executes target inside dedicated QEMU virtual machine guest with live TCP telemetry and automatic snapshot rollback.",
            .examples = {"/sandbox sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleSandbox(args);
            }
        });

        // 11. /scan
        Register({
            .name = "scan",
            .aliases = {},
            .description = "Scan a file using a hex/AOB wildcard pattern",
            .usage = "/scan [file] <pattern>",
            .category = "Analysis",
            .detailedHelp = "Searches for bytecode patterns with wildcards (e.g. '48 8B 05 ?? ?? ?? ?? 48 85 C0').",
            .examples = {"/scan sample.exe \"48 8B ?? ?? ?? ??\"", "/scan \"E8 ?? ?? ?? ??\""},
            .takesFilePath = true,
            .requiresArgs = true,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleScan(args);
            }
        });

        // 12. /functions
        Register({
            .name = "functions",
            .aliases = {"funcs", "fn"},
            .description = "Show discovered functions and entrypoints",
            .usage = "/functions [file]",
            .category = "Inspection",
            .detailedHelp = "Lists all identified function entry points, sizes, and basic block counts in the active binary.",
            .examples = {"/functions", "/functions sample.exe"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleFunctions(args);
            }
        });

        // 13. /cfg
        Register({
            .name = "cfg",
            .aliases = {},
            .description = "Show Control-Flow Graph for target function",
            .usage = "/cfg [file] [rva]",
            .category = "Inspection",
            .detailedHelp = "Constructs and renders the control-flow basic block topology with conditional branch pathways.",
            .examples = {"/cfg", "/cfg sample.exe", "/cfg sample.exe 0x1000"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleCfg(args);
            }
        });

        // 14. /xrefs
        Register({
            .name = "xrefs",
            .aliases = {"xref", "x"},
            .description = "Show cross references to code, strings, and imports",
            .usage = "/xrefs [file] [rva]",
            .category = "Inspection",
            .detailedHelp = "Analyzes CALL/JMP targets and data references across the binary to build cross-reference graphs.",
            .examples = {"/xrefs", "/xrefs sample.exe", "/xrefs sample.exe 0x1000"},
            .takesFilePath = true,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleXrefs(args);
            }
        });

        // 15. /findings
        Register({
            .name = "findings",
            .aliases = {},
            .description = "Show findings and evidence from the active session",
            .usage = "/findings",
            .category = "Session",
            .detailedHelp = "Displays all structured security, threat, and mitigation findings collected during analysis.",
            .examples = {"/findings"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleFindings(args);
            }
        });

        // 16. /report
        Register({
            .name = "report",
            .aliases = {},
            .description = "Export current analysis to JSON, Markdown, or TXT",
            .usage = "/report [json|md|txt] [output_path]",
            .category = "Session",
            .detailedHelp = "Serializes the active session analysis results to standard machine-readable JSON, Markdown documentation, or summary TXT.",
            .examples = {"/report json", "/report md report.md", "/report txt summary.txt"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"json", "md", "txt", "markdown"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleReport(args);
            }
        });

        // 17. /session
        Register({
            .name = "session",
            .aliases = {},
            .description = "Display active session status, sample, and findings count",
            .usage = "/session",
            .category = "Session",
            .detailedHelp = "Shows the active binary path, architecture, threat score, SHA-256 hash, and session state.",
            .examples = {"/session"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleSession(args);
            }
        });

        // 18. /mcp
        Register({
            .name = "mcp",
            .aliases = {},
            .description = "Start Model Context Protocol (MCP) stdio server",
            .usage = "/mcp",
            .category = "System",
            .detailedHelp = "Launches native JSON-RPC 2.0 stdio server for AI pair-programming and tool invocation.",
            .examples = {"/mcp"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleMcp(args);
            }
        });

        // 19. /changelog
        Register({
            .name = "changelog",
            .aliases = {"changes", "cl"},
            .description = "Show Dracula version history and release notes",
            .usage = "/changelog [version]",
            .category = "System",
            .detailedHelp = "Reads and displays entries from CHANGELOG.txt. Optionally pass a version number to inspect specific release.",
            .examples = {"/changelog", "/changelog 1.0.0"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"1.0.0"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleChangelog(args);
            }
        });

        // 20. /version
        Register({
            .name = "version",
            .aliases = {"v"},
            .description = "Show Dracula version, build architecture, and engines",
            .usage = "/version",
            .category = "System",
            .detailedHelp = "Prints central authoritative version string, compiler toolchain, and integrated engine versions.",
            .examples = {"/version"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleVersion(args);
            }
        });

        // 21. /clear
        Register({
            .name = "clear",
            .aliases = {"cls"},
            .description = "Clear terminal screen and reset viewport",
            .usage = "/clear",
            .category = "System",
            .detailedHelp = "Clears the active console screen buffer and returns cursor to top-left position.",
            .examples = {"/clear"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleClear(args);
            }
        });

        // 22. /help
        Register({
            .name = "help",
            .aliases = {"?", "h"},
            .description = "Show interactive command overview or detailed command help",
            .usage = "/help [command]",
            .category = "System",
            .detailedHelp = "Displays complete command reference organized by category, or detailed syntax for a specific command.",
            .examples = {"/help", "/help analyze", "/help emulate"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {"analyze", "disasm", "headers", "security", "imports", "exports", "strings", "entropy", "emulate", "sandbox", "scan", "functions", "cfg", "xrefs", "findings", "report", "session", "mcp", "changelog", "version", "clear", "help", "exit"},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleHelp(args);
            }
        });

        // 23. /exit
        Register({
            .name = "exit",
            .aliases = {"quit", "q"},
            .description = "Exit Dracula interactive shell",
            .usage = "/exit",
            .category = "System",
            .detailedHelp = "Saves command history and terminates the interactive shell session cleanly.",
            .examples = {"/exit"},
            .takesFilePath = false,
            .requiresArgs = false,
            .argCompletions = {},
            .handler = [](DraculaShell& shell, const std::vector<std::string>& args) {
                shell.HandleExit(args);
            }
        });

        m_initialized = true;
    }

} // namespace Dracula
