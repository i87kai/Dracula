#pragma once

//
// Dracula's authoritative command table.
//
// SINGLE SOURCE OF TRUTH. The slash palette, Tab completion, /help, usage
// strings, capability validation and actual dispatch are all derived from the
// definitions registered here. Nothing may hard-code a command list anywhere
// else -- that divergence is how the palette came to advertise
// "/dll [info|exports|imports|run|trace]" while the handler only implemented
// "exports" and "run".
//
// tests/test_command_registry.cpp enforces this: every advertised subcommand
// must resolve to a real handler.
//

#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <memory>

#include "app/dto.h"

namespace Dracula {

    class DraculaShell;

    // What a command needs from the active target in order to run. Dispatch
    // checks this BEFORE invoking a handler, so the user gets a capability-aware
    // explanation instead of a confusing failure from deep inside an engine.
    enum class CommandRequirement {
        None,             // always available (help, version, project list)
        ActiveProject,    // needs a project, any kind
        FileBacking,      // needs a static image (a process supplies its backing exe)
        LiveProcess,      // needs a running process
        ManagedTarget,    // needs a .NET target
    };

    // How dangerous the command is. Reserved for execution gating; nothing at
    // Safe level can run or modify a target.
    enum class CommandSafety {
        Safe,             // read-only inspection
        Mutating,         // writes to project storage
        Executing,        // runs target code under policy
    };

    // A subcommand is a first-class, dispatchable entity -- not a word in a
    // usage string. If it appears in the palette, it has a handler.
    struct SubcommandDefinition {
        std::string name;
        std::string description;
        std::string usage;

        // Positional value suggestions offered on Tab after this subcommand.
        std::vector<std::string> argCompletions;

        CommandRequirement requirement = CommandRequirement::None;
        CommandSafety      safety = CommandSafety::Safe;

        // Service-backed handler. Receives the arguments AFTER the subcommand
        // name and returns a structured result the presentation layer renders.
        // A subcommand with no handler is a metadata-only alias handled by the
        // parent command's legacy handler.
        std::function<App::CommandResult(const std::vector<std::string>&)> handler;
    };

    struct CommandDefinition {
        std::string name;
        std::vector<std::string> aliases;
        std::string description;
        std::string usage;
        std::string category;        // "Analysis", "Inspection", "Emulation", "Session", "System"
        std::string detailedHelp;
        std::vector<std::string> examples;
        bool takesFilePath = false;
        bool requiresArgs = false;

        CommandRequirement requirement = CommandRequirement::None;

        // Subcommands, when this command has them. The palette renders these
        // directly, so they are guaranteed to match what dispatch accepts.
        std::vector<SubcommandDefinition> subcommands;

        // Subcommand invoked when the user supplies none (e.g. "/memory" alone
        // behaves as "/memory map"). Empty means "show the subcommand list".
        std::string defaultSubcommand;

        // Positional value suggestions offered on Tab (e.g. json / md / txt).
        std::vector<std::string> argCompletions;

        // Values offered after a specific flag, e.g. --policy -> bypass|realistic|neutral.
        // Argument completion is driven entirely by this metadata; the line
        // editor contains no per-command special cases.
        std::vector<std::pair<std::string, std::vector<std::string>>> flagCompletions;

        // Legacy shell handler, used when no subcommand handler applies.
        std::function<void(DraculaShell&, const std::vector<std::string>&)> handler;
    };

    class CommandRegistry {
    public:
        static CommandRegistry& Instance();

        // Registration & Lookup
        void Register(const CommandDefinition& cmd);
        const CommandDefinition* Find(const std::string& nameOrAlias) const;
        const CommandDefinition* FindExact(const std::string& name) const;

        // Resolves a subcommand by name or unambiguous prefix. Null when the
        // command has no such subcommand.
        const SubcommandDefinition* FindSubcommand(const CommandDefinition& cmd,
                                                   const std::string& name) const;

        // Interactive filtering
        std::vector<const CommandDefinition*> FilterByPrefix(const std::string& prefix) const;

        // Subcommand names for the hierarchical palette. Exactly what dispatch
        // accepts -- the palette cannot drift from the handlers.
        std::vector<std::string> SubcommandNames(const CommandDefinition& cmd) const;

        // Querying
        const std::vector<CommandDefinition>& GetAllCommands() const;
        std::vector<std::string> GetCategories() const;
        std::vector<const CommandDefinition*> GetCommandsByCategory(const std::string& category) const;

        // Human-readable requirement description, used to explain why a
        // command is unavailable for the current target.
        static std::string DescribeRequirement(CommandRequirement req);

        // Checks a requirement against the active project. Returns an empty
        // optional-style error string when satisfied.
        static bool RequirementSatisfied(CommandRequirement req, App::ErrorDetail& errorOut);

        // Initialize built-in command table
        void InitializeDefaultCommands();

    private:
        CommandRegistry() = default;
        std::vector<CommandDefinition> m_commands;
        bool m_initialized = false;
    };

} // namespace Dracula
