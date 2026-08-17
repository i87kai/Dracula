#pragma once

#include <string>
#include <vector>
#include <utility>
#include <functional>
#include <memory>

namespace Dracula {

    class DraculaShell;

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

        // Positional value suggestions offered on Tab (e.g. json / md / txt).
        std::vector<std::string> argCompletions;

        // Values offered after a specific flag, e.g. --policy -> bypass|realistic|neutral.
        // Argument completion is driven entirely by this metadata; the line
        // editor contains no per-command special cases.
        std::vector<std::pair<std::string, std::vector<std::string>>> flagCompletions;
        std::function<void(DraculaShell&, const std::vector<std::string>&)> handler;
    };

    class CommandRegistry {
    public:
        static CommandRegistry& Instance();

        // Registration & Lookup
        void Register(const CommandDefinition& cmd);
        const CommandDefinition* Find(const std::string& nameOrAlias) const;
        const CommandDefinition* FindExact(const std::string& name) const;

        // Interactive filtering
        std::vector<const CommandDefinition*> FilterByPrefix(const std::string& prefix) const;

        // Querying
        const std::vector<CommandDefinition>& GetAllCommands() const;
        std::vector<std::string> GetCategories() const;
        std::vector<const CommandDefinition*> GetCommandsByCategory(const std::string& category) const;

        // Initialize built-in command table
        void InitializeDefaultCommands();

    private:
        CommandRegistry() = default;
        std::vector<CommandDefinition> m_commands;
        bool m_initialized = false;
    };

} // namespace Dracula
