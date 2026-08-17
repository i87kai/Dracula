#pragma once

//
// Dracula semantic output layer.
//
// Commands describe WHAT they are saying (a success, a warning, a section, a
// key/value pair) and this layer decides how it looks. Nothing below this line
// should be printing its own separator rules or ANSI literals.
//

#include <string>
#include <vector>
#include <cstddef>

namespace Dracula {

    struct CommandDefinition;

    namespace Ui {

        // Usable content width for the current terminal (bounded so output stays
        // readable on very wide monitors).
        size_t ContentWidth();

        // ─── Semantic messages ──────────────────────────────────────────────
        void Success(const std::string& message);
        void Warning(const std::string& message);
        void Error(const std::string& message);
        void Info(const std::string& message);
        void Note(const std::string& message);

        // Error state tracking for CLI return codes
        bool HasError();
        void ResetError();
        void SetError();

        // ─── Structure ──────────────────────────────────────────────────────

        // A titled section: the title in the Dracula accent above a hairline
        // rule sized to the content, followed by a blank line.
        void Section(const std::string& title, const std::string& subtitle = "");

        // A group label inside a section (no rule).
        void Group(const std::string& label);

        // Aligned "  Key        Value" row.
        void KeyValue(const std::string& key, const std::string& value,
                      size_t keyWidth = 22);

        // Key/value where the value carries a semantic state.
        enum class State { Good, Bad, Warn, Neutral };
        void KeyState(const std::string& key, State state, const std::string& value,
                      size_t keyWidth = 22);

        void Blank();
        void Lines(const std::vector<std::string>& lines);

        // "Showing 50 of 1,428" style footer for truncated output.
        void Truncated(size_t shown, size_t total, const std::string& noun,
                       const std::string& allHint = "");

        // ─── Guidance ───────────────────────────────────────────────────────

        // A missing/invalid argument is guidance, not a catastrophe: render the
        // reason as a warning followed by usage, an example and a tip.
        void MissingArgument(const CommandDefinition& cmd, const std::string& reason,
                             const std::string& tip = "");

        // Same, for commands that are not in the registry (or when the registry
        // entry is unavailable).
        void UsageHint(const std::string& reason, const std::string& usage,
                       const std::string& example = "",
                       const std::string& tip = "");

        // Formatted integer with thousands separators.
        std::string Number(unsigned long long value);

    } // namespace Ui
} // namespace Dracula
