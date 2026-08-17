#pragma once

#include <string>
#include <cstdint>

namespace Dracula {

    enum class FileValidationStatus {
        Valid,
        DoesNotExist,
        IsDirectory,
        NotRegularFile,
        Unreadable,
        Empty
    };

    struct FileValidationResult {
        FileValidationStatus status = FileValidationStatus::Valid;
        std::string errorMessage;
        uint64_t fileSize = 0;
        std::string resolvedPath;

        bool IsValid() const { return status == FileValidationStatus::Valid; }
        explicit operator bool() const { return IsValid(); }
    };

    class InputValidator {
    public:
        // Generic non-throwing filesystem validator
        static FileValidationResult ValidateFile(const std::string& path);

        // Human-readable error message generator for standard Dracula error reporting
        static std::string StatusToString(FileValidationStatus status, const std::string& path);
    };

} // namespace Dracula
