#include "common/input_validator.h"
#include <filesystem>
#include <fstream>
#include <system_error>

namespace fs = std::filesystem;

namespace Dracula {

    FileValidationResult InputValidator::ValidateFile(const std::string& path) {
        FileValidationResult result;
        result.resolvedPath = path;

        if (path.empty()) {
            result.status = FileValidationStatus::DoesNotExist;
            result.errorMessage = "Error: file path cannot be empty.";
            return result;
        }

        std::error_code ec;
        fs::file_status st = fs::status(path, ec);

        if (ec || !fs::exists(st)) {
            result.status = FileValidationStatus::DoesNotExist;
            result.errorMessage = "Error: file does not exist: " + path;
            return result;
        }

        if (fs::is_directory(st)) {
            result.status = FileValidationStatus::IsDirectory;
            result.errorMessage = "Error: expected a file, but the supplied path is a directory: " + path;
            return result;
        }

        if (!fs::is_regular_file(st)) {
            result.status = FileValidationStatus::NotRegularFile;
            result.errorMessage = "Error: expected a regular file, but the supplied path is not a regular file: " + path;
            return result;
        }

        // Test readability
        std::ifstream test(path, std::ios::binary);
        if (!test.is_open()) {
            result.status = FileValidationStatus::Unreadable;
            result.errorMessage = "Error: cannot open file for reading: " + path;
            return result;
        }

        uintmax_t sz = fs::file_size(path, ec);
        if (ec) {
            result.status = FileValidationStatus::Unreadable;
            result.errorMessage = "Error: cannot determine file size: " + path;
            return result;
        }

        result.fileSize = static_cast<uint64_t>(sz);

        if (sz == 0) {
            result.status = FileValidationStatus::Empty;
            result.errorMessage = "Error: file is empty (0 bytes): " + path;
            return result;
        }

        result.status = FileValidationStatus::Valid;
        result.errorMessage.clear();
        return result;
    }

    std::string InputValidator::StatusToString(FileValidationStatus status, const std::string& path) {
        switch (status) {
            case FileValidationStatus::Valid:
                return "";
            case FileValidationStatus::DoesNotExist:
                return "Error: file does not exist: " + path;
            case FileValidationStatus::IsDirectory:
                return "Error: expected a file, but the supplied path is a directory: " + path;
            case FileValidationStatus::NotRegularFile:
                return "Error: expected a regular file, but the supplied path is not a regular file: " + path;
            case FileValidationStatus::Unreadable:
                return "Error: cannot open file for reading: " + path;
            case FileValidationStatus::Empty:
                return "Error: file is empty (0 bytes): " + path;
            default:
                return "Error: invalid file: " + path;
        }
    }

} // namespace Dracula
