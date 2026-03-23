#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include <windows.h>
#include <string>
#include <filesystem>
#include <vector>

namespace Aegis::Modules {
    class DataPurge {
        Core::Logger& log;

        void SafeDelete(const std::wstring& path) {
            std::error_code ec;
            if (std::filesystem::exists(path, ec)) {
                if (!DeleteFileW(path.c_str())) {
                    DWORD err = GetLastError();
                    if (err == ERROR_ACCESS_DENIED || err == ERROR_SHARING_VIOLATION) {
                        // Delayed delete via MoveFileEx for locked files (e.g. active CBS logs)
                        if (MoveFileExW(path.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT)) {
                            log.Log(Core::LogLevel::DEBUG, "DATA", 101, "File locked. Scheduled for deletion on reboot: " + Core::Utils::ws2s(path));
                        }
                    }
                }
            }
        }

    public:
        explicit DataPurge(Core::Logger& logger) : log(logger) {}

        void Execute(bool dryRun) {
            log.Log(Core::LogLevel::INFO, "DATA", 100, "Executing Safe Data Purge (Delayed deletes for locked files)...");
            if (dryRun) return;

            std::vector<std::wstring> dirs = {
                L"C:\\ProgramData\\Microsoft\\Diagnosis\\ETLLogs",
                L"C:\\Windows\\Temp\\DiagTrack"
            };

            for (const auto& dir : dirs) {
                std::error_code ec;
                if (std::filesystem::exists(dir, ec) && std::filesystem::is_directory(dir, ec)) {
                    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
                        if (!entry.is_directory()) {
                            SafeDelete(entry.path().wstring());
                        }
                    }
                }
            }
            log.Log(Core::LogLevel::INFO, "DONE", 200, "Telemetry data purged or scheduled for reboot.");
        }
    };
}
