#pragma once
#include "../Core/Logger.hpp"
#include "../Core/State.hpp"
#include "../Core/SysInfo.hpp"
#include "../Modules/ServiceManager.hpp"
#include "../Modules/RegistryManager.hpp"
#include "../Modules/TaskManager.hpp"
#include <filesystem>
#include <fstream>
#include <iomanip>

namespace Aegis::Engine {
    class StateController {
        Core::Logger& log;
        Modules::ServiceManager& sm;
        Modules::RegistryManager& rm;
        Modules::TaskManager& tm;

    public:
        StateController(Core::Logger& l, Modules::ServiceManager& s, Modules::RegistryManager& r, Modules::TaskManager& t) 
            : log(l), sm(s), rm(r), tm(t) {}

        void CreateBaseline(const std::string& filepath) {
            log.Log(Core::LogLevel::INFO, "STATE", "Creating global system baseline snapshot...");
            Core::SystemSnapshot snap;
            snap.format = "aegis11.system-snapshot";
            snap.schemaVersion = Core::SystemSnapshot::CurrentSchemaVersion;
            
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            std::tm tm_now; gmtime_s(&tm_now, &now);
            char time_buf[64]; std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_now);
            
            snap.timestamp = time_buf;
            const auto capabilities = Core::SysInfo::GetCapabilities();
            snap.osVersion = capabilities.osVersion.empty()
                ? "unknown"
                : capabilities.osVersion + "." + std::to_string(capabilities.buildNumber);

            sm.Snapshot(snap);
            rm.Snapshot(snap);
            tm.Snapshot(snap);

            const std::filesystem::path target(filepath);
            const std::filesystem::path temporary = target.string() + ".tmp." + std::to_string(GetCurrentProcessId());
            std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) {
                log.Log(Core::LogLevel::ERR, "STATE", "Failed to write snapshot file.");
                return;
            }

            nlohmann::json j = snap;
            out << std::setw(4) << j << '\n';
            out.flush();
            if (!out.good()) {
                out.close();
                std::error_code cleanupError;
                std::filesystem::remove(temporary, cleanupError);
                log.Log(Core::LogLevel::ERR, "STATE", "Failed to flush snapshot file.");
                return;
            }
            out.close();

            if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                std::error_code cleanupError;
                std::filesystem::remove(temporary, cleanupError);
                log.Log(Core::LogLevel::ERR, "STATE", "Failed to replace snapshot file atomically.");
                return;
            }
            log.Log(Core::LogLevel::INFO, "STATE", "Baseline saved to: " + filepath);
        }
    };
}
