#pragma once
#include "../Core/Logger.hpp"
#include "../Core/PolicyEngine.hpp"
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

        bool CompatibleOperatingSystem(const Core::SystemSnapshot& snap) const {
            if (snap.osVersion.empty() || snap.osVersion == "unknown") return false;
            const auto capabilities = Core::SysInfo::GetCapabilities();
            const std::string current = capabilities.osVersion.empty()
                ? "unknown"
                : capabilities.osVersion + "." + std::to_string(capabilities.buildNumber);
            const auto snapDot = snap.osVersion.find('.');
            const auto currentDot = current.find('.');
            if (snapDot == std::string::npos || currentDot == std::string::npos) return false;
            const auto snapMinor = snap.osVersion.find('.', snapDot + 1);
            const auto currentMinor = current.find('.', currentDot + 1);
            const std::string snapFamily = snapMinor == std::string::npos ? snap.osVersion : snap.osVersion.substr(0, snapMinor);
            const std::string currentFamily = currentMinor == std::string::npos ? current : current.substr(0, currentMinor);
            return snapFamily == currentFamily;
        }

        bool AppendRestoreWal(const std::string& line) {
            std::ofstream out("aegis_restore_wal.jsonl", std::ios::binary | std::ios::app);
            if (!out.is_open()) return false;
            out << line << '\n';
            out.flush();
            return out.good();
        }

    public:
        StateController(Core::Logger& l, Modules::ServiceManager& s, Modules::RegistryManager& r, Modules::TaskManager& t)
            : log(l), sm(s), rm(r), tm(t) {}

        bool CreateBaseline(const std::string& filepath) {
            log.Log(Core::LogLevel::INFO, "STATE", "Creating global system baseline snapshot...");
            Core::SystemSnapshot snap;

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
                return false;
            }

            nlohmann::json j = snap;
            out << std::setw(4) << j << '\n';
            out.flush();
            if (!out.good()) {
                out.close();
                std::error_code cleanupError;
                std::filesystem::remove(temporary, cleanupError);
                log.Log(Core::LogLevel::ERR, "STATE", "Failed to flush snapshot file.");
                return false;
            }
            out.close();

            if (!MoveFileExW(temporary.c_str(), target.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
                std::error_code cleanupError;
                std::filesystem::remove(temporary, cleanupError);
                log.Log(Core::LogLevel::ERR, "STATE", "Failed to replace snapshot file atomically.");
                return false;
            }
            log.Log(Core::LogLevel::INFO, "STATE", "Baseline saved to: " + filepath);
            return true;
        }

        bool RestoreBaseline(const std::string& filepath, Core::PolicyEngine& engine) {
            std::ifstream in(filepath, std::ios::binary);
            if (!in.is_open()) {
                log.Log(Core::LogLevel::ERR, "STATE", "Snapshot file could not be opened.");
                return false;
            }
            nlohmann::json document;
            try {
                in >> document;
            } catch (const std::exception&) {
                log.Log(Core::LogLevel::ERR, "STATE", "Snapshot file is not valid JSON.");
                return false;
            }
            Core::SystemSnapshot snap;
            try {
                snap = document.get<Core::SystemSnapshot>();
            } catch (const std::exception&) {
                log.Log(Core::LogLevel::ERR, "STATE", "Snapshot schema could not be parsed.");
                return false;
            }
            if (snap.schemaVersion != "1") {
                log.Log(Core::LogLevel::ERR, "STATE", "Incompatible snapshot schema version: " + snap.schemaVersion);
                return false;
            }
            if (!CompatibleOperatingSystem(snap)) {
                log.Log(Core::LogLevel::ERR, "STATE", "Snapshot operating-system family does not match this host.");
                return false;
            }

            bool complete = true;
            if (!AppendRestoreWal("{\"phase\":\"pending\",\"file\":\"" + filepath + "\"}")) {
                log.Log(Core::LogLevel::ERR, "STATE", "Unable to persist restore WAL before mutations.");
                return false;
            }

            for (const auto& [id, state] : snap.registry) {
                if (!AppendRestoreWal("{\"phase\":\"registry\",\"id\":\"" + id + "\",\"state\":\"pending\"}")) {
                    complete = false;
                    break;
                }
                if (!rm.Restore(engine, id, state)) {
                    complete = false;
                    AppendRestoreWal("{\"phase\":\"registry\",\"id\":\"" + id + "\",\"state\":\"failed\"}");
                    break;
                }
                AppendRestoreWal("{\"phase\":\"registry\",\"id\":\"" + id + "\",\"state\":\"committed\"}");
            }

            if (complete) {
                for (const auto& [name, state] : snap.services) {
                    if (!AppendRestoreWal("{\"phase\":\"service\",\"id\":\"" + name + "\",\"state\":\"pending\"}")) {
                        complete = false;
                        break;
                    }
                    if (!sm.Restore(state)) {
                        complete = false;
                        AppendRestoreWal("{\"phase\":\"service\",\"id\":\"" + name + "\",\"state\":\"failed\"}");
                        break;
                    }
                    AppendRestoreWal("{\"phase\":\"service\",\"id\":\"" + name + "\",\"state\":\"committed\"}");
                }
            }

            if (complete) {
                for (const auto& [path, state] : snap.tasks) {
                    if (!AppendRestoreWal("{\"phase\":\"task\",\"id\":\"" + path + "\",\"state\":\"pending\"}")) {
                        complete = false;
                        break;
                    }
                    if (!tm.Restore(state)) {
                        complete = false;
                        AppendRestoreWal("{\"phase\":\"task\",\"id\":\"" + path + "\",\"state\":\"failed\"}");
                        break;
                    }
                    AppendRestoreWal("{\"phase\":\"task\",\"id\":\"" + path + "\",\"state\":\"committed\"}");
                }
            }

            log.Log(Core::LogLevel::INFO, "STATE", "Purge and Appx modules remain outside snapshot restore.");
            if (!complete) {
                log.Log(Core::LogLevel::ERR, "STATE", "Restore is incomplete and was not reported as success.");
                return false;
            }
            if (!AppendRestoreWal("{\"phase\":\"committed\",\"file\":\"" + filepath + "\"}")) {
                log.Log(Core::LogLevel::ERR, "STATE", "Restore mutations finished but the restore WAL could not be finalized.");
                return false;
            }
            log.Log(Core::LogLevel::INFO, "STATE", "Snapshot restore completed for captured registry, services and tasks.");
            return true;
        }
    };
}
