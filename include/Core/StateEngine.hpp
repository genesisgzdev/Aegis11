#pragma once
#include "../Core/Logger.hpp"
#include "../Core/State.hpp"
#include "../Modules/ServiceManager.hpp"
#include "../Modules/RegistryManager.hpp"
#include "../Modules/TaskManager.hpp"
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
            log.Log(Core::LogLevel::L_INFO, "STATE", "Creating global system baseline snapshot...");
            Core::SystemSnapshot snap;
            
            auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
            std::tm tm_now; localtime_s(&tm_now, &now);
            char time_buf[64]; std::strftime(time_buf, sizeof(time_buf), "%Y-%m-%dT%H:%M:%SZ", &tm_now);
            
            snap.timestamp = time_buf;
            snap.osVersion = "Windows 11 (Dynamic)";

            sm.Snapshot(snap);
            rm.Snapshot(snap);
            tm.Snapshot(snap);

            std::ofstream out(filepath);
            if (out.is_open()) {
                nlohmann::json j = snap;
                out << std::setw(4) << j << std::endl;
                log.Log(Core::LogLevel::L_INFO, "STATE", "Baseline saved to: " + filepath);
            } else {
                log.Log(Core::LogLevel::L_ERR, "STATE", "Failed to write snapshot file.");
            }
        }
    };
}
