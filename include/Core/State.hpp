#pragma once
#include <windows.h>
#include <string>
#include <map>
#include <vector>
#include <cstdint>
#include "../Support/json.hpp"

namespace Aegis::Core {
    
    struct ServiceState {
        std::string name;
        DWORD startType;
        DWORD currentState;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(ServiceState, name, startType, currentState)
    };

    struct RegistryState {
        std::string fullPath;
        DWORD value;
        bool exists;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(RegistryState, fullPath, value, exists)
    };

    struct TaskState {
        std::string path;
        bool isEnabled;
        bool exists;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(TaskState, path, isEnabled, exists)
    };

    struct SystemSnapshot {
        static constexpr std::uint32_t CurrentSchemaVersion = 1;
        std::string format = "aegis11.system-snapshot";
        std::uint32_t schemaVersion = CurrentSchemaVersion;
        std::string timestamp;
        std::string osVersion;
        std::map<std::string, ServiceState> services;
        std::map<std::string, RegistryState> registry;
        std::map<std::string, TaskState> tasks;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(SystemSnapshot, format, schemaVersion, timestamp, osVersion, services, registry, tasks)
    };
}
