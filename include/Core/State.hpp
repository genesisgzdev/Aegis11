#pragma once
#include <string>
#include <map>
#include <vector>
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
        std::string timestamp;
        std::string osVersion;
        std::map<std::string, ServiceState> services;
        std::map<std::string, RegistryState> registry;
        std::map<std::string, TaskState> tasks;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(SystemSnapshot, timestamp, osVersion, services, registry, tasks)
    };
}
