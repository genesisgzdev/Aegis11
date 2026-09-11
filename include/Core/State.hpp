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
        DWORD serviceType;
        DWORD startType;
        DWORD errorControl;
        DWORD currentState;
        std::string binaryPath;
        std::string loadOrderGroup;
        std::string accountName;
        std::vector<std::string> dependencies;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(ServiceState, name, serviceType, startType, errorControl, currentState, binaryPath, loadOrderGroup, accountName, dependencies)
    };

    struct RegistryState {
        std::string fullPath;
        DWORD type;
        std::vector<std::uint8_t> data;
        bool exists;
        std::string view;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(RegistryState, fullPath, type, data, exists, view)
    };

    struct TaskState {
        std::string path;
        bool isEnabled;
        bool exists;
        std::string xml;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(TaskState, path, isEnabled, exists, xml)
    };

    struct SystemSnapshot {
        std::string schemaVersion = "1";
        std::string timestamp;
        std::string osVersion;
        std::map<std::string, ServiceState> services;
        std::map<std::string, RegistryState> registry;
        std::map<std::string, TaskState> tasks;
        NLOHMANN_DEFINE_TYPE_INTRUSIVE(SystemSnapshot, schemaVersion, timestamp, osVersion, services, registry, tasks)
    };
}
