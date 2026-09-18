#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/State.hpp"
#include "../Core/Utils.hpp"
#include <windows.h>
#include <winsvc.h>
#include <string>
#include <vector>
#include <set>
#include <utility>

namespace Aegis::Modules {
    class ScHandle {
        SC_HANDLE h;
    public:
        explicit ScHandle(SC_HANDLE handle) : h(handle) {}
        ~ScHandle() { if (h) CloseServiceHandle(h); h = NULL; }
        SC_HANDLE get() const { return h; }
        operator bool() const { return h != NULL; }
    };

    class ServiceManager {
        Core::Logger& log;
        std::set<std::wstring> visited;

    public:
        explicit ServiceManager(Core::Logger& logger) : log(logger) {}

        void Snapshot(Core::SystemSnapshot& snapshot) {
            const std::vector<std::wstring> targets = {
                L"DiagTrack", L"dmwappushservice", L"WerSvc", L"PcaSvc", L"edgeupdate", L"edgeupdatem"
            };
            ScHandle hSCM(OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT));
            if (!hSCM) return;
            for (const auto& name : targets) {
                ScHandle service(OpenServiceW(hSCM.get(), name.c_str(), SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS));
                if (!service) continue;
                DWORD bytes = 0;
                QueryServiceConfigW(service.get(), nullptr, 0, &bytes);
                if (!bytes) continue;
                std::vector<BYTE> buffer(bytes);
                auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
                if (!QueryServiceConfigW(service.get(), config, bytes, &bytes)) continue;
                SERVICE_STATUS status{};
                if (!QueryServiceStatus(service.get(), &status)) continue;
                const std::string key = Core::Utils::ws2s(name);
                Core::ServiceState state;
                state.name = key;
                state.serviceType = config->dwServiceType;
                state.startType = config->dwStartType;
                state.errorControl = config->dwErrorControl;
                state.currentState = status.dwCurrentState;
                state.binaryPath = config->lpBinaryPathName ? Core::Utils::ws2s(config->lpBinaryPathName) : "";
                state.loadOrderGroup = config->lpLoadOrderGroup ? Core::Utils::ws2s(config->lpLoadOrderGroup) : "";
                state.accountName = config->lpServiceStartName ? Core::Utils::ws2s(config->lpServiceStartName) : "";
                if (config->lpDependencies) {
                    for (const wchar_t* dependency = config->lpDependencies; *dependency; dependency += wcslen(dependency) + 1) {
                        state.dependencies.push_back(Core::Utils::ws2s(dependency));
                    }
                }
                snapshot.services[key] = std::move(state);
            }
        }

        bool Restore(const Core::ServiceState& desired) {
            const std::wstring name = Core::Utils::s2ws(desired.name);
            ScHandle hSCM(OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE));
            if (!hSCM) {
                log.Log(Core::LogLevel::ERR, "SVC", 500, "Cannot open service control manager for restore.");
                return false;
            }
            ScHandle service(OpenServiceW(hSCM.get(), name.c_str(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP));
            if (!service) {
                log.Log(Core::LogLevel::ERR, "SVC", 501, "Restore refused: service is absent and creation is out of snapshot scope: " + desired.name);
                return false;
            }
            DWORD bytes = 0;
            QueryServiceConfigW(service.get(), nullptr, 0, &bytes);
            if (!bytes) return false;
            std::vector<BYTE> buffer(bytes);
            auto* config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(buffer.data());
            if (!QueryServiceConfigW(service.get(), config, bytes, &bytes)) return false;
            const std::string liveBinary = config->lpBinaryPathName ? Core::Utils::ws2s(config->lpBinaryPathName) : "";
            if (liveBinary != desired.binaryPath) {
                log.Log(Core::LogLevel::ERR, "SVC", 502, "Restore refused: binary path drifted for " + desired.name);
                return false;
            }
            const std::wstring group = Core::Utils::s2ws(desired.loadOrderGroup);
            const std::wstring account = Core::Utils::s2ws(desired.accountName);
            std::wstring deps;
            for (const auto& dependency : desired.dependencies) {
                deps += Core::Utils::s2ws(dependency);
                deps.push_back(L'\0');
            }
            deps.push_back(L'\0');
            if (!ChangeServiceConfigW(service.get(), desired.serviceType, desired.startType, desired.errorControl,
                    NULL, group.empty() ? NULL : group.c_str(), NULL, deps.c_str(),
                    account.empty() ? NULL : account.c_str(), NULL, NULL)) {
                log.Log(Core::LogLevel::ERR, "SVC", 503, "Restore failed to write service configuration: " + desired.name);
                return false;
            }
            SERVICE_STATUS status{};
            if (!QueryServiceStatus(service.get(), &status)) return false;
            if (desired.currentState == SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOPPED) {
                ControlService(service.get(), SERVICE_CONTROL_STOP, &status);
            } else if (desired.currentState == SERVICE_RUNNING && status.dwCurrentState != SERVICE_RUNNING) {
                StartServiceW(service.get(), 0, nullptr);
            }
            log.Log(Core::LogLevel::INFO, "SVC", 210, "Restored journaled service configuration: " + desired.name);
            return true;
        }

        void NeutralizeService(const std::wstring& name) {
            ScHandle hSCM(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
            if (!hSCM) return;
            ScHandle hSvc(OpenServiceW(hSCM.get(), name.c_str(), SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG));
            if (!hSvc) return;
            SERVICE_STATUS ss;
            ControlService(hSvc.get(), SERVICE_CONTROL_STOP, &ss);
            ChangeServiceConfigW(hSvc.get(), SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            log.Log(Core::LogLevel::INFO, "SVC", 200, "Neutralized service and preserved recovery configuration: " + Core::Utils::ws2s(name));
        }

        void EnforcePolicy(bool dryRun) {
            const std::vector<std::wstring> targets = { L"DiagTrack", L"dmwappushservice", L"WerSvc", L"PcaSvc", L"edgeupdate", L"edgeupdatem" };
            for (const auto& s : targets) {
                if (dryRun) {
                    log.Log(Core::LogLevel::INFO, "SVC", 150, "Dry-run: would stop and disable service: " + Core::Utils::ws2s(s));
                } else {
                    NeutralizeService(s);
                }
            }
        }
    };
}
