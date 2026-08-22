#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/State.hpp"
#include <windows.h>
#include <winsvc.h>
#include <string>
#include <vector>
#include <set>

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
                snapshot.services[key] = Core::ServiceState{key, config->dwStartType, status.dwCurrentState};
            }
        }

        void NeutralizeService(const std::wstring& name) {
            ScHandle hSCM(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
            if (!hSCM) return;

            ScHandle hSvc(OpenServiceW(hSCM.get(), name.c_str(), SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG));
            if (!hSvc) return;

            // Only change the running/start state currently represented by the
            // service snapshot. Recovery actions and trigger definitions are
            // intentionally preserved until they have a journaled snapshot.
            SERVICE_STATUS ss;
            ControlService(hSvc.get(), SERVICE_CONTROL_STOP, &ss);
            ChangeServiceConfigW(hSvc.get(), SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            
            log.Log(Core::LogLevel::INFO, "SVC", 200, "Neutralized service & disabled recovery: " + Core::Utils::ws2s(name));
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
