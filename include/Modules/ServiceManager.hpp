#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
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

        void NeutralizeService(const std::wstring& name) {
            ScHandle hSCM(OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS));
            if (!hSCM) return;

            ScHandle hSvc(OpenServiceW(hSCM.get(), name.c_str(), SERVICE_STOP | SERVICE_CHANGE_CONFIG | SERVICE_QUERY_CONFIG));
            if (!hSvc) return;

            // 1. Disable Recovery Actions (Anti-Restart)
            SERVICE_FAILURE_ACTIONS fa = {0};
            fa.dwResetPeriod = INFINITE;
            ChangeServiceConfig2W(hSvc.get(), SERVICE_CONFIG_FAILURE_ACTIONS, &fa);

            // Advanced mitigation: Wipe Trigger-Start Events (WNF, ETW, Network State Changes)
            SERVICE_TRIGGER_INFO triggerInfo = {0};
            triggerInfo.cTriggers = 0; // Wipe array
            ChangeServiceConfig2W(hSvc.get(), SERVICE_CONFIG_TRIGGER_INFO, &triggerInfo);

            // 2. Stop and Disable
            SERVICE_STATUS ss;
            ControlService(hSvc.get(), SERVICE_CONTROL_STOP, &ss);
            ChangeServiceConfigW(hSvc.get(), SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
            
            log.Log(Core::LogLevel::INFO, "SVC", 200, "Neutralized service & disabled recovery: " + Core::Utils::ws2s(name));
        }

        void EnforcePolicy(bool dryRun) {
            if (dryRun) return;
            std::vector<std::wstring> targets = { L"DiagTrack", L"dmwappushservice", L"WerSvc", L"PcaSvc", L"edgeupdate", L"edgeupdatem" };
            for (const auto& s : targets) NeutralizeService(s);
        }
    };
}
