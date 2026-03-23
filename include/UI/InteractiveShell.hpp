#pragma once
#include "../Core/Logger.hpp"
#include "../Core/PolicyEngine.hpp"
#include "../Core/SysInfo.hpp"
#include "../Core/Utils.hpp"
#include "../Modules/AppxManager.hpp"
#include "../Modules/TaskManager.hpp"
#include "../Modules/NetworkWfp.hpp"
#include "../Modules/ServiceManager.hpp"
#include "../Modules/FirewallManager.hpp"
#include "../Modules/DataPurge.hpp"
#include "../Modules/NetworkOptimizer.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <iomanip>

namespace Aegis::UI {
    class InteractiveShell {
        Core::Logger& log;
        Core::PolicyEngine& engine;
        Modules::AppxManager& appx;
        Modules::TaskManager& tasks;
        Modules::NetworkWfp& wfp;
        Modules::ServiceManager& svc;
        Modules::FirewallManager& fw;
        Modules::DataPurge& data;
        Modules::NetworkOptimizer& netOpt;

        void PrintInfo() {
            auto caps = Core::SysInfo::GetCapabilities();
            std::cout << "Aegis System Controller\n";
            std::cout << "Host: Windows " << caps.osVersion << " (" << caps.buildNumber << ") [" << caps.sku << "]\n";
            std::cout << "Hardware: " << (caps.is64Bit ? "x64" : "x86") << " (" << caps.processorCount << " Cores)\n";
            std::cout << "--------------------------------------------------\n";
        }

        void PrintMenu() {
            std::cout << "\n Mitigation Presets:\n";
            std::cout << "  [1] Light (Safe GPOs, No App removal)\n";
            std::cout << "  [2] Balanced (GPOs, Services, Tasks, Edge/OneDrive)\n";
            std::cout << "  [3] Aggressive (Balanced, Appx Removal, WFP Kernel Block, FW COM)\n";
            std::cout << "  [R] Rollback WAL Database\n";
            std::cout << "  [0] Exit\n\n> ";
        }

        std::vector<Core::PolicyDefinition> GetBasePolicies() {
            std::vector<BYTE> val0 = {0,0,0,0};
            std::vector<BYTE> val1 = {1,0,0,0};
            return {
                {L"Disable Telemetry", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry", Core::RegType::DWORD, val0},
                {L"Disable Copilot", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot", L"TurnOffWindowsCopilot", Core::RegType::DWORD, val1},
                {L"Disable Web Search", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", L"DisableWebSearch", Core::RegType::DWORD, val1},
                {L"Block Edge Updates", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\EdgeUpdate", L"DoNotUpdateToEdgeWithChromium", Core::RegType::DWORD, val1}
            };
        }

        bool ConfirmExecution(const std::vector<Core::PolicyDefinition>& policies, const std::string& profile) {
            std::cout << "\n--- EXECUTION DIFF PREVIEW: " << profile << " ---\n";
            
            // Real Diff Generation for Registry GPOs
            for (const auto& p : policies) {
                HKEY hKey;
                DWORD currentVal = 0;
                bool exists = false;
                if (RegOpenKeyExW(p.rootHive, p.path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
                    DWORD type = 0, size = sizeof(DWORD);
                    if (RegQueryValueExW(hKey, p.key.c_str(), nullptr, &type, (LPBYTE)&currentVal, &size) == ERROR_SUCCESS) {
                        exists = true;
                    }
                    RegCloseKey(hKey);
                }

                DWORD targetVal = *((DWORD*)p.targetData.data());
                std::cout << " [GPO] " << Core::Utils::ws2s(p.name) << "\n";
                if (exists) {
                    if (currentVal == targetVal) std::cout << "       State: [OK] Already at " << targetVal << "\n";
                    else std::cout << "       State: [DRIFT] Will change " << currentVal << " -> " << targetVal << "\n";
                } else {
                    std::cout << "       State: [NEW] Will insert value " << targetVal << "\n";
                }
            }

            if (profile == "BALANCED" || profile == "AGGRESSIVE") {
                std::cout << " [COM] Will resolve dependencies and STOP Telemetry Services\n";
                std::cout << " [COM] Will verify Digital Signatures & Disable Telemetry Tasks\n";
            }
            if (profile == "AGGRESSIVE") {
                std::cout << " [COM] Will spawn native Appx removal operations\n";
                std::cout << " [WFP] Will commit Network Layer block for telemetry endpoints\n";
            }
            
            std::cout << "\nType 'YES' to authorize atomic execution: ";
            std::string ans; std::cin >> ans;
            return (ans == "YES");
        }

    public:
        InteractiveShell(Core::Logger& l, Core::PolicyEngine& e, Modules::AppxManager& am, Modules::TaskManager& tm, Modules::NetworkWfp& nw,
                         Modules::ServiceManager& sm, Modules::FirewallManager& fm, Modules::DataPurge& dp, Modules::NetworkOptimizer& no) 
            : log(l), engine(e), appx(am), tasks(tm), wfp(nw), svc(sm), fw(fm), data(dp), netOpt(no) {}

        void Run() {
            bool running = true;
            while (running) {
                Core::Utils::ClearScreen();
                PrintInfo();
                
                if (Core::ProcessHost::CurrentState == Core::AppState::RECOVERY) {
                    std::cout << "[!] SYSTEM IN RECOVERY STATE. Run Rollback [R] before applying new policies.\n";
                }

                PrintMenu();
                char choice;
                if (!(std::cin >> choice)) { std::cin.clear(); std::cin.ignore(10000, '\n'); continue; }
                
                auto basePols = GetBasePolicies();
                switch (choice) {
                    case '1': 
                        if (ConfirmExecution(basePols, "LIGHT")) {
                            for (const auto& p : basePols) engine.ApplyPolicy(p); 
                        }
                        break;
                    case '2': 
                        if (ConfirmExecution(basePols, "BALANCED")) {
                            for (const auto& p : basePols) engine.ApplyPolicy(p);
                            svc.EnforcePolicy(false);
                            tasks.DisableTelemetryTasks();
                            appx.RemoveEdgeAndOneDrive();
                        }
                        break;
                    case '3': 
                        if (ConfirmExecution(basePols, "AGGRESSIVE")) {
                            for (const auto& p : basePols) engine.ApplyPolicy(p);
                            svc.EnforcePolicy(false);
                            tasks.DisableTelemetryTasks();
                            fw.EnforceBlockRules(false);
                            wfp.EnforceHardBlock(false);
                            appx.RemoveEdgeAndOneDrive();
                            appx.RemoveBloatware(true);
                            data.Execute(false);
                            netOpt.UniversalHardening();
                        }
                        break;
                    case 'r': case 'R': engine.RollbackAll(); Core::ProcessHost::CurrentState = Core::AppState::NORMAL; break;
                    case '0': running = false; break;
                }
                if(running) { std::cout << "\nOperation Complete. Press Enter to return..."; std::cin.ignore(); std::cin.get(); }
            }
        }
    };
}
