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
#include <cstring>
#include <limits>

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
            std::cout << "Aegis11 | Privacidad de Windows\n";
            std::cout << "Windows " << caps.osVersion << " (" << caps.buildNumber << ") [" << caps.sku << "]\n";
            std::cout << "Equipo: " << (caps.is64Bit ? "x64" : "x86") << " (" << caps.processorCount << " nucleos)\n";
            std::cout << "Revisa cada cambio antes de decidir.\n";
        }

        void PrintMenu() {
            std::cout << "\nQue quieres hacer?\n\n";
            std::cout << "  1   Revisar ajustes de privacidad\n";
            std::cout << "  R   Deshacer los cambios guardados por Aegis\n";
            std::cout << "  0   Salir\n\nElige una opcion: ";
        }

        std::vector<Core::PolicyDefinition> GetBasePolicies() {
            std::vector<BYTE> val0 = {0,0,0,0};
            std::vector<BYTE> val1 = {1,0,0,0};
            return {
                {L"Reducir el envio de datos de diagnostico", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection", L"AllowTelemetry", Core::RegType::DWORD, val0},
                {L"Desactivar Copilot", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsCopilot", L"TurnOffWindowsCopilot", Core::RegType::DWORD, val1},
                {L"Desactivar resultados web en la busqueda", HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search", L"DisableWebSearch", Core::RegType::DWORD, val1},
            };
        }

        bool ConfirmExecution(const std::vector<Core::PolicyDefinition>& policies, const std::string& profile) {
            std::cout << "\nCambios propuestos | " << profile << "\n";
            std::cout << "Estos ajustes dependen de la edicion de Windows.\n\n";

            // Real Diff Generation for Registry GPOs
            for (const auto& p : policies) {
                HKEY hKey;
                DWORD currentVal = 0;
                bool exists = false;
                const LSTATUS opened = RegOpenKeyExW(p.rootHive, p.path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hKey);
                if (opened == ERROR_SUCCESS) {
                    DWORD type = 0, size = sizeof(DWORD);
                    const LSTATUS queried = RegQueryValueExW(hKey, p.key.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(&currentVal), &size);
                    RegCloseKey(hKey);
                    if (queried == ERROR_SUCCESS && type == REG_DWORD && size == sizeof(DWORD)) {
                        exists = true;
                    } else if (queried != ERROR_FILE_NOT_FOUND) {
                        std::cout << "No se pudo leer el valor actual con certeza. No se aplicara esta propuesta.\n";
                        return false;
                    }
                } else if (opened != ERROR_FILE_NOT_FOUND && opened != ERROR_PATH_NOT_FOUND) {
                    std::cout << "Windows no permitio consultar un ajuste. Revisa los permisos antes de continuar.\n";
                    return false;
                }

                DWORD targetVal = 0;
                std::memcpy(&targetVal, p.targetData.data(), sizeof(targetVal));
                std::cout << "  " << Core::Utils::ws2s(p.name) << "\n";
                if (exists) {
                    if (currentVal == targetVal) std::cout << "    Ya tiene el valor " << targetVal << "\n";
                    else std::cout << "    Valor actual: " << currentVal << " | Nuevo valor: " << targetVal << "\n";
                } else {
                    std::cout << "    Se guardara un ajuste nuevo con valor " << targetVal << "\n";
                }
            }

            std::cout << "\nSe guarda el estado anterior para poder deshacer estos ajustes.\n";
            std::cout << "Escribe SI para aplicarlos o cualquier otra cosa para volver: ";
            std::string ans; std::cin >> ans;
            return (ans == "SI" || ans == "YES");
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
                    std::cout << "Hay una recuperacion pendiente. Elige R antes de aplicar otros cambios.\n";
                }

                PrintMenu();
                char choice;
                if (!(std::cin >> choice)) {
                    if (std::cin.eof()) break;
                    std::cin.clear(); std::cin.ignore(10000, '\n'); continue;
                }

                auto basePols = GetBasePolicies();
                switch (choice) {
                    case '1':
                        if (Core::ProcessHost::CurrentState == Core::AppState::RECOVERY) {
                            std::cout << "Primero recupera los cambios pendientes con R.\n";
                            break;
                        }
                        if (ConfirmExecution(basePols, "Privacidad")) {
                            for (const auto& p : basePols) {
                                if (!engine.ApplyPolicy(p)) {
                                    std::cout << "No se pudo guardar un ajuste. Se detuvieron los siguientes cambios. Revisa el registro antes de continuar.\n";
                                    break;
                                }
                            }
                        }
                        break;
                    case '2':
                        std::cout << "[!] Balanced is disabled: service, task and Appx mutations do not yet share a journaled rollback plan.\n";
                        break;
                    case '3':
                        std::cout << "[!] Aggressive is disabled: it includes non-journaled and potentially irreversible operations.\n";
                        break;
                    case 'r': case 'R':
                        if (engine.RollbackAll()) {
                            Core::ProcessHost::CurrentState = Core::AppState::NORMAL;
                            std::cout << "Se recuperaron los cambios guardados.\n";
                        } else {
                            Core::ProcessHost::CurrentState = Core::AppState::RECOVERY;
                            std::cout << "Quedan cambios por recuperar. Se conserva el registro para volver a intentarlo.\n";
                        }
                        break;
                    case '0': running = false; break;
                    default: std::cout << "Elige 1, R o 0.\n"; break;
                }
                if(running) { std::cout << "\nPulsa Enter para volver al menu."; std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); std::cin.get(); }
            }
        }
    };
}
