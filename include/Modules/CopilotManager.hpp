#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include <windows.h>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    class CopilotManager {
        Core::Logger& log;

    public:
        explicit CopilotManager(Core::Logger& logger) : log(logger) {}
        void Eradicate(bool dryRun) {
            log.Log(Core::LogLevel::INFO, "AI", "Neutralizing Windows Copilot infrastructure...");
            if (dryRun) return;
            HKEY h;
            std::wstring path = _X("Software\\Policies\\Microsoft\\Windows\\WindowsCopilot");
            if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) == ERROR_SUCCESS) {
                Core::RegHandle hk = Core::RegHandle::From(h);
                DWORD val = 1; RegSetValueExW(hk.get(), _X("TurnOffWindowsCopilot").c_str(), 0, REG_DWORD, (const BYTE*)&val, 4);
            }
            log.Log(Core::LogLevel::INFO, "DONE", "Copilot policy applied; ACLs were left unchanged because they are not journaled.");
        }
    };
}
