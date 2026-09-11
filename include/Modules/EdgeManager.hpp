#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include <windows.h>
#include <winsvc.h>
#include <string>
#include <filesystem>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    class EdgeManager {
        Core::Logger& log;
        void ExecuteSilent(const std::wstring& cmd) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {};
            std::wstring mcmd = cmd;
            if (CreateProcessW(nullptr, &mcmd[0], nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                WaitForSingleObject(pi.hProcess, 120000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
            }
        }
        
        std::wstring FindInstaller() {
            wchar_t pf86[MAX_PATH];
            ExpandEnvironmentStringsW(_X("%ProgramFiles(x86)%\\Microsoft\\Edge\\Application").c_str(), pf86, MAX_PATH);
            std::wstring base = pf86;
            if (std::filesystem::exists(base)) {
                for (const auto& e : std::filesystem::directory_iterator(base)) {
                    if (e.is_directory()) {
                        std::wstring p = e.path().wstring() + _X("\\Installer\\setup.exe");
                        if (std::filesystem::exists(p)) return p;
                    }
                }
            }
            return L"";
        }
    public:
        explicit EdgeManager(Core::Logger& logger) : log(logger) {}
        void Neuter(bool d) {
            log.Log(Core::LogLevel::INFO, "INFO", "Blocking Edge via IFEO...");
            if (d) return;
            HKEY h;
            std::wstring path = _X("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msedge.exe");
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) == ERROR_SUCCESS) {
                Core::RegHandle hk = Core::RegHandle::From(h);
                std::wstring dbg = _X("systray.exe");
                RegSetValueExW(hk.get(), _X("Debugger").c_str(), 0, REG_SZ, (const BYTE*)dbg.c_str(), (dbg.length() + 1) * sizeof(wchar_t));
            }
        }
        void Eradicate(bool d) {
            log.Log(Core::LogLevel::INFO, "INFO", "Hard-Uninstalling Microsoft Edge...");
            std::wstring s = FindInstaller();
            if (s.empty()) return;
            if (d) return;
            ExecuteSilent(_X("\"") + s + _X("\" --uninstall --system-level --force-uninstall"));
            DeleteServiceNative(_X("edgeupdate"));
            DeleteServiceNative(_X("edgeupdatem"));
            log.Log(Core::LogLevel::INFO, "DONE", "Edge eradication complete.");
        }
    };
}
