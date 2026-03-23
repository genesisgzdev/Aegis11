#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include <windows.h>
#include <winsvc.h>
#include <aclapi.h>
#include <sddl.h>
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
        
        bool LockRegistryKey(HKEY root, const std::wstring& path) {
            std::wstring rootStr = (root == HKEY_LOCAL_MACHINE) ? _X("MACHINE\\") : _X("CURRENT_USER\\");
            std::wstring fullPath = rootStr + path;
            PSID pSystemSID = NULL, pTiSID = NULL;
            if (!ConvertStringSidToSidW(_X("S-1-5-18").c_str(), &pSystemSID)) return false;
            if (!ConvertStringSidToSidW(_X("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464").c_str(), &pTiSID)) { LocalFree(pSystemSID); return false; }
            PACL pOldDACL = NULL, pNewDACL = NULL; PSECURITY_DESCRIPTOR pSD = NULL;
            if (GetNamedSecurityInfoW(fullPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS) {
                LocalFree(pSystemSID); LocalFree(pTiSID); return false;
            }
            EXPLICIT_ACCESS_W ea[2] = {0};
            DWORD denyMask = KEY_WRITE | DELETE | WRITE_DAC | WRITE_OWNER;
            for (int i = 0; i < 2; i++) {
                ea[i].grfAccessPermissions = denyMask; ea[i].grfAccessMode = DENY_ACCESS;
                ea[i].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
                ea[i].Trustee.TrusteeForm = TRUSTEE_IS_SID; ea[i].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            }
            ea[0].Trustee.ptstrName = (LPWSTR)pSystemSID; ea[1].Trustee.ptstrName = (LPWSTR)pTiSID;
            bool success = false;
            if (SetEntriesInAclW(2, ea, pOldDACL, &pNewDACL) == ERROR_SUCCESS) {
                success = (SetNamedSecurityInfoW((LPWSTR)fullPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) == ERROR_SUCCESS);
                LocalFree(pNewDACL);
            }
            if (pSD) LocalFree(pSD); LocalFree(pSystemSID); LocalFree(pTiSID);
            return success;
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
            log.Log(Core::LogLevel::L_INFO, "INFO", "Blocking Edge via IFEO...");
            if (d) return;
            HKEY h;
            std::wstring path = _X("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\msedge.exe");
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) == ERROR_SUCCESS) {
                Core::RegHandle hk = Core::RegHandle::From(h);
                std::wstring dbg = _X("systray.exe");
                RegSetValueExW(hk.get(), _X("Debugger").c_str(), 0, REG_SZ, (const BYTE*)dbg.c_str(), (dbg.length() + 1) * sizeof(wchar_t));
                LockRegistryKey(HKEY_LOCAL_MACHINE, path);
            }
        }
        void Eradicate(bool d) {
            log.Log(Core::LogLevel::L_INFO, "INFO", "Hard-Uninstalling Microsoft Edge...");
            std::wstring s = FindInstaller();
            if (s.empty()) return;
            if (d) return;
            ExecuteSilent(_X("\"") + s + _X("\" --uninstall --system-level --force-uninstall"));
            DeleteServiceNative(_X("edgeupdate"));
            DeleteServiceNative(_X("edgeupdatem"));
            log.Log(Core::LogLevel::L_INFO, "DONE", "Edge eradication complete.");
        }
    };
}
