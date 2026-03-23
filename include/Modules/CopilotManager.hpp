#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    class CopilotManager {
        Core::Logger& log;

        bool LockRegistryKey(HKEY root, const std::wstring& path) {
            std::wstring rootStr = (root == HKEY_LOCAL_MACHINE) ? _X("MACHINE\\") : _X("CURRENT_USER\\");
            std::wstring fullPath = rootStr + path;
            PSID pSystemSID = NULL, pTiSID = NULL;
            
            if (!ConvertStringSidToSidW(_X("S-1-5-18").c_str(), &pSystemSID)) return false;
            if (!ConvertStringSidToSidW(_X("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464").c_str(), &pTiSID)) {
                LocalFree(pSystemSID); return false;
            }
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

    public:
        explicit CopilotManager(Core::Logger& logger) : log(logger) {}
        void Eradicate(bool dryRun) {
            log.Log(Core::LogLevel::L_INFO, "AI", "Neutralizing Windows Copilot infrastructure...");
            if (dryRun) return;
            HKEY h;
            std::wstring path = _X("Software\\Policies\\Microsoft\\Windows\\WindowsCopilot");
            if (RegCreateKeyExW(HKEY_CURRENT_USER, path.c_str(), 0, nullptr, 0, KEY_WRITE | KEY_WOW64_64KEY, nullptr, &h, nullptr) == ERROR_SUCCESS) {
                Core::RegHandle hk = Core::RegHandle::From(h);
                DWORD val = 1; RegSetValueExW(hk.get(), _X("TurnOffWindowsCopilot").c_str(), 0, REG_DWORD, (const BYTE*)&val, 4);
                LockRegistryKey(HKEY_CURRENT_USER, path);
            }
            log.Log(Core::LogLevel::L_INFO, "DONE", "Copilot neutralized and LOCKED via DACL.");
        }
    };
}
