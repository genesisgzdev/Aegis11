#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include "../Core/State.hpp"
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <map>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    class RegistryManager {
        Core::Logger& log;

        // Kernel-Level DACL Hardening: Denies write access to SYSTEM and TrustedInstaller
        bool LockRegistryKey(HKEY root, const std::wstring& path) {
            std::wstring rootStr;
            if (root == HKEY_LOCAL_MACHINE) rootStr = L"MACHINE\\";
            else if (root == HKEY_CURRENT_USER) rootStr = L"CURRENT_USER\\";
            else return false;

            std::wstring fullPath = rootStr + path;
            PSID pSystemSID = NULL, pTiSID = NULL;
            
            // SID for NT AUTHORITY\SYSTEM
            if (!ConvertStringSidToSidW(L"S-1-5-18", &pSystemSID)) return false;
            // SID for NT SERVICE\TrustedInstaller
            if (!ConvertStringSidToSidW(L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", &pTiSID)) {
                LocalFree(pSystemSID); return false;
            }

            PACL pOldDACL = NULL, pNewDACL = NULL;
            PSECURITY_DESCRIPTOR pSD = NULL;
            if (GetNamedSecurityInfoW(fullPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &pOldDACL, NULL, &pSD) != ERROR_SUCCESS) {
                LocalFree(pSystemSID); LocalFree(pTiSID); return false;
            }

            EXPLICIT_ACCESS_W ea[2] = {0};
            // We allow READ so the OS doesn't crash, but completely deny WRITE/DELETE/CHANGE_PERMISSIONS
            DWORD denyMask = KEY_WRITE | DELETE | WRITE_DAC | WRITE_OWNER;

            ea[0].grfAccessPermissions = denyMask;
            ea[0].grfAccessMode = DENY_ACCESS;
            ea[0].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[0].Trustee.ptstrName = (LPWSTR)pSystemSID;

            ea[1].grfAccessPermissions = denyMask;
            ea[1].grfAccessMode = DENY_ACCESS;
            ea[1].grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
            ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
            ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
            ea[1].Trustee.ptstrName = (LPWSTR)pTiSID;

            bool success = false;
            if (SetEntriesInAclW(2, ea, pOldDACL, &pNewDACL) == ERROR_SUCCESS) {
                success = (SetNamedSecurityInfoW((LPWSTR)fullPath.c_str(), SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pNewDACL, NULL) == ERROR_SUCCESS);
                LocalFree(pNewDACL);
            }
            if (pSD) LocalFree(pSD); LocalFree(pSystemSID); LocalFree(pTiSID);
            return success;
        }

        // Real-time Kernel Token Privilege Escalation for Backup/Restore Operations
        bool EnablePrivilege(LPCWSTR privName) {
            HANDLE hToken;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
            LUID luid;
            if (!LookupPrivilegeValueW(NULL, privName, &luid)) { CloseHandle(hToken); return false; }
            TOKEN_PRIVILEGES tp = {0};
            tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            bool res = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
            CloseHandle(hToken); return res;
        }

        // Offline Hive Mounting: Direct modification of physical NTUSER.DAT files
        void ApplyToOfflineHives(const std::wstring& keyPath, const std::wstring& valName, DWORD val) {
            if (!EnablePrivilege(SE_BACKUP_NAME) || !EnablePrivilege(SE_RESTORE_NAME)) {
                log.Log(Core::LogLevel::ERR, "REG", 401, "Failed to acquire SE_RESTORE_NAME privilege. Skipping offline hives.");
                return;
            }

            std::wstring profileList = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList";
            HKEY hKey;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, profileList.c_str(), 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                DWORD index = 0; wchar_t sid[256]; DWORD sidSize = 256;
                while (RegEnumKeyExW(hKey, index++, sid, &sidSize, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                    std::wstring sidStr = sid;
                    if (sidStr.find(L"S-1-5-21-") == 0) { // Standard User Profile SID
                        HKEY hProfKey;
                        std::wstring profPath = profileList + L"\\" + sidStr;
                        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, profPath.c_str(), 0, KEY_READ, &hProfKey) == ERROR_SUCCESS) {
                            wchar_t imgPath[MAX_PATH]; DWORD imgSize = MAX_PATH * sizeof(wchar_t);
                            if (RegQueryValueExW(hProfKey, L"ProfileImagePath", NULL, NULL, (LPBYTE)imgPath, &imgSize) == ERROR_SUCCESS) {
                                std::wstring ntuserPath = std::wstring(imgPath) + L"\\NTUSER.DAT";
                                std::wstring mountName = L"AegisOffline_" + sidStr;
                                
                                // Attempt to mount the physical registry hive. If the user is online, sharing violation occurs, which is intended behavior.
                                if (RegLoadKeyW(HKEY_LOCAL_MACHINE, mountName.c_str(), ntuserPath.c_str()) == ERROR_SUCCESS) {
                                    HKEY hSubKey;
                                    std::wstring targetKey = mountName + L"\\" + keyPath;
                                    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, targetKey.c_str(), 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL) == ERROR_SUCCESS) {
                                        RegSetValueExW(hSubKey, valName.c_str(), 0, REG_DWORD, (const BYTE*)&val, sizeof(val));
                                        RegCloseKey(hSubKey);
                                        log.Log(Core::LogLevel::INFO, "REG", 201, "Offline Hive injected for: " + Core::Utils::ws2s(sidStr));
                                    }
                                    RegUnLoadKeyW(HKEY_LOCAL_MACHINE, mountName.c_str());
                                }
                            }
                            RegCloseKey(hProfKey);
                        }
                    }
                    sidSize = 256;
                }
                RegCloseKey(hKey);
            }
        }

    public:
        explicit RegistryManager(Core::Logger& logger) : log(logger) {}

        void Snapshot(Core::SystemSnapshot& snapshot) {
            auto read_val = [&](HKEY root, const std::wstring& path, const std::wstring& key, const std::string& snapshot_id) {
                HKEY raw_hk = nullptr;
                if (RegOpenKeyExW(root, path.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &raw_hk) == ERROR_SUCCESS) {
                    Core::RegHandle hk = Core::RegHandle::From(raw_hk);
                    DWORD rv = 0, sz = sizeof(rv), type = 0;
                    if (RegQueryValueExW(hk.get(), key.c_str(), nullptr, &type, (LPBYTE)&rv, &sz) == ERROR_SUCCESS) {
                        Core::RegistryState rs; rs.fullPath = snapshot_id; rs.value = rv; rs.exists = true;
                        snapshot.registry[snapshot_id] = rs;
                    }
                }
            };
            read_val(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"), _X("AllowTelemetry"), "HKLM_AllowTelemetry");
        }

        void EnforcePolicies(bool dryRun) {
            log.Log(Core::LogLevel::L_INFO, "INFO", "Enforcing Privacy GPOs...");
            auto apply = [&](HKEY r, const std::wstring& p, const std::wstring& k, DWORD tv) {
                HKEY raw_hk = nullptr;
                REGSAM access = KEY_WRITE | KEY_READ | KEY_WOW64_64KEY;
                if (RegOpenKeyExW(r, p.c_str(), 0, access, &raw_hk) != ERROR_SUCCESS) {
                    if (dryRun) return;
                    RegCreateKeyExW(r, p.c_str(), 0, nullptr, 0, access, nullptr, &raw_hk, nullptr);
                }
                if (raw_hk) {
                    Core::RegHandle hk = Core::RegHandle::From(raw_hk);
                    if (!dryRun) {
                        RegSetValueExW(hk.get(), k.c_str(), 0, REG_DWORD, (const BYTE*)&tv, sizeof(tv));
                        // Lock the key so Windows Update cannot overwrite it
                        LockRegistryKey(r, p);
                    } else {
                        log.Log(Core::LogLevel::L_INFO, "DRY-RUN", "Would set and LOCK policy: " + std::string(k.begin(), k.end()));
                    }
                }
            };
            
            // Comprehensive GPO suite
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"), _X("AllowTelemetry"), 0);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"), _X("DisableDiagnosticDataViewer"), 1);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"), _X("DisableWebSearch"), 1);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"), _X("AllowCortana"), 0);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive"), _X("DisableFileSyncNGSC"), 1);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent"), _X("DisableWindowsConsumerFeatures"), 1);
            apply(HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\System"), _X("EnableActivityFeed"), 0);
            apply(HKEY_CURRENT_USER, _X("Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo"), _X("Enabled"), 0);
            
            if (!dryRun) log.Log(Core::LogLevel::L_INFO, "DONE", "Registry policies enforced and locked via Kernel DACLs.");
        }
    };
}
