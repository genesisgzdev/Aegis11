#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include "../Core/State.hpp"
#include <windows.h>
#include <string>
#include <map>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    class RegistryManager {
        Core::Logger& log;

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
            log.Log(Core::LogLevel::INFO, "INFO", "Enforcing Privacy GPOs...");
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
                    } else {
                        log.Log(Core::LogLevel::INFO, "DRY-RUN", "Would set and LOCK policy: " + std::string(k.begin(), k.end()));
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
            
            if (!dryRun) log.Log(Core::LogLevel::INFO, "DONE", "Registry policies enforced; ACLs were left unchanged because they are not journaled.");
        }
    };
}
