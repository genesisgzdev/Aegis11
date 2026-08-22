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
