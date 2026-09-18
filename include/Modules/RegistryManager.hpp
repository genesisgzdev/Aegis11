#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include "../Core/PolicyEngine.hpp"
#include "../Core/State.hpp"
#include "../Core/Utils.hpp"
#include <windows.h>
#include <string>
#include <utility>
#include <vector>

#pragma comment(lib, "advapi32.lib")

namespace Aegis::Modules {
    struct RegistryTarget {
        HKEY root;
        std::wstring path;
        std::wstring key;
        std::string id;
        std::string view;
        REGSAM sam;
    };

    inline std::vector<RegistryTarget> PrivacyRegistryTargets() {
        return {
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"), _X("AllowTelemetry"), "HKLM_AllowTelemetry", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection"), _X("DisableDiagnosticDataViewer"), "HKLM_DisableDiagnosticDataViewer", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"), _X("DisableWebSearch"), "HKLM_DisableWebSearch", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\Windows Search"), _X("AllowCortana"), "HKLM_AllowCortana", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\OneDrive"), _X("DisableFileSyncNGSC"), "HKLM_DisableFileSyncNGSC", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\CloudContent"), _X("DisableWindowsConsumerFeatures"), "HKLM_DisableWindowsConsumerFeatures", "64-bit", KEY_WOW64_64KEY},
            {HKEY_LOCAL_MACHINE, _X("SOFTWARE\\Policies\\Microsoft\\Windows\\System"), _X("EnableActivityFeed"), "HKLM_EnableActivityFeed", "64-bit", KEY_WOW64_64KEY},
            {HKEY_CURRENT_USER, _X("Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo"), _X("Enabled"), "HKCU_AdvertisingInfo", "64-bit", KEY_WOW64_64KEY},
        };
    }

    class RegistryManager {
        Core::Logger& log;

    public:
        explicit RegistryManager(Core::Logger& logger) : log(logger) {}

        void Snapshot(Core::SystemSnapshot& snapshot) {
            for (const auto& target : PrivacyRegistryTargets()) {
                Core::RegistryState rs;
                rs.fullPath = target.id;
                rs.exists = false;
                rs.type = REG_NONE;
                rs.view = target.view;
                HKEY raw_hk = nullptr;
                if (RegOpenKeyExW(target.root, target.path.c_str(), 0, KEY_READ | target.sam, &raw_hk) == ERROR_SUCCESS) {
                    Core::RegHandle hk = Core::RegHandle::From(raw_hk);
                    DWORD type = REG_NONE, size = 0;
                    if (RegQueryValueExW(hk.get(), target.key.c_str(), nullptr, &type, nullptr, &size) == ERROR_SUCCESS) {
                        rs.type = type;
                        rs.data.resize(size);
                        if (RegQueryValueExW(hk.get(), target.key.c_str(), nullptr, &type,
                                rs.data.empty() ? nullptr : rs.data.data(), &size) == ERROR_SUCCESS) {
                            rs.data.resize(size);
                            rs.exists = true;
                        } else {
                            rs.data.clear();
                        }
                    }
                }
                snapshot.registry[target.id] = std::move(rs);
            }
        }

        bool Restore(Core::PolicyEngine& engine, const std::string& id, const Core::RegistryState& state) {
            for (const auto& target : PrivacyRegistryTargets()) {
                if (target.id != id) continue;
                if (!state.exists) {
                    HKEY raw = nullptr;
                    if (RegOpenKeyExW(target.root, target.path.c_str(), 0, KEY_WRITE | target.sam, &raw) != ERROR_SUCCESS) return true;
                    Core::RegHandle hk = Core::RegHandle::From(raw);
                    const LONG deleted = RegDeleteValueW(hk.get(), target.key.c_str());
                    if (deleted != ERROR_SUCCESS && deleted != ERROR_FILE_NOT_FOUND) {
                        log.Log(Core::LogLevel::ERR, "STATE", "Registry absence restore failed: " + id);
                        return false;
                    }
                    return true;
                }
                Core::PolicyDefinition definition{};
                definition.name = L"snapshot-restore";
                definition.rootHive = target.root;
                definition.path = target.path;
                definition.key = target.key;
                definition.targetData.assign(state.data.begin(), state.data.end());
                switch (state.type) {
                    case REG_DWORD: definition.type = Core::RegType::DWORD; break;
                    case REG_QWORD: definition.type = Core::RegType::QWORD; break;
                    case REG_SZ: definition.type = Core::RegType::SZ; break;
                    case REG_EXPAND_SZ: definition.type = Core::RegType::EXPAND_SZ; break;
                    case REG_MULTI_SZ: definition.type = Core::RegType::MULTI_SZ; break;
                    default: definition.type = Core::RegType::BINARY; break;
                }
                if (!engine.ApplyPolicy(definition)) {
                    log.Log(Core::LogLevel::ERR, "STATE", "Registry restore failed: " + id);
                    return false;
                }
                log.Log(Core::LogLevel::INFO, "STATE", "Registry restore applied: " + id);
                return true;
            }
            log.Log(Core::LogLevel::ERR, "STATE", "Registry restore refused unknown snapshot id: " + id);
            return false;
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
                        log.Log(Core::LogLevel::INFO, "DRY-RUN", "Would set policy: " + Core::Utils::ws2s(k));
                    }
                }
            };
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
