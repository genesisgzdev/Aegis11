#pragma once
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include "../Core/PolicyEngine.hpp"
#include <windows.h>
#include <vector>

namespace Aegis::Modules {
    class NetworkOptimizer {
        Core::Logger& log;
        Core::PolicyEngine& engine;

    public:
        NetworkOptimizer(Core::Logger& logger, Core::PolicyEngine& eng) : log(logger), engine(eng) {}

        void UniversalHardening() {
            log.Log(Core::LogLevel::INFO, "NET", 100, "Hardening network stack (NCSI, LLMNR) via WAL...");
            
            std::vector<BYTE> val1 = {1,0,0,0};
            std::vector<BYTE> val0 = {0,0,0,0};

            // Using PolicyEngine ensures these changes are recorded in the WAL and reversible
            engine.ApplyPolicy({L"Disable Smart Name Resolution", HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows NT\\DNSClient", L"DisableSmartNameResolution", Core::RegType::DWORD, val1});
            engine.ApplyPolicy({L"Disable Multicast (LLMNR)", HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows NT\\DNSClient", L"EnableMulticast", Core::RegType::DWORD, val0});
            
            // NCSI Passive mode (Captive portals still work, but active telemetry pings stop)
            engine.ApplyPolicy({L"NCSI Passive Mode", HKEY_LOCAL_MACHINE, L"Software\\Policies\\Microsoft\\Windows\\NetworkConnectivityStatusIndicator", L"NoActiveProbe", Core::RegType::DWORD, val1});
        }

        void FlushResolver() {
            HMODULE hDns = LoadLibraryW(L"dnsapi.dll");
            if (hDns) {
                typedef BOOL(WINAPI *F)();
                auto f = (F)GetProcAddress(hDns, "DnsFlushResolverCache");
                if (f) f();
                FreeLibrary(hDns);
            }
        }
    };
}
