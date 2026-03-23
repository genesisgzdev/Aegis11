#pragma once
#include "../Core/Logger.hpp"
#include "../Core/Obfuscation.hpp"
#include <windows.h>
#include <string>
#include <fstream>
#include <vector>
#include <filesystem>

namespace Aegis::Modules {
    typedef BOOL(WINAPI *DnsFlushResolverCacheFunc)();

    class NetworkSinkhole {
        Core::Logger& log;

    public:
        explicit NetworkSinkhole(Core::Logger& logger) : log(logger) {}

        void Apply(bool dryRun) {
            log.Log(Core::LogLevel::L_INFO, "INFO", "Applying DNS sinkhole to hosts file...");
            wchar_t windir[MAX_PATH];
            ExpandEnvironmentStringsW(_X("%WINDIR%").c_str(), windir, MAX_PATH);
            std::filesystem::path hostsPath = std::filesystem::path(windir) / _X("System32") / _X("drivers") / _X("etc") / _X("hosts");
            std::filesystem::path tempPath = std::filesystem::temp_directory_path() / _X("hosts.aegis.tmp");
            std::filesystem::path backupPath = std::filesystem::path(windir) / _X("System32") / _X("drivers") / _X("etc") / _X("hosts.aegis.bak");
            
            if (dryRun) {
                log.Log(Core::LogLevel::L_INFO, "DRY-RUN", "Would inject telemetry null routes into " + hostsPath.string());
                return;
            }

            SetFileAttributesW(hostsPath.c_str(), FILE_ATTRIBUTE_NORMAL);

            std::ifstream in(hostsPath);
            std::ofstream out(tempPath, std::ios::trunc);
            
            if (!in || !out) { 
                log.Log(Core::LogLevel::L_ERR, "ERROR", "File I/O error. Hosts might be locked by AV."); 
                return; 
            }

            const std::vector<std::string> domains = {
                _XA("vortex.data.microsoft.com"), _XA("vortex-win.data.microsoft.com"), _XA("telecommand.telemetry.microsoft.com"), 
                _XA("oca.telemetry.microsoft.com"), _XA("sqm.telemetry.microsoft.com"), _XA("watson.telemetry.microsoft.com")
            };

            std::string line;
            while (std::getline(in, line)) { out << line << "\n"; }

            int added = 0;
            out << "\n# --- Aegis11 Telemetry Block ---\n";
            for (const auto& d : domains) {
                out << "0.0.0.0 " << d << "\n";
                out << ":: " << d << "\n"; 
                added += 2;
            }
            
            in.close(); out.close();

            if (ReplaceFileW(hostsPath.c_str(), tempPath.c_str(), backupPath.c_str(), REPLACEFILE_IGNORE_MERGE_ERRORS, nullptr, nullptr)) {
                log.Log(Core::LogLevel::L_INFO, "DONE", std::to_string(added) + " routes injected securely via ReplaceFileW.");
                HMODULE hDns = LoadLibraryW(_X("dnsapi.dll").c_str());
                if (hDns) {
                    auto pDnsFlush = (DnsFlushResolverCacheFunc)GetProcAddress(hDns, "DnsFlushResolverCache");
                    if (pDnsFlush && pDnsFlush()) log.Log(Core::LogLevel::L_INFO, "INFO", "Native DnsFlushResolverCache executed.");
                    FreeLibrary(hDns);
                }
            } else {
                log.Log(Core::LogLevel::L_ERR, "ERROR", "ReplaceFileW failed: " + log.GetLastErrorString());
            }
            std::filesystem::remove(tempPath);
        }
    };
}
