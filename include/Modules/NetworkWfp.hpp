#pragma once
#include <winsock2.h>
#include <ws2tcpip.h>
#include "../Core/RAII.hpp"
#include "../Core/Logger.hpp"
#include <fwpmu.h>
#include <fwpmtypes.h>
#include <vector>
#include <string>

#pragma comment(lib, "ws2_32.lib")

#define AEGIS_WFP_VERSION L"v1.0"

// Multi-layer filtering to drop new authentication requests and already established data flows (ALE_AUTH_CONNECT & ALE_FLOW_ESTABLISHED)
static const GUID AEGIS_FWPM_LAYER_ALE_AUTH_CONNECT_V4 = { 0xc38d57d1, 0x05a7, 0x4c33, { 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82 } };
static const GUID AEGIS_FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 = { 0x51409b15, 0x38f1, 0x4dba, { 0xa4, 0x1b, 0x74, 0xd5, 0xc8, 0x6e, 0xa9, 0xc4 } };

static const GUID AEGIS_FWPM_CONDITION_IP_REMOTE_ADDRESS = { 0x0066cf4d, 0x9f9a, 0x4d99, { 0xba, 0x66, 0x25, 0x8d, 0x02, 0x39, 0xf7, 0x1a } };
static const GUID AEGIS_FWPM_CONDITION_IP_PROTOCOL = { 0x1aa0fae1, 0x86bd, 0x44a3, { 0x80, 0x86, 0x26, 0xd1, 0xe7, 0x47, 0xa1, 0xf6 } };
static const GUID AEGIS_PROVIDER_GUID = { 0x1A2B3C4D, 0x5E6F, 0x7A8B, { 0x9C, 0x0D, 0x1E, 0x2F, 0x3A, 0x4B, 0x5C, 0x6D } };
static const GUID AEGIS_SUBLAYER_GUID = { 0x11223344, 0x5566, 0x7788, { 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00 } };

#ifndef FWPM_FILTER_FLAG_PERSISTENT
#define FWPM_FILTER_FLAG_PERSISTENT (0x00000001)
#endif

// ICMP Structures for Dynamic API Resolution
typedef struct {
    ULONG Address;
    ULONG Status;
    ULONG RoundTripTime;
    USHORT DataSize;
    USHORT Reserved;
    void* Data;
    struct { UCHAR Ttl; UCHAR Tos; UCHAR Flags; UCHAR OptionsSize; void* OptionsData; } Options;
} AEGIS_ICMP_ECHO_REPLY;

typedef HANDLE (WINAPI *IcmpCreateFile_t)();
typedef DWORD (WINAPI *IcmpSendEcho_t)(HANDLE, ULONG, LPVOID, WORD, LPVOID, LPVOID, DWORD, DWORD);
typedef BOOL (WINAPI *IcmpCloseHandle_t)(HANDLE);

namespace Aegis::Modules {
    class NetworkWfp {
        Core::Logger& log;

        void CleanupOrphanedRules(HANDLE engine) {
            if (FwpmProviderDeleteByKey0(engine, &AEGIS_PROVIDER_GUID) == ERROR_SUCCESS) {
                log.Log(Core::LogLevel::INFO, "WFP", 200, "Cleaned up orphaned Aegis WFP rules based on Version-tagged Provider.");
            }
        }

        bool HealthCheckConnectivity() {
            HMODULE hIpHlp = LoadLibraryW(L"iphlpapi.dll");
            if (!hIpHlp) return false;

            auto pIcmpCreateFile = (IcmpCreateFile_t)GetProcAddress(hIpHlp, "IcmpCreateFile");
            auto pIcmpSendEcho = (IcmpSendEcho_t)GetProcAddress(hIpHlp, "IcmpSendEcho");
            auto pIcmpCloseHandle = (IcmpCloseHandle_t)GetProcAddress(hIpHlp, "IcmpCloseHandle");

            if (!pIcmpCreateFile || !pIcmpSendEcho || !pIcmpCloseHandle) {
                FreeLibrary(hIpHlp);
                return false;
            }

            HANDLE hIcmpFile = pIcmpCreateFile();
            if (hIcmpFile == INVALID_HANDLE_VALUE) {
                FreeLibrary(hIpHlp);
                return false;
            }

            char SendData[32] = "AegisHealthCheck";
            DWORD ReplySize = sizeof(AEGIS_ICMP_ECHO_REPLY) + sizeof(SendData) + 8;
            LPVOID ReplyBuffer = (VOID*)malloc(ReplySize);

            // Ping 1.1.1.1 using modern memory-safe parsing
            ULONG ipAddr = 0;
            InetPtonA(AF_INET, "1.1.1.1", &ipAddr);
            DWORD dwRetVal = pIcmpSendEcho(hIcmpFile, ipAddr, SendData, sizeof(SendData), NULL, ReplyBuffer, ReplySize, 2000);
            
            bool ok = (dwRetVal > 0);
            free(ReplyBuffer);
            pIcmpCloseHandle(hIcmpFile);
            FreeLibrary(hIpHlp);
            return ok;
        }

    public:
        explicit NetworkWfp(Core::Logger& logger) : log(logger) {}

        void EnforceHardBlock(bool dryRun) {
            log.Log(Core::LogLevel::INFO, "WFP", 100, "Initiating Versioned WFP Hard-Block Transaction...");
            if (dryRun) return;

            HANDLE h = NULL;
            for(int i=0; i<3; ++i) {
                if (FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &h) == ERROR_SUCCESS) break;
                Sleep(500);
            }
            if (!h) { log.Log(Core::LogLevel::FATAL, "WFP", 500, "WFP Engine failed to open after retries."); return; }
            Core::KernelHandle engine = Core::KernelHandle::From(h);

            CleanupOrphanedRules(engine.get());

            if (FwpmTransactionBegin0(engine.get(), 0) != ERROR_SUCCESS) return;

            FWPM_PROVIDER0 provider = {0};
            provider.providerKey = AEGIS_PROVIDER_GUID;
            std::wstring pName = std::wstring(L"Aegis11 Mitigation Engine ") + AEGIS_WFP_VERSION;
            provider.displayData.name = (wchar_t*)pName.c_str();
            FwpmProviderAdd0(engine.get(), &provider, NULL);

            FWPM_SUBLAYER0 sub = {0};
            sub.subLayerKey = AEGIS_SUBLAYER_GUID;
            sub.providerKey = (GUID*)&AEGIS_PROVIDER_GUID;
            sub.displayData.name = (wchar_t*)L"Aegis11 Immutable Sublayer";
            sub.weight = 0x00FF; 
            FwpmSubLayerAdd0(engine.get(), &sub, NULL);

            // Rate Limiting and Flood Protection: Utilizing CIDR subnets rather than individual IP rules
            struct { UINT32 ip; UINT32 mask; } rangesV4[] = { { 0x14B80000, 0xFFF80000 }, { 0x34910000, 0xFFFF0000 } };
            const GUID* layers[] = { &AEGIS_FWPM_LAYER_ALE_AUTH_CONNECT_V4, &AEGIS_FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4 };
            
            for (const auto& layer : layers) {
                for (const auto& r : rangesV4) {
                    FWPM_FILTER0 f = {0};
                    f.displayData.name = (wchar_t*)L"Aegis V4 Telemetry Block (Reauth/Est)";
                    f.providerKey = (GUID*)&AEGIS_PROVIDER_GUID;
                    f.layerKey = *layer;
                    f.subLayerKey = AEGIS_SUBLAYER_GUID;
                    f.action.type = FWP_ACTION_BLOCK;
                    f.weight.type = FWP_UINT8; f.weight.uint8 = 15;
                    f.flags = FWPM_FILTER_FLAG_PERSISTENT;

                    FWPM_FILTER_CONDITION0 c[2] = {0};
                    // Condition 1: Remote Subnet
                    c[0].fieldKey = AEGIS_FWPM_CONDITION_IP_REMOTE_ADDRESS;
                    c[0].matchType = FWP_MATCH_EQUAL;
                    c[0].conditionValue.type = (FWP_DATA_TYPE)15; // FWP_V4_ADDR_MASK
                    FWP_V4_ADDR_AND_MASK am; am.addr = r.ip; am.mask = r.mask;
                    c[0].conditionValue.v4AddrMask = &am;
                    
                    // Condition 2: TCP Only (Prevents UDP/ICMP filtering overhead for Microsoft telemetry)
                    c[1].fieldKey = AEGIS_FWPM_CONDITION_IP_PROTOCOL;
                    c[1].matchType = FWP_MATCH_EQUAL;
                    c[1].conditionValue.type = FWP_UINT8;
                    c[1].conditionValue.uint8 = IPPROTO_TCP;

                    f.filterCondition = c; f.numFilterConditions = 2;
                    FwpmFilterAdd0(engine.get(), &f, NULL, NULL);
                }
            }

            if (FwpmTransactionCommit0(engine.get()) == ERROR_SUCCESS) {
                log.Log(Core::LogLevel::INFO, "WFP", 201, "Transaction committed. Performing Network Health Check...");
                if (!HealthCheckConnectivity()) {
                    log.Log(Core::LogLevel::ERR, "WFP", 502, "Health check failed post-commit. Traffic completely dropped? Requires manual review.");
                } else {
                    log.Log(Core::LogLevel::INFO, "WFP", 202, "Health check passed. Base routing unaffected.");
                }
            } else {
                FwpmTransactionAbort0(engine.get());
                log.Log(Core::LogLevel::ERR, "WFP", 501, "Transaction aborted.");
            }
        }
    };
}
