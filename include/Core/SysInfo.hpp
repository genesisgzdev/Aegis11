#pragma once
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string>
#include <vector>

namespace Aegis::Core::SysInfo {

    typedef void (WINAPI *RtlGetVersion_FUNC)(OSVERSIONINFOEXW*);

    struct SystemCaps {
        std::string osVersion;
        DWORD buildNumber;
        std::string sku;
        bool is64Bit;
        DWORD processorCount;
    };

    inline SystemCaps GetCapabilities() {
        SystemCaps caps{};
        HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            auto rtlGetVersion = (RtlGetVersion_FUNC)GetProcAddress(hMod, "RtlGetVersion");
            if (rtlGetVersion) {
                OSVERSIONINFOEXW osInfo = { sizeof(osInfo) };
                rtlGetVersion(&osInfo);
                caps.osVersion = std::to_string(osInfo.dwMajorVersion) + "." + std::to_string(osInfo.dwMinorVersion);
                caps.buildNumber = osInfo.dwBuildNumber;
            }
        }

        DWORD productType = 0;
        if (GetProductInfo(10, 0, 0, 0, &productType)) {
            switch (productType) {
                case PRODUCT_PROFESSIONAL: caps.sku = "Professional"; break;
                case PRODUCT_ENTERPRISE: caps.sku = "Enterprise"; break;
                case PRODUCT_CORE: caps.sku = "Home"; break;
                default: caps.sku = "Other"; break;
            }
        }

        SYSTEM_INFO si;
        GetNativeSystemInfo(&si);
        caps.is64Bit = (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);
        caps.processorCount = si.dwNumberOfProcessors;

        return caps;
    }

    inline bool IsElevated() {
        HANDLE token = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
        TOKEN_ELEVATION elev{};
        DWORD sz = 0;
        bool result = GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &sz) && elev.TokenIsElevated;
        CloseHandle(token);
        return result;
    }
}
