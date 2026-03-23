#pragma once
#include "RAII.hpp"
#include "Logger.hpp"
#include <windows.h>
#include <objbase.h>
#include <iostream>

namespace Aegis::Core {
    enum class AppState { INIT, RECOVERY, NORMAL, DEGRADED };

    class ProcessHost {
        static inline HANDLE hMutex = NULL;
    public:
        static inline AppState CurrentState = AppState::INIT;

        static bool EnforceSingleInstance() {
            hMutex = CreateMutexW(NULL, TRUE, L"Global\\Aegis11_Controller_Mutex");
            DWORD err = GetLastError();
            if (err == ERROR_ALREADY_EXISTS) {
                std::cout << "[!] FATAL: Aegis11 is already running.\n";
                CloseHandle(hMutex); hMutex = NULL; return false;
            }
            if (err == ERROR_ABANDONED_WAIT_0) {
                std::cout << "[*] CRITICAL: Recovered abandoned mutex. Forcing RECOVERY state.\n";
                CurrentState = AppState::RECOVERY;
            } else {
                CurrentState = AppState::NORMAL;
            }
            return true;
        }

        static bool IsElevated() {
            HANDLE t = nullptr;
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &t)) return false;
            KernelHandle hToken = KernelHandle::From(t);
            TOKEN_ELEVATION e{}; DWORD sz = 0;
            return GetTokenInformation(hToken.get(), TokenElevation, &e, sizeof(e), &sz) && e.TokenIsElevated;  
        }

        static bool InitializeCOM(Logger& log) {
            HRESULT hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
            if (FAILED(hr)) {
                log.Log(LogLevel::ERR, "FATAL", 500, "COM MTA Init Failed.");
                return false;
            }
            hr = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);
            return true;
        }

        static void TeardownCOM() {
            if (hMutex) { CloseHandle(hMutex); hMutex = NULL; }
            CoUninitialize();
        }

        static void SetConsoleState() { SetConsoleTitleW(L"aegis11 v1"); }
    };
}
