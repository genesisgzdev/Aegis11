#pragma once
#include <windows.h>
#include <string>
#include <wintrust.h>
#include <softpub.h>
#include <vector>

#pragma comment(lib, "wintrust.lib")

namespace Aegis::Core {
    class Utils {
    public:
        static void ClearScreen() {
            HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (GetConsoleScreenBufferInfo(hStdOut, &csbi)) {
                DWORD count;
                DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
                COORD homeCoords = { 0, 0 };
                FillConsoleOutputCharacterW(hStdOut, L' ', cellCount, homeCoords, &count);
                FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count);
                SetConsoleCursorPosition(hStdOut, homeCoords);
            }
        }

        static std::string ws2s(const std::wstring& wstr) {
            if (wstr.empty()) return "";
            int size = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
            std::string res(size, 0);
            WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &res[0], size, NULL, NULL);
            return res;
        }

        static std::wstring s2ws(const std::string& str) {
            if (str.empty()) return L"";
            int size = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
            std::wstring res(size, 0);
            MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &res[0], size);
            return res;
        }

        // FNV-1a 64-bit for cryptographic-lite WAL integrity
        static uint64_t FNV1a64(const std::string& data) {
            uint64_t hash = 0xcbf29ce484222325ULL;
            for (char c : data) {
                hash ^= (uint8_t)c;
                hash *= 0x100000001b3ULL;
            }
            return hash;
        }

        static bool VerifyDigitalSignature(const std::wstring& filePath) {
            WINTRUST_FILE_INFO fileData;
            memset(&fileData, 0, sizeof(fileData));
            fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
            fileData.pcwszFilePath = filePath.c_str();

            GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
            WINTRUST_DATA wintrustData;
            memset(&wintrustData, 0, sizeof(wintrustData));
            wintrustData.cbStruct = sizeof(WINTRUST_DATA);
            wintrustData.dwUIChoice = WTD_UI_NONE;
            wintrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
            wintrustData.dwUnionChoice = WTD_CHOICE_FILE;
            wintrustData.dwStateAction = WTD_STATEACTION_VERIFY;
            wintrustData.pFile = &fileData;

            LONG status = WinVerifyTrust(NULL, &guidAction, &wintrustData);
            
            wintrustData.dwStateAction = WTD_STATEACTION_CLOSE;
            WinVerifyTrust(NULL, &guidAction, &wintrustData);
            
            return (status == ERROR_SUCCESS);
        }
    };
}
