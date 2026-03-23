#pragma once
#include <iostream>
#include <string>
#include <windows.h>
#include <cstdlib>

namespace Aegis::CLI {
    class InteractiveMenu {
    public:
        enum class Action {
            APPLY_POLICY,
            SIMULATE_POLICY,
            CREATE_SNAPSHOT,
            EXPORT_TEMPLATE,
            EXIT
        };

        static void ClearScreen() {
            HANDLE hStdOut = GetStdHandle(STD_OUTPUT_HANDLE);
            if (hStdOut == INVALID_HANDLE_VALUE) return;
            CONSOLE_SCREEN_BUFFER_INFO csbi;
            if (!GetConsoleScreenBufferInfo(hStdOut, &csbi)) return;
            DWORD cellCount = csbi.dwSize.X * csbi.dwSize.Y;
            DWORD count; COORD homeCoords = { 0, 0 };
            if (!FillConsoleOutputCharacterW(hStdOut, (WCHAR)' ', cellCount, homeCoords, &count)) return;
            if (!FillConsoleOutputAttribute(hStdOut, csbi.wAttributes, cellCount, homeCoords, &count)) return;
            SetConsoleCursorPosition(hStdOut, homeCoords);
        }

        static void PrintHeader() {
            std::cout << "\nAegis11 System Controller [Version 1.0.0]\n";
            std::cout << "Copyright (c) 2026. All rights reserved.\n\n";
        }

        static Action Show() {
            while (true) {
                ClearScreen();
                PrintHeader();
                
                std::cout << "Available Operations:\n\n";
                std::cout << "  1. Enforce System Policy\n";
                std::cout << "  2. Simulate Policy Enforcement (Dry-Run)\n";
                std::cout << "  3. Capture System State Baseline\n";
                std::cout << "  4. Export Policy Template\n";
                std::cout << "  5. Exit\n\n";
                
                std::cout << "Select operation [1-5]: ";

                std::string input;
                if (!std::getline(std::cin, input)) {
                    return Action::EXIT; // Handle EOF gracefully (e.g., Ctrl+C or closed stream)
                }

                if (input == "1") return Action::APPLY_POLICY;
                if (input == "2") return Action::SIMULATE_POLICY;
                if (input == "3") return Action::CREATE_SNAPSHOT;
                if (input == "4") return Action::EXPORT_TEMPLATE;
                if (input == "5") return Action::EXIT;

                std::cout << "\nInvalid input. Press Enter to continue...\n";
                std::cin.get();
            }
        }

        static void Pause() {
            std::cout << "\nOperation completed. Press Enter to return to menu...\n";
            std::cin.get();
        }
        
        static std::string PromptInput(const std::string& message) {
            std::cout << message;
            std::string input;
            std::getline(std::cin, input);
            return input;
        }
    };
}