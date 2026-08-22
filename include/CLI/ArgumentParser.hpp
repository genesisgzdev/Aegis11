#pragma once
#include <string>
#include <vector>
#include <iostream>

namespace Aegis::CLI {
    struct RunConfig {
        bool simulate = false;
        bool apply = false;
        bool reconcile = false;
        bool interactive = false;
        std::string snapshot_file = "";
        std::string restore_file = "";
        bool show_help = false;
        bool invalid = false;
    };

    class ArgumentParser {
    public:
        static RunConfig Parse(int argc, char* argv[]) {
            RunConfig config;
            
            // If no arguments passed (e.g., double-clicked from Explorer), enter Interactive Mode
            if (argc == 1) {
                config.interactive = true;
                return config;
            }

            for (int i = 1; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--simulate" || arg == "--dry-run") config.simulate = true;
                else if (arg == "--apply") config.apply = true;
                else if (arg == "--help") config.show_help = true;
                else if (arg == "--snapshot" && i + 1 < argc) config.snapshot_file = argv[++i];
                else if (arg == "--restore" && i + 1 < argc) config.restore_file = argv[++i];
                else if (arg == "--snapshot" || arg == "--restore") config.invalid = true;
                else if (arg == "--interactive") config.interactive = true;
                else if (arg == "--reconcile") config.reconcile = true;
                else config.invalid = true;
            }

            const int selectedModes =
                static_cast<int>(config.simulate) +
                static_cast<int>(config.apply) +
                static_cast<int>(config.reconcile) +
                static_cast<int>(config.interactive) +
                static_cast<int>(!config.snapshot_file.empty()) +
                static_cast<int>(!config.restore_file.empty());
            if (selectedModes > 1) config.invalid = true;
            return config;
        }

        static void PrintHelp() {
            std::cout << "Aegis11 - Policy-Driven System Controller\n";
            std::cout << "Usage:\n";
            std::cout << "  Aegis11.exe [options]\n\n";
            std::cout << "Options:\n";
            std::cout << "  (none)                   Launch Interactive Menu (Default for double-click)\n";
            std::cout << "  --snapshot <file.json>   Write a baseline of the supported service, registry and task state.\n";
            std::cout << "  --apply                  Apply the Aegis Security Policy to the system.\n";
            std::cout << "  --simulate               Perform a dry-run of the policy application.\n";
            std::cout << "  --restore <file.json>    Reserved; restore from a baseline is not implemented.\n";
            std::cout << "  --reconcile              Recover the WAL and re-apply service/task checks.\n";
            std::cout << "  --help                   Show this menu.\n";
        }
    };
}
