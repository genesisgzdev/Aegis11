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

            if (argc == 1) {
                config.interactive = true;
                return config;
            }

            for (int i = 1; i < argc; ++i) {
                std::string arg = argv[i];
                if (arg == "--preview" || arg == "--simulate" || arg == "--dry-run") config.simulate = true;
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
            std::cout << "Aegis11 | Revisa y administra ajustes de Windows\n\n";
            std::cout << "Abre Aegis11.exe para usar el menu paso a paso.\n\n";
            std::cout << "  --interactive           Abrir el menu\n";
            std::cout << "  --preview               Ver el plan de servicios sin cambiar nada\n";
            std::cout << "  --snapshot archivo.json Guardar los ajustes compatibles para compararlos\n";
            std::cout << "  --restore archivo.json  Restaurar registro, servicios y tareas capturados\n";
            std::cout << "  --reconcile             Recuperar cambios del registro guardados por Aegis\n";
            std::cout << "  --help                  Mostrar esta ayuda\n\n";
            std::cout << "La copia de ajustes no es una copia completa de Windows.\n";
            std::cout << "DataPurge y Appx quedan fuera de --restore. --apply permanece deshabilitado.\n";
            std::cout << "--simulate sigue siendo alias de --preview.\n";
        }
    };
}
