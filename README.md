# Aegis11

[![C++20](https://img.shields.io/badge/C%2B%2B-20-00599C?style=flat-square&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/platform-Windows-0078D4?style=flat-square&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![CMake](https://img.shields.io/badge/build-CMake%20%2B%20MSVC-064F8C?style=flat-square&logo=cmake&logoColor=white)](https://cmake.org/)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue?style=flat-square)](LICENSE)

Aegis11 es un controlador de políticas para Windows. Su objetivo es aplicar una configuración deseada, registrar los cambios y volver a comprobar el estado cuando el sistema se desvía de esa configuración.

El proyecto trabaja sobre componentes sensibles de Windows como registro, servicios, tareas programadas y Windows Filtering Platform. Por eso el README separa lo que compila de lo que todavía necesita pruebas nativas en una máquina Windows aislada.

## Estado actual

- La ruta reproducible de compilación usa Visual Studio 2022, MSVC v143, Windows SDK 10.0.22000 o superior y CMake 3.21 o superior.
- GitHub Actions comprueba la compilación de Windows y los checks del repositorio.
- `--reconcile`, `--simulate` y `--apply` están expuestos por la CLI.
- La ejecución con privilegios, los cambios de red y la reconciliación sobre un sistema real necesitan validación específica en Windows.
- La interfaz de snapshot y restore todavía no está implementada. El binario rechaza esas opciones para no informar un éxito falso.

Esto no es un antivirus ni un EDR terminado. Es una base de ingeniería para control de estado y mitigación en Windows.

## Cómo está organizado

- `PolicyEngine` y el WAL coordinan transacciones y recuperación
- `Registry`, `Service` y `Task` inspeccionan y aplican políticas del sistema
- `NetworkWfp` y `FirewallManager` encapsulan las capas de filtrado
- `AppxManager` y `DataPurge` cubren operaciones de paquetes y limpieza
- `Reinforcement` registra la tarea de reconciliación
- `InteractiveShell` y `ArgumentParser` forman la interfaz de consola

El WAL usa entradas JSONL con estados de transacción y validación de integridad. Las garantías concretas dependen de la implementación del módulo y deben probarse con el sistema que se vaya a modificar.

## Uso

```powershell
.\aegis11.exe --help
.\aegis11.exe --simulate
.\aegis11.exe --apply
.\aegis11.exe --reconcile
```

`--simulate` calcula la ruta de aplicación sin pedir una escritura efectiva. `--apply` ejecuta la política y `--reconcile` está pensado para una ejecución programada. Prueba primero en una instalación descartable y conserva una forma externa de recuperar el sistema.

## Compilar en Windows

```powershell
cmake -B build -S .
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

El proyecto es Windows-only. El job de CI demuestra que el código compila y que pasan los checks estáticos del repositorio; no prueba que una política privilegiada sea segura para cualquier máquina.

## Seguridad y límites

Aegis11 puede afectar conectividad, servicios, tareas y políticas del registro. No lo ejecutes sobre equipos ajenos ni en producción sin una política revisada, una copia recuperable y una prueba de aceptación para cada módulo.

No se deben interpretar los nombres de los módulos como evidencia de una capacidad ya validada en runtime. La aceptación real requiere observar el cambio en Windows y comprobar también el camino de reversión.

## Licencia

GPL-3.0. Consulta [LICENSE](LICENSE).
