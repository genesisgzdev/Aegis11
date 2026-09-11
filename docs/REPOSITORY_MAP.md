# Mapa del repositorio

Revisión de estructura y flujos: 2026-09-11. Este inventario cubre los archivos versionados y las incorporaciones de esta revisión; excluye dependencias instaladas y artefactos de build. Los límites de validación aparecen por área.

## Flujos y fronteras

| Área | Recorrido real | Verificación / límite |
| --- | --- | --- |
| CLI | ArgumentParser → main → snapshot, simulate, reconcile o menú | Modos excluyentes; EOF termina el menú |
| Light | políticas de registro → PolicyEngine → WAL PENDING/COMMITTED | Falla de preimagen bloquea aplicación; no sigue aplicando después de un error |
| Recuperación | WAL framing/checksum → última transición → compensación inversa | Retry conserva conflictos; no borra valores ajenos; CTest usa HKCU temporal real |
| Snapshot | registro, servicios y tareas → JSON versionado y reemplazo atómico | Error de escritura devuelve fallo; no equivale a restore |
| Módulos fuera de la ruta activa | servicios/tareas/Appx/WFP/firewall/limpieza | --apply, Balanced y Aggressive permanecen deshabilitados sin rollback completo |
| Distribución | CMake/MSVC, manifest, script de firma/lanzamiento | Authenticode existente; no instala confianza ni elimina certificados |

La librería include/Support/json.hpp es una dependencia vendorizada. El inventario no representa una auditoría formal de su implementación. La restauración completa del sistema, los efectos privilegiados, WFP, Appx y recuperación tras caída del equipo necesitan aceptación en una VM Windows dedicada.

## Inventario de archivos

| Archivo | Responsabilidad |
| --- | --- |
| [.github/workflows/windows-build.yml](../.github/workflows/windows-build.yml) | Automatización de windows-build |
| [.gitignore](../.gitignore) | Configuración/metadata: .gitignore |
| [CHANGELOG.md](../CHANGELOG.md) | Documentación: CHANGELOG |
| [CMakeLists.txt](../CMakeLists.txt) | Configuración/metadata: CMakeLists.txt |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | Documentación: CONTRIBUTING |
| [LICENSE](../LICENSE) | Licencia del proyecto |
| [README.md](../README.md) | Documentación: README |
| [SECURITY.md](../SECURITY.md) | Documentación: SECURITY |
| [build.bat](../build.bat) | Herramienta de ejecución: build |
| [docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md) | Documentación: ARCHITECTURE |
| [docs/REPOSITORY_MAP.md](../docs/REPOSITORY_MAP.md) | Documentación: REPOSITORY_MAP |
| [include/CLI/ArgumentParser.hpp](../include/CLI/ArgumentParser.hpp) | Componente nativo: ArgumentParser |
| [include/CLI/InteractiveMenu.hpp](../include/CLI/InteractiveMenu.hpp) | Componente nativo: InteractiveMenu |
| [include/Core/Logger.hpp](../include/Core/Logger.hpp) | Componente nativo: Logger |
| [include/Core/Obfuscation.hpp](../include/Core/Obfuscation.hpp) | Componente nativo: Obfuscation |
| [include/Core/PolicyEngine.hpp](../include/Core/PolicyEngine.hpp) | Componente nativo: PolicyEngine |
| [include/Core/ProcessHost.hpp](../include/Core/ProcessHost.hpp) | Componente nativo: ProcessHost |
| [include/Core/RAII.hpp](../include/Core/RAII.hpp) | Componente nativo: RAII |
| [include/Core/State.hpp](../include/Core/State.hpp) | Componente nativo: State |
| [include/Core/StateEngine.hpp](../include/Core/StateEngine.hpp) | Componente nativo: StateEngine |
| [include/Core/SysInfo.hpp](../include/Core/SysInfo.hpp) | Componente nativo: SysInfo |
| [include/Core/Utils.hpp](../include/Core/Utils.hpp) | Componente nativo: Utils |
| [include/Modules/AppxManager.hpp](../include/Modules/AppxManager.hpp) | Componente nativo: AppxManager |
| [include/Modules/CopilotManager.hpp](../include/Modules/CopilotManager.hpp) | Componente nativo: CopilotManager |
| [include/Modules/DataPurge.hpp](../include/Modules/DataPurge.hpp) | Componente nativo: DataPurge |
| [include/Modules/EdgeManager.hpp](../include/Modules/EdgeManager.hpp) | Componente nativo: EdgeManager |
| [include/Modules/FirewallManager.hpp](../include/Modules/FirewallManager.hpp) | Componente nativo: FirewallManager |
| [include/Modules/NetworkOptimizer.hpp](../include/Modules/NetworkOptimizer.hpp) | Componente nativo: NetworkOptimizer |
| [include/Modules/NetworkSinkhole.hpp](../include/Modules/NetworkSinkhole.hpp) | Componente nativo: NetworkSinkhole |
| [include/Modules/NetworkWfp.hpp](../include/Modules/NetworkWfp.hpp) | Componente nativo: NetworkWfp |
| [include/Modules/RegistryManager.hpp](../include/Modules/RegistryManager.hpp) | Componente nativo: RegistryManager |
| [include/Modules/Reinforcement.hpp](../include/Modules/Reinforcement.hpp) | Componente nativo: Reinforcement |
| [include/Modules/ServiceManager.hpp](../include/Modules/ServiceManager.hpp) | Componente nativo: ServiceManager |
| [include/Modules/TaskManager.hpp](../include/Modules/TaskManager.hpp) | Componente nativo: TaskManager |
| [include/Support/MathHardener.hpp](../include/Support/MathHardener.hpp) | Componente nativo: MathHardener |
| [include/Support/json.hpp](../include/Support/json.hpp) | Dependencia vendorizada nlohmann/json |
| [include/UI/InteractiveShell.hpp](../include/UI/InteractiveShell.hpp) | Componente nativo: InteractiveShell |
| [resources/aegis.manifest](../resources/aegis.manifest) | Recursos de distribución: aegis.manifest |
| [resources/aegis.rc](../resources/aegis.rc) | Recursos de distribución: aegis.rc |
| [scripts/TrustAndLaunch.ps1](../scripts/TrustAndLaunch.ps1) | Verificación Authenticode y lanzamiento explícito |
| [src/main.cpp](../src/main.cpp) | Componente nativo: main |
| [tests/compile_checks.py](../tests/compile_checks.py) | Validación: compile_checks |
| [tests/policy_runtime.cpp](../tests/policy_runtime.cpp) | Validación: policy_runtime |
