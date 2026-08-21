# Aegis11 architecture

Aegis11 tiene una ruta interactiva amplia y tres rutas CLI deliberadamente más estrechas. Documentarlas como si todas ejecutaran el mismo perfil sería incorrecto.

## Cómo leerlo

La primera figura es un mapa de modos, no una promesa de que todos los módulos se ejecuten juntos. La secuencia explica la única transacción con WAL documentada aquí. El cierre separa compilación de comportamiento privilegiado observado en Windows.

## 1. Enrutamiento por modo

~~~mermaid
flowchart TD
    MAIN[main.cpp] --> P[ArgumentParser]
    P -->|invalid/help| EXIT[exit 2 or 0]
    P -->|--simulate| DRY[ServiceManager dry-run]
    P -->|--apply| APPLY[ServiceManager fixed service list]
    P -->|--reconcile| REC[PolicyEngine LoadAndRecover]
    REC --> S[ServiceManager apply]
    REC --> T[TaskManager disable two known tasks]
    P -->|no args or --interactive| UI[InteractiveShell]
    UI --> L[Light: PolicyEngine registry writes]
    UI --> B[Balanced: registry + services + tasks + Appx Edge/OneDrive]
    UI --> A[Aggressive: WFP + firewall + Appx + purge + network optimizer]
    UI --> W[Reinforcement servicing-event scheduled task]
~~~

`--snapshot` y `--restore` son opciones parser-only: `main.cpp` las rechaza con exit code 3. No hay un archivo de snapshot que conecte el CLI con `RegistryManager`.

## 2. Transacción de política de registro

~~~mermaid
sequenceDiagram
    participant UI as InteractiveShell
    participant PE as PolicyEngine
    participant WAL as aegis_wal.jsonl
    participant REG as Windows Registry
    UI->>PE: ApplyPolicy definition
    PE->>REG: read current key/value
    alt target already equal
      PE-->>UI: true without new transaction
    else drift or missing
      PE->>WAL: append PENDING + FNV integrity + commit marker
      PE->>REG: RegCreateKeyEx + RegSetValueEx
      alt write succeeds
        PE->>WAL: append COMMITTED + FlushFileBuffers
        PE-->>UI: true
      else write or durable commit fails
        PE->>REG: RollbackRecord
        PE-->>UI: false
      end
    end
~~~

El WAL usa entradas alineadas a 4096 bytes, FNV-1a sobre el payload, marcador final `0xAA` y `FlushFileBuffers`. Eso describe integridad de escritura; no equivale a snapshot completo ni rollback de todos los módulos.

## 3. Recuperación y persistencia

~~~mermaid
stateDiagram-v2
    [*] --> PENDING: append before registry write
    PENDING --> COMMITTED: registry write + durable WAL append
    PENDING --> RECOVERY_APPLIED: startup rollback
    PARTIAL_APPLY --> RECOVERY_APPLIED: startup rollback
    COMMITTED --> ROLLED_BACK: interactive R
    FAILED --> [*]
    RECOVERY_APPLIED --> [*]
~~~

- Constructor de `PolicyEngine` llama `LoadAndRecover`; `--reconcile` lo vuelve a llamar antes de ejecutar servicios y tareas.
- Interactive `R` revierte solo registros marcados `COMMITTED` y elimina `aegis_wal.jsonl`.
- `Reinforcement` se registra solo desde la ruta interactiva y dispara por eventos de servicing de Windows con argumento `--reconcile`.

## 4. Límite de validación

- `tests/compile_checks.py` valida contratos de repo/CMake; Windows CI valida compilación.
- No se ha demostrado aquí la ejecución privilegiada sobre registro, servicios, tareas, WFP, firewall o Appx.
- Cualquier prueba de `--apply`, perfil Aggressive o tarea de auto-reconciliación debe ejecutarse en VM/equipo Windows descartable con recuperación externa.
