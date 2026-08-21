# Aegis11 architecture

~~~mermaid
flowchart TD
    Main[main.cpp] --> Parse[ArgumentParser]
    Parse -->|no args or interactive| UI[InteractiveShell]
    Parse -->|simulate| Sim[ServiceManager dry-run]
    Parse -->|apply| Apply[ServiceManager apply]
    Parse -->|reconcile| Rec[WAL recovery plus ServiceManager plus TaskManager]
    UI --> Policy[PolicyEngine registry WAL]
    UI --> Modules[Task Appx WFP firewall purge network modules]
    UI --> Reinforce[Reinforcement scheduled task]
    Policy --> Registry[Windows registry]
    Modules --> Windows[services tasks WFP firewall Appx system state]
    Reinforce -->|Windows servicing events| Main
~~~

## Code-aligned behavior

- --apply is not the interactive profile. It calls ServiceManager::EnforcePolicy(false) for the fixed service list in that class.
- --simulate produces dry-run log entries for that same service list and does not write service state.
- --reconcile recovers the WAL, applies the service list and disables the two task paths implemented by TaskManager; it does not run every interactive module.
- No-argument interactive mode is the only path that exposes the Light, Balanced and Aggressive profiles and registers the servicing-event task.
- --snapshot and --restore are parser placeholders. main.cpp exits with code 3 rather than pretending those operations succeeded.

The CMake test invokes tests/compile_checks.py; Windows compilation is performed by CI. Neither proves that privileged registry, service, task or WFP changes are safe on an arbitrary host.
