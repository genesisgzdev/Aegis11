# Contributing to Aegis11

Thank you for your interest in contributing to the Aegis11 engine. 
To maintain the architectural integrity, security, and OS-evasion capabilities of the project, all contributions must adhere to strict C++ systems programming guidelines modeled for EDR compatibility and Kernel safety.

## General Guidelines

1. **No External Dependencies:** Aegis11 is fully self-contained. It relies exclusively on the standard library (C++17) and native Windows APIs (`advapi32.lib`, `ole32.lib`, `wbemuuid.lib`, `fwpuclnt.lib`, `runtimeobject.lib`). Do not introduce third-party libraries (e.g., Boost, Qt) unless absolutely critical to the core architecture and statically linked.
2. **Zero "Shell" Execution (Absolute Rule):** We do not invoke external binaries via `system()`, `_popen()`, or `CreateProcess` calling `cmd.exe` or `powershell.exe`. 
    * *Do not use* `taskkill /F`. Use `CreateToolhelp32Snapshot` + `TerminateProcess`.
    * *Do not use* `sc stop`. Use `OpenSCManagerW` + `ControlService`.
    * *Do not use* `Remove-AppxPackage`. Use WRL `IPackageManager`.
3. **RAII Enforcement:** All kernel handles, SC_HANDLES, COM pointers, and dynamically allocated memory must be wrapped in `std::unique_ptr`, `ComPtr`, or custom RAII handle wrappers (see `RAII.hpp`). We do not tolerate raw handle leaks or manual `CloseHandle()` calls in the core execution paths.
4. **Error Handling:** Use the central `Logger` via ETW (Event Tracing for Windows). Avoid printing directly to `std::cout` inside core modules. If a Windows API call fails, fetch the error code natively and utilize `FormatMessageA` to handle it gracefully.

## Architectural Integrity Checks

Before submitting a PR, ensure your module respects the state:
* **Write-Ahead Logging (WAL):** Any change to the Registry (`advapi32`) must be routed through the `PolicyEngine` to guarantee 4KB anti-torn-write safety and rollback capability.
* **Hardware Agnostic:** Never hardcode paths like `C:\Windows`. Always resolve paths dynamically via `ExpandEnvironmentStringsW` (e.g., `%WINDIR%` or `%ProgramFiles(x86)%`).

## Environment Setup

To build and test Aegis11 locally:
* Install **Visual Studio 2022** with the "Desktop development with C++" workload.
* Ensure **CMake 3.21+** and the Windows 11 SDK (10.0.22000.0 or higher) are installed.
* Use the **Developer Command Prompt for VS 2022** to generate build files. 

## Pull Request Process

1. Fork the repository and create your feature branch from `main`.
2. Ensure your code compiles warning-free under MSVC `/W4` and `/O2` Release optimization.
3. Ensure you have tested your mitigation logic on both an active account and an offline profile (to test `NTUSER.DAT` hive mounting if applicable).
4. Describe the technical necessity of the PR. Provide performance metrics or threat models if modifying critical layers (e.g., WFP or WMI).
5. Submit the PR for review.

## Code Style

* Standard C++17 structure.
* Use `std::wstring` and wide-character APIs (`ExW` / `W` variants) exclusively when dealing with Windows paths and strings to prevent Unicode corruption.
* Apply the namespace `Aegis::Modules` or `Aegis::Core` appropriately.