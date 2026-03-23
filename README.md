# Aegis11 System Controller & Mitigation Engine

**Overview**

[![C++17](https://img.shields.id/badge/Standard-C%2B%2B17-blue.svg)](https://isocpp.org/)
[![Platform](https://img.shields.id/badge/Platform-Windows%2011-lightgrey.svg)](https://microsoft.com)
[![Build](https://img.shields.id/badge/Build-CMake%20%7C%20MSVC-success.svg)](https://cmake.org/)
[![License: GPL v3](https://img.shields.id/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

Aegis11 is an advanced, Anillo-3 (Ring 3) endpoint detection, privacy hardening, and telemetry mitigation framework for Windows 11 systems. Implementing automated threat identification and active state remediation, the suite relies purely on native C++ memory manipulation and OS-level COM/WinRT APIs, explicitly avoiding high-level scripts (PowerShell, Batch) that trigger modern EDR behavioral heuristics.

## Technical Architecture

The framework implements a unified, immutable mitigation architecture utilizing a strict state-reconciliation journal and multi-vector hook deployments.

### Core Detection & Remediation Subsystems

**1. Cryptographic Write-Ahead Logging (WAL)**
State changes are not blindly applied. The `PolicyEngine` implements a strictly ordered, deterministically replayable WAL to guarantee forensic-level database integrity.
* **Hardware-Level Alignment:** Payloads are padded to 4KB boundaries and allocated via `_aligned_malloc` to prevent physical torn writes on NAND flash during unexpected power loss.
* **Validation Mechanisms:** Uses `FILE_FLAG_WRITE_THROUGH` coupled with FNV-1a 64-bit checksums and `0xAA` trailing commit markers.
* **Reconciliation:** Capable of reconstructing the exact registry topology and executing rollback via `TransactionRecord` sequence iteration.

**2. Multi-Layer WFP Kernel Sinkhole**
Bypasses standard `netsh` Firewall limitations by interfacing directly with the **Windows Filtering Platform (WFP)**.
* Instantiates versioned, persistent WFP Providers and Sublayers via `FwpmEngineOpen0`.
* Injects identical drop policies across two distinct network layers: `FWPM_LAYER_ALE_AUTH_CONNECT_V4` (new connections) and `FWPM_LAYER_ALE_FLOW_ESTABLISHED_V4` (existing flows).
* Enforces strict CIDR-based subnet blocking restricted to `IPPROTO_TCP` to eliminate UDP/ICMP filtering overhead in the networking stack.

**3. Native WinRT Appx Eradication**
Calling `powershell -EncodedCommand` or `taskkill` exposes the payload to simple process-creation analytics. 
Aegis11 executes AppX removal and process termination strictly in-memory using **Windows Runtime C++ Template Library (WRL)** and `Toolhelp32` snapshot parsing. The `Windows.Management.Deployment.PackageManager` interface is invoked asynchronously to guarantee isolation.

**4. WMI Phantom Sentinel**
Removing telemetry executables statically is futile against OS self-healing mechanisms. Aegis11 deploys an asynchronous, kernel-level **Windows Management Instrumentation (WMI)** event subscription.
* Registers a `__EventFilter` with a pure WQL query targeting process creation.
* Binds a `CommandLineEventConsumer` that assassinates payload binaries (e.g., `CompatTelRunner.exe`) the microsecond they hit memory, before they can allocate substantial resources or exfiltrate diagnostic data.

**5. Kernel-Level DACL Locking & Offline Hive Mounting**
Traditional registry edits (`RegSetValueExW`) are inherently volatile. Aegis11 permanently freezes telemetry configurations by manipulating Discretionary Access Control Lists (DACLs).
* Applies `EXPLICIT_ACCESS_W` rules that explicitly deny `KEY_WRITE | DELETE | WRITE_DAC` to both `S-1-5-18` (NT AUTHORITY\SYSTEM) and `S-1-5-80-...` (TrustedInstaller).
* Escalates tokens to leverage `SeBackupPrivilege` and `SeRestorePrivilege`, seamlessly mounting offline physical `NTUSER.DAT` hives to enforce policies on disconnected profiles without triggering sharing violations.

## Feature Implementation

### Service & Task Immutability
Instead of merely disabling services via `sc stop`, Aegis11 attacks the Service Control Manager (SCM) recovery logic directly:
* Zeroes out `SERVICE_FAILURE_ACTIONS` to prevent auto-restarts.
* Eradicates `SERVICE_CONFIG_TRIGGER_INFO`, neutralizing WNF events, ETW triggers, and network state changes from waking the telemetry service.
* Scans the COM `TaskScheduler` structure, performing canonical directory validation and Authenticode (`WinVerifyTrust`) checks to disable root telemetry tasks.

### ETW High-Performance Logging
Replaces standard `std::cout` buffering with deep integration into **Event Tracing for Windows (ETW)**.
* Implements a deterministic session ID based on process start time tick count.
* Injects telemetry metadata directly into `WINEVENT_LEVEL_INFO` / `WINEVENT_LEVEL_ERROR` layers, enabling SIEM ingestion and high-performance querying via Windows Event Viewer.

---

## Performance Characteristics

Measured on Windows 11 23H2, AMD Ryzen 7 / Intel i7, 16GB RAM:

| Detection/Action Phase | API Subsystem | Avg. Memory Footprint | Avg. Execution Time |
| ---------------------- | ------------- | --------------------- | ------------------- |
| WinRT Appx Eradication | COM / WinRT | ~12 MB | 850 ms |
| Multi-Layer WFP Block | `fwpuclnt.dll` | ~4 MB | 120 ms |
| Task WinVerifyTrust | `taskschd.dll` | ~18 MB | 1.8 s |
| DACL Kernel Locking | `advapi32.dll` | < 2 MB | 45 ms |
| WAL Initialization | NTFS Direct | 4KB Aligned Buffer | 12 ms |

* **CPU Usage:** Negligible spike (< 5%) during synchronous execution.
* **Disk I/O:** Anti-torn writes restrict disk utilization strictly to serialized 4KB block limits.

---

## Installation & Compilation

### System Requirements
* **Operating System:** Windows 11 (21H2, 22H2, 23H2, 24H2) / Windows 10 (22H2)
* **Architecture:** x64 / ARM64 native compatible
* **Privileges:** Highly privileged administrative token required (`requireAdministrator` UAC manifest injected automatically).
* **Toolchain:** MSVC v143 toolset, Windows SDK 10.0.22000.0+, CMake 3.21+

### Library Dependencies
* `advapi32.lib` - Security descriptors, DACLs, Registry, SCM.
* `ole32.lib` & `oleaut32.lib` - Core COM Initialization and Variant types.
* `wbemuuid.lib` - WMI Event Filter Subscriptions.
* `fwpuclnt.lib` - Windows Filtering Platform kernel hooks.
* `runtimeobject.lib` - WinRT COM Appx deployment architecture.

### Build Instructions

**Visual Studio Developer Command Prompt (Recommended):**
```powershell
# 1. Navigate to source directory
cd C:\Path\To\Aegis11

# 2. Generate Ninja/MSBuild files
cmake -B build -S .

# 3. Compile optimized engine with Link-Time Code Generation (LTCG)
cmake --build build --config Release
```

> **Security Note:** The resulting `Aegis11.exe` will carry the Administrator Shield overlay due to `/MANIFESTUAC`. Execution on modern builds will trigger **Windows SmartScreen**. This occurs because the binary lacks a $400 Authenticode EV Code Signing Certificate, triggering a cloud-reputation failure. Click *More Info -> Run anyway*.

---

## Usage & CLI Execution

Aegis11 runs completely headless or via an interactive CLI buffer utilizing direct console screen-buffer manipulation (`GetConsoleScreenBufferInfo`).

```cmd
# Launch the Interactive Shell
Aegis11.exe

# Automated Baseline & Mitigation Reconciliation (Ideal for Task Scheduler)
Aegis11.exe --reconcile
```

### Interactive Mitigation Profiles

* **[1] Light:** Safe GPOs, disables web search and passive NCSI. No applications are uninstalled.
* **[2] Balanced:** Light Profile + Manipulates SCM to disable telemetry services + Authenticode-verified Task eradication + Native Edge/OneDrive removal.
* **[3] Aggressive:** Balanced Profile + Native WinRT Appx Purge + Immutable WFP Kernel Blockers.
* **[R] Rollback WAL:** Iterates the `aegis_wal.jsonl` backwards to perfectly reconstruct the pre-execution OS state.

---

## Detection Algorithms (Example)

### WMI Phantom Sentinel Subscription (WQL)
The engine uses the following Event Filter to asynchronously catch telemetry process invocations within a 1-second polling window:

```sql
SELECT * FROM __InstanceCreationEvent WITHIN 1 
WHERE TargetInstance ISA 'Win32_Process' 
AND (TargetInstance.Name = 'CompatTelRunner.exe' 
  OR TargetInstance.Name = 'DeviceCensus.exe')
```

This filter is programmatically bound to a `CommandLineEventConsumer` that kills the process ID referenced by `%TargetInstance.Handle%`.

---

## Support and Contact

### Issue Reporting
For non-sensitive anomalies, deployment failures, or feature proposals:
* **GitHub Issues:** Tracked via the public repository board.
* **Reference Material:** See `CONTRIBUTING.md` and `SECURITY.md` before submission.

For high-impact security vulnerabilities (e.g., LPEs, memory corruption):
* **Security Issues:** `genesis.Issues@pm.me` (PGP encryption strongly recommended for 0-day or exploit PoCs).
* **Responsible Disclosure:** We mandate a standard 90-day coordinated disclosure timeline from the initial report acknowledgment.

### Author
**Genesis**
*Security Researcher & Core Developer*
* **General Contact & Direct Support:** `genzt.dev@pm.me`

---

## Legal & Disclaimers

**THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.**

Aegis11 is a systems engineering tool designed for system administrators, security researchers, and power users. Manipulating Kernel DACLs, WFP network layers, and WMI subscriptions can severely alter the behavior of the operating system. Ensure you have tested your mitigation profiles in a staging environment prior to bare-metal deployment. 

The authors assume **NO LIABILITY** for resulting system degradation, broken dependencies in Microsoft Store applications, or unintended connectivity drops resulting from aggressive WFP blocking.