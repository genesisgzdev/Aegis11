# Aegis11 System Controller & Mitigation Engine

## Overview

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Windows 11](https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![Build](https://img.shields.io/badge/Build-CMake%20%7C%20MSVC-064F8C?style=for-the-badge&logo=cmake&logoColor=white)](https://cmake.org/)
[![License](https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/gpl-3.0)
![Release](https://img.shields.io/github/v/release/yourusername/Aegis11?style=for-the-badge)
![Issues](https://img.shields.io/github/issues/yourusername/Aegis11?style=for-the-badge)
![Build Status](https://img.shields.io/github/actions/workflow/status/yourusername/Aegis11/build.yml?style=for-the-badge)

Aegis11 is a deterministic state enforcement engine for Windows systems.

It applies, validates, and continuously reconciles a desired system configuration across multiple OS subsystems, including the registry, services, scheduled tasks, and network filtering layers.

Rather than relying on one-time modifications, it implements a transactional Write-Ahead Log (WAL) and a drift reconciliation model, ensuring consistency across reboots, updates, and external interference.

---

## Design Philosophy

The engine does not attempt to break or remove core system components.

Instead, it enforces control through:

- **Deterministic state application** (no blind writes)  
- **Continuous drift detection and reconciliation**  
- **Transactional safety with full rollback capability**  

Windows is treated as a mutable system where state must be continuously enforced, not assumed.

---

## Core Architecture

### 1. Core Engine

- Write-Ahead Log (WAL) with append-only JSONL entries  
- Deterministic transaction replay and rollback  
- Drift-aware state reconciliation engine  
- Cross-module execution coordination  

---

### 2. State Providers

#### Registry Engine

- Multi-hive support (HKLM, HKCU, HKU, offline hives)  
- Byte-level idempotence with strict type validation  
- REG_EXPAND_SZ normalization and environment expansion  
- Optional ACL snapshot and restoration  

#### Service Manager

- Dependency graph resolution (`EnumDependentServicesW`)  
- Circular dependency protection  
- Adaptive shutdown with real-time status polling  
- Recovery policy neutralization (`SERVICE_FAILURE_ACTIONS`)  
- Trigger-based service awareness  

#### Task Scheduler Engine

- Full COM inspection of task definitions  
- Extraction of execution targets (`IExecAction`)  
- Authenticode validation via `WinVerifyTrust`  
- Canonical path and argument verification  

#### Network Filtering (WFP)

- Native interaction with Windows Filtering Platform  
- Custom provider and sublayer isolation  
- Filtering layers:
  - ALE_AUTH_CONNECT (new connections)  
  - ALE_FLOW_ESTABLISHED (existing flows)  
- IPv4 / IPv6 dual-stack support  
- CIDR-based rule aggregation  
- Selective cleanup via provider GUID  

---

### 3. Application & Package Management

- Native WinRT-based Appx removal (`Windows.Management.Deployment`)  
- No reliance on PowerShell or external scripts  
- Post-removal validation via re-query  

---

### 4. Persistence & Reconciliation

- Scheduled execution via `--reconcile`  
- Drift detection against live system state  
- Automatic re-application of desired configuration  
- Jittered execution to avoid startup contention  

---

## Write-Ahead Log (WAL)

The WAL guarantees transactional integrity:

- Append-only JSONL format with entry framing  
- Per-entry integrity validation (hash/checksum)  
- 4KB-aligned writes to prevent torn writes  
- Explicit disk flush via `FlushFileBuffers`  

### Transaction States

- PENDING  
- COMMITTED  
- ROLLED_BACK  
- FAILED  
- RECOVERY_APPLIED  

---

## Recovery Model

On startup:

- Invalid or truncated entries are discarded  
- Pending transactions are rolled back  
- System state is deterministically reconstructed  

---

## Execution Modes

### Interactive Mode


Aegis11.exe


Profiles:

- **[1] Light** → minimal, non-intrusive enforcement  
- **[2] Balanced** → registry + services + task mitigation  
- **[3] Aggressive** → full enforcement (Appx + WFP)  
- **[R] Rollback** → full state restoration via WAL  

---

### Reconciliation Mode


Aegis11.exe --reconcile


- Fully non-interactive  
- Designed for scheduled execution  
- Applies drift correction only  

---

## Performance Characteristics

Measured on Windows 11 23H2 (Ryzen 7 / i7, 16GB RAM):

| Operation            | API Layer        | Memory | Time   |
|---------------------|------------------|--------|--------|
| Appx Removal        | WinRT / COM      | ~12MB  | ~850ms |
| WFP Injection       | fwpuclnt.dll     | ~4MB   | ~120ms |
| Task Validation     | taskschd.dll     | ~18MB  | ~1.8s  |
| Service Mitigation  | advapi32.dll     | <2MB   | ~45ms  |
| WAL Initialization  | NTFS (aligned)   | 4KB    | ~12ms  |

- CPU usage: <5% peak  
- Disk I/O: bounded and aligned  

---

## Build & Installation

### Requirements

- Windows 10/11 (22H2+)  
- MSVC v143  
- Windows SDK ≥ 10.0.22000  
- CMake ≥ 3.21  

### Build


cd C:\Path\To\Aegis11
cmake -B build -S .
cmake --build build --config Release


---

## Security Considerations

This tool operates with elevated privileges and modifies critical OS subsystems.

Potential risks:

- Network disruption (WFP misconfiguration)  
- Service dependency instability  
- Windows Update conflicts  
- Application compatibility issues  

Intended for:

- advanced users  
- system engineers  
- security researchers  

---

## What This Is Not

- Not an antivirus  
- Not an EDR  
- Not guaranteed to override Windows internals permanently  
- Not safe for unattended use without validation  

---

## Disclaimer

Provided **“as is”**, without warranty of any kind.

Modifying system services, registry policies, and network layers may significantly alter system behavior.  
No responsibility is assumed for instability, data loss, or connectivity issues.

---

## Author

**Genesis**  
Security Researcher & Lead Developer
