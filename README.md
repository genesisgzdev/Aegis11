# Aegis11 System Controller & Mitigation Engine

## Overview

[![C++17](https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge&logo=c%2B%2B&logoColor=white)](https://isocpp.org/)
[![Windows 11](https://img.shields.io/badge/Platform-Windows%2011-0078D4?style=for-the-badge&logo=windows&logoColor=white)](https://www.microsoft.com/windows/)
[![CMake](https://img.shields.io/badge/Build-CMake%20%7C%20MSVC-064F8C?style=for-the-badge&logo=cmake&logoColor=white)](https://cmake.org/)
[![GPLv3](https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge&logo=gnu&logoColor=white)](https://www.gnu.org/licenses/gpl-3.0)

Aegis11 is a state enforcement engine for Windows systems.
 
It applies, validates, and continuously reconciles a desired system configuration across multiple OS subsystems, including the registry, services, scheduled tasks, and network filtering layers.

Instead of relying on one-time modifications, Aegis11 implements a transactional Write-Ahead Log (WAL) and a drift reconciliation model, ensuring that system state remains consistent even after reboots, updates, or external modifications.

Design Philosophy

Aegis11 does not attempt to permanently remove or “break” system components.

Instead, it operates on three principles:

Deterministic state application (no blind writes)
Continuous drift detection and reconciliation
Transactional safety with full rollback capability

The system treats Windows as a mutable environment and enforces a consistent configuration over time.

Core Architecture

Aegis11 is structured around a modular, transaction-driven architecture:

1. Core Engine
Write-Ahead Log (WAL) with append-only JSONL entries
Deterministic transaction replay and rollback
State reconciliation engine (drift-aware)
Cross-module execution coordination
2. State Providers
Registry Engine
Multi-hive support (HKLM, HKCU, HKU, offline hives)
Byte-level idempotence with type validation
REG_EXPAND_SZ normalization and environment expansion
Optional ACL snapshot and restoration
Service Manager
Dependency graph resolution using EnumDependentServicesW
Circular dependency protection
Controlled shutdown with adaptive timeouts
Recovery policy neutralization (SERVICE_FAILURE_ACTIONS)
Trigger-based services awareness
Task Scheduler Engine
Full COM inspection of task definitions
Extraction of execution targets (IExecAction)
Authenticode validation via WinVerifyTrust
Canonical path validation and argument inspection
Network Filtering (WFP)
Native interaction with Windows Filtering Platform (WFP)
Custom provider and sublayer isolation
Filtering at:
ALE_AUTH_CONNECT (new connections)
ALE_FLOW_ESTABLISHED (existing flows)
Support for IPv4 and IPv6
CIDR-based rule aggregation (reduced rule explosion)
Selective cleanup via provider GUID
3. Application & Package Management
Native WinRT-based Appx removal (Windows.Management.Deployment)
No reliance on PowerShell or external scripting
Post-removal validation via re-query
4. Persistence & Reconciliation
Scheduled task (--reconcile) for state enforcement at logon
Drift detection against current system state
Re-application of desired configuration when necessary
Jittered execution to avoid contention with system startup
Write-Ahead Log (WAL)

The WAL is the foundation of system integrity:

Append-only JSONL format with entry framing
Per-entry integrity validation (checksum / hash)
4KB-aligned writes to reduce risk of torn writes
Explicit flush via FlushFileBuffers
Transaction states:
PENDING
COMMITTED
ROLLED_BACK
FAILED
RECOVERY_APPLIED
Recovery Model

On startup:

Incomplete or corrupted entries are discarded
Pending transactions are rolled back
System state is reconstructed deterministically
Execution Modes
Interactive Mode
Aegis11.exe

Profiles:

[1] Light
Minimal policy enforcement (safe defaults)
[2] Balanced
Registry + services + validated task mitigation
[3] Aggressive
Full enforcement including Appx removal and WFP filtering
[R] Rollback
Reverts all applied transactions via WAL replay
Reconciliation Mode
Aegis11.exe --reconcile
Non-interactive
Intended for scheduled execution
Applies drift correction only
Performance Characteristics

Measured on Windows 11 23H2 (Ryzen 7 / i7, 16GB RAM):

Operation	API Layer	Memory	Time
Appx Removal	WinRT / COM	~12MB	~850ms
WFP Rule Injection	fwpuclnt.dll	~4MB	~120ms
Task Validation	taskschd.dll	~18MB	~1.8s
Service Mitigation	advapi32.dll	<2MB	~45ms
WAL Initialization	NTFS (aligned)	4KB	~12ms
CPU usage: <5% peak
Disk I/O: bounded to aligned WAL writes
Build & Installation
Requirements
Windows 10/11 (22H2+)
MSVC v143
Windows SDK 10.0.22000+
CMake 3.21+
Build
cd C:\Path\To\Aegis11
cmake -B build -S .
cmake --build build --config Release
Security Considerations

Aegis11 operates with elevated privileges and modifies critical OS subsystems.

Potential risks include:

Network disruption due to WFP misconfiguration
Service dependency breakage
Conflicts with Windows Update behavior
Application compatibility issues

This tool is intended for:

advanced users
system engineers
security researchers

Testing in isolated environments is strongly recommended.

What Aegis11 Is Not
Not an antivirus
Not an EDR
Not guaranteed to override all Windows updates
Not safe for unattended use without validation
Disclaimer

This software is provided “as is”, without warranty of any kind.

Modifying system services, network filtering layers, and registry access controls can significantly alter system behavior.
The authors assume no responsibility for system instability, data loss, or connectivity issues.

Author

Genesis
Security Researcher & Lead Developer
