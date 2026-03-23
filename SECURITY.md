# Security Policy

Aegis11 is built as a defensive mitigation engine operating at elevated privilege rings. We take the security of its execution context, memory handling, and permission boundaries very seriously.

## Threat Model

Aegis11 assumes the following operational context:
* **Requires Elevation:** The software operates fundamentally at `Anillo 3` (Ring 3) but acquires and requires a highly privileged security token (`SeDebugPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`). It explicitly relies on Windows UAC (`requireAdministrator`) for initial escalation.
* **Data Integrity:** The internal WAL (Write-Ahead Log) is stored locally (`aegis_wal.jsonl`). While it leverages hardware-level 4KB padding and FNV-1a checksums to detect physical NAND torn writes, the data is unencrypted at rest. We assume an attacker with physical or `SYSTEM` logical access to the drive could manipulate the journal. 
* **Evasion & Stealth:** Aegis11 is architected to operate transparently via WinRT and WFP to avoid false-positive behavioral triggers from commercial EDRs (Endpoint Detection and Response). However, it is not a rootkit. It does not employ Direct Kernel Object Manipulation (DKOM) or SSDT hooking to mask its memory footprint.

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a vulnerability in Aegis11, specifically regarding:
* **Local Privilege Escalation (LPE):** Exploitable flaws resulting from insecure DACL assignments (`EXPLICIT_ACCESS_W` configurations) across registry keys or services.
* **Memory Safety:** Buffer overflows, UAF (Use-After-Free), or memory leaks resulting from improper COM/WinRT unmarshaling processes.
* **Transaction Logic:** TOCTOU (Time-of-Check to Time-of-Use) vulnerabilities in the `PolicyEngine` affecting system recovery.

Please do **NOT** open a public issue. 

Instead, send a detailed report to the repository maintainer directly via secure email at **genesis.Issues@pm.me**. Please include:
1. A summary of the vulnerability.
2. Steps to reproduce the issue (including specific Windows 11 Build numbers, e.g., 23H2 OS Build 22631).
3. A Proof of Concept (PoC) if applicable.

## Out of Scope

The following are not considered vulnerabilities within the scope of this repository:
* **SmartScreen / AMSI Detections:** Windows Defender SmartScreen flagging the un-signed compiled executable as unrecognized.
* **Social Engineering:** The user manually granting UAC permissions to a maliciously modified fork of Aegis11.
* **Self-Inflicted Denial of Service (DoS):** Operating System instability, broken Appx provisioning, or loss of general internet connectivity resulting from running the **Aggressive** mitigation preset without proper testing. Disabling system-critical services is an intended, albeit risky, feature of this engine.