# Enumeration-for-Processes

A cross-platform process enumeration and inspection tool for low-level investigation, forensic analysis, and systems research.

## Purpose

This tool is not meant to replicate surface-level enumeration as seen with Sysinternals or standard utilities. Instead, it is designed for **deep process introspection**, pulling from **native APIs**, **undocumented system calls**, and **direct handle enumeration** to uncover details that higher-level tools often abstract or omit.

It is especially useful for:

- Threat hunting and malware triage
- Advanced process forensics
- Persistence and anomaly detection
- Kernel object tracking
- Research into OS-level behavior

## Capabilities (Windows)

- Full process listing via Toolhelp32
- Thread and module inspection per PID
- Open handle enumeration via `NtQuerySystemInformation` (SystemHandleInformation)
- Privilege escalation to `SE_DEBUG_NAME` for system-wide analysis
- User context extraction via `TOKEN_USER` and SID resolution
- Memory profiling with working set/pagefile stats
- CSV export for offline analysis

## Why Not Sysinternals?

Sysinternals offers powerful tooling for operational use, but often operates at a layer that obscures raw system state. This tool:

- Interfaces directly with **NTAPI** for handle and object access
- Provides **unfiltered low-level data structures**
- Enables deeper enumeration in scenarios where standard tools are blocked, sandboxed, or restricted
- Is **open-source and extendable**, supporting research and red team adaptation

## Roadmap

- [x] Windows support via WinAPI and NTAPI
- [ ] Linux support using `/proc`, `ptrace`, and `syscall`
- [ ] macOS support via `sysctl`, `libproc`, and task inspection APIs
- [ ] Abstracted cross-platform interface
- [ ] Plugin system for custom enum modules (e.g., registry keys, hooks)
