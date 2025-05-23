# Enumeration-for-Processes

A cross-platform process enumeration and inspection tool for low-level investigation, forensic analysis, and systems research.

## Purpose

This project is designed for **deep, low-level process introspection**, offering capabilities beyond what tools like Sysinternals provide. It interfaces directly with **native Windows APIs** and **undocumented NT kernel functions** to extract granular process, thread, module, handle, and memory information in ways that traditional tools abstract or obscure.

Ideal for:

- Malware triage and red team tooling
- Digital forensics and incident response (DFIR)
- Advanced persistence and anomaly detection
- Kernel object and handle tracking
- Research into OS internals and execution behavior

## Key Features (Windows)

- Full process listing via ToolHelp32
- Module and thread enumeration by PID
- Open handle enumeration via `NtQuerySystemInformation(SystemHandleInformation)`
- Privilege escalation via `SE_DEBUG_NAME`
- Export process info including memory usage and user context (SID) to CSV
- Uses `TOKEN_USER`, `GetProcessMemoryInfo`, `EnumProcessModules`, and raw NTAPI

## Why Not Use Sysinternals?

Sysinternals is excellent for operational use but abstracts lower-level internals for usability. This tool goes deeper:

- Direct use of `ntdll.dll` and undocumented structures
- Native access to kernel-level handle/object structures
- Unfiltered data dump for use in red team automation, malware analysis, or memory forensics
- Open-source and modifiable for tailored research environments

## Code Design and Analysis

This project emphasizes **clarity, extensibility, and low-level correctness**:

- Uses **dynamic memory scaling** for querying system handle tables (with room for optimization)
- All enumeration functions operate independently and provide clean diagnostic output
- Integrates full token privilege manipulation for debugging and introspection capabilities
- Capable of revealing data from protected processes if permissions allow
- Includes thread creation timestamps and memory metrics for profiling

Areas for Future Improvement:
- More robust memory reallocation strategies in `NtQuerySystemInformation`
- Smarter error handling and handle cleanup
- Modular breakdown for OS abstraction (Linux/macOS support planned)
- Potential for multithreaded per-process enumeration for scale

## Roadmap

- [x] Initial Windows implementation
- [ ] Linux support via `/proc`, `ptrace`, and `syscalls`
- [ ] macOS support via `libproc`, `task_for_pid`, `sysctl`
- [ ] Abstract platform-independent interface
- [ ] Plugin support for extended inspections (hooks, registry, memory)
