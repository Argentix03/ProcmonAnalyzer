---
name: Parse-ProcmonWriteables
description: Parses Procmon traces for writable paths, extracting operation context, integrity levels, SQOS flags, and process metadata for downstream exploitation primitive analysis.
---
# Parse-ProcmonWriteables

This skill parses raw CSV outputs from ProcMon (`BootLogProcMonAllHighPrivFiles.CSV` or similar) to identify mathematically verifiable writable paths for the current execution user without relying on dropping telemetry-heavy test strings.

## What It Captures

For each writable path, the parser extracts:
- **Path**: Filesystem path confirmed writable by the current user
- **RelatedProcesses**: All processes observed accessing this path
- **Operation**: The Procmon operation (CreateFile, ReadFile, WriteFile, etc.)
- **Result**: SUCCESS, NAME NOT FOUND, ACCESS DENIED, etc.
- **Detail**: Raw Procmon detail string (contains Desired Access, SQOS flags, Options)
- **Integrity**: Process integrity level (System, High, Medium, Low)
- **Timestamp**: Time of first observed event

These fields are critical for downstream analysis by `Analyze-ExecutionLeads`, which uses them to classify 12+ exploitation primitives including SMB coercion, oplock+junction attacks, pipe planting, and config poisoning.

## Usage
Execute `scripts/ParseProcmonTraceTestWritablePaths.ps1`.
It outputs a `writable_paths.json` file in the plugin root. It automatically transitions state by invoking `Analyze-ExecutionLeads`.

## Key Fields for Exploitation Analysis

| Field | Downstream Use |
|-------|---------------|
| `Operation` | Determines Read vs Write kill chain. Writes = oplock+junction. Reads = SMB coercion, DLL hijack. |
| `Result` | `NAME NOT FOUND` = trivial to plant (no race condition needed). `SUCCESS` = must race or replace. |
| `Detail` | Contains SQOS impersonation level. Absence of SQOS = dangerous default for pipe attacks. |
| `Integrity` | System/High integrity processes are primary targets. Their actions on writable paths are escalation vectors. |
