---
name: Capture-NativeTrace
description: Starts and stops a native Windows ETW trace (Kernel-File, Kernel-Registry, Kernel-Process, Security-Auditing) using logman and captures a live process-integrity snapshot (ActiveProcessesSnapshot.json) without requiring Sysinternals Procmon.
---
# Capture-NativeTrace

Captures kernel file, registry, and process telemetry via Windows built-in `logman.exe` ETW sessions and snapshots active process PIDs and token integrity levels (`ActiveProcessesSnapshot.json`).

## Usage

Run from an elevated (Administrator) PowerShell prompt:

```powershell
# Start capture
.\scripts\CaptureNativeTrace.ps1 -Start -OutputPath "C:\Temp\RawTrace.etl"

# Exercise the target application / service workflow...

# Stop capture and write ActiveProcessesSnapshot.json
.\scripts\CaptureNativeTrace.ps1 -Stop -OutputPath "C:\Temp\RawTrace.etl"
```

After stopping the capture, invoke `Parse-NativeTrace` (`scripts/ParseEtwTrace.ps1`) to convert the `.etl` and snapshot into a Procmon-compatible CSV for `Parse-ProcmonWriteables`.
