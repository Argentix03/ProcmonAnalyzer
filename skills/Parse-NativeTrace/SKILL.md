---
name: Parse-NativeTrace
description: Converts a native ETW .etl capture and ActiveProcessesSnapshot.json into a Procmon-compatible CSV (with normalized drive letters, registry hives, operation types, NTSTATUS results, and process integrity columns) ready for Parse-ProcmonWriteables.
---
# Parse-NativeTrace

Decompiles a binary `.etl` file via `tracerpt.exe`, cross-references PIDs against `ActiveProcessesSnapshot.json` and `Microsoft-Windows-Kernel-Process` events, maps `\Device\HarddiskVolume<N>` and `\REGISTRY\...` paths, and outputs a Procmon-compatible CSV.

## Usage

```powershell
.\scripts\ParseEtwTrace.ps1 -EtlPath "C:\Temp\RawTrace.etl" -OutputPath "C:\Temp\NativeWritablePaths.csv"
```

Optional parameters:
- `-MaxEvents <int>` — optional event cap (`0` = unlimited, default).

Once `NativeWritablePaths.csv` is generated, pass it to `skills/Parse-ProcmonWriteables/scripts/ParseProcmonTraceTestWritablePaths.ps1`.
