---
name: Parse-ProcmonWriteables
description: Parses Procmon / ETW traces for writable paths, extracting operation context, integrity, SQOS, reparse-point and open-link flags, impersonation, and best-event scoring for downstream exploitation-primitive analysis.
---
# Parse-ProcmonWriteables

This skill parses raw CSV outputs from ProcMon (`BootLogProcMonAllHighPrivFiles.CSV` or similar — including the `NativeWritablePaths.csv` produced by the bundled `NativeTrace.ps1` ETW capture) to identify mathematically verifiable writable paths for the current execution user without dropping telemetry-heavy test strings.

## What It Captures

For each writable path, the parser extracts:

- **Path** — display path; **CanonicalPath** — lowercased, dedup-collapsed (no trailing slash, `\??\` and `\Device\HarddiskVolume<N>\` normalized)
- **RelatedProcesses** — every process observed on that path
- **Operations** — every distinct operation observed (so the analyzer can detect Read+Write race windows)
- **EventCount** — total events seen (for severity inflation when a path is hit repeatedly)
- **Operation / Result / Detail / Integrity / Impersonating** — from the **best-scoring event** for that path. Best-event scoring prefers privileged writes with NAME-NOT-FOUND over benign medium-IL reads, so a single SYSTEM `WriteFile` is not buried by 100 prior `QueryDirectory` calls.
- **DesiredAccess / SqosLevel** — parsed out of the `Detail` field
- **IsPagingIO / IsKernelAttribution** — LPE-prompt §2 false-positive markers (Cache-Manager flushes whose Process Name column is whatever thread the Memory Manager scheduled)
- **OpenReparsePoint / OpenLink** — `FILE_FLAG_OPEN_REPARSE_POINT` / `REG_OPTION_OPEN_LINK` presence on this event
- **AnyWrite / AnyRead / AnyPrivWrite / AnyPrivRead / AnyImpersonating / AnyOpenReparsePoint / AnyOpenLink / AnyPagingIO** — aggregated across every event for the path
- **IsUserOnlyConsumer** — if every actor on this path was the current user's own session (LPE prompt §9 "user-already-has-it" filter)

## Self-Trace Filtering

Rows whose Path or Process belong to the trace pipeline itself (Procmon, tracerpt, `NativeTrace.ps1`, `RawTrace.etl`, the analyzer's own JSON outputs, etc.) are skipped — the previous version of this skill flagged its own captures as findings.

## Usage

Execute `scripts/ParseProcmonTraceTestWritablePaths.ps1`.
It outputs a `writable_paths.json` file in the plugin root. It then transitions state by instructing the agent to invoke `Analyze-ExecutionLeads`.

Optional parameters:

- `-CsvPath <file>` — input CSV
- `-OutputPath <dir>` — where to write `writable_paths.json` and `parsing_errors.json`
- `-Silent` — skip the `Out-GridView` preview
- `-ExcludeProcessTraces <names>` — extra process names to treat as self-trace contamination

## Key Fields for Exploitation Analysis

| Field | Downstream Use |
|-------|---------------|
| `Operation` / `Operations` | Determines Read vs Write kill chain. Writes = oplock+junction. Reads = SMB coercion, DLL hijack. Read+Write together = TOCTOU race window. |
| `Result` | `NAME NOT FOUND` = trivial to plant (no race needed). `SUCCESS` = must race or replace. `REPARSE` = the kernel followed a redirection (lead is a chain step, not a primitive). |
| `Detail` | Contains SQOS impersonation level, Desired Access, Open Reparse Point, Open Link. Absence of SQOS = dangerous default for pipe attacks. |
| `Integrity` + `Impersonating` | Drives the "effective principal" at the moment of I/O — the credentials that actually hit the disk / wire (LPE prompt §6). |
| `IsPagingIO` | Drop for write-primitive analysis. Process attribution unreliable. |
| `OpenReparsePoint` / `OpenLink` | When set on EVERY observed event the consumer is correctly using the safe flag — demote, but do not drop, since other code paths may omit it. |
| `IsUserOnlyConsumer` | If true and no privileged actor is involved → drop entirely (the redirect couldn't reach anywhere the user can't reach already). |
