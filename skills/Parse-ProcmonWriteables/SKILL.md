---
name: Parse-ProcmonWriteables
description: Parses Procmon / ETW traces for writable paths and classifies each one against three writability perspectives (LowPriv / MediumILAdmin / HighILAdmin) so downstream analysis can distinguish LPE candidates from UAC-bypass candidates from admin-to-SYSTEM candidates. Captures SQOS, reparse-point / open-link flags, impersonation, and best-event scoring.
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

### Perspective-aware writability (rev 3)

Each path is classified against three hypothetical tokens, not just "the current user":

- **WritableByLowPriv** — a standard-user (no Admin SID) token can plant here.
- **WritableByMediumILAdmin** — an admin's UAC-filtered medium-IL token can plant here. Mandatory Integrity Control's NW (no-write-up) blocks writes to High-IL labeled paths even if the DACL grants Admins write.
- **WritableByHighILAdmin** — an elevated admin token can plant here.
- **WritableFrom** — the **lowest** perspective at which the path is writable (`LowPriv` / `MediumILAdmin` / `HighILAdmin` / `None`). Drives the analyzer's escalation-category assignment.
- **IntegrityLabel** — `Default` / `High` / `System`. Currently a path-based heuristic (System32, Program Files, WinSxS, etc.); the SACL-derived label requires `SeSecurityPrivilege` which medium-IL admin doesn't hold.
- **AclSource** — `exact-file` / `exact-directory` / `ancestor` / `registry-heuristic`, plus `-denied` / `-null` suffixes when DACL read failed. Tells the analyzer how trustworthy the writability verdict is.
- **CurrentUserCanWrite** — convenience field: whether the *running* token can write right now (informational, depends on current process IL + admin-elevated state).
- **CurrentUserSid / CurrentUserIsAdminLatent / CurrentUserIsAdminElevated / CurrentProcessIntegrity** — the user-context the parser ran under; replicated on every entry for the analyzer.

Bug fixes that ride along with rev 3:

- **Right-mask bug**: rev 2 used `-band [FileSystemRights]::Modify` and `-band ::FullControl` to test for write. Both are union masks containing read bits, so any `ReadAndExecute` ACE for `BUILTIN\Users` matched non-zero — false-positive across `\Windows\System32\`, `\Windows\servicing\`, `\Program Files\`. Rev 3 ANDs only against `WriteData -bor AppendData`, the pure plant bits.
- **Sharing-violation hack**: rev 2 mapped `ERROR_SHARING_VIOLATION` (`0x80070020`) to "writable", which falsely flagged `pagefile.sys`, mapped DLLs, and any locked file. Rev 3 drops the file-handle test entirely and relies on ACL walking; if the file's own ACL can't be read, we return `false` rather than fall through to the parent's ACL.
- **`IsInRole(Admin)` confusion**: rev 2 used `Principal.IsInRole(adminSid)` to match admin grants, but that returns true for split-token admins at medium IL because the Admin SID is in the token (just deny-only). Running the parser as an admin user thus bled admin grants into the "user-writable" verdict. Rev 3 classifies SIDs explicitly into low-priv / admin / system buckets and never relies on `IsInRole`.

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
