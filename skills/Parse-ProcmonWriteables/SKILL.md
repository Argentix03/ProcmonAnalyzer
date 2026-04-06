---
name: Parse-ProcmonWriteables
description: Parses Procmon traces for writable paths dynamically.
---
# Parse-ProcmonWriteables

This skill is designed to parse raw CSV outputs from ProcMon (`BootLogProcMonAllHighPrivFiles.CSV` or similar) to identify mathematically verifiable and exploitable writable paths for the current execution user without relying on dropping telemetry-heavy test strings.

## Usage
Execute `scripts/ParseProcmonTraceTestWritablePaths.ps1`.
It outputs a `writable_paths.json` file in the plugin root. It automatically transitions state by invoking `Analyze-ExecutionLeads`.
