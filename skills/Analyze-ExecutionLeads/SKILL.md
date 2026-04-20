---
name: Analyze-ExecutionLeads
description: Triages writable path JSON feeds and intelligently evaluates cognitive queues for edge-case vulnerabilities.
---
# Analyze-ExecutionLeads

This skill dictates how to process ProcMon path dumps using a hybrid Script + Agent model.

## Workflow

1. **Invoke the Heuristic Triage Script:** 
   Execute `scripts/AnalyzeExecutionLeads.ps1 -JsonFeed writable_paths.json` to immediately evaluate structurally obvious vulnerabilities (Binary Planting, Pipes, AutoRuns).
   
2. **Review High Confidence Baseline:**
   The script outputs a hard-coded mapping of paths to `high_confidence_leads.json`. These are guaranteed hits.

3. **Cognitive Agent Evaluation:**
   The script pushes ambiguous or deeply complex configuration files / directories to a `cognitive_review_queue.json`.
   **YOUR JOB AS THE AGENT:**
   - Use your `view_file` tool to chunk-read `cognitive_review_queue.json`.
   - Put on the hat of a highly skilled security researcher and logically deduce if any given path/process duo represents an exploitable primitive (e.g. Can this XML be poisoned for deserialization? Is this log file actually a system binary hijack?).
   - You do NOT need to ingest the entire queue if it's massive. Read up to 500 lines or split it, but do your best to categorize the findings.

4. **Formulate the Report:**
   After completing your cognitive review, combine the `high_confidence_leads.json` results and your manually detected anomalies into a final markdown file called `Execution_Leads_Report.md`. 
   
   **CRITICAL REPORT STRUCTURE REQUIREMENTS:**
   Every individual finding MUST be formatted natively as an unchecked Markdown task list item so the Web UI can parse it. You MUST include the raw analytical fields from the JSON natively under the list item.
   
   Example strict format:
   - [ ] [Critical] **Path:** `C:\Program Files\App\Core.dll`
     - **Processes:** svchost.exe
     - **Trace Source:** BootLog.csv | **Time:** 12:44:01 
     - **Event Context:** Operation: CreateFile | Result: NAME NOT FOUND | Integrity: System
     - **Detail:** Access: Read/Write
     - **Analysis:** Direct hijacking of an executable component inside a historically privileged hierarchy.
