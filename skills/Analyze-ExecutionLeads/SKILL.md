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
   After completing your cognitive review, combine the `high_confidence_leads.json` results and your manually detected anomalies into a final markdown file called `Execution_Leads_Report.md`. Be precise, categorize by Severity, and include detailed descriptions for your cognitive hits.
