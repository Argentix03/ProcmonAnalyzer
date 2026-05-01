# Procmon Analyzer

A Procmon / ETW trace triage pipeline that identifies user-writable filesystem and registry paths consumed by privileged Windows processes, classifies them across 20+ exploitation primitives (LPE, UAC bypass, RCE / Lateral, Proxy / LOLBin, Admin → SYSTEM / Kernel), and hands each lead off to a downstream agentic research workflow with a purpose-built prompt.

## What it does

Procmon Analyzer reads the trace, tells you **which paths a low-privilege user can plant into**, **which privileged processes consume those paths**, and **which exploitation primitive each lead matches** — then attaches a research prompt that an agent (Claude Code, Antigravity, etc.) can run against to produce a verdict.

It is built specifically to *not* miss good leads and *not* spam you with the well-known false-positive classes from the LPE-research playbook (Paging-I/O attribution, "user-already-has-it" reads, `Open Reparse Point` already correctly used, indexer-only readers, self-trace contamination).

## Pipeline at a glance

1. **Capture** — Procmon CSV (or `NativeTrace.ps1` ETW capture, included).
2. **Parse** (`Parse-ProcmonWriteables` skill) — best-event scoring per path; capture SQOS, Open Reparse Point, Open Link, Impersonating, Operations[]; canonicalize paths; filter self-trace contamination. **Classifies each path against three writability perspectives** (LowPriv / MediumILAdmin / HighILAdmin) so downstream rules don't conflate "low-priv can plant here" with "an admin running the parser can plant here".
3. **Analyze** (`Analyze-ExecutionLeads` skill) — heuristic primitives + cognitive queue. Each lead carries an `EscalationCategory` (LPE / UAC_Bypass / Admin_To_System / RCE_Lateral / Proxy_Execution) computed from the writability perspective + consumer integrity. Suppresses Paging-I/O / kernel attribution, demotes `Open Reparse Point`/`Open Link` always-set, drops user-only-consumer and same-IL noise, gates LOLBin matches by extension.
4. **Triage in UI** — sortable lead lists with category and perspective filters; per-lead modal showing effective principal, escalation category, writable-from perspective, and the matched research prompt.
5. **Research** *(optional, gated)* — `Research-Lead` skill stages per-lead workspaces and dispatches a research subagent against the matching prompt. **Destructive**: confirmed snapshotted-VM only.

## Features

- **Best-event scoring** — a single SYSTEM `WriteFile` is no longer buried by 100 prior `QueryDirectory` reads on the same path.
- **Effective-principal disclosure** — every lead states whose NTLMv2 hits the wire (user / `MACHINE$` / service account), per LPE prompt §6.
- **20+ exploitation primitives** including (new in rev 2): COM hijack, env-var hijack (SilentCleanup), App Execution Alias squat, PowerShell profile sinks, Electron `app.asar` tamper, `desktop.ini`/`.url`/`.theme` NTLM coercion, IFEO/AeDebug/Service-binary-path ACL anomalies, scheduled-task plant.
- **Five built-in research prompts** for downstream agents: LPE, UAC Bypass, RCE / Lateral, Proxy Execution / LOLBin, Admin → SYSTEM / Kernel.
- **Project Workspaces** for isolating different traces.
- **Optional Gemini cognitive analysis** via the UI.
- **Skill-based usage** — works fully agent-driven via `skills/Parse-ProcmonWriteables/SKILL.md` even without the UI.

## UI Setup

```bash
cd ui
npm install
node server.js
```

Open `http://localhost:3000` and drop in your Procmon `.CSV` exports. (Convert `.PML` binary traces with Procmon's `File → Save As → CSV` first.)

## Recording a Procmon trace correctly

When recording in Procmon:

1. **Filter to file & registry activity.** Apply: `Operation is RegOpenKey / RegSetValue / RegCreateKey / RegQueryValue` AND `Class is File System` (alternative: filter by `Integrity is High` OR `System` to dramatically shrink the trace).
2. **Enable Registry Activity** (toolbar icon).
3. **Enable the optional columns** — Procmon's defaults DO NOT include the columns the analyzer reads:
   - `Options → Columns` → check **Detail**, **Integrity**, **Impersonating**, **Result**, **Operation**, **Process Name**, **Time of Day**, **Path**.
4. Capture, then `File → Save → CSV → All events`.

If you capture at boot time via Procmon's bootlog, expect noise from Paging-I/O attributions during the first seconds — the analyzer will mark and demote them automatically.

## Native ETW alternative

If you want a Procmon-free capture, the bundled `ui/public/NativeTrace.ps1` ships a tiny ETW pipeline that produces a CSV in the same shape:

```powershell
.\NativeTrace.ps1 -Start
# ... run your target workflow ...
.\NativeTrace.ps1 -Stop
```

Then upload the generated `NativeWritablePaths.csv` into the UI (or hand it to the parsing skill).

## Agent-Driven Local Workflow (no UI / no Gemini)

Point a terminal agent (Claude Code, Antigravity) at the parsing skill:

> *"Read `skills/Parse-ProcmonWriteables/SKILL.md` and run the pipeline on `C:\Path\To\trace.csv`."*

The agent runs the parser, follows the shell-output instruction to invoke `Analyze-ExecutionLeads`, semantically reviews the cognitive queue, and produces `Execution_Leads_Report.md`. It then picks the matching research prompt for each `EXPLOITABLE`-suspect lead — see § "Research prompts" below.

## Research prompts

Each lead's `ExploitPrimitive` maps to one of five Markdown research prompts at the project root. Hand the relevant prompt to a research agent operating against a snapshotted Windows VM; the prompt frames the threat model, the primitives, the false-positive patterns, the PoC requirements, and the per-lead deliverables.

| Prompt | Primitives covered |
|---|---|
| `LPE_Research_Prompt.md` | `SMB_Coercion`, `Oplock_ArbitraryWrite`, `Pipe_Plant_Redirect`, `Pipe_Hijack`, `Registry_Coercion`, `Binary_Plant_*`, `SxS_DotLocal`, `Dependency_Hijack`, `Config_Poison`, `AppExecAlias_Plant`, `PowerShell_Profile`, `Electron_AsarTamper` |
| `UAC_Bypass_Research_Prompt.md` | `COM_Hijack_HKCU`, `Env_Hijack_HKCU` |
| `RCE_LateralMovement_Research_Prompt.md` | `URL_NTLM_Coerce`, `Theme_NTLM_Coerce`, `DesktopIni_Coerce`, `WebShell_Plant`, `LNK_Hijack`, `Cert_Plant` |
| `ProxyExecution_LOLBin_Research_Prompt.md` | `LOLBin_Proxy`, `AutoRun_Persistence` |
| `AdminToSystemKernel_Research_Prompt.md` | `Service_BinaryPath`, `IFEO_Debugger`, `AeDebug`, `ScheduledTask_Plant` |

In the UI, the **Research Prompts** tab lists, displays, and copies these prompts. Each lead's details modal shows a "Suggested research prompt" row with a one-click jump.

## Optional final step: `Research-Lead` skill

After the report is produced, the agent-driven workflow can run the optional `skills/Research-Lead/SKILL.md`. It:

- **Asks for explicit confirmation** before doing anything (the skill is hard-gated; nothing happens without `-Confirmed` and a snapshot reference).
- **Stages `Execution_Lead_N\` workspaces** under the project root, each with a `manifest.json` carrying the lead record, the matched research prompt, the snapshot ID, and the GUI-driver choice. A research subagent then reads the prompt verbatim and produces the per-lead deliverables (`VERDICT_*.txt`, `Setup/Reproduce/Restore_LeadN.ps1`, `Evidence_LeadN.txt`, proof artefact).

> **WARNING — destructive workflow.** The research prompts plant junctions / OM symlinks / REG_LINKs / oplocks, attach debuggers, can disable AV, and (for the kernel prompt) load test-signed drivers that may BSOD. **Do not run on a production host.** The trace can be captured on any machine, but the research must run on a **snapshotted Windows VM** with a known-good revert point — ideally not the same host the trace originated from. If it must be the same host, that host MUST itself be a snapshotted VM you control.

### GUI-driver MCPs (optional but recommended for secure-desktop work)

Several research tasks need to drive the **secure desktop** (UAC consent.exe, Winlogon, lock screen) — surfaces invisible to in-guest user-session automation.

| Option | Reaches secure desktop? | Notes |
|---|---|---|
| [`SystemAccessMCP`](https://github.com/Argentix03/SystemAccessMCP) | **Yes** — `HostHyperV` profile drives the guest VM through VMConnect from the host | Recommended. Two profiles (`GuestDesktop` / `HostHyperV`) are already referenced by name in `LPE_Research_Prompt.md`. Three transports (stdio, HTTP, MCP-over-HTTP). |
| [Windows-MCP](https://github.com/CursorTouch/Windows-MCP) | No — user session only | Strong fallback for in-guest work. Exposes the UI Automation tree (more reliable than blind screenshot+vision). |
| Claude Code Desktop **Computer Use** (built-in 2026, Pro/Max) | No — user session only | Lowest friction; toggle in **Settings → General → Desktop app → Computer use**. |

If no GUI-driver is available, the agent falls back to manual user steps for any secure-desktop interaction and notes those steps as `# MANUAL: …` in the lead's `Reproduce_LeadN.ps1`.

## Output JSON shapes (for agentic consumers)

`writable_paths.json` includes per-path: `Path`, `CanonicalPath`, `RelatedProcesses`, `Operations`, `EventCount`, `Operation` (best-event), `Result`, `Detail`, `Integrity`, `Impersonating`, `BestProcess`, `DesiredAccess`, `SqosLevel`, `IsPagingIO`, `OpenReparsePoint`, `OpenLink`, `IsKernelAttribution`, `AnyWrite`, `AnyRead`, `AnyPrivWrite`, `AnyPrivRead`, `AnyImpersonating`, `AnyOpenReparsePoint`, `AnyOpenLink`, `AnyPagingIO`, `IsUserOnlyConsumer`.

`high_confidence_leads.json` includes per-lead: `Severity`, `Type`, `ExploitPrimitive`, `EscalationCategory`, `ResearchPromptId`, `WritableFrom`, `IntegrityLabel`, `WritableByLowPriv` / `WritableByMediumILAdmin` / `WritableByHighILAdmin`, `Path`, `Processes`, `Operations`, `DetailedReason`, `EffectivePrincipal`, `OperationDirection`, `SqosLevel`, `OpenReparsePoint`, `OpenLink`, `AnyPrivRead`, `AnyPrivWrite`, `AnyImpersonating`, plus the original `Detail`/`Integrity`/`Impersonating`/`TraceFile`/`Timestamp`/`Result`.

`cognitive_review_queue.json` items have a `Hint` field (free-form text describing what the agent should look for) plus the same telemetry context. `FilterReason` is set when the analyzer demoted a finding (Paging-I/O, OpenReparsePoint always-set, OpenLink always-set, BenignReaderOnly).
