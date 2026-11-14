---
name: Research-Lead
description: OPTIONAL final step in the workflow. Drives a research agent through one or more `Execution_Leads_Report.md` findings using the matching research prompt (LPE / UAC / RCE+Lateral / Proxy+LOLBin / Admin→SYSTEM+Kernel). HARD-GATED behind explicit user confirmation because the work is destructive — planting symlinks / REG_LINKs / files / oplocks mutates host state and must run on a snapshotted VM, ideally NOT the same machine the trace originated from.
---

# Research-Lead

This skill is the **optional** final step that turns a triaged lead set into per-lead verdicts (`EXPLOITABLE` / `NOT_EXPLOITABLE` / `INCONCLUSIVE`) with reproducible PoCs.

> **STOP** — Read § 1 before invoking. This skill is destructive by design.

---

## 1. Hard requirements (the agent MUST satisfy these before doing anything)

### 1.1 Confirm with the user

The agent **MUST NOT** start research autonomously. Before any setup step:

1. Surface the candidate leads (severity, exploit primitive, path) and ask the user **which** to research and **how many in parallel**.
2. Confirm the **target host** is acceptable. The mandatory phrasing:

   > "Research is destructive — it plants junctions / OM symlinks / REG_LINKs / files / oplocks, attaches debuggers, can disable AV, and may force reboots. **Do not run on a production machine or on the same host the trace was captured from unless that host is a dedicated snapshotted VM you can revert.** A clean snapshotted Windows test VM (with the same build / patch level as the trace source) is the correct target. Confirm: which host should the research run on, and is it snapshotted with a known-good revert point?"

3. Wait for explicit user confirmation. If the user says "the same machine the trace came from", ask once more whether that machine is snapshotted, and refuse if the user cannot confirm a revert path.

### 1.2 Why running on the trace-source machine is risky

The standard research playbook ([`LPE_Research_Prompt.md`](../../LPE_Research_Prompt.md) § 12 et al.) explicitly requires:

- Snapshot at clean start, before each PoC, after each PoC, after restore.
- Disabling AV / firewall / EDR for repeatable PoC behavior.
- Loading vulnerable / test-signed kernel drivers (`AdminToSystemKernel_Research_Prompt.md`).
- ACL / registry / scheduled-task / service mutations that may not roll back cleanly.

Running this on the trace-source workstation can:

- Permanently change service binary paths, IFEO debuggers, AeDebug debuggers.
- Leave behind OM symlinks and reparse points that survive logoff.
- Trigger Defender / MDE incidents and ship telemetry to MAPS / VirusTotal.
- BSOD the host (kernel work).
- Lose user data (uncommitted Word docs, browser sessions, etc.).

**Same-machine research is allowed only when the user explicitly acknowledges all of the above and the host is a snapshotted VM.**

---

## 2. MCP Tooling Architecture (Static Reversing, 3-Tier GUI & Time-Travel Debugging)

Before touching a test VM (and while driving reproduction inside the VM), `Research-Lead` integrates three categories of MCP servers:

### 2.1 Pre-VM Static Reversing MCP (`Verify-LeadStatically`)
Always run `skills/Verify-LeadStatically/scripts/VerifyLeadStatically.ps1` (and/or attach **IDA MCP**) before booting the test VM to answer the 4 static questions (Open/Reparse flags, Impersonation check, Downstream sink, and Trigger reachability):
- **Official Hex-Rays IDA MCP (`HexRaysSA/ida-mcp`):** Headless `idalib` (IDA Pro 9.0+) MCP server (`uvx ida-hcli mcp install`) capable of decompiling target `.exe`/`.dll`/`.sys` binaries in the background with Microsoft Symbol Server PDB auto-loading.
- **Community `mrexodia/ida-pro-mcp`:** Connects to an interactive IDA Pro instance (`check_connection`, `list_strings_filter`, `list_imports`, `get_xrefs_to`, `decompile_function`, `get_callers`, `set_comment`) to verify sink code paths and annotate `.i64` databases live.

### 2.2 Three-Tier GUI & Application Automation MCPs
Several research tasks need to drive either complex multi-tab usermode desktop apps, Electron/WebView2 IPC clients, or the **Secure Desktop** (`consent.exe` / UAC prompt, **Winlogon**, **Lock Screen**).

| Tier / Option | Reaches Secure Desktop? | Primary Role in `Research-Lead` |
|---|---|---|
| **Tier 1 — Usermode UIA MCP:**<br/>[`CursorTouch/Windows-MCP`](https://github.com/CursorTouch/Windows-MCP) (`uvx windows-mcp`) or [`locomorange/uiautomation-mcp`](https://github.com/locomorange/uiautomation-mcp) | No — user session only | **Default for usermode desktop apps.** Exposes the Windows UI Automation (UIA) control tree (`AutomationId`, `Name`, `ControlType`, `InvokePattern`, `ValuePattern`) for fast, deterministic clicking/typing without coordinate guessing, plus automated "UI Surface Fuzzing" during trace capture. |
| **Tier 2 — Secure Desktop & Hyper-V MCP:**<br/>[**`SystemAccessMCP`**](https://github.com/Argentix03/SystemAccessMCP) | **Yes** — via `HostHyperV` profile driving the guest VM through VMConnect from the host | **Required for Secure Desktop (`consent.exe`, Winlogon, Lock Screen) & VM snapshot orchestration.** Two profiles: `GuestDesktop` for in-guest work, `HostHyperV` for crossing session/desktop boundaries and managing Hyper-V snapshots (`hyperv_status`, `hyperv_list_vms`, `hyperv_start_vm`). |
| **Tier 3 — Electron & WebView2 MCP:**<br/>**Chrome DevTools MCP** (`chrome-devtools-plugin`) | No — renderer/DOM | **Default for Electron & WebView2 apps.** Attach via `--remote-debugging-port=9222` (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS="--remote-debugging-port=9222"`) to inspect `window.chrome.webview.postMessage` / `ipcRenderer` bridges and test `Electron_AsarTamper` & `Config_Poison` leads live. |
| Claude Code Desktop **Computer Use** (built-in, 2026, Pro/Max) | No — user session only | Zero-install fallback when the lead does not require the secure desktop. |

### 2.3 Dynamic & Time-Travel Debugging (TTD) MCPs
- **Official Microsoft WinDbg MCP (WinDbg `1.2610+` / `glslang/windbg-mcp`):** Attach to user-mode services, kernel targets (`kd -k net`), or record a 5-second **Time-Travel Debugging (TTD)** trace (`ttd.exe -attach <PID>`) while triggering the lead. Query every `ntdll!NtCreateFile` / `ntdll!NtOpenKeyEx` call backward and forward in time, inspect `OBJECT_ATTRIBUTES.Attributes` (`OBJ_DONT_REPARSE` / `0x1000`), and verify the active thread token (`!token`) at the exact instruction pointer.
- **`x64dbg-mcp-server` (`duty1g/x64dbg-mcp-server`):** Rapid conditional breakpoint scripting and memory inspection for stripped 3rd-party user-mode binaries inside the guest VM.

**Recommendation:** Run `Verify-LeadStatically` + IDA MCP first on the analysis host; then on the test VM use **Tier 1 (`Windows-MCP` / `uiautomation-mcp`)** for usermode UI driving, **Tier 2 (`SystemAccessMCP` `HostHyperV`)** for UAC/Winlogon/snapshot control, **Tier 3 (`Chrome DevTools MCP`)** for WebView2/Electron targets, and **WinDbg MCP (TTD)** to capture instruction-level proof.

The agent should **ask the user once** which option they have available and accept "none — I'll click the secure-desktop steps myself" as a valid answer; in that case, mark every secure-desktop step in `Reproduce_LeadN.ps1` with a `# MANUAL: <instruction>` comment and pause execution at those points.

---

## 3. Workflow

### 3.1 Inputs

- `high_confidence_leads.json` and/or `cognitive_review_queue.json` (or the rendered `Execution_Leads_Report.md`).
- A target host the user has explicitly confirmed is safe to mutate.
- A GUI-driver MCP, OR a user willing to perform secure-desktop steps manually.
- Optional: subset of leads to research (default: every lead with `Severity in (Critical, High)` after de-dup by `ExploitPrimitive` + canonical path).

### 3.2 Steps

1. **Confirm with the user** (see § 1.1). Print the lead list, total count, target host, GUI-driver choice. Wait for explicit go-ahead.
2. **Snapshot the target VM** (or instruct the user to do so) and record the snapshot name in `_research_state.json`.
3. **For each lead:**
   1. Pick the matching research prompt by `ExploitPrimitive`. The mapping is defined in `scripts/Get-ResearchPromptForPrimitive.ps1` — same source of truth as the UI's `/api/research-prompts/match` endpoint and the `Analyze-ExecutionLeads` SKILL.md taxonomy. Default to `LPE_Research_Prompt.md` if no match.
   2. Create `Execution_Lead_N\` under the project root.
   3. Hand the chosen prompt **verbatim** to a research subagent (Claude Code, Antigravity, etc.) along with the lead's full JSON record. The prompt is the agent's instructions; do not paraphrase.
   4. The subagent produces `VERDICT_*_LeadN.txt`, `Setup_LeadN.ps1`, `Reproduce_LeadN.ps1`, `Restore_LeadN.ps1`, `Evidence_LeadN.txt`, and the actual proof artifact (file, hash string, captured packet, screenshot).
   5. Run `Restore_LeadN.ps1` and confirm cleanup before moving to the next lead.
   6. If the subagent crashes the VM, revert to the snapshot and continue with the next lead.
4. **Aggregate.** After all leads: produce `FINAL_SUMMARY_All_Leads.md` per the prompt's § 11 spec.
5. **Restore.** Revert the VM to the clean snapshot, OR run all `Restore_LeadN.ps1` scripts in reverse order, then re-baseline-test.

### 3.3 What NOT to do

- Don't bypass user confirmation, even if the user said "go ahead with everything" earlier in the conversation — re-confirm at the start of THIS skill.
- Don't research a lead whose `EffectivePrincipal` is `Token: Medium` and there's no privileged consumer; that's a "user-already-has-it" false positive that already should have been suppressed by `Analyze-ExecutionLeads`. If it slipped through, drop it instead of researching.
- Don't load BYOVD / test-signed drivers without explicit user buy-in to the kernel-mode path (a separate confirmation beyond § 1.1).
- Don't disable Defender / EDR globally without re-enabling at the end of the run. Use snapshot revert as the primary cleanup, not surgical re-enable.
- Don't ship hashes / dumps / certificates / driver hashes anywhere — keep all artefacts inside `Execution_Lead_N\`.

---

## 4. Output layout

```
Execution_Lead_1\
  VERDICT_EXPLOITABLE_Lead1.txt
  Setup_Lead1.ps1
  Reproduce_Lead1.ps1
  Restore_Lead1.ps1
  Evidence_Lead1.txt
  proof_capture.pcapng        # or screenshot, hash string, etc.
  manifest.json               # lead-record copy + chosen prompt id + snapshot ref
Execution_Lead_2\
  VERDICT_NOT_EXPLOITABLE_Lead2.txt
  ...
FINAL_SUMMARY_All_Leads.md
_research_state.json          # snapshot name, run timestamps, lead -> verdict map
```

---

## 5. Mapping primitives → research prompts

The script `scripts/Get-ResearchPromptForPrimitive.ps1` returns the right prompt filename for any `ExploitPrimitive` value. The table is the same one `ui/server.js` exposes via `/api/research-prompts`:

| Primitive(s) | Prompt |
|---|---|
| `SMB_Coercion`, `Oplock_ArbitraryWrite`, `Pipe_Plant_Redirect`, `Pipe_Hijack`, `Pipe_Instance_Squat`, `Pipe_Client_IPC_Sink`, `Registry_Coercion`, `Registry_BufferOverflow_TOCTOU`, `Registry_Data_Path_Reference`, `Binary_Plant_*`, `File_DeleteChild_Recreate`, `SxS_DotLocal`, `Dependency_Hijack`, `Config_Poison`, `AppExecAlias_Plant`, `PowerShell_Profile`, `Electron_AsarTamper`, `ACL_WriteDac_WriteOwner`, `Arbitrary_DACL_Overwrite`, `Arbitrary_Delete_ConfigMsi_LPE`, `Arbitrary_Move_FileRename`, `Parent_Directory_Reparse_Bypass`, `BackupSemantics_DACL_Bypass`, `Signature_TOCTOU_Bypass`, `CheckThenUse_Reparse_TOCTOU`, `COM_HKLM_Hijack`, `RPC_Unauthenticated_PathSink`, `DCOM_Privileged_Activation`, `WMI_LocalSystemHost_Sink`, `Service_OnDemand_Trigger_Chain`, `ScheduledTask_OnDemand_Run`, `Leaked_Privileged_Handle`, `SharedSection_MemoryTamper` | `LPE_Research_Prompt.md` |
| `AppContainer_Sandbox_Escape` | `SandboxEscape_Research_Prompt.md` |
| `COM_Hijack_HKCU`, `Env_Hijack_HKCU`, `UIPI_HighIL_MessageSink` | `UAC_Bypass_Research_Prompt.md` |
| `URL_NTLM_Coerce`, `Theme_NTLM_Coerce`, `DesktopIni_Coerce`, `WebShell_Plant`, `LNK_Hijack`, `Cert_Plant` | `RCE_LateralMovement_Research_Prompt.md` |
| `LOLBin_Proxy`, `AutoRun_Persistence` | `ProxyExecution_LOLBin_Research_Prompt.md` |
| `Service_BinaryPath`, `IFEO_Debugger`, `AeDebug`, `ScheduledTask_Plant`, `Kernel_Device_IOCTL_Surface` | `AdminToSystemKernel_Research_Prompt.md` |
| (anything else) | `LPE_Research_Prompt.md` (universal default) |

---

## 6. Usage (terminal-agent driven)

```
> Read skills/Research-Lead/SKILL.md and run it on Execution_Leads_Report.md
```

The agent will (1) print the lead list, (2) ask § 1.1 questions, (3) wait for confirmation, (4) execute the workflow, (5) produce the per-lead deliverables.

## 7. Usage (UI driven)

The UI's per-lead modal exposes a "Suggested research prompt" row with a one-click jump into the matching prompt body. Hand the prompt to a research agent yourself, or paste it into a Claude Code session pointed at the test VM. The UI does NOT autostart the research workflow — the user must explicitly hand off the lead to an agent.
