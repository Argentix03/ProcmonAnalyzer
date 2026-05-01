---
name: Analyze-ExecutionLeads
description: Triages writable-path feeds via hybrid heuristic + cognitive model, covering 20+ exploitation primitives across LPE / UAC-Bypass / RCE-Lateral / Proxy-Execution / Admin-to-System families. Each lead is tagged with an EscalationCategory derived from the lowest writability perspective (LowPriv / MediumILAdmin / HighILAdmin) and the consumer integrity, so leads route to the right research prompt. Built-in suppression for the LPE-prompt false-positive classes.
---
# Analyze-ExecutionLeads

This skill processes ProcMon/ETW path dumps using a hybrid Script + Agent model. The analysis is framed from the perspective of a **standard low-privilege user with no special privileges** (no `SeImpersonatePrivilege`, no admin rights).

## Workflow

1. **Invoke the heuristic triage script:** Execute `scripts/AnalyzeExecutionLeads.ps1 -JsonFeed writable_paths.json` to evaluate structurally obvious primitives.
2. **Review high-confidence baseline:** `high_confidence_leads.json` — each finding includes `ExploitPrimitive`, `OperationDirection`, `SqosLevel`, `EffectivePrincipal`, `OpenReparsePoint`, `OpenLink`, `AnyPrivRead`, `AnyPrivWrite`, `Severity`, `Type`, `DetailedReason`.
3. **Cognitive agent evaluation:** ambiguous items go to `cognitive_review_queue.json`. **YOUR JOB AS THE AGENT:**
   - Read `cognitive_review_queue.json` in chunks (≤500 lines).
   - Evaluate each entry against the **Exploitation Primitive Taxonomy** below.
   - Pay special attention to `OperationDirection`, `SqosLevel`, `EffectivePrincipal`, `OpenReparsePoint`, and `OpenLink`.
4. **Formulate the report.** Combine `high_confidence_leads.json` and your cognitive findings into `Execution_Leads_Report.md`. Every finding MUST be formatted as an unchecked Markdown task list item. Example:

   ```markdown
   - [ ] [Critical] **Path:** `C:\Program Files\App\Core.dll`
     - **Exploit Primitive:** `Binary_Plant_HighPriv`
     - **Processes:** svchost.exe
     - **Trace Source:** BootLog.csv | **Time:** 12:44:01
     - **Event Context:** Operation: CreateFile (Read) | Result: NAME NOT FOUND | Integrity: System
     - **Effective Principal:** Pure SYSTEM (MACHINE$ NTLMv2 — uncrackable but relayable to LDAP/SMB)
     - **SQOS:** NotSpecified (dangerous default)
     - **Analysis:** Direct hijacking of an executable component inside a privileged hierarchy. No privileges required.
     - **Suggested Research Prompt:** `LPE_Research_Prompt.md`
   ```

5. **Recommend research follow-up.** For each `EXPLOITABLE`-suspect lead, point the operator at the matching Markdown research prompt at the project root (`LPE_Research_Prompt.md`, `UAC_Bypass_Research_Prompt.md`, `RCE_LateralMovement_Research_Prompt.md`, `ProxyExecution_LOLBin_Research_Prompt.md`, `AdminToSystemKernel_Research_Prompt.md`). The UI also exposes a **Research Prompts** panel that lets the operator copy the prompt into a new agent context.

6. **Offer the OPTIONAL `Research-Lead` skill.** After producing the report, ask the user: *"Want me to run the optional `Research-Lead` skill on the top leads? It is destructive and must run on a snapshotted VM (ideally **not** the same host the trace was captured from). I will not start it without your explicit go-ahead."*
   - If the user confirms, hand off to `skills/Research-Lead/SKILL.md`. That skill enforces its own confirmation gate (warning text, snapshot reference, GUI-driver choice) before staging any per-lead workspace.
   - If the user declines, finish here. The report + JSON queues are sufficient for the operator to drive research themselves later.

---

## Low-Privilege Attacker Model

All analysis assumes the attacker is a **standard local user** with:

- ❌ No `SeImpersonatePrivilege`, no admin group membership, no debug privileges
- ✅ Can create NTFS junctions, OM symlinks (in `\RPC Control\`, per-session DosDevices)
- ✅ Can plant `REG_LINK`s in their own hive
- ✅ Can set oplocks on files they own
- ✅ Can run a named-pipe server, local SMB/HTTP listener, Responder
- ✅ Can crack captured Net-NTLMv2 hashes offline (hashcat -m 5600)

---

## EscalationCategory (rev 3)

Every high-confidence lead now carries an `EscalationCategory` field that names the threat boundary it crosses. The category is computed from `WritableFrom` (the lowest perspective at which the path is writable) plus the privileged consumer's integrity, with primitive-specific overrides for cases where the primitive itself fixes the category regardless of perspective.

| Category | When it fires | Maps to research prompt |
|---|---|---|
| `LPE` | LowPriv-writable + High/System consumer (low-priv → SYSTEM) | `LPE_Research_Prompt.md` |
| `UAC_Bypass` | MediumIL-admin-writable + High consumer; or any `COM_Hijack_HKCU` / `Env_Hijack_HKCU` (auto-elevation surface) | `UAC_Bypass_Research_Prompt.md` |
| `Admin_To_System` | HighIL-admin-only-writable + System/TI consumer; or any `Service_BinaryPath` / `IFEO_Debugger` / `AeDebug` / `ScheduledTask_Plant` | `AdminToSystemKernel_Research_Prompt.md` |
| `RCE_Lateral` | NTLM-coercion / web-shell / cert-plant family (primitive override) | `RCE_LateralMovement_Research_Prompt.md` |
| `Proxy_Execution` | LOLBin / autorun family (primitive override) | `ProxyExecution_LOLBin_Research_Prompt.md` |
| `Same_Level` | Writability and consumer at the same effective IL — not an escalation; routed to cognitive queue with hint |  |
| `Unknown` | Cannot determine (insufficient feed metadata) |  |

The `ResearchPromptId` field on each lead is the prompt-catalog id that matches the category — same source of truth as the UI's `/api/research-prompts` and the Research-Lead skill's `Get-ResearchPromptForPrimitive.ps1`. The lead modal's "Suggested research prompt" row uses it.

Re-tagged ACL-anomaly rules: `Service_BinaryPath`, `IFEO_Debugger`, `AeDebug`, `ScheduledTask_Plant` previously fired as `Critical` "ACL anomaly" leads whenever the path appeared in the writable feed. With perspective fields available, they now fire `Critical` only when LowPriv-writable (the genuine ACL anomaly); when only HighIL-admin-writable they downgrade to `High` and retag as the standard Admin → SYSTEM primitive (not an anomaly, just admin's documented elevation path).

---

## Built-in False-Positive Suppression (LPE prompt § 2 / § 9)

The script drops or demotes leads on the following patterns BEFORE writing the high-confidence queue:

1. **Paging-I/O / kernel-thread attribution** — Cache Manager dirty-page flush, attribution unreliable (LPE §2).
2. **Open Reparse Point set on every observed open** — consumer is using `FILE_FLAG_OPEN_REPARSE_POINT` correctly. Demoted to cognitive queue with hint "look elsewhere in the code path for an open missing the flag" (LPE §2).
3. **REG_OPTION_OPEN_LINK set on every observed open** — same logic for registry coercion candidates.
4. **User-only-consumer** — every observed actor is the current user's own session and no privileged actor touched the path. The redirect cannot reach anywhere the user can't reach already (LPE §9).
5. **Benign-readers-only** — when the only actors are AV/Search indexers (`MsMpEng.exe`, `SearchProtocolHost.exe`, `MsSense.exe`, etc.) and they only read, the lead is "Defender scanned the file" — demoted unless a non-indexer privileged process also touches the path.
6. **LOLBin extension mismatch** — `powershell.exe` → `~/Downloads/` no longer fires the LOLBin-proxy rule; only file extensions the LOLBin actually parses (`.ps1`/`.psm1`/`.psd1`/`.ps1xml` for PowerShell, `.dll`/`.ocx`/`.cpl` for rundll32, etc.) escalate severity.
7. **Self-trace contamination** — already filtered upstream by `Parse-ProcmonWriteables`.

---

## Exploitation Primitive Taxonomy

### READ-PATH (privileged consumer reads from a writable path)

| Primitive | Trigger | Attack | Reference Prompt |
|---|---|---|---|
| `SMB_Coercion` | High-IL process reads writable dir | NTFS junction → drive-letter → UNC chain (LPE §3.5) | `LPE_Research_Prompt.md`, `RCE_LateralMovement_Research_Prompt.md` |
| `Binary_Plant_HighPriv` / `Binary_Plant_UserSpace` | `.exe`/`.dll`/`.sys` / etc. in writable dir | Replace; loaded by High/SYSTEM = code exec at integrity | `LPE_Research_Prompt.md` |
| `Pipe_Plant_Redirect` | NAME NOT FOUND from privileged process | Symlink → `\\.\pipe\<own>` for relay/Identification | `LPE_Research_Prompt.md`, `RCE_LateralMovement_Research_Prompt.md` |
| `Config_Poison` | `.config`/`.xml`/`.json` read by framework host | `assemblyBinding`, `machineKey`, XXE, type-confusion deserialization | `LPE_Research_Prompt.md`, `ProxyExecution_LOLBin_Research_Prompt.md` |
| `SxS_DotLocal` | `.manifest`/`.local` writable | DLL load-order hijack | `LPE_Research_Prompt.md` |
| `Dependency_Hijack` | writable `node_modules`/`site-packages`/`vendor`/`gems`/Cargo registry | Replace package | `LPE_Research_Prompt.md` |
| `Registry_Coercion` | High-IL `RegOpenKey` etc. on `HKCU` / `HKU\<SID>` without `REG_OPTION_OPEN_LINK` | Plant REG_LINK; CVE-2014-6322 archetype | `LPE_Research_Prompt.md`, `UAC_Bypass_Research_Prompt.md` |
| `COM_Hijack_HKCU` | `HKCU\Software\Classes\CLSID\{...}` | Plant `InprocServer32` | `UAC_Bypass_Research_Prompt.md` |
| `Env_Hijack_HKCU` | `HKCU\Environment` — esp. `windir`/`SystemRoot`/`Path`/`PSModulePath` | SilentCleanup-class auto-elevation hijack | `UAC_Bypass_Research_Prompt.md` |
| `AppExecAlias_Plant` | `%LocalAppData%\Microsoft\WindowsApps\` writable + on PATH | Drop `notepad.exe`/`wt.exe`/etc. shadow | `LPE_Research_Prompt.md` |
| `PowerShell_Profile` | `Documents\PowerShell\*.ps1` writable | Auto-loaded on every shell start | `LPE_Research_Prompt.md`, `AdminToSystemKernel_Research_Prompt.md` |
| `Electron_AsarTamper` | `\resources\app.asar` writable | Unpack/repack; Electron sig doesn't cover .asar | `LPE_Research_Prompt.md` |
| `URL_NTLM_Coerce` / `Theme_NTLM_Coerce` / `DesktopIni_Coerce` | writable shortcuts/themes/desktop.ini | Set Icon/Wallpaper to UNC for NTLM coercion | `RCE_LateralMovement_Research_Prompt.md` |

### WRITE-PATH (privileged consumer writes to a writable path)

| Primitive | Trigger | Attack | Reference Prompt |
|---|---|---|---|
| `Oplock_ArbitraryWrite` | High-IL process writes to writable path | Exclusive oplock + junction swap → write lands in System32/Tasks/etc. | `LPE_Research_Prompt.md`, `AdminToSystemKernel_Research_Prompt.md` |
| `Service_BinaryPath` | `HKLM\...\Services\<name>\ImagePath` writable (ACL anomaly) | Direct service hijack | `AdminToSystemKernel_Research_Prompt.md` |
| `IFEO_Debugger` / `AeDebug` | `HKLM\...\IFEO\<exe>\Debugger` or `AeDebug\Debugger` writable | Target EXE launches your debugger | `AdminToSystemKernel_Research_Prompt.md` |
| `ScheduledTask_Plant` | `\System32\Tasks\<task>` XML writable | Rewrite `<Command>`; runs at task's principal | `AdminToSystemKernel_Research_Prompt.md` |

### EXECUTION (no privileged consumer needed)

| Primitive | Trigger | Reference Prompt |
|---|---|---|
| `AutoRun_Persistence` | `.bat`/`.ps1`/`.vbs`/Startup/Run/Tasks | `ProxyExecution_LOLBin_Research_Prompt.md` |
| `WebShell_Plant` | webroot + script extension | `RCE_LateralMovement_Research_Prompt.md` |
| `LNK_Hijack` | writable `.lnk` | `RCE_LateralMovement_Research_Prompt.md` |
| `Cert_Plant` | `.cer`/`.pfx`/etc. or AuthRoot store | `RCE_LateralMovement_Research_Prompt.md` |
| `LOLBin_Proxy` | extension parsed by signed binary | `ProxyExecution_LOLBin_Research_Prompt.md` |

---

## SQOS Analysis Guide

When reviewing findings, check the `SqosLevel` field:

| Value | Meaning | Low-Priv Exploitability |
|-------|---------|------------------------|
| `NotSpecified` | No SECURITY_SQOS_PRESENT flag. Default = Impersonation for local pipes | **HIGH** — full SMB relay, token access for service accounts |
| `Impersonation` | Explicitly allows impersonation | **HIGH** — same as above |
| `Delegation` | Allows delegation (most permissive) | **HIGHEST** — can forward credentials |
| `Identification` | Can query token info but not impersonate | **MEDIUM** — SMB relay still works, enum SIDs/groups |
| `Anonymous` | Minimal access | **LOW** — DoS, timing side-channels only |

Most Windows services do NOT set SQOS flags, meaning the dangerous default applies.

---

## Operation Direction Guide

| Direction | Low-Priv Kill Chain |
|-----------|-------------------|
| **Read** | SMB coercion, DLL hijack, config poison, pipe plant |
| **Write** | Oplock+junction arbitrary write, log/cache poisoning |
| **Read+Write (same path)** | TOCTOU race window — LPE §3.7 oplock primitive applies directly |

**Critical insight:** A privileged WRITE to a writable path is often MORE dangerous than a read because the oplock+junction primitive yields arbitrary file write as SYSTEM — the most powerful escalation primitive available to a standard user.

---

## Effective Principal — Whose NTLM Hits the Wire

The `EffectivePrincipal` field is computed once per lead and tells you exactly which credential class lands on the disk / registry / SMB share at the moment of I/O. This is **mandatory** for any credential-coercion verdict (LPE prompt §6).

| Effective Principal | What you capture |
|---|---|
| `Impersonating <user>` | User's NTLMv2 (crackable, relayable) |
| `Pure SYSTEM` | `MACHINE$` NTLMv2 (uncrackable; relayable to LDAP / SMB / HTTP) |
| `Token: High` | The launching user's NTLMv2 |
