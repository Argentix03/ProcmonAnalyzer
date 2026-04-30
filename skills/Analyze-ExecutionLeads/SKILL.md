---
name: Analyze-ExecutionLeads
description: Triages writable path feeds via hybrid heuristic + cognitive model, covering 10+ low-privilege exploitation primitives.
---
# Analyze-ExecutionLeads

This skill dictates how to process ProcMon/ETW path dumps using a hybrid Script + Agent model. The analysis is framed from the perspective of a **standard low-privilege user with no special privileges** (no `SeImpersonatePrivilege`, no admin rights).

## Workflow

1. **Invoke the Heuristic Triage Script:** 
   Execute `scripts/AnalyzeExecutionLeads.ps1 -JsonFeed writable_paths.json` to evaluate structurally obvious vulnerabilities across all known exploitation primitives.
   
2. **Review High Confidence Baseline:**
   The script outputs `high_confidence_leads.json` with deterministic findings. Each finding includes:
   - `ExploitPrimitive`: canonical attack name (see taxonomy below)
   - `OperationDirection`: `Read` or `Write` — determines which kill chain applies
   - `SqosLevel`: Security Quality of Service from Procmon Detail field
   - `Severity`, `Type`, `DetailedReason`: human-readable classification

3. **Cognitive Agent Evaluation:**
   The script pushes ambiguous items to `cognitive_review_queue.json`.
   **YOUR JOB AS THE AGENT:**
   - Read `cognitive_review_queue.json` in chunks (up to 500 lines).
   - Evaluate each entry against the **Exploitation Primitive Taxonomy** below.
   - Pay special attention to `OperationDirection` and `SqosLevel` fields.
   - You are looking for exploitable patterns that the heuristic rules couldn't match structurally.

4. **Formulate the Report:**
   Combine `high_confidence_leads.json` and your cognitive findings into `Execution_Leads_Report.md`.
   
   **CRITICAL REPORT STRUCTURE:**
   Every finding MUST be formatted as an unchecked Markdown task list item:
   - [ ] [Critical] **Path:** `C:\Program Files\App\Core.dll`
     - **Exploit Primitive:** `Binary_Plant_HighPriv`
     - **Processes:** svchost.exe
     - **Trace Source:** BootLog.csv | **Time:** 12:44:01 
     - **Event Context:** Operation: CreateFile (Read) | Result: NAME NOT FOUND | Integrity: System
     - **SQOS:** NotSpecified (dangerous default)
     - **Analysis:** Direct hijacking of an executable component inside a privileged hierarchy. No privileges required.

---

## Low-Privilege Attacker Model

All analysis assumes the attacker is a **standard local user** with:
- ❌ No `SeImpersonatePrivilege`
- ❌ No admin group membership
- ❌ No debug privileges
- ✅ Can create NTFS junctions (no special privilege needed)
- ✅ Can create files/directories in writable paths
- ✅ Can set oplocks on files they own
- ✅ Can run a named pipe server
- ✅ Can run a local SMB/HTTP listener for NTLM capture
- ✅ Can crack captured Net-NTLMv2 hashes offline

---

## Exploitation Primitive Taxonomy

### READ-PATH Primitives (privileged process READS from writable path)

#### 1. SMB / NTLM Coercion (`SMB_Coercion`)
- **Trigger:** High-integrity process reads from user-writable directory
- **Attack:** Plant NTFS junction → `\\attacker-ip\share`. Kernel follows junction. Privileged process authenticates via NTLM to attacker's listener.
- **Result:** Net-NTLMv2 hash captured. Crack offline (hashcat -m 5600) or relay to another service (ntlmrelayx.py → LDAP/SMB/HTTP).
- **Privileges needed:** NONE. Standard users can create junctions.
- **Severity:** Critical
- **Look for in cognitive review:** Any privileged read from `%ProgramData%`, `%TEMP%`, or any path confirmed writable. Even `.log` or `.tmp` paths count — the file content doesn't matter, only the path traversal.

#### 2. DLL / Binary Hijacking (`Binary_Plant_HighPriv`, `Binary_Plant_UserSpace`)
- **Trigger:** Process loads `.dll`/`.exe`/`.sys` from writable path
- **Attack:** Replace binary with attacker's. Process loads attacker code.
- **Result:** Code execution at the loading process's integrity level.
- **Privileges needed:** NONE. Just write access to the directory.
- **Severity:** Critical if in System32/ProgramFiles, High otherwise

#### 3. Pipe Planting via Path Redirection (`Pipe_Plant_Redirect`)
- **Trigger:** High-integrity process opens a **non-existent file path** (`Result: NAME NOT FOUND`)
- **Attack:** Plant NTFS symlink from that path to `\\.\pipe\attacker_pipe`. Process connects as pipe client.
- **Without SeImpersonatePrivilege:** Cannot call `ImpersonateNamedPipeClient()` for token. BUT:
  - Can relay the NTLM auth embedded in the pipe connection
  - Can query token at Identification level (enumerate SIDs, groups)
  - Can deny service by holding the pipe open
- **SQOS matters:** Check `SqosLevel` field. `NotSpecified` = dangerous default (Impersonation level for local pipes). `Identification` = relay still works. `Anonymous` = limited value.
- **Severity:** Critical if SQOS absent/Impersonation, High if Identification, Medium if Anonymous

#### 4. Config Poisoning (`Config_Poison`)
- **Trigger:** Framework host process (w3wp, svchost, dotnet) reads `.config`/`.xml` from writable path
- **Attack vectors:**
  - `.NET config:` Inject `<assemblyBinding>` to redirect DLL loads to attacker assembly
  - `.NET config:` Add `<machineKey>` for ViewState deserialization RCE
  - `XML files:` XXE (XML External Entity) to read local files or trigger SMB auth
  - `applicationHost.config:` Redirect IIS virtual directories
- **Privileges needed:** NONE
- **Severity:** Critical for .NET configs, High for generic XML

#### 5. SxS / DotLocal Manifest Poisoning (`SxS_DotLocal`)
- **Trigger:** `.manifest` or `.local` file in writable directory
- **Attack:** Drop `.local` directory next to target EXE → DLL load order hijack
- **Privileges needed:** NONE

#### 6. Dependency Package Subversion (`Dependency_Hijack`)
- **Trigger:** Writable `node_modules/`, `site-packages/`, `vendor/`, `gems/`
- **Attack:** Replace any package with trojanized version
- **Privileges needed:** NONE

#### 7. Registry Path Coercion (`Registry_Coercion`)
- **Trigger:** High-integrity process opens/creates a key in `HKCU` or `HKU\<SID>` without `REG_OPTION_OPEN_LINK`.
- **Attack:** Plant a `REG_LINK` (registry symbolic link) to redirect the registry access to a different, attacker-controlled key within the user's hive.
- **Result:** Context-dependent. Can result in privileged config poisoning, CLSID (COM) hijacking, or arbitrary registry write via TOCTOU.
- **Privileges needed:** NONE. A standard medium-IL user can create `REG_LINK`s.
- **Severity:** Critical
- **Look for in cognitive review:** Any `RegOpenKey`, `RegCreateKey`, or `RegQueryValue` by a SYSTEM process against `HKCU` or `HKEY_USERS\<SID>`. Ensure `Open Link` is missing from the Options/Detail fields.

### WRITE-PATH Primitives (privileged process WRITES to writable path)

#### 8. Arbitrary Write via Oplock + Junction (`Oplock_ArbitraryWrite`)
- **Trigger:** High-integrity process WRITES to user-writable path
- **Attack:** Set oplock on target file → oplock fires when process opens file → attacker swaps NTFS junction → write lands in arbitrary privileged location (System32, drivers, etc.)
- **Result:** Arbitrary file write as SYSTEM. Can drop DLLs into System32, modify hosts file, plant scheduled tasks.
- **Privileges needed:** NONE. Standard users can set oplocks and create junctions.
- **Severity:** Critical
- **Best targets:** `.tmp`, `.log`, `.cache`, `.bak` files that are written repeatedly (reliable trigger). One-shot writes are harder to race.
- **Look for in cognitive review:** ANY `WriteFile` or `SetDisposition` from a SYSTEM process to a writable path. The file content is irrelevant — it's the write operation itself that's the weapon.

### EXECUTION Primitives (no privileged process required)

#### 9. AutoRun / Script Persistence (`AutoRun_Persistence`)
- **Trigger:** Writable `.bat`/`.ps1`/`.vbs`/`.cmd` or Startup/Tasks directories
- **Privileges needed:** NONE

#### 10. Web Shell Planting (`WebShell_Plant`)
- **Trigger:** Writable webroot + script extension
- **Privileges needed:** NONE

#### 11. LNK Shortcut Hijacking (`LNK_Hijack`)
- **Trigger:** Writable `.lnk` shortcuts
- **Attack:** Modify target field to redirect execution
- **Privileges needed:** NONE

#### 12. Certificate Store Planting (`Cert_Plant`)
- **Trigger:** Writable cert files (`.cer`/`.pfx`/`.p12`) or crypto store directories
- **Attack:** Inject trusted root CA for MitM, or code-signing cert to bypass signature verification
- **Privileges needed:** NONE to write; system impact depends on cert store location

#### 13. LOLBin Proxy (`LOLBin_Proxy`)
- **Trigger:** File accessed by a Living-off-the-Land binary
- **Attack:** Depends on specific LOLBin parsing behavior
- **Privileges needed:** NONE

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

The `OperationDirection` field tells you which kill chain applies:

| Direction | Low-Priv Kill Chain |
|-----------|-------------------|
| **Read** | SMB coercion (junction → UNC), DLL hijack, config poison, pipe plant |
| **Write** | Oplock+junction arbitrary write, log/cache poisoning |

**Critical insight:** A privileged WRITE to a writable path is often MORE dangerous than a read, because the oplock+junction primitive gives you arbitrary file write as SYSTEM — the most powerful escalation primitive available to a standard user.
