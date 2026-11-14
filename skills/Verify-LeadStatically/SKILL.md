---
name: Verify-LeadStatically
description: Phase 3 (Rev 3.6) 100% static, read-only binary & decompilation verification skill that sits between `Analyze-ExecutionLeads` and `Research-Lead`. Resolves the backing PE binary/DLL/driver for each surfaced lead (including `svchost.exe` `ServiceDll`s, Scheduled Task `<ComHandler>` CLSIDs, DCOM `AppID`/`CLSID` servers, and kernel `.sys` drivers), extracts PE imports, mitigations, embedded manifests (`autoElevate`, `uiAccess`), string RVAs, and optional `NtApiDotNet` RPC servers, and generates an actionable IDA MCP (`HexRaysSA/ida-mcp` / `mrexodia/ida-pro-mcp`) verification playbook answering the 4 static exploitability questions before touching a VM.
---

# Verify-LeadStatically

This skill bridges the gap between **trace/subsystem triage** (`Analyze-ExecutionLeads`) and **destructive VM exploitation** (`Research-Lead`).

> [!IMPORTANT]
> **100% Static & Read-Only Guarantee:**
> `Verify-LeadStatically` NEVER starts/stops services, triggers tasks, opens device handles, or modifies files/registry keys. It inspects PE headers, import tables, embedded manifests, string RVAs, and read-only registry/COM metadata, and drives **IDA MCP** (`HexRaysSA/ida-mcp` or `mrexodia/ida-pro-mcp`) to verify the code path statically before you ever boot a test VM.

---

## 1. The 4 Questions Answered Statically Before Touching a VM

For every surfaced lead in `high_confidence_leads.json`, `Verify-LeadStatically` resolves the responsible binary/DLL/driver and answers four questions:

1. **Q1 — Open / Creation / Device Flag Check:**
   - *Filesystem leads:* Does `CreateFileW` / `NtCreateFile` pass `FILE_FLAG_OPEN_REPARSE_POINT` (`0x00200000`) or `OBJECT_ATTRIBUTES.Attributes = OBJ_DONT_REPARSE` (`0x1000`)?
   - *Registry leads:* Does `RegOpenKeyExW` / `NtOpenKeyEx` pass `REG_OPTION_OPEN_LINK` (`0x0008`)?
   - *Kernel driver leads:* Does `DriverEntry` call `WdmlibIoCreateDeviceSecure` or pass `FILE_DEVICE_SECURE_OPEN` (`0x00000100`) to `IoCreateDevice`?
2. **Q2 — Impersonation Check:**
   - Does the target binary import and call `RpcImpersonateClient`, `CoImpersonateClient`, `ImpersonateNamedPipeClient`, or `ImpersonateLoggedOnUser` before the sink?
   - **Critical check in IDA:** Does the code check the return value (`!= RPC_S_OK` / `FAILED(hr)` / `== FALSE`) and abort on failure, or does it silently fall back to executing as `SYSTEM`?
   - *Fast static signal:* If the target module handles RPC/DCOM/Pipe requests as `SYSTEM` and **does not import any impersonation API**, all file/registry/process operations in that module run under the host service's `SYSTEM` token!
3. **Q3 — Downstream Sink Identification:**
   - What sink receives the handle, path, or registry data buffer?
     - **Execution sink:** `LoadLibraryExW`, `LdrLoadDll`, `CreateProcessAsUserW`, `CreateProcessWithTokenW`, `ShellExecuteExW`
     - **Destructive / Arbitrary Write / Delete / Move sink:** `WriteFile`, `DeleteFileW`, `RemoveDirectoryW`, `MoveFileExW`, `SetFileInformationByHandle` (`FileDispositionInfo` / `FileRenameInfo`)
     - **ACL / Security Descriptor sink:** `SetNamedSecurityInfoW`, `SetSecurityInfo`, `SetKernelObjectSecurity`
     - **Kernel IOCTL sink:** `MajorFunction[IRP_MJ_DEVICE_CONTROL]` (`0x0E`) handler (`MethodNeither` raw user pointers, physical memory mapping `MmMapIoSpace`, MSR writes, or arbitrary kernel R/W)
4. **Q4 — Trigger Reachability:**
   - How does a standard user (`LowPriv`) or sandboxed process (`AppContainer`) trigger this code path on demand?
     - **RPC:** Interface UUID + `OpNum` (extracted via `NtApiDotNet` `Get-RpcServer` or IDA `MIDL_SERVER_INFO` XREFs)
     - **DCOM / COM:** `AppID` / `CLSID` + `CoCreateInstance` / `CoGetClassObject` method vtable
     - **Scheduled Task:** `schtasks /Run /TN "<TaskPath>"` or `ITaskFolder::GetTask` COM call (with optional `$(Arg0)` arguments)
     - **SCM Service:** `sc start <Svc>` or ETW / WNF / RPC / DeviceArrival trigger GUID
     - **Kernel Driver:** `CreateFileW("\\.\<DosDeviceSymLink>", ...)` + `DeviceIoControl(hDev, IOCTL_CODE, ...)`

---

## 2. Automated Binary & Module Resolution

Many privileged leads in Procmon/ETW traces are attributed to generic host processes (`svchost.exe`, `taskhostw.exe`, `dllhost.exe`, `wmiprvse.exe`, `mmc.exe`). `VerifyLeadStatically.ps1` automatically resolves the true backing PE module:

| Lead Source / Host Process | Static Resolution Mechanism |
|---|---|
| `svchost.exe (<SvcName>)` or `HKLM\...\Services\<Svc>` | Queries `HKLM\SYSTEM\CurrentControlSet\Services\<Svc>\Parameters\ServiceDll` (falls back to `ImagePath`) |
| `ScheduledTask_OnDemand_Run` / `Tasks\<TaskPath>` | Parses task XML / `Schedule.Service` COM definition for `<Command>` or resolves `<ComHandler><ClassId>{GUID}</ClassId></ComHandler>` $\rightarrow$ `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32` / `LocalServer32` |
| `DCOM_Privileged_Activation` (`AppID\{GUID}`) | Maps `AppID` $\rightarrow$ `LocalService` (`ServiceDll`/`ImagePath`) or scans `HKLM\SOFTWARE\Classes\CLSID` for classes bound to `AppID` and resolves `InprocServer32` / `LocalServer32` |
| `COM_HKLM_Hijack` / `COM_Hijack_HKCU` (`CLSID\{GUID}`) | Resolves the existing/counterpart `CLSID` server binary plus the calling client process executable |
| `Kernel_Device_IOCTL_Surface` (`\Device\<Drv>`) | Queries `HKLM\SYSTEM\CurrentControlSet\Services\<Drv>\ImagePath` $\rightarrow$ `C:\Windows\System32\drivers\<Drv>.sys` |
| `WMI_LocalSystemHost_Sink` (`WMI:\ROOT\...`) | Resolves `__Win32Provider.CLSID` $\rightarrow$ `InprocServer32` DLL |

---

## 3. Running `VerifyLeadStatically.ps1`

```powershell
# Verify top 25 Critical/High leads from high_confidence_leads.json
powershell.exe -ExecutionPolicy Bypass -File .\skills\Verify-LeadStatically\scripts\VerifyLeadStatically.ps1 `
    -LeadsJson ".\high_confidence_leads.json" `
    -OutputPath ".\static_verification_results.json" `
    -MinSeverity High `
    -MaxLeads 25
```

### Outputs Produced
1. **`static_verification_results.json`**: Enriched JSON array containing the resolved `TargetBinaryPath`, PE security mitigations (`ASLR`, `CFG`, `ForceIntegrity`), Authenticode status, embedded manifest flags (`AutoElevate`, `UiAccess`, `ExecutionLevel`), categorized dangerous imports (`ImpersonationApis`, `ExecutionSinkApis`, `FilesystemRegistryApis`, `DaclSecurityApis`, `RpcComIpcApis`), matched UTF-16LE/ASCII string RVAs inside the binary, optional `NtApiDotNet` RPC server metadata, `StaticTriageStatus`, and the 4-question static analysis summary.
2. **`ida_mcp_verification_queue.json`**: Ready-to-run playbook of `ida-pro-mcp` / `HexRaysSA/ida-mcp` tool calls (`list_strings_filter`, `list_imports`, `get_xrefs_to`, `decompile_function`, `get_callers`, `set_comment`) anchored to the exact binary path, string RVAs, and sink imports for each lead.
3. **`Static_Verification_Report.md`**: Human- and agent-readable Markdown report summarizing the static findings and IDA decompilation targets.

---

## 4. Interactive / Headless IDA MCP Workflow

After running `VerifyLeadStatically.ps1`, if **`ida-pro-mcp`** or **Official Hex-Rays IDA MCP (`HexRaysSA/ida-mcp`)** is connected in the agent's MCP tools:

1. Call `check_connection` / `get_metadata` to confirm which binary is currently loaded in IDA (or spawn a headless `ida-mcp` instance on `TargetBinaryPath`).
2. For each lead in `ida_mcp_verification_queue.json`:
   - Call `list_strings_filter` with the lead's `SearchStrings` (or jump directly to `MatchedStringRvas` using `get_xrefs_to`).
   - Call `get_xrefs_to` on the matched string address or imported sink API (`CreateFileW`, `NtCreateFile`, `RegOpenKeyExW`, `CreateProcessAsUserW`, `SetNamedSecurityInfoW`, `IoCreateDevice`).
   - Call `decompile_function` on the referencing function and inspect:
     - **Q1:** `dwFlagsAndAttributes` / `CreateOptions` / `ulOptions`
     - **Q2:** `RpcImpersonateClient` / `CoImpersonateClient` presence and return-value check
     - **Q3:** Handle/buffer data flow into execution, write, delete, or DACL sinks
   - Call `get_callers` upward to identify the entry point (`OpNum`, COM method, `ServiceMain`, `DriverEntry` / `MajorFunction[0x0E]`).
   - Optionally call `set_comment` to annotate the verified sink and trigger chain inside the `.i64` database.
3. Record the static verdict (`CONFIRMED_STATIC_SINK`, `MITIGATED_IN_CODE`, or `NEEDS_DYNAMIC_TRACE`) before handing off confirmed leads to `Research-Lead`.
