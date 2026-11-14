---
name: Enrich-SystemPermissions
description: Performs a 100% read-only, zero-dependency static security audit of Windows non-filesystem/registry permission surfaces — Services (SCM SDs & TriggerInfo), Scheduled Tasks (TaskCache SDs & $(Arg0) actions), DCOM/COM (LaunchPermission, AccessPermission, Elevation), WMI (Namespace SDs & LocalSystemHost providers), Process/Thread/Token DACLs & SystemExtendedHandleInformation leaked handles, UIPI High-IL window sinks, WNF state SDs, and Kernel Device objects — producing system_permissions_audit.json to enrich Analyze-ExecutionLeads.
---
# Enrich-SystemPermissions (Phase 2 — Rev 3.5)

This skill audits live Windows subsystem security descriptors that Procmon CSV traces do not directly expose, and outputs `system_permissions_audit.json` (plus optionalsynthetic/direct lead entries that `AnalyzeExecutionLeads.ps1` automatically ingests and correlates with File/Registry trace leads).

## Safety & Compatibility Guarantees
- **100% Static & Read-Only:** Never modifies, starts, stops, or writes to any service, task, registry key, WMI class, process, or device object.
- **Zero External Dependencies:** Uses built-in `.NET` (`RawSecurityDescriptor`, `CommonSecurityDescriptor`, `Registry`, `CimSession`) and read-only Win32/NT P/Invoke (`QueryServiceObjectSecurity`, `NtQuerySystemInformation`, `EnumWindows`, `GetSecurityInfo`).
- **Graceful Degradation:** Runs both as a standard user (auditing everything readable by `Medium` IL) and as Administrator (unlocking full `TaskCache` SDs and cross-process handle inspection).

## Audited Subsystems & Surfaced Primitives

| Subsystem | What Is Audited | Surfaced `ExploitPrimitive` |
|---|---|---|
| **SCM Services & Triggers** | Service SD (`SERVICE_CHANGE_CONFIG`, `WRITE_DAC`, `WRITE_OWNER`, `SERVICE_START`, `SERVICE_STOP`, `SERVICE_USER_DEFINED_CONTROL`) + `TriggerInfo` (ETW/WNF/Pipe/RPC triggers & WMI Security GUID SDs) | `Service_OnDemand_Trigger_Chain` (and enriches existing service binary/config leads) |
| **Scheduled Tasks (`TaskCache`)** | `HKLM\...\Schedule\TaskCache\Tree\*\SD` (`TASK_EXECUTE` `0x20`, `WRITE_DAC`) + `TaskCache\Tasks\*` (`Author`, `URI`, `Actions`, `$(Arg0)` arguments) | `ScheduledTask_OnDemand_Run` |
| **DCOM / COM (`AppID` & `Elevation`)** | `MachineLaunchRestriction` / `MachineAccessRestriction` ceiling + per-`AppID` `LaunchPermission` / `AccessPermission` (`COM_RIGHTS_EXECUTE_LOCAL`, `ACTIVATE_LOCAL`) on `RunAs = Interactive User` / `LocalService` + UAC `Elevation` (`Enabled=1`) | `DCOM_Privileged_Activation`, `COM_HKLM_Hijack` |
| **WMI Namespaces & Providers** | Recursive `__SystemSecurity::GetSecurityDescriptor` (`WBEM_METHOD_EXECUTE`, `WBEM_WRITE_PROVIDER`, `WRITE_DAC`) + `__Win32Provider` `HostingModel` (`LocalSystemHost`, `Decoupled:Com`) | `WMI_LocalSystemHost_Sink` |
| **Process DACLs & Leaked Handles** | `NtQuerySystemInformation(SystemExtendedHandleInformation)` for High/SYSTEM process/thread/token handles inherited into Medium/Low-IL processes + permissive High/SYSTEM Process DACLs | `Leaked_Privileged_Handle` |
| **UIPI & Window Stations** | Top-level and `HWND_MESSAGE` windows owned by High/SYSTEM processes in the interactive session (`WinSta0\Default`) + Desktop DACLs (`DESKTOP_HOOKCONTROL`, `DESKTOP_JOURNALPLAYBACK`) | `UIPI_HighIL_MessageSink` |
| **Kernel Devices, Sections & WNF** | `\Device\*` DACLs (`\\.\GLOBALROOT\Device\*`), `\BaseNamedObjects\*` shared sections (`SECTION_MAP_WRITE`), and WNF `Notifications` SDs | `Kernel_Device_IOCTL_Surface`, `SharedSection_MemoryTamper` |

## Usage

```powershell
powershell -ExecutionPolicy Bypass -File .\skills\Enrich-SystemPermissions\scripts\EnrichSystemPermissions.ps1 -OutputPath .\system_permissions_audit.json
```

When `system_permissions_audit.json` is placed in the same directory as `writable_paths.json` (or passed via `-SystemPermissionsPath` to `AnalyzeExecutionLeads.ps1`), `AnalyzeExecutionLeads.ps1` automatically:
1. Correlates every service process (`svchost.exe`, vendor service `.exe`, `ServiceDll`) and scheduled task in `writable_paths.json` with its on-demand start/stop/trigger permissions (`Service_OnDemand_Trigger_Chain`).
2. Merges standalone subsystem findings (`DCOM_Privileged_Activation`, `WMI_LocalSystemHost_Sink`, `ScheduledTask_OnDemand_Run`, `Leaked_Privileged_Handle`, `UIPI_HighIL_MessageSink`, `Kernel_Device_IOCTL_Surface`, `SharedSection_MemoryTamper`) directly into `high_confidence_leads.json`.
