# Surfaced Security Leads — Commit `7b39ef3` (Phase 1 `Rev 3.4` + Phase 2 `Rev 3.5`)

- **Commit:** `7b39ef3` (`fix/rev3.3-audit-fixes`)
- **Generated At:** 2026-11-14T18:33:01.2260101+02:00
- **Audit Mode:** 100% Static & Read-Only (Perspective-Aware: `LowPriv`, `AppContainer`, `MediumILAdmin`, `HighILAdmin`)

---

## 1. Executive Summary & Breakdown

### 1.1 Phase 2 Native Subsystem Audit Summary (`EnrichSystemPermissions.ps1`)
| Metric | Count |
|---|---|
| **SCM Services Audited** | 427 |
| **Privileged Services with LowPriv Start/Stop or On-Demand Triggers** | 154 |
| **Scheduled Tasks Audited** | 182 |
| **DCOM AppIDs Flagged** | 151 |
| **UIPI High-IL Interactive Windows** | 1 |
| **Total Direct Subsystem Leads** | **134** |

| ExploitPrimitive | Count | Severity |
|---|---|---|
| `DCOM_Privileged_Activation` | 98 | High |
| `Kernel_Device_IOCTL_Surface` | 21 | High |
| `ScheduledTask_OnDemand_Run` | 15 | Critical, High |

### 1.2 Phase 1 Trace Benchmark Summary (`BootLogProcMonAll.CSV` — 6,054,550 Events)
| ExploitPrimitive | High-Confidence Leads |
|---|---|
| `Registry_Coercion` | 1,528 |
| `File_DeleteChild_Recreate` *(New in Rev 3.4)* | 839 |
| `SMB_Coercion` | 413 |
| `Registry_BufferOverflow_TOCTOU` *(New in Rev 3.4)* | 364 |
| `Registry_Data_Path_Reference` *(New in Rev 3.4 — includes read-only HKLM keys)* | 285 |
| `CheckThenUse_Reparse_TOCTOU` *(New in Rev 3.4)* | 240 |
| `COM_Hijack_HKCU` | 180 |
| `Parent_Directory_Reparse_Bypass` *(New in Rev 3.4)* | 159 |
| `Binary_Plant_UserSpace` | 124 |
| `Cert_Plant` | 97 |
| `Arbitrary_DACL_Overwrite` *(New in Rev 3.4)* | 75 |
| `Config_Poison` | 57 |
| `AutoRun_Persistence` | 50 |
| `AppContainer_Sandbox_Escape` *(New in Rev 3.4)* | 34 |
| `BackupSemantics_DACL_Bypass` *(New in Rev 3.4)* | 20 |
| `DesktopIni_Coerce` | 17 |
| `ACL_WriteDac_WriteOwner` *(New in Rev 3.4)* | 16 |
| `LNK_Hijack` | 16 |
| `Oplock_ArbitraryWrite` | 15 |
| `Binary_Plant_HighPriv` | 4 |
| `Env_Hijack_HKCU` | 3 |
| `SxS_DotLocal` | 3 |
| `Service_BinaryPath` | 3 |
| `URL_NTLM_Coerce` | 2 |
| `IFEO_Debugger` | 2 |
| `ScheduledTask_Plant` | 2 |
| `AppExecAlias_Plant` | 2 |
| `Signature_TOCTOU_Bypass` *(New in Rev 3.4)* | 1 |
| `Arbitrary_Delete_ConfigMsi_LPE` *(New in Rev 3.4)* | 1 |
| `Electron_AsarTamper` | 1 |
| **Total High-Confidence Trace Leads** | **4,553** *(10,736 sibling bursts collapsed)* |

---

## 2. Surfaced Phase 2 Subsystem Leads (134 Total)

### 2.1 `ScheduledTask_OnDemand_Run` (15 Leads)

- [ ] [Critical] **Lead #1 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Application Experience\MareBackup`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Application Experience\MareBackup' (Command: '%windir%\system32\compattelrunner.exe', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #2 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\File Classification Infrastructure\Property Definition Sync' (Command: '', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #3 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Input\LocalUserSyncDataAvailable`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Input\LocalUserSyncDataAvailable' (Command: '', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #4 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Input\MouseSyncDataAvailable`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Input\MouseSyncDataAvailable' (Command: '', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #5 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Input\PenSyncDataAvailable`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Input\PenSyncDataAvailable' (Command: '', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #6 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Input\TouchpadSyncDataAvailable`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Input\TouchpadSyncDataAvailable' (Command: '', AcceptsUserArgs=False) is visible/executable by a standard user and grants task modification rights.

- [ ] [Critical] **Lead #7 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\NetTrace\GatherNetworkInfo`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\NetTrace\GatherNetworkInfo' (Command: '%windir%\system32\gatherNetworkInfo.vbs', AcceptsUserArgs=True) is visible/executable by a standard user and accepts user-supplied $(ArgN) command-line parameters.

- [ ] [Critical] **Lead #8 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Shell\FamilySafetyRefreshTask`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Shell\FamilySafetyRefreshTask' (Command: '', AcceptsUserArgs=True) is visible/executable by a standard user and accepts user-supplied $(ArgN) command-line parameters.

- [ ] [Critical] **Lead #9 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\WlanSvc\CDSSync`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\WlanSvc\CDSSync' (Command: '', AcceptsUserArgs=True) is visible/executable by a standard user and accepts user-supplied $(ArgN) command-line parameters.

- [ ] [Critical] **Lead #10 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Workplace Join\Automatic-Device-Join`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Workplace Join\Automatic-Device-Join' (Command: '%SystemRoot%\System32\dsregcmd.exe', AcceptsUserArgs=True) is visible/executable by a standard user and accepts user-supplied $(ArgN) command-line parameters.

- [ ] [High] **Lead #11 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\AppxDeploymentClient\MyTaskName`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\AppxDeploymentClient\MyTaskName' (Command: 'C:\Path\To\YourApp.exe', AcceptsUserArgs=False) is visible/executable by a standard user and executes a non-standard binary path.

- [ ] [High] **Lead #12 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Windows Defender\Windows Defender Cache Maintenance' (Command: 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe', AcceptsUserArgs=False) is visible/executable by a standard user and executes a non-standard binary path.

- [ ] [High] **Lead #13 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Cleanup`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Windows Defender\Windows Defender Cleanup' (Command: 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe', AcceptsUserArgs=False) is visible/executable by a standard user and executes a non-standard binary path.

- [ ] [High] **Lead #14 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Windows Defender\Windows Defender Scheduled Scan' (Command: 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe', AcceptsUserArgs=False) is visible/executable by a standard user and executes a non-standard binary path.

- [ ] [High] **Lead #15 — Path:** `C:\Windows\System32\Tasks\Microsoft\Windows\Windows Defender\Windows Defender Verification`
  - **Exploit Primitive:** `ScheduledTask_OnDemand_Run` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Schedule)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `taskcache-sd`
  - **Analysis:** Privileged scheduled task '\Microsoft\Windows\Windows Defender\Windows Defender Verification' (Command: 'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpCmdRun.exe', AcceptsUserArgs=False) is visible/executable by a standard user and executes a non-standard binary path.

### 2.2 `Kernel_Device_IOCTL_Surface` (21 Leads)

- [ ] [High] **Lead #16 — Path:** `\Device\applockerfltr`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (applockerfltr)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'applockerfltr' (system32\drivers\applockerfltr.sys) defines an explicit Security Descriptor under Services\applockerfltr\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:BAG:SYD:P(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCLCSWRPWPDTLOCRRC;;;LS)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLORC;;;BU)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-80-2078495744-2416903469-4072184685-3943858305-976987417)(A;;CCLCSWLORC;;;AC)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #17 — Path:** `\Device\CLFS`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (CLFS)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'CLFS' (System32\drivers\CLFS.sys) defines an explicit Security Descriptor under Services\CLFS\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464G:S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464D:P(A;;CCLCSWLORC;;;SY)(A;;CCLCSWLORC;;;BA)(A;;CCLCSWLORC;;;BU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;CCLCSWLORC;;;AC)(A;;CCLCSWLORC;;;S-1-15-3-1024-1065365936-1281604716-3511738428-1654721687-432734479-3232135806-4053264122-3456934681)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #18 — Path:** `\Device\HTTP`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (HTTP)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'HTTP' (system32\drivers\HTTP.sys) defines an explicit Security Descriptor under Services\HTTP\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLORC;;;S-1-5-3)(A;;CCLCSWRPLORC;;;IU)(A;;CCLCSWRPLORC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #19 — Path:** `\Device\IpFilterDriver`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (IpFilterDriver)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'IpFilterDriver' (system32\DRIVERS\ipfltdrv.sys) defines an explicit Security Descriptor under Services\IpFilterDriver\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;S-1-5-80-611605672-2879557022-2206624263-4029342278-3129212340)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #20 — Path:** `\Device\IPT`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (IPT)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'IPT' (\SystemRoot\System32\drivers\ipt.sys) defines an explicit Security Descriptor under Services\IPT\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;RP;;;WD)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #21 — Path:** `\Device\MMCSS`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (MMCSS)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'MMCSS' (\SystemRoot\system32\drivers\mmcss.sys) defines an explicit Security Descriptor under Services\MMCSS\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RP;;;BU)(A;;LCRP;;;AC)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #22 — Path:** `\Device\mpsdrv`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (mpsdrv)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'mpsdrv' (System32\drivers\mpsdrv.sys) defines an explicit Security Descriptor under Services\mpsdrv\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCLORC;;;AU)(A;;CCDCLCSWRPLORCWDWO;;;SY)(A;;CCLCSWRPLORCWDWO;;;BA)(A;;CCLCLO;;;BU)S:(AU;FA;CCDCLCSWRPWPDTLOSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #23 — Path:** `\Device\MsQuic`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (MsQuic)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'MsQuic' (system32\drivers\msquic.sys) defines an explicit Security Descriptor under Services\MsQuic\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLORC;;;S-1-5-3)(A;;CCLCSWRPLORC;;;IU)(A;;CCLCSWRPLORC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #24 — Path:** `\Device\MsSecCore`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (MsSecCore)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'MsSecCore' (system32\drivers\msseccore.sys) defines an explicit Security Descriptor under Services\MsSecCore\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #25 — Path:** `\Device\MsSecFlt`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (MsSecFlt)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'MsSecFlt' (system32\drivers\mssecflt.sys) defines an explicit Security Descriptor under Services\MsSecFlt\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #26 — Path:** `\Device\MsSecWfp`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (MsSecWfp)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'MsSecWfp' (system32\drivers\mssecwfp.sys) defines an explicit Security Descriptor under Services\MsSecWfp\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRRCWDWO;;;BA)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #27 — Path:** `\Device\NetBT`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (NetBT)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'NetBT' (System32\DRIVERS\netbt.sys) defines an explicit Security Descriptor under Services\NetBT\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;DT;;;LS)(A;;DT;;;NS)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPWPDTLOCRRC;;;SO)(A;;CCLCSWRPLOCRRC;;;NO)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #28 — Path:** `\Device\QWAVEdrv`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (QWAVEdrv)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'QWAVEdrv' (\SystemRoot\system32\drivers\qwavedrv.sys) defines an explicit Security Descriptor under Services\QWAVEdrv\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLO;;;IU)(A;;CCLCSWRPLO;;;NS)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLO;;;UD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #29 — Path:** `\Device\RasAcd`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (RasAcd)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'RasAcd' (System32\DRIVERS\rasacd.sys) defines an explicit Security Descriptor under Services\RasAcd\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:AI(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #30 — Path:** `\Device\RdpVideoMiniport`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (RdpVideoMiniport)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'RdpVideoMiniport' (System32\drivers\rdpvideominiport.sys) defines an explicit Security Descriptor under Services\RdpVideoMiniport\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;RPWP;;;S-1-5-80-446051430-1559341753-4161941529-1950928533-810483104)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #31 — Path:** `\Device\scfilter`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (scfilter)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'scfilter' (System32\DRIVERS\scfilter.sys) defines an explicit Security Descriptor under Services\scfilter\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRRC;;;BA)S:(AU;SAFA;WDWO;;;BA)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #32 — Path:** `\Device\UCPD`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (UCPD)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'UCPD' (system32\drivers\UCPD.sys) defines an explicit Security Descriptor under Services\UCPD\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLORC;;;S-1-5-3)(A;;CCLCSWRPLORC;;;IU)(A;;CCLCSWRPLORC;;;SU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #33 — Path:** `\Device\WdBoot`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (WdBoot)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'WdBoot' (system32\drivers\wd\WdBoot.sys) defines an explicit Security Descriptor under Services\WdBoot\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-30551196-2029750602-3680353947-2336859763-523537544)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #34 — Path:** `\Device\WdFilter`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (WdFilter)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'WdFilter' (system32\drivers\wd\WdFilter.sys) defines an explicit Security Descriptor under Services\WdFilter\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-30551196-2029750602-3680353947-2336859763-523537544)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #35 — Path:** `\Device\WdNisDrv`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (WdNisDrv)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'WdNisDrv' (system32\drivers\wd\WdNisDrv.sys) defines an explicit Security Descriptor under Services\WdNisDrv\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWRPLOCRRC;;;SU)(A;;CCLCSWRPLOCRRC;;;SY)(A;;CCLCSWRPLOCRRC;;;BA)(A;;CCLCSWRPLOCRRC;;;BU)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-30551196-2029750602-3680353947-2336859763-523537544)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

- [ ] [High] **Lead #36 — Path:** `\Device\WinNat`
  - **Exploit Primitive:** `Kernel_Device_IOCTL_Surface` | **Category:** `LPE` | **Prompt:** `admin_kernel`
  - **Processes:** `System (WinNat)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `driver-registry-sd`
  - **Analysis:** Kernel driver 'WinNat' (system32\drivers\winnat.sys) defines an explicit Security Descriptor under Services\WinNat\Security that grants device access or DACL modification rights to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs.

### 2.3 `DCOM_Privileged_Activation` (98 Leads)

- [ ] [High] **Lead #37 — Path:** `HKLM\SOFTWARE\Classes\AppID\{03E09F3B-DCE4-44FE-A9CF-82D050827E1C}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (AudioSrv)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{03E09F3B-DCE4-44FE-A9CF-82D050827E1C}' ('', RunAs='', LocalService='AudioSrv') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCSW;;;WD)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #38 — Path:** `HKLM\SOFTWARE\Classes\AppID\{05516190-a2c3-4596-9505-66d0e7913e44}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ExtServer)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{05516190-a2c3-4596-9505-66d0e7913e44}' ('ExtServer', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-2-1723189366-2159580849-2248400763-1481059666-1951766778-2756563051-3565589001)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #39 — Path:** `HKLM\SOFTWARE\Classes\AppID\{0A886F29-465A-4aea-8B8E-BE926BFAE83E}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (EapHost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{0A886F29-465A-4aea-8B8E-BE926BFAE83E}' ('', RunAs='', LocalService='EapHost') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;NS)(A;;CCDCSW;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #40 — Path:** `HKLM\SOFTWARE\Classes\AppID\{0B15AFD8-3A99-4A6E-9975-30D66F70BD94}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (AxInstSv)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{0B15AFD8-3A99-4A6E-9975-30D66F70BD94}' ('AxInstSv', RunAs='', LocalService='AxInstSv') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;S-1-15-3-4096)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #41 — Path:** `HKLM\SOFTWARE\Classes\AppID\{0B789C73-D8DA-416D-B665-C1603676CEB1}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (WpnUserService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{0B789C73-D8DA-416D-B665-C1603676CEB1}' ('MainController App ID', RunAs='', LocalService='WpnUserService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-15-2-4057404492-3731908925-1689078144-1791141876-1511382783-3872526277-3538393654)(A;;CCDCSW;;;S-1-15-3-1024-3167453650-624722384-889205278-321484983-714554697-3592933102-807660695-1632717421)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #42 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1111A26D-EF95-4A45-9F55-21E52ADF9887}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (MpUx Agent Host)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1111A26D-EF95-4A45-9F55-21E52ADF9887}' ('MpUx Agent Host', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;LS)(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #43 — Path:** `HKLM\SOFTWARE\Classes\AppID\{136A0DC7-DF5C-4271-A2AC-15DF1A1323F2}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wercplsupport)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{136A0DC7-DF5C-4271-A2AC-15DF1A1323F2}' ('', RunAs='', LocalService='wercplsupport') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #44 — Path:** `HKLM\SOFTWARE\Classes\AppID\{145B4335-FE2A-4927-A040-7C35AD3180EF}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (fdPHost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{145B4335-FE2A-4927-A040-7C35AD3180EF}' ('', RunAs='', LocalService='fdPHost') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #45 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1538524A-8AC3-4C33-BF0C-C2F9CE51DD50}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (SharedRealitySvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1538524A-8AC3-4C33-BF0C-C2F9CE51DD50}' ('', RunAs='', LocalService='SharedRealitySvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;S-1-5-80-2731152606-4244467407-1946816704-3721569673-479255522)(A;;CCDCLCSWRP;;;UD)(A;;CCDCLCSWRP;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #46 — Path:** `HKLM\SOFTWARE\Classes\AppID\{15c20b67-12e7-4bb6-92bb-7aff07997402}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (PerAppRuntimeBroker)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{15c20b67-12e7-4bb6-92bb-7aff07997402}' ('PerAppRuntimeBroker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(XA;;CCDCSW;;;IU;(!(WIN://ISMULTISESSIONSKU)))(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #47 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1725704B-A716-4E04-8EF6-87ED4F0A180A}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Speech Runtime COM)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1725704B-A716-4E04-8EF6-87ED4F0A180A}' ('Speech Runtime COM', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #48 — Path:** `HKLM\SOFTWARE\Classes\AppID\{19BCA967-D266-436f-B2D4-CBE4D4B42F96}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (lltdsvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{19BCA967-D266-436f-B2D4-CBE4D4B42F96}' ('', RunAs='', LocalService='lltdsvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;NS)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;BU)(A;;CCDCSW;;;PU)(A;;CCDCSW;;;NO)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #49 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1B162A5B-B67A-4468-9613-C3F9765B353B}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (PerceptionSimulation)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1B162A5B-B67A-4468-9613-C3F9765B353B}' ('PerceptionSimulation', RunAs='', LocalService='PerceptionSimulation') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;S-1-5-80-2731152606-4244467407-1946816704-3721569673-479255522)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #50 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1b7778f3-fe54-443c-8729-1e78b0715299}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (DebugTargetAdapters Class)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1b7778f3-fe54-443c-8729-1e78b0715299}' ('DebugTargetAdapters Class', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2687912068-1527563483-2246345126-2445616054-2679617633-2814117500-2092001380-704615243)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #51 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1BE1F766-5536-11D1-B726-00C04FB926AF}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (EventSystem)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1BE1F766-5536-11D1-B726-00C04FB926AF}' ('', RunAs='', LocalService='EventSystem') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCSW;;;WD)(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #52 — Path:** `HKLM\SOFTWARE\Classes\AppID\{1BF1C030-CE12-4A8A-A4E1-EDDCE7176799}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Futuremark SystemInfo Service)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{1BF1C030-CE12-4A8A-A4E1-EDDCE7176799}' ('FMSISvc', RunAs='', LocalService='Futuremark SystemInfo Service') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #53 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2568BFC5-CDBE-4585-B8AE-C403A2A5B84A}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2568BFC5-CDBE-4585-B8AE-C403A2A5B84A}' ('Experimentation Broker', RunAs='', LocalService='wisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #54 — Path:** `HKLM\SOFTWARE\Classes\AppID\{27550CA0-E9DE-4186-A566-37A59BB6CA69}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `Sandbox_Escape` | **Prompt:** `sandbox_escape`
  - **Processes:** `dllhost.exe (WInRTDesktopBroker)` | **Integrity:** `System`
  - **Writable From:** `AppContainer` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{27550CA0-E9DE-4186-A566-37A59BB6CA69}' ('WInRTDesktopBroker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'AppContainer' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #55 — Path:** `HKLM\SOFTWARE\Classes\AppID\{27AF75ED-20D9-11D1-B1CE-00805FC1270E}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (netman)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{27AF75ED-20D9-11D1-B1CE-00805FC1270E}' ('netman', RunAs='', LocalService='netman') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;NS)(A;;CCDCSW;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #56 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2A81FE91-95D7-487E-BBF8-B03308E54207}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2A81FE91-95D7-487E-BBF8-B03308E54207}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;AC)(A;;CCDCLCSWRP;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #57 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2A947841-0594-48CF-9C53-A08C95C22B55}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (XblAuthManager)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2A947841-0594-48CF-9C53-A08C95C22B55}' ('', RunAs='', LocalService='XblAuthManager') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #58 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2EB6D15C-5239-41CF-82FB-353D20B816CF}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (SecurityHealthService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2EB6D15C-5239-41CF-82FB-353D20B816CF}' ('Windows Security Health Service', RunAs='', LocalService='SecurityHealthService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;LS)(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #59 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2ED83BAA-B2FD-43B1-99BF-E6149C622692}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (WaaSMedicSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2ED83BAA-B2FD-43B1-99BF-E6149C622692}' ('WaaSMedicSvc', RunAs='', LocalService='WaaSMedicSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #60 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2F93C02D-77F9-46B4-95FB-8CBB81EEB62C}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (DevicesFlow)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2F93C02D-77F9-46B4-95FB-8CBB81EEB62C}' ('DevicesFlow', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #61 — Path:** `HKLM\SOFTWARE\Classes\AppID\{2FD08A73-D1F1-43EB-B888-24C2496F95FD}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ImmersiveShellBrokers)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{2FD08A73-D1F1-43EB-B888-24C2496F95FD}' ('ImmersiveShellBrokers', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #62 — Path:** `HKLM\SOFTWARE\Classes\AppID\{30AD8C8E-AE85-42FA-B9E8-7E99E3DFBFC5}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ShellServiceHostBrokerProvider)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{30AD8C8E-AE85-42FA-B9E8-7E99E3DFBFC5}' ('ShellServiceHostBrokerProvider', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #63 — Path:** `HKLM\SOFTWARE\Classes\AppID\{333AD674-15C4-4AE0-9B8E-76311249842D}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (HgClientService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{333AD674-15C4-4AE0-9B8E-76311249842D}' ('HgClientService', RunAs='', LocalService='HgClientService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BAD:(A;;CCDCSW;;;AU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #64 — Path:** `HKLM\SOFTWARE\Classes\AppID\{354ff91b-5e49-4bdc-a8e6-1cb6c6877182}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{354ff91b-5e49-4bdc-a8e6-1cb6c6877182}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;AC)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #65 — Path:** `HKLM\SOFTWARE\Classes\AppID\{362cc086-4d81-4824-bbb5-666d34b3197d}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Windows Push Notification Platform)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{362cc086-4d81-4824-bbb5-666d34b3197d}' ('Windows Push Notification Platform', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRPWPDT;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;LS)(A;;CCDCLCSWRP;;;BA)(A;;CCWPDT;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-3167453650-624722384-889205278-321484983-714554697-3592933102-807660695-1632717421)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #66 — Path:** `HKLM\SOFTWARE\Classes\AppID\{36938566-B1AA-4E77-9B3F-730CF4E996AB}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (TabTip)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{36938566-B1AA-4E77-9B3F-730CF4E996AB}' ('TabTip', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #67 — Path:** `HKLM\SOFTWARE\Classes\AppID\{370121D2-AA7E-4608-A86D-0BBAB9DA1A60}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (WSLService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{370121D2-AA7E-4608-A86D-0BBAB9DA1A60}' ('', RunAs='', LocalService='WSLService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AU)(A;;CCDCSW;;;SY)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #68 — Path:** `HKLM\SOFTWARE\Classes\AppID\{379001DE-7108-4A45-8A74-6CD0A9FBEF2C}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (dosvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{379001DE-7108-4A45-8A74-6CD0A9FBEF2C}' ('Delivery Optimization', RunAs='', LocalService='dosvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;BU)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #69 — Path:** `HKLM\SOFTWARE\Classes\AppID\{38E441FB-3D16-422F-8750-B2DACEC5CEFC}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{38E441FB-3D16-422F-8750-B2DACEC5CEFC}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDC;;;WD)(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;BU)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #70 — Path:** `HKLM\SOFTWARE\Classes\AppID\{41928E27-7275-491C-A5A1-4FDC791BF609}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Core Shell Broker Provider)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{41928E27-7275-491C-A5A1-4FDC791BF609}' ('Core Shell Broker Provider', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #71 — Path:** `HKLM\SOFTWARE\Classes\AppID\{42C21DF5-FB58-4102-90E9-96A213DC7CE8}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (EntAppSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{42C21DF5-FB58-4102-90E9-96A213DC7CE8}' ('EntAppSvc', RunAs='', LocalService='EntAppSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #72 — Path:** `HKLM\SOFTWARE\Classes\AppID\{42CBFAA7-A4A7-47BB-B422-BD10E9D02700}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (DiagnosticsHub.StandardCollector.Service)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{42CBFAA7-A4A7-47BB-B422-BD10E9D02700}' ('', RunAs='', LocalService='DiagnosticsHub.StandardCollector.Service') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-3153509613-960666767-3724611135-2725662640-12138253-543910227-1950414635-4190290187)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #73 — Path:** `HKLM\SOFTWARE\Classes\AppID\{50E1C3FD-EC35-490E-9CCF-C68F9AE91919}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (wuapihost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{50E1C3FD-EC35-490E-9CCF-C68F9AE91919}' ('wuapihost', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;S-1-5-32-2707581722-3970398075-3301609242-3412871183-2565310287-2959982868-2531230773-2372594412)(A;;CCDCSW;;;S-1-15-3-1024-2707581722-3970398075-3301609242-3412871183-2565310287-2959982868-2531230773-2372594412)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #74 — Path:** `HKLM\SOFTWARE\Classes\AppID\{52551A19-B337-498d-AE75-2283E29902DE}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (CscService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{52551A19-B337-498d-AE75-2283E29902DE}' ('Offline Files Service', RunAs='', LocalService='CscService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:S-1-5-21-528768928-1231760990-50533070-500G:S-1-5-21-528768928-1231760990-50533070-500D:(D;;CCDCLCRP;;;AU)(A;;CCSW;;;AU)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #75 — Path:** `HKLM\SOFTWARE\Classes\AppID\{549e57e9-b362-49d1-b679-b64d510efe4b}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ShareFlow)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{549e57e9-b362-49d1-b679-b64d510efe4b}' ('ShareFlow', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #76 — Path:** `HKLM\SOFTWARE\Classes\AppID\{5A4ED3BD-2F40-44B4-93DA-2B5ECC197B26}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Docking.VirtualInput Create Object Server)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{5A4ED3BD-2F40-44B4-93DA-2B5ECC197B26}' ('Docking.VirtualInput Create Object Server', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;S-1-15-2-155514346-2573954481-755741238-1654018636-1233331829-3075935687-2861478708)(A;;CCDCSW;;;S-1-15-2-460998419-1048838040-1306765847-3036341007-2963401754-1630001092-3310782549)(A;;CCDCSW;;;S-1-15-3-1024-2152139330-3124897132-671935159-3762809077-3273429135-2233686478-1435376800-2420532691)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #77 — Path:** `HKLM\SOFTWARE\Classes\AppID\{5BC7A3A1-E905-414B-9790-E511346F5CA6}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (WalletService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{5BC7A3A1-E905-414B-9790-E511346F5CA6}' ('WalletService', RunAs='', LocalService='WalletService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(A;;0x111fffff;;;SY)(A;;0x111fffff;;;BA)(A;;0x111fffff;;;BU)(A;;CCDC;;;S-1-5-21-2702878673-795188819-444038987-1030)(A;;CCDC;;;S-1-5-21-2702878673-795188819-444038987-1031)(A;;0x111fffff;;;AC)(A;;CCDC;;;S-1-15-3-1024-3625662137-2682091254-856171984-2868379045-3001028726-1009205972-4175949866-684286152)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #78 — Path:** `HKLM\SOFTWARE\Classes\AppID\{5E176815-9A63-4A69-810F-62E90D36612A}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (cdpsvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{5E176815-9A63-4A69-810F-62E90D36612A}' ('', RunAs='', LocalService='cdpsvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCWP;;;IU)(A;;CCDCLCSWRPWP;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #79 — Path:** `HKLM\SOFTWARE\Classes\AppID\{64D4882D-CB4E-4ea2-95B5-CD77F8ED8AB2}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (CoreShellHost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{64D4882D-CB4E-4ea2-95B5-CD77F8ED8AB2}' ('CoreShellHost', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #80 — Path:** `HKLM\SOFTWARE\Classes\AppID\{6DF5BCF4-22E9-446D-8763-A2C7677ECF7D}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (TieringEngineService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{6DF5BCF4-22E9-446D-8763-A2C7677ECF7D}' ('TieringEngineService', RunAs='', LocalService='TieringEngineService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;AU)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #81 — Path:** `HKLM\SOFTWARE\Classes\AppID\{6F4B8D94-91FE-4665-B1E7-A34AE3F299F6}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (SEMgrSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{6F4B8D94-91FE-4665-B1E7-A34AE3F299F6}' ('SEMgrSvc', RunAs='', LocalService='SEMgrSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;AU)(A;;0x111fffff;;;SY)(A;;0x111fffff;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #82 — Path:** `HKLM\SOFTWARE\Classes\AppID\{7006698d-2974-4091-a424-85dd0b909e23}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{7006698d-2974-4091-a424-85dd0b909e23}' ('Windows Insider Service', RunAs='', LocalService='wisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-2-4016783169-893401051-2237370320-274899566-412088533-2398988950-2155762795)(A;;CCDCSW;;;S-1-15-2-4100369157-1034187050-1364371154-1714612948-1847883727-388702109-1961059416)(A;;CCDCSW;;;S-1-15-2-1322174799-1054373777-2441082058-564842223-2721992343-4124100487-3261661085)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #83 — Path:** `HKLM\SOFTWARE\Classes\AppID\{7966b4d8-4fdc-4126-a10b-39a3209ad251}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (WebPlatStorageBrokerServer)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{7966b4d8-4fdc-4126-a10b-39a3209ad251}' ('WebPlatStorageBrokerServer', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-3623855041-1826999956-3747069818-3525260223-3747374510-1746272624-950601168-56556331)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #84 — Path:** `HKLM\SOFTWARE\Classes\AppID\{7E55A26D-EF95-4A45-9F55-21E52ADF9887}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Security Health Agent Interactive User Host)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{7E55A26D-EF95-4A45-9F55-21E52ADF9887}' ('Security Health Agent Interactive User Host', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #85 — Path:** `HKLM\SOFTWARE\Classes\AppID\{7FC12E96-4CB7-4ABD-ADAA-EF7845B10629}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Authentication UI CredUI Out of Proc Helper for AppContainer Clients)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{7FC12E96-4CB7-4ABD-ADAA-EF7845B10629}' ('Authentication UI CredUI Out of Proc Helper for AppContainer Clients', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1788129303-2183208577-3999474272-3147359985-1757322193-3815756386-151582180-1888101193)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #86 — Path:** `HKLM\SOFTWARE\Classes\AppID\{88283d7c-46f4-47d5-8fc2-db0b5cf0cb54}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (AppReadiness)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{88283d7c-46f4-47d5-8fc2-db0b5cf0cb54}' ('AppReadiness Service', RunAs='', LocalService='AppReadiness') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:S-1-5-21-528768928-1231760990-50533070-500G:S-1-5-21-528768928-1231760990-50533070-500D:(A;;CC;;;IU)(A;;CC;;;SU)(A;;CC;;;SY)(A;;CC;;;BA)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #87 — Path:** `HKLM\SOFTWARE\Classes\AppID\{8D02CEE1-70BC-449A-B873-70AC08B2676A}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (MixedRealityOpenXRSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{8D02CEE1-70BC-449A-B873-70AC08B2676A}' ('', RunAs='', LocalService='MixedRealityOpenXRSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #88 — Path:** `HKLM\SOFTWARE\Classes\AppID\{9037e3cf-1794-4af6-9c8d-92838d7a23db}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (sdrsvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{9037e3cf-1794-4af6-9c8d-92838d7a23db}' ('SDRSVC service', RunAs='', LocalService='sdrsvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;AU)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #89 — Path:** `HKLM\SOFTWARE\Classes\AppID\{93AAD2A0-036A-4B11-A078-DA8776B38139}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (HtmlLocalFileResolver)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{93AAD2A0-036A-4B11-A078-DA8776B38139}' ('HtmlLocalFileResolver', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #90 — Path:** `HKLM\SOFTWARE\Classes\AppID\{94a38670-983b-459c-87c8-bb6ad617fd74}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (UiaManager)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{94a38670-983b-459c-87c8-bb6ad617fd74}' ('UiaManager', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #91 — Path:** `HKLM\SOFTWARE\Classes\AppID\{9980CAAB-B154-408C-B5FD-29A701E40825}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (BluetoothUserService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{9980CAAB-B154-408C-B5FD-29A701E40825}' ('Bluetooth User Service', RunAs='', LocalService='BluetoothUserService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;S-1-5-80-2586557155-168560303-1373426920-983201488-1499765686)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #92 — Path:** `HKLM\SOFTWARE\Classes\AppID\{9CA88EE3-ACB7-47c8-AFC4-AB702511C276}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (RuntimeBroker)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{9CA88EE3-ACB7-47c8-AFC4-AB702511C276}' ('RuntimeBroker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(XA;;CCDCSW;;;IU;(!(WIN://ISMULTISESSIONSKU)))(A;;CCDCSW;;;PS)(XA;;CCDCSW;;;S-1-5-80-1650428981-2266088947-4151340993-835779039-3052504975;(!(WIN://ISMULTISESSIONSKU)))(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #93 — Path:** `HKLM\SOFTWARE\Classes\AppID\{9D73451F-6BFC-47C7-95FB-46598431BC19}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `Sandbox_Escape` | **Prompt:** `sandbox_escape`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `AppContainer` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{9D73451F-6BFC-47C7-95FB-46598431BC19}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'AppContainer' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #94 — Path:** `HKLM\SOFTWARE\Classes\AppID\{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{a463fcb9-6b1c-4e0d-a80b-a2ca7999e25d}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-3623855041-1826999956-3747069818-3525260223-3747374510-1746272624-950601168-56556331)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #95 — Path:** `HKLM\SOFTWARE\Classes\AppID\{A67168DB-418E-4087-B63E-852E822BB1ED}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Core Shell Service Provider)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{A67168DB-418E-4087-B63E-852E822BB1ED}' ('Core Shell Service Provider', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;S-1-15-3-1024-2152139330-3124897132-671935159-3762809077-3273429135-2233686478-1435376800-2420532691)(A;;CCDCSW;;;S-1-15-3-1024-2165721414-884371012-2773947476-2437641138-4209659587-972658821-4033014341-190168586)(A;;CCDCSW;;;S-1-15-3-1024-3167453650-624722384-889205278-321484983-714554697-3592933102-807660695-1632717421)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #96 — Path:** `HKLM\SOFTWARE\Classes\AppID\{A7E84C44-F0C0-44F9-A4F2-68B5EA50B200}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Core Shell LPAC Broker Provider)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{A7E84C44-F0C0-44F9-A4F2-68B5EA50B200}' ('Core Shell LPAC Broker Provider', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #97 — Path:** `HKLM\SOFTWARE\Classes\AppID\{AA8F1F23-D819-4E95-9B36-7FD68D5218F9}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Core Shell COM Server Registrar)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{AA8F1F23-D819-4E95-9B36-7FD68D5218F9}' ('Core Shell COM Server Registrar', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-15-3-1024-2152139330-3124897132-671935159-3762809077-3273429135-2233686478-1435376800-2420532691)(A;;CCDCSW;;;S-1-15-3-1024-2165721414-884371012-2773947476-2437641138-4209659587-972658821-4033014341-190168586)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #98 — Path:** `HKLM\SOFTWARE\Classes\AppID\{AABAA6AA-5398-4C08-AE60-6321A7F05E9C}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (F12AppFrameClient Class)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{AABAA6AA-5398-4C08-AE60-6321A7F05E9C}' ('F12AppFrameClient Class', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #99 — Path:** `HKLM\SOFTWARE\Classes\AppID\{AB7BDC53-0BB5-44F5-9E25-C444313D4686}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (WpnUserService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{AB7BDC53-0BB5-44F5-9E25-C444313D4686}' ('QuietHours App ID', RunAs='', LocalService='WpnUserService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-15-2-4057404492-3731908925-1689078144-1791141876-1511382783-3872526277-3538393654)(A;;CCDCSW;;;S-1-15-3-1024-3167453650-624722384-889205278-321484983-714554697-3592933102-807660695-1632717421)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #100 — Path:** `HKLM\SOFTWARE\Classes\AppID\{ab7c873b-eb14-49a6-be60-a602f80e6d22}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (defragsvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{ab7c873b-eb14-49a6-be60-a602f80e6d22}' ('DEFRAGSVC service', RunAs='', LocalService='defragsvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;AU)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #101 — Path:** `HKLM\SOFTWARE\Classes\AppID\{AC05815A-A8D5-434B-B9A8-2FFD162F2B7D}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (SEMgrSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{AC05815A-A8D5-434B-B9A8-2FFD162F2B7D}' ('PaymentsSvc', RunAs='', LocalService='SEMgrSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2922296261-1647482768-2017091146-3858667068-4135663662-2931985894-1627820925-818366431)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #102 — Path:** `HKLM\SOFTWARE\Classes\AppID\{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (RetailDemo)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{ac793c1d-eb2f-4ffd-b1ec-7af1aaaf3325}' ('RetailDemo Service', RunAs='', LocalService='RetailDemo') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:S-1-5-21-528768928-1231760990-50533070-500G:S-1-5-21-528768928-1231760990-50533070-500D:(A;;CC;;;IU)(A;;CC;;;SU)(A;;CC;;;SY)(A;;CC;;;BA)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #103 — Path:** `HKLM\SOFTWARE\Classes\AppID\{AD829705-CCA8-44D4-88E0-331E48336059}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (VacSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{AD829705-CCA8-44D4-88E0-331E48336059}' ('Microsoft Volumetric Audio Compositor', RunAs='', LocalService='VacSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:SUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #104 — Path:** `HKLM\SOFTWARE\Classes\AppID\{b0316d0c-da2f-40e0-9f91-f600caf042dc}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `Sandbox_Escape` | **Prompt:** `sandbox_escape`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `AppContainer` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{b0316d0c-da2f-40e0-9f91-f600caf042dc}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'AppContainer' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-79080987-3398622760-2608912076-1085899501-4039864605-4024366022-736258278-368603348)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #105 — Path:** `HKLM\SOFTWARE\Classes\AppID\{B06FF84E-0A77-4DD2-A919-0EABD8979DC1}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (WorkspaceBroker Class)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{B06FF84E-0A77-4DD2-A919-0EABD8979DC1}' ('WorkspaceBroker Class', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #106 — Path:** `HKLM\SOFTWARE\Classes\AppID\{B6C292BC-7C88-41EE-8B54-8EC92617E599}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (stisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{B6C292BC-7C88-41EE-8B54-8EC92617E599}' ('WIA Device Manager 2', RunAs='', LocalService='stisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #107 — Path:** `HKLM\SOFTWARE\Classes\AppID\{B9305506-D05B-4C36-81C5-0E50886C1755}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ApplicationActivationImpl)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{B9305506-D05B-4C36-81C5-0E50886C1755}' ('ApplicationActivationImpl', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #108 — Path:** `HKLM\SOFTWARE\Classes\AppID\{B98C6EB5-6AA7-471E-B5C5-D04FD677DB3B}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (BthAvctpSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{B98C6EB5-6AA7-471E-B5C5-D04FD677DB3B}' ('Bluetooth AVCTP Service', RunAs='', LocalService='BthAvctpSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #109 — Path:** `HKLM\SOFTWARE\Classes\AppID\{bcbb3f8c-2889-474f-8fb7-904d4a416145}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Setting Sync Task Factory)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{bcbb3f8c-2889-474f-8fb7-904d4a416145}' ('Setting Sync Task Factory', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-15-3-1024-4013343662-1780721540-2368661007-3594614809-3500637591-3061816900-1306469177-829351717)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #110 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C08E4363-9771-4955-A002-09932AE4874B}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (McpManagementService)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C08E4363-9771-4955-A002-09932AE4874B}' ('Universal Print Management Service', RunAs='', LocalService='McpManagementService') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;IU)(A;;CCDCSW;;;PS)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;NS)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-4044835139-2658482041-3127973164-329287231-3865880861-1938685643-461067658-1087000422)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #111 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C0E1CE99-C981-44A2-AC4C-41036FAC6593}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (Spectrum)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C0E1CE99-C981-44A2-AC4C-41036FAC6593}' ('Spectrum', RunAs='', LocalService='Spectrum') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCDCLCSWRP;;;S-1-5-80-2731152606-4244467407-1946816704-3721569673-479255522)(A;;CCDCLCSWRP;;;S-1-5-80-3246321066-2451215914-3422911474-2201726393-166328789)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #112 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C2E9756F-8155-4EAC-9ED5-0B690169D412}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `Sandbox_Escape` | **Prompt:** `sandbox_escape`
  - **Processes:** `dllhost.exe (DataExchangeHost)` | **Integrity:** `System`
  - **Writable From:** `AppContainer` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C2E9756F-8155-4EAC-9ED5-0B690169D412}' ('DataExchangeHost', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'AppContainer' (SDDL: O:SYG:SYD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1502825166-1963708345-2616377461-2562897074-4192028372-3968301570-1997628692-1435953622)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #113 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C2EA2356-994C-45AF-BDAE-10796F73BC47}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (RetailDemo)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C2EA2356-994C-45AF-BDAE-10796F73BC47}' ('RetailCoreSystemAgent Service', RunAs='', LocalService='RetailDemo') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:S-1-5-21-528768928-1231760990-50533070-500G:S-1-5-21-528768928-1231760990-50533070-500D:(A;;CC;;;IU)(A;;CC;;;SU)(A;;CC;;;SY)(A;;CC;;;BA)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #114 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C5D3C0E1-DC41-4F83-8BA8-CC0D46BCCDE3}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (XblGameSave)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C5D3C0E1-DC41-4F83-8BA8-CC0D46BCCDE3}' ('Xbox Live Game Saves', RunAs='', LocalService='XblGameSave') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #115 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C63261E4-6052-41FF-B919-496FECF4C4E5}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (EntAppSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C63261E4-6052-41FF-B919-496FECF4C4E5}' ('EntAppSvc', RunAs='', LocalService='EntAppSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #116 — Path:** `HKLM\SOFTWARE\Classes\AppID\{C97E2AEF-AB0E-4FA6-BA29-1A1A7CCBA125}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `Sandbox_Escape` | **Prompt:** `sandbox_escape`
  - **Processes:** `dllhost.exe (editionupgradebroker)` | **Integrity:** `System`
  - **Writable From:** `AppContainer` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{C97E2AEF-AB0E-4FA6-BA29-1A1A7CCBA125}' ('editionupgradebroker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'AppContainer' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-1692970155-4054893335-185714091-3362601943-3526593181-1159816984-2199008581-497492991)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #117 — Path:** `HKLM\SOFTWARE\Classes\AppID\{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (GraphicsPerfSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{cd93979b-c14e-4c29-87a4-75e4f9fa5e0a}' ('GraphicsPerfSvc', RunAs='', LocalService='GraphicsPerfSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;BU)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #118 — Path:** `HKLM\SOFTWARE\Classes\AppID\{D3DCB472-7261-43ce-924B-0704BD730D5F}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (fdPHost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{D3DCB472-7261-43ce-924B-0704BD730D5F}' ('', RunAs='', LocalService='fdPHost') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #119 — Path:** `HKLM\SOFTWARE\Classes\AppID\{E055B85B-22BD-4E15-A34D-46C58AB320AD}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{E055B85B-22BD-4E15-A34D-46C58AB320AD}' ('OneSetttings Broker', RunAs='', LocalService='wisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #120 — Path:** `HKLM\SOFTWARE\Classes\AppID\{E495081B-BBA5-4b89-BA3C-3B86A686B87A}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (upnphost)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{E495081B-BBA5-4b89-BA3C-3B86A686B87A}' ('upnphost', RunAs='', LocalService='upnphost') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:BAD:(D;;CC;;;NU)(A;;CC;;;WD)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #121 — Path:** `HKLM\SOFTWARE\Classes\AppID\{e53cd6ee-5c5c-4701-9ff2-c204bfed819d}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (LicenseManager)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{e53cd6ee-5c5c-4701-9ff2-c204bfed819d}' ('ContainerHostActivation', RunAs='', LocalService='LicenseManager') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSWWPDT;;;WD)(A;;CCDCSWWPDT;;;AN)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #122 — Path:** `HKLM\SOFTWARE\Classes\AppID\{E62A7A31-6025-408E-87F6-81AEB0DC9347}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Visual Studio Just-In-Time Debugger)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{E62A7A31-6025-408E-87F6-81AEB0DC9347}' ('Visual Studio Just-In-Time Debugger', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;S-1-2-0)(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #123 — Path:** `HKLM\SOFTWARE\Classes\AppID\{e82567ae-2ea4-4dbc-bc68-8b0a0526d8d5}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (LxssManager)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{e82567ae-2ea4-4dbc-bc68-8b0a0526d8d5}' ('', RunAs='', LocalService='LxssManager') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AU)(A;;CCDCSW;;;SY)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #124 — Path:** `HKLM\SOFTWARE\Classes\AppID\{EA022610-0748-4c24-B229-6C507EBDFDBB}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (HomeGroupProvider)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{EA022610-0748-4c24-B229-6C507EBDFDBB}' ('HomeGroup Provider Service', RunAs='', LocalService='HomeGroupProvider') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #125 — Path:** `HKLM\SOFTWARE\Classes\AppID\{EAB99738-0ADF-4A53-856C-DE58AFDE7682}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{EAB99738-0ADF-4A53-856C-DE58AFDE7682}' ('Feature Usage Listener', RunAs='', LocalService='wisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)(A;;CCDCSW;;;S-1-5-32-1045063015-423899465-3012769174-65638258-1865874412-2349348127-763856749-1075684855)(A;;CCDCSW;;;S-1-15-2-350187224-1905355452-1037786396-3028148496-2624191407-3283318427-1255436723)(A;;CCDCSW;;;S-1-15-3-1024-1045063015-423899465-3012769174-65638258-1865874412-2349348127-763856749-1075684855)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #126 — Path:** `HKLM\SOFTWARE\Classes\AppID\{eadbb044-2aed-4aba-bab5-1f8ae07a4a0c}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (SuspendablePerAppRuntimeBroker)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{eadbb044-2aed-4aba-bab5-1f8ae07a4a0c}' ('SuspendablePerAppRuntimeBroker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:SYG:SYD:(XA;;CCDCSW;;;IU;(!(WIN://ISMULTISESSIONSKU)))(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1024-2405443489-874036122-4286035555-1823921565-1746547431-2453885448-3625952902-991631256)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #127 — Path:** `HKLM\SOFTWARE\Classes\AppID\{EBF6A8B8-8259-4EEF-B3A0-E46F90D40563}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (wisvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{EBF6A8B8-8259-4EEF-B3A0-E46F90D40563}' ('Smart Feature Rollout Broker', RunAs='', LocalService='wisvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #128 — Path:** `HKLM\SOFTWARE\Classes\AppID\{F2DC0F57-0B99-49E3-BE80-936DBAA54EE0}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (VSStandardCollectorService150)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{F2DC0F57-0B99-49E3-BE80-936DBAA54EE0}' ('', RunAs='', LocalService='VSStandardCollectorService150') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;PS)(A;;CCDCSW;;;AU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #129 — Path:** `HKLM\SOFTWARE\Classes\AppID\{f59bbec1-0907-4464-b04d-1da329585370}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (ActivatableApplicationRegistrar)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{f59bbec1-0907-4464-b04d-1da329585370}' ('ActivatableApplicationRegistrar', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)(A;;CCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #130 — Path:** `HKLM\SOFTWARE\Classes\AppID\{F5A6ACF4-FFE0-4934-AE1D-5F960EA0AAD9}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (Pen Workspace Discover Broker)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{F5A6ACF4-FFE0-4934-AE1D-5F960EA0AAD9}' ('Pen Workspace Discover Broker', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #131 — Path:** `HKLM\SOFTWARE\Classes\AppID\{F72671A9-012C-4725-9D2F-2A4D32D65169}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{F72671A9-012C-4725-9D2F-2A4D32D65169}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSWWPDT;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;S-1-5-80-3433512109-503559027-1389316256-1766580070-2256751264)(A;;CCDCSW;;;S-1-5-80-345135819-4012009209-3062012967-1747265747-3674605950)(A;;CCDCSW;;;S-1-5-80-951620777-1059631183-2804607755-3010024351-809615488)(A;;CCDCSW;;;S-1-5-80-1260278928-804197538-2066346633-4268302704-2216462912)(A;;CCDCSWWPDT;;;AC)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #132 — Path:** `HKLM\SOFTWARE\Classes\AppID\{f8842f8e-dafe-4b37-9d38-4e0714a61149}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe ()` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{f8842f8e-dafe-4b37-9d38-4e0714a61149}' ('', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:PSG:BUD:(A;;CCDCSW;;;IU)(A;;CCDCSW;;;SY)(A;;CCDCSW;;;LS)(A;;CCDCSW;;;AC)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #133 — Path:** `HKLM\SOFTWARE\Classes\AppID\{F9717507-6651-4EDB-BFF7-AE615179BCCF}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `dllhost.exe (WinInetBrokerServer)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{F9717507-6651-4EDB-BFF7-AE615179BCCF}' ('WinInetBrokerServer', RunAs='Interactive User', LocalService='') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCSW;;;WD)(A;;CCDCSW;;;AC)(A;;CCDCSW;;;S-1-15-3-1)(A;;CCDCSW;;;S-1-15-3-2)(A;;CCDCSW;;;S-1-15-3-3)S:). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

- [ ] [High] **Lead #134 — Path:** `HKLM\SOFTWARE\Classes\AppID\{FFE1E5FE-F1F0-48C8-953E-72BA272F2744}`
  - **Exploit Primitive:** `DCOM_Privileged_Activation` | **Category:** `LPE` | **Prompt:** `lpe`
  - **Processes:** `svchost.exe (EntAppSvc)` | **Integrity:** `System`
  - **Writable From:** `LowPriv` | **ACL Source:** `dcom-launch-sd`
  - **Analysis:** DCOM AppID '{FFE1E5FE-F1F0-48C8-953E-72BA272F2744}' ('EntAppSvc', RunAs='', LocalService='EntAppSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to 'LowPriv' (SDDL: O:BAG:BAD:(A;;CCDCLCSWRP;;;WD)(A;;CCDCLCSWRP;;;IU)(A;;CCDCLCSWRP;;;SY)(A;;CCDCLCSWRP;;;BA)). Audit exposed COM interfaces on this class for file/process/marshaling sinks.

---

## 3. UIPI High-Integrity / SYSTEM Windows in Interactive Session (1 Found)

| HWND | PID | ProcessName | Integrity | ClassName | Title |
|---|---|---|---|---|---|
| `0x68143A` | 1524 | `csrss.exe` | `System` | `#32774` |  |

---

## 4. Privileged SCM Services with Low-Priv Start/Stop or On-Demand Triggers (154 Services)

> These services are automatically correlated by `AnalyzeExecutionLeads.ps1` (Rule 13 `Service_OnDemand_Trigger_Chain`) whenever a trace captures file/registry/DLL operations from their service process.

| ServiceName | Account | ImagePath | LowPrivConfig | LowPrivStartStop | HasLowPrivTrigger | Triggers |
|---|---|---|---|---|---|---|
| `Appinfo` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `AppMgmt` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | False |  |
| `AppVClient` | `LocalSystem` | `C:\Windows\system32\AppVClient.exe` | False | True | False |  |
| `AppXSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k wsappx -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `BcastDVRUserService` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k BcastDVRUserService` | False | True | False |  |
| `BcastDVRUserService_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k BcastDVRUserService` | False | True | False |  |
| `BDESVC` | `localSystem` | `C:\Windows\System32\svchost.exe -k netsvcs -p` | False | True | False | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `BrokerInfrastructure` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DcomLaunch -p` | False | True | False |  |
| `ClickToRunSvc` | `LocalSystem` | `"C:\Program Files\Common Files\Microsoft Shared\ClickToRun\OfficeClickToRun.exe" /service` | False | True | False |  |
| `ClipSVC` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k wsappx -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `cloudidsvc` | `NT AUTHORITY\NetworkService` | `C:\Windows\system32\svchost.exe -k CloudIdServiceGroup -p` | False | True | False |  |
| `CodexSandboxService.OpenAI.Codex` | `LocalSystem` | `C:\Program Files\WindowsApps\OpenAI.Codex_26.1021.3705.0_x64__2p2nqsd0c76g0\app\resources\codex-windows-sandbox-service.exe` | False | True | False |  |
| `ConsentUxUserSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `ConsentUxUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `CoreMessagingRegistrar` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork -p` | False | True | False |  |
| `CorsairLLAService` | `LocalSystem` | `"C:\Program Files\Corsair\CORSAIR iCUE 4 Software\CueLLAccessService.exe"` | False | True | False |  |
| `CorsairService` | `LocalSystem` | `"C:\Program Files\Corsair\CORSAIR iCUE 4 Software\Corsair.Service.exe"` | False | True | False |  |
| `CoworkVMService` | `LocalSystem` | `C:\Program Files\WindowsApps\Claude_1.34493.1.0_x64__pzs8sxrjxfjjc\app\resources\cowork-svc.exe` | False | True | False | TriggerType_20(1f81d131-3e60-4c76-9860-37334e4ffce3) |
| `CredentialEnrollmentManagerUserSvc` | `LocalSystem` | `C:\Windows\system32\CredentialEnrollmentManager.exe` | False | True | False |  |
| `CredentialEnrollmentManagerUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\CredentialEnrollmentManager.exe` | False | True | False |  |
| `DeviceAssociationBrokerSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow -p` | False | True | False |  |
| `DeviceAssociationBrokerSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow -p` | False | True | False |  |
| `DevicePickerUserSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `DevicePickerUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `DevicesFlowUserSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `DevicesFlowUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DevicesFlow` | False | True | False |  |
| `DiscordSystemHelper` | `LocalSystem` | `"C:\Program Files\Common Files\Discord\Discord\DiscordSystemHelper.exe" service` | False | True | False |  |
| `DisplayEnhancementService` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), DeviceArrival(97f115c8-599a-4153-8894-d2d12899918a), DeviceArrival(a7029aac-77dd-4ddd-959b-054f5574f4fb), DeviceArrival(db524086-ba90-4e1e-be42-894e94ecf289) |
| `dmwappushservice` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `Dnscache` | `NT AUTHORITY\NetworkService` | `C:\Windows\system32\svchost.exe -k NetworkService -p` | False | True | False | TriggerType_20(277c9237-51d8-5c1c-b089-f02c683e5ba7) |
| `DoSvc` | `NT Authority\NetworkService` | `C:\Windows\System32\svchost.exe -k NetworkService -p` | False | True | True | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), NetworkEndpoint_RPC_NamedPipe(659fcae6-5bdb-4da9-b1ff-ca2a178d46e0) |
| `DsmSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | False | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `DsSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `EasyAntiCheat` | `LocalSystem` | `"C:\Program Files (x86)\EasyAntiCheat\EasyAntiCheat.exe"` | False | True | False |  |
| `EasyAntiCheat_EOS` | `LocalSystem` | `"C:\Program Files (x86)\EasyAntiCheat_EOS\EasyAntiCheat_EOS.exe"` | False | True | False |  |
| `EFS` | `LocalSystem` | `C:\Windows\System32\lsass.exe` | False | True | True | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `embeddedmode` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | False | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `EntAppSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k appmodel -p` | False | True | False |  |
| `EpicOnlineServices` | `LocalSystem` | `"C:\Program Files (x86)\Epic Games\Epic Online Services\service\EpicOnlineServicesHost.exe"` | False | True | False |  |
| `Fax` | `NT AUTHORITY\NetworkService` | `C:\Windows\system32\fxssvc.exe` | False | True | False |  |
| `fhsvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | True | NetworkEndpoint_RPC_NamedPipe(659fcae6-5bdb-4da9-b1ff-ca2a178d46e0), NetworkEndpoint_RPC_NamedPipe(54fb46c8-f089-464c-b1fd-59d1b62c3b50) |
| `FontCache` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalService -p` | False | True | False |  |
| `FontCache3.0.0.0` | `NT Authority\LocalService` | `C:\Windows\Microsoft.Net\Framework64\v3.0\WPF\PresentationFontCache.exe` | False | True | False |  |
| `HgClientService` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k netsvcs -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `icssvc` | `NT Authority\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `iCUEDevicePluginHost` | `LocalSystem` | `"C:\Program Files\Corsair\CORSAIR iCUE 4 Software\iCUEDevicePluginHost.exe"` | False | True | False |  |
| `KeyIso` | `LocalSystem` | `C:\Windows\system32\lsass.exe` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `KtmRm` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k NetworkServiceAndNoImpersonation -p` | False | True | False | TriggerType_20(ce20d1c3-a247-4c41-bcb8-3c7f52c8b805) |
| `lfsvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), DeviceArrival(3336e5e4-018a-4669-84c5-bd05f3bd368b) |
| `MapsBroker` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k NetworkService -p` | False | True | False |  |
| `MDCoreSvc` | `LocalSystem` | `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MpDefenderCoreService.exe"` | False | True | False |  |
| `MozillaMaintenance` | `LocalSystem` | `"C:\Program Files (x86)\Mozilla Maintenance Service\maintenanceservice.exe"` | False | True | False |  |
| `MSDTC` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\msdtc.exe` | False | True | False |  |
| `msiserver` | `LocalSystem` | `C:\Windows\system32\msiexec.exe /V` | False | True | False |  |
| `NaturalAuthentication` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `NetTcpPortSharing` | `NT AUTHORITY\LocalService` | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe` | False | True | False |  |
| `NlaSvc` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k NetworkService -p` | False | True | False |  |
| `npggsvc` | `LocalSystem` | `C:\Windows\system32\GameMon.des -service` | False | True | False |  |
| `NvContainerLocalSystem` | `LocalSystem` | `"C:\Program Files\NVIDIA Corporation\NvContainer\nvcontainer.exe" -s NvContainerLocalSystem -a -f "C:\ProgramData\NVIDIA Corporation\NVIDIA App\NvContainer\NvContainerLocalSystem.log" -l 3 -d "C:\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem" -r -p 30000  -ert` | False | True | False |  |
| `OneSyncSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `OneSyncSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `OptionsPlusUpdaterService` | `LocalSystem` | `"C:\Program Files\LogiOptionsPlus\logioptionsplus_updater.exe" --run-as-service` | False | True | False |  |
| `OverwolfUpdater` | `LocalSystem` | `"C:\Program Files (x86)\Common Files\Overwolf\OverwolfUpdater.exe" /RunningFrom SCM` | False | True | False |  |
| `p2pimsvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServicePeerNet` | False | True | False |  |
| `p2psvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServicePeerNet` | False | True | False |  |
| `PcaSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | False |  |
| `PeerDistSvc` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k PeerDist` | False | True | False |  |
| `PhoneSvc` | `NT Authority\LocalService` | `C:\Windows\system32\svchost.exe -k LocalService -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `PimIndexMaintenanceSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `PimIndexMaintenanceSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `PNRPAutoReg` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServicePeerNet` | False | True | False |  |
| `PNRPsvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServicePeerNet` | False | True | False |  |
| `PrintWorkflowUserSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k PrintWorkflow` | False | True | False | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `PrintWorkflowUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k PrintWorkflow` | False | True | False | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `RasMan` | `localSystem` | `C:\Windows\System32\svchost.exe -k netsvcs` | False | True | False |  |
| `RmSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted` | False | True | False |  |
| `Rockstar Service` | `LocalSystem` | `"C:\Program Files\Rockstar Games\Launcher\RockstarService.exe"` | False | True | False |  |
| `RpcEptMapper` | `NT AUTHORITY\NetworkService` | `C:\Windows\system32\svchost.exe -k RPCSS -p` | False | True | False |  |
| `seclogon` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | False |  |
| `SecurityHealthService` | `LocalSystem` | `C:\Windows\system32\SecurityHealthService.exe` | False | True | False |  |
| `SEMgrSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalService -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `Sense` | `LocalSystem` | `"C:\Program Files\Windows Defender Advanced Threat Protection\MsSense.exe"` | False | True | False |  |
| `SensorService` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | True | DeviceArrival(c2fb0f5f-e2d2-4c78-bcd0-352a9582819d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `SensrSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p` | False | True | False | DeviceArrival(17a665c0-9063-4216-b202-5c7a255e18ce), DeviceArrival(ca19690f-a2c7-477d-a99e-99ec6e2b5648), DeviceArrival(cd09daf1-3b2e-4c3d-b598-b5e5ff93fd46), DeviceArrival(c2fb0f5f-e2d2-4c78-bcd0-352a9582819d) |
| `smphost` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k smphost` | False | True | False |  |
| `SmsRouter` | `NT Authority\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `sppsvc` | `NT AUTHORITY\NetworkService` | `C:\Windows\system32\sppsvc.exe` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_20(f5528ada-be5f-4f14-8aef-a95de7281161) |
| `SSDPSRV` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p` | False | True | False |  |
| `ssh-agent` | `LocalSystem` | `C:\Windows\System32\OpenSSH\ssh-agent.exe` | False | True | False |  |
| `SstpSvc` | `NT Authority\LocalService` | `C:\Windows\system32\svchost.exe -k LocalService -p` | False | True | False |  |
| `StateRepository` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k appmodel -p` | False | True | False |  |
| `Steam Client Service` | `LocalSystem` | `"C:\Program Files (x86)\Common Files\Steam\steamservice.exe" /RunAsService` | False | True | False |  |
| `SystemEventsBroker` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DcomLaunch -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `TabletInputService` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | True | False | DeviceArrival(4d1e55b2-f16f-11cf-88cb-001111000030) |
| `TapiSrv` | `NT AUTHORITY\NetworkService` | `C:\Windows\System32\svchost.exe -k NetworkService -p` | False | True | False |  |
| `TimeBrokerSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `UdkUserSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UdkSvcGroup` | False | True | False |  |
| `UdkUserSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UdkSvcGroup` | False | True | False |  |
| `UevAgentService` | `LocalSystem` | `C:\Windows\system32\AgentService.exe` | False | True | False |  |
| `UnistoreSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `UnistoreSvc_12c276` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `upnphost` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation -p` | False | True | False |  |
| `UserDataSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `UserDataSvc_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `UsoSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | False |  |
| `VaultSvc` | `LocalSystem` | `C:\Windows\system32\lsass.exe` | False | True | False |  |
| `vgc` | `LocalSystem` | `C:\Program Files\Riot Vanguard\vgc.exe` | False | True | False |  |
| `VSInstallerElevationService` | `LocalSystem` | `"C:\Program Files (x86)\Microsoft Visual Studio\Installer\VSInstallerElevationService.exe"` | False | True | False |  |
| `WaaSMedicSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k wusvcs -p` | False | True | False |  |
| `WbioSrvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k WbioSvcGroup` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `wcncsvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServiceAndNoImpersonation -p` | False | True | False |  |
| `WdNisSvc` | `NT AUTHORITY\LocalService` | `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\NisSrv.exe"` | False | True | False |  |
| `WinDefend` | `LocalSystem` | `"C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26100.4-0\MsMpEng.exe"` | False | True | False |  |
| `WinHttpAutoProxySvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | True | False |  |
| `wlidsvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `WMPNetworkSvc` | `NT AUTHORITY\NetworkService` | `"C:\Program Files\Windows Media Player\wmpnetwk.exe"` | False | True | False |  |
| `WpnUserService` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `WpnUserService_12c276` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k UnistackSvcGroup` | False | True | False |  |
| `wscsvc` | `NT AUTHORITY\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | True | False |  |
| `WslInstaller` | `LocalSystem` | `C:\Program Files\WindowsApps\MicrosoftCorporationII.WindowsSubsystemForLinux_2.2.4.0_x64__8wekyb3d8bbwe\wslinstaller.exe` | False | True | False |  |
| `wuauserv` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | True | True | NetworkEndpoint_RPC_NamedPipe(659fcae6-5bdb-4da9-b1ff-ca2a178d46e0), NetworkEndpoint_RPC_NamedPipe(54fb46c8-f089-464c-b1fd-59d1b62c3b50) |
| `AJRouter` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | False | True | ETW(1f81d131-3fac-4537-9e0c-7e7b0c2f4b55) |
| `bthserv` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalService -p` | False | False | True | DeviceArrival(0850302a-b344-4fda-9be9-90576b8d46f0), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `dcsvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `DeviceAssociationService` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `DeviceInstall` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k DcomLaunch -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `DevQueryBroker` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `diagsvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k diagnostics` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `FrameServer` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k Camera` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), DeviceArrival(e5323777-f976-4f5b-9b55-b94699c46e44), DeviceArrival(24e552d7-6523-47f7-a647-d3465bf1f5ca) |
| `gpsvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `hns` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k NetSvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `IpxlatCfgSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `LanmanServer` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(1f81d131-3fac-4537-9e0c-7e7b0c2f4b55) |
| `LicenseManager` | `NT Authority\LocalService` | `C:\Windows\System32\svchost.exe -k LocalService -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `NcaSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k NetSvcs -p` | False | False | True | NetworkEndpoint_RPC_NamedPipe(659fcae6-5bdb-4da9-b1ff-ca2a178d46e0), FirewallPort(1ce20aba-9851-4421-9430-1ddeb766e809), FirewallPort(ddaf516e-58c2-4866-9574-c3b615d42ea1) |
| `NcbService` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `NetSetupSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k netsvcs -p` | False | False | True | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `NgcCtnrSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `NgcSvc` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), DeviceArrival(00f40965-e89d-4487-9890-87c3abb211f4) |
| `RemoteRegistry` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k localService -p` | False | False | True | ETW(1f81d131-3fac-4537-9e0c-7e7b0c2f4b55) |
| `SCardSvr` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation` | False | False | True | DeviceArrival(50dd5230-ba8a-11d1-bf5d-0000f805f530), DeviceArrival(121d8161-866d-4a24-ba58-9058940c0d47), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `ScDeviceEnum` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted` | False | False | True | TriggerType_20(aedd909f-41c6-401a-9e41-dfc33006af5d), TriggerType_20(0621b9df-3249-4559-9889-21f76b5c80f3), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `SensorDataService` | `LocalSystem` | `C:\Windows\System32\SensorDataService.exe` | False | False | True | ETW(1f81d131-3fac-4537-9e0c-7e7b0c2f4b55) |
| `SharedAccess` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `spectrum` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\spectrum.exe` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `StorSvc` | `LocalSystem` | `C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p` | False | False | True | DeviceArrival(4f40006f-b933-4550-b532-2b58cee614d3), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `UserManager` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `vmcompute` | `LocalSystem` | `C:\Windows\system32\vmcompute.exe` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `WarpJITSvc` | `NT Authority\LocalService` | `C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `WEPHOSTSVC` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k WepHostSvcGroup` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `WFDSConMgrSvc` | `NT AUTHORITY\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `wlpasvc` | `NT Authority\LocalService` | `C:\Windows\system32\svchost.exe -k LocalServiceNetworkRestricted -p` | False | False | True | TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |
| `WPDBusEnum` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k LocalSystemNetworkRestricted` | False | False | True | DeviceArrival(53f56307-b6bf-11d0-94f2-00a0c91efb8b), DeviceArrival(c1e9bc6d-1dae-421a-9369-cc7ff0d6e359), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), DeviceArrival(6ac27878-a6fa-4155-ba85-f98f491d4f33), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), NetworkEndpoint_RPC_NamedPipe(659fcae6-5bdb-4da9-b1ff-ca2a178d46e0), NetworkEndpoint_RPC_NamedPipe(54fb46c8-f089-464c-b1fd-59d1b62c3b50), TriggerType_20(199fe037-2b82-40a9-82ac-e1d46c792b99), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9), TriggerType_7(2d7a2816-0c5e-45fc-9ce7-570e5ecde9c9) |
| `XblGameSave` | `LocalSystem` | `C:\Windows\system32\svchost.exe -k netsvcs -p` | False | False | True | ETW(bc90d167-9470-4139-a9ba-be0bbbf5b74d) |

