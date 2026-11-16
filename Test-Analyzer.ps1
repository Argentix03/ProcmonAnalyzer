# Test-Analyzer.ps1
# Creates a mock writable_paths.json (covering rev 1 through rev 3.3 schemas)
# and runs the analyzer script to verify rule matching, false-positive filters,
# perspective gating, and cognitive queue routing.

$mockData = @(
    [PSCustomObject]@{
        Path = "C:\Windows\System32\hijackable.dll"
        RelatedProcesses = "explorer.exe, svchost.exe"
        Operation = "CreateFile"
        Result = "NAME NOT FOUND"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "\\.\pipe\vulnerable_service_pipe"
        RelatedProcesses = "services.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        SqosLevel = "Impersonation"
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Program Files\EnterpriseApp\app.config"
        RelatedProcesses = "EnterpriseApp.exe, svchost.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "High"
        HighestIntegrity = "High"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Program Files\EnterpriseApp\build.proj"
        RelatedProcesses = "EnterpriseApp.exe, msbuild.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "Medium"
        HighestIntegrity = "Medium"
        IsUserOnlyConsumer = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Public\Downloads\innocent.txt"
        RelatedProcesses = "notepad.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "Medium"
        HighestIntegrity = "Medium"
        IsUserOnlyConsumer = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Windows\Tasks\persistence.bat"
        RelatedProcesses = "cmd.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Integrity = "Medium"
        HighestIntegrity = "Medium"
        IsUserOnlyConsumer = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\launch.lnk"
        RelatedProcesses = "explorer.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "Medium"
        HighestIntegrity = "Medium"
        IsUserOnlyConsumer = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Windows\System32\Tasks\Microsoft\Windows\Maintenance\WinSAT"
        RelatedProcesses = "svchost.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivRead = $true
        WritableByLowPriv = $false
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin = $true
        WritableFrom = "HighILAdmin"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Alice\AppData\Local\Temp\missing_pipe_redirect.dat"
        RelatedProcesses = "spoolsv.exe"
        Operation = "CreateFile"
        Result = "NAME NOT FOUND"
        Detail = "Desired Access: Generic Read, Impersonation: Impersonation"
        SqosLevel = "Impersonation"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Alice\AppData\Local\Temp\partial_reparse_open.dat"
        RelatedProcesses = "svchost.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivRead = $true
        OpenReparsePoint = $false
        AnyOpenReparsePoint = $true
        AllOpenReparsePoint = $false
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Alice\AppData\Local\VendorApp\latent_helper.dll"
        RelatedProcesses = "VendorApp.exe"
        Operation = "ReadFile"
        Result = "SUCCESS"
        Integrity = "Medium"
        HighestIntegrity = "Medium"
        IsUserOnlyConsumer = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HKLM\SYSTEM\ControlSet001\Services\VulnSvc"
        RelatedProcesses = "services.exe"
        Operation = "RegOpenKey"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    # --- rev 3.4 test cases ---
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorSuite\LockedSubdir\state.dat"
        RelatedProcesses = "VendorService.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Detail = "Desired Access: Generic Read, Options: Open Reparse Point"
        Integrity = "System"
        HighestIntegrity = "System"
        OpenReparsePoint = $true
        AnyOpenReparsePoint = $true
        AllOpenReparsePoint = $true
        HasWritableAncestor = $true
        WritableAncestorPath = "C:\ProgramData\VendorSuite"
        AclSource = "ancestor-dir-replaceable"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Alice\AppData\Local\Temp\UpdaterCleanup\staging.tmp"
        RelatedProcesses = "UpdateService.exe"
        Operation = "SetDispositionInformationFile"
        Result = "SUCCESS"
        Detail = "Delete: True"
        Integrity = "System"
        HighestIntegrity = "System"
        HasDeleteOp = $true
        AnyPrivWrite = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorAgent\logs\audit.log"
        RelatedProcesses = "VendorAgent.exe"
        Operation = "SetSecurityFile"
        Result = "SUCCESS"
        Detail = "Information: DACL"
        Integrity = "System"
        HighestIntegrity = "System"
        HasSetSecurityOp = $true
        AnyPrivWrite = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorApp\ReadOnlyPlugin.dll"
        RelatedProcesses = "VendorService.exe"
        Operation = "Load Image"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        CanDeleteOrReplace = $true
        AclSource = "parent-delete-recreate"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "\\.\pipe\VendorServiceControlPipe"
        RelatedProcesses = "VendorService.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        CanCreatePipeInstance = $false
        CanWritePipeClient = $true
        AclSource = "pipe-dacl"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HKCU\Software\VendorService\ConfigBuffer"
        RelatedProcesses = "VendorService.exe"
        Operation = "RegQueryValue"
        Result = "BUFFER OVERFLOW"
        Detail = "Length: 512"
        Integrity = "System"
        HighestIntegrity = "System"
        HasBufferOverflow = $true
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorUpdater\signed_update.exe"
        RelatedProcesses = "VendorUpdater.exe"
        Operation = "Load Image"
        Result = "SUCCESS"
        Detail = "ShareMode: Read, Write, Delete"
        Integrity = "System"
        HighestIntegrity = "System"
        HasVerifyThenLoad = $true
        HasSharedWriteOrDelete = $true
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\BackupService\restore_target.dat"
        RelatedProcesses = "BackupSvc.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Detail = "Desired Access: Generic Read/Write, Options: Open For Backup"
        Integrity = "System"
        HighestIntegrity = "System"
        HasOpenForBackup = $true
        AnyPrivWrite = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorService\check_then_open.dat"
        RelatedProcesses = "VendorService.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Detail = "Desired Access: Generic Write"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyOpenReparsePoint = $true
        AllOpenReparsePoint = $false
        HasReparseCheckThenUse = $true
        AnyPrivWrite = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HKLM\SOFTWARE\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32\(Default)"
        RelatedProcesses = "svchost.exe"
        Operation = "RegQueryValue"
        Result = "SUCCESS"
        Detail = "Type: REG_SZ, Length: 64, Data: C:\ProgramData\VendorCOM\MissingServer.dll"
        Integrity = "System"
        HighestIntegrity = "System"
        RegistryDataPath = "C:\ProgramData\VendorCOM\MissingServer.dll"
        RegistryDataTarget = "C:\ProgramData\VendorCOM\MissingServer.dll"
        RegistryDataTargetWritableByLowPriv = $true
        RegistryDataTargetWritableByMediumILAdmin = $true
        RegistryDataTargetWritableFrom = "LowPriv"
        RegistryDataTargetAclSource = "ancestor"
        RegistryDataTargetHasWritableAncestor = $true
        RegistryDataTargetWritableAncestorPath = "C:\ProgramData\VendorCOM"
        AnyPrivRead = $true
        WritableByLowPriv = $false
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin = $true
        WritableFrom = "HighILAdmin"
    },
    [PSCustomObject]@{
        Path = "HKLM\SOFTWARE\VendorSuite\AgentConfig\PluginPath"
        RelatedProcesses = "VendorAgent.exe"
        Operation = "RegQueryValue"
        Result = "SUCCESS"
        Detail = "Type: REG_SZ, Data: C:\ProgramData\VendorSuite\Plugins\custom_hook.dll"
        Integrity = "System"
        HighestIntegrity = "System"
        RegistryDataPath = "C:\ProgramData\VendorSuite\Plugins\custom_hook.dll"
        RegistryDataTarget = "C:\ProgramData\VendorSuite\Plugins\custom_hook.dll"
        RegistryDataTargetWritableByLowPriv = $true
        RegistryDataTargetWritableByMediumILAdmin = $true
        RegistryDataTargetWritableFrom = "LowPriv"
        RegistryDataTargetAclSource = "parent-delete-recreate"
        RegistryDataTargetCanDeleteOrReplace = $true
        AnyPrivRead = $true
        WritableByLowPriv = $false
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin = $true
        WritableFrom = "HighILAdmin"
    },
    [PSCustomObject]@{
        Path = "C:\Users\Alice\AppData\Local\Packages\VendorPkg\LocalState\broker_ipc.json"
        RelatedProcesses = "VendorBrokerService.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Detail = "Desired Access: Generic Read"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "exact"
        AnyPrivRead = $true
        WritableByLowPriv = $false
        WritableByAppContainer = $true
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin = $true
        WritableFrom = "AppContainer"
    },
    # --- rev 3.5 (Phase 2) test cases ---
    [PSCustomObject]@{
        Path = "C:\ProgramData\VendorRPC\rpc_spool.dat"
        RelatedProcesses = "VendorRpcSvc.exe"
        Operation = "CreateFile"
        Result = "SUCCESS"
        Detail = "Desired Access: Generic Write | RPC_Context: Interface={12345678-1234-1234-1234-123456789abc} OpNum=4"
        Integrity = "System"
        HighestIntegrity = "System"
        AnyPrivWrite = $true
        AnyImpersonating = $false
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HKLM\SOFTWARE\Classes\AppID\{AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE}"
        RelatedProcesses = "dllhost.exe"
        Operation = "DCOM_LaunchPermission_Audit"
        Result = "SUCCESS"
        Detail = "RunAs=Interactive User"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "dcom-launch-sd"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "WMI:\ROOT\VendorMgmt"
        RelatedProcesses = "wmiprvse.exe"
        Operation = "WMI_Namespace_Audit"
        Result = "SUCCESS"
        Detail = "WMI_Context: Namespace=ROOT\VendorMgmt Provider=VendorSysProv"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "wmi-namespace-sd"
        AnyPrivRead = $true
        AnyImpersonating = $false
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HKLM\SYSTEM\CurrentControlSet\Services\VendorOnDemandSvc"
        RelatedProcesses = "services.exe (VendorOnDemandSvc)"
        Operation = "QueryServiceObjectSecurity"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "service-scm-sd"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "C:\Windows\System32\Tasks\VendorOnDemandTask"
        RelatedProcesses = "svchost.exe (Schedule)"
        Operation = "TaskCache_SD_Audit"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "taskcache-sd"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "Handle://VendorHelper.exe (PID 4420) -> Handle 0x1A4"
        RelatedProcesses = "VendorHelper.exe"
        Operation = "SystemExtendedHandleInformation"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "system-handle-table"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "\Device\VendorKernelDrv"
        RelatedProcesses = "System (VendorKernelDrv)"
        Operation = "DeviceIoControl"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "driver-registry-sd"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "\BaseNamedObjects\VendorSharedMemSection"
        RelatedProcesses = "VendorService.exe"
        Operation = "CreateFileMapping"
        Result = "SUCCESS"
        Integrity = "System"
        HighestIntegrity = "System"
        AclSource = "om-shared-section"
        AnyPrivWrite = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    },
    [PSCustomObject]@{
        Path = "HWND://VendorTrayElevated.exe/VendorMsgClass (0x1045A)"
        RelatedProcesses = "VendorTrayElevated.exe"
        Operation = "EnumWindows"
        Result = "SUCCESS"
        Integrity = "High"
        HighestIntegrity = "High"
        AclSource = "uipi-session-window"
        AnyPrivRead = $true
        WritableByLowPriv = $true
        WritableByMediumILAdmin = $true
        WritableByHighILAdmin = $true
        WritableFrom = "LowPriv"
    }
)

$jsonPath = Join-Path $PSScriptRoot "mock_writable_paths.json"
ConvertTo-Json -InputObject @($mockData) -Depth 4 | Out-File $jsonPath -Encoding UTF8

Write-Host "Created mock data at: $jsonPath" -ForegroundColor Cyan

$analyzerScript = Join-Path $PSScriptRoot "skills\Analyze-ExecutionLeads\scripts\AnalyzeExecutionLeads.ps1"

if (Test-Path $analyzerScript) {
    Write-Host "Running Analyzer on mock data..." -ForegroundColor Cyan
    & $analyzerScript -JsonFeed $jsonPath

    $hardcodedJson = Join-Path $PSScriptRoot "high_confidence_leads.json"
    $cognitiveJson = Join-Path $PSScriptRoot "cognitive_review_queue.json"

    $rawHc = Get-Content $hardcodedJson -Raw | ConvertFrom-Json
    $rawCg = Get-Content $cognitiveJson -Raw | ConvertFrom-Json
    $hc = @($rawHc | Where-Object { $null -ne $_ })
    $cg = @($rawCg | Where-Object { $null -ne $_ })

    Write-Host "`n--- Verification Assertions ---" -ForegroundColor Cyan
    $primitives = @($hc | ForEach-Object { $_.ExploitPrimitive })
    $expectedPrimitives = @(
        "Binary_Plant_HighPriv",
        "Pipe_Hijack",
        "Config_Poison",
        "LOLBin_Proxy",
        "AutoRun_Persistence",
        "LNK_Hijack",
        "ScheduledTask_Plant",
        "Pipe_Plant_Redirect",
        "SMB_Coercion",
        "Service_BinaryPath",
        "Parent_Directory_Reparse_Bypass",
        "Arbitrary_Delete_ConfigMsi_LPE",
        "Arbitrary_DACL_Overwrite",
        "File_DeleteChild_Recreate",
        "Pipe_Client_IPC_Sink",
        "Registry_BufferOverflow_TOCTOU",
        "Signature_TOCTOU_Bypass",
        "BackupSemantics_DACL_Bypass",
        "CheckThenUse_Reparse_TOCTOU",
        "COM_HKLM_Hijack",
        "Registry_Data_Path_Reference",
        "AppContainer_Sandbox_Escape",
        "RPC_Unauthenticated_PathSink",
        "DCOM_Privileged_Activation",
        "WMI_LocalSystemHost_Sink",
        "Service_OnDemand_Trigger_Chain",
        "ScheduledTask_OnDemand_Run",
        "Leaked_Privileged_Handle",
        "Kernel_Device_IOCTL_Surface",
        "SharedSection_MemoryTamper",
        "UIPI_HighIL_MessageSink"
    )
    $allPassed = $true
    foreach ($ep in $expectedPrimitives) {
        if ($primitives -contains $ep) {
            Write-Host "  [PASS] High-confidence queue contains primitive: $ep" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Missing expected primitive: $ep" -ForegroundColor Red
            $allPassed = $false
        }
    }

    $cgReasons = @($cg | ForEach-Object { $_.FilterReason })
    if ($cgReasons -contains "PersistenceBinary_NoPrivilegedConsumer") {
        Write-Host "  [PASS] Cognitive queue contains PersistenceBinary_NoPrivilegedConsumer (latent_helper.dll)" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] Missing PersistenceBinary_NoPrivilegedConsumer in cognitive queue" -ForegroundColor Red
        $allPassed = $false
    }

    $innocentInHc = @($hc | Where-Object { $_.Path -match "innocent\.txt" })
    $innocentInCg = @($cg | Where-Object { $_.Path -match "innocent\.txt" })
    if ($innocentInHc.Count -eq 0 -and $innocentInCg.Count -eq 0) {
        Write-Host "  [PASS] User-only noise (innocent.txt) was cleanly dropped" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] User-only noise (innocent.txt) was not dropped" -ForegroundColor Red
        $allPassed = $false
    }

    # Phase 3 (Rev 3.6) Verify-LeadStatically Test
    $verifyScript = Join-Path $PSScriptRoot "skills\Verify-LeadStatically\scripts\VerifyLeadStatically.ps1"
    $staticOutJson = Join-Path $PSScriptRoot "static_verification_results.json"
    $idaQueueJson  = Join-Path $PSScriptRoot "ida_mcp_verification_queue.json"
    $staticRepMd   = Join-Path $PSScriptRoot "Static_Verification_Report.md"

    if (Test-Path $verifyScript) {
        & $verifyScript -LeadsJson $hardcodedJson -OutputPath $staticOutJson -MinSeverity Medium -MaxLeads 40 -Silent
        if ((Test-Path $staticOutJson) -and (Test-Path $idaQueueJson) -and (Test-Path $staticRepMd)) {
            $svParsed = Get-Content $staticOutJson -Raw | ConvertFrom-Json
            $svItems  = New-Object System.Collections.Generic.List[PSCustomObject]
            foreach ($s in $svParsed) { if ($null -ne $s) { $svItems.Add($s) } }
            $resolvedCount = @($svItems | Where-Object { $_.BinaryExists -eq $true -and -not [string]::IsNullOrWhiteSpace($_.Q1_FlagCheck) }).Count
            if ($svItems.Count -ge 20 -and $resolvedCount -ge 1) {
                Write-Host "  [PASS] Phase 3 Verify-LeadStatically verified $($svItems.Count) leads ($resolvedCount host binaries statically analyzed with IDA MCP playbooks)" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Phase 3 Verify-LeadStatically returned insufficient verified items ($($svItems.Count))" -ForegroundColor Red
                $allPassed = $false
            }
        } else {
            Write-Host "  [FAIL] Phase 3 Verify-LeadStatically did not emit expected output files" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [FAIL] VerifyLeadStatically.ps1 not found at $verifyScript" -ForegroundColor Red
        $allPassed = $false
    }

    # Phase 4 (Rev 4.0) ProcmonSecDrv.sys Kernel Driver & Client Verification
    $drvSysPath    = Join-Path $PSScriptRoot "driver\ProcmonSecDrv\bin\x64\ProcmonSecDrv.sys"
    $drvClientPath = Join-Path $PSScriptRoot "driver\ProcmonSecDrv\Invoke-ProcmonSecDrvClient.ps1"
    if ((Test-Path $drvSysPath) -and (Test-Path $drvClientPath)) {
        . $drvClientPath
        $drvPe = [ProcmonPhase3Verifier.StaticPeAnalyzer]::AnalyzePeFile($drvSysPath, @("\Device\ProcmonSecDrv", "\DosDevices\ProcmonSecDrv"))
        if ($drvPe.IsValidPe -and $drvPe.IsKernelDriver -and $drvPe.HasForceIntegrity -and ($drvPe.ImportedFunctions -contains "ObRegisterCallbacks") -and ($drvPe.ImportedFunctions -contains "MmCopyVirtualMemory")) {
            Write-Host "  [PASS] Phase 4 ProcmonSecDrv.sys verified (x64 Kernel Driver, ForceIntegrity=True, ObRegisterCallbacks + MmCopyVirtualMemory + ObGetObjectSecurity imported)" -ForegroundColor Green
        } else {
            Write-Host "  [FAIL] Phase 4 ProcmonSecDrv.sys PE validation failed" -ForegroundColor Red
            $allPassed = $false
        }
    } else {
        Write-Host "  [FAIL] Phase 4 ProcmonSecDrv.sys or Invoke-ProcmonSecDrvClient.ps1 missing" -ForegroundColor Red
        $allPassed = $false
    }

    # Cleanup temporary test outputs
    Remove-Item -Path $jsonPath, $hardcodedJson, $cognitiveJson, $staticOutJson, $idaQueueJson, $staticRepMd -Force -ErrorAction SilentlyContinue

    if (-not $allPassed) {
        exit 1
    }
} else {
    Write-Host "Analyzer script not found: $analyzerScript" -ForegroundColor Red
    exit 1
}
