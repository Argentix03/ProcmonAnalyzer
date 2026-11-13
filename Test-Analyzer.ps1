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
        "Service_BinaryPath"
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

    # Cleanup temporary test outputs
    Remove-Item -Path $jsonPath, $hardcodedJson, $cognitiveJson -Force -ErrorAction SilentlyContinue

    if (-not $allPassed) {
        exit 1
    }
} else {
    Write-Host "Analyzer script not found: $analyzerScript" -ForegroundColor Red
    exit 1
}
