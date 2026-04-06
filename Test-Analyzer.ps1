# Test-Analyzer.ps1
# Creates a mock writable_paths.json and runs the analyzer script to verify logic.

$mockData = @(
    [PSCustomObject]@{
        Path = "C:\Windows\System32\hijackable.dll"
        RelatedProcesses = "explorer.exe, svchost.exe"
        FileExists = $false
    },
    [PSCustomObject]@{
        Path = "\\.\pipe\vulnerable_service_pipe"
        RelatedProcesses = "services.exe"
        FileExists = $true
    },
    [PSCustomObject]@{
        Path = "C:\Program Files\EnterpriseApp\settings.xml"
        RelatedProcesses = "EnterpriseApp.exe, msbuild.exe"
        FileExists = $true
    },
    [PSCustomObject]@{
        Path = "C:\Users\Public\Downloads\innocent.txt"
        RelatedProcesses = "notepad.exe"
        FileExists = $true
    },
    [PSCustomObject]@{
        Path = "C:\Windows\Tasks\persistence.bat"
        RelatedProcesses = "cmd.exe"
        FileExists = $true
    },
    [PSCustomObject]@{
        Path = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\launch.lnk"
        RelatedProcesses = "explorer.exe"
        FileExists = $true
    }
)

$jsonPath = Join-Path $PSScriptRoot "mock_writable_paths.json"
$mockData | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding UTF8

Write-Host "Created mock data at: $jsonPath" -ForegroundColor Cyan

$analyzerScript = Join-Path $PSScriptRoot "skills\Analyze-ExecutionLeads\scripts\AnalyzeExecutionLeads.ps1"

if (Test-Path $analyzerScript) {
    Write-Host "Running Analyzer on mock data..." -ForegroundColor Cyan
    & $analyzerScript -JsonFeed $jsonPath

    $hardcodedJson = Join-Path $PSScriptRoot "high_confidence_leads.json"
    $cognitiveJson = Join-Path $PSScriptRoot "cognitive_review_queue.json"

    if (Test-Path $hardcodedJson) {
        Write-Host "`n--- Generated High Confidence JSON ---" -ForegroundColor Yellow
        Get-Content $hardcodedJson | Select-Object -First 20
        Write-Host "..." -ForegroundColor DarkGray
    }

    if (Test-Path $cognitiveJson) {
        Write-Host "`n--- Generated Cognitive Review Queue JSON ---" -ForegroundColor Yellow
        Get-Content $cognitiveJson | Select-Object -First 20
        Write-Host "..." -ForegroundColor DarkGray
    }
} else {
    Write-Host "Analyzer script not found: $analyzerScript" -ForegroundColor Red
}
