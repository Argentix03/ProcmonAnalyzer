# Configuration
#$ProcMonPath = "C:\Tools\Procmon.exe"
#$PmlPath = "C:\Logs\trace.pml"
$CsvPath = "C:\Users\Argentix\Downloads\BootLogProcMonAllHighPrivFiles.CSV"

#if (!(Test-Path $CsvPath)) {
#    Write-Host "Converting PML to CSV (this may take time)..." -ForegroundColor Cyan
#    Start-Process -FilePath $ProcMonPath -ArgumentList "/OpenLog `"$PmlPath`" /SaveAs `"$CsvPath`" /Quiet" -Wait
#}

Write-Host "Streaming CSV to extract paths and mapping to processes..." -ForegroundColor Cyan

# Dictionary: Key = Path (String), Value = Unique Process Names (HashSet)
$pathProcessMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]' ([System.StringComparer]::OrdinalIgnoreCase)

$reader = [System.IO.File]::OpenText($CsvPath)
$header = $reader.ReadLine()

# Regexes designed for the default ProcMon CSV layout
$pathRegex = ',"([a-zA-Z]:\\[^"]+)"'
$procRegex = '^"[^"]*","([^"]+)"' # Grabs the 2nd column (Process Name)

while ($line = $reader.ReadLine()) {
    $pathMatch = [regex]::Match($line, $pathRegex)
    if ($pathMatch.Success) {
        $path = $pathMatch.Groups[1].Value
        
        # Grab Process Name
        $procMatch = [regex]::Match($line, $procRegex)
        $processName = if ($procMatch.Success) { $procMatch.Groups[1].Value } else { "Unknown" }

        # Add Path to Dictionary if it doesn't exist
        if (-not $pathProcessMap.ContainsKey($path)) {
            $pathProcessMap[$path] = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
        }
        
        # Add Process Name to that Path's Set
        [void]$pathProcessMap[$path].Add($processName)
    }
}
$reader.Close()

$uniquePaths = [string[]]$pathProcessMap.Keys
$totalCount = $uniquePaths.Count
Write-Host "Found $totalCount unique paths. Starting safe permission tests..." -ForegroundColor Cyan

# 3. 100% SAFE Testing Function (No data destruction)
function Test-SafeWritePermission {
    param([string]$TargetPath)

    try {
        if ([System.IO.Directory]::Exists($TargetPath)) {
            $testFile = [System.IO.Path]::Combine($TargetPath, "$([guid]::NewGuid()).tmp")
            [System.IO.File]::Create($testFile, 1, [System.IO.FileOptions]::DeleteOnClose).Close()
            return $true
        }

        if ([System.IO.File]::Exists($TargetPath)) {
            $fs = [System.IO.File]::Open($TargetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
            $fs.Close()
            return $true
        }

        $parent = [System.IO.Path]::GetDirectoryName($TargetPath)
        while (-not [string]::IsNullOrWhiteSpace($parent) -and -not [System.IO.Directory]::Exists($parent)) {
            $parent = [System.IO.Path]::GetDirectoryName($parent)
        }

        if ([System.IO.Directory]::Exists($parent)) {
            $testDir = [System.IO.Path]::Combine($parent, "$([guid]::NewGuid())")
            [System.IO.Directory]::CreateDirectory($testDir) | Out-Null
            [System.IO.Directory]::Delete($testDir)
            return $true
        }

        return $false
    } catch {
        return $false
    }
}

# 4. Execution
$counter = 0
$results = New-Object System.Collections.Generic.List[PSCustomObject]

foreach ($path in $uniquePaths) {
    $counter++
    if ($counter % 50 -eq 0) { 
        Write-Progress -Activity "Testing Permissions" -Status "Path: $path" -PercentComplete (($counter / $totalCount) * 100)
    }

    if (Test-SafeWritePermission -TargetPath $path) {
        
        # Join the process names together separated by commas
        $relatedProcesses = $pathProcessMap[$path] -join ", "

        $results.Add([PSCustomObject]@{
            Path             = $path
            FileExists    = ([System.IO.Directory]::Exists($path) -or [System.IO.File]::Exists($path))
            RelatedProcesses = $relatedProcesses
        })
    }
}
Write-Progress -Activity "Testing Permissions" -Completed

# 5. Results
Write-Host "Process Complete. $( $results.Count ) writable paths found." -ForegroundColor Green
$results | Out-GridView -Title "Writable Paths and Associated Processes"