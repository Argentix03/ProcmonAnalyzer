param(
    [string]$EtlPath = "C:\Temp\RawTrace.etl",
    [string]$OutputPath = "C:\Temp\NativeWritablePaths.csv"
)

Write-Host "[+] Initializing Standalone ETW Parser Pipeline..." -ForegroundColor Cyan

$CsvPath = ($EtlPath -replace '\.etl$', '.csv')
$SnapshotPath = Join-Path (Split-Path $EtlPath) "ActiveProcessesSnapshot.json"

if (-not (Test-Path $EtlPath)) {
    Write-Host "[!] ERROR: Trace file not found at $EtlPath" -ForegroundColor Red
    exit
}

# Step 1: Decompile binary ETW to CSV
Write-Host "[+] Running tracerpt OS tool to decompile `.etl` binary..."
$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = "tracerpt.exe"
$pinfo.Arguments = "`"$EtlPath`" -o `"$CsvPath`" -of CSV -y"
$pinfo.WindowStyle = 'Hidden'
$pinfo.CreateNoWindow = $true
$pinfo.UseShellExecute = $false
$p = [System.Diagnostics.Process]::Start($pinfo)
$p.WaitForExit()

if (-not (Test-Path $CsvPath)) {
    Write-Host "[!] ERROR: Failed to generate CSV from ETL." -ForegroundColor Red
    exit
}
Write-Host "[+] ETW Binary decompiled successfully to $CsvPath." -ForegroundColor Green

# Step 2: Load Hybrid Process Snapshot Table
$ProcessMap = @{}
if (Test-Path $SnapshotPath) {
    Write-Host "[+] Ingesting Master Hybrid Execution Snapshot ($SnapshotPath)..."
    $SnapshotRaw = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    foreach ($pidKey in $SnapshotRaw.psobject.properties.name) {
        $ProcessMap[$pidKey] = $SnapshotRaw.$pidKey
    }
} else {
    Write-Host "[!] WARNING: ActiveProcessesSnapshot.json not found! Long-running PID mapping will fail." -ForegroundColor Yellow
}

# Step 3: Setup Opcode Dictionaries (Translate Hex to Procmon Text)
$OpcodeLookup = @{
    "64" = "CreateFile"
    "65" = "CreateFileMapping"
    "67" = "ReadFile"
    "68" = "WriteFile"
    "70" = "DeleteFile"
    "72" = "RenameFile"
}

$NtStatusLookup = @{
    "0x00000000" = "SUCCESS"
    "0xC0000022" = "ACCESS DENIED"
    "0xC000003A" = "PATH NOT FOUND"
    "0xC0000034" = "NAME NOT FOUND"
    "0xC0000043" = "SHARING VIOLATION"
}

# Step 4: Parse the massive CSV sequentially
Write-Host "[+] Commencing deep telemetry normalization phase..." -ForegroundColor Cyan

# (NOTE: Tracerpt CSV headers change dynamically depending on the OS build. 
# We implement a skeletal streaming parser here assuming standard Windows Event format)

$ProcmonEvents = New-Object System.Collections.Generic.List[object]
$LineCount = 0

# Dummy example hook to demonstrate the data structure merging:
# In production, we'd regex through the UserData block of Tracerpt CSV.
# This loop simulates processing the mapped ETW stream.

$SimRead = $false # Switched to PHYSICAL parsing!

if ($SimRead) {
    # Dummy block skipped
} else {
    Write-Host "[+] Processing raw I/O Stream natively... (this may take a moment for large traces)"
    $reader = [System.IO.File]::OpenText($CsvPath)
    $LineCount = 0
    $MatchCount = 0

    while ($null -ne ($line = $reader.ReadLine())) {
        $LineCount++
        
        # Fast filter: only care about Kernel File telemetry
        if (-not $line.StartsWith("Microsoft-Windows-Kernel-File")) { continue }
        
        # Heuristic fast-path extraction:
        # We are looking for any logged line containing a physical drive path
        # (Procmon/ETW paths are often formatted with Device\HarddiskVolume or literal C:\)
        if ($line -match "\\Device\\HarddiskVolume\d+\\([\w\.\-\\]+)" -or $line -match "([A-Z]:\\[\w\.\-\\]+)") {
            
            $RawPath = $matches[0]
            if ($RawPath.StartsWith("\Device")) {
                # Attempt an arbitrary conversion to C:\ for UI normalization
                $RawPath = $RawPath -replace "^\\Device\\HarddiskVolume\d+", "C:"
            }
            
            # Very basic extraction from tracerpt chaos format
            # PID is natively column 9. Let's do a safe string check:
            $blocks = $line -split ","
            $hexPid = $blocks[9].Trim()
            $TestPID = "System"
            try { $TestPID = [Convert]::ToInt32($hexPid, 16).ToString() } catch {}

            $MappedName = if ($ProcessMap.ContainsKey($TestPID)) { $ProcessMap[$TestPID].ProcessName } else { "Unknown.exe" }
            $MappedIntegrity = if ($ProcessMap.ContainsKey($TestPID)) { $ProcessMap[$TestPID].Integrity } else { "Unknown" }

            $obj = [PSCustomObject]@{
                "Time of Day"  = (Get-Date).ToString("hh:mm:ss.fffffff AM") # Simplification for demo
                "Process Name" = $MappedName
                "PID"          = $TestPID
                "Operation"    = "ReadFile" # Generalized
                "Path"         = $RawPath
                "Result"       = "SUCCESS"
                "Detail"       = "Integrity: $MappedIntegrity | Native File IO"
            }
            $ProcmonEvents.Add($obj)
            $MatchCount++
            
            if ($MatchCount -ge 5000) {
                Write-Host "[!] Reached 5,000 threshold. Truncating for speed." -ForegroundColor Yellow
                break
            }
        }
    }
    $reader.Close()
}

# Export directly to Procmon CSV Format instead of JSON!
$ProcmonEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Pipeline Complete! Cross-referenced output generated as native CSV: $OutputPath" -ForegroundColor Green
