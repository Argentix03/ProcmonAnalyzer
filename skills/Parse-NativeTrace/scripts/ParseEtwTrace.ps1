param(
    [string]$EtlPath = "C:\Temp\RawTrace.etl",
    [string]$OutputPath = "C:\Temp\NativeWritablePaths.csv",
    [int]$MaxEvents = 0
)

Write-Host "[+] Initializing Standalone ETW Parser Pipeline..." -ForegroundColor Cyan

$CsvPath = ($EtlPath -replace '\.etl$', '.raw.csv')
$SnapshotPath = Join-Path (Split-Path $EtlPath) "ActiveProcessesSnapshot.json"

if (-not (Test-Path $EtlPath)) {
    Write-Host "[!] ERROR: Trace file not found at $EtlPath" -ForegroundColor Red
    exit 1
}

$csharpCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace Win32Security {
    public class DosDeviceHelper {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
        public static string GetDevicePath(string driveLetter) {
            StringBuilder sb = new StringBuilder(1000);
            uint result = QueryDosDevice(driveLetter, sb, 1000);
            if (result > 0) return sb.ToString();
            return "";
        }
    }
}
"@
try { Add-Type -TypeDefinition $csharpCode -Language CSharp -ErrorAction SilentlyContinue } catch {}

$DriveMap = @{}
foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
    if ($drive.DriveType -eq 'Fixed' -or $drive.DriveType -eq 'Removable') {
        $letter = $drive.Name.TrimEnd('\')
        try {
            $devicePath = [Win32Security.DosDeviceHelper]::GetDevicePath($letter)
            if ($devicePath) { $DriveMap[$devicePath] = $letter }
        } catch {}
    }
}

# Step 1: Decompile binary ETW to CSV
Write-Host "[+] Running tracerpt OS tool to decompile .etl binary..."
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
    exit 1
}
Write-Host "[+] ETW Binary decompiled successfully to $CsvPath." -ForegroundColor Green

# Step 2: Load Hybrid Process Snapshot Table
$ProcessMap = @{}
if (Test-Path $SnapshotPath) {
    Write-Host "[+] Ingesting Master Hybrid Execution Snapshot ($SnapshotPath)..."
    $SnapshotRaw = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
    foreach ($pidKey in $SnapshotRaw.PSObject.Properties.Name) {
        $ProcessMap[$pidKey] = $SnapshotRaw.$pidKey
    }
} else {
    Write-Host "[!] WARNING: ActiveProcessesSnapshot.json not found! Falling back to Kernel-Process events only." -ForegroundColor Yellow
}

function Resolve-EtwOperation {
    param([string]$Provider, [string]$TaskOrOpcode, [string]$Line)
    $t = if ($TaskOrOpcode) { $TaskOrOpcode.Trim() } else { "" }
    if ($Provider -match "Kernel-Registry") {
        if ($t -match "(?i)(SetValue|69)" -or $Line -match "(?i)SetValue") { return "RegSetValue" }
        if ($t -match "(?i)(CreateKey|Create|64)" -or $Line -match "(?i)CreateKey") { return "RegCreateKey" }
        if ($t -match "(?i)(DeleteValue)" -or $Line -match "(?i)DeleteValue") { return "RegDeleteValue" }
        if ($t -match "(?i)(DeleteKey|Delete)" -or $Line -match "(?i)DeleteKey") { return "RegDeleteKey" }
        if ($t -match "(?i)(QueryValue)" -or $Line -match "(?i)QueryValue") { return "RegQueryValue" }
        return "RegOpenKey"
    }
    if ($t -match "(?i)(Write|68)") { return "WriteFile" }
    if ($t -match "(?i)(Create|64)") { return "CreateFile" }
    if ($t -match "(?i)(Delete|70|SetDelete)") { return "SetDispositionInformationFile" }
    if ($t -match "(?i)(Rename|72)") { return "SetRenameInformationFile" }
    if ($t -match "(?i)(SetInfo|69)") { return "SetBasicInformationFile" }
    if ($t -match "(?i)(DirEnum|75|76)") { return "QueryDirectory" }
    return "ReadFile"
}

function Resolve-EtwResult {
    param([string]$Line)
    if ($Line -match "(?i)0xC0000034") { return "NAME NOT FOUND" }
    if ($Line -match "(?i)0xC000003A") { return "PATH NOT FOUND" }
    if ($Line -match "(?i)0xC0000022") { return "ACCESS DENIED" }
    if ($Line -match "(?i)0xC0000043") { return "SHARING VIOLATION" }
    return "SUCCESS"
}

# Step 3: Parse the CSV sequentially (with per-PID/TID RPC, COM, WMI & Kernel-Object correlation)
Write-Host "[+] Commencing deep telemetry normalization & RPC/COM/WMI thread correlation phase..." -ForegroundColor Cyan
$ProcmonEvents = New-Object System.Collections.Generic.List[object]
$ThreadRpcContext = @{}
$ThreadComContext = @{}
$ThreadWmiContext = @{}
$PidWmiContext    = @{}
$reader = [System.IO.File]::OpenText($CsvPath)
$LineCount = 0
$MatchCount = 0

while ($null -ne ($line = $reader.ReadLine())) {
    $LineCount++

    if ($line.StartsWith("Microsoft-Windows-Kernel-Process")) {
        if ($line -match '([^\\,"]+\.exe)') {
            $exeName = $matches[1]
            $blocks = $line -split ","
            if ($blocks.Count -gt 9) {
                try {
                    $procPid = [Convert]::ToInt32($blocks[9].Trim(), 16).ToString()
                    if (-not $ProcessMap.ContainsKey($procPid)) {
                        $ProcessMap[$procPid] = [PSCustomObject]@{ "ProcessName" = $exeName; "Integrity" = "Medium" }
                    }
                } catch {}
            }
        }
        continue
    }

    # Track per-(PID,TID) RPC server call context
    if ($line.StartsWith("Microsoft-Windows-RPC") -or $line.StartsWith("{6ad52b32-d609-4be9-ae07-ce8dae937e39}")) {
        $blocks = $line -split ","
        if ($blocks.Count -gt 10) {
            try {
                $rPid = [Convert]::ToInt32($blocks[9].Trim(), 16).ToString()
                $rTid = [Convert]::ToInt32($blocks[10].Trim(), 16).ToString()
                $ifUuid = if ($line -match '(\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?)') { $matches[1] } else { "UnknownInterface" }
                $opNum  = if ($line -match '(?i)(?:OpNum|ProcNum)[=:\s"]+([0-9xXa-fA-F]+)') { $matches[1] } else { "?" }
                $ThreadRpcContext["${rPid}:${rTid}"] = "Interface=$ifUuid OpNum=$opNum"
            } catch {}
        }
        continue
    }

    # Track per-(PID,TID) COM runtime activation / call context
    if ($line.StartsWith("Microsoft-Windows-COMRuntime") -or $line.StartsWith("{bf406804-6afa-46e7-8a48-6c357e1d6d61}")) {
        $blocks = $line -split ","
        if ($blocks.Count -gt 10) {
            try {
                $cPid = [Convert]::ToInt32($blocks[9].Trim(), 16).ToString()
                $cTid = [Convert]::ToInt32($blocks[10].Trim(), 16).ToString()
                if ($line -match '(\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})') {
                    $ThreadComContext["${cPid}:${cTid}"] = "CLSID=$($matches[1])"
                }
            } catch {}
        }
        continue
    }

    # Track WMI-Activity namespace / provider context
    if ($line.StartsWith("Microsoft-Windows-WMI-Activity") -or $line.StartsWith("{1418ef04-b0b4-4623-bf7e-d74ab47bbbd3}")) {
        $blocks = $line -split ","
        if ($blocks.Count -gt 10) {
            try {
                $wPid = [Convert]::ToInt32($blocks[9].Trim(), 16).ToString()
                $wTid = [Convert]::ToInt32($blocks[10].Trim(), 16).ToString()
                $ns = if ($line -match '(?i)(ROOT\\[A-Za-z0-9_\\]+)') { $matches[1] } else { "ROOT\CIMV2" }
                $prov = if ($line -match '(?i)ProviderName[=:\s"]+([^",\r\n]+)') { $matches[1].Trim() } else { "" }
                $wmiTag = if ($prov) { "Namespace=$ns Provider=$prov" } else { "Namespace=$ns" }
                $ThreadWmiContext["${wPid}:${wTid}"] = $wmiTag
                $PidWmiContext[$wPid] = $wmiTag
            } catch {}
        }
        continue
    }

    $isFile   = $line.StartsWith("Microsoft-Windows-Kernel-File")
    $isReg    = $line.StartsWith("Microsoft-Windows-Kernel-Registry")
    $isObj    = $line.StartsWith("Microsoft-Windows-Kernel-Object") -or $line.StartsWith("{89497f50-effe-4440-8cf2-ce6b1cdcaca7}")
    if (-not $isFile -and -not $isReg -and -not $isObj) { continue }

    if ($line -match '(\\Device\\HarddiskVolume\d+\\[^",\r\n]+|\\Device\\[^",\r\n]+|\\BaseNamedObjects\\[^",\r\n]+|\\Sessions\\\d+\\BaseNamedObjects\\[^",\r\n]+|[A-Za-z]:\\[^",\r\n]+|\\REGISTRY\\[^",\r\n]+)') {
        $RawPath = $matches[1].Trim()
        if ($RawPath.StartsWith("\Device\HarddiskVolume", [System.StringComparison]::OrdinalIgnoreCase)) {
            if ($RawPath -match "^(\\Device\\HarddiskVolume\d+)(\\.*)?$") {
                $volumePart = $matches[1]
                $restPart = if ($matches[2]) { $matches[2] } else { "\" }
                if ($DriveMap.ContainsKey($volumePart)) {
                    $RawPath = $DriveMap[$volumePart] + $restPart
                } else {
                    $RawPath = "C:" + $restPart
                }
            }
        } elseif ($RawPath -match "(?i)^\\REGISTRY\\MACHINE\\(.*)$") {
            $RawPath = "HKLM\" + $matches[1]
        } elseif ($RawPath -match "(?i)^\\REGISTRY\\USER\\(.*)$") {
            $RawPath = "HKU\" + $matches[1]
        }

        $blocks = $line -split ","
        $taskField = if ($blocks.Count -gt 3) { "$($blocks[1]) $($blocks[2]) $($blocks[3])" } else { "" }
        $tsField   = if ($blocks.Count -gt 6 -and $blocks[6].Trim()) { $blocks[6].Trim() } else { (Get-Date).ToString("hh:mm:ss.fffffff tt") }
        $hexPid    = if ($blocks.Count -gt 9) { $blocks[9].Trim() } else { "0" }
        $hexTid    = if ($blocks.Count -gt 10) { $blocks[10].Trim() } else { "0" }
        $TestPID   = "4"
        $TestTID   = "0"
        try { $TestPID = [Convert]::ToInt32($hexPid, 16).ToString() } catch {}
        try { $TestTID = [Convert]::ToInt32($hexTid, 16).ToString() } catch {}

        $MappedName      = if ($ProcessMap.ContainsKey($TestPID)) { $ProcessMap[$TestPID].ProcessName } else { "Unknown.exe" }
        $MappedIntegrity = if ($ProcessMap.ContainsKey($TestPID)) { $ProcessMap[$TestPID].Integrity } else { "Unknown" }
        $SimOp           = Resolve-EtwOperation -Provider $blocks[0] -TaskOrOpcode $taskField -Line $line
        $SimResult       = Resolve-EtwResult -Line $line

        $tidKey = "${TestPID}:${TestTID}"
        $detailParts = @("Integrity: $MappedIntegrity | Native ETW IO")
        if ($ThreadRpcContext.ContainsKey($tidKey)) {
            $detailParts += "RPC_Context: $($ThreadRpcContext[$tidKey])"
        }
        if ($ThreadComContext.ContainsKey($tidKey)) {
            $detailParts += "COM_Context: $($ThreadComContext[$tidKey])"
        }
        if ($ThreadWmiContext.ContainsKey($tidKey)) {
            $detailParts += "WMI_Context: $($ThreadWmiContext[$tidKey])"
        } elseif ($MappedName -match "(?i)^wmiprvse\.exe$" -and $PidWmiContext.ContainsKey($TestPID)) {
            $detailParts += "WMI_Context: $($PidWmiContext[$TestPID])"
        }

        $obj = [PSCustomObject]@{
            "Time of Day"   = $tsField
            "Process Name"  = $MappedName
            "PID"           = $TestPID
            "TID"           = $TestTID
            "Operation"     = $SimOp
            "Path"          = $RawPath
            "Result"        = $SimResult
            "Integrity"     = $MappedIntegrity
            "Detail"        = ($detailParts -join " | ")
            "Impersonating" = "Unknown"
        }
        $ProcmonEvents.Add($obj)
        $MatchCount++

        if ($MaxEvents -gt 0 -and $MatchCount -ge $MaxEvents) {
            Write-Host "[!] Reached MaxEvents ($MaxEvents) threshold." -ForegroundColor Yellow
            break
        }
    }
}
$reader.Close()

$ProcmonEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
Write-Host "[+] Pipeline Complete! Cross-referenced output generated ($MatchCount events) as native CSV: $OutputPath" -ForegroundColor Green
