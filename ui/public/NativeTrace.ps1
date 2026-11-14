param(
    [switch]$Start,
    [switch]$Stop,
    [string]$TraceName = "NativeRedTeamTrace",
    [string]$OutputPath = "$PSScriptRoot\NativeWritablePaths.csv",
    [string]$EtlPath = "$PSScriptRoot\RawTrace.etl",
    [int]$MaxEvents = 0
)

if (-not $Start -and -not $Stop) {
    Write-Host "Please specify -Start or -Stop." -ForegroundColor Yellow
    exit 1
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] ERROR: This script must be run as Administrator." -ForegroundColor Red
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
    public class ProcessToken {
        [DllImport("advapi32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        static extern bool CloseHandle(IntPtr hObject);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        public static string GetIntegrityLevel(int processId) {
            IntPtr hProcess = OpenProcess(0x1000, false, processId); // PROCESS_QUERY_LIMITED_INFORMATION
            if (hProcess == IntPtr.Zero) hProcess = OpenProcess(0x0400, false, processId);
            if (hProcess == IntPtr.Zero) return "System";
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, 0x0008, out hToken)) {
                CloseHandle(hProcess); return "Unknown";
            }
            uint returnLength = 0;
            GetTokenInformation(hToken, 25, IntPtr.Zero, 0, out returnLength);
            if (returnLength == 0) {
                CloseHandle(hToken); CloseHandle(hProcess); return "Unknown";
            }
            IntPtr tokenInfo = Marshal.AllocHGlobal((int)returnLength);
            bool result = GetTokenInformation(hToken, 25, tokenInfo, returnLength, out returnLength);
            string integrity = "Unknown";
            if (result) {
                IntPtr pSid = Marshal.ReadIntPtr(tokenInfo);
                IntPtr countPtr = GetSidSubAuthorityCount(pSid);
                byte count = Marshal.ReadByte(countPtr);
                IntPtr authPtr = GetSidSubAuthority(pSid, (uint)(count - 1));
                uint authVal = (uint)Marshal.ReadInt32(authPtr);
                if (authVal == 0x0000) integrity = "Untrusted";
                else if (authVal < 0x2000) integrity = "Low";
                else if (authVal < 0x2010) integrity = "Medium";
                else if (authVal < 0x3000) integrity = "Medium Plus";
                else if (authVal < 0x4000) integrity = "High";
                else if (authVal < 0x5000) integrity = "System";
                else integrity = "Protected Process";
            }
            Marshal.FreeHGlobal(tokenInfo);
            CloseHandle(hToken); CloseHandle(hProcess);
            return integrity;
        }
    }
}
"@
try { Add-Type -TypeDefinition $csharpCode -Language CSharp -ErrorAction SilentlyContinue } catch {}

function Get-ProcessSnapshotMap {
    param([hashtable]$Existing = @{})
    foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        $pidStr = $p.Id.ToString()
        $integrity = "Unknown"
        try { $integrity = [Win32Security.ProcessToken]::GetIntegrityLevel($p.Id) } catch {}
        $Existing[$pidStr] = @{
            "ProcessName" = $p.ProcessName + ".exe"
            "Integrity"   = $integrity
        }
    }
    return $Existing
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

$OutDir = Split-Path $EtlPath
if ([string]::IsNullOrWhiteSpace($OutDir)) { $OutDir = $PSScriptRoot }
$SnapshotPath = Join-Path $OutDir "ActiveProcessesSnapshot.json"

if ($Start) {
    Write-Host "[+] Initializing Native ETW Telemetry Engine..." -ForegroundColor Cyan
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }

    logman stop $TraceName -ets 2>$null | Out-Null

    # Capture initial process snapshot at trace start so processes that exit before -Stop are preserved
    $InitialSnapshot = Get-ProcessSnapshotMap
    $InitialSnapshot | ConvertTo-Json -Depth 3 -Compress | Out-File $SnapshotPath -Encoding UTF8

    Write-Host "[+] Generating ETW Provider Manifest..."
    $ManifestPath = Join-Path $OutDir "etw_providers.txt"
    $Providers = @(
        "Microsoft-Windows-Kernel-File 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Process 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Security-Auditing 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Registry 0xffffffffffffffff 0xff"
        "Microsoft-Windows-RPC 0xffffffffffffffff 0xff"
        "Microsoft-Windows-COMRuntime 0xffffffffffffffff 0xff"
        "Microsoft-Windows-WMI-Activity 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Object 0xffffffffffffffff 0xff"
    )
    $Providers | Out-File $ManifestPath -Encoding ascii

    Write-Host "[+] Binding Kernel & Subsystem Providers..."
    & logman.exe create trace $TraceName -pf "$ManifestPath" -o "$EtlPath" -ets | Out-Null

    Write-Host "[+] ETW Trace '$TraceName' is actively running." -ForegroundColor Green

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $balloon = New-Object System.Windows.Forms.NotifyIcon
        $balloon.Icon = [System.Drawing.SystemIcons]::Information
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipTitle = "ETW Tracer"
        $balloon.BalloonTipText = "Native ETW Telemetry Capture has Started!"
        $balloon.Visible = $true
        $balloon.ShowBalloonTip(3000)
        Start-Sleep -Milliseconds 500
        $balloon.Dispose()
    } catch {}

    exit 0
}

if ($Stop) {
    Write-Host "[+] Attempting to terminate trace '$TraceName'..." -ForegroundColor Cyan
    logman stop $TraceName -ets 2>$null | Out-Null
    Write-Host "[+] ETW Matrix Socket Closed safely." -ForegroundColor Green

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

    $Snapshot = @{}
    if (Test-Path $SnapshotPath) {
        try {
            $loaded = Get-Content $SnapshotPath -Raw | ConvertFrom-Json
            foreach ($prop in $loaded.PSObject.Properties) {
                $Snapshot[$prop.Name] = @{
                    "ProcessName" = $prop.Value.ProcessName
                    "Integrity"   = $prop.Value.Integrity
                }
            }
        } catch {}
    }
    $Snapshot = Get-ProcessSnapshotMap -Existing $Snapshot
    $Snapshot | ConvertTo-Json -Depth 3 -Compress | Out-File $SnapshotPath -Encoding UTF8

    if (-not (Test-Path $EtlPath)) {
        Write-Host "[!] ERROR: Trace file not found at $EtlPath" -ForegroundColor Red
        exit 1
    }

    $RawCsvPath = ($EtlPath -replace '\.etl$', '.raw.csv')
    Write-Host "[+] Running tracerpt to decompile .etl binary..."
    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "tracerpt.exe"
    $pinfo.Arguments = "`"$EtlPath`" -o `"$RawCsvPath`" -of CSV -y"
    $pinfo.WindowStyle = 'Hidden'
    $pinfo.CreateNoWindow = $true
    $pinfo.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($pinfo)
    $p.WaitForExit()

    if (-not (Test-Path $RawCsvPath)) {
        Write-Host "[!] ERROR: Failed to generate CSV from ETL." -ForegroundColor Red
        exit 1
    }

    Write-Host "[+] Processing raw I/O Stream natively (with RPC/COM/WMI thread correlation)..."
    $ProcmonEvents = New-Object System.Collections.Generic.List[object]
    $ThreadRpcContext = @{}
    $ThreadComContext = @{}
    $ThreadWmiContext = @{}
    $PidWmiContext    = @{}
    $reader = [System.IO.File]::OpenText($RawCsvPath)
    $MatchCount = 0

    while ($null -ne ($line = $reader.ReadLine())) {
        if ($line.StartsWith("Microsoft-Windows-Kernel-Process")) {
            # Capture short-lived process creations from Kernel-Process events
            if ($line -match '([^\\,"]+\.exe)') {
                $exeName = $matches[1]
                $blocks = $line -split ","
                if ($blocks.Count -gt 9) {
                    try {
                        $procPid = [Convert]::ToInt32($blocks[9].Trim(), 16).ToString()
                        if (-not $Snapshot.ContainsKey($procPid)) {
                            $Snapshot[$procPid] = @{ "ProcessName" = $exeName; "Integrity" = "Medium" }
                        }
                    } catch {}
                }
            }
            continue
        }

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

        $isFileEvent = $line.StartsWith("Microsoft-Windows-Kernel-File")
        $isRegEvent  = $line.StartsWith("Microsoft-Windows-Kernel-Registry")
        $isObjEvent  = $line.StartsWith("Microsoft-Windows-Kernel-Object") -or $line.StartsWith("{89497f50-effe-4440-8cf2-ce6b1cdcaca7}")
        if (-not $isFileEvent -and -not $isRegEvent -and -not $isObjEvent) { continue }

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

            $MappedName      = if ($Snapshot.ContainsKey($TestPID)) { $Snapshot[$TestPID].ProcessName } else { "Unknown.exe" }
            $MappedIntegrity = if ($Snapshot.ContainsKey($TestPID)) { $Snapshot[$TestPID].Integrity } else { "Unknown" }
            $MappedOp        = Resolve-EtwOperation -Provider $blocks[0] -TaskOrOpcode $taskField -Line $line
            $MappedResult    = Resolve-EtwResult -Line $line

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
                "Operation"     = $MappedOp
                "Path"          = $RawPath
                "Result"        = $MappedResult
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
    Write-Host "[+] Pipeline Complete! Exported $MatchCount events to: $OutputPath" -ForegroundColor Green

    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction SilentlyContinue
        $balloon = New-Object System.Windows.Forms.NotifyIcon
        $balloon.Icon = [System.Drawing.SystemIcons]::Information
        $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
        $balloon.BalloonTipTitle = "ETW Tracer"
        $balloon.BalloonTipText = "ETW Capture Stopped Successfully!`nData parsed and written to: $($OutputPath)"
        $balloon.Visible = $true
        $balloon.ShowBalloonTip(3000)
        Start-Sleep -Milliseconds 500
        $balloon.Dispose()
    } catch {}
}
