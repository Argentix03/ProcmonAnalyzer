param(
    [switch]$Start,
    [switch]$Stop,
    [string]$TraceName = "NativeRedTeamTrace",
    [string]$OutputPath = "$PSScriptRoot\NativeWritablePaths.csv",
    [string]$EtlPath = "$PSScriptRoot\RawTrace.etl"
)

if (-not $Start -and -not $Stop) {
    Write-Host "Please specify -Start or -Stop." -ForegroundColor Yellow
    exit
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] ERROR: This script must be run as Administrator." -ForegroundColor Red
    exit
}

if ($Start) {
    Write-Host "[+] Initializing Native ETW Telemetry Engine..." -ForegroundColor Cyan
    $OutDir = Split-Path $EtlPath
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    
    logman stop $TraceName -ets 2>$null

    Write-Host "[+] Generating ETW Provider Manifest..."
    $ManifestPath = Join-Path $OutDir "etw_providers.txt"
    $Providers = @(
        "Microsoft-Windows-Kernel-File 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Process 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Security-Auditing 0xffffffffffffffff 0xff"
    )
    $Providers | Out-File $ManifestPath -Encoding ascii

    Write-Host "[+] Binding Kernel Providers..."
    $cmd = "logman create trace $TraceName -pf `"$ManifestPath`" -o $EtlPath -ets"
    Invoke-Expression $cmd

    Write-Host "[+] ETW Trace '$TraceName' is actively running." -ForegroundColor Green

    Add-Type -AssemblyName System.Windows.Forms
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Information
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipTitle = "ETW Tracer"
    $balloon.BalloonTipText = "Native ETW Telemetry Capture has Started!"
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(3000)
    Start-Sleep -Milliseconds 500
    $balloon.Dispose()

    exit
}

if ($Stop) {
    Write-Host "[+] Attempting to terminate trace '$TraceName'..." -ForegroundColor Cyan
    logman stop $TraceName -ets 2>$null
    Write-Host "[+] ETW Matrix Socket Closed safely." -ForegroundColor Green
    
    # Run the snapshot logic
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
            IntPtr hProcess = OpenProcess(0x0400, false, processId);
            if (hProcess == IntPtr.Zero) return `"System`";
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, 0x0008, out hToken)) {
                CloseHandle(hProcess); return `"Unknown`";
            }
            uint returnLength = 0;
            GetTokenInformation(hToken, 25, IntPtr.Zero, 0, out returnLength);
            IntPtr tokenInfo = Marshal.AllocHGlobal((int)returnLength);
            bool result = GetTokenInformation(hToken, 25, tokenInfo, returnLength, out returnLength);
            string integrity = `"Unknown`";
            if (result) {
                IntPtr pSid = Marshal.ReadIntPtr(tokenInfo);
                IntPtr countPtr = GetSidSubAuthorityCount(pSid);
                byte count = Marshal.ReadByte(countPtr);
                IntPtr authPtr = GetSidSubAuthority(pSid, (uint)(count - 1));
                uint authVal = (uint)Marshal.ReadInt32(authPtr);
                if (authVal == 0x0000) integrity = `"Untrusted`";
                else if (authVal == 0x1000) integrity = `"Low`";
                else if (authVal == 0x2000) integrity = `"Medium`";
                else if (authVal == 0x2010) integrity = `"Medium Plus`";
                else if (authVal == 0x3000) integrity = `"High`";
                else if (authVal == 0x4000) integrity = `"System`";
                else if (authVal == 0x5000) integrity = `"Protected Process`";
                else integrity = `"System`";
            }
            Marshal.FreeHGlobal(tokenInfo);
            CloseHandle(hToken); CloseHandle(hProcess);
            return integrity;
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

    $AllProcs = Get-Process
    $Snapshot = @{}
    foreach ($p in $AllProcs) {
        $integrity = "Unknown"
        try { $integrity = [Win32Security.ProcessToken]::GetIntegrityLevel($p.Id) } catch { }
        $Snapshot[$p.Id.ToString()] = @{ "ProcessName" = $p.ProcessName + ".exe"; "Integrity" = $integrity }
    }
    
    # Parse ETL
    if (-not (Test-Path $EtlPath)) {
        Write-Host "[!] ERROR: Trace file not found at $EtlPath" -ForegroundColor Red
        exit
    }

    $RawCsvPath = ($EtlPath -replace '\.etl$', '.raw.csv')
    Write-Host "[+] Running tracerpt to decompile \`.etl\` binary..."
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
        exit
    }

    Write-Host "[+] Processing raw I/O Stream natively..."
    $ProcmonEvents = New-Object System.Collections.Generic.List[object]
    $reader = [System.IO.File]::OpenText($RawCsvPath)
    $MatchCount = 0

    while ($null -ne ($line = $reader.ReadLine())) {
        if (-not $line.StartsWith("Microsoft-Windows-Kernel-File")) { continue }
        if ($line -match "\\Device\\HarddiskVolume\d+\\([\w\.\-\\]+)" -or $line -match "([A-Z]:\\[\w\.\-\\]+)") {
            $RawPath = $matches[0]
            if ($RawPath.StartsWith("\Device")) {
                if ($RawPath -match "^(\\Device\\HarddiskVolume\d+)(.*)$") {
                    $volumePart = $matches[1]
                    $restPart = $matches[2]
                    if ($DriveMap.ContainsKey($volumePart)) {
                        $RawPath = $DriveMap[$volumePart] + $restPart
                    } else {
                        $RawPath = $RawPath -replace "^\\Device\\HarddiskVolume\d+", "C:"
                    }
                }
            }
            
            $blocks = $line -split ","
            $hexPid = $blocks[9].Trim()
            $TestPID = "System"
            try { $TestPID = [Convert]::ToInt32($hexPid, 16).ToString() } catch {}

            $MappedName = if ($Snapshot.ContainsKey($TestPID)) { $Snapshot[$TestPID].ProcessName } else { "Unknown.exe" }
            $MappedIntegrity = if ($Snapshot.ContainsKey($TestPID)) { $Snapshot[$TestPID].Integrity } else { "Unknown" }

            $obj = [PSCustomObject]@{
                "Time of Day"  = (Get-Date).ToString("hh:mm:ss.fffffff AM")
                "Process Name" = $MappedName
                "PID"          = $TestPID
                "Operation"    = "ReadFile"
                "Path"         = $RawPath
                "Result"       = "SUCCESS"
                "Integrity"    = $MappedIntegrity
                "Detail"       = "Native File IO"
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

    $ProcmonEvents | Export-Csv -Path $OutputPath -NoTypeInformation -Encoding UTF8
    Write-Host "[+] Pipeline Complete! Output: $OutputPath" -ForegroundColor Green

    Add-Type -AssemblyName System.Windows.Forms
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Information
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipTitle = "ETW Tracer"
    $balloon.BalloonTipText = "ETW Capture Stopped Successfully!`nData parsed and written to: $($OutputPath)"
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(3000)
    Start-Sleep -Milliseconds 500
    $balloon.Dispose()
}
