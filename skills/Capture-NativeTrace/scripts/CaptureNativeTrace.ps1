param(
    [switch]$Start,
    [switch]$Stop,
    [string]$TraceName = "NativeRedTeamTrace",
    [string]$OutputPath = "C:\Temp\RawTrace.etl"
)

if (-not $Start -and -not $Stop) {
    Write-Host "Please specify -Start or -Stop." -ForegroundColor Yellow
    exit
}

# Ensure running as Administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "[!] ERROR: This script must be run as Administrator to bind ETW telemetry providers." -ForegroundColor Red
    exit
}

if ($Start) {
    Write-Host "[+] Initializing Native ETW Telemetry Engine..." -ForegroundColor Cyan
    
    # Ensure directory exists
    $OutDir = Split-Path $OutputPath
    if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force -Path $OutDir | Out-Null }
    
    # Try to clean up any leftover ghost sessions
    logman stop $TraceName -ets 2>$null

    Write-Host "[+] Generating ETW Provider Manifest..."
    $ManifestPath = Join-Path $OutDir "etw_providers.txt"
    $Providers = @(
        "Microsoft-Windows-Kernel-File 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Process 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Security-Auditing 0xffffffffffffffff 0xff"
        "Microsoft-Windows-Kernel-Registry 0xffffffffffffffff 0xff"
    )
    $Providers | Out-File $ManifestPath -Encoding ascii

    Write-Host "[+] Binding Kernel Providers: File, Process, Auditing..."
    $cmd = "logman create trace $TraceName -pf `"$ManifestPath`" -o $OutputPath -ets"
    Invoke-Expression $cmd

    Write-Host "[+] ETW Trace '$TraceName' is actively running and locked securely to OS." -ForegroundColor Green
    
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
    logman stop $TraceName -ets
    
    Write-Host "[+] Native ETW Socket Closed safely." -ForegroundColor Green
    
    # Compile C# definition natively for reading raw Token Integrity
    $csharpCode = @"
using System;
using System.Runtime.InteropServices;

namespace Win32Security {
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
            IntPtr hProcess = OpenProcess(0x0400, false, processId); // PROCESS_QUERY_INFORMATION
            if (hProcess == IntPtr.Zero) return "System"; // Protected or elevated system processes usually deny 0x0400
            
            IntPtr hToken;
            if (!OpenProcessToken(hProcess, 0x0008, out hToken)) { // TOKEN_QUERY
                CloseHandle(hProcess);
                return "Unknown";
            }

            uint returnLength = 0;
            GetTokenInformation(hToken, 25, IntPtr.Zero, 0, out returnLength); // 25 = TokenIntegrityLevel
            
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
                else if (authVal == 0x1000) integrity = "Low";
                else if (authVal == 0x2000) integrity = "Medium";
                else if (authVal == 0x2010) integrity = "Medium Plus";
                else if (authVal == 0x3000) integrity = "High";
                else if (authVal == 0x4000) integrity = "System";
                else if (authVal == 0x5000) integrity = "Protected Process";
                else integrity = "System"; // Failsafe for custom highest
            }

            Marshal.FreeHGlobal(tokenInfo);
            CloseHandle(hToken);
            CloseHandle(hProcess);
            
            return integrity;
        }
    }
}
"@
    # Add Type explicitly, ignoring errors if it has already been loaded in this terminal session
    try {
        Add-Type -TypeDefinition $csharpCode -Language CSharp -ErrorAction SilentlyContinue 
    } catch {}

    Write-Host "[+] Generating Hybrid Real-Time Process Snapshot..." -ForegroundColor Yellow
    $DumpOutput = Join-Path (Split-Path $OutputPath) "ActiveProcessesSnapshot.json"
    
    $AllProcs = Get-Process
    $Snapshot = @{}
    
    foreach ($p in $AllProcs) {
        $integrity = "Unknown"
        try {
            $integrity = [Win32Security.ProcessToken]::GetIntegrityLevel($p.Id)
        } catch { }

        $Snapshot[$p.Id.ToString()] = @{
            "ProcessName" = $p.ProcessName + ".exe"
            "Integrity"   = $integrity
        }
    }
    
    $Snapshot | ConvertTo-Json -Depth 3 -Compress | Out-File $DumpOutput -Encoding ascii
    Write-Host "[+] Secure Snapshot generated containing $($Snapshot.Count) entries at: $DumpOutput" -ForegroundColor Green
    
    Add-Type -AssemblyName System.Windows.Forms
    $balloon = New-Object System.Windows.Forms.NotifyIcon
    $balloon.Icon = [System.Drawing.SystemIcons]::Information
    $balloon.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Info
    $balloon.BalloonTipTitle = "ETW Tracer"
    $balloon.BalloonTipText = "ETW Capture Stopped Successfully!`nGenerated Snapshot with $($Snapshot.Count) active PIDs."
    $balloon.Visible = $true
    $balloon.ShowBalloonTip(3000)
    Start-Sleep -Milliseconds 500
    $balloon.Dispose()
}
