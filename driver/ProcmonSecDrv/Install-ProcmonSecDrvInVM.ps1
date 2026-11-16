#requires -Version 5.1
<#
.SYNOPSIS
    Phase 4 (Rev 4.0) VMware / Hyper-V Test VM Provisioning & Loader Script for ProcmonSecDrv.sys.
.DESCRIPTION
    Prepares a snapshotted Windows 10/11 test VM for ProcmonSecDrv.sys:
      1. Verifies Administrator privileges and checks UEFI Secure Boot status.
      2. Enables Test Signing (`bcdedit /set testsigning on`) and optionally disables HVCI
         so test-signed research drivers can load.
      3. Installs the test-signing certificate into Cert:\LocalMachine\Root and
         Cert:\LocalMachine\TrustedPublisher, signs ProcmonSecDrv.sys, registers the
         ProcmonSecDrv kernel service, starts it, and verifies \\.\ProcmonSecDrv via IOCTL_PROCMONSEC_PING.
#>
param(
    [switch]$EnableTestSigningAndConfigureVM,
    [switch]$DisableHvci,
    [switch]$Uninstall
)

$ErrorActionPreference = "Stop"
$drvDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$sysPath = Join-Path $drvDir "bin\x64\ProcmonSecDrv.sys"
$cerPath = Join-Path $drvDir "bin\x64\ProcmonSecDrvTestCert.cer"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Install-ProcmonSecDrvInVM.ps1 must be run from an Administrator PowerShell prompt inside the test VM."
    exit 1
}

if ($Uninstall) {
    Write-Host "[*] Stopping and removing ProcmonSecDrv kernel service..." -ForegroundColor Cyan
    & sc.exe stop ProcmonSecDrv 2>&1 | Out-Null
    & sc.exe delete ProcmonSecDrv 2>&1 | Out-Null
    Write-Host "[+] ProcmonSecDrv service removed." -ForegroundColor Green
    exit 0
}

# 1. Check UEFI Secure Boot
$secureBootOn = $false
try {
    $secureBootOn = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
} catch {}

if ($secureBootOn) {
    Write-Warning "UEFI Secure Boot is currently ENABLED in VMware VM Settings!"
    Write-Host "    To allow test-signing in VMware Workstation / Player:" -ForegroundColor Yellow
    Write-Host "      1. Shut down the Windows 11 VM." -ForegroundColor Yellow
    Write-Host "      2. Open VM -> Settings -> Options -> Advanced -> Firmware type (UEFI)." -ForegroundColor Yellow
    Write-Host "      3. UNCHECK 'Enable secure boot' and click OK." -ForegroundColor Yellow
    Write-Host "      4. Boot the VM and re-run this script." -ForegroundColor Yellow
    exit 1
}

# 2. Check / Enable bcdedit testsigning & HVCI
$bcdOut = (& bcdedit.exe /enum `{current}` 2>&1) | Out-String
$testSigningActive = ($bcdOut -match '(?i)testsigning\s+Yes')

if ($EnableTestSigningAndConfigureVM -or (-not $testSigningActive)) {
    Write-Host "[*] Configuring Windows Boot Configuration for Test-Signed Research Driver..." -ForegroundColor Cyan
    & bcdedit.exe /set `{current}` testsigning on | Out-Host

    if ($DisableHvci) {
        Write-Host "[*] Disabling HVCI (Hypervisor-Protected Code Integrity) for test-signed driver compatibility..." -ForegroundColor Cyan
        New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" -Name "Enabled" -Value 0 -PropertyType DWord -Force -ErrorAction SilentlyContinue | Out-Null
    }

    if (-not $testSigningActive) {
        Write-Host ""
        Write-Host "[!] Test Signing has been enabled in BCD, but a REBOOT is required to take effect." -ForegroundColor Yellow
        Write-Host "    -> Reboot the VM now (`Restart-Computer`), take a clean VMware snapshot, and re-run:" -ForegroundColor Cyan
        Write-Host "       .\driver\ProcmonSecDrv\Install-ProcmonSecDrvInVM.ps1" -ForegroundColor Green
        exit 0
    }
}

# 3. Ensure ProcmonSecDrv.sys exists and is signed with a trusted local test certificate
if (-not (Test-Path $sysPath)) {
    Write-Error "Compiled driver not found at $sysPath. Run Build-ProcmonSecDrv.ps1 first."
    exit 1
}

Write-Host "[*] Installing test-signing certificate into LocalMachine\Root & TrustedPublisher..." -ForegroundColor Cyan
$cert = Get-ChildItem Cert:\LocalMachine\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq "CN=ProcmonSecDrvTestCert" } | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=ProcmonSecDrvTestCert" -CertStoreLocation "Cert:\LocalMachine\My" -NotAfter (Get-Date).AddYears(5)
}
Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
Import-Certificate -FilePath $cerPath -CertStoreLocation "Cert:\LocalMachine\TrustedPublisher" | Out-Null
Set-AuthenticodeSignature -FilePath $sysPath -Certificate $cert -HashAlgorithm SHA256 | Out-Null

# 4. Copy driver to System32\drivers and register/start SCM service
$destSys = "$env:SystemRoot\System32\drivers\ProcmonSecDrv.sys"
& sc.exe stop ProcmonSecDrv 2>&1 | Out-Null
& sc.exe delete ProcmonSecDrv 2>&1 | Out-Null
Start-Sleep -Milliseconds 300

Copy-Item -Path $sysPath -Destination $destSys -Force
Write-Host "[*] Registering and starting ProcmonSecDrv kernel service ($destSys)..." -ForegroundColor Cyan
& sc.exe create ProcmonSecDrv type= kernel start= demand binPath= "\SystemRoot\System32\drivers\ProcmonSecDrv.sys" | Out-Host
& sc.exe start ProcmonSecDrv | Out-Host

# 5. Verify \\.\ProcmonSecDrv via IOCTL_PROCMONSEC_PING
. (Join-Path $drvDir "Invoke-ProcmonSecDrvClient.ps1")
$ping = Test-ProcmonSecDrvConnection
if ($ping.Connected) {
    Write-Host "[+] ProcmonSecDrv.sys is LIVE! Version=$($ping.VersionMajor).$($ping.VersionMinor) | ObCallbacksActive=$($ping.ObCallbacksActive) | BufferedHandleEvents=$($ping.BufferedHandleEvents)" -ForegroundColor Green
} else {
    Write-Warning "ProcmonSecDrv service started, but \\.\ProcmonSecDrv ping did not succeed (ensure you are running as Administrator with SeDebugPrivilege)."
}
