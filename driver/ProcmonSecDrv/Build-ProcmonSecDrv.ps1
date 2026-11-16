#requires -Version 5.1
<#
.SYNOPSIS
    Compiles and links the Phase 4 (Rev 4.0) ProcmonSecDrv.sys KMDF/WDM Research Kernel Driver.
.DESCRIPTION
    Automatically discovers MSVC (cl.exe / link.exe) and Windows Driver Kit (WDK) kernel-mode
    headers and libraries (ntifs.h, wdm.h, ntoskrnl.lib), compiles ProcmonSecDrv.c for x64,
    links with /DRIVER /SUBSYSTEM:NATIVE /INTEGRITYCHECK (required for ObRegisterCallbacks),
    and optionally test-signs the resulting ProcmonSecDrv.sys binary.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$OutputDir = "",

    [switch]$SignDriver
)

$ErrorActionPreference = "Stop"
$drvRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($OutputDir)) {
    $OutputDir = Join-Path $drvRoot "bin\x64"
}
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

Write-Host "[*] Locating MSVC x64 compiler and Windows Driver Kit (WDK)..." -ForegroundColor Cyan

# 1. Locate MSVC cl.exe and link.exe
$clExe = $null
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPaths = @()
if (Test-Path $vswhere) {
    $vsPaths = @(& $vswhere -all -property installationPath)
}
$vsPaths += @(
    "C:\Program Files\Microsoft Visual Studio\2022\Community",
    "C:\Program Files\Microsoft Visual Studio\2022\Professional",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
    "C:\Program Files\Microsoft Visual Studio\2022\BuildTools",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\BuildTools"
)

foreach ($vp in ($vsPaths | Select-Object -Unique)) {
    if (-not [string]::IsNullOrWhiteSpace($vp) -and (Test-Path $vp)) {
        $foundCl = Get-ChildItem -Path "$vp\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
        if ($null -ne $foundCl) {
            $clExe = $foundCl.FullName
            break
        }
    }
}

if (-not $clExe) {
    throw "MSVC x64 compiler (cl.exe) not found. Install Visual Studio C++ Desktop/Driver build tools."
}
$msvcBinDir = Split-Path -Parent $clExe
$msvcRoot   = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $msvcBinDir))
$msvcIncDir = Join-Path $msvcRoot "include"
$linkExe    = Join-Path $msvcBinDir "link.exe"

# 2. Locate WDK km headers and ntoskrnl.lib
$kitsRoot = "C:\Program Files (x86)\Windows Kits\10"
$ntddkFile = Get-ChildItem -Path "$kitsRoot\Include\*\km\ntddk.h" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $ntddkFile) {
    throw "WDK kernel headers (km\ntddk.h) not found under $kitsRoot\Include."
}
$wdkIncVerDir = Split-Path -Parent (Split-Path -Parent $ntddkFile.FullName)
$kmIncDir     = Join-Path $wdkIncVerDir "km"
$kmCrtIncDir  = Join-Path $kmIncDir "crt"
$sharedIncDir = Join-Path $wdkIncVerDir "shared"

$ntosLibFile = Get-ChildItem -Path "$kitsRoot\Lib\10.*\km\x64\ntoskrnl.lib" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $ntosLibFile) {
    $ntosLibFile = Get-ChildItem -Path "$kitsRoot\Lib\*\km\x64\ntoskrnl.lib" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
}
if (-not $ntosLibFile) {
    throw "WDK ntoskrnl.lib not found under $kitsRoot\Lib\*\km\x64."
}
$kmLibDir = Split-Path -Parent $ntosLibFile.FullName

Write-Host "    -> Compiler:    $clExe"
Write-Host "    -> WDK Include: $kmIncDir"
Write-Host "    -> WDK Lib:     $kmLibDir"

$srcFile = Join-Path $drvRoot "ProcmonSecDrv.c"
$objFile = Join-Path $OutputDir "ProcmonSecDrv.obj"
$sysFile = Join-Path $OutputDir "ProcmonSecDrv.sys"
$pdbFile = Join-Path $OutputDir "ProcmonSecDrv.pdb"

# 3. Compile ProcmonSecDrv.c
$clArgs = @(
    "/nologo", "/c", "/Zi", "/W3", "/Od", "/Oi", "/GF", "/GS-", "/Gy", "/Zc:wchar_t", "/Zc:inline", "/GR-",
    "/D_WIN64", "/D_AMD64_", "/DAMD64", "/D_UNICODE", "/DUNICODE", "/DNTDDI_VERSION=0x0A000008",
    "/I`"$kmIncDir`"", "/I`"$kmCrtIncDir`"", "/I`"$sharedIncDir`"", "/I`"$msvcIncDir`"", "/I`"$drvRoot`"",
    "/Fo`"$objFile`"", "/Fd`"$pdbFile`"",
    "`"$srcFile`""
)

Write-Host "[*] Compiling ProcmonSecDrv.c..." -ForegroundColor Cyan
$env:PATH = "$msvcBinDir;$env:PATH"
$compOut = & $clExe $clArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ($compOut | Out-String) -ForegroundColor Red
    throw "Compilation failed with exit code $LASTEXITCODE"
}

# 4. Link ProcmonSecDrv.sys with /INTEGRITYCHECK (required for ObRegisterCallbacks)
$linkArgs = @(
    "/NOLOGO", "/DRIVER", "/SUBSYSTEM:NATIVE,10.00", "/ENTRY:DriverEntry", "/NODEFAULTLIB",
    "/INTEGRITYCHECK", "/DYNAMICBASE", "/NXCOMPAT", "/MACHINE:X64", "/DEBUG",
    "/PDB:`"$pdbFile`"", "/OUT:`"$sysFile`"",
    "/LIBPATH:`"$kmLibDir`"",
    "`"$objFile`"", "ntoskrnl.lib", "hal.lib"
)

Write-Host "[*] Linking ProcmonSecDrv.sys (/INTEGRITYCHECK enabled)..." -ForegroundColor Cyan
$linkOut = & $linkExe $linkArgs 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host ($linkOut | Out-String) -ForegroundColor Red
    throw "Linking failed with exit code $LASTEXITCODE"
}

# 5. Optional self-signed test certificate signing for VM deployment
if ($SignDriver) {
    Write-Host "[*] Generating/locating test-signing certificate and signing ProcmonSecDrv.sys..." -ForegroundColor Cyan
    $cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert -ErrorAction SilentlyContinue | Where-Object { $_.Subject -eq "CN=ProcmonSecDrvTestCert" } | Select-Object -First 1
    if (-not $cert) {
        $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=ProcmonSecDrvTestCert" -CertStoreLocation "Cert:\CurrentUser\My" -NotAfter (Get-Date).AddYears(5)
    }
    $cerPath = Join-Path $OutputDir "ProcmonSecDrvTestCert.cer"
    Export-Certificate -Cert $cert -FilePath $cerPath -Force | Out-Null
    Set-AuthenticodeSignature -FilePath $sysFile -Certificate $cert -HashAlgorithm SHA256 | Out-Null
    Write-Host "    -> Test Certificate exported to: $cerPath" -ForegroundColor Green
}

Write-Host "[+] Successfully built ProcmonSecDrv.sys -> $sysFile ($((Get-Item $sysFile).Length) bytes)" -ForegroundColor Green
