#requires -Version 5.1
<#
.SYNOPSIS
    Phase 3 (Rev 3.6) 100% Static & Read-Only Binary, PE Import/String, & IDA MCP Verification Engine.
.DESCRIPTION
    Resolves the backing PE binary/DLL/driver for surfaced leads in high_confidence_leads.json
    (including svchost ServiceDlls, Scheduled Task <ComHandler> CLSIDs, DCOM AppIDs/CLSIDs, and
    kernel .sys drivers), parses PE headers, mitigations, import tables, embedded manifests, and
    target string RVAs, optionally queries NtApiDotNet (Get-RpcServer), and outputs:
      1. static_verification_results.json (4-question static verification per lead)
      2. ida_mcp_verification_queue.json (ready-to-run IDA MCP tool call playbook)
      3. Static_Verification_Report.md (Markdown report for human/agent review)

    100% STATIC & READ-ONLY: Never starts/stops services, never executes target binaries,
    and never modifies files or registry keys.
#>
param(
    [Parameter(Mandatory=$false)]
    [string]$LeadsJson = "",

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",

    [ValidateSet('Critical','High','Medium','Low')]
    [string]$MinSeverity = 'High',

    [int]$MaxLeads = 25,

    [int[]]$LeadIndices = @(),

    [string]$PrimitiveFilter = "",

    [switch]$Silent
)

$ErrorActionPreference = "Continue"
$swTotal = [System.Diagnostics.Stopwatch]::StartNew()

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = (Resolve-Path (Join-Path $scriptDir '..\..\..')).Path

if ([string]::IsNullOrWhiteSpace($LeadsJson)) {
    $LeadsJson = Join-Path $projectRoot "high_confidence_leads.json"
}
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $OutputPath = Join-Path (Split-Path -Parent $LeadsJson) "static_verification_results.json"
}

if (-not (Test-Path $LeadsJson)) {
    Write-Error "Leads JSON file not found: $LeadsJson"
    exit 1
}

# ═══════════════════════════════════════════════════════════════════════════════
#  1. NATIVE C# READ-ONLY PE HEADER, IMPORT, MANIFEST & STRING RVA ANALYZER
# ═══════════════════════════════════════════════════════════════════════════════
$csharpPeAnalyzer = @"
using System;
using System.IO;
using System.Text;
using System.Collections.Generic;

namespace ProcmonPhase3Verifier {
    public class PeStaticSummary {
        public bool Exists;
        public bool IsValidPe;
        public string FilePath;
        public long FileSize;
        public string Architecture;
        public ushort Subsystem;
        public bool IsKernelDriver;
        public ushort DllCharacteristics;
        public bool HasAslr;
        public bool HasHighEntropyVa;
        public bool HasNx;
        public bool HasCfg;
        public bool HasForceIntegrity;
        public ulong ImageBase;
        public string ManifestExecLevel;
        public bool AutoElevate;
        public bool UiAccess;
        public List<string> ImportedDlls = new List<string>();
        public List<string> ImportedFunctions = new List<string>();
        public Dictionary<string, string> MatchedStringRvas = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public static class StaticPeAnalyzer {
        private struct SectionInfo {
            public uint VirtualAddress;
            public uint VirtualSize;
            public uint PointerToRawData;
            public uint SizeOfRawData;
        }

        private static int RvaToOffset(uint rva, List<SectionInfo> sections) {
            if (rva == 0) return -1;
            foreach (var s in sections) {
                uint span = Math.Max(s.VirtualSize, s.SizeOfRawData);
                if (rva >= s.VirtualAddress && rva < s.VirtualAddress + span) {
                    uint delta = rva - s.VirtualAddress;
                    if (delta < s.SizeOfRawData) {
                        return (int)(s.PointerToRawData + delta);
                    }
                }
            }
            return -1;
        }

        private static uint OffsetToRva(int fileOffset, List<SectionInfo> sections) {
            if (fileOffset < 0) return 0;
            uint uOff = (uint)fileOffset;
            foreach (var s in sections) {
                if (uOff >= s.PointerToRawData && uOff < s.PointerToRawData + s.SizeOfRawData) {
                    return s.VirtualAddress + (uOff - s.PointerToRawData);
                }
            }
            return 0;
        }

        private static string ReadAsciiZ(byte[] data, int offset, int maxLen) {
            if (offset < 0 || offset >= data.Length) return "";
            int end = offset;
            int limit = Math.Min(data.Length, offset + maxLen);
            while (end < limit && data[end] != 0) end++;
            if (end <= offset) return "";
            return Encoding.ASCII.GetString(data, offset, end - offset);
        }

        public static PeStaticSummary AnalyzePeFile(string path, string[] searchStrings) {
            PeStaticSummary res = new PeStaticSummary();
            res.FilePath = path;
            res.ManifestExecLevel = "asInvoker (or none)";
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path)) {
                res.Exists = false;
                return res;
            }
            res.Exists = true;
            byte[] data;
            try {
                FileInfo fi = new FileInfo(path);
                res.FileSize = fi.Length;
                if (fi.Length < 128 || fi.Length > 150 * 1024 * 1024) return res;
                using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) {
                    data = new byte[fi.Length];
                    int read = 0;
                    while (read < data.Length) {
                        int n = fs.Read(data, read, data.Length - read);
                        if (n <= 0) break;
                        read += n;
                    }
                }
            } catch {
                return res;
            }

            try {
                if (BitConverter.ToUInt16(data, 0) != 0x5A4D) return res; // 'MZ'
                int e_lfanew = BitConverter.ToInt32(data, 0x3C);
                if (e_lfanew < 0x40 || e_lfanew + 24 >= data.Length) return res;
                if (BitConverter.ToUInt32(data, e_lfanew) != 0x00004550) return res; // 'PE\0\0'
                res.IsValidPe = true;

                int coffOff = e_lfanew + 4;
                ushort machine = BitConverter.ToUInt16(data, coffOff);
                ushort numSections = BitConverter.ToUInt16(data, coffOff + 2);
                ushort sizeOfOptHeader = BitConverter.ToUInt16(data, coffOff + 16);

                if (machine == 0x8664) res.Architecture = "x64";
                else if (machine == 0x014C) res.Architecture = "x86";
                else if (machine == 0xAA64) res.Architecture = "ARM64";
                else res.Architecture = string.Format("0x{0:X4}", machine);

                int optOff = coffOff + 20;
                if (optOff + sizeOfOptHeader > data.Length) return res;
                ushort magic = BitConverter.ToUInt16(data, optOff);
                bool is64 = (magic == 0x020B);

                res.ImageBase = is64 ? BitConverter.ToUInt64(data, optOff + 24) : BitConverter.ToUInt32(data, optOff + 28);
                res.Subsystem = BitConverter.ToUInt16(data, optOff + 68);
                res.IsKernelDriver = (res.Subsystem == 1); // IMAGE_SUBSYSTEM_NATIVE
                res.DllCharacteristics = BitConverter.ToUInt16(data, optOff + 70);

                res.HasHighEntropyVa  = (res.DllCharacteristics & 0x0020) != 0;
                res.HasAslr           = (res.DllCharacteristics & 0x0040) != 0;
                res.HasForceIntegrity = (res.DllCharacteristics & 0x0080) != 0;
                res.HasNx             = (res.DllCharacteristics & 0x0100) != 0;
                res.HasCfg            = (res.DllCharacteristics & 0x4000) != 0;

                int dataDirOff = optOff + (is64 ? 112 : 96);
                uint importDirRva = 0;
                if (dataDirOff + 16 <= optOff + sizeOfOptHeader) {
                    importDirRva = BitConverter.ToUInt32(data, dataDirOff + 8); // DataDirectory[1] = IMPORT
                }

                int secTableOff = optOff + sizeOfOptHeader;
                List<SectionInfo> sections = new List<SectionInfo>();
                for (int i = 0; i < numSections; i++) {
                    int sOff = secTableOff + (i * 40);
                    if (sOff + 40 > data.Length) break;
                    SectionInfo si = new SectionInfo();
                    si.VirtualSize = BitConverter.ToUInt32(data, sOff + 8);
                    si.VirtualAddress = BitConverter.ToUInt32(data, sOff + 12);
                    si.SizeOfRawData = BitConverter.ToUInt32(data, sOff + 16);
                    si.PointerToRawData = BitConverter.ToUInt32(data, sOff + 20);
                    sections.Add(si);
                }

                // Walk Import Directory Table
                if (importDirRva != 0) {
                    int impOff = RvaToOffset(importDirRva, sections);
                    HashSet<string> seenDlls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    HashSet<string> seenFuncs = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    int maxDesc = 256;
                    while (impOff >= 0 && impOff + 20 <= data.Length && maxDesc-- > 0) {
                        uint origFirstThunk = BitConverter.ToUInt32(data, impOff);
                        uint nameRva = BitConverter.ToUInt32(data, impOff + 12);
                        uint firstThunk = BitConverter.ToUInt32(data, impOff + 16);
                        if (origFirstThunk == 0 && nameRva == 0 && firstThunk == 0) break;

                        int nameOff = RvaToOffset(nameRva, sections);
                        string dllName = ReadAsciiZ(data, nameOff, 128);
                        if (!string.IsNullOrEmpty(dllName) && seenDlls.Add(dllName)) {
                            res.ImportedDlls.Add(dllName);
                        }

                        uint thunkRva = (origFirstThunk != 0) ? origFirstThunk : firstThunk;
                        int thunkOff = RvaToOffset(thunkRva, sections);
                        int ptrStride = is64 ? 8 : 4;
                        int maxThunks = 4096;
                        while (thunkOff >= 0 && thunkOff + ptrStride <= data.Length && maxThunks-- > 0) {
                            ulong val = is64 ? BitConverter.ToUInt64(data, thunkOff) : BitConverter.ToUInt32(data, thunkOff);
                            if (val == 0) break;
                            bool isOrdinal = is64 ? ((val & 0x8000000000000000UL) != 0) : ((val & 0x80000000UL) != 0);
                            if (!isOrdinal) {
                                uint hintNameRva = (uint)(val & 0x7FFFFFFFUL);
                                int hnOff = RvaToOffset(hintNameRva, sections);
                                if (hnOff >= 0 && hnOff + 2 < data.Length) {
                                    string fn = ReadAsciiZ(data, hnOff + 2, 192);
                                    if (!string.IsNullOrEmpty(fn) && seenFuncs.Add(fn)) {
                                        res.ImportedFunctions.Add(fn);
                                    }
                                }
                            }
                            thunkOff += ptrStride;
                        }
                        impOff += 20;
                    }
                }

                // Scan for embedded manifest XML indicators (autoElevate, uiAccess, requestedExecutionLevel)
                string asciiWindow = Encoding.ASCII.GetString(data);
                if (asciiWindow.IndexOf("autoElevate>true<", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    asciiWindow.IndexOf("autoElevate>True<", StringComparison.OrdinalIgnoreCase) >= 0) {
                    res.AutoElevate = true;
                }
                if (asciiWindow.IndexOf("uiAccess=\"true\"", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    asciiWindow.IndexOf("uiAccess='true'", StringComparison.OrdinalIgnoreCase) >= 0) {
                    res.UiAccess = true;
                }
                if (asciiWindow.IndexOf("level=\"requireAdministrator\"", StringComparison.OrdinalIgnoreCase) >= 0) {
                    res.ManifestExecLevel = "requireAdministrator";
                } else if (asciiWindow.IndexOf("level=\"highestAvailable\"", StringComparison.OrdinalIgnoreCase) >= 0) {
                    res.ManifestExecLevel = "highestAvailable";
                } else if (asciiWindow.IndexOf("level=\"asInvoker\"", StringComparison.OrdinalIgnoreCase) >= 0) {
                    res.ManifestExecLevel = "asInvoker";
                }

                // Search for candidate strings (both UTF-16LE and ASCII) and compute their RVAs for IDA
                if (searchStrings != null && searchStrings.Length > 0) {
                    string unicodeWindow = Encoding.Unicode.GetString(data);
                    foreach (string rawTerm in searchStrings) {
                        if (string.IsNullOrWhiteSpace(rawTerm) || rawTerm.Length < 4) continue;
                        string term = rawTerm.Trim();
                        if (res.MatchedStringRvas.ContainsKey(term)) continue;

                        int uIdx = unicodeWindow.IndexOf(term, StringComparison.OrdinalIgnoreCase);
                        if (uIdx >= 0) {
                            int byteOff = uIdx * 2;
                            uint rva = OffsetToRva(byteOff, sections);
                            ulong va = (rva > 0) ? (res.ImageBase + rva) : 0;
                            res.MatchedStringRvas[term] = string.Format("UTF16LE@RVA=0x{0:X} (VA=0x{1:X})", rva, va);
                            continue;
                        }
                        int aIdx = asciiWindow.IndexOf(term, StringComparison.OrdinalIgnoreCase);
                        if (aIdx >= 0) {
                            uint rva = OffsetToRva(aIdx, sections);
                            ulong va = (rva > 0) ? (res.ImageBase + rva) : 0;
                            res.MatchedStringRvas[term] = string.Format("ASCII@RVA=0x{0:X} (VA=0x{1:X})", rva, va);
                        }
                    }
                }
            } catch {}
            return res;
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $csharpPeAnalyzer -Language CSharp -ErrorAction Stop
} catch {
    if (-not $_.Exception.Message.Contains("already exists")) {
        Write-Warning "Failed to compile StaticPeAnalyzer: $($_.Exception.Message)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  2. HELPER CACHES & BINARY RESOLUTION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
$peAnalysisCache   = @{}
$AuthenticodeCache = @{}
$appIdToClsidCache = $null
$schedTaskMapCache = $null
$liveProcessCache  = @{}

foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    try {
        if (-not [string]::IsNullOrWhiteSpace($p.Path)) {
            $liveProcessCache["$($p.ProcessName).exe".ToLowerInvariant()] = $p.Path
        }
    } catch {}
}

# Check if NtObjectManager / NtApiDotNet is installed for optional static RPC server extraction
$hasNtObjectManager = $null -ne (Get-Command Get-RpcServer -ErrorAction SilentlyContinue)
$rpcServerCache     = @{}

function Normalize-WindowsBinaryPath {
    param([string]$RawPath)
    if ([string]::IsNullOrWhiteSpace($RawPath)) { return "" }
    $s = $RawPath.Trim()

    # Strip COM prefix if formatted as "COM:{GUID} -> <path>"
    if ($s -match '->\s*(.+)$') {
        $s = $matches[1].Trim()
    }

    # Expand environment variables & kernel path prefixes
    $s = $s -replace '(?i)^\\?\?\?\\', ''
    $s = $s -replace '(?i)^\\SystemRoot\\', "$env:SystemRoot\"
    $s = $s -replace '(?i)^System32\\', "$env:SystemRoot\System32\"
    $s = $s -replace '(?i)^SystemRoot\\', "$env:SystemRoot\"
    $s = [Environment]::ExpandEnvironmentVariables($s)

    # Extract executable/DLL/SYS path from command line with arguments
    if ($s.StartsWith('"')) {
        if ($s -match '^"([^"]+)"') {
            return $matches[1].Trim()
        }
    }
    if ($s -match '(?i)^([a-z]:\\[^\r\n"*?<>|]+?\.(?:exe|dll|sys|ocx|cpl|scr))\b') {
        return $matches[1].Trim()
    }
    if ($s -match '(?i)^([^\s"]+\.(?:exe|dll|sys))\b') {
        $token = $matches[1].Trim()
        if ($token -notmatch ':\\') {
            $sys32Candidate = Join-Path "$env:SystemRoot\System32" $token
            if ([System.IO.File]::Exists($sys32Candidate)) { return $sys32Candidate }
            $drvCandidate = Join-Path "$env:SystemRoot\System32\drivers" $token
            if ([System.IO.File]::Exists($drvCandidate)) { return $drvCandidate }
        }
        return $token
    }
    return $s.Trim('"')
}

function Resolve-ClsidServerBinary {
    param([string]$Clsid)
    if ([string]::IsNullOrWhiteSpace($Clsid)) { return "" }
    $cleanGuid = $Clsid.Trim()
    if (-not $cleanGuid.StartsWith("{")) { $cleanGuid = "{$cleanGuid}" }

    foreach ($rootHive in @("SOFTWARE\Classes\CLSID", "SOFTWARE\WOW6432Node\Classes\CLSID")) {
        foreach ($sub in @("InprocServer32", "LocalServer32")) {
            try {
                $k = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$rootHive\$cleanGuid\$sub")
                if ($null -ne $k) {
                    $val = [string]$k.GetValue("", "")
                    $k.Close()
                    $norm = Normalize-WindowsBinaryPath $val
                    if (-not [string]::IsNullOrWhiteSpace($norm) -and [System.IO.File]::Exists($norm)) {
                        return $norm
                    }
                }
            } catch {}
        }
    }
    return ""
}

function Resolve-ServiceBackingBinary {
    param([string]$ServiceName)
    if ([string]::IsNullOrWhiteSpace($ServiceName)) { return $null }
    $cleanSvc = $ServiceName.Trim()
    try {
        $sk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$cleanSvc")
        if ($null -eq $sk) { return $null }
        try {
            $imgPath = [string]$sk.GetValue("ImagePath", "")
            $svcDll  = ""
            $pk = $sk.OpenSubKey("Parameters")
            if ($null -ne $pk) {
                $svcDll = [string]$pk.GetValue("ServiceDll", "")
                $pk.Close()
            }
            if ([string]::IsNullOrWhiteSpace($svcDll)) {
                $svcDll = [string]$sk.GetValue("ServiceDll", "")
            }
            $normDll = Normalize-WindowsBinaryPath $svcDll
            $normImg = Normalize-WindowsBinaryPath $imgPath
            if (-not [string]::IsNullOrWhiteSpace($normDll) -and [System.IO.File]::Exists($normDll)) {
                return [PSCustomObject]@{
                    HostExecutable   = if ($normImg) { $normImg } else { "$env:SystemRoot\System32\svchost.exe" }
                    TargetBinaryPath = $normDll
                    ResolutionMethod = "SCM ServiceParameters ServiceDll ($cleanSvc)"
                }
            }
            if (-not [string]::IsNullOrWhiteSpace($normImg)) {
                return [PSCustomObject]@{
                    HostExecutable   = $normImg
                    TargetBinaryPath = $normImg
                    ResolutionMethod = "SCM Service ImagePath ($cleanSvc)"
                }
            }
        } finally {
            $sk.Close()
        }
    } catch {}
    return $null
}

function Initialize-ScheduledTaskMapCache {
    if ($null -ne $script:schedTaskMapCache) { return }
    $script:schedTaskMapCache = @{}
    try {
        $sched = New-Object -ComObject "Schedule.Service"
        $sched.Connect()
        $q = New-Object System.Collections.Generic.Queue[object]
        $q.Enqueue($sched.GetFolder("\"))
        while ($q.Count -gt 0) {
            $f = $q.Dequeue()
            try { foreach ($sf in $f.GetFolders(0)) { $q.Enqueue($sf) } } catch {}
            try {
                foreach ($t in $f.GetTasks(1)) {
                    $xml = [string]$t.Xml
                    $cmd = if ($xml -match '(?i)<Command>([^<]+)</Command>') { $matches[1].Trim() } else { "" }
                    $argsStr = if ($xml -match '(?i)<Arguments>([^<]+)</Arguments>') { $matches[1].Trim() } else { "" }
                    $clsid = if ($xml -match '(?i)<ClassId>(\{[0-9a-fA-F-]+\})</ClassId>') { $matches[1].Trim() } else { "" }
                    $script:schedTaskMapCache[$t.Path.ToLowerInvariant()] = [PSCustomObject]@{
                        TaskPath  = $t.Path
                        Command   = $cmd
                        Arguments = $argsStr
                        ComClsid  = $clsid
                    }
                }
            } catch {}
        }
    } catch {}
}

function Resolve-LeadTargetBinary {
    param([PSCustomObject]$Lead)

    $pathStr   = [string]$Lead.Path
    $procStr   = [string]$Lead.Processes
    $primStr   = [string]$Lead.ExploitPrimitive
    $reasonStr = [string]$Lead.DetailedReason

    # 1. Kernel Driver Device Surface (\Device\<drv> or Driver:<drv>)
    if ($primStr -eq "Kernel_Device_IOCTL_Surface" -or $pathStr -match '(?i)^\\Device\\([^\\]+)' -or $procStr -match '(?i)^Driver:([^\s,;]+)') {
        $drvName = if ($pathStr -match '(?i)^\\Device\\([^\\]+)') { $matches[1] } elseif ($procStr -match '(?i)^Driver:([^\s,;]+)') { $matches[1] } else { "" }
        if ($drvName) {
            $svcRes = Resolve-ServiceBackingBinary -ServiceName $drvName
            if ($null -ne $svcRes) { return $svcRes }
            $fallbackSys = Join-Path "$env:SystemRoot\System32\drivers" "$drvName.sys"
            return [PSCustomObject]@{
                HostExecutable   = "ntoskrnl.exe"
                TargetBinaryPath = $fallbackSys
                ResolutionMethod = "Kernel Driver Convention ($drvName.sys)"
            }
        }
    }

    # 2. Scheduled Task Lead (C:\Windows\System32\Tasks\...)
    if ($primStr -in @("ScheduledTask_OnDemand_Run", "ScheduledTask_Plant") -or $pathStr -match '(?i)\\System32\\Tasks(\\.+)$') {
        $relTask = if ($pathStr -match '(?i)\\System32\\Tasks(\\.+)$') { $matches[1] } else { "" }
        # First check if DetailedReason already has Command: '...'
        if ($reasonStr -match "Command:\s*'([^']+)'") {
            $cmdInReason = $matches[1].Trim()
            if ($cmdInReason -match '^COM:(\{[0-9a-fA-F-]+\})') {
                $resolvedCom = Resolve-ClsidServerBinary -Clsid $matches[1]
                if ($resolvedCom) {
                    return [PSCustomObject]@{
                        HostExecutable   = "$env:SystemRoot\System32\taskhostw.exe"
                        TargetBinaryPath = $resolvedCom
                        ResolutionMethod = "Scheduled Task ComHandler CLSID ($($matches[1]))"
                    }
                }
            } elseif (-not [string]::IsNullOrWhiteSpace($cmdInReason)) {
                $normCmd = Normalize-WindowsBinaryPath $cmdInReason
                if ($normCmd) {
                    return [PSCustomObject]@{
                        HostExecutable   = "$env:SystemRoot\System32\svchost.exe"
                        TargetBinaryPath = $normCmd
                        ResolutionMethod = "Scheduled Task Action Command ($relTask)"
                    }
                }
            }
        }
        # Query Schedule.Service cache for <Command> or <ComHandler><ClassId>
        if ($relTask) {
            Initialize-ScheduledTaskMapCache
            $tEntry = $script:schedTaskMapCache[$relTask.ToLowerInvariant()]
            if ($null -ne $tEntry) {
                if (-not [string]::IsNullOrWhiteSpace($tEntry.Command)) {
                    $normCmd = Normalize-WindowsBinaryPath $tEntry.Command
                    return [PSCustomObject]@{
                        HostExecutable   = "$env:SystemRoot\System32\svchost.exe"
                        TargetBinaryPath = $normCmd
                        ResolutionMethod = "Schedule.Service Task XML <Command> ($relTask)"
                    }
                }
                if (-not [string]::IsNullOrWhiteSpace($tEntry.ComClsid)) {
                    $comDll = Resolve-ClsidServerBinary -Clsid $tEntry.ComClsid
                    if ($comDll) {
                        return [PSCustomObject]@{
                            HostExecutable   = "$env:SystemRoot\System32\taskhostw.exe"
                            TargetBinaryPath = $comDll
                            ResolutionMethod = "Schedule.Service Task XML <ComHandler> $($tEntry.ComClsid)"
                        }
                    }
                }
            }
        }
    }

    # 3. DCOM AppID Lead (HKLM\SOFTWARE\Classes\AppID\{GUID})
    if ($primStr -eq "DCOM_Privileged_Activation" -or $pathStr -match '(?i)AppID\\(\{[0-9a-fA-F-]+\})') {
        $appIdGuid = if ($pathStr -match '(?i)AppID\\(\{[0-9a-fA-F-]+\})') { $matches[1] } else { "" }
        if ($appIdGuid) {
            try {
                $ak = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Classes\AppID\$appIdGuid")
                if ($null -ne $ak) {
                    $locSvc = [string]$ak.GetValue("LocalService", "")
                    $dllSur = [string]$ak.GetValue("DllSurrogate", "")
                    $ak.Close()
                    if (-not [string]::IsNullOrWhiteSpace($locSvc)) {
                        $svcRes = Resolve-ServiceBackingBinary -ServiceName $locSvc
                        if ($null -ne $svcRes) {
                            $svcRes.ResolutionMethod = "DCOM AppID $appIdGuid -> LocalService '$locSvc' ($($svcRes.ResolutionMethod))"
                            return $svcRes
                        }
                    }
                }
            } catch {}

            # Check if a CLSID with the same GUID exists (common 1:1 AppID==CLSID convention)
            $sameGuidBin = Resolve-ClsidServerBinary -Clsid $appIdGuid
            if (-not [string]::IsNullOrWhiteSpace($sameGuidBin)) {
                return [PSCustomObject]@{
                    HostExecutable   = "$env:SystemRoot\System32\dllhost.exe"
                    TargetBinaryPath = $sameGuidBin
                    ResolutionMethod = "DCOM AppID->CLSID 1:1 Match ($appIdGuid)"
                }
            }

            # Lazy-build AppID -> CLSID index from HKLM\SOFTWARE\Classes\CLSID
            if ($null -eq $script:appIdToClsidCache) {
                $script:appIdToClsidCache = @{}
                try {
                    $clsidRoot = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Classes\CLSID")
                    if ($null -ne $clsidRoot) {
                        foreach ($cName in $clsidRoot.GetSubKeyNames()) {
                            if (-not $cName.StartsWith("{")) { continue }
                            try {
                                $ck = $clsidRoot.OpenSubKey($cName)
                                if ($null -ne $ck) {
                                    $aid = [string]$ck.GetValue("AppID", "")
                                    $ck.Close()
                                    if (-not [string]::IsNullOrWhiteSpace($aid)) {
                                        $aidKey = $aid.Trim().ToLowerInvariant()
                                        if (-not $script:appIdToClsidCache.ContainsKey($aidKey)) {
                                            $script:appIdToClsidCache[$aidKey] = $cName
                                        }
                                    }
                                }
                            } catch {}
                        }
                        $clsidRoot.Close()
                    }
                } catch {}
            }

            $mappedClsid = $script:appIdToClsidCache[$appIdGuid.ToLowerInvariant()]
            if (-not [string]::IsNullOrWhiteSpace($mappedClsid)) {
                $mappedBin = Resolve-ClsidServerBinary -Clsid $mappedClsid
                if (-not [string]::IsNullOrWhiteSpace($mappedBin)) {
                    return [PSCustomObject]@{
                        HostExecutable   = "$env:SystemRoot\System32\dllhost.exe"
                        TargetBinaryPath = $mappedBin
                        ResolutionMethod = "DCOM AppID $appIdGuid -> CLSID $mappedClsid"
                    }
                }
            }
        }
    }

    # 4. Explicit Service Name in Processes (e.g. "svchost.exe (Schedule)" or "services.exe (UsoSvc)") or Path
    if ($procStr -match '\(([^)]+)\)') {
        $svcCandidate = $matches[1].Trim()
        $svcRes = Resolve-ServiceBackingBinary -ServiceName $svcCandidate
        if ($null -ne $svcRes) { return $svcRes }
    }
    if ($pathStr -match '(?i)\\Services\\([^\\]+)') {
        $svcCandidate = $matches[1].Trim()
        $svcRes = Resolve-ServiceBackingBinary -ServiceName $svcCandidate
        if ($null -ne $svcRes) { return $svcRes }
    }

    # 5. CLSID in Path or COM_Context
    $comCtxStr = [string]$Lead.COM_Context
    if ($pathStr -match '(?i)CLSID\\(\{[0-9a-fA-F-]+\})' -or $comCtxStr -match '(\{[0-9a-fA-F-]+\})') {
        $clsidGuid = $matches[1]
        $clsidBin = Resolve-ClsidServerBinary -Clsid $clsidGuid
        if (-not [string]::IsNullOrWhiteSpace($clsidBin)) {
            return [PSCustomObject]@{
                HostExecutable   = $procStr
                TargetBinaryPath = $clsidBin
                ResolutionMethod = "COM CLSID Server ($clsidGuid)"
            }
        }
    }

    # 6. Resolve First Process Name in $Lead.Processes
    $firstProc = ($procStr -split '[,;]')[0].Trim()
    $firstProc = ($firstProc -replace '\s*\([^)]*\)\s*$', '').Trim()
    if (-not [string]::IsNullOrWhiteSpace($firstProc)) {
        $lowerProc = $firstProc.ToLowerInvariant()
        if ($liveProcessCache.ContainsKey($lowerProc)) {
            $methodLabel = if ($lowerProc -eq "dllhost.exe" -and $primStr -eq "DCOM_Privileged_Activation") {
                "COM Surrogate Host (DllHost.exe — Out-of-Proc AppID Surrogate)"
            } else {
                "Running Process MainModule ($firstProc)"
            }
            return [PSCustomObject]@{
                HostExecutable   = $liveProcessCache[$lowerProc]
                TargetBinaryPath = $liveProcessCache[$lowerProc]
                ResolutionMethod = $methodLabel
            }
        }
        $sys32Path = Join-Path "$env:SystemRoot\System32" $firstProc
        if ([System.IO.File]::Exists($sys32Path)) {
            return [PSCustomObject]@{
                HostExecutable   = $sys32Path
                TargetBinaryPath = $sys32Path
                ResolutionMethod = "System32 Standard Binary ($firstProc)"
            }
        }
        try {
            $apKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$firstProc")
            if ($null -ne $apKey) {
                $apVal = Normalize-WindowsBinaryPath ([string]$apKey.GetValue("", ""))
                $apKey.Close()
                if ([System.IO.File]::Exists($apVal)) {
                    return [PSCustomObject]@{
                        HostExecutable   = $apVal
                        TargetBinaryPath = $apVal
                        ResolutionMethod = "Registry App Paths ($firstProc)"
                    }
                }
            }
        } catch {}
    }

    return [PSCustomObject]@{
        HostExecutable   = $firstProc
        TargetBinaryPath = ""
        ResolutionMethod = "Unresolved (Dynamic Host or Missing Component)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  3. API CATEGORIZATION & 4-QUESTION STATIC VERIFICATION ENGINE
# ═══════════════════════════════════════════════════════════════════════════════
$ImpersonationApiSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@(
    'RpcImpersonateClient', 'RpcRevertToSelf', 'RpcRevertToSelfEx',
    'CoImpersonateClient', 'CoRevertToSelf', 'CoGetCallContext',
    'ImpersonateNamedPipeClient', 'ImpersonateLoggedOnUser', 'ImpersonateSelf',
    'RevertToSelf', 'OpenThreadToken', 'SetThreadToken', 'DuplicateTokenEx'
) | ForEach-Object { [void]$ImpersonationApiSet.Add($_) }

$ExecutionSinkApiSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@(
    'LoadLibraryW', 'LoadLibraryA', 'LoadLibraryExW', 'LoadLibraryExA', 'LdrLoadDll',
    'CreateProcessW', 'CreateProcessA', 'CreateProcessAsUserW', 'CreateProcessAsUserA',
    'CreateProcessWithTokenW', 'CreateProcessWithLogonW', 'CreateProcessInternalW',
    'ShellExecuteW', 'ShellExecuteA', 'ShellExecuteExW', 'ShellExecuteExA', 'WinExec'
) | ForEach-Object { [void]$ExecutionSinkApiSet.Add($_) }

$FileRegSinkApiSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@(
    'CreateFileW', 'CreateFileA', 'CreateFile2', 'NtCreateFile', 'ZwCreateFile',
    'IoCreateFile', 'IoCreateFileEx', 'IoCreateFileSpecifyDeviceObjectHint',
    'DeleteFileW', 'DeleteFileA', 'RemoveDirectoryW', 'RemoveDirectoryA',
    'MoveFileExW', 'MoveFileExA', 'MoveFileWithProgressW', 'ReplaceFileW',
    'SetFileInformationByHandle', 'NtSetInformationFile', 'ZwSetInformationFile',
    'CopyFileW', 'CopyFileExW', 'WriteFile', 'NtWriteFile', 'ZwWriteFile',
    'RegOpenKeyExW', 'RegOpenKeyExA', 'RegCreateKeyExW', 'RegCreateKeyExA',
    'NtOpenKeyEx', 'NtOpenKey', 'NtCreateKey', 'ZwOpenKey', 'ZwCreateKey',
    'RegGetValueW', 'RegQueryValueExW', 'RegSetValueExW'
) | ForEach-Object { [void]$FileRegSinkApiSet.Add($_) }

$DaclSecurityApiSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@(
    'SetNamedSecurityInfoW', 'SetNamedSecurityInfoA', 'SetSecurityInfo',
    'SetFileSecurityW', 'SetKernelObjectSecurity',
    'ConvertStringSecurityDescriptorToSecurityDescriptorW',
    'IoCreateDevice', 'IoCreateDeviceSecure', 'WdmlibIoCreateDeviceSecure', 'IoCreateSymbolicLink'
) | ForEach-Object { [void]$DaclSecurityApiSet.Add($_) }

$RpcComIpcApiSet = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
@(
    'RpcServerRegisterIf', 'RpcServerRegisterIfEx', 'RpcServerRegisterIf2', 'RpcServerRegisterIf3',
    'NdrServerCall2', 'NdrServerCallAll', 'Ndr64AsyncServerCallAll',
    'CoRegisterClassObject', 'RoRegisterActivationFactories',
    'CreateNamedPipeW', 'ConnectNamedPipe', 'FilterCreateCommunicationPort'
) | ForEach-Object { [void]$RpcComIpcApiSet.Add($_) }

function Get-CandidateSearchStringsForLead {
    param([PSCustomObject]$Lead)
    $candidates = New-Object System.Collections.Generic.List[string]
    $p = [string]$Lead.Path
    if (-not [string]::IsNullOrWhiteSpace($p)) {
        $leaf = Split-Path -Leaf $p
        if ($leaf.Length -ge 4 -and $leaf -notmatch '^\{[0-9a-fA-F-]+\}$') {
            $candidates.Add($leaf)
        }
        # Also add parent folder name if meaningful
        $parent = Split-Path -Parent $p
        if ($parent) {
            $parentLeaf = Split-Path -Leaf $parent
            if ($parentLeaf.Length -ge 4 -and $parentLeaf -notin @('System32','Windows','Tasks','Services','Classes','AppID','CLSID','Device')) {
                $candidates.Add($parentLeaf)
            }
        }
    }
    if ($Lead.ExploitPrimitive -eq "Kernel_Device_IOCTL_Surface") {
        $candidates.Add("\Device\")
        $candidates.Add("\DosDevices\")
        $candidates.Add("\??\")
    }
    if ($Lead.RegistryDataTarget) {
        $regLeaf = Split-Path -Leaf ([string]$Lead.RegistryDataTarget)
        if ($regLeaf.Length -ge 4) { $candidates.Add($regLeaf) }
    }
    return @($candidates | Select-Object -Unique)
}

# ═══════════════════════════════════════════════════════════════════════════════
#  4. LOAD LEADS & EXECUTE STATIC VERIFICATION PASS
# ═══════════════════════════════════════════════════════════════════════════════
$rawContent = Get-Content -Path $LeadsJson -Raw
$parsedJson = $rawContent | ConvertFrom-Json
$allLeads   = New-Object System.Collections.Generic.List[PSCustomObject]
foreach ($elem in $parsedJson) {
    if ($null -ne $elem) {
        $allLeads.Add($elem)
    }
}

$sevOrder = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }
$minRank  = $sevOrder[$MinSeverity]

$selectedLeads = New-Object System.Collections.Generic.List[PSCustomObject]
if ($LeadIndices -and $LeadIndices.Count -gt 0) {
    foreach ($idx in $LeadIndices) {
        if ($idx -ge 1 -and $idx -le $allLeads.Count) {
            $selectedLeads.Add($allLeads[$idx - 1])
        }
    }
} else {
    $filtered = $allLeads | Where-Object {
        $r = if ($sevOrder.ContainsKey([string]$_.Severity)) { $sevOrder[[string]$_.Severity] } else { 5 }
        $passSev = ($r -le $minRank)
        $passPrim = if ([string]::IsNullOrWhiteSpace($PrimitiveFilter)) { $true } else { [string]$_.ExploitPrimitive -match $PrimitiveFilter }
        $passSev -and $passPrim
    } | Sort-Object @{Expression={ if ($sevOrder.ContainsKey([string]$_.Severity)) { $sevOrder[[string]$_.Severity] } else { 5 } }}, ExploitPrimitive | Select-Object -First $MaxLeads
    foreach ($item in $filtered) { $selectedLeads.Add($item) }
}

if (-not $Silent) {
    Write-Host "[*] Phase 3 Static Verification Engine (`Verify-LeadStatically`) starting on $($selectedLeads.Count) leads..." -ForegroundColor Cyan
}

$verificationResults = New-Object System.Collections.Generic.List[PSCustomObject]
$idaPlaybookQueue    = New-Object System.Collections.Generic.List[PSCustomObject]

$leadCounter = 0
foreach ($lead in $selectedLeads) {
    $leadCounter++
    $resBin = Resolve-LeadTargetBinary -Lead $lead
    $targetBin = [string]$resBin.TargetBinaryPath
    $searchTerms = Get-CandidateSearchStringsForLead -Lead $lead

    $peInfo = $null
    $sigStatus = "Unknown"
    $sigSigner = ""

    if (-not [string]::IsNullOrWhiteSpace($targetBin) -and [System.IO.File]::Exists($targetBin)) {
        $cacheKey = "$($targetBin.ToLowerInvariant())|$($searchTerms -join ';')"
        if (-not $peAnalysisCache.ContainsKey($cacheKey)) {
            $peAnalysisCache[$cacheKey] = [ProcmonPhase3Verifier.StaticPeAnalyzer]::AnalyzePeFile($targetBin, [string[]]$searchTerms)
        }
        $peInfo = $peAnalysisCache[$cacheKey]

        $binLower = $targetBin.ToLowerInvariant()
        if (-not $AuthenticodeCache.ContainsKey($binLower)) {
            try {
                $sig = Get-AuthenticodeSignature -FilePath $targetBin -ErrorAction SilentlyContinue
                if ($null -ne $sig) {
                    $AuthenticodeCache[$binLower] = [PSCustomObject]@{
                        Status = [string]$sig.Status
                        Signer = if ($sig.SignerCertificate) { [string]$sig.SignerCertificate.Subject } else { "" }
                    }
                }
            } catch {}
        }
        if ($AuthenticodeCache.ContainsKey($binLower)) {
            $sigStatus = $AuthenticodeCache[$binLower].Status
            $sigSigner = $AuthenticodeCache[$binLower].Signer
        }
    }

    $impImpersonation = @()
    $impExecSinks     = @()
    $impFileRegSinks  = @()
    $impDaclSinks     = @()
    $impRpcComIpc     = @()
    $matchedRvas      = @{}

    if ($null -ne $peInfo -and $peInfo.IsValidPe) {
        foreach ($fn in $peInfo.ImportedFunctions) {
            if ($ImpersonationApiSet.Contains($fn)) { $impImpersonation += $fn }
            if ($ExecutionSinkApiSet.Contains($fn)) { $impExecSinks     += $fn }
            if ($FileRegSinkApiSet.Contains($fn))   { $impFileRegSinks  += $fn }
            if ($DaclSecurityApiSet.Contains($fn))  { $impDaclSinks     += $fn }
            if ($RpcComIpcApiSet.Contains($fn))     { $impRpcComIpc     += $fn }
        }
        foreach ($kv in $peInfo.MatchedStringRvas.GetEnumerator()) {
            $matchedRvas[$kv.Key] = $kv.Value
        }
    }

    # Optional NtObjectManager / NtApiDotNet RPC Server extraction
    $rpcEndpointsSummary = @()
    if ($hasNtObjectManager -and -not [string]::IsNullOrWhiteSpace($targetBin) -and [System.IO.File]::Exists($targetBin)) {
        $binLower = $targetBin.ToLowerInvariant()
        if (-not $rpcServerCache.ContainsKey($binLower)) {
            try {
                $rpcSvcs = @(Get-RpcServer -ExecutablePath $targetBin -ErrorAction SilentlyContinue)
                $rpcServerCache[$binLower] = @(
                    foreach ($rs in $rpcSvcs) {
                        "UUID=$($rs.InterfaceId) v$($rs.InterfaceVersion) Procs=$($rs.ProcedureCount)"
                    }
                )
            } catch {
                $rpcServerCache[$binLower] = @()
            }
        }
        $rpcEndpointsSummary = $rpcServerCache[$binLower]
    }

    # Check if TargetBinaryPath is a plain-text script (.vbs, .ps1, .bat, .cmd, .js, .wsf)
    $isScriptTarget = ($targetBin -match '(?i)\.(vbs|ps1|bat|cmd|js|wsf)$') -and (-not [string]::IsNullOrWhiteSpace($targetBin)) -and [System.IO.File]::Exists($targetBin)
    $scriptSinksFound = @()
    if ($isScriptTarget) {
        try {
            $scriptText = [System.IO.File]::ReadAllText($targetBin)
            foreach ($pat in @('WScript\.Shell','Scripting\.FileSystemObject','WScript\.Arguments','\.Run\b','\.Exec\b','CopyFile','DeleteFile','MoveFile','CreateTextFile','OpenTextFile','RegWrite','RegRead','ExpandEnvironmentStrings','GetTempName','Invoke-Expression','Start-Process','New-Object')) {
                if ($scriptText -match "(?i)$pat") {
                    $scriptSinksFound += ($pat -replace '\\b','' -replace '\\.','.')
                }
            }
        } catch {}
    }

    # ── Answer the 4 Static Verification Questions ─────────────────────────────
    $prim = [string]$lead.ExploitPrimitive

    # Question 1: Open / Reparse / Device Security Flag Check
    $q1FlagCheck = if ($isScriptTarget) {
        "Target is a plain-text script ('$(([System.IO.Path]::GetFileName($targetBin)))'). Script file/registry operations via WSH/PowerShell do NOT set FILE_FLAG_OPEN_REPARSE_POINT or REG_OPTION_OPEN_LINK."
    } else {
        switch -Wildcard ($prim) {
            "Kernel_Device_IOCTL_Surface" {
                if ($impDaclSinks -contains "WdmlibIoCreateDeviceSecure" -or $impDaclSinks -contains "IoCreateDeviceSecure") {
                    "Driver imports IoCreateDeviceSecure/WdmlibIoCreateDeviceSecure; decompile DriverEntry in IDA to verify default SDDL and whether FILE_DEVICE_SECURE_OPEN (0x100) is set on DeviceCharacteristics."
                } elseif ($impDaclSinks -contains "IoCreateDevice") {
                    "HIGH-PRIORITY: Driver imports raw IoCreateDevice (without IoCreateDeviceSecure); verify in IDA DriverEntry whether FILE_DEVICE_SECURE_OPEN (0x100) is missing and inspect MajorFunction[IRP_MJ_CREATE / IRP_MJ_DEVICE_CONTROL]."
                } else {
                    "Decompile DriverEntry in IDA to inspect device creation flags (FILE_DEVICE_SECURE_OPEN = 0x100) and IRP_MJ_DEVICE_CONTROL (0x0E) dispatch handler."
                }
            }
            "*Registry*" {
                "Verify in IDA whether RegOpenKeyExW / RegCreateKeyExW / NtOpenKeyEx passes REG_OPTION_OPEN_LINK (0x0008) or OBJ_OPENLINK when opening '$($lead.Path)'."
            }
            default {
                if ($lead.OpenReparsePoint -eq $false) {
                    "Trace confirms FILE_OPEN_REPARSE_POINT (0x00200000) was ABSENT at runtime. Verify in IDA whether CreateFileW / NtCreateFile hardcodes dwFlagsAndAttributes=0 without OBJ_DONT_REPARSE (0x1000)."
                } else {
                    "Verify in IDA whether CreateFileW / NtCreateFile on '$($lead.Path)' omits FILE_FLAG_OPEN_REPARSE_POINT (0x00200000) or OBJ_DONT_REPARSE (0x1000) on any code path."
                }
            }
        }
    }

    # Question 2: Impersonation Check
    $q2Impersonation = if ($isScriptTarget) {
        "HIGH-SIGNAL: Script '$(([System.IO.Path]::GetFileName($targetBin)))' executes directly under the host token ($($lead.EffectivePrincipal)) without impersonation."
    } elseif ($null -eq $peInfo -or -not $peInfo.IsValidPe) {
        "Target binary not yet resolved on disk; resolve binary path before checking impersonation imports."
    } elseif ($peInfo.IsKernelDriver) {
        "Kernel driver: check whether IRP_MJ_DEVICE_CONTROL / IRP_MJ_CREATE checks Irp->RequestorMode (UserMode vs KernelMode) and SeSinglePrivilegeCheck / SeAccessCheck."
    } elseif ($impImpersonation.Count -eq 0) {
        "HIGH-SIGNAL: Binary '$(([System.IO.Path]::GetFileName($targetBin)))' imports ZERO impersonation APIs (no RpcImpersonateClient / CoImpersonateClient / ImpersonateNamedPipeClient). Any file/registry/process sink in this module executes directly under the host process token ($($lead.EffectivePrincipal))!"
    } else {
        "Binary imports [$($impImpersonation -join ', ')]. Decompile the sink caller in IDA to verify: (1) whether impersonation is called BEFORE the sink, and (2) whether the return value is checked (preventing silent fallback to SYSTEM)."
    }

    # Question 3: Downstream Sink Identification
    $allSinks = @($impExecSinks + $impDaclSinks + $impFileRegSinks) | Select-Object -Unique
    $q3Sink = if ($isScriptTarget) {
        "Script Sinks Matched in '$(([System.IO.Path]::GetFileName($targetBin)))': [$($scriptSinksFound -join ', ')]. Inspect script source directly for command injection or unvalidated file/registry operations."
    } elseif ($null -eq $peInfo -or -not $peInfo.IsValidPe) {
        "Unresolved binary — sink imports unavailable."
    } elseif ($peInfo.IsKernelDriver) {
        "Kernel Driver Dispatch Sink: Locate DriverObject->MajorFunction[14] (IRP_MJ_DEVICE_CONTROL). Imports of interest: [$($allSinks -join ', ')]. Matched strings: [$($matchedRvas.Keys -join ', ')]."
    } else {
        "Exec Sinks: [$(if ($impExecSinks) { $impExecSinks -join ', ' } else { 'None' })] | DACL Sinks: [$(if ($impDaclSinks) { $impDaclSinks -join ', ' } else { 'None' })] | File/Reg Sinks: [$(if ($impFileRegSinks) { ($impFileRegSinks | Select-Object -First 8) -join ', ' } else { 'None' })] | Matched String RVAs: $(if ($matchedRvas.Count -gt 0) { ($matchedRvas.GetEnumerator() | ForEach-Object { "$($_.Key)=$($_.Value)" }) -join '; ' } else { 'None (path likely constructed dynamically via GetTempPath/SHGetKnownFolderPath/ExpandEnvironmentStrings)' })."
    }

    # Question 4: Trigger Reachability
    $q4Trigger = switch ($prim) {
        "ScheduledTask_OnDemand_Run" {
            "Trigger on-demand as standard user via Task Scheduler COM API (`Schedule.Service` -> `GetTask('$($lead.Path -replace '(?i)^.*\\Tasks', '')').Run(...)`) or `schtasks /Run /TN `"$($lead.Path -replace '(?i)^.*\\Tasks', '')`"`."
        }
        "DCOM_Privileged_Activation" {
            "Trigger on-demand via `CoCreateInstance` / `CoGetClassObject` (`CLSCTX_LOCAL_SERVER` / `CLSCTX_INPROC_SERVER`) targeting '$($lead.Path)' ($($resBin.ResolutionMethod))."
        }
        "Kernel_Device_IOCTL_Surface" {
            "Trigger on-demand via `CreateFileW(`"\\\\.\\<DosDeviceSymLink>`", GENERIC_READ | GENERIC_WRITE, ...)` + `DeviceIoControl(hDevice, IOCTL_CODE, ...)`."
        }
        "Service_OnDemand_Trigger_Chain" {
            "Trigger on-demand via `Start-Service` / `sc.exe start` or ETW/WNF/RPC service trigger event."
        }
        default {
            if ($rpcEndpointsSummary.Count -gt 0) {
                "RPC Server Endpoints in module: [$($rpcEndpointsSummary -join '; ')]. Walk XREFs upward in IDA from sink to RPC stub (`NdrServerCall2` / `Ndr64AsyncServerCallAll`) to identify exact OpNum."
            } elseif ($impRpcComIpc.Count -gt 0) {
                "IPC/Server APIs imported: [$($impRpcComIpc -join ', ')]. Walk callers (`get_callers`) in IDA from the sink to the exported COM vtable, RPC stub, or ServiceMain handler."
            } else {
                "Walk callers (`get_callers`) in IDA from the sink upward to `wmain` / `WinMain` / `ServiceMain` / `DllMain` or exported entry point."
            }
        }
    }

    # Determine Static Triage Status
    $staticStatus = if ($isScriptTarget) {
        "HIGH_PRIORITY_SCRIPT_SINK_RESOLVED"
    } elseif ($null -eq $peInfo -or -not $peInfo.Exists) {
        "BINARY_NOT_FOUND_ON_HOST"
    } elseif ($peInfo.IsKernelDriver -and ($impDaclSinks -contains "IoCreateDevice") -and ($impDaclSinks -notcontains "WdmlibIoCreateDeviceSecure") -and ($impDaclSinks -notcontains "IoCreateDeviceSecure")) {
        "HIGH_PRIORITY_RAW_IOCREATEDEVICE"
    } elseif ($impExecSinks.Count -gt 0 -and $impImpersonation.Count -eq 0) {
        "HIGH_PRIORITY_EXEC_SINK_NO_IMPERSONATION"
    } elseif ($impDaclSinks.Count -gt 0 -and $impImpersonation.Count -eq 0) {
        "HIGH_PRIORITY_DACL_SINK_NO_IMPERSONATION"
    } elseif ($matchedRvas.Count -gt 0) {
        "STRING_ANCHOR_RESOLVED_READY_FOR_IDA"
    } else {
        "BINARY_RESOLVED_READY_FOR_IDA"
    }

    # Build IDA MCP Tool Call Playbook for this lead
    $idaSteps = New-Object System.Collections.Generic.List[PSCustomObject]
    if ($null -ne $peInfo -and $peInfo.IsValidPe) {
        $idaSteps.Add([PSCustomObject]@{
            Step     = 1
            Tool     = "get_metadata"
            Args     = @{ TargetBinary = $targetBin; ImageBase = ("0x{0:X}" -f $peInfo.ImageBase); Architecture = $peInfo.Architecture }
            Purpose  = "Verify '$(([System.IO.Path]::GetFileName($targetBin)))' is loaded in IDA MCP (`HexRaysSA/ida-mcp` or `mrexodia/ida-pro-mcp`) with PDB symbols."
        })
        if ($matchedRvas.Count -gt 0) {
            foreach ($kv in $matchedRvas.GetEnumerator()) {
                $idaSteps.Add([PSCustomObject]@{
                    Step     = $idaSteps.Count + 1
                    Tool     = "get_xrefs_to"
                    Args     = @{ StringLiteral = $kv.Key; Location = $kv.Value }
                    Purpose  = "Locate code XREFs referencing string '$($kv.Key)' ($($kv.Value)) and decompile referencing functions."
                })
            }
        } elseif ($searchTerms.Count -gt 0) {
            $idaSteps.Add([PSCustomObject]@{
                Step     = $idaSteps.Count + 1
                Tool     = "list_strings_filter"
                Args     = @{ filter = $searchTerms[0] }
                Purpose  = "Search IDA string table for '$($searchTerms[0])' or related format strings."
            })
        }

        $primarySinkImports = @($impExecSinks + $impDaclSinks + ($impFileRegSinks | Select-Object -First 4)) | Select-Object -First 5
        if ($primarySinkImports.Count -gt 0) {
            $idaSteps.Add([PSCustomObject]@{
                Step     = $idaSteps.Count + 1
                Tool     = "list_imports"
                Args     = @{ TargetApis = $primarySinkImports }
                Purpose  = "Resolve import thunks for [$($primarySinkImports -join ', ')], then call get_xrefs_to + decompile_function on each caller."
            })
        }

        $idaSteps.Add([PSCustomObject]@{
            Step     = $idaSteps.Count + 1
            Tool     = "decompile_function"
            Args     = @{ VerifyQuestions = @("Q1_OpenFlags", "Q2_ImpersonationCheck", "Q3_SinkDataFlow", "Q4_CallerTrigger") }
            Purpose  = "Decompile candidate sink functions and call get_callers upward to document the exact RPC/COM/Task/Service/IOCTL entry point."
        })
    }

    $verRecord = [PSCustomObject]@{
        LeadIndex               = $leadCounter
        Severity                = $lead.Severity
        ExploitPrimitive        = $prim
        EscalationCategory      = $lead.EscalationCategory
        Path                    = $lead.Path
        Processes               = $lead.Processes
        WritableFrom            = $lead.WritableFrom
        AclSource               = $lead.AclSource
        HostExecutable          = $resBin.HostExecutable
        TargetBinaryPath        = $targetBin
        ResolutionMethod        = $resBin.ResolutionMethod
        BinaryExists            = if ($null -ne $peInfo) { $peInfo.Exists } else { $false }
        Architecture            = if ($null -ne $peInfo) { $peInfo.Architecture } else { "" }
        IsKernelDriver          = if ($null -ne $peInfo) { $peInfo.IsKernelDriver } else { $false }
        AuthenticodeStatus      = $sigStatus
        AuthenticodeSigner      = $sigSigner
        ManifestExecutionLevel  = if ($null -ne $peInfo) { $peInfo.ManifestExecLevel } else { "" }
        AutoElevate             = if ($null -ne $peInfo) { $peInfo.AutoElevate } else { $false }
        UiAccess                = if ($null -ne $peInfo) { $peInfo.UiAccess } else { $false }
        Mitigations             = if ($null -ne $peInfo -and $peInfo.IsValidPe) {
            "ASLR=$($peInfo.HasAslr), HighEntropyVA=$($peInfo.HasHighEntropyVa), NX=$($peInfo.HasNx), CFG=$($peInfo.HasCfg), ForceIntegrity=$($peInfo.HasForceIntegrity)"
        } else { "" }
        ImpersonationApis       = $impImpersonation
        ExecutionSinkApis       = $impExecSinks
        DaclSecurityApis        = $impDaclSinks
        FileRegSinkApis         = $impFileRegSinks
        RpcComIpcApis           = $impRpcComIpc
        MatchedStringRvas       = $matchedRvas
        RpcServerInterfaces     = $rpcEndpointsSummary
        StaticTriageStatus      = $staticStatus
        Q1_FlagCheck            = $q1FlagCheck
        Q2_ImpersonationCheck   = $q2Impersonation
        Q3_SinkIdentification   = $q3Sink
        Q4_TriggerReachability  = $q4Trigger
        IdaMcpSteps             = @($idaSteps)
    }

    $verificationResults.Add($verRecord)
    if ($idaSteps.Count -gt 0) {
        $idaPlaybookQueue.Add([PSCustomObject]@{
            LeadIndex         = $leadCounter
            Severity          = $lead.Severity
            ExploitPrimitive  = $prim
            Path              = $lead.Path
            TargetBinaryPath  = $targetBin
            StaticTriageStatus= $staticStatus
            IdaMcpSteps       = @($idaSteps)
        })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  5. EXPORT JSON, IDA PLAYBOOK & MARKDOWN REPORT
# ═══════════════════════════════════════════════════════════════════════════════
$outDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}

$verificationResults | ConvertTo-Json -Depth 7 | Out-File -FilePath $OutputPath -Encoding UTF8

$idaQueuePath = Join-Path $outDir "ida_mcp_verification_queue.json"
$idaPlaybookQueue | ConvertTo-Json -Depth 7 | Out-File -FilePath $idaQueuePath -Encoding UTF8

$mdReportPath = Join-Path $outDir "Static_Verification_Report.md"
$md = [System.Text.StringBuilder]::new()
[void]$md.AppendLine("# Phase 3 Static Verification & IDA MCP Triage Report (`Rev 3.6`)")
[void]$md.AppendLine("")
[void]$md.AppendLine("- **Generated At:** $((Get-Date).ToString('o'))")
[void]$md.AppendLine("- **Source Leads File:** ``$LeadsJson``")
[void]$md.AppendLine("- **Leads Statically Verified:** $($verificationResults.Count)")
[void]$md.AppendLine("- **Audit Mode:** 100% Static & Read-Only (PE Header/Import/Manifest/String RVA + IDA MCP Playbook)")
[void]$md.AppendLine("")
[void]$md.AppendLine("## 1. Summary by Static Triage Status")
[void]$md.AppendLine("")
[void]$md.AppendLine("| StaticTriageStatus | Count |")
[void]$md.AppendLine("|---|---|")
foreach ($g in ($verificationResults | Group-Object StaticTriageStatus | Sort-Object Count -Descending)) {
    [void]$md.AppendLine("| ``$($g.Name)`` | $($g.Count) |")
}
[void]$md.AppendLine("")
[void]$md.AppendLine("---")
[void]$md.AppendLine("")
[void]$md.AppendLine("## 2. Per-Lead Static Verification & 4-Question Analysis")
[void]$md.AppendLine("")

foreach ($v in $verificationResults) {
    [void]$md.AppendLine("### Lead #$($v.LeadIndex) [$($v.Severity)] ``$($v.ExploitPrimitive)`` — ``$($v.Path)``")
    [void]$md.AppendLine("- **Target Binary:** ``$($v.TargetBinaryPath)`` *(Resolved via: $($v.ResolutionMethod))*")
    [void]$md.AppendLine("- **PE Metadata:** Arch=``$($v.Architecture)`` | Driver=``$($v.IsKernelDriver)`` | Signer=``$($v.AuthenticodeStatus)`` | Manifest=``$($v.ManifestExecutionLevel)`` (AutoElevate=``$($v.AutoElevate)``, UiAccess=``$($v.UiAccess)``)")
    [void]$md.AppendLine("- **Mitigations:** $($v.Mitigations)")
    [void]$md.AppendLine("- **Static Triage Status:** ``$($v.StaticTriageStatus)``")
    [void]$md.AppendLine("- **Q1 (Open / Reparse / Device Flags):** $($v.Q1_FlagCheck)")
    [void]$md.AppendLine("- **Q2 (Impersonation Check):** $($v.Q2_ImpersonationCheck)")
    [void]$md.AppendLine("- **Q3 (Downstream Sink):** $($v.Q3_SinkIdentification)")
    [void]$md.AppendLine("- **Q4 (Trigger Reachability):** $($v.Q4_TriggerReachability)")
    [void]$md.AppendLine("")
}

$md.ToString() | Out-File -FilePath $mdReportPath -Encoding UTF8

if (-not $Silent) {
    Write-Host "[+] Phase 3 Static Verification Complete in $([Math]::Round($swTotal.Elapsed.TotalSeconds, 2))s." -ForegroundColor Green
    Write-Host "    -> Leads Verified:      $($verificationResults.Count)"
    Write-Host "    -> Static Results JSON: $OutputPath"
    Write-Host "    -> IDA MCP Queue JSON:  $idaQueuePath"
    Write-Host "    -> Markdown Report:     $mdReportPath" -ForegroundColor Cyan
}
