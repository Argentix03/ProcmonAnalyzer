param (
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = ".\NativeWritablePaths.csv",
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    [Parameter(Mandatory=$false)]
    [string[]]$ExcludeProcessTraces = @("Procmon.exe", "Procmon64.exe", "tracerpt.exe", "logman.exe", "NativeTrace.ps1"),
    [switch]$Silent
)

# ═══════════════════════════════════════════════════════════════════════════════
#  Parse-ProcmonWriteables (rev 3 — perspective-aware)
#
#  Purpose: stream a Procmon CSV (or NativeTrace ETW-derived CSV), classify
#  every path against three writability perspectives, and emit a structured
#  feed for Analyze-ExecutionLeads.
#
#  Design notes / hardenings vs rev 2:
#   - PERSPECTIVE-AWARE WRITABILITY: each path is now classified against three
#     hypothetical tokens, not just "the current user":
#       * WritableByLowPriv       — a standard-user (no admin SID) token
#       * WritableByMediumILAdmin — an admin token at medium integrity (UAC
#                                   filtered token; Admin SID is "deny only")
#       * WritableByHighILAdmin   — an elevated admin token (high integrity)
#     This lets downstream rules distinguish low-priv → SYSTEM (real LPE)
#     from medium-IL admin → high-IL admin (UAC bypass) from high-IL admin →
#     SYSTEM/TI (admin-to-system) primitives.
#   - FIXED ACL RIGHT-MASK BUG: rev 2 used `-band [FileSystemRights]::Modify`
#     and `-band ::FullControl` to test for write access. Those are UNION
#     masks containing read bits; any ReadAndExecute ACE matched non-zero,
#     producing dozens of false positives across the Windows tree (e.g.
#     dbgcore.dll-style binary plant). Now we AND only against pure write
#     bits (WriteData | AppendData), which is what 'plant a file/junction'
#     actually requires.
#   - DROPPED SHARING-VIOLATION HACK: rev 2 mapped ERROR_SHARING_VIOLATION
#     (0x80070020) to "writable", which falsely flagged pagefile.sys, mapped
#     DLLs, etc. ACL walking is the source of truth now.
#   - CURRENT USER CONTEXT: the script computes and propagates whether the
#     running token is admin-latent (Admin SID present, even if filtered)
#     vs admin-elevated, and the running process integrity level. The user's
#     own-SID grants count for whichever perspective applies.
#   - INTEGRITY-LABEL HEURISTIC: paths under \Windows\System32, \Program Files,
#     \WinSxS, etc. are tagged IntegrityLabel=High. MIC's NW (no-write-up)
#     means even a medium-IL admin can't write there regardless of ACL.
#
#  Carried over from rev 2:
#   - Best-event selection per path (privileged write w/ NAME-NOT-FOUND beats
#     benign medium-IL read).
#   - Telemetry-quality flags: IsPagingIO, OpenReparsePoint, OpenLink,
#     IsKernelOrCacheManager.
#   - Path canonicalization (case, trailing slash, `\??\`, `\Device\HarddiskVolumeN\`).
#   - Self-trace filtering.
#   - Operations[] aggregation.
# ═══════════════════════════════════════════════════════════════════════════════

Write-Host "Streaming CSV via high-throughput native C# aggregator (best-event scoring per canonical path)..." -ForegroundColor Cyan

# Dictionary keyed by CANONICAL path; preserves original Path for display.
$pathProcessMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Hashtable]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:skippedErrors = New-Object System.Collections.Generic.List[PSCustomObject]
$script:skippedSelfTrace = 0
$script:skippedPagingIO  = 0
$totalLines = 0

$traceFileName = Split-Path $CsvPath -Leaf
$processLineageMap = @{}

# ── HELPERS ──────────────────────────────────────────────────────────────────

# Cache manager / kernel-deferred-work attribution. Procmon will sometimes show
# a path as accessed by an arbitrary process whose thread the Memory Manager
# borrowed for a Cache flush; the LPE prompt §2 flags this as Paging-I/O noise.
$kernelAttribProcs = @("System", "System.exe", "MemCompression", "Registry", "Memory Compression")

# Operations classes
$writeOps = @(
    "WriteFile",
    "SetDispositionInformationFile",
    "SetRenameInformationFile",
    "SetBasicInformationFile",
    "SetEndOfFileInformationFile",
    "SetAllocationInformationFile",
    "SetSecurityFile",
    "RegSetValue",
    "RegCreateKey",
    "RegDeleteKey",
    "RegDeleteValue",
    "WriteConfig"
)
$readOps = @(
    "CreateFile",
    "ReadFile",
    "QueryDirectory",
    "QueryBasicInformationFile",
    "QueryStandardInformationFile",
    "QueryNameInformationFile",
    "Load Image",
    "QueryOpen",
    "RegQueryValue",
    "CreateFileMapping",
    "RegOpenKey",
    "RegEnumKey",
    "RegEnumValue",
    "FileSystemControl"
)

function Get-OperationDirection {
    param([string]$Operation)
    $op = if ($Operation) { $Operation.Trim() } else { "" }
    if ($writeOps -contains $op) { return "Write" }
    if ($readOps  -contains $op) { return "Read" }
    if ($op -match "(?i)(write|set|create|delete|rename)") { return "Write" }
    return "Read"
}

function Test-PrivilegedIntegrity {
    param([string]$Integrity)
    $i = if ($Integrity) { $Integrity.Trim().ToLower() } else { "" }
    return ($i -eq "system" -or $i -eq "high" -or $i -eq "protected process")
}

function Get-IntegrityRank {
    param([string]$Integrity)
    $i = if ($Integrity) { $Integrity.Trim().ToLower() } else { "" }
    switch ($i) {
        "protected process" { return 6 }
        "system"            { return 5 }
        "high"              { return 4 }
        "medium plus"       { return 3 }
        "medium"            { return 2 }
        "low"               { return 1 }
        "appcontainer"      { return 1 }
        "untrusted"         { return 0 }
        default             { return -1 }
    }
}

# Build volume device -> drive letter map, unprivileged Mandatory Label reader, and C# fast CSV stream engine.
$script:_driveMap = @{}
try {
    if (-not ("Win32DeviceMap.ProcmonFastParser" -as [type])) {
        Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32;

namespace Win32DeviceMap {
    public class DosDeviceHelper {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
        public static string GetDevicePath(string driveLetter) {
            StringBuilder sb = new StringBuilder(1000);
            uint result = QueryDosDevice(driveLetter, sb, 1000);
            if (result > 0) return sb.ToString();
            return "";
        }

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
        static extern uint GetNamedSecurityInfoW(
            string pObjectName,
            int ObjectType,
            uint SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            uint SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen);

        [DllImport("kernel32.dll")]
        static extern IntPtr LocalFree(IntPtr hMem);

        // SE_FILE_OBJECT = 1, SE_REGISTRY_KEY = 4; LABEL_SECURITY_INFORMATION = 0x00000010
        public static string GetMandatoryLabelSddl(string objectName, int objectType) {
            IntPtr owner, group, dacl, sacl, sd;
            uint err = GetNamedSecurityInfoW(objectName, objectType, 0x00000010u, out owner, out group, out dacl, out sacl, out sd);
            if (err != 0 || sd == IntPtr.Zero) return "";
            try {
                IntPtr strSd;
                uint strLen;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, 1u, 0x00000010u, out strSd, out strLen) && strSd != IntPtr.Zero) {
                    try {
                        return Marshal.PtrToStringUni(strSd) ?? "";
                    } finally {
                        LocalFree(strSd);
                    }
                }
            } finally {
                LocalFree(sd);
            }
            return "";
        }
    }

    public class ParseSummary {
        public int TotalLines;
        public int SkippedSelfTrace;
        public int SkippedPagingIO;
        public Dictionary<string, Hashtable> PathMap = new Dictionary<string, Hashtable>(StringComparer.OrdinalIgnoreCase);
        public Dictionary<string, string> ProcessLineage = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    }

    public class ProcmonFastParser {
        static readonly HashSet<string> KernelProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "System", "System.exe", "MemCompression", "Registry", "Memory Compression"
        };
        static readonly HashSet<string> KnownSystemDaemons = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "System", "Registry", "MemCompression", "Memory Compression",
            "smss.exe", "csrss.exe", "wininit.exe", "services.exe",
            "lsass.exe", "lsaiso.exe", "winlogon.exe", "spoolsv.exe",
            "SearchIndexer.exe", "MsMpEng.exe", "MpDefenderCoreService.exe",
            "NisSrv.exe", "SecurityHealthService.exe", "SgrmBroker.exe",
            "TrustedInstaller.exe", "TiWorker.exe", "WmiPrvSE.exe",
            "WUDFHost.exe", "dwm.exe", "LogonUI.exe", "audiodg.exe", "dasHost.exe"
        };
        static readonly HashSet<string> UserSessionDropProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "userinit.exe", "explorer.exe", "sihost.exe", "fontdrvhost.exe",
            "StartMenuExperienceHost.exe", "SearchHost.exe", "SearchApp.exe",
            "ShellExperienceHost.exe", "RuntimeBroker.exe", "ApplicationFrameHost.exe",
            "backgroundTaskHost.exe", "TextInputHost.exe", "smartscreen.exe", "mobsync.exe"
        };
        static readonly Regex RxParentPid = new Regex(@"Parent\s*PID:\s*(\d+)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
        static readonly HashSet<string> WriteOps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "WriteFile", "SetDispositionInformationFile", "SetRenameInformationFile",
            "SetBasicInformationFile", "SetEndOfFileInformationFile", "SetAllocationInformationFile",
            "SetSecurityFile", "RegSetValue", "RegCreateKey", "RegDeleteKey", "RegDeleteValue", "WriteConfig"
        };
        static readonly HashSet<string> ReadOps = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "CreateFile", "ReadFile", "QueryDirectory", "QueryBasicInformationFile",
            "QueryStandardInformationFile", "QueryNameInformationFile", "Load Image",
            "QueryOpen", "RegQueryValue", "CreateFileMapping", "RegOpenKey", "RegEnumKey",
            "RegEnumValue", "FileSystemControl"
        };
        static readonly string[] TraceArtifacts = new string[] {
            "\\rawtrace.etl", "\\nativewritablepaths.csv", "\\activeprocessessnapshot.json",
            "\\writable_paths.json", "\\high_confidence_leads.json", "\\cognitive_review_queue.json",
            "\\cognitive_review_queue.j", "\\parsing_errors.json", "\\etw_providers.txt",
            "\\execution_leads_report.md", "\\testtrace.etl"
        };

        static readonly Regex RxIntegrityDetail = new Regex(@"(?i)Integrity:\s*(System|High|Medium Plus|Medium|Low|Untrusted|Protected Process)", RegexOptions.Compiled);
        static readonly Regex RxSqos = new Regex(@"(?i)Impersonation(?:\s*Level)?:\s*(Impersonation|Delegation|Identification|Anonymous)", RegexOptions.Compiled);
        static readonly Regex RxDesiredAccess = new Regex(@"(?i)Desired\s*Access:\s*(.+?)(?:,\s*(?:Disposition|Options|ShareMode|Attributes|AllocationSize|OpenResult|Impersonating|Security\s*QOS):|$)", RegexOptions.Compiled);
        static readonly Regex RxDisposition = new Regex(@"(?i)Disposition:\s*([^,\r\n]+)", RegexOptions.Compiled);
        static readonly Regex RxShareMode = new Regex(@"(?i)ShareMode:\s*(.+?)(?:,\s*(?:Attributes|Options|AllocationSize|OpenResult|Impersonating):|$)", RegexOptions.Compiled);
        static readonly Regex RxDataPath = new Regex(@"(?i)\bData:\s*""?([a-zA-Z]:\\[^""\r\n,;]+|\\\\[^""\r\n,;]+)", RegexOptions.Compiled);
        static readonly Regex RxCmdLine = new Regex(@"(?i)Command\s*line:\s*(.+?)(?:,\s*Current\s*directory:|,\s*Environment:|\r|\n|$)", RegexOptions.Compiled);
        static readonly Regex RxImpersonating = new Regex(@"(?i)Impersonating:\s*([^,\r\n]+)", RegexOptions.Compiled);
        static readonly Regex RxHarddiskVol = new Regex(@"^(?i)(\\Device\\HarddiskVolume\d+)(\\|$)(.*)$", RegexOptions.Compiled);
        static readonly Regex RxAdminSurface = new Regex(@"(?i)(^HKLM\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+(\\(ImagePath|ServiceDll|FailureCommand|Parameters))?$|^HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\(Image File Execution Options|AeDebug)|\\(System32|SysWOW64)\\Tasks\\|\\schedule\\taskcache\\tree\\|Crypto\\Keys|Certificate|PKI|AuthRoot|SystemCertificates\\Root|\\ssl\\certs\\|\.(cer|crt|pfx|p12|pem|key|p7b|manifest|local|asar)$)", RegexOptions.Compiled);
        static readonly Regex RxUserOnlyKeep = new Regex(@"(?i)(\.(exe|dll|sys|cpl|ocx|efi|scr|msi|msp|msc|com|hta|jar|xll|wll|xla|drv|tlb|node|manifest|local|lnk|url|theme|themepack|deskthemepack|bat|ps1|psm1|psd1|vbs|vbe|cmd|wsf|js|jse|wsh|ax|war|pyd|so|cer|crt|pfx|p12|pem|key|p7b)$|\\desktop\.ini$|Startup|\\CurrentVersion\\Run|\\Tasks\\|schedule\\taskcache|wbem\\mof|scripts\\|node_modules|site-packages|vendor\\|gems\\|\.cargo\\registry|inetpub\\wwwroot|xampp\\htdocs|tomcat\\webapps|nginx\\html|machine\.config|web\.config|app\.config|applicationHost\.config|Crypto\\Keys|Certificate|PKI|AuthRoot|SystemCertificates|\\ssl\\certs\\|\\Software\\Classes\\(CLSID|Wow6432Node\\CLSID|Interface)\\\{|\\Environment(\\|$))", RegexOptions.Compiled);
        static readonly HashSet<string> LolBinProcs = new HashSet<string>(StringComparer.OrdinalIgnoreCase) {
            "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "mshta.exe", "rundll32.exe",
            "regsvr32.exe", "odbcconf.exe", "wscript.exe", "cscript.exe", "msiexec.exe", "cmstp.exe",
            "certutil.exe", "bitsadmin.exe", "forfiles.exe", "pcalua.exe", "syncappvpublishingserver.exe",
            "presentationhost.exe", "dfsvc.exe", "xwizard.exe", "hh.exe", "infdefaultinstall.exe", "ieexec.exe"
        };

        static List<string> ReadCsvRow(StreamReader sr, ref int physicalLines) {
            string line = sr.ReadLine();
            if (line == null) return null;
            physicalLines++;
            var fields = new List<string>(10);
            var sb = new StringBuilder();
            bool inQuotes = false;
            int i = 0;
            while (true) {
                while (i < line.Length) {
                    char c = line[i];
                    if (inQuotes) {
                        if (c == '"') {
                            if (i + 1 < line.Length && line[i + 1] == '"') {
                                sb.Append('"');
                                i += 2;
                                continue;
                            } else {
                                inQuotes = false;
                            }
                        } else {
                            sb.Append(c);
                        }
                    } else {
                        if (c == '"') {
                            inQuotes = true;
                        } else if (c == ',') {
                            fields.Add(sb.ToString());
                            sb.Length = 0;
                        } else {
                            sb.Append(c);
                        }
                    }
                    i++;
                }
                if (!inQuotes || sr.EndOfStream) break;
                string nextLine = sr.ReadLine();
                if (nextLine == null) break;
                physicalLines++;
                sb.Append('\n');
                line = nextLine;
                i = 0;
            }
            fields.Add(sb.ToString());
            return fields;
        }

        static Dictionary<string, string> LoadCompanionIntegrityMap(string csvPath, out bool hasCompanion) {
            hasCompanion = false;
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            try {
                string dir = Path.GetDirectoryName(csvPath);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return map;
                string selfName = Path.GetFileName(csvPath);
                foreach (var f in Directory.GetFiles(dir, "*HighPriv*.CSV")) {
                    if (string.Equals(Path.GetFileName(f), selfName, StringComparison.OrdinalIgnoreCase)) continue;
                    using (var sr = new StreamReader(f)) {
                        string hdr = sr.ReadLine();
                        if (hdr == null || hdr.IndexOf("\"Integrity\"", StringComparison.OrdinalIgnoreCase) < 0) continue;
                        hasCompanion = true;
                        string line;
                        while ((line = sr.ReadLine()) != null) {
                            if (line.Length < 10 || line[0] != '"') continue;
                            int p1 = line.IndexOf("\",\"", 1); if (p1 < 0) continue;
                            int p2 = line.IndexOf("\",\"", p1 + 3); if (p2 < 0) continue;
                            int p3 = line.IndexOf("\",\"", p2 + 3); if (p3 < 0) continue;
                            string proc = line.Substring(p1 + 3, p2 - (p1 + 3));
                            string pid = line.Substring(p2 + 3, p3 - (p2 + 3));
                            int lq = line.LastIndexOf("\",\"");
                            if (lq > 0 && line.EndsWith("\"")) {
                                string val = line.Substring(lq + 3, line.Length - lq - 4);
                                string key = proc + ":" + pid;
                                if (!map.ContainsKey(key) && (val == "System" || val == "High" || val == "Medium" || val == "Medium Plus" || val == "Low" || val == "Protected Process")) {
                                    map[key] = val;
                                }
                            }
                        }
                    }
                    if (hasCompanion) break;
                }
            } catch {}
            return map;
        }

        static string NormalizePath(string raw, IDictionary driveMap) {
            if (string.IsNullOrWhiteSpace(raw)) return "";
            string p = raw.Trim();
            if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p.Substring(4);
            else if (p.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase)) p = @"\\" + p.Substring(8);
            else if (p.StartsWith(@"\\?\", StringComparison.Ordinal) && p.Length > 6 && p[5] == ':') p = p.Substring(4);
            else if (p.StartsWith(@"\Device\NamedPipe\", StringComparison.OrdinalIgnoreCase)) p = @"\\.\pipe\" + p.Substring(18);
            else if (p.StartsWith(@"\\?\pipe\", StringComparison.OrdinalIgnoreCase)) p = @"\\.\pipe\" + p.Substring(9);
            else if (p.StartsWith(@"\Device\HarddiskVolume", StringComparison.OrdinalIgnoreCase)) {
                var m = RxHarddiskVol.Match(p);
                if (m.Success) {
                    string vol = m.Groups[1].Value.ToLowerInvariant();
                    string sep = m.Groups[2].Value;
                    string rest = m.Groups[3].Value;
                    if (driveMap != null && driveMap.Contains(vol)) {
                        string letter = (string)driveMap[vol];
                        p = !string.IsNullOrEmpty(sep) ? (letter + "\\" + rest) : (letter + "\\");
                    } else if (driveMap == null || driveMap.Count == 0) {
                        p = !string.IsNullOrEmpty(sep) ? ("C:\\" + rest) : "C:\\";
                    }
                }
            } else if (p.StartsWith(@"\REGISTRY\MACHINE", StringComparison.OrdinalIgnoreCase)) {
                p = "HKLM" + p.Substring(17);
            } else if (p.StartsWith(@"\REGISTRY\USER", StringComparison.OrdinalIgnoreCase)) {
                p = "HKU" + p.Substring(14);
            }
            if (p.EndsWith(@"\*", StringComparison.Ordinal) && p.Length > 4) {
                p = p.Substring(0, p.Length - 2);
            }
            return p;
        }

        static string CanonicalizePath(string normPath) {
            if (string.IsNullOrWhiteSpace(normPath)) return "";
            string p = normPath.TrimEnd();
            while (p.Length > 3 && (p.EndsWith("\\") || p.EndsWith("/"))) p = p.Substring(0, p.Length - 1);
            if (p.StartsWith("\\\\")) {
                p = "\\\\" + Regex.Replace(p.Substring(2), @"\\\\+", "\\");
            } else {
                p = Regex.Replace(p, @"\\\\+", "\\");
            }
            return p.ToLowerInvariant();
        }

        static int GetIntegrityRank(string integ) {
            if (string.IsNullOrEmpty(integ)) return -1;
            switch (integ.Trim().ToLowerInvariant()) {
                case "protected process": return 6;
                case "system": return 5;
                case "high": return 4;
                case "medium plus": return 3;
                case "medium": return 2;
                case "low": return 1;
                case "appcontainer": return 1;
                case "untrusted": return 0;
                default: return -1;
            }
        }

        static string GetOpDir(string op) {
            if (string.IsNullOrEmpty(op)) return "Read";
            string t = op.Trim();
            if (WriteOps.Contains(t)) return "Write";
            if (ReadOps.Contains(t)) return "Read";
            if (t.IndexOf("write", StringComparison.OrdinalIgnoreCase) >= 0 ||
                t.IndexOf("set", StringComparison.OrdinalIgnoreCase) >= 0 ||
                t.IndexOf("create", StringComparison.OrdinalIgnoreCase) >= 0 ||
                t.IndexOf("delete", StringComparison.OrdinalIgnoreCase) >= 0 ||
                t.IndexOf("rename", StringComparison.OrdinalIgnoreCase) >= 0) return "Write";
            return "Read";
        }

        public static ParseSummary StreamAndAggregateCsv(string csvPath, string[] excludeProcs, IDictionary driveMap, string userSid, bool isAdminLatent) {
            var summary = new ParseSummary();
            var excludeSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (excludeProcs != null) {
                foreach (var ep in excludeProcs) if (!string.IsNullOrEmpty(ep)) excludeSet.Add(ep.Trim());
            }

            bool hasCompanion = false;
            Dictionary<string, string> companionIntMap = null;
            var pidIntMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            pidIntMap["4"] = "System";

            using (var sr = new StreamReader(csvPath)) {
                int physLines = 0;
                var headers = ReadCsvRow(sr, ref physLines);
                if (headers == null) return summary;

                var hMap = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
                for (int i = 0; i < headers.Count; i++) hMap[headers[i].Trim()] = i;

                int idxTime = hMap.ContainsKey("time of day") ? hMap["time of day"] : 0;
                int idxProc = hMap.ContainsKey("process name") ? hMap["process name"] : 1;
                int idxPid  = hMap.ContainsKey("pid") ? hMap["pid"] : -1;
                int idxOp   = hMap.ContainsKey("operation") ? hMap["operation"] : 3;
                int idxPath = hMap.ContainsKey("path") ? hMap["path"] : 4;
                int idxRes  = hMap.ContainsKey("result") ? hMap["result"] : 5;
                int idxDet  = hMap.ContainsKey("detail") ? hMap["detail"] : 6;
                int idxInt  = hMap.ContainsKey("integrity") ? hMap["integrity"] : -1;
                int idxImp  = hMap.ContainsKey("impersonating") ? hMap["impersonating"] : -1;
                int idxCmd  = hMap.ContainsKey("command line") ? hMap["command line"] : -1;

                if (idxInt < 0) {
                    companionIntMap = LoadCompanionIntegrityMap(csvPath, out hasCompanion);
                }

                List<string> fields;
                int rowCount = 0;
                while ((fields = ReadCsvRow(sr, ref physLines)) != null) {
                    rowCount++;
                    if (fields.Count < 5) continue;

                    string procName = (idxProc >= 0 && idxProc < fields.Count) ? fields[idxProc].Trim() : "";
                    string pidStr   = (idxPid >= 0 && idxPid < fields.Count) ? fields[idxPid].Trim() : "";
                    string opStr    = (idxOp >= 0 && idxOp < fields.Count) ? fields[idxOp].Trim() : "";
                    string detStr   = (idxDet >= 0 && idxDet < fields.Count) ? fields[idxDet] : "";
                    string cmdStr   = (idxCmd >= 0 && idxCmd < fields.Count) ? fields[idxCmd].Trim() : "";

                    if (!string.IsNullOrEmpty(procName)) {
                        if (!string.IsNullOrEmpty(cmdStr)) {
                            summary.ProcessLineage[procName] = cmdStr;
                        } else if (opStr.StartsWith("Process ", StringComparison.OrdinalIgnoreCase) && detStr.IndexOf("Command line:", StringComparison.OrdinalIgnoreCase) >= 0) {
                            var mCmd = RxCmdLine.Match(detStr);
                            if (mCmd.Success) summary.ProcessLineage[procName] = mCmd.Groups[1].Value.Trim();
                        }
                        if (opStr.Equals("Process Start", StringComparison.OrdinalIgnoreCase) && !string.IsNullOrEmpty(pidStr)) {
                            if (detStr.IndexOf(@"config\systemprofile", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                detStr.IndexOf(@"ServiceProfiles\LocalService", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                detStr.IndexOf(@"ServiceProfiles\NetworkService", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                detStr.IndexOf("USERNAME=SYSTEM", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                KnownSystemDaemons.Contains(procName)) {
                                pidIntMap[pidStr] = "System";
                            } else {
                                var mPpid = RxParentPid.Match(detStr);
                                string ppid = mPpid.Success ? mPpid.Groups[1].Value : "";
                                string parentInt;
                                if (!string.IsNullOrEmpty(ppid) && pidIntMap.TryGetValue(ppid, out parentInt) && (parentInt == "System" || parentInt == "High")) {
                                    if (UserSessionDropProcs.Contains(procName) ||
                                        detStr.IndexOf("UnistackSvcGroup", StringComparison.OrdinalIgnoreCase) >= 0 ||
                                        detStr.IndexOf("-Embedding", StringComparison.OrdinalIgnoreCase) >= 0) {
                                        pidIntMap[pidStr] = "Medium";
                                    } else if (parentInt == "System" && detStr.IndexOf(@"Users\", StringComparison.OrdinalIgnoreCase) < 0) {
                                        pidIntMap[pidStr] = "System";
                                    } else {
                                        pidIntMap[pidStr] = "High";
                                    }
                                } else {
                                    pidIntMap[pidStr] = "Medium";
                                }
                            }
                        }
                    }

                    string pathOrig = (idxPath >= 0 && idxPath < fields.Count) ? fields[idxPath] : "";
                    if (string.IsNullOrWhiteSpace(pathOrig)) continue;

                    string pathRaw = NormalizePath(pathOrig, driveMap);
                    if (string.IsNullOrWhiteSpace(pathRaw)) continue;

                    bool isPipe = pathRaw.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase);
                    bool isUnc  = !isPipe && pathRaw.StartsWith(@"\\", StringComparison.Ordinal) && !pathRaw.StartsWith(@"\\.\") && !pathRaw.StartsWith(@"\\?\");
                    bool isDriveFs = (pathRaw.Length >= 3 && char.IsLetter(pathRaw[0]) && pathRaw[1] == ':' && pathRaw[2] == '\\');
                    bool isFsPath = isDriveFs || isPipe || isUnc;
                    bool isRegPath = !isFsPath && (
                        pathRaw.StartsWith("HKCU", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_CURRENT_USER", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKU", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_USERS", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKLM", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKCR", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_CLASSES_ROOT", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKCC", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_CURRENT_CONFIG", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKPD", StringComparison.OrdinalIgnoreCase) ||
                        pathRaw.StartsWith("HKEY_PERFORMANCE_DATA", StringComparison.OrdinalIgnoreCase)
                    );
                    if (!isFsPath && !isRegPath) continue;

                    // Self-trace contamination check
                    if (excludeSet.Contains(procName)) {
                        summary.SkippedSelfTrace++;
                        continue;
                    }
                    string pl = pathRaw.ToLowerInvariant();
                    bool isSelfArtifact = false;
                    for (int a = 0; a < TraceArtifacts.Length; a++) {
                        if (pl.EndsWith(TraceArtifacts[a], StringComparison.Ordinal)) { isSelfArtifact = true; break; }
                    }
                    if (isSelfArtifact || pl.EndsWith("\\procmon.exe") || pl.EndsWith("\\procmon64.exe") ||
                        pl.EndsWith("\\tracerpt.exe") || pl.EndsWith("\\logman.exe") || pl.EndsWith("\\nativetrace.ps1")) {
                        summary.SkippedSelfTrace++;
                        continue;
                    }

                    string timeStr  = (idxTime >= 0 && idxTime < fields.Count) ? fields[idxTime] : "";
                    string resStr   = (idxRes >= 0 && idxRes < fields.Count) ? fields[idxRes] : "";
                    string integStr = (idxInt >= 0 && idxInt < fields.Count) ? fields[idxInt].Trim() : "Unknown";
                    string impStr   = (idxImp >= 0 && idxImp < fields.Count) ? fields[idxImp].Trim() : "";

                    if (string.IsNullOrEmpty(integStr) || integStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) {
                        if (detStr.IndexOf("Integrity:", StringComparison.OrdinalIgnoreCase) >= 0) {
                            var mInt = RxIntegrityDetail.Match(detStr);
                            if (mInt.Success) integStr = mInt.Groups[1].Value;
                        }
                        if ((string.IsNullOrEmpty(integStr) || integStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) && hasCompanion && companionIntMap != null) {
                            string cVal;
                            if (companionIntMap.TryGetValue(procName + ":" + pidStr, out cVal)) integStr = cVal;
                            else integStr = "Medium";
                        }
                        if (string.IsNullOrEmpty(integStr) || integStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) {
                            string pInt;
                            if (!string.IsNullOrEmpty(pidStr) && pidIntMap.TryGetValue(pidStr, out pInt)) integStr = pInt;
                            else if (KnownSystemDaemons.Contains(procName)) integStr = "System";
                        }
                    }

                    if (string.IsNullOrEmpty(impStr) && detStr.IndexOf("Impersonating:", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mImp = RxImpersonating.Match(detStr);
                        if (mImp.Success) {
                            string candImp = mImp.Groups[1].Value.Trim();
                            if (!candImp.Equals(@"NT AUTHORITY\SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                                !candImp.Equals(@"NT AUTHORITY\LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
                                !candImp.Equals(@"NT AUTHORITY\NETWORK SERVICE", StringComparison.OrdinalIgnoreCase)) {
                                impStr = candImp;
                            }
                        }
                    }

                    bool isPagingIO  = detStr.IndexOf("Paging I/O", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("Paging IO", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool openRP      = detStr.IndexOf("Open Reparse Point", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool openLink    = detStr.IndexOf("Open Link", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("REG_OPTION_OPEN_LINK", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("OBJ_OPENLINK", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool delOnClose  = detStr.IndexOf("Delete On Close", StringComparison.OrdinalIgnoreCase) >= 0;
                    bool openBackup  = detStr.IndexOf("Open For Backup", StringComparison.OrdinalIgnoreCase) >= 0;
                    string sqos      = "NotSpecified";
                    if (detStr.IndexOf("Impersonation", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("Identification", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("Delegation", StringComparison.OrdinalIgnoreCase) >= 0 || detStr.IndexOf("Anonymous", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mSqos = RxSqos.Match(detStr);
                        if (mSqos.Success) sqos = mSqos.Groups[1].Value;
                    }
                    string desAcc = "";
                    if (detStr.IndexOf("Desired Access:", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mDa = RxDesiredAccess.Match(detStr);
                        if (mDa.Success) desAcc = mDa.Groups[1].Value.Trim();
                    }
                    string disp = "";
                    if (detStr.IndexOf("Disposition:", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mDp = RxDisposition.Match(detStr);
                        if (mDp.Success) disp = mDp.Groups[1].Value.Trim();
                    }
                    string shareMode = "";
                    if (detStr.IndexOf("ShareMode:", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mSm = RxShareMode.Match(detStr);
                        if (mSm.Success) shareMode = mSm.Groups[1].Value.Trim();
                    }
                    string regDataPath = "";
                    if (isRegPath && detStr.IndexOf("Data:", StringComparison.OrdinalIgnoreCase) >= 0) {
                        var mRd = RxDataPath.Match(detStr);
                        if (mRd.Success) regDataPath = mRd.Groups[1].Value.Trim();
                    }

                    if (isPagingIO) summary.SkippedPagingIO++;
                    bool isKernelAttrib = KernelProcs.Contains(procName);

                    string opDir = GetOpDir(opStr);
                    int intRank = GetIntegrityRank(integStr);
                    bool isPriv = (intRank >= 4); // High (4), System (5), Protected Process (6)

                    int score = 0;
                    if (intRank >= 5) score += 220;
                    else if (intRank == 4) score += 180;
                    if (opDir == "Write") score += 100;
                    if (resStr.IndexOf("NAME NOT FOUND", StringComparison.OrdinalIgnoreCase) >= 0) score += 25;
                    if (resStr.IndexOf("PATH NOT FOUND", StringComparison.OrdinalIgnoreCase) >= 0) score += 20;
                    if (resStr.IndexOf("REPARSE", StringComparison.OrdinalIgnoreCase) >= 0) score += 10;
                    if (isPagingIO) score -= 80;
                    if (isKernelAttrib) score -= 30;
                    if (openRP) score -= 5;
                    if (openLink) score -= 5;
                    if (opStr.Equals("Load Image", StringComparison.OrdinalIgnoreCase)) score += 60;

                    string canonical = CanonicalizePath(pathRaw);
                    Hashtable rec;
                    if (!summary.PathMap.TryGetValue(canonical, out rec)) {
                        var evt = new Hashtable(StringComparer.OrdinalIgnoreCase);
                        evt["Time"] = timeStr;
                        evt["Operation"] = opStr;
                        evt["Result"] = resStr;
                        evt["Detail"] = detStr;
                        evt["Integrity"] = integStr;
                        evt["Impersonating"] = impStr;
                        evt["ProcessName"] = procName;
                        evt["IsPagingIO"] = isPagingIO;
                        evt["OpenReparsePoint"] = openRP;
                        evt["OpenLink"] = openLink;
                        evt["DeleteOnClose"] = delOnClose;
                        evt["OpenForBackup"] = openBackup;
                        evt["SqosLevel"] = sqos;
                        evt["DesiredAccess"] = desAcc;
                        evt["Disposition"] = disp;
                        evt["ShareMode"] = shareMode;
                        evt["RegistryDataPath"] = regDataPath;
                        evt["IsKernelOrCacheManager"] = isKernelAttrib;

                        rec = new Hashtable(StringComparer.OrdinalIgnoreCase);
                        rec["Path"] = pathRaw;
                        rec["Processes"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        rec["Operations"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        rec["BestEvent"] = evt;
                        rec["BestScore"] = score;
                        rec["HighestIntegrity"] = integStr;
                        rec["HighestIntegrityRank"] = intRank;
                        rec["EventCount"] = 0;
                        rec["AnyWrite"] = false;
                        rec["AnyRead"] = false;
                        rec["AnyPrivWrite"] = false;
                        rec["AnyPrivRead"] = false;
                        rec["AnyImpersonating"] = false;
                        rec["AnyOpenReparsePoint"] = false;
                        rec["AllOpenReparsePoint"] = true;
                        rec["OpenEventCount"] = 0;
                        rec["AnyOpenLink"] = false;
                        rec["AllOpenLink"] = true;
                        rec["RegOpenEventCount"] = 0;
                        rec["AnyPagingIO"] = false;
                        rec["HasDeleteOp"] = false;
                        rec["HasSetSecurityOp"] = false;
                        rec["HasRenameOp"] = false;
                        rec["HasOpenForBackup"] = false;
                        rec["HasBufferOverflow"] = false;
                        rec["HasSharedWriteOrDelete"] = false;
                        rec["HasReadOrCheckOp"] = false;
                        rec["HasLoadOrExecOp"] = false;
                        rec["HasNameNotFound"] = false;
                        rec["RegistryDataPaths"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        rec["NamePrincipals"] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        summary.PathMap[canonical] = rec;
                    }

                    ((HashSet<string>)rec["Processes"]).Add(procName);
                    ((HashSet<string>)rec["Operations"]).Add(opStr);
                    rec["EventCount"] = ((int)rec["EventCount"]) + 1;

                    if (intRank > (int)rec["HighestIntegrityRank"]) {
                        rec["HighestIntegrityRank"] = intRank;
                        rec["HighestIntegrity"] = integStr;
                    }
                    if (opDir == "Write") rec["AnyWrite"] = true; else rec["AnyRead"] = true;
                    if (isPriv && opDir == "Write") rec["AnyPrivWrite"] = true;
                    if (isPriv && opDir == "Read")  rec["AnyPrivRead"] = true;
                    if (!string.IsNullOrEmpty(impStr) && !impStr.Equals("Unknown", StringComparison.OrdinalIgnoreCase)) {
                        rec["AnyImpersonating"] = true;
                        ((HashSet<string>)rec["NamePrincipals"]).Add(impStr);
                    }
                    if (openRP) rec["AnyOpenReparsePoint"] = true;
                    if (isFsPath && (opStr.Equals("CreateFile", StringComparison.OrdinalIgnoreCase) || opStr.Equals("QueryOpen", StringComparison.OrdinalIgnoreCase) || opStr.Equals("OpenFile", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(detStr))) {
                        rec["OpenEventCount"] = ((int)rec["OpenEventCount"]) + 1;
                        if (!openRP) rec["AllOpenReparsePoint"] = false;
                    }
                    if (openLink) rec["AnyOpenLink"] = true;
                    if (isRegPath && (opStr.Equals("RegOpenKey", StringComparison.OrdinalIgnoreCase) || opStr.Equals("RegCreateKey", StringComparison.OrdinalIgnoreCase) || !string.IsNullOrEmpty(detStr))) {
                        rec["RegOpenEventCount"] = ((int)rec["RegOpenEventCount"]) + 1;
                        if (!openLink) rec["AllOpenLink"] = false;
                    }
                    if (isPagingIO) rec["AnyPagingIO"] = true;

                    if (isPriv || !string.IsNullOrEmpty(impStr)) {
                        if (opStr.Equals("SetDispositionInformationFile", StringComparison.OrdinalIgnoreCase) ||
                            opStr.Equals("SetDispositionInformationEx", StringComparison.OrdinalIgnoreCase) ||
                            opStr.Equals("RegDeleteKey", StringComparison.OrdinalIgnoreCase) ||
                            opStr.Equals("RegDeleteValue", StringComparison.OrdinalIgnoreCase) ||
                            delOnClose) {
                            rec["HasDeleteOp"] = true;
                        }
                        if (opStr.Equals("SetSecurityFile", StringComparison.OrdinalIgnoreCase) ||
                            opStr.Equals("RegSetKeySecurity", StringComparison.OrdinalIgnoreCase)) {
                            rec["HasSetSecurityOp"] = true;
                        }
                        if (opStr.Equals("SetRenameInformationFile", StringComparison.OrdinalIgnoreCase)) {
                            rec["HasRenameOp"] = true;
                        }
                        if (openBackup) rec["HasOpenForBackup"] = true;
                        if (resStr.IndexOf("BUFFER OVERFLOW", StringComparison.OrdinalIgnoreCase) >= 0 ||
                            resStr.IndexOf("MORE DATA", StringComparison.OrdinalIgnoreCase) >= 0) {
                            rec["HasBufferOverflow"] = true;
                        }
                    }
                    if (shareMode.IndexOf("Write", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        shareMode.IndexOf("Delete", StringComparison.OrdinalIgnoreCase) >= 0) {
                        rec["HasSharedWriteOrDelete"] = true;
                    }
                    if (opStr.Equals("ReadFile", StringComparison.OrdinalIgnoreCase) ||
                        opStr.Equals("QueryBasicInformationFile", StringComparison.OrdinalIgnoreCase) ||
                        opStr.Equals("QueryOpen", StringComparison.OrdinalIgnoreCase)) {
                        rec["HasReadOrCheckOp"] = true;
                    }
                    if (opStr.Equals("Load Image", StringComparison.OrdinalIgnoreCase) ||
                        opStr.StartsWith("Process ", StringComparison.OrdinalIgnoreCase)) {
                        rec["HasLoadOrExecOp"] = true;
                    }
                    if (resStr.IndexOf("NAME NOT FOUND", StringComparison.OrdinalIgnoreCase) >= 0 ||
                        resStr.IndexOf("PATH NOT FOUND", StringComparison.OrdinalIgnoreCase) >= 0) {
                        rec["HasNameNotFound"] = true;
                    }
                    if (!string.IsNullOrEmpty(regDataPath)) {
                        ((HashSet<string>)rec["RegistryDataPaths"]).Add(regDataPath);
                    }

                    if (score > (int)rec["BestScore"]) {
                        var evt = new Hashtable(StringComparer.OrdinalIgnoreCase);
                        evt["Time"] = timeStr;
                        evt["Operation"] = opStr;
                        evt["Result"] = resStr;
                        evt["Detail"] = detStr;
                        evt["Integrity"] = integStr;
                        evt["Impersonating"] = impStr;
                        evt["ProcessName"] = procName;
                        evt["IsPagingIO"] = isPagingIO;
                        evt["OpenReparsePoint"] = openRP;
                        evt["OpenLink"] = openLink;
                        evt["DeleteOnClose"] = delOnClose;
                        evt["OpenForBackup"] = openBackup;
                        evt["SqosLevel"] = sqos;
                        evt["DesiredAccess"] = desAcc;
                        evt["Disposition"] = disp;
                        evt["ShareMode"] = shareMode;
                        evt["RegistryDataPath"] = regDataPath;
                        evt["IsKernelOrCacheManager"] = isKernelAttrib;
                        rec["BestEvent"] = evt;
                        rec["BestScore"] = score;
                        rec["Path"] = pathRaw;
                    }
                }
                summary.TotalLines = rowCount;
            }

            if (summary.PathMap.Count > 1500) {
                PreFilterLargeTrace(summary.PathMap, userSid);
            }
            return summary;
        }

        static bool IsLowOrUserSid(string sid, string userSid) {
            if (sid == "S-1-1-0" || sid == "S-1-5-11" || sid == "S-1-5-32-545" ||
                sid == "S-1-5-4" || sid == "S-1-2-0"  || sid == "S-1-5-32-546" ||
                sid == "S-1-15-2-1" || sid == "S-1-15-2-2") return true;
            if (!string.IsNullOrEmpty(userSid) && string.Equals(sid, userSid, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        static int GetFsLowMask(FileSystemSecurity acl, string userSid) {
            int allow = 0, deny = 0;
            try {
                foreach (FileSystemAccessRule r in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                    string sid = r.IdentityReference.Value;
                    if (!IsLowOrUserSid(sid, userSid)) continue;
                    int bits = (int)r.FileSystemRights;
                    if (r.AccessControlType == AccessControlType.Deny) deny |= bits;
                    else allow |= bits;
                }
                var owner = acl.GetOwner(typeof(SecurityIdentifier));
                if (owner != null && IsLowOrUserSid(owner.Value, userSid)) {
                    allow |= (int)FileSystemRights.ChangePermissions;
                }
            } catch {}
            return allow & ~deny;
        }

        static bool HasRegLowWrite(RegistrySecurity acl, string userSid) {
            int mask = (int)(RegistryRights.SetValue | RegistryRights.CreateSubKey | RegistryRights.CreateLink | RegistryRights.ChangePermissions | RegistryRights.TakeOwnership);
            bool allow = false, deny = false;
            try {
                foreach (RegistryAccessRule r in acl.GetAccessRules(true, true, typeof(SecurityIdentifier))) {
                    string sid = r.IdentityReference.Value;
                    if (!IsLowOrUserSid(sid, userSid)) continue;
                    if (((int)r.RegistryRights & mask) != 0) {
                        if (r.AccessControlType == AccessControlType.Deny) deny = true;
                        else allow = true;
                    }
                }
                var owner = acl.GetOwner(typeof(SecurityIdentifier));
                if (owner != null && IsLowOrUserSid(owner.Value, userSid)) allow = true;
            } catch {}
            return allow && !deny;
        }

        static void PreFilterLargeTrace(Dictionary<string, Hashtable> pathMap, string userSid) {
            int writeOrDacMask = (int)(FileSystemRights.WriteData | FileSystemRights.AppendData | FileSystemRights.WriteExtendedAttributes | FileSystemRights.WriteAttributes | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);
            int addFileOrDacMask = (int)(FileSystemRights.WriteData | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);
            int addDirOrDacMask = (int)(FileSystemRights.AppendData | FileSystemRights.WriteData | FileSystemRights.ChangePermissions | FileSystemRights.TakeOwnership);
            int delChildMask = (int)FileSystemRights.DeleteSubdirectoriesAndFiles;

            var dirMaskCache = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
            var regLowCache = new Dictionary<string, bool>(StringComparer.OrdinalIgnoreCase);
            var keysToRemove = new List<string>();
            var tempBurstBuckets = new Dictionary<string, List<KeyValuePair<string, int>>>(StringComparer.OrdinalIgnoreCase);

            foreach (var kv in pathMap) {
                string canonical = kv.Key;
                Hashtable rec = kv.Value;
                string p = (string)rec["Path"];

                if (p.StartsWith(@"\\.\pipe\", StringComparison.OrdinalIgnoreCase)) continue;
                var regData = (HashSet<string>)rec["RegistryDataPaths"];
                if (regData != null && regData.Count > 0) continue;
                if (RxAdminSurface.IsMatch(p)) continue;

                bool anyPriv = (bool)rec["AnyPrivRead"] || (bool)rec["AnyPrivWrite"] || (bool)rec["AnyImpersonating"];
                if (!anyPriv) {
                    bool hasLolBin = false;
                    var procSet = (HashSet<string>)rec["Processes"];
                    if (procSet != null) {
                        foreach (var pr in procSet) {
                            if (LolBinProcs.Contains(pr)) { hasLolBin = true; break; }
                        }
                    }
                    if (!hasLolBin && !RxUserOnlyKeep.IsMatch(p)) {
                        keysToRemove.Add(canonical);
                        continue;
                    }
                }

                // Registry check
                if (p.StartsWith("HK", StringComparison.OrdinalIgnoreCase)) {
                    if (p.StartsWith("HKCU\\", StringComparison.OrdinalIgnoreCase) ||
                        p.StartsWith("HKEY_CURRENT_USER\\", StringComparison.OrdinalIgnoreCase) ||
                        (p.StartsWith("HKU\\", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("HKU\\.DEFAULT", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("HKU\\S-1-5-18", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("HKU\\S-1-5-19", StringComparison.OrdinalIgnoreCase) && !p.StartsWith("HKU\\S-1-5-20", StringComparison.OrdinalIgnoreCase))) {
                        continue;
                    }
                    int fs = p.IndexOf('\\');
                    if (fs < 0) { keysToRemove.Add(canonical); continue; }
                    string rootStr = p.Substring(0, fs).ToUpperInvariant();
                    string sub = p.Substring(fs + 1).TrimEnd('\\');
                    var bestEvt = (Hashtable)rec["BestEvent"];
                    string bestOp = (string)bestEvt["Operation"];
                    if (bestOp == "RegQueryValue" || bestOp == "RegSetValue" || bestOp == "RegDeleteValue" || bestOp == "RegEnumValue") {
                        int ls = sub.LastIndexOf('\\');
                        if (ls > 0) sub = sub.Substring(0, ls);
                    }
                    string cacheKey = rootStr + "\\" + sub;
                    bool isRegLow = false;
                    if (!regLowCache.TryGetValue(cacheKey, out isRegLow)) {
                        RegistryKey root = null;
                        if (rootStr == "HKLM" || rootStr == "HKEY_LOCAL_MACHINE") root = Registry.LocalMachine;
                        else if (rootStr == "HKCR" || rootStr == "HKEY_CLASSES_ROOT") root = Registry.ClassesRoot;
                        else if (rootStr == "HKU" || rootStr == "HKEY_USERS") root = Registry.Users;
                        else if (rootStr == "HKCC" || rootStr == "HKEY_CURRENT_CONFIG") root = Registry.CurrentConfig;
                        if (root != null) {
                            string probe = sub;
                            int depth = 0;
                            while (!string.IsNullOrEmpty(probe) && depth < 16) {
                                string pk = rootStr + "\\" + probe;
                                if (regLowCache.TryGetValue(pk, out isRegLow)) break;
                                try {
                                    using (var rk = root.OpenSubKey(probe, RegistryKeyPermissionCheck.Default, RegistryRights.ReadPermissions)) {
                                        if (rk != null) {
                                            var sec = rk.GetAccessControl(AccessControlSections.Access | AccessControlSections.Owner);
                                            isRegLow = HasRegLowWrite(sec, userSid);
                                            regLowCache[pk] = isRegLow;
                                            break;
                                        }
                                    }
                                } catch {
                                    regLowCache[pk] = false;
                                    break;
                                }
                                int ls = probe.LastIndexOf('\\');
                                probe = (ls > 0) ? probe.Substring(0, ls) : "";
                                depth++;
                            }
                        }
                        regLowCache[cacheKey] = isRegLow;
                    }
                    if (!isRegLow) keysToRemove.Add(canonical);
                    continue;
                }

                // Filesystem check
                bool keepFs = false;
                try {
                    if (File.Exists(p)) {
                        var acl = File.GetAccessControl(p, AccessControlSections.Access | AccessControlSections.Owner);
                        int fMask = GetFsLowMask(acl, userSid);
                        if ((fMask & writeOrDacMask) != 0) keepFs = true;
                        else {
                            string imm = Path.GetDirectoryName(p);
                            if (!string.IsNullOrEmpty(imm) && Directory.Exists(imm)) {
                                int dMask;
                                if (!dirMaskCache.TryGetValue(imm, out dMask)) {
                                    var dAcl = Directory.GetAccessControl(imm, AccessControlSections.Access | AccessControlSections.Owner);
                                    dMask = GetFsLowMask(dAcl, userSid);
                                    dirMaskCache[imm] = dMask;
                                }
                                if (((fMask & (int)FileSystemRights.Delete) != 0 || (dMask & delChildMask) != 0) && (dMask & addFileOrDacMask) != 0) {
                                    keepFs = true;
                                }
                            }
                        }
                    } else if (Directory.Exists(p)) {
                        int dMask;
                        if (!dirMaskCache.TryGetValue(p, out dMask)) {
                            var dAcl = Directory.GetAccessControl(p, AccessControlSections.Access | AccessControlSections.Owner);
                            dMask = GetFsLowMask(dAcl, userSid);
                            dirMaskCache[p] = dMask;
                        }
                        if ((dMask & writeOrDacMask) != 0) keepFs = true;
                    } else {
                        string imm = Path.GetDirectoryName(p);
                        bool immExists = !string.IsNullOrEmpty(imm) && Directory.Exists(imm);
                        string dir = imm;
                        while (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) dir = Path.GetDirectoryName(dir);
                        if (!string.IsNullOrEmpty(dir)) {
                            int dMask;
                            if (!dirMaskCache.TryGetValue(dir, out dMask)) {
                                var dAcl = Directory.GetAccessControl(dir, AccessControlSections.Access | AccessControlSections.Owner);
                                dMask = GetFsLowMask(dAcl, userSid);
                                dirMaskCache[dir] = dMask;
                            }
                            int needed = immExists ? addFileOrDacMask : addDirOrDacMask;
                            if ((dMask & needed) != 0) keepFs = true;
                        }
                    }
                } catch {}

                if (!keepFs) {
                    keysToRemove.Add(canonical);
                } else {
                    // Check if inside Temp or WER burst bucket and not an executable/script/config
                    bool isTempOrWer = (p.IndexOf(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase) >= 0) ||
                                       (p.IndexOf(@"\Windows\WER\", StringComparison.OrdinalIgnoreCase) >= 0);
                    if (isTempOrWer && !Regex.IsMatch(p, @"(?i)\.(exe|dll|sys|msi|msp|ocx|cpl|scr|bat|cmd|ps1|psm1|vbs|js|hta|wsf|config|xml|json|ini|inf|cer|crt|pfx|lnk|url)$")) {
                        var bestEvt = (Hashtable)rec["BestEvent"];
                        string bProc = (string)bestEvt["ProcessName"];
                        string bKey = bProc + "|" + (p.IndexOf(@"\Windows\WER\", StringComparison.OrdinalIgnoreCase) >= 0 ? "WER" : "TEMP");
                        List<KeyValuePair<string, int>> list;
                        if (!tempBurstBuckets.TryGetValue(bKey, out list)) {
                            list = new List<KeyValuePair<string, int>>();
                            tempBurstBuckets[bKey] = list;
                        }
                        list.Add(new KeyValuePair<string, int>(canonical, (int)rec["BestScore"]));
                    }
                }
            }

            foreach (var k in keysToRemove) pathMap.Remove(k);

            foreach (var bkv in tempBurstBuckets) {
                var list = bkv.Value;
                if (list.Count > 10) {
                    list.Sort((a, b) => b.Value.CompareTo(a.Value));
                    for (int i = 10; i < list.Count; i++) {
                        pathMap.Remove(list[i].Key);
                    }
                }
            }
        }
    }
}
"@ -Language CSharp -ErrorAction Stop
    }
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        if ($drive.DriveType -eq 'Fixed' -or $drive.DriveType -eq 'Removable') {
            $letter = $drive.Name.TrimEnd('\')
            $devPath = [Win32DeviceMap.DosDeviceHelper]::GetDevicePath($letter)
            if ($devPath) { $script:_driveMap[$devPath.ToLowerInvariant()] = $letter }
        }
    }
} catch {
    Write-Host "[!] Warning compiling Win32DeviceMap C# accelerator: $($_.Exception.Message)" -ForegroundColor Yellow
}

function ConvertTo-NormalizedDisplayPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path.Trim()
    # \??\X: -> X:
    $p = $p -replace '^\\\?\?\\', ''
    # \Device\NamedPipe\foo -> \\.\pipe\foo
    $p = $p -replace '(?i)^\\Device\\NamedPipe\\', '\\.\pipe\'
    # \Device\HarddiskVolume<N>\... -> <Drive>:\...
    if ($p -match '^(?i)(\\Device\\HarddiskVolume\d+)(\\|$)(.*)$') {
        $vol = $matches[1].ToLowerInvariant()
        $sep = $matches[2]
        $rest = $matches[3]
        if ($script:_driveMap.ContainsKey($vol)) {
            $letter = $script:_driveMap[$vol]
            $p = if ($sep) { "$letter\$rest" } else { "$letter\" }
        } elseif ($script:_driveMap.Count -eq 0) {
            $p = if ($sep) { "C:\$rest" } else { "C:\" }
        }
    }
    # Kernel registry paths -> standard hive names
    $p = $p -replace '(?i)^\\REGISTRY\\MACHINE(\\|$)', 'HKLM$1'
    $p = $p -replace '(?i)^\\REGISTRY\\USER(\\|$)', 'HKU$1'
    return $p
}

# Path canonicalization for deduplication purposes only — original path preserved.
function ConvertTo-CanonicalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = ConvertTo-NormalizedDisplayPath -Path $Path
    # Collapse trailing whitespace/separator
    $p = $p.TrimEnd()
    while ($p.Length -gt 3 -and ($p.EndsWith("\") -or $p.EndsWith("/"))) { $p = $p.Substring(0, $p.Length - 1) }
    # Collapse double-separators (except leading UNC \\)
    if ($p.StartsWith("\\")) {
        $p = "\\" + (($p.Substring(2)) -replace '\\\\+', '\')
    } else {
        $p = $p -replace '\\\\+', '\'
    }
    return $p.ToLowerInvariant()
}

# Self-trace contamination filter. We must NOT flag the trace pipeline's own
# writes/reads as findings.
function Test-SelfTraceContamination {
    param([string]$Path, [string]$ProcessName)
    $pl = if ($Path) { $Path.ToLowerInvariant() } else { "" }
    $procL = if ($ProcessName) { $ProcessName.ToLowerInvariant() } else { "" }

    # Process is part of the trace pipeline itself
    foreach ($proc in $script:_excludeProcSet) {
        if ($procL -eq $proc) { return $true }
    }

    # Path is the trace artifacts
    $traceArtifacts = @(
        '\rawtrace.etl',
        '\nativewritablepaths.csv',
        '\activeprocessessnapshot.json',
        '\writable_paths.json',
        '\high_confidence_leads.json',
        '\cognitive_review_queue.json',
        '\cognitive_review_queue.j',  # truncated chunked write
        '\parsing_errors.json',
        '\etw_providers.txt',
        '\execution_leads_report.md',
        '\testtrace.etl'
    )
    foreach ($t in $traceArtifacts) {
        if ($pl.EndsWith($t)) { return $true }
    }

    # Procmon launcher binaries
    if ($pl -match '\\(procmon|procmon64|tracerpt|logman)\.exe$') { return $true }

    # NativeTrace.ps1 (the user's own capture script)
    if ($pl -match '\\nativetrace\.ps1$') { return $true }

    return $false
}

$script:_excludeProcSet = @($ExcludeProcessTraces | ForEach-Object { $_.ToLowerInvariant() })

# Best-event scoring. Higher score = stronger evidence.
# Prioritization rationale (LPE prompt §2 + §6):
#   * SYSTEM/High > Medium IL (privileged consumer must never be buried by a
#     Medium-IL write on the same path)
#   * Privileged WRITE > Privileged READ (write-what-where is the strongest primitive)
#   * NAME NOT FOUND > SUCCESS (planting without race condition)
#   * Open Reparse Point present is a NEGATIVE signal but not a kill (LPE §2)
function Get-EventScore {
    param([hashtable]$Evt)
    $s = 0
    $opDir = Get-OperationDirection -Operation $Evt.Operation
    $intLower = if ($Evt.Integrity) { $Evt.Integrity.Trim().ToLowerInvariant() } else { "" }
    if ($intLower -eq "system" -or $intLower -eq "protected process") {
        $s += 220
    } elseif ($intLower -eq "high") {
        $s += 180
    }
    if ($opDir -eq "Write") { $s += 100 }
    if ($Evt.Result -match "(?i)NAME NOT FOUND")      { $s += 25 }
    if ($Evt.Result -match "(?i)PATH NOT FOUND")      { $s += 20 }
    if ($Evt.Result -match "(?i)REPARSE")             { $s += 10 }
    if ($Evt.IsPagingIO)        { $s -= 80 }   # demote, but don't drop
    if ($Evt.IsKernelOrCacheManager) { $s -= 30 }
    if ($Evt.OpenReparsePoint)  { $s -= 5 }    # informative not disqualifying
    if ($Evt.OpenLink)          { $s -= 5 }
    if ($Evt.Operation -match "(?i)Load Image") { $s += 60 } # Load Image strong signal
    return $s
}

# Detail-string flag parsing
function Get-DetailFlags {
    param([string]$Detail)
    $flags = @{
        IsPagingIO        = $false
        OpenReparsePoint  = $false
        OpenLink          = $false
        DeleteOnClose     = $false
        OpenForBackup     = $false
        SqosLevel         = "NotSpecified"
        DesiredAccess     = ""
        Disposition       = ""
        ShareMode         = ""
        RegistryDataPath  = ""
        CommandLine       = ""
    }
    if ([string]::IsNullOrWhiteSpace($Detail)) { return $flags }

    if ($Detail -match '(?i)Paging\s*I/?O') { $flags.IsPagingIO = $true }
    # Procmon Options field: "Open Reparse Point", "Delete On Close", "Open For Backup"
    if ($Detail -match '(?i)Open\s*Reparse\s*Point') { $flags.OpenReparsePoint = $true }
    if ($Detail -match '(?i)Delete\s*On\s*Close')    { $flags.DeleteOnClose    = $true }
    if ($Detail -match '(?i)Open\s*For\s*Backup')    { $flags.OpenForBackup    = $true }
    # Registry symlink open: "Open Link" or "REG_OPTION_OPEN_LINK"
    if ($Detail -match '(?i)Open\s*Link|REG_OPTION_OPEN_LINK|OBJ_OPENLINK') { $flags.OpenLink = $true }
    # SQOS impersonation level
    if ($Detail -match '(?i)Impersonation(?:\s*Level)?:\s*(Impersonation|Delegation|Identification|Anonymous)') {
        $flags.SqosLevel = $matches[1]
    }
    # Desired Access (captures full comma-separated list up to the next named field)
    if ($Detail -match '(?i)Desired\s*Access:\s*(.+?)(?:,\s*(?:Disposition|Options|ShareMode|Attributes|AllocationSize|OpenResult|Impersonating|Security\s*QOS):|$)') {
        $flags.DesiredAccess = $matches[1].Trim()
    }
    if ($Detail -match '(?i)Disposition:\s*([^,\r\n]+)') {
        $flags.Disposition = $matches[1].Trim()
    }
    if ($Detail -match '(?i)ShareMode:\s*(.+?)(?:,\s*(?:Attributes|Options|AllocationSize|OpenResult|Impersonating):|$)') {
        $flags.ShareMode = $matches[1].Trim()
    }
    # Registry value Data containing a filesystem or UNC path
    if ($Detail -match '(?i)\bData:\s*"?([a-zA-Z]:\\[^"\r\n,;]+|\\\\[^"\r\n,;]+)') {
        $flags.RegistryDataPath = $matches[1].Trim()
    }
    if ($Detail -match '(?i)Command\s*line:\s*(.+)$') {
        $flags.CommandLine = $matches[1].Trim()
    }
    return $flags
}

# ── STREAM PARSE ─────────────────────────────────────────────────────────────

$activeIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$activePrincipal = New-Object System.Security.Principal.WindowsPrincipal($activeIdentity)
$currentUserName = $activeIdentity.Name
$adminSidObj     = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")

$isAdminLatent = $false
foreach ($g in $activeIdentity.Groups) {
    if ($g.Equals($adminSidObj)) { $isAdminLatent = $true; break }
}
$isAdminElevated = $activePrincipal.IsInRole($adminSidObj)

$processIntegrity = "Medium"
try {
    $wamiOut = & whoami /groups 2>$null
    foreach ($line in $wamiOut) {
        if ($line -match 'Mandatory Label\\(\w+) Mandatory Level') {
            $processIntegrity = $matches[1]
            break
        }
    }
} catch { }

$userContext = @{
    UserSid               = $activeIdentity.User.Value
    UserName              = $currentUserName
    IsAdminLatent         = $isAdminLatent
    IsAdminElevated       = $isAdminElevated
    ProcessIntegrityLevel = $processIntegrity
}

$sw = [System.Diagnostics.Stopwatch]::StartNew()
$parseSummary = [Win32DeviceMap.ProcmonFastParser]::StreamAndAggregateCsv(
    $CsvPath,
    [string[]]$ExcludeProcessTraces,
    $script:_driveMap,
    $userContext.UserSid,
    $userContext.IsAdminLatent
)
$sw.Stop()

$pathProcessMap          = $parseSummary.PathMap
$processLineageMap       = $parseSummary.ProcessLineage
$lineCount               = $parseSummary.TotalLines
$script:skippedSelfTrace = $parseSummary.SkippedSelfTrace
$script:skippedPagingIO  = $parseSummary.SkippedPagingIO

$canonicalPaths = [string[]]$pathProcessMap.Keys
$totalCount = $canonicalPaths.Count
Write-Host "Parsed $lineCount lines in $($sw.Elapsed.TotalSeconds.ToString('0.00'))s. $totalCount candidate canonical paths retained for deep ACL inspection." -ForegroundColor Cyan
Write-Host "  - Skipped self-trace contamination rows: $script:skippedSelfTrace" -ForegroundColor DarkGray
Write-Host "  - Paging-I/O attributions detected (kept, marked): $script:skippedPagingIO" -ForegroundColor DarkGray
Write-Host "Starting safe permission tests (no destructive writes)..." -ForegroundColor Cyan

# ── PERSPECTIVE-AWARE WRITABILITY ────────────────────────────────────────────
#
# Get-PathWritability classifies one path against three writability
# perspectives. It is the heart of the rev-3 false-positive fixes.
#
# Why three perspectives:
#   * LowPriv        — a hypothetical standard-user (no Admin SID at all)
#                      token. Models the canonical LPE attacker.
#   * MediumILAdmin  — an admin's UAC-filtered medium-IL token. Admin SID is
#                      "deny-only", so admin grants don't count as writable;
#                      Mandatory Integrity Control's NW (no-write-up) flag
#                      blocks writes to High-IL labeled paths.
#   * HighILAdmin    — an elevated admin token. Admin grants count and MIC's
#                      NW restriction does not apply.
#
# Why not just trust Principal.IsInRole(adminSid) at runtime: that returns
# TRUE for split-token admins at medium IL because the Admin SID is present
# in the token, just with Use=DenyOnly. Using IsInRole conflated MediumIL
# admin with HighIL admin and produced dozens of false positives across the
# Windows tree in rev 2.
#
# Why we AND only against (WriteData | AppendData) instead of also Modify
# / FullControl: those two FileSystemRights values are UNION masks that
# include read bits. `-band Modify` matches any ACE with the ReadAndExecute
# bits set, which is most BUILTIN\Users grants in System32/Program Files.
# This single bug accounted for the bulk of the 7 Binary_Plant_HighPriv +
# 33 Windows-tree SMB_Coercion FPs in rev 2. WriteData|AppendData are pure
# bits; FullControl ACEs already match through them because FullControl
# sets every bit including those two.

# Pure plant bits — what "you can plant a file/junction/symlink here" means.
# NT generic access masks: filesystem WriteData|AppendData = 0x6, and registry
# SetValue|CreateSubKey are encoded onto the same bit positions (also 0x6),
# so the same mask works for both ACL families in Invoke-DaclEvaluation below.
$script:_plantBits = [int]([System.Security.AccessControl.FileSystemRights]::WriteData) -bor `
                     [int]([System.Security.AccessControl.FileSystemRights]::AppendData)
$script:_dacOwnerBits         = 0x00040000 -bor 0x00080000 # WRITE_DAC | WRITE_OWNER
$script:_deleteBit            = 0x00010000                 # DELETE
$script:_deleteChildBit       = 0x00000040                 # FILE_DELETE_CHILD
$script:_regCreateLinkBit     = 0x00000020                 # KEY_CREATE_LINK
$script:_pipeCreateInstBit    = 0x00000004                 # FILE_CREATE_PIPE_INSTANCE
$script:_pipeClientWriteBit   = 0x00000002                 # FILE_WRITE_DATA
$script:_appContainerSids     = @(
    'S-1-15-2-1',       # ALL APPLICATION PACKAGES
    'S-1-15-2-2'        # ALL RESTRICTED APPLICATION PACKAGES
)
$script:_dirEvalCache = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Hashtable]' ([System.StringComparer]::OrdinalIgnoreCase)

# SID classification. Names match the canonical well-known SIDs.
$script:_lowPrivSids = @(
    'S-1-1-0',          # Everyone
    'S-1-5-7',          # ANONYMOUS LOGON
    'S-1-5-11',         # Authenticated Users
    'S-1-5-32-545',     # BUILTIN\Users
    'S-1-5-4',          # INTERACTIVE
    'S-1-5-2',          # NETWORK
    'S-1-5-32-546'      # BUILTIN\Guests
)
$script:_adminSids = @(
    'S-1-5-32-544',     # BUILTIN\Administrators
    'S-1-5-32-548',     # BUILTIN\Account Operators
    'S-1-5-32-549',     # BUILTIN\Server Operators
    'S-1-5-32-551'      # BUILTIN\Backup Operators
)
# SYSTEM/TI/Service grants reach paths that neither low-priv nor admin tokens
# hold directly without service/SYSTEM impersonation.
$script:_systemSids = @(
    'S-1-5-18',         # SYSTEM
    'S-1-5-19',         # LOCAL SERVICE
    'S-1-5-20',         # NETWORK SERVICE
    'S-1-5-32-552',     # BUILTIN\Replicators
    'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464'  # NT SERVICE\TrustedInstaller
)
# CREATOR OWNER (S-1-3-0) is special — the ACE applies to the principal who
# eventually creates an object under this container. We do NOT count it as
# "writable now"; whether you can plant depends on the OTHER ACEs that let
# you create the entry first.

# Heuristic: paths under these directories are protected by High mandatory
# integrity label by default. SACL parsing requires SeSecurityPrivilege
# which is rarely held; this path-based check is a reliable proxy.
$script:_highILPathPatterns = @(
    '\Windows\System32\',
    '\Windows\SysWOW64\',
    '\Windows\Boot\',
    '\Windows\Fonts\',
    '\Windows\WinSxS\',
    '\Windows\servicing\',
    '\Program Files\',
    '\Program Files (x86)\'
)

# ── REGISTRY HELPERS (rev 3.2) ───────────────────────────────────────────────
#
# rev 3.1 left registry paths on a coarse heuristic (HKLM=admin-only,
# HKCU=everyone-writable) with no DACL parse. That silently under-reported
# real low-priv-writable HKLM subkeys (vendor-installed keys with permissive
# ACLs, misconfigured Performance subkeys) and missed conditional ACEs on
# HKLM entirely. rev 3.2 promotes registry to a first-class DACL parse.

# Translate a registry path string ("HKLM\Software\Foo", "HKEY_CURRENT_USER\..\Bar")
# into a (Hive, Subkey, RootName) triple. Long-form roots are normalised to
# short-form for matching, but the subkey portion preserves original case so
# OpenSubKey's case-insensitive lookup still works.
function Get-RegistryHiveAndSubkey {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    $p = $Path.Trim()
    $p = $p -replace '^HKEY_LOCAL_MACHINE\\?',   'HKLM\'
    $p = $p -replace '^HKEY_CURRENT_USER\\?',    'HKCU\'
    $p = $p -replace '^HKEY_CLASSES_ROOT\\?',    'HKCR\'
    $p = $p -replace '^HKEY_USERS\\?',           'HKU\'
    $p = $p -replace '^HKEY_CURRENT_CONFIG\\?',  'HKCC\'
    $p = $p -replace '^HKEY_PERFORMANCE_DATA\\?','HKPD\'

    $hive = $null; $sub = ""; $rootName = ""
    if     ($p -match '^HKLM\\?(.*)$') { $hive = [Microsoft.Win32.Registry]::LocalMachine;    $sub = $matches[1]; $rootName = "HKLM" }
    elseif ($p -match '^HKCU\\?(.*)$') { $hive = [Microsoft.Win32.Registry]::CurrentUser;     $sub = $matches[1]; $rootName = "HKCU" }
    elseif ($p -match '^HKCR\\?(.*)$') { $hive = [Microsoft.Win32.Registry]::ClassesRoot;     $sub = $matches[1]; $rootName = "HKCR" }
    elseif ($p -match '^HKU\\?(.*)$')  { $hive = [Microsoft.Win32.Registry]::Users;           $sub = $matches[1]; $rootName = "HKU" }
    elseif ($p -match '^HKCC\\?(.*)$') { $hive = [Microsoft.Win32.Registry]::CurrentConfig;   $sub = $matches[1]; $rootName = "HKCC" }
    elseif ($p -match '^HKPD\\?(.*)$') { $hive = [Microsoft.Win32.Registry]::PerformanceData; $sub = $matches[1]; $rootName = "HKPD" }
    else { return $null }

    return @{ Hive = $hive; Subkey = $sub; RootName = $rootName }
}

# Open the registry key at $Path (ancestor-walk style: the trace often gives
# us value paths like "...\BIOS\SystemSKU" which aren't keys, so step up to
# the parent key whose DACL governs SetValue rights). Returns a hashtable with
# the RegistrySecurity, the AclSource tag ("registry-exact" / "-ancestor" /
# "-hive-root" / "-denied" / "-bad-path"), and the resolved root name so the
# caller can decide IntegrityLabel + fallback behavior.
function Get-RegistryDaclForPath {
    param([string]$Path)
    $parts = Get-RegistryHiveAndSubkey -Path $Path
    if ($null -eq $parts) {
        return @{ Sec = $null; Source = "registry-bad-path"; RootName = "" }
    }

    $sub = $parts.Subkey
    while ($sub.EndsWith('\')) { $sub = $sub.Substring(0, $sub.Length - 1) }
    $exact = $true
    $depth = 0

    while ($depth -lt 32) {
        if ([string]::IsNullOrEmpty($sub)) {
            # Hive root — read its DACL directly. GetAccessControl on the hive
            # key itself works without needing OpenSubKey first.
            try {
                $sec = $parts.Hive.GetAccessControl()
                $src = if ($exact) { "registry-hive-root" } else { "registry-ancestor" }
                return @{ Sec = $sec; Source = $src; RootName = $parts.RootName }
            } catch {
                return @{ Sec = $null; Source = "registry-denied"; RootName = $parts.RootName }
            }
        }
        try {
            $key = $parts.Hive.OpenSubKey(
                $sub,
                [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
                [System.Security.AccessControl.RegistryRights]::ReadPermissions)
            if ($key) {
                try {
                    $sec = $key.GetAccessControl()
                    $src = if ($exact) { "registry-exact" } else { "registry-ancestor" }
                    return @{ Sec = $sec; Source = $src; RootName = $parts.RootName }
                } finally {
                    $key.Close()
                }
            }
        } catch {
            # OpenSubKey failed (key missing / no ReadPermissions). Walk up.
        }
        $lastSlash = $sub.LastIndexOf('\')
        if ($lastSlash -lt 0) { $sub = "" } else { $sub = $sub.Substring(0, $lastSlash) }
        $exact = $false
        $depth++
    }
    return @{ Sec = $null; Source = "registry-denied"; RootName = $parts.RootName }
}

# ── SHARED DACL EVALUATION (rev 3.2) ─────────────────────────────────────────
#
# Single-source-of-truth for the rules loop + conditional-ACE detection +
# writability flag computation. Used by both the FS and Registry branches of
# Get-PathWritability. The $Result hashtable is mutated in place — its
# WritableByLowPriv / WritableByMediumILAdmin / WritableByHighILAdmin /
# HasConditionalACE / ConditionalACEPrincipals / ConditionalACESddl fields
# are populated.
#
# Caller is responsible for:
#   * Determining the ACL object ($Acl) — FileSecurity or RegistrySecurity
#   * Choosing IsContainer correctly (true for directories and registry keys,
#     false for individual files)
#   * Setting IsRegistry so the rights extractor picks RegistryRights vs
#     FileSystemRights (the underlying mask bits coincide for plant rights,
#     but using the wrong concrete property would throw)
#   * Pre-setting Result.AclSource / Result.IntegrityLabel as appropriate
#   * Applying MIC NW (no-write-up) at the end if IntegrityLabel is High/System
function Invoke-DaclEvaluation {
    param(
        [Parameter(Mandatory=$true)] $Acl,
        [Parameter(Mandatory=$true)] [hashtable]$Result,
        [Parameter(Mandatory=$true)] [hashtable]$UserContext,
        [Parameter(Mandatory=$true)] [bool]$IsContainer,
        [Parameter(Mandatory=$true)] [bool]$IsRegistry
    )

    $rules = $Acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    $effectiveWriteMask = $script:_plantBits -bor $script:_dacOwnerBits

    # Conditional / callback ACE detection via raw SDDL.
    $sddl = $null
    try { $sddl = $Acl.Sddl } catch { $sddl = $null }
    $unconditionalAllowSids = New-Object System.Collections.Generic.HashSet[string]
    $conditionalAllowSids   = New-Object System.Collections.Generic.HashSet[string]
    $unconditionalDenySids  = New-Object System.Collections.Generic.HashSet[string]
    $conditionalDenySids    = New-Object System.Collections.Generic.HashSet[string]
    if (-not [string]::IsNullOrWhiteSpace($sddl)) {
        # Check SACL for an explicit Mandatory Label (LW/ME/HI/SI) if present in SDDL
        if ($sddl -match 'S:\([^)]*ML[^)]*;;;(LW|ME|HI|SI|S-1-16-\d+)\)') {
            $mlToken = $matches[1]
            switch ($mlToken) {
                { $_ -eq 'SI' -or $_ -eq 'S-1-16-16384' } { $Result.IntegrityLabel = "System" }
                { $_ -eq 'HI' -or $_ -eq 'S-1-16-12288' } { $Result.IntegrityLabel = "High" }
                { $_ -eq 'LW' -or $_ -eq 'S-1-16-4096'  } { $Result.IntegrityLabel = "Low" }
                { $_ -eq 'ME' -or $_ -eq 'S-1-16-8192'  } { $Result.IntegrityLabel = "Medium" }
            }
        }
        try {
            $csd = New-Object System.Security.AccessControl.CommonSecurityDescriptor(
                $IsContainer, $false, $sddl)
            foreach ($ace in $csd.DiscretionaryAcl) {
                if (-not ($ace -is [System.Security.AccessControl.CommonAce])) { continue }
                $aceMask = [int]$ace.AccessMask
                if (($aceMask -band $effectiveWriteMask) -eq 0) { continue }
                $aceSid  = $ace.SecurityIdentifier.Value
                $aceType = $ace.AceType
                $isAllow = ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) `
                        -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedCallback) `
                        -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedObject) `
                        -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedCallbackObject)
                $isDenyAce = ($aceType -eq [System.Security.AccessControl.AceType]::AccessDenied) `
                          -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedCallback) `
                          -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedObject) `
                          -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedCallbackObject)
                $isCallback = ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedCallback) `
                           -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedCallbackObject) `
                           -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedCallback) `
                           -or ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedCallbackObject)
                if ($isAllow) {
                    if ($isCallback) { [void]$conditionalAllowSids.Add($aceSid) }
                    else             { [void]$unconditionalAllowSids.Add($aceSid) }
                } elseif ($isDenyAce) {
                    if ($isCallback) { [void]$conditionalDenySids.Add($aceSid) }
                    else             { [void]$unconditionalDenySids.Add($aceSid) }
                }
            }
            if ($conditionalAllowSids.Count -gt 0 -or $conditionalDenySids.Count -gt 0) {
                $Result.ConditionalACESddl = $sddl
            }
        } catch {
            # SDDL parser hiccup — fall through to standard rule iteration.
        }
    }

    $allowedLow = $false; $deniedLow = $false
    $allowedMed = $false; $deniedMed = $false
    $allowedHigh = $false; $deniedHigh = $false
    $allowedAppContainer = $false; $deniedAppContainer = $false
    $allowCreateFilesLow = $false; $denyCreateFilesLow = $false
    $allowCreateDirsLow  = $false; $denyCreateDirsLow  = $false
    $hasOwnerRightsAce = $false
    $flaggedConditionalSids = New-Object System.Collections.Generic.HashSet[string]
    $serviceSids = New-Object System.Collections.Generic.HashSet[string]

    foreach ($rule in $rules) {
        $sid = $rule.IdentityReference.Value
        if ($sid -eq 'S-1-3-0') { continue } # CREATOR OWNER
        if ($sid -eq 'S-1-3-4') { $hasOwnerRightsAce = $true }
        if ($script:_systemSids -contains $sid) { continue }

        $rights = if ($IsRegistry) {
            [int]$rule.RegistryRights
        } else {
            [int]$rule.FileSystemRights
        }
        $isDeny = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)

        # Track per-service SIDs (S-1-5-80-*) that hold modification rights
        if (-not $isDeny -and $sid -match '^S-1-5-80-' -and (($rights -band $effectiveWriteMask) -ne 0)) {
            [void]$serviceSids.Add($sid)
            continue
        }

        # Track AppContainer SIDs (S-1-15-2-1 / S-1-15-2-2)
        if ($script:_appContainerSids -contains $sid -and (($rights -band $effectiveWriteMask) -ne 0)) {
            if ($isDeny) { $deniedAppContainer = $true }
            else         { $allowedAppContainer = $true }
        }

        $isLowOrUser = ($script:_lowPrivSids -contains $sid) -or ($sid -eq $UserContext.UserSid -and -not $UserContext.IsAdminLatent)
        $isMedUser   = ($sid -eq $UserContext.UserSid -and $UserContext.IsAdminLatent)

        # Check auxiliary permission bits (DELETE, FILE_DELETE_CHILD, KEY_CREATE_LINK, WRITE_DAC/WRITE_OWNER)
        if (-not $isDeny -and ($isLowOrUser -or $isMedUser)) {
            if (($rights -band $script:_dacOwnerBits) -ne 0) {
                $Result.CanWriteDacOrOwner = $true
            }
            if (-not $IsRegistry -and (($rights -band $script:_deleteBit) -ne 0)) {
                $Result.CanDeleteSelf = $true
            }
            if (-not $IsRegistry -and $IsContainer -and (($rights -band $script:_deleteChildBit) -ne 0)) {
                $Result.CanDeleteChild = $true
            }
            if ($IsRegistry -and (($rights -band $script:_regCreateLinkBit) -ne 0) -and (($rights -band 0x2) -ne 0)) {
                $Result.CanCreateRegLink = $true
            }
        }

        if (-not $IsRegistry -and $IsContainer -and $isLowOrUser) {
            if ((($rights -band 0x2) -ne 0) -or (($rights -band $script:_dacOwnerBits) -ne 0)) {
                if ($isDeny) { $denyCreateFilesLow = $true } else { $allowCreateFilesLow = $true }
            }
            if ((($rights -band 0x4) -ne 0) -or (($rights -band $script:_dacOwnerBits) -ne 0)) {
                if ($isDeny) { $denyCreateDirsLow = $true } else { $allowCreateDirsLow = $true }
            }
        }

        if (($rights -band $effectiveWriteMask) -eq 0) { continue }

        # Conditional-ACE handling — symmetric across Allow and Deny (rev 3.2)
        if (-not $isDeny -and $conditionalAllowSids.Contains($sid)) {
            $Result.HasConditionalACE = $true
            [void]$flaggedConditionalSids.Add($sid)
            if (-not $unconditionalAllowSids.Contains($sid)) {
                continue
            }
        }
        if ($isDeny -and $conditionalDenySids.Contains($sid)) {
            $Result.HasConditionalACE = $true
            [void]$flaggedConditionalSids.Add($sid)
            if (-not $unconditionalDenySids.Contains($sid)) {
                continue
            }
        }

        if ($script:_lowPrivSids -contains $sid) {
            if ($isDeny) {
                $deniedLow = $true; $deniedMed = $true; $deniedHigh = $true
            } else {
                $allowedLow = $true; $allowedMed = $true; $allowedHigh = $true
            }
            continue
        }

        if ($script:_adminSids -contains $sid) {
            if ($isDeny) {
                $deniedMed = $true; $deniedHigh = $true
            } else {
                $allowedHigh = $true
            }
            continue
        }

        if ($sid -eq $UserContext.UserSid) {
            if ($UserContext.IsAdminLatent) {
                if ($isDeny) { $deniedMed = $true; $deniedHigh = $true }
                else         { $allowedMed = $true; $allowedHigh = $true }
            } else {
                if ($isDeny) {
                    $deniedLow = $true; $deniedMed = $true; $deniedHigh = $true
                } else {
                    $allowedLow = $true; $allowedMed = $true; $allowedHigh = $true
                }
            }
            continue
        }
    }

    # Check object Owner SID: in Windows, the Owner implicitly holds WRITE_DAC
    # unless constrained by an explicit S-1-3-4 (OWNER_RIGHTS) ACE.
    if (-not $hasOwnerRightsAce) {
        try {
            $ownerRef = $Acl.GetOwner([System.Security.Principal.SecurityIdentifier])
            if ($null -ne $ownerRef -and -not [string]::IsNullOrWhiteSpace($ownerRef.Value)) {
                $ownerSid = $ownerRef.Value
                $Result.OwnerSid = $ownerSid
                if (($script:_lowPrivSids -contains $ownerSid) -or ($ownerSid -eq $UserContext.UserSid -and -not $UserContext.IsAdminLatent)) {
                    $Result.CanWriteDacOrOwner = $true
                    $allowedLow = $true; $allowedMed = $true; $allowedHigh = $true
                    $allowCreateFilesLow = $true; $allowCreateDirsLow = $true
                } elseif ($ownerSid -eq $UserContext.UserSid -and $UserContext.IsAdminLatent) {
                    $Result.CanWriteDacOrOwner = $true
                    $allowedMed = $true; $allowedHigh = $true
                }
            }
        } catch {}
    }

    $Result.WritableByLowPriv       = $allowedLow  -and -not $deniedLow
    $Result.WritableByMediumILAdmin = $allowedMed  -and -not $deniedMed
    $Result.WritableByHighILAdmin   = $allowedHigh -and -not $deniedHigh
    $Result.CanCreateFilesLow       = $allowCreateFilesLow -and -not $denyCreateFilesLow
    $Result.CanCreateDirsLow        = $allowCreateDirsLow  -and -not $denyCreateDirsLow
    $Result.WritableByAppContainer  = ($allowedAppContainer -or $Result.WritableByLowPriv) -and (-not $deniedAppContainer) -and ($Result.IntegrityLabel -eq "Low")
    if ($serviceSids.Count -gt 0) {
        $Result.WritableServiceSids = @($serviceSids)
    }

    if ($flaggedConditionalSids.Count -gt 0) {
        $Result.ConditionalACEPrincipals = @($flaggedConditionalSids)
    }
}

function Test-TopLevelProtectedRoot {
    param([string]$DirPath)
    if ([string]::IsNullOrWhiteSpace($DirPath)) { return $true }
    $d = $DirPath.TrimEnd('\')
    if ($d -match '^[a-zA-Z]:$') { return $true }
    if ($d -match '^(?i)[a-zA-Z]:\\(Windows|Program Files|Program Files \(x86\)|ProgramData|Users|System Volume Information|\$Recycle\.Bin)$') { return $true }
    if ($d -match '^(?i)[a-zA-Z]:\\Users\\[^\\]+$') { return $true }
    return $false
}

function Get-DirectoryWritabilityCached {
    param(
        [Parameter(Mandatory=$true)] [string]$DirPath,
        [Parameter(Mandatory=$true)] [hashtable]$UserContext
    )
    $key = $DirPath.TrimEnd('\')
    if ($script:_dirEvalCache.ContainsKey($key)) {
        return $script:_dirEvalCache[$key]
    }
    $dRes = @{
        WritableByLowPriv       = $false
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin   = $false
        WritableByAppContainer  = $false
        CanWriteDacOrOwner      = $false
        CanDeleteSelf           = $false
        CanDeleteChild          = $false
        CanCreateFilesLow       = $false
        CanCreateDirsLow        = $false
        CanCreateRegLink        = $false
        IntegrityLabel          = "Default"
        OwnerSid                = ""
        WritableServiceSids     = @()
        HasConditionalACE       = $false
        ConditionalACEPrincipals = @()
        ConditionalACESddl      = ""
    }
    try {
        foreach ($pat in $script:_highILPathPatterns) {
            if (($DirPath + '\') -like ('*' + $pat + '*')) {
                $dRes.IntegrityLabel = "High"
                break
            }
        }
        if ($dRes.IntegrityLabel -eq "Default" -and $DirPath -match '(?i)\\Windows\\?$') {
            $dRes.IntegrityLabel = "High"
        }
        $dAcl = Get-Acl -LiteralPath $DirPath -ErrorAction Stop
        if ($null -ne $dAcl) {
            Invoke-DaclEvaluation -Acl $dAcl -Result $dRes -UserContext $UserContext -IsContainer $true -IsRegistry $false
            if ($dRes.IntegrityLabel -eq "Default") {
                $lblSddl = [Win32DeviceMap.DosDeviceHelper]::GetMandatoryLabelSddl($DirPath, 1)
                if ($lblSddl -match 'S:\([^)]*ML[^)]*;;;(LW|ME|HI|SI|S-1-16-\d+)\)') {
                    $mlTok = $matches[1]
                    if ($mlTok -eq 'SI' -or $mlTok -eq 'S-1-16-16384') { $dRes.IntegrityLabel = "System" }
                    elseif ($mlTok -eq 'HI' -or $mlTok -eq 'S-1-16-12288') { $dRes.IntegrityLabel = "High" }
                    elseif ($mlTok -eq 'LW' -or $mlTok -eq 'S-1-16-4096') { $dRes.IntegrityLabel = "Low" }
                }
            }
            if ($dRes.IntegrityLabel -eq "High" -or $dRes.IntegrityLabel -eq "System") {
                $dRes.WritableByLowPriv       = $false
                $dRes.WritableByMediumILAdmin = $false
                $dRes.CanDeleteSelf           = $false
                $dRes.CanDeleteChild          = $false
                $dRes.CanCreateFilesLow       = $false
                $dRes.CanCreateDirsLow        = $false
            }
        }
    } catch {}
    $script:_dirEvalCache[$key] = $dRes
    return $dRes
}

function Get-PathWritability {
    param(
        [Parameter(Mandatory=$true)] [string]$TargetPath,
        [Parameter(Mandatory=$true)] [hashtable]$UserContext,
        [bool]$HasNameNotFound = $false
    )

    $r = @{
        WritableByLowPriv         = $false
        WritableByMediumILAdmin   = $false
        WritableByHighILAdmin     = $false
        WritableByAppContainer    = $false
        CanWriteDacOrOwner        = $false
        CanDeleteSelf             = $false
        CanDeleteChild            = $false
        CanCreateFilesLow         = $false
        CanCreateDirsLow          = $false
        CanDeleteOrReplace        = $false
        HasWritableAncestor       = $false
        WritableAncestorPath      = ""
        CanCreateRegLink          = $false
        CanCreatePipeInstance     = $false
        CanWritePipeClient        = $false
        OwnerSid                  = ""
        WritableServiceSids       = @()
        IntegrityLabel            = "Default"
        AclSource                 = "none"
        HasConditionalACE         = $false
        ConditionalACEPrincipals  = @()
        ConditionalACESddl        = ""
    }

    try {
        # Named pipe namespace (\\.\pipe\...): read-only check.
        if ($TargetPath -match '^\\\\\.\\pipe\\') {
            $r.WritableByHighILAdmin = $true
            $pipeAcl = $null
            try { $pipeAcl = Get-Acl -LiteralPath $TargetPath -ErrorAction Stop } catch { $pipeAcl = $null }
            if ($null -ne $pipeAcl) {
                $pipeRules = $pipeAcl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
                $allowInstLow = $false; $denyInstLow = $false
                $allowWriteLow = $false; $denyWriteLow = $false
                foreach ($pr in $pipeRules) {
                    $pSid = $pr.IdentityReference.Value
                    $pRights = [int]$pr.FileSystemRights
                    $pDeny = ($pr.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)
                    if (($script:_lowPrivSids -contains $pSid) -or ($pSid -eq $UserContext.UserSid -and -not $UserContext.IsAdminLatent)) {
                        if (($pRights -band $script:_pipeCreateInstBit) -ne 0) {
                            if ($pDeny) { $denyInstLow = $true } else { $allowInstLow = $true }
                        }
                        if (($pRights -band $script:_pipeClientWriteBit) -ne 0) {
                            if ($pDeny) { $denyWriteLow = $true } else { $allowWriteLow = $true }
                        }
                    }
                }
                $r.CanCreatePipeInstance = ($allowInstLow -and -not $denyInstLow) -or $HasNameNotFound
                $r.CanWritePipeClient    = ($allowWriteLow -and -not $denyWriteLow)
                $r.WritableByLowPriv     = ($r.CanCreatePipeInstance -or $r.CanWritePipeClient)
                $r.WritableByMediumILAdmin = $r.WritableByLowPriv
                $r.AclSource             = if ($HasNameNotFound) { "named-pipe-unbound-in-trace" } else { "named-pipe-live-dacl" }
            } else {
                $r.CanCreatePipeInstance   = $true
                $r.CanWritePipeClient      = $true
                $r.WritableByLowPriv       = $true
                $r.WritableByMediumILAdmin = $true
                $r.AclSource               = "named-pipe-namespace"
            }
            return $r
        }

        # Registry — proper DACL parse (rev 3.2/3.4).
        if ($TargetPath -match '^(HKLM|HKCU|HKCR|HKU|HKCC|HKPD|HKEY_)') {
            $regResult = Get-RegistryDaclForPath -Path $TargetPath
            $r.AclSource = $regResult.Source
            if ($null -ne $regResult.Sec) {
                Invoke-DaclEvaluation -Acl $regResult.Sec -Result $r `
                    -UserContext $UserContext -IsContainer $true -IsRegistry $true
                if ($r.IntegrityLabel -eq "High" -or $r.IntegrityLabel -eq "System") {
                    $r.WritableByLowPriv       = $false
                    $r.WritableByMediumILAdmin = $false
                    $r.CanCreateRegLink        = $false
                }
            } else {
                if ($regResult.RootName -eq 'HKCU' -or $regResult.RootName -eq 'HKU') {
                    $r.WritableByLowPriv       = $true
                    $r.WritableByMediumILAdmin = $true
                    $r.WritableByHighILAdmin   = $true
                    $r.CanCreateRegLink        = $true
                } else {
                    $r.IntegrityLabel        = "High"
                    $r.WritableByHighILAdmin = $true
                }
            }
            return $r
        }

        # Filesystem: pick the right ACL bearer (100% read-only; NEVER opens or writes to files).
        $aclTarget = $null
        $treatAsExistingFile = $false
        $immediateParent = [System.IO.Path]::GetDirectoryName($TargetPath)
        $immExists = (-not [string]::IsNullOrWhiteSpace($immediateParent)) -and [System.IO.Directory]::Exists($immediateParent)
        if ([System.IO.File]::Exists($TargetPath)) {
            $aclTarget = $TargetPath
            $treatAsExistingFile = $true
            $r.AclSource = "exact-file"
        } elseif ([System.IO.Directory]::Exists($TargetPath)) {
            $aclTarget = $TargetPath
            $r.AclSource = "exact-directory"
        } else {
            $dir = $immediateParent
            while (-not [string]::IsNullOrWhiteSpace($dir) -and -not [System.IO.Directory]::Exists($dir)) {
                $dir = [System.IO.Path]::GetDirectoryName($dir)
            }
            if ([string]::IsNullOrWhiteSpace($dir)) { return $r }
            $aclTarget = $dir
            $r.AclSource = "ancestor"
        }

        # Tag integrity label by path heuristic first
        foreach ($pat in $script:_highILPathPatterns) {
            if ($aclTarget -like ('*' + $pat + '*')) {
                $r.IntegrityLabel = "High"
                break
            }
        }
        if ($r.IntegrityLabel -eq "Default" -and $aclTarget -match '(?i)\\Windows\\?$') {
            $r.IntegrityLabel = "High"
        }

        # Pull DACL read-only
        $acl = $null
        try {
            $acl = Get-Acl -LiteralPath $aclTarget -ErrorAction Stop
        } catch {
            $r.AclSource = $r.AclSource + "-denied"
        }

        if ($null -ne $acl) {
            $isContainerAcl = [System.IO.Directory]::Exists($aclTarget)
            Invoke-DaclEvaluation -Acl $acl -Result $r `
                -UserContext $UserContext -IsContainer $isContainerAcl -IsRegistry $false

            # Query LABEL_SECURITY_INFORMATION (0x10) when IntegrityLabel is still Default
            if ($r.IntegrityLabel -eq "Default") {
                try {
                    $lblSddl = [Win32DeviceMap.DosDeviceHelper]::GetMandatoryLabelSddl($aclTarget, 1)
                    if ($lblSddl -match 'S:\([^)]*ML[^)]*;;;(LW|ME|HI|SI|S-1-16-\d+)\)') {
                        $mlTok = $matches[1]
                        if ($mlTok -eq 'SI' -or $mlTok -eq 'S-1-16-16384') { $r.IntegrityLabel = "System" }
                        elseif ($mlTok -eq 'HI' -or $mlTok -eq 'S-1-16-12288') { $r.IntegrityLabel = "High" }
                        elseif ($mlTok -eq 'LW' -or $mlTok -eq 'S-1-16-4096') {
                            $r.IntegrityLabel = "Low"
                            if ($r.WritableByLowPriv) { $r.WritableByAppContainer = $true }
                        }
                    }
                } catch {}
            }

            if ($r.IntegrityLabel -eq "High" -or $r.IntegrityLabel -eq "System") {
                $r.WritableByLowPriv       = $false
                $r.WritableByMediumILAdmin = $false
                $r.CanDeleteSelf           = $false
                $r.CanDeleteChild          = $false
                $r.CanCreateFilesLow       = $false
                $r.CanCreateDirsLow        = $false
                $r.CanWriteDacOrOwner      = $false
            }

            # When the target does not exist (AclSource = ancestor):
            # - If its immediate parent directory exists, creating a file directly inside it requires FILE_ADD_FILE (0x2).
            # - If intermediate directories are missing, creating the missing subdirectory requires FILE_ADD_SUBDIRECTORY (0x4).
            if ($r.AclSource -eq "ancestor") {
                if ($immExists) {
                    if (-not $r.CanCreateFilesLow) {
                        $r.WritableByLowPriv       = $false
                        $r.WritableByMediumILAdmin = $false
                    }
                } else {
                    if (-not $r.CanCreateDirsLow) {
                        $r.WritableByLowPriv       = $false
                        $r.WritableByMediumILAdmin = $false
                    } elseif (-not (Test-TopLevelProtectedRoot -DirPath $aclTarget)) {
                        $r.HasWritableAncestor  = $true
                        $r.WritableAncestorPath = $aclTarget
                    }
                }
            }
        }

        # Ancestor-Chain & Parent Delete-Recreate Walk (rev 3.4, 100% read-only):
        # 1. If the target is an existing file that isn't directly writable, check if its
        #    immediate parent directory allows FILE_ADD_FILE (CanCreateFilesLow) AND either
        #    the file grants DELETE or the parent grants FILE_DELETE_CHILD (0x40).
        # 2. Walk existing intermediate ancestor directories (below top-level roots) to detect
        #    whether an existing intermediate directory can be deleted/renamed and replaced.
        if ($immExists -and -not (Test-TopLevelProtectedRoot -DirPath $immediateParent)) {
            $parentEval = Get-DirectoryWritabilityCached -DirPath $immediateParent -UserContext $UserContext
            if ($treatAsExistingFile -and ($r.CanDeleteSelf -or $parentEval.CanDeleteChild) -and $parentEval.CanCreateFilesLow) {
                $r.CanDeleteOrReplace = $true
                if (-not $r.WritableByLowPriv) {
                    $r.WritableByLowPriv       = $true
                    $r.WritableByMediumILAdmin = $true
                    $r.WritableByHighILAdmin   = $true
                    $r.AclSource               = "parent-delete-recreate"
                }
            }
        }

        $ancDir = $immediateParent
        $ancDepth = 0
        while (-not [string]::IsNullOrWhiteSpace($ancDir) -and $ancDepth -lt 16) {
            if (Test-TopLevelProtectedRoot -DirPath $ancDir) { break }
            if ([System.IO.Directory]::Exists($ancDir)) {
                $ancParent = [System.IO.Path]::GetDirectoryName($ancDir)
                if (-not [string]::IsNullOrWhiteSpace($ancParent) -and [System.IO.Directory]::Exists($ancParent)) {
                    $ancEval = Get-DirectoryWritabilityCached -DirPath $ancDir -UserContext $UserContext
                    $ancParentEval = Get-DirectoryWritabilityCached -DirPath $ancParent -UserContext $UserContext
                    if (($ancEval.CanDeleteSelf -or $ancParentEval.CanDeleteChild) -and $ancParentEval.CanCreateDirsLow) {
                        $r.HasWritableAncestor  = $true
                        $r.WritableAncestorPath = $ancDir
                        if (-not $r.WritableByLowPriv) {
                            $r.WritableByLowPriv       = $true
                            $r.WritableByMediumILAdmin = $true
                            $r.WritableByHighILAdmin   = $true
                            $r.AclSource               = "ancestor-dir-replaceable"
                        }
                        break
                    }
                }
            }
            $ancDir = [System.IO.Path]::GetDirectoryName($ancDir)
            $ancDepth++
        }

        return $r
    } catch {
        $script:skippedErrors.Add([PSCustomObject]@{ Type = "Permission Evaluation Error"; Path = $TargetPath; Error = $_.Exception.Message })
        return $r
    }
}

# Return the lowest-privilege perspective at which the path is writable.
# That value is what the analyzer maps to LPE / UAC_Bypass / Admin_To_System.
function Get-LowestWritablePerspective {
    param([hashtable]$Writability)
    if ($Writability.WritableByLowPriv)       { return "LowPriv" }
    if ($Writability.WritableByMediumILAdmin) { return "MediumILAdmin" }
    if ($Writability.WritableByHighILAdmin)   { return "HighILAdmin" }
    return "None"
}

# ── EXECUTION ────────────────────────────────────────────────────────────────

$counter = 0
$results = New-Object System.Collections.Generic.List[PSCustomObject]
$swTest = [System.Diagnostics.Stopwatch]::StartNew()

Write-Host "Current user context:" -ForegroundColor Cyan
Write-Host "  User:                     $($userContext.UserName) ($($userContext.UserSid))" -ForegroundColor DarkGray
Write-Host "  Process integrity level:  $($userContext.ProcessIntegrityLevel)" -ForegroundColor DarkGray
Write-Host "  Admin SID present:        $($userContext.IsAdminLatent) (latent)" -ForegroundColor DarkGray
Write-Host "  Admin SID active:         $($userContext.IsAdminElevated) (elevated)" -ForegroundColor DarkGray
if ($isAdminLatent -and -not $isAdminElevated) {
    Write-Host "  -> Split-token admin at medium IL. UAC-bypass research surface is in scope." -ForegroundColor DarkYellow
}

foreach ($canonical in $canonicalPaths) {
    if ($counter % 100 -eq 0 -or $counter -eq $totalCount) {
        Write-Progress -Activity "Testing Permissions" -Status "Testing: $canonical" -PercentComplete (($counter / [Math]::Max(1, $totalCount)) * 100)
        Write-Output "[PROGRESS] $counter / $totalCount Evaluating File/ACL Permissions..."
    }
    $counter++

    $rec = $pathProcessMap[$canonical]
    $displayPath = $rec.Path

    $writability = Get-PathWritability -TargetPath $displayPath -UserContext $userContext -HasNameNotFound ([bool]$rec.HasNameNotFound)
    $lowestPersp = Get-LowestWritablePerspective -Writability $writability

    # Skip paths writable by NONE of our perspectives (unless they carry a RegistryDataPath reference).
    if ($lowestPersp -eq "None" -and $rec.RegistryDataPaths.Count -eq 0) { continue }

    # Whether the running token can ACTUALLY write (informational; depends on
    # current process IL + admin status).
    $currentCanWrite = $false
    if ($processIntegrity -eq "High" -or $processIntegrity -eq "System") {
        $currentCanWrite = $writability.WritableByHighILAdmin
    } elseif ($isAdminLatent) {
        $currentCanWrite = $writability.WritableByMediumILAdmin
    } else {
        $currentCanWrite = $writability.WritableByLowPriv
    }

    $relatedProcesses = ($rec.Processes -join ", ")
    $operationsList   = ($rec.Operations -join ", ")
    $bestEvt = $rec.BestEvent
    $cmdLineEntries = @()
    foreach ($pn in $rec.Processes) {
        if ($null -ne $processLineageMap -and $processLineageMap.ContainsKey($pn)) {
            $cmdLineEntries += "$pn`: $($processLineageMap[$pn])"
        }
    }
    $processCommandLines = ($cmdLineEntries -join " | ")
    $regDataPathList     = ($rec.RegistryDataPaths -join "; ")
    $hasVerifyThenLoad   = ([bool]$rec.HasReadOrCheckOp -and [bool]$rec.HasLoadOrExecOp)

    # User-only-consumed filter: every observed process is the current user's
    # own session and no privileged actor touches the path. The redirect
    # cannot reach anywhere the user couldn't reach already.
    $userOnlyConsumer = (-not $rec.AnyPrivWrite) -and (-not $rec.AnyPrivRead)
    $allOpenRP   = ($rec.OpenEventCount -gt 0) -and $rec.AllOpenReparsePoint
    $allOpenLink = ($rec.RegOpenEventCount -gt 0) -and $rec.AllOpenLink

    $results.Add([PSCustomObject]@{
        Path                    = $displayPath
        CanonicalPath           = $canonical
        FileExists              = ([System.IO.Directory]::Exists($displayPath) -or [System.IO.File]::Exists($displayPath))
        RelatedProcesses        = $relatedProcesses
        ProcessCommandLines     = $processCommandLines
        Operations              = $operationsList
        EventCount              = $rec.EventCount
        TraceFile               = $traceFileName
        Timestamp               = $bestEvt.Time
        Operation               = $bestEvt.Operation
        Result                  = $bestEvt.Result
        Detail                  = $bestEvt.Detail
        Integrity               = $bestEvt.Integrity
        HighestIntegrity        = $rec.HighestIntegrity
        Impersonating           = $bestEvt.Impersonating
        BestProcess             = $bestEvt.ProcessName
        DesiredAccess           = $bestEvt.DesiredAccess
        Disposition             = $bestEvt.Disposition
        ShareMode               = $bestEvt.ShareMode
        SqosLevel               = $bestEvt.SqosLevel
        IsPagingIO              = [bool]$bestEvt.IsPagingIO
        OpenReparsePoint        = [bool]$bestEvt.OpenReparsePoint
        OpenLink                = [bool]$bestEvt.OpenLink
        DeleteOnClose           = [bool]$bestEvt.DeleteOnClose
        OpenForBackup           = [bool]$bestEvt.OpenForBackup
        IsKernelAttribution     = [bool]$bestEvt.IsKernelOrCacheManager
        AnyWrite                = $rec.AnyWrite
        AnyRead                 = $rec.AnyRead
        AnyPrivWrite            = $rec.AnyPrivWrite
        AnyPrivRead             = $rec.AnyPrivRead
        AnyImpersonating        = $rec.AnyImpersonating
        AnyOpenReparsePoint     = $rec.AnyOpenReparsePoint
        AllOpenReparsePoint     = [bool]$allOpenRP
        AnyOpenLink             = $rec.AnyOpenLink
        AllOpenLink             = [bool]$allOpenLink
        AnyPagingIO             = $rec.AnyPagingIO
        HasDeleteOp             = [bool]$rec.HasDeleteOp
        HasSetSecurityOp        = [bool]$rec.HasSetSecurityOp
        HasRenameOp             = [bool]$rec.HasRenameOp
        HasOpenForBackup        = [bool]$rec.HasOpenForBackup
        HasBufferOverflow       = [bool]$rec.HasBufferOverflow
        HasSharedWriteOrDelete  = [bool]$rec.HasSharedWriteOrDelete
        HasVerifyThenLoad       = [bool]$hasVerifyThenLoad
        RegistryDataPath        = $regDataPathList
        IsUserOnlyConsumer      = $userOnlyConsumer
        # Perspective-aware writability (rev 3 / rev 3.4)
        WritableByLowPriv       = $writability.WritableByLowPriv
        WritableByMediumILAdmin = $writability.WritableByMediumILAdmin
        WritableByHighILAdmin   = $writability.WritableByHighILAdmin
        WritableByAppContainer  = [bool]$writability.WritableByAppContainer
        WritableFrom            = $lowestPersp
        CanWriteDacOrOwner      = [bool]$writability.CanWriteDacOrOwner
        CanDeleteSelf           = [bool]$writability.CanDeleteSelf
        CanDeleteChild          = [bool]$writability.CanDeleteChild
        CanDeleteOrReplace      = [bool]$writability.CanDeleteOrReplace
        HasWritableAncestor     = [bool]$writability.HasWritableAncestor
        WritableAncestorPath    = $writability.WritableAncestorPath
        CanCreateRegLink        = [bool]$writability.CanCreateRegLink
        CanCreatePipeInstance   = [bool]$writability.CanCreatePipeInstance
        CanWritePipeClient      = [bool]$writability.CanWritePipeClient
        OwnerSid                = $writability.OwnerSid
        WritableServiceSids     = @($writability.WritableServiceSids)
        IntegrityLabel          = $writability.IntegrityLabel
        AclSource               = $writability.AclSource
        HasConditionalACE        = [bool]$writability.HasConditionalACE
        ConditionalACEPrincipals = @($writability.ConditionalACEPrincipals)
        ConditionalACESddl       = $writability.ConditionalACESddl
        # Current-user context for the analyzer
        CurrentUserSid          = $userContext.UserSid
        CurrentUserIsAdminLatent   = $userContext.IsAdminLatent
        CurrentUserIsAdminElevated = $userContext.IsAdminElevated
        CurrentUserCanWrite     = $currentCanWrite
        CurrentProcessIntegrity = $userContext.ProcessIntegrityLevel
    })
}
Write-Progress -Activity "Testing Permissions" -Completed
$swTest.Stop()

Write-Host "Process Complete in $($swTest.Elapsed.TotalSeconds.ToString('0.00'))s. $( $results.Count ) writable paths found." -ForegroundColor Green
$conditionalCount = @($results | Where-Object { $_.HasConditionalACE }).Count
if ($conditionalCount -gt 0) {
    Write-Host "  - $conditionalCount path(s) had conditional/callback ACEs (Microsoft-restricted by SKU/capability/AppID). See HasConditionalACE / ConditionalACEPrincipals / ConditionalACESddl." -ForegroundColor DarkYellow
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$pluginDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptDir))
$outFolder = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath } else { $pluginDir }
if (-not (Test-Path $outFolder)) { New-Item -ItemType Directory -Force -Path $outFolder | Out-Null }

$jsonPath = Join-Path $outFolder "writable_paths.json"
if ($results.Count -eq 0) {
    "[]" | Out-File $jsonPath -Encoding UTF8
    Write-Host "No writable paths found. Exported empty array to $jsonPath" -ForegroundColor Yellow
} else {
    ConvertTo-Json -InputObject @($results) -Depth 4 | Out-File $jsonPath -Encoding UTF8
    Write-Host "Exported RAW results to $jsonPath" -ForegroundColor Green
}

if ($script:skippedErrors.Count -gt 0) {
    $errJsonPath = Join-Path $outFolder "parsing_errors.json"
    $uniqueErrors = @($script:skippedErrors | Group-Object Error | Select-Object Name, Count, @{Name="SampleDetails"; Expression={$_.Group[0].Details}}, @{Name="SamplePath"; Expression={$_.Group[0].Path}}, @{Name="Type"; Expression={$_.Group[0].Type}})
    ConvertTo-Json -InputObject $uniqueErrors -Depth 3 | Out-File $errJsonPath -Encoding UTF8
    Write-Host "[!] Logged $($script:skippedErrors.Count) unhandled errors (grouped to $($uniqueErrors.Count) unique patterns) to $errJsonPath" -ForegroundColor Yellow
}

if ($results.Count -gt 0 -and -not $Silent) {
    $results | Out-GridView -Title "RAW Writable Paths and Associated Processes"
}

Write-Host "[!] INSTRUCTION: Writable paths extracted. Agent should invoke 'Analyze-ExecutionLeads' skill now." -ForegroundColor Magenta
