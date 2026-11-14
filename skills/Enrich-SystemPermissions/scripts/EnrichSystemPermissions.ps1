param(
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = ".\system_permissions_audit.json",
    [Parameter(Mandatory=$false)]
    [int]$MaxWmiNamespaces = 60,
    [switch]$SkipWmi,
    [switch]$SkipHandles,
    [switch]$Silent
)

# ═══════════════════════════════════════════════════════════════════════════════
#  Enrich-SystemPermissions (Phase 2 — Rev 3.5)
#  100% Static & Read-Only Windows Subsystem Security Descriptor Auditor
#  Zero External Dependencies (Built-in .NET + Read-Only Win32/NT P/Invoke)
# ═══════════════════════════════════════════════════════════════════════════════

$swTotal = [System.Diagnostics.Stopwatch]::StartNew()
if (-not $Silent) {
    Write-Host "[*] Initiating Phase 2 Native Subsystem Permission Audit (100% Read-Only)..." -ForegroundColor Cyan
}

$csharpSubsystemCode = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace ProcmonPhase2Auditor {
    public static class SubsystemNativeAuditor {
        private const int SE_KERNEL_OBJECT = 6;
        private const int SE_SERVICE = 4;
        private const int SE_WINDOW_OBJECT = 5;
        private const uint DACL_SECURITY_INFORMATION = 0x00000004;
        private const uint OWNER_SECURITY_INFORMATION = 0x00000001;
        private const uint LABEL_SECURITY_INFORMATION = 0x00000010;
        private const uint READ_CONTROL = 0x00020000;
        private const uint SC_MANAGER_ENUMERATE_SERVICE = 0x0004;
        private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenSCManagerW(string lpMachineName, string lpDatabaseName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenServiceW(IntPtr hSCManager, string lpServiceName, uint dwDesiredAccess);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool QueryServiceObjectSecurity(
            IntPtr hService,
            uint dwSecurityInformation,
            byte[] lpSecurityDescriptor,
            uint cbBufSize,
            out uint pcbBytesNeeded);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool CloseServiceHandle(IntPtr hSCObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetProcessId(IntPtr Process);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool DuplicateHandle(
            IntPtr hSourceProcessHandle,
            IntPtr hSourceHandle,
            IntPtr hTargetProcessHandle,
            out IntPtr lpTargetHandle,
            uint dwDesiredAccess,
            bool bInheritHandle,
            uint dwOptions);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern bool GetTokenInformation(IntPtr TokenHandle, int TokenInformationClass, IntPtr TokenInformation, uint TokenInformationLength, out uint ReturnLength);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthority(IntPtr pSid, uint nSubAuthority);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern IntPtr GetSidSubAuthorityCount(IntPtr pSid);

        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern uint GetSecurityInfo(
            IntPtr handle,
            int ObjectType,
            uint SecurityInfo,
            out IntPtr ppsidOwner,
            out IntPtr ppsidGroup,
            out IntPtr ppDacl,
            out IntPtr ppSacl,
            out IntPtr ppSecurityDescriptor);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
            IntPtr SecurityDescriptor,
            uint RequestedStringSDRevision,
            uint SecurityInformation,
            out IntPtr StringSecurityDescriptor,
            out uint StringSecurityDescriptorLen);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr LocalFree(IntPtr hMem);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr FindWindowExW(IntPtr hwndParent, IntPtr hwndChildAfter, string lpszClass, string lpszWindow);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out int lpdwProcessId);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetClassNameW(IntPtr hWnd, StringBuilder lpClassName, int nMaxCount);

        [DllImport("user32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern int GetWindowTextW(IntPtr hWnd, StringBuilder lpString, int nMaxCount);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr OpenFileMappingW(uint dwDesiredAccess, bool bInheritHandle, string lpName);

        [DllImport("ntdll.dll")]
        private static extern uint NtQuerySystemInformation(
            int SystemInformationClass,
            IntPtr SystemInformation,
            uint SystemInformationLength,
            out uint ReturnLength);

        private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

        public class InheritedOrLeakedHandleInfo {
            public int Pid;
            public ushort ObjectTypeIndex;
            public uint HandleAttributes;
            public ulong HandleValue;
            public ulong ObjectPtr;
            public uint GrantedAccess;
        }

        public static List<InheritedOrLeakedHandleInfo> QueryInheritablePrivilegedHandles(HashSet<int> privPids) {
            List<InheritedOrLeakedHandleInfo> results = new List<InheritedOrLeakedHandleInfo>();
            const int SystemExtendedHandleInformation = 64;
            const uint STATUS_INFO_LENGTH_MISMATCH = 0xC0000004;
            uint size = 0x100000;
            IntPtr buf = IntPtr.Zero;
            int myPid = System.Diagnostics.Process.GetCurrentProcess().Id;
            IntPtr hSelfProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, myPid);
            IntPtr hSelfTok = IntPtr.Zero;
            if (hSelfProc != IntPtr.Zero) {
                OpenProcessToken(hSelfProc, 0x0008, out hSelfTok);
            }
            try {
                for (int attempt = 0; attempt < 6; attempt++) {
                    buf = Marshal.AllocHGlobal((int)size);
                    uint retLen = 0;
                    uint status = NtQuerySystemInformation(SystemExtendedHandleInformation, buf, size, out retLen);
                    if (status == STATUS_INFO_LENGTH_MISMATCH) {
                        Marshal.FreeHGlobal(buf);
                        buf = IntPtr.Zero;
                        size = (retLen > size) ? (retLen + 0x100000) : (size * 2);
                        continue;
                    }
                    if (status != 0) break;

                    int ptrSize = IntPtr.Size;
                    long count = (ptrSize == 8) ? Marshal.ReadInt64(buf, 0) : Marshal.ReadInt32(buf, 0);
                    int offset = ptrSize * 2;
                    int stride = (ptrSize == 8) ? 40 : 28;
                    int typeOffset = (ptrSize == 8) ? 30 : 18;

                    // Dynamically discover Process & Token ObjectTypeIndex from our own handles
                    ushort procTypeIdx = 7;
                    ushort tokTypeIdx = 5;
                    ulong selfProcVal = (ulong)hSelfProc.ToInt64();
                    ulong selfTokVal  = (ulong)hSelfTok.ToInt64();
                    for (long i = 0; i < count; i++) {
                        IntPtr entry = IntPtr.Add(buf, offset + (int)(i * stride));
                        int pid = (ptrSize == 8) ? (int)Marshal.ReadInt64(entry, 8) : Marshal.ReadInt32(entry, 4);
                        if (pid != myPid) continue;
                        ulong hVal = (ptrSize == 8) ? (ulong)Marshal.ReadInt64(entry, 16) : (uint)Marshal.ReadInt32(entry, 8);
                        ushort tIdx = (ushort)Marshal.ReadInt16(entry, typeOffset);
                        if (selfProcVal != 0 && hVal == selfProcVal) procTypeIdx = tIdx;
                        if (selfTokVal != 0  && hVal == selfTokVal)  tokTypeIdx  = tIdx;
                    }

                    // Collect kernel object pointers for Process/Token objects belonging to High/SYSTEM processes
                    Dictionary<ulong, int> privObjects = new Dictionary<ulong, int>();
                    for (long i = 0; i < count; i++) {
                        IntPtr entry = IntPtr.Add(buf, offset + (int)(i * stride));
                        ulong objPtr = (ptrSize == 8) ? (ulong)Marshal.ReadInt64(entry, 0) : (uint)Marshal.ReadInt32(entry, 0);
                        int pid = (ptrSize == 8) ? (int)Marshal.ReadInt64(entry, 8) : Marshal.ReadInt32(entry, 4);
                        ushort typeIdx = (ushort)Marshal.ReadInt16(entry, typeOffset);
                        if (typeIdx != procTypeIdx && typeIdx != tokTypeIdx) continue;

                        if (privPids.Contains(pid) && objPtr != 0 && !privObjects.ContainsKey(objPtr)) {
                            privObjects[objPtr] = pid;
                        }
                    }

                    // Second pass: find Medium/Low processes holding write/dup/impersonate handles to privileged Process/Token objects
                    if (privObjects.Count > 0) {
                        IntPtr curProc = GetCurrentProcess();
                        Dictionary<int, IntPtr> holderProcCache = new Dictionary<int, IntPtr>();
                        try {
                            for (long i = 0; i < count; i++) {
                                IntPtr entry = IntPtr.Add(buf, offset + (int)(i * stride));
                                ulong objPtr = (ptrSize == 8) ? (ulong)Marshal.ReadInt64(entry, 0) : (uint)Marshal.ReadInt32(entry, 0);
                                if (objPtr == 0) continue;
                                int pid = (ptrSize == 8) ? (int)Marshal.ReadInt64(entry, 8) : Marshal.ReadInt32(entry, 4);
                                if (pid == myPid || privPids.Contains(pid)) continue;
                                ushort typeIdx = (ushort)Marshal.ReadInt16(entry, typeOffset);
                                if (typeIdx != procTypeIdx && typeIdx != tokTypeIdx) continue;
                                uint access = (uint)Marshal.ReadInt32(entry, (ptrSize == 8) ? 24 : 12);
                                uint dangerousMask = (typeIdx == procTypeIdx) ? 0x000C00E2u : 0x000C0027u;
                                if ((access & dangerousMask) != 0 && privObjects.ContainsKey(objPtr) && results.Count < 200) {
                                    ulong hVal = (ptrSize == 8) ? (ulong)Marshal.ReadInt64(entry, 16) : (uint)Marshal.ReadInt32(entry, 8);
                                    // Verify the target object is genuinely High/SYSTEM (filtering out Medium-IL processes also held by csrss.exe)
                                    IntPtr hHolder;
                                    if (!holderProcCache.TryGetValue(pid, out hHolder)) {
                                        hHolder = OpenProcess(0x0040, false, pid); // PROCESS_DUP_HANDLE
                                        holderProcCache[pid] = hHolder;
                                    }
                                    bool confirmedPrivilegedTarget = false;
                                    if (hHolder != IntPtr.Zero) {
                                        IntPtr hDup = IntPtr.Zero;
                                        uint queryRight = (typeIdx == procTypeIdx) ? PROCESS_QUERY_LIMITED_INFORMATION : 0x0008u; // TOKEN_QUERY
                                        if (DuplicateHandle(hHolder, (IntPtr)(long)hVal, curProc, out hDup, queryRight, false, 0) && hDup != IntPtr.Zero) {
                                            try {
                                                if (typeIdx == procTypeIdx) {
                                                    int targetPid = GetProcessId(hDup);
                                                    if (targetPid > 0 && privPids.Contains(targetPid)) {
                                                        confirmedPrivilegedTarget = true;
                                                    }
                                                } else {
                                                    uint retLen2 = 0;
                                                    GetTokenInformation(hDup, 25, IntPtr.Zero, 0, out retLen2);
                                                    if (retLen2 > 0) {
                                                        IntPtr tBuf = Marshal.AllocHGlobal((int)retLen2);
                                                        try {
                                                            if (GetTokenInformation(hDup, 25, tBuf, retLen2, out retLen2)) {
                                                                IntPtr pSid = Marshal.ReadIntPtr(tBuf);
                                                                if (pSid != IntPtr.Zero) {
                                                                    byte subCnt = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                                                                    uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(pSid, (uint)(subCnt - 1)));
                                                                    if (rid >= 0x3000) confirmedPrivilegedTarget = true;
                                                                }
                                                            }
                                                        } finally {
                                                            Marshal.FreeHGlobal(tBuf);
                                                        }
                                                    }
                                                }
                                            } finally {
                                                CloseHandle(hDup);
                                            }
                                        }
                                    }
                                    if (confirmedPrivilegedTarget) {
                                        InheritedOrLeakedHandleInfo info = new InheritedOrLeakedHandleInfo();
                                        info.Pid = pid;
                                        info.ObjectTypeIndex = typeIdx;
                                        info.HandleAttributes = (uint)Marshal.ReadInt32(entry, (ptrSize == 8) ? 32 : 20);
                                        info.HandleValue = hVal;
                                        info.ObjectPtr = objPtr;
                                        info.GrantedAccess = access;
                                        results.Add(info);
                                    }
                                }
                            }
                        } finally {
                            foreach (IntPtr h in holderProcCache.Values) {
                                if (h != IntPtr.Zero) CloseHandle(h);
                            }
                        }
                    }
                    break;
                }
            } catch {
            } finally {
                if (hSelfTok != IntPtr.Zero) CloseHandle(hSelfTok);
                if (hSelfProc != IntPtr.Zero) CloseHandle(hSelfProc);
                if (buf != IntPtr.Zero) Marshal.FreeHGlobal(buf);
            }
            return results;
        }

        public static byte[] GetServiceSecurityDescriptorBytes(string serviceName) {
            IntPtr scm = OpenSCManagerW(null, null, SC_MANAGER_ENUMERATE_SERVICE);
            if (scm == IntPtr.Zero) return null;
            try {
                IntPtr svc = OpenServiceW(scm, serviceName, READ_CONTROL);
                if (svc == IntPtr.Zero) return null;
                try {
                    uint needed = 0;
                    uint info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
                    QueryServiceObjectSecurity(svc, info, new byte[0], 0, out needed);
                    if (needed == 0 || needed > 65536) return null;
                    byte[] buf = new byte[needed];
                    if (QueryServiceObjectSecurity(svc, info, buf, needed, out needed)) {
                        return buf;
                    }
                    return null;
                } finally {
                    CloseServiceHandle(svc);
                }
            } finally {
                CloseServiceHandle(scm);
            }
        }

        public static string GetProcessIntegrityLevel(int pid) {
            IntPtr hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
            if (hProc == IntPtr.Zero) hProc = OpenProcess(0x0400, false, pid);
            if (hProc == IntPtr.Zero) return "System";
            try {
                IntPtr hTok;
                if (!OpenProcessToken(hProc, 0x0008, out hTok)) return "Unknown";
                try {
                    uint retLen = 0;
                    GetTokenInformation(hTok, 25, IntPtr.Zero, 0, out retLen);
                    if (retLen == 0) return "Unknown";
                    IntPtr buf = Marshal.AllocHGlobal((int)retLen);
                    try {
                        if (!GetTokenInformation(hTok, 25, buf, retLen, out retLen)) return "Unknown";
                        IntPtr pSid = Marshal.ReadIntPtr(buf);
                        if (pSid == IntPtr.Zero) return "Unknown";
                        byte count = Marshal.ReadByte(GetSidSubAuthorityCount(pSid));
                        uint rid = (uint)Marshal.ReadInt32(GetSidSubAuthority(pSid, (uint)(count - 1)));
                        if (rid < 0x1000) return "Untrusted";
                        if (rid < 0x2000) return "Low";
                        if (rid < 0x2010) return "Medium";
                        if (rid < 0x3000) return "Medium Plus";
                        if (rid < 0x4000) return "High";
                        if (rid < 0x5000) return "System";
                        return "Protected Process";
                    } finally {
                        Marshal.FreeHGlobal(buf);
                    }
                } finally {
                    CloseHandle(hTok);
                }
            } finally {
                CloseHandle(hProc);
            }
        }

        public static string GetProcessSddl(int pid) {
            IntPtr hProc = OpenProcess(READ_CONTROL, false, pid);
            if (hProc == IntPtr.Zero) return null;
            try {
                return GetHandleSddl(hProc, SE_KERNEL_OBJECT);
            } finally {
                CloseHandle(hProc);
            }
        }

        public static string GetNamedSectionSddl(string sectionName) {
            IntPtr hMap = OpenFileMappingW(READ_CONTROL, false, sectionName);
            if (hMap == IntPtr.Zero) return null;
            try {
                return GetHandleSddl(hMap, SE_KERNEL_OBJECT);
            } finally {
                CloseHandle(hMap);
            }
        }

        private static string GetHandleSddl(IntPtr handle, int objectType) {
            IntPtr pOwner, pGroup, pDacl, pSacl, pSd;
            uint info = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
            uint err = GetSecurityInfo(handle, objectType, info, out pOwner, out pGroup, out pDacl, out pSacl, out pSd);
            if (err != 0 || pSd == IntPtr.Zero) return null;
            try {
                IntPtr pSddl;
                uint len;
                if (ConvertSecurityDescriptorToStringSecurityDescriptorW(pSd, 1, info, out pSddl, out len) && pSddl != IntPtr.Zero) {
                    try {
                        return Marshal.PtrToStringUni(pSddl);
                    } finally {
                        LocalFree(pSddl);
                    }
                }
                return null;
            } finally {
                LocalFree(pSd);
            }
        }

        public class WindowInfo {
            public long Hwnd;
            public int Pid;
            public string ClassName;
            public string Title;
            public bool IsMessageOnly;
        }

        public static List<WindowInfo> EnumerateSessionWindows() {
            List<WindowInfo> list = new List<WindowInfo>();
            HashSet<IntPtr> seen = new HashSet<IntPtr>();
            EnumWindows(delegate(IntPtr hWnd, IntPtr lParam) {
                if (seen.Add(hWnd)) {
                    int pid = 0;
                    GetWindowThreadProcessId(hWnd, out pid);
                    if (pid > 0) {
                        StringBuilder sbClass = new StringBuilder(256);
                        GetClassNameW(hWnd, sbClass, 256);
                        StringBuilder sbTitle = new StringBuilder(256);
                        GetWindowTextW(hWnd, sbTitle, 256);
                        WindowInfo wi = new WindowInfo();
                        wi.Hwnd = hWnd.ToInt64();
                        wi.Pid = pid;
                        wi.ClassName = sbClass.ToString();
                        wi.Title = sbTitle.ToString();
                        wi.IsMessageOnly = false;
                        list.Add(wi);
                    }
                }
                return true;
            }, IntPtr.Zero);

            // Also enumerate HWND_MESSAGE (-3) message-only windows used for hidden IPC
            IntPtr hwndMsgParent = new IntPtr(-3);
            IntPtr child = IntPtr.Zero;
            int safety = 0;
            while (safety++ < 2000) {
                child = FindWindowExW(hwndMsgParent, child, null, null);
                if (child == IntPtr.Zero) break;
                if (seen.Add(child)) {
                    int pid = 0;
                    GetWindowThreadProcessId(child, out pid);
                    if (pid > 0) {
                        StringBuilder sbClass = new StringBuilder(256);
                        GetClassNameW(child, sbClass, 256);
                        WindowInfo wi = new WindowInfo();
                        wi.Hwnd = child.ToInt64();
                        wi.Pid = pid;
                        wi.ClassName = sbClass.ToString();
                        wi.Title = "";
                        wi.IsMessageOnly = true;
                        list.Add(wi);
                    }
                }
            }
            return list;
        }
    }
}
"@

try {
    Add-Type -TypeDefinition $csharpSubsystemCode -Language CSharp -ErrorAction Stop
} catch {
    if (-not $_.Exception.Message.Contains("already exists")) {
        Write-Warning "Failed to compile SubsystemNativeAuditor: $($_.Exception.Message)"
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  PERSPECTIVE-AWARE SECURITY DESCRIPTOR EVALUATOR
# ═══════════════════════════════════════════════════════════════════════════════

$currentIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$currentUserSid   = if ($currentIdentity.User) { $currentIdentity.User.Value } else { "" }
$adminSid         = "S-1-5-32-544"
$lowPrivSids = @(
    "S-1-1-0",      # Everyone
    "S-1-5-11",     # Authenticated Users
    "S-1-5-32-545", # Builtin\Users
    "S-1-5-4",      # INTERACTIVE
    "S-1-2-0"       # LOCAL
)
$appContainerSids = @(
    "S-1-15-2-1",   # ALL APPLICATION PACKAGES
    "S-1-15-2-2"    # ALL RESTRICTED APPLICATION PACKAGES (LPAC)
)

function Evaluate-RawSecurityDescriptor {
    param(
        [Parameter(Mandatory=$false)] [System.Security.AccessControl.CommonSecurityDescriptor]$Csd,
        [Parameter(Mandatory=$false)] [byte[]]$RawBytes,
        [Parameter(Mandatory=$false)] [string]$Sddl,
        [Parameter(Mandatory=$true)]  [int]$TargetMask,
        [int]$CeilingLowMask = -1,
        [int]$CeilingACMask  = -1,
        [int]$CeilingMedMask = -1
    )

    $result = @{
        LowPriv         = $false
        AppContainer    = $false
        MediumILAdmin   = $false
        HighILAdmin     = $false
        WritableFrom    = "None"
        CanWriteDacOwner= $false
        ServiceSids     = @()
        Sddl            = $Sddl
    }

    if ($null -eq $Csd) {
        try {
            if ($null -ne $RawBytes -and $RawBytes.Length -ge 20) {
                $Csd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $RawBytes, 0)
            } elseif (-not [string]::IsNullOrWhiteSpace($Sddl)) {
                $Csd = New-Object System.Security.AccessControl.CommonSecurityDescriptor($false, $false, $Sddl)
            }
        } catch {
            return $result
        }
    }
    if ($null -eq $Csd) { return $result }

    if ([string]::IsNullOrWhiteSpace($result.Sddl)) {
        try { $result.Sddl = $Csd.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All) } catch {}
    }

    $dacOwnerMask = 0x00040000 -bor 0x00080000 -bor 0x10000000 # WRITE_DAC | WRITE_OWNER | GENERIC_ALL
    $allowLow = 0; $denyLow = 0
    $allowAC  = 0; $denyAC  = 0
    $allowMed = 0; $denyMed = 0
    $allowHigh= 0; $denyHigh= 0
    $svcSids  = New-Object System.Collections.Generic.HashSet[string]

    # Check Owner implicit WRITE_DAC
    try {
        if ($null -ne $Csd.Owner) {
            $ownerSid = $Csd.Owner.Value
            if ($lowPrivSids -contains $ownerSid -or $ownerSid -eq $currentUserSid) {
                $allowLow  = $allowLow -bor 0x00040000
                $allowMed  = $allowMed -bor 0x00040000
                $allowHigh = $allowHigh -bor 0x00040000
                $result.CanWriteDacOwner = $true
            } elseif ($ownerSid -eq $adminSid) {
                $allowHigh = $allowHigh -bor 0x00040000
            }
        }
    } catch {}

    if ($null -ne $Csd.DiscretionaryAcl) {
        foreach ($ace in $Csd.DiscretionaryAcl) {
            if (-not ($ace -is [System.Security.AccessControl.KnownAce])) { continue }
            $sid = $ace.SecurityIdentifier.Value
            $mask = [int]$ace.AccessMask
            $aceType = $ace.AceType
            $isAllow = ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowed) -or
                       ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedCallback) -or
                       ($aceType -eq [System.Security.AccessControl.AceType]::AccessAllowedObject)
            $isDeny  = ($aceType -eq [System.Security.AccessControl.AceType]::AccessDenied) -or
                       ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedCallback) -or
                       ($aceType -eq [System.Security.AccessControl.AceType]::AccessDeniedObject)

            if ($sid.StartsWith("S-1-5-80-") -and $isAllow -and (($mask -band ($TargetMask -bor $dacOwnerMask)) -ne 0)) {
                [void]$svcSids.Add($sid)
            }

            $isLowSid = ($lowPrivSids -contains $sid)
            $isACSid  = ($appContainerSids -contains $sid) -or $sid.StartsWith("S-1-15-3-")
            $isAdmin  = ($sid -eq $adminSid) -or ($sid -eq "S-1-5-32-549") -or ($sid -eq "S-1-5-32-551")

            if ($isLowSid) {
                if ($isAllow) {
                    $allowLow  = $allowLow  -bor $mask
                    $allowMed  = $allowMed  -bor $mask
                    $allowHigh = $allowHigh -bor $mask
                    if (($mask -band $dacOwnerMask) -ne 0) { $result.CanWriteDacOwner = $true }
                } elseif ($isDeny) {
                    $denyLow   = $denyLow   -bor $mask
                    $denyMed   = $denyMed   -bor $mask
                    $denyHigh  = $denyHigh  -bor $mask
                }
            }
            if ($isACSid) {
                if ($isAllow) {
                    $allowAC = $allowAC -bor $mask
                    if (($mask -band $dacOwnerMask) -ne 0) { $result.CanWriteDacOwner = $true }
                } elseif ($isDeny) {
                    $denyAC  = $denyAC  -bor $mask
                }
            }
            if ($isAdmin) {
                if ($isAllow) {
                    $allowHigh = $allowHigh -bor $mask
                } elseif ($isDeny) {
                    $denyMed   = $denyMed   -bor $mask
                    $denyHigh  = $denyHigh  -bor $mask
                }
            }
        }
    }

    $effLow  = ($allowLow  -band (-bnot $denyLow))  -band $CeilingLowMask
    $effAC   = ($allowAC   -band (-bnot $denyAC))   -band $CeilingACMask
    $effMed  = ($allowMed  -band (-bnot $denyMed))  -band $CeilingMedMask
    $effHigh = ($allowHigh -band (-bnot $denyHigh))

    $result.LowPriv       = (($effLow  -band $TargetMask) -ne 0)
    $result.AppContainer  = (($effAC   -band $TargetMask) -ne 0)
    $result.MediumILAdmin = (($effMed  -band $TargetMask) -ne 0)
    $result.HighILAdmin   = (($effHigh -band $TargetMask) -ne 0)
    $result.ServiceSids   = @($svcSids)

    if ($result.LowPriv)           { $result.WritableFrom = "LowPriv" }
    elseif ($result.AppContainer)  { $result.WritableFrom = "AppContainer" }
    elseif ($result.MediumILAdmin) { $result.WritableFrom = "MediumILAdmin" }
    elseif ($result.HighILAdmin)   { $result.WritableFrom = "HighILAdmin" }

    return $result
}

$directLeads     = New-Object System.Collections.Generic.List[PSCustomObject]
$servicesAudit   = @{}
$servicesByBinary= @{}
$tasksAudit      = @{}
$dcomAudit       = New-Object System.Collections.Generic.List[PSCustomObject]
$wmiAudit        = New-Object System.Collections.Generic.List[PSCustomObject]
$uipiAudit       = New-Object System.Collections.Generic.List[PSCustomObject]
$processAudit    = New-Object System.Collections.Generic.List[PSCustomObject]
$deviceAudit     = New-Object System.Collections.Generic.List[PSCustomObject]

# ═══════════════════════════════════════════════════════════════════════════════
#  1. WMI / ETW SECURITY GUID LOOKUP TABLE (For Service Trigger Verification)
# ═══════════════════════════════════════════════════════════════════════════════
$etwLowPrivGuids = @{}
try {
    $wmiSecKey = Get-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Security" -ErrorAction SilentlyContinue
    if ($null -ne $wmiSecKey) {
        foreach ($valName in $wmiSecKey.GetValueNames()) {
            if ([string]::IsNullOrWhiteSpace($valName)) { continue }
            $bytes = $wmiSecKey.GetValue($valName)
            if ($bytes -is [byte[]] -and $bytes.Length -ge 20) {
                # TRACELOG_REGISTER_GUIDS (0x0008) | WMIGUID_NOTIFICATION (0x0004) | GENERIC_WRITE (0x40000000) | GENERIC_ALL (0x10000000)
                $ev = Evaluate-RawSecurityDescriptor -RawBytes $bytes -TargetMask 0x5000000C
                if ($ev.LowPriv -or $ev.AppContainer) {
                    $etwLowPrivGuids[$valName.ToLowerInvariant().Trim('{}')] = $ev.WritableFrom
                }
            }
        }
    }
} catch {}

# ═══════════════════════════════════════════════════════════════════════════════
#  2. SERVICES (SCM SDs, TriggerInfo, ServiceDll & Kernel Device Drivers)
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $Silent) { Write-Host "[*] Auditing SCM Service Security Descriptors, Triggers & Driver Objects..." -ForegroundColor Cyan }

$svcRegRoot = "HKLM:\SYSTEM\CurrentControlSet\Services"
$svcItems = Get-ChildItem -Path $svcRegRoot -ErrorAction SilentlyContinue

foreach ($svcKey in $svcItems) {
    $svcName = $svcKey.PSChildName
    $svcType = $svcKey.GetValue("Type", 0)
    $imgPath = [string]$svcKey.GetValue("ImagePath", "")
    $objName = [string]$svcKey.GetValue("ObjectName", "LocalSystem")
    $startMode = $svcKey.GetValue("Start", 3)

    # Kernel driver (Type 1 = Kernel Driver, Type 2 = File System Driver)
    if ($svcType -in @(1, 2)) {
        try {
            $secSubKey = $svcKey.OpenSubKey("Security")
            if ($null -ne $secSubKey) {
                $drvSdBytes = $secSubKey.GetValue("Security")
                $secSubKey.Close()
                if ($drvSdBytes -is [byte[]] -and $drvSdBytes.Length -ge 20) {
                    # FILE_WRITE_DATA (0x2) | FILE_READ_DATA (0x1) | GENERIC_WRITE (0x40000000) | GENERIC_ALL (0x10000000) | WRITE_DAC (0x40000)
                    $drvEval = Evaluate-RawSecurityDescriptor -RawBytes $drvSdBytes -TargetMask 0x500C0003
                    if ($drvEval.LowPriv -or $drvEval.AppContainer) {
                        $devLead = [PSCustomObject]@{
                            ServiceName  = $svcName
                            ImagePath    = $imgPath
                            WritableFrom = $drvEval.WritableFrom
                            Sddl         = $drvEval.Sddl
                        }
                        $deviceAudit.Add($devLead)
                        $directLeads.Add([PSCustomObject]@{
                            Severity           = "High"
                            Type               = "Kernel Driver Registry Security Descriptor Grants User Access"
                            ExploitPrimitive   = "Kernel_Device_IOCTL_Surface"
                            EscalationCategory = if ($drvEval.WritableFrom -eq "AppContainer") { "Sandbox_Escape" } else { "LPE" }
                            ResearchPromptId   = if ($drvEval.WritableFrom -eq "AppContainer") { "sandbox_escape" } else { "admin_kernel" }
                            Path               = "\Device\$svcName"
                            Processes          = "System ($svcName)"
                            Operations         = "DeviceIoControl / CreateFile"
                            DetailedReason     = "Kernel driver '$svcName' ($imgPath) defines an explicit Security Descriptor under Services\$svcName\Security that grants device access or DACL modification rights to '$($drvEval.WritableFrom)' (SDDL: $($drvEval.Sddl)). Any valid handle to this device allows sending FILE_ANY_ACCESS IOCTLs."
                            EffectivePrincipal = "System"
                            Integrity          = "System"
                            HighestIntegrity   = "System"
                            WritableByLowPriv  = $drvEval.LowPriv
                            WritableByAppContainer = $drvEval.AppContainer
                            WritableByMediumILAdmin = $drvEval.MediumILAdmin
                            WritableByHighILAdmin = $true
                            WritableFrom       = $drvEval.WritableFrom
                            AclSource          = "driver-registry-sd"
                        })
                    }
                }
            }
        } catch {}
        continue
    }

    # Win32 Service (Type 0x10, 0x20, etc.)
    $isPrivilegedSvc = ($objName -match "(?i)^(LocalSystem|NT AUTHORITY\\SYSTEM|NT AUTHORITY\\LocalService|NT AUTHORITY\\NetworkService)$") -or ([string]::IsNullOrWhiteSpace($objName))
    $serviceDll = ""
    try {
        $paramKey = $svcKey.OpenSubKey("Parameters")
        if ($null -ne $paramKey) {
            $serviceDll = [string]$paramKey.GetValue("ServiceDll", "")
            $paramKey.Close()
        }
    } catch {}

    # Check TriggerInfo subkeys
    $hasTrigger = $false
    $hasLowPrivTrigger = $false
    $triggerSummary = New-Object System.Collections.Generic.List[string]
    try {
        $trigKey = $svcKey.OpenSubKey("TriggerInfo")
        if ($null -ne $trigKey) {
            $subNames = $trigKey.GetSubKeyNames()
            if ($subNames.Count -gt 0) {
                $hasTrigger = $true
                foreach ($tsn in $subNames) {
                    $tSub = $trigKey.OpenSubKey($tsn)
                    if ($null -ne $tSub) {
                        $tType = $tSub.GetValue("Type", 0)
                        $tGuidBytes = $tSub.GetValue("Guid")
                        $tGuidStr = ""
                        if ($tGuidBytes -is [byte[]] -and $tGuidBytes.Length -eq 16) {
                            try { $tGuidStr = ([guid]$tGuidBytes).ToString().ToLowerInvariant() } catch {}
                        }
                        $typeLabel = switch ($tType) {
                            1 { "DeviceArrival" }
                            2 { "DomainJoin" }
                            3 { "FirewallPort" }
                            4 { "GroupPolicy" }
                            5 { "NetworkEndpoint_RPC_NamedPipe" }
                            6 { "Custom_ETW_Provider" }
                            8 { "WNF_StateChange" }
                            default { "TriggerType_$tType" }
                        }
                        if ($tType -eq 5) {
                            $hasLowPrivTrigger = $true
                            $triggerSummary.Add("$typeLabel($tGuidStr)")
                        } elseif ($tType -eq 6 -and -not [string]::IsNullOrWhiteSpace($tGuidStr)) {
                            if ($etwLowPrivGuids.ContainsKey($tGuidStr) -or (-not $etwLowPrivGuids.ContainsKey($tGuidStr))) {
                                # Unregistered WMI Security GUID defaults to accessible for ETW event registration by local users in many service triggers
                                $hasLowPrivTrigger = $true
                                $triggerSummary.Add("ETW($tGuidStr)")
                            }
                        } elseif ($tType -eq 8) {
                            $hasLowPrivTrigger = $true
                            $triggerSummary.Add("WNF($tGuidStr)")
                        } else {
                            $triggerSummary.Add("$typeLabel($tGuidStr)")
                        }
                        $tSub.Close()
                    }
                }
            }
            $trigKey.Close()
        }
    } catch {}

    # Query SCM Security Descriptor
    $sdBytes = $null
    try { $sdBytes = [ProcmonPhase2Auditor.SubsystemNativeAuditor]::GetServiceSecurityDescriptorBytes($svcName) } catch {}

    $canConfigLow = $false; $canConfigAC = $false; $canConfigFrom = "None"
    $canStartStopLow = $false; $canStartStopAC = $false; $canStartStopFrom = "None"
    $canUserControlLow = $false
    $svcSddl = ""

    if ($null -ne $sdBytes) {
        # SERVICE_CHANGE_CONFIG (0x0002) | WRITE_DAC (0x40000) | WRITE_OWNER (0x80000) | GENERIC_WRITE (0x40000000) | GENERIC_ALL (0x10000000)
        $cfgEval = Evaluate-RawSecurityDescriptor -RawBytes $sdBytes -TargetMask 0x500C0002
        $canConfigLow  = $cfgEval.LowPriv
        $canConfigAC   = $cfgEval.AppContainer
        $canConfigFrom = $cfgEval.WritableFrom
        $svcSddl       = $cfgEval.Sddl

        # SERVICE_START (0x0010) | SERVICE_STOP (0x0020) | GENERIC_EXECUTE (0x20000000) | GENERIC_ALL (0x10000000)
        $startEval = Evaluate-RawSecurityDescriptor -RawBytes $sdBytes -TargetMask 0x30000030
        $canStartStopLow  = $startEval.LowPriv
        $canStartStopAC   = $startEval.AppContainer
        $canStartStopFrom = $startEval.WritableFrom

        # SERVICE_USER_DEFINED_CONTROL (0x0100)
        $ctrlEval = Evaluate-RawSecurityDescriptor -RawBytes $sdBytes -TargetMask 0x00000100
        $canUserControlLow = $ctrlEval.LowPriv
    }

    $svcRecord = [PSCustomObject]@{
        ServiceName          = $svcName
        ObjectName           = $objName
        IsPrivileged         = $isPrivilegedSvc
        StartMode            = $startMode
        ImagePath            = $imgPath
        ServiceDll           = $serviceDll
        CanChangeConfigLow   = $canConfigLow
        CanChangeConfigFrom  = $canConfigFrom
        CanStartStopLow      = $canStartStopLow
        CanStartStopFrom     = $canStartStopFrom
        CanUserControlLow    = $canUserControlLow
        HasTrigger           = $hasTrigger
        HasLowPrivTrigger    = $hasLowPrivTrigger
        Triggers             = ($triggerSummary -join ", ")
        Sddl                 = $svcSddl
    }
    $servicesAudit[$svcName.ToLowerInvariant()] = $svcRecord

    # Map executable basename & ServiceDll basename -> service record for Procmon correlation
    foreach ($rawCandidate in @($imgPath, $serviceDll)) {
        if (-not [string]::IsNullOrWhiteSpace($rawCandidate)) {
            if ($rawCandidate -match '(?i)([^\\"\s]+\.(?:exe|dll))') {
                $baseBin = $matches[1].ToLowerInvariant()
                if ($baseBin -ne "svchost.exe") {
                    if (-not $servicesByBinary.ContainsKey($baseBin)) {
                        $servicesByBinary[$baseBin] = New-Object System.Collections.Generic.List[PSCustomObject]
                    }
                    $servicesByBinary[$baseBin].Add($svcRecord)
                }
            }
        }
    }

    if ($isPrivilegedSvc -and ($canConfigLow -or $canConfigAC)) {
        $directLeads.Add([PSCustomObject]@{
            Severity           = "Critical"
            Type               = "Privileged Service Security Descriptor Allows Reconfiguration / DACL Takeover"
            ExploitPrimitive   = "Service_OnDemand_Trigger_Chain"
            EscalationCategory = if ($canConfigFrom -eq "AppContainer") { "Sandbox_Escape" } else { "LPE" }
            ResearchPromptId   = if ($canConfigFrom -eq "AppContainer") { "sandbox_escape" } else { "lpe" }
            Path               = "HKLM\SYSTEM\CurrentControlSet\Services\$svcName"
            Processes          = "services.exe ($svcName)"
            Operations         = "QueryServiceObjectSecurity"
            DetailedReason     = "Privileged service '$svcName' (runs as '$objName', ImagePath: '$imgPath') has a Service Security Descriptor granting SERVICE_CHANGE_CONFIG, WRITE_DAC, or WRITE_OWNER to '$canConfigFrom' (SDDL: $svcSddl). A non-admin principal can reconfigure BinaryPathName to execute arbitrary commands as $objName."
            EffectivePrincipal = "System"
            Integrity          = "System"
            HighestIntegrity   = "System"
            WritableByLowPriv  = $canConfigLow
            WritableByAppContainer = $canConfigAC
            WritableByMediumILAdmin = $true
            WritableByHighILAdmin = $true
            WritableFrom       = $canConfigFrom
            AclSource          = "service-scm-sd"
        })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  3. SCHEDULED TASKS (TaskCache\Tree\*\SD & TaskCache\Tasks\*)
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $Silent) { Write-Host "[*] Auditing Scheduled Task 'TaskCache' Security Descriptors..." -ForegroundColor Cyan }

$taskTreeSubPath  = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree"
$taskTasksSubPath = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks"

$taskStack = New-Object System.Collections.Generic.Stack[string]
$taskStack.Push($taskTreeSubPath)

while ($taskStack.Count -gt 0) {
    $curSub = $taskStack.Pop()
    $tk = $null
    try {
        $tk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
            $curSub,
            [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
            [System.Security.AccessControl.RegistryRights]::ReadKey)
    } catch { $tk = $null }
    if ($null -eq $tk) { continue }

    try {
        foreach ($childName in $tk.GetSubKeyNames()) {
            $taskStack.Push("$curSub\$childName")
        }
        $taskId = [string]$tk.GetValue("Id", "")
        $sdBytes = $tk.GetValue("SD")
        if (-not [string]::IsNullOrWhiteSpace($taskId) -and ($sdBytes -is [byte[]]) -and $sdBytes.Length -ge 20) {
            $relTaskPath = $curSub.Substring($taskTreeSubPath.Length)
            # Check write/modify rights on the Task SD: FILE_WRITE_DATA (0x2) | WRITE_DAC (0x40000) | WRITE_OWNER (0x80000) | GENERIC_WRITE (0x40000000) | GENERIC_ALL (0x10000000)
            $writeEval = Evaluate-RawSecurityDescriptor -RawBytes $sdBytes -TargetMask 0x500C0006
            # Check execute/run rights: FILE_EXECUTE (0x20) | GENERIC_EXECUTE (0x20000000) | GENERIC_ALL (0x10000000)
            $execEval  = Evaluate-RawSecurityDescriptor -RawBytes $sdBytes -TargetMask 0x30000020

            $taskUri = $relTaskPath
            try {
                $tMeta = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey(
                    "$taskTasksSubPath\$taskId",
                    [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadSubTree,
                    [System.Security.AccessControl.RegistryRights]::ReadKey)
                if ($null -ne $tMeta) {
                    $taskUri = [string]$tMeta.GetValue("URI", $relTaskPath)
                    $tMeta.Close()
                }
            } catch {}

            # Inspect XML on disk (Read-Only) if accessible to check UserId / RunLevel / Actions / $(Arg0)
            $xmlFile = Join-Path "$env:SystemRoot\System32\Tasks" $relTaskPath.TrimStart('\')
            $runsAsPriv = $false
            $hasUserArgs = $false
            $actionCmd = ""
            if ([System.IO.File]::Exists($xmlFile)) {
                try {
                    $xmlText = [System.IO.File]::ReadAllText($xmlFile)
                    if ($xmlText -match '(?i)<UserId>(S-1-5-18|S-1-5-19|S-1-5-20|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)</UserId>' -or $xmlText -match '(?i)<RunLevel>HighestAvailable</RunLevel>') {
                        $runsAsPriv = $true
                    }
                    if ($xmlText -match '(?i)<Command>([^<]+)</Command>') {
                        $actionCmd = $matches[1].Trim()
                    }
                    if ($xmlText -match '\$\(Arg\d+\)') {
                        $hasUserArgs = $true
                    }
                } catch {}
            }

            $taskRec = [PSCustomObject]@{
                TaskPath          = $taskUri
                TaskId            = $taskId
                RunsAsPrivileged  = $runsAsPriv
                ActionCommand     = $actionCmd
                AcceptsUserArgs   = $hasUserArgs
                WritableLow       = $writeEval.LowPriv
                WritableFrom      = $writeEval.WritableFrom
                ExecutableLow     = $execEval.LowPriv
                ExecutableFrom    = $execEval.WritableFrom
                Sddl              = $writeEval.Sddl
            }
            $tasksAudit[$taskUri.ToLowerInvariant()] = $taskRec

            if ($runsAsPriv -and ($writeEval.LowPriv -or $writeEval.AppContainer -or (($execEval.LowPriv -or $execEval.AppContainer) -and ($hasUserArgs -or ($actionCmd -ne "" -and $actionCmd -notmatch '(?i)^(%windir%|%systemroot%|c:\\windows\\system32)'))))) {
                $persp = if ($writeEval.LowPriv -or $writeEval.AppContainer) { $writeEval.WritableFrom } else { $execEval.WritableFrom }
                $directLeads.Add([PSCustomObject]@{
                    Severity           = if ($writeEval.LowPriv -or $hasUserArgs) { "Critical" } else { "High" }
                    Type               = "Privileged Scheduled Task On-Demand Trigger / Modification Surface"
                    ExploitPrimitive   = "ScheduledTask_OnDemand_Run"
                    EscalationCategory = if ($persp -eq "AppContainer") { "Sandbox_Escape" } else { "LPE" }
                    ResearchPromptId   = if ($persp -eq "AppContainer") { "sandbox_escape" } else { "lpe" }
                    Path               = "C:\Windows\System32\Tasks$relTaskPath"
                    Processes          = "svchost.exe (Schedule)"
                    Operations         = "TaskCache_SD_Audit"
                    DetailedReason     = "Privileged scheduled task '$taskUri' (Command: '$actionCmd', AcceptsUserArgs=$hasUserArgs) has a TaskCache\Tree Security Descriptor granting $(if ($writeEval.LowPriv) { 'WRITE / MODIFY' } else { 'ON-DEMAND EXECUTE' }) rights to '$persp' (SDDL: $($writeEval.Sddl))."
                    EffectivePrincipal = "System"
                    Integrity          = "System"
                    HighestIntegrity   = "System"
                    WritableByLowPriv  = ($persp -eq "LowPriv")
                    WritableByAppContainer = ($persp -eq "AppContainer")
                    WritableByMediumILAdmin = $true
                    WritableByHighILAdmin = $true
                    WritableFrom       = $persp
                    AclSource          = "taskcache-sd"
                })
            }
        }
    } catch {
    } finally {
        $tk.Close()
    }
}

# Fallback when running unprivileged (where TaskCache\Tree SD values are admin-gated):
# Query the built-in Schedule.Service COM reader (100% read-only) to inspect visible scheduled tasks and their XML SecurityDescriptors / Actions
if ($tasksAudit.Count -eq 0) {
    try {
        $schedSvc = New-Object -ComObject "Schedule.Service"
        $schedSvc.Connect()
        $folderQueue = New-Object System.Collections.Generic.Queue[object]
        $folderQueue.Enqueue($schedSvc.GetFolder("\"))
        while ($folderQueue.Count -gt 0) {
            $curFolder = $folderQueue.Dequeue()
            try {
                foreach ($subF in $curFolder.GetFolders(0)) {
                    $folderQueue.Enqueue($subF)
                }
            } catch {}
            try {
                foreach ($taskItem in $curFolder.GetTasks(1)) {
                    $relTaskPath = [string]$taskItem.Path
                    $xmlText     = [string]$taskItem.Xml
                    $runsAsPriv  = ($xmlText -match '(?i)<UserId>(S-1-5-18|S-1-5-19|S-1-5-20|SYSTEM|LOCAL SERVICE|NETWORK SERVICE)</UserId>' -or $xmlText -match '(?i)<RunLevel>HighestAvailable</RunLevel>')
                    $actionCmd   = if ($xmlText -match '(?i)<Command>([^<]+)</Command>') { $matches[1].Trim() } else { "" }
                    $hasUserArgs = ($xmlText -match '\$\(Arg\d+\)')
                    $embSddl     = ""
                    try { $embSddl = [string]$taskItem.SecurityDescriptor } catch {}
                    if ([string]::IsNullOrWhiteSpace($embSddl) -and $xmlText -match '(?i)<SecurityDescriptor>([^<]+)</SecurityDescriptor>') {
                        $embSddl = $matches[1].Trim()
                    }

                    $writeLow = $false; $execLow = $true; $writeFrom = "LowPriv"; $execFrom = "LowPriv"
                    if (-not [string]::IsNullOrWhiteSpace($embSddl)) {
                        $wEv = Evaluate-RawSecurityDescriptor -Sddl $embSddl -TargetMask 0x500C0006
                        $eEv = Evaluate-RawSecurityDescriptor -Sddl $embSddl -TargetMask 0x30000020
                        $writeLow = $wEv.LowPriv; $writeFrom = $wEv.WritableFrom
                        $execLow  = $eEv.LowPriv; $execFrom  = $eEv.WritableFrom
                    }

                    $taskRec = [PSCustomObject]@{
                        TaskPath         = $relTaskPath
                        TaskId           = ""
                        RunsAsPrivileged = $runsAsPriv
                        ActionCommand    = $actionCmd
                        AcceptsUserArgs  = $hasUserArgs
                        WritableLow      = $writeLow
                        WritableFrom     = $writeFrom
                        ExecutableLow    = $execLow
                        ExecutableFrom   = $execFrom
                        Sddl             = $embSddl
                    }
                    $tasksAudit[$relTaskPath.ToLowerInvariant()] = $taskRec

                    if ($runsAsPriv -and ($writeLow -or ($execLow -and ($hasUserArgs -or ($actionCmd -ne "" -and $actionCmd -notmatch '(?i)^"?(%windir%|%systemroot%|c:\\windows\\system32|c:\\program files)'))))) {
                        $directLeads.Add([PSCustomObject]@{
                            Severity           = if ($writeLow -or $hasUserArgs) { "Critical" } else { "High" }
                            Type               = "Privileged Scheduled Task On-Demand Trigger / Modification Surface"
                            ExploitPrimitive   = "ScheduledTask_OnDemand_Run"
                            EscalationCategory = "LPE"
                            ResearchPromptId   = "lpe"
                            Path               = "C:\Windows\System32\Tasks$relTaskPath"
                            Processes          = "svchost.exe (Schedule)"
                            Operations         = "ScheduleService_COM_Audit"
                            DetailedReason     = "Privileged scheduled task '$relTaskPath' (Command: '$actionCmd', AcceptsUserArgs=$hasUserArgs) is visible/executable by a standard user and $(if ($writeLow) { 'grants task modification rights' } elseif ($hasUserArgs) { 'accepts user-supplied $(ArgN) command-line parameters' } else { 'executes a non-standard binary path' })."
                            EffectivePrincipal = "System"
                            Integrity          = "System"
                            HighestIntegrity   = "System"
                            WritableByLowPriv  = $true
                            WritableByAppContainer = $false
                            WritableByMediumILAdmin = $true
                            WritableByHighILAdmin = $true
                            WritableFrom       = "LowPriv"
                            AclSource          = "taskcache-sd"
                        })
                    }
                }
            } catch {}
        }
    } catch {}
}

# ═══════════════════════════════════════════════════════════════════════════════
#  4. DCOM / COM (Machine Restrictions, AppID Launch/Access SDs & UAC Elevation)
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $Silent) { Write-Host "[*] Auditing DCOM AppID Security Descriptors & Auto-Elevated CLSIDs..." -ForegroundColor Cyan }

# COM_RIGHTS_EXECUTE (1) | EXECUTE_LOCAL (2) | EXECUTE_REMOTE (4) | ACTIVATE_LOCAL (8) | ACTIVATE_REMOTE (16)
$comLocalMask = 0x1 -bor 0x2 -bor 0x8 -bor 0x00040000 -bor 0x00080000 # Local Execute + Activate + WriteDac/Owner
$machineLaunchLowCeiling = -1
$machineAccessLowCeiling = -1

try {
    $oleKey = Get-Item -Path "HKLM:\SOFTWARE\Microsoft\Ole" -ErrorAction SilentlyContinue
    if ($null -ne $oleKey) {
        $mlr = $oleKey.GetValue("MachineLaunchRestriction")
        if ($mlr -is [byte[]] -and $mlr.Length -ge 20) {
            $mlrEval = Evaluate-RawSecurityDescriptor -RawBytes $mlr -TargetMask $comLocalMask
            if (-not $mlrEval.LowPriv) { $machineLaunchLowCeiling = 0 }
        }
        $mar = $oleKey.GetValue("MachineAccessRestriction")
        if ($mar -is [byte[]] -and $mar.Length -ge 20) {
            $marEval = Evaluate-RawSecurityDescriptor -RawBytes $mar -TargetMask $comLocalMask
            if (-not $marEval.LowPriv) { $machineAccessLowCeiling = 0 }
        }
    }
} catch {}

$appIdRoot = "HKLM:\SOFTWARE\Classes\AppID"
if (Test-Path $appIdRoot) {
    foreach ($appKey in (Get-ChildItem -Path $appIdRoot -ErrorAction SilentlyContinue)) {
        if ($appKey.PSChildName -notmatch '^\{[0-9a-fA-F-]+\}$') { continue }
        try {
            $appIdGuid = $appKey.PSChildName
            $appName   = [string]$appKey.GetValue("", "")
            $runAs     = [string]$appKey.GetValue("RunAs", "")
            $localSvc  = [string]$appKey.GetValue("LocalService", "")
            if ([string]::IsNullOrWhiteSpace($runAs) -and [string]::IsNullOrWhiteSpace($localSvc)) { continue }

            $isPrivComTarget = ($runAs -match "(?i)Interactive User")
            if (-not [string]::IsNullOrWhiteSpace($localSvc)) {
                $svcKeyMatch = $servicesAudit[$localSvc.ToLowerInvariant()]
                if ($null -ne $svcKeyMatch -and $svcKeyMatch.IsPrivileged) {
                    $isPrivComTarget = $true
                }
            }
            if (-not $isPrivComTarget) { continue }

            $launchBytes = $appKey.GetValue("LaunchPermission")
            $accessBytes = $appKey.GetValue("AccessPermission")

            $launchLow = $false; $launchAC = $false; $launchFrom = "None"; $launchSddl = ""
            if ($launchBytes -is [byte[]] -and $launchBytes.Length -ge 20) {
                $lEval = Evaluate-RawSecurityDescriptor -RawBytes $launchBytes -TargetMask $comLocalMask -CeilingLowMask $machineLaunchLowCeiling
                $launchLow  = $lEval.LowPriv
                $launchAC   = $lEval.AppContainer
                $launchFrom = $lEval.WritableFrom
                $launchSddl = $lEval.Sddl
            }
            $accessLow = $false; $accessAC = $false; $accessFrom = "None"
            if ($accessBytes -is [byte[]] -and $accessBytes.Length -ge 20) {
                $aEval = Evaluate-RawSecurityDescriptor -RawBytes $accessBytes -TargetMask $comLocalMask -CeilingLowMask $machineAccessLowCeiling
                $accessLow  = $aEval.LowPriv
                $accessAC   = $aEval.AppContainer
                $accessFrom = $aEval.WritableFrom
            }

            if ($launchLow -or $launchAC -or $accessLow -or $accessAC) {
                $effFrom = if ($launchLow -or $accessLow) { "LowPriv" } else { "AppContainer" }
                $dcomRec = [PSCustomObject]@{
                    AppID        = $appIdGuid
                    Name         = $appName
                    RunAs        = $runAs
                    LocalService = $localSvc
                    LaunchFrom   = $launchFrom
                    AccessFrom   = $accessFrom
                    WritableFrom = $effFrom
                    Sddl         = $launchSddl
                }
                $dcomAudit.Add($dcomRec)

                # Surface high-signal DCOM leads:
                #   (a) LocalService running as SYSTEM/Privileged that is non-OS-core and grants LaunchPermission to LowPriv/AppContainer, OR
                #   (b) RunAs="Interactive User" that grants LaunchPermission to AppContainer (S-1-15-2-*: AppContainer -> Medium-IL Sandbox Escape!)
                $isCustomPrivSvcDcom = (-not [string]::IsNullOrWhiteSpace($localSvc)) -and ($localSvc -notmatch "(?i)^(wuauserv|bits|schedule|eventlog|plugplay|rpcss|dcomlaunch|winmgmt|trustedinstaller|profsvc|themes|sens| Audiosrv|AudioEndpointBuilder| BrokerInfrastructure|CoreMessagingRegistrar|CryptSvc|Dhcp|Dnscache|DPS|FontCache|gpsvc|iphlpsvc|KeyIso|LanmanServer|LanmanWorkstation|lfsvc|lmhosts|mpssvc|NcbService|netprofm|NlaSvc|nsi|PcaSvc|Power|PrintNotify|RmSvc|SamSs|SCardSvr|ScDeviceEnum|seclogon|ShellHWDetection|Spooler|SSDPSRV|StateRepository|StorSvc|SysMain|SystemEventsBroker|TabletInputService|TermService|TimeBrokerSvc|TokenBroker|TrkWks|UserManager|UsoSvc|VaultSvc|W32Time|Wcmsvc|WdiServiceHost|WdiSystemHost|WebClient|Wecsvc|WEPHOSTSVC|WerSvc|WinHttpAutoProxySvc|WinRM|WlanSvc|wlidsvc|WpnService|wscsvc|WSearch)$")
                $isAppContainerInteractiveEscape = ($runAs -match "(?i)Interactive User") -and $launchAC
                if (($launchLow -and $isCustomPrivSvcDcom) -or $isAppContainerInteractiveEscape) {
                    $dcomFrom = if ($isAppContainerInteractiveEscape -and -not $launchLow) { "AppContainer" } else { $effFrom }
                    $directLeads.Add([PSCustomObject]@{
                        Severity           = "High"
                        Type               = "Privileged DCOM AppID Grants Local Activation to Non-Admin / Sandbox"
                        ExploitPrimitive   = "DCOM_Privileged_Activation"
                        EscalationCategory = if ($dcomFrom -eq "AppContainer") { "Sandbox_Escape" } else { "LPE" }
                        ResearchPromptId   = if ($dcomFrom -eq "AppContainer") { "sandbox_escape" } else { "lpe" }
                        Path               = "HKLM\SOFTWARE\Classes\AppID\$appIdGuid"
                        Processes          = if ($localSvc) { "svchost.exe ($localSvc)" } else { "dllhost.exe ($appName)" }
                        Operations         = "DCOM_LaunchPermission_Audit"
                        DetailedReason     = "DCOM AppID '$appIdGuid' ('$appName', RunAs='$runAs', LocalService='$localSvc') has an explicit LaunchPermission Security Descriptor granting local activation/execution to '$dcomFrom' (SDDL: $launchSddl). Audit exposed COM interfaces on this class for file/process/marshaling sinks."
                        EffectivePrincipal = "System"
                        Integrity          = "System"
                        HighestIntegrity   = "System"
                        WritableByLowPriv  = ($dcomFrom -eq "LowPriv")
                        WritableByAppContainer = ($dcomFrom -eq "AppContainer" -or $launchAC)
                        WritableByMediumILAdmin = $true
                        WritableByHighILAdmin = $true
                        WritableFrom       = $dcomFrom
                        AclSource          = "dcom-launch-sd"
                    })
                }
            }
        } catch {}
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  5. WMI NAMESPACES & __Win32Provider HOSTING MODELS
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $SkipWmi) {
    if (-not $Silent) { Write-Host "[*] Auditing WMI Namespace Security Descriptors & '__Win32Provider' HostingModels..." -ForegroundColor Cyan }
    $nsQueue = New-Object System.Collections.Generic.Queue[string]
    $nsQueue.Enqueue("ROOT")
    $visitedNs = New-Object System.Collections.Generic.HashSet[string] ([System.StringComparer]::OrdinalIgnoreCase)

    while ($nsQueue.Count -gt 0 -and $visitedNs.Count -lt $MaxWmiNamespaces) {
        $curNs = $nsQueue.Dequeue()
        if (-not $visitedNs.Add($curNs)) { continue }

        try {
            $subNsList = Get-CimInstance -Namespace $curNs -ClassName "__NAMESPACE" -ErrorAction Stop
            foreach ($s in $subNsList) {
                if (-not [string]::IsNullOrWhiteSpace($s.Name)) {
                    $nsQueue.Enqueue("$curNs\$($s.Name)")
                }
            }
        } catch {}

        try {
            $sdRes = Invoke-CimMethod -Namespace $curNs -ClassName "__SystemSecurity" -MethodName "GetSecurityDescriptor" -ErrorAction Stop
            if ($null -ne $sdRes -and $sdRes.ReturnValue -eq 0 -and $null -ne $sdRes.Descriptor) {
                # Evaluate WMI DACL entries directly from Win32_SecurityDescriptor
                # WBEM_METHOD_EXECUTE (0x2) | WBEM_FULL_WRITE_REP (0x4) | WBEM_PARTIAL_WRITE_REP (0x8) | WBEM_WRITE_PROVIDER (0x10) | WRITE_DAC (0x40000)
                $wmiWriteMask = 0x4 -bor 0x8 -bor 0x10 -bor 0x00040000 -bor 0x00080000
                $wmiExecMask  = 0x2
                $lowCanWriteNs = $false
                $lowCanExecNs  = $false

                foreach ($ace in $sdRes.Descriptor.DACL) {
                    if ($null -eq $ace -or $null -eq $ace.Trustee) { continue }
                    $tSid = [string]$ace.Trustee.SIDString
                    $tMask = [int]$ace.AccessMask
                    $isAllowAce = ($ace.AceType -eq 0)
                    if ($isAllowAce -and ($lowPrivSids -contains $tSid)) {
                        if (($tMask -band $wmiWriteMask) -ne 0) { $lowCanWriteNs = $true }
                        if (($tMask -band $wmiExecMask)  -ne 0) { $lowCanExecNs  = $true }
                    }
                }

                # Check __Win32Provider instances in this namespace
                $localSysProviders = @()
                try {
                    $provs = Get-CimInstance -Namespace $curNs -ClassName "__Win32Provider" -ErrorAction SilentlyContinue
                    foreach ($pv in $provs) {
                        $hm = [string]$pv.HostingModel
                        if ($hm -match "(?i)LocalSystemHost|Decoupled") {
                            $localSysProviders += "$($pv.Name) ($hm)"
                        }
                    }
                } catch {}

                if ($lowCanWriteNs -or ($lowCanExecNs -and $localSysProviders.Count -gt 0 -and $curNs -notmatch "(?i)^ROOT\\(CIMV2|Default|WMI|StandardCimv2|Microsoft)$")) {
                    $wmiRec = [PSCustomObject]@{
                        Namespace            = $curNs
                        LowPrivCanWrite      = $lowCanWriteNs
                        LowPrivCanExecute    = $lowCanExecNs
                        LocalSystemProviders = ($localSysProviders -join ", ")
                    }
                    $wmiAudit.Add($wmiRec)
                    $directLeads.Add([PSCustomObject]@{
                        Severity           = if ($lowCanWriteNs) { "Critical" } else { "High" }
                        Type               = "WMI Namespace Permission / LocalSystemHost Provider Sink"
                        ExploitPrimitive   = "WMI_LocalSystemHost_Sink"
                        EscalationCategory = "LPE"
                        ResearchPromptId   = "lpe"
                        Path               = "WMI:\\$curNs"
                        Processes          = "wmiprvse.exe"
                        Operations         = "WMI_Namespace_Audit"
                        DetailedReason     = "WMI namespace '$curNs' grants $(if ($lowCanWriteNs) { 'REPOSITORY/PROVIDER WRITE or WRITE_DAC' } else { 'WBEM_METHOD_EXECUTE' }) to non-admin users and hosts LocalSystemHost / Decoupled provider(s): [$($localSysProviders -join ', ')]. Providers with LocalSystemHost run as pure SYSTEM without impersonating unless they explicitly call CoImpersonateClient()."
                        EffectivePrincipal = "System"
                        Integrity          = "System"
                        HighestIntegrity   = "System"
                        WritableByLowPriv  = $true
                        WritableByAppContainer = $false
                        WritableByMediumILAdmin = $true
                        WritableByHighILAdmin = $true
                        WritableFrom       = "LowPriv"
                        AclSource          = "wmi-namespace-sd"
                    })
                }
            }
        } catch {}
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
#  6. PROCESS DACLs & UIPI HIGH-IL INTERACTIVE WINDOWS
# ═══════════════════════════════════════════════════════════════════════════════
if (-not $Silent) { Write-Host "[*] Auditing High/SYSTEM Process DACLs & UIPI Interactive Window Sinks..." -ForegroundColor Cyan }

$pidIntegrityCache = @{}
$pidNameCache      = @{}
foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    $pidNameCache[$p.Id] = "$($p.ProcessName).exe"
    $il = "Unknown"
    try { $il = [ProcmonPhase2Auditor.SubsystemNativeAuditor]::GetProcessIntegrityLevel($p.Id) } catch {}
    $pidIntegrityCache[$p.Id] = $il

    if (-not $SkipHandles -and $il -in @("High", "System")) {
        try {
            $procSddl = [ProcmonPhase2Auditor.SubsystemNativeAuditor]::GetProcessSddl($p.Id)
            if (-not [string]::IsNullOrWhiteSpace($procSddl)) {
                # PROCESS_CREATE_THREAD (0x2) | PROCESS_VM_OPERATION (0x8) | PROCESS_VM_WRITE (0x20) | PROCESS_DUP_HANDLE (0x40) | PROCESS_CREATE_PROCESS (0x80) | WRITE_DAC (0x40000) | WRITE_OWNER (0x80000)
                $pEval = Evaluate-RawSecurityDescriptor -Sddl $procSddl -TargetMask 0x500C00EA
                if ($pEval.LowPriv -or $pEval.AppContainer) {
                    $procRec = [PSCustomObject]@{
                        Pid          = $p.Id
                        ProcessName  = "$($p.ProcessName).exe"
                        Integrity    = $il
                        WritableFrom = $pEval.WritableFrom
                        Sddl         = $procSddl
                    }
                    $processAudit.Add($procRec)
                    $directLeads.Add([PSCustomObject]@{
                        Severity           = "Critical"
                        Type               = "Privileged Process DACL Grants Memory/Thread/Handle Access to Non-Admin"
                        ExploitPrimitive   = "Leaked_Privileged_Handle"
                        EscalationCategory = if ($pEval.WritableFrom -eq "AppContainer") { "Sandbox_Escape" } else { "LPE" }
                        ResearchPromptId   = if ($pEval.WritableFrom -eq "AppContainer") { "sandbox_escape" } else { "lpe" }
                        Path               = "Process://$($p.ProcessName).exe (PID $($p.Id))"
                        Processes          = "$($p.ProcessName).exe"
                        Operations         = "Process_DACL_Audit"
                        DetailedReason     = "Running $il-integrity process '$($p.ProcessName).exe' (PID $($p.Id)) has a permissive Process Security Descriptor granting VM_WRITE, CREATE_THREAD, DUP_HANDLE, CREATE_PROCESS, or WRITE_DAC to '$($pEval.WritableFrom)' (SDDL: $procSddl)."
                        EffectivePrincipal = $il
                        Integrity          = $il
                        HighestIntegrity   = $il
                        WritableByLowPriv  = $pEval.LowPriv
                        WritableByAppContainer = $pEval.AppContainer
                        WritableByMediumILAdmin = $true
                        WritableByHighILAdmin = $true
                        WritableFrom       = $pEval.WritableFrom
                        AclSource          = "process-dacl"
                    })
                }
            }
        } catch {}
    }
}

# Enumerate interactive session windows owned by High/SYSTEM processes
try {
    $sessionWindows = [ProcmonPhase2Auditor.SubsystemNativeAuditor]::EnumerateSessionWindows()
    $seenUipiPids = New-Object System.Collections.Generic.HashSet[int]
    foreach ($wi in $sessionWindows) {
        $wIl = if ($pidIntegrityCache.ContainsKey($wi.Pid)) { $pidIntegrityCache[$wi.Pid] } else { "Unknown" }
        if ($wIl -in @("High", "System")) {
            $pName = if ($pidNameCache.ContainsKey($wi.Pid)) { $pidNameCache[$wi.Pid] } else { "PID_$($wi.Pid)" }
            $uipiRec = [PSCustomObject]@{
                Hwnd          = ("0x{0:X}" -f $wi.Hwnd)
                Pid           = $wi.Pid
                ProcessName   = $pName
                Integrity     = $wIl
                ClassName     = $wi.ClassName
                Title         = $wi.Title
                IsMessageOnly = $wi.IsMessageOnly
            }
            $uipiAudit.Add($uipiRec)

            # Emit one consolidated UIPI lead per non-OS-shell High/SYSTEM process owning windows in the user session
            if ($pName -notmatch "(?i)^(explorer\.exe|taskmgr\.exe|csrss\.exe|winlogon\.exe|dwm\.exe)$" -and $seenUipiPids.Add($wi.Pid)) {
                $directLeads.Add([PSCustomObject]@{
                    Severity           = "Medium"
                    Type               = "High/SYSTEM Window in Interactive Session (UIPI Message Sink Candidate)"
                    ExploitPrimitive   = "UIPI_HighIL_MessageSink"
                    EscalationCategory = "UAC_Bypass"
                    ResearchPromptId   = "uac"
                    Path               = "HWND://$pName/$($wi.ClassName) (0x$("{0:X}" -f $wi.Hwnd))"
                    Processes          = $pName
                    Operations         = "EnumWindows / FindWindowEx"
                    DetailedReason     = "Privileged ($wIl) process '$pName' (PID $($wi.Pid)) owns window class '$($wi.ClassName)' (MessageOnly=$($wi.IsMessageOnly)) in the interactive user desktop. Check whether the binary sets uiAccess=true or calls ChangeWindowMessageFilterEx(MSGFLT_ALLOW) exposing custom window messages or WM_COPYDATA to Medium-IL callers."
                    EffectivePrincipal = $wIl
                    Integrity          = $wIl
                    HighestIntegrity   = $wIl
                    WritableByLowPriv  = $true
                    WritableByAppContainer = $false
                    WritableByMediumILAdmin = $true
                    WritableByHighILAdmin = $true
                    WritableFrom       = "LowPriv"
                    AclSource          = "uipi-session-window"
                })
            }
        }
    }
} catch {}

# Query SystemExtendedHandleInformation for cross-IL leaked handles
if (-not $SkipHandles) {
    try {
        $privPidSet = New-Object 'System.Collections.Generic.HashSet[int]'
        foreach ($kv in $pidIntegrityCache.GetEnumerator()) {
            if ($kv.Value -in @("High", "System")) {
                [void]$privPidSet.Add([int]$kv.Key)
            }
        }
        $leakedHandles = [ProcmonPhase2Auditor.SubsystemNativeAuditor]::QueryInheritablePrivilegedHandles($privPidSet)
        $seenLeakPids = New-Object 'System.Collections.Generic.HashSet[int]'
        foreach ($lh in $leakedHandles) {
            if (-not $privPidSet.Contains($lh.Pid) -and $seenLeakPids.Add($lh.Pid)) {
                $holderName = if ($pidNameCache.ContainsKey($lh.Pid)) { $pidNameCache[$lh.Pid] } else { "PID_$($lh.Pid)" }
                $holderIl   = if ($pidIntegrityCache.ContainsKey($lh.Pid)) { $pidIntegrityCache[$lh.Pid] } else { "Medium" }
                $accessHex  = ("0x{0:X8}" -f $lh.GrantedAccess)
                $directLeads.Add([PSCustomObject]@{
                    Severity           = "Critical"
                    Type               = "Leaked / Inherited Privileged Kernel Object Handle in Lower-IL Process"
                    ExploitPrimitive   = "Leaked_Privileged_Handle"
                    EscalationCategory = "LPE"
                    ResearchPromptId   = "lpe"
                    Path               = "Handle://$holderName (PID $($lh.Pid)) -> Handle 0x$("{0:X}" -f $lh.HandleValue)"
                    Processes          = $holderName
                    Operations         = "SystemExtendedHandleInformation"
                    DetailedReason     = "Lower-integrity ($holderIl) process '$holderName' (PID $($lh.Pid)) holds an open handle (0x$("{0:X}" -f $lh.HandleValue), ObjectTypeIndex=$($lh.ObjectTypeIndex), GrantedAccess=$accessHex) referencing a kernel object also held by a High/SYSTEM process."
                    EffectivePrincipal = "System"
                    Integrity          = "System"
                    HighestIntegrity   = "System"
                    WritableByLowPriv  = $true
                    WritableByAppContainer = $false
                    WritableByMediumILAdmin = $true
                    WritableByHighILAdmin = $true
                    WritableFrom       = "LowPriv"
                    AclSource          = "system-handle-table"
                })
            }
        }
    } catch {}
}

# ═══════════════════════════════════════════════════════════════════════════════
#  7. EXPORT ENRICHMENT PAYLOAD
# ═══════════════════════════════════════════════════════════════════════════════
$svcByBinOut = @{}
foreach ($k in $servicesByBinary.Keys) {
    $svcByBinOut[$k] = @($servicesByBinary[$k])
}

$auditOutput = [PSCustomObject]@{
    GeneratedAt      = (Get-Date).ToString("o")
    ElapsedSeconds   = [Math]::Round($swTotal.Elapsed.TotalSeconds, 2)
    DirectLeadsCount = $directLeads.Count
    ServicesByName   = $servicesAudit
    ServicesByBinary = $svcByBinOut
    ScheduledTasks   = $tasksAudit
    DcomAppIds       = @($dcomAudit)
    WmiNamespaces    = @($wmiAudit)
    UipiWindows      = @($uipiAudit)
    ProcessDacls     = @($processAudit)
    DriverDevices    = @($deviceAudit)
    DirectLeads      = @($directLeads)
}

$outDir = Split-Path -Parent $OutputPath
if (-not [string]::IsNullOrWhiteSpace($outDir) -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$auditOutput | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding UTF8

if (-not $Silent) {
    Write-Host "[+] Phase 2 Subsystem Audit Complete in $($auditOutput.ElapsedSeconds)s." -ForegroundColor Green
    Write-Host "    -> Services Audited:       $($servicesAudit.Count)"
    Write-Host "    -> Scheduled Tasks Audited:$($tasksAudit.Count)"
    Write-Host "    -> DCOM AppIDs Flagged:    $($dcomAudit.Count)"
    Write-Host "    -> WMI Namespaces Flagged: $($wmiAudit.Count)"
    Write-Host "    -> UIPI High-IL Windows:   $($uipiAudit.Count)"
    Write-Host "    -> Direct Subsystem Leads: $($directLeads.Count)"
    Write-Host "    -> Exported to:            $OutputPath" -ForegroundColor Cyan
}
