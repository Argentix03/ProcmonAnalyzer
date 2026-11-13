param (
    [Parameter(Mandatory=$true)]
    [string]$JsonFeed,

    [switch]$Silent
)

# ═══════════════════════════════════════════════════════════════════════════════
#  Analyze-ExecutionLeads (rev 3.3)
#
#  Reads a writable_paths.json feed (from Parse-ProcmonWriteables rev 3.3) and
#  emits two queues:
#    high_confidence_leads.json    — heuristic matches, structured per primitive
#    cognitive_review_queue.json   — items that need agent semantic review
#
#  Threat model: perspective-aware across LowPriv (medium-IL standard user),
#  MediumILAdmin (UAC-filtered split-token admin), and HighILAdmin (elevated
#  admin targeting SYSTEM / TrustedInstaller).
# ═══════════════════════════════════════════════════════════════════════════════

$feedDir = Split-Path $JsonFeed
if ([string]::IsNullOrWhiteSpace($feedDir)) { $feedDir = ".\" }

Write-Host "[*] Initiating Advanced Execution Lead Analysis on: $JsonFeed" -ForegroundColor Cyan
Write-Host "    Mode: Perspective-Aware Attacker Model (LowPriv / MediumILAdmin / HighILAdmin)" -ForegroundColor Gray

if (-not (Test-Path $JsonFeed)) {
    Write-Host "[-] JSON feed not found" -ForegroundColor Red
    exit 1
}

$hardcodedJsonPath = Join-Path $feedDir "high_confidence_leads.json"
$cognitiveJsonPath = Join-Path $feedDir "cognitive_review_queue.json"

$rawContent = Get-Content $JsonFeed -Raw
$parsedJson = if (-not [string]::IsNullOrWhiteSpace($rawContent)) { $rawContent | ConvertFrom-Json } else { $null }
$rawData = @($parsedJson | Where-Object { $null -ne $_ })
if ($rawData.Count -eq 0) {
    Write-Host "[!] No paths in JSON feed. Writing empty output queues." -ForegroundColor Yellow
    "[]" | Out-File $hardcodedJsonPath -Encoding UTF8
    "[]" | Out-File $cognitiveJsonPath -Encoding UTF8
    exit 0
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

# Compute the escalation category for a lead. Used to map leads to the right
# research prompt and decide severity adjustments.
#
# Inputs:
#   $writableFrom        : "LowPriv" | "MediumILAdmin" | "HighILAdmin" | "None"
#                          (lowest perspective at which the path is writable)
#   $consumerIntegrity   : process integrity of the privileged consumer ("System","High","Medium",...)
#   $primitive           : the matched ExploitPrimitive string
#   $anyImpersonating    : whether the consumer impersonates the user at any point
#
# Categories:
#   LPE             — low-priv user can plant; consumer at High/System
#   UAC_Bypass      — only medium-IL admin can plant; consumer at High (auto-elevating)
#   Admin_To_System — only high-IL admin can plant; consumer is System / TI
#   RCE_Lateral     — primitive is a coercion / web / cert family
#   Proxy_Execution — primitive is a LOLBin / autorun family
#   Same_Level      — writability and consumer at the same effective IL; no escalation
#   Unknown         — cannot determine
function Get-EscalationCategory {
    param(
        [string]$writableFrom,
        [string]$consumerIntegrity,
        [string]$primitive,
        [bool]$anyImpersonating = $false
    )

    $consumerHighIL   = $consumerIntegrity -in @('High','System','Protected Process')
    $consumerSystemTI = $consumerIntegrity -in @('System','Protected Process')
    $consumerUnknown  = [string]::IsNullOrWhiteSpace($consumerIntegrity) -or ($consumerIntegrity -eq 'Unknown')

    # Primitive overrides — some primitives are inherently a specific category,
    # gated by the writability perspective so HighILAdmin-only paths are never
    # misclassified as low-priv LPEs.
    if ($primitive -in @('COM_Hijack_HKCU','Env_Hijack_HKCU')) { return 'UAC_Bypass' }
    if ($primitive -in @('Service_BinaryPath','IFEO_Debugger','AeDebug','ScheduledTask_Plant')) {
        if ($writableFrom -eq 'LowPriv')       { return 'LPE' }
        if ($writableFrom -eq 'MediumILAdmin') { return 'UAC_Bypass' }
        return 'Admin_To_System'
    }
    if ($primitive -in @('URL_NTLM_Coerce','Theme_NTLM_Coerce','DesktopIni_Coerce','WebShell_Plant','LNK_Hijack','Cert_Plant')) {
        return 'RCE_Lateral'
    }
    if ($primitive -in @('LOLBin_Proxy','AutoRun_Persistence')) {
        return 'Proxy_Execution'
    }
    if ($primitive -in @('AppExecAlias_Plant','PowerShell_Profile','Electron_AsarTamper','SxS_DotLocal','Dependency_Hijack','Binary_Plant_HighPriv','Pipe_Hijack','Config_Poison')) {
        switch ($writableFrom) {
            'LowPriv'       { return 'LPE' }
            'MediumILAdmin' { return 'UAC_Bypass' }
            'HighILAdmin'   { if ($consumerSystemTI -or $consumerUnknown) { return 'Admin_To_System' } else { return 'Same_Level' } }
            default         { return 'LPE' }
        }
    }

    switch ($writableFrom) {
        'LowPriv'        { if ($consumerHighIL -or $consumerUnknown) { return 'LPE' }             else { return 'Same_Level' } }
        'MediumILAdmin'  { if ($consumerHighIL -or $consumerUnknown) { return 'UAC_Bypass' }      else { return 'Same_Level' } }
        'HighILAdmin'    { if ($consumerSystemTI)                    { return 'Admin_To_System' } else { return 'Same_Level' } }
        default          { return 'Unknown' }
    }
}

# Map an escalation category to the matching research-prompt id (mirror of
# the catalog in ui/server.js and skills/Research-Lead/scripts/Get-ResearchPromptForPrimitive.ps1).
function Get-ResearchPromptIdForCategory {
    param([string]$category, [string]$primitive)
    switch ($category) {
        'LPE'              { return 'lpe' }
        'UAC_Bypass'       { return 'uac' }
        'Admin_To_System'  { return 'admin_kernel' }
        'RCE_Lateral'      { return 'rce_lateral' }
        'Proxy_Execution'  { return 'proxy' }
        default            { return 'lpe' }   # fallback
    }
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
    $hasAllOpenRP     = ($null -ne (Get-FieldValue $entry "AllOpenReparsePoint" $null))
    $allOpenRP        = if ($hasAllOpenRP) { [bool](Get-FieldValue $entry "AllOpenReparsePoint" $false) } else { $openRP -and $anyOpenRP }
    $hasAllOpenLink   = ($null -ne (Get-FieldValue $entry "AllOpenLink" $null))
    $allOpenLink      = if ($hasAllOpenLink) { [bool](Get-FieldValue $entry "AllOpenLink" $false) } else { $openLink -and $anyOpenLink }
    $highestIntegrity = Get-FieldValue $entry "HighestIntegrity" $integrity
    $isUserOnly       = [bool](Get-FieldValue $entry "IsUserOnlyConsumer" $false)
    $sqosFromFeed     = Get-FieldValue $entry "SqosLevel" "NotSpecified"

    # Perspective-aware writability fields (rev 3 parser). Backwards compat:
    # if the feed predates rev 3, every path defaults to LowPriv-writable
    # (the rev-2 parser only emitted LowPriv-writable paths anyway).
    $hasPerspectiveFields = ($null -ne (Get-FieldValue $entry "WritableFrom" $null))
    if ($hasPerspectiveFields) {
        $writableLow  = [bool](Get-FieldValue $entry "WritableByLowPriv" $false)
        $writableMed  = [bool](Get-FieldValue $entry "WritableByMediumILAdmin" $false)
        $writableHigh = [bool](Get-FieldValue $entry "WritableByHighILAdmin" $false)
        $writableFrom = Get-FieldValue $entry "WritableFrom" "LowPriv"
        $intLabel     = Get-FieldValue $entry "IntegrityLabel" "Default"
    } else {
        $writableLow  = $true
        $writableMed  = $true
        $writableHigh = $true
        $writableFrom = "LowPriv"
        $intLabel     = "Default"
    }

    $isDirectLead     = $false
    $severity         = "Low"
    $type             = "Unknown"
    $reason           = ""
    $exploitPrimitive = ""

    $opDirection   = Get-OperationDirection -Operation $operation
    $sqos          = Get-SqosLevel -Detail $detail -Existing $sqosFromFeed
    $effectiveIntegrity = if (Test-PrivilegedIntegrity -Integrity $integrity) {
        $integrity
    } elseif (Test-PrivilegedIntegrity -Integrity $highestIntegrity) {
        $highestIntegrity
    } else {
        $integrity
    }
    $isPrivileged    = (Test-PrivilegedIntegrity -Integrity $effectiveIntegrity) -or $anyPrivRead -or $anyPrivWrite
    $isPrivilegedAny = $isPrivileged
    $isNameNotFound  = ($result -match "(?i)NAME NOT FOUND")
    # Filesystem vs registry — gates the FS-only LPE primitives (Rules 5/6/7).
    # NTFS junction / oplock / pipe-symlink plants require an actual FS path;
    # they can't be planted on a registry key. Mirrors the parser's path class.
    $isFsPath        = ($path -match "^[a-zA-Z]:\\") -or ($path -match "^\\\\")
    $effectivePrincipal = Get-EffectivePrincipal -Integrity $effectiveIntegrity -Impersonating $impersonating

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
            Integrity = $effectiveIntegrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "PagingIO_or_KernelAttribution"
        })
        continue
    }

    # When EVERY observed event already had Open Reparse Point set, the
    # consumer is correctly using FILE_FLAG_OPEN_REPARSE_POINT. Demote to the
    # cognitive queue with a hint so an analyst can still scan the surrounding
    # code path (LPE §2: another open of the same path elsewhere may still be
    # missing the flag).
    if ($allOpenRP -and -not $anyWrite) {
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
            Integrity = $effectiveIntegrity
            Impersonating = $impersonating
            OperationDirection = $opDirection
            SqosLevel = $sqos
            FilterReason = "OpenReparsePoint_AlwaysSet"
        })
        continue
    }
    # Same logic for registry: every observed open had REG_OPTION_OPEN_LINK.
    if ($allOpenLink -and ($path -match "^HK")) {
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
            Integrity = $effectiveIntegrity
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
            Integrity = $effectiveIntegrity
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
    if ($path -match "^\\\\\.\\pipe\\" -and ($writableLow -or $writableMed)) {
        $severity = "Critical"
        $type = "Named Pipe Hijacking / Impersonation"
        $exploitPrimitive = "Pipe_Hijack"
        $reason = "Direct named-pipe endpoint at a writable location. A medium-IL attacker can plant a pipe server here and capture connecting clients."
        if ($isPrivileged) {
            $reason += " PRIVILEGED CLIENT ($effectiveIntegrity) connects → token material available."
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
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(?i)\\AppData\\Local\\Microsoft\\WindowsApps\\") {
        $severity = "High"
        $type = "App Execution Alias Squatting"
        $exploitPrimitive = "AppExecAlias_Plant"
        $reason = "Path lives under %LOCALAPPDATA%\\Microsoft\\WindowsApps — an App Execution Alias folder that is on the user's PATH. Dropping a binary here that shadows an unqualified command ('notepad', 'wt', 'winget', 'bash', etc.) hijacks subsequent invocations. ACL anomaly note: Microsoft default is TrustedInstaller-owned with conditional WIN://SYSAPPID ACEs; a user-FullControl ACE here is non-default and is itself worth flagging."
        if ($isPrivileged) {
            $reason += " A privileged consumer ($effectiveIntegrity) was observed touching this folder — chain potentially elevates beyond user-scope squatting."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.6: PowerShell profile sinks (auto-loaded on every shell start)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(?i)\\(Documents\\(WindowsPowerShell|PowerShell)\\(Microsoft\.)?(PowerShell_)?profile\.ps1|Documents\\(WindowsPowerShell|PowerShell)\\Modules\\.+\.(psm1|ps1))$") {
        $severity = "High"
        $type = "PowerShell Profile Auto-Load Sink"
        $exploitPrimitive = "PowerShell_Profile"
        $reason = "Writable PowerShell profile / auto-loaded module. Every interactive PS session sources this on launch. Drop 'Invoke-Expression'/payload here for execution at the integrity level of whatever account opens PowerShell next (including admin-RunAs, scheduled tasks, or DSC pulls)."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.7: Electron app.asar tamper surface
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) -and $path -match "(?i)\\resources\\app\.asar(\.unpacked)?(\\|$)") {
        $severity = "High"
        $type = "Electron app.asar Tamper"
        $exploitPrimitive = "Electron_AsarTamper"
        $reason = "User-writable Electron 'app.asar' archive. Even when the EXE is AuthentiCode-signed, Electron's signature DOES NOT cover the '.asar' payload. Unpack/repack with '@electron/asar' to inject 'require('child_process').exec(...)' for in-process RCE at the Electron host's integrity. Verify 'EnableEmbeddedAsarIntegrityValidation' fuse with 'npx @electron/fuses read --app <exe>'; if OFF, plain extract-repack works (CVE-2024-46992 / CVE-2025-55305 cover the on-fuse cases)."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.8: Service Binary Path / IFEO debugger / AeDebug surfaces
    #
    # These keys are admin-only-write by default. The interpretation depends
    # on which perspective made the path appear in the writable feed:
    #
    #   * LowPriv-writable      => ACL ANOMALY. A non-admin user can rewrite
    #                              this value; that's a non-default ACL bug
    #                              that should be flagged Critical.
    #   * HighILAdmin-only       => Standard admin -> SYSTEM primitive. Not an
    #                              anomaly, just the well-known elevation
    #                              path. Still relevant for admin -> SYSTEM
    #                              research. Tagged High severity and routed
    #                              to AdminToSystemKernel_Research_Prompt.
    # ─────────────────────────────────────────────────────────────────────────
    $isSvcValuePath = ($path -match "(?i)^HKLM\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Services\\.+\\(ImagePath|ServiceDll|FailureCommand)$")
    $isSvcKeyAnomaly = (($writableLow -or $writableMed) -and ($path -match "(?i)^HKLM\\SYSTEM\\(CurrentControlSet|ControlSet\d+)\\Services\\[^\\]+(\\Parameters)?$"))
    if (-not $isDirectLead -and ($isSvcValuePath -or $isSvcKeyAnomaly)) {
        $exploitPrimitive = "Service_BinaryPath"
        if ($writableLow) {
            $severity = "Critical"
            $type = "Service Binary Path Hijack (ACL anomaly)"
            $reason = "Service key or ImagePath/ServiceDll under HKLM is writable by a NON-ADMIN user. Non-default ACL; direct LPE primitive: rewrite the value, restart the service, run as the service account."
        } else {
            $severity = "High"
            $type = "Service Binary Path Hijack (admin -> SYSTEM)"
            $reason = "Service ImagePath/ServiceDll under HKLM. Standard admin -> SYSTEM primitive: as elevated admin, rewrite the value, stop+start the service, code runs as SYSTEM (or whichever account the service is configured to run as). Not an anomaly; documented technique."
        }
        $isDirectLead = $true
    }
    $isIfeoValuePath = ($path -match "(?i)^HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\.+\\(Debugger|GlobalFlag|VerifierDlls)$")
    $isIfeoKeyAnomaly = (($writableLow -or $writableMed) -and ($path -match "(?i)^HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[^\\]+$"))
    if (-not $isDirectLead -and ($isIfeoValuePath -or $isIfeoKeyAnomaly)) {
        $exploitPrimitive = "IFEO_Debugger"
        if ($writableLow) {
            $severity = "Critical"
            $type = "IFEO Debugger Hijack (ACL anomaly)"
            $reason = "IFEO Debugger key/value writable to a NON-ADMIN user. Non-default ACL; plant your binary here; whenever the targeted EXE is launched, the OS spawns YOUR debugger as the parent."
        } else {
            $severity = "High"
            $type = "IFEO Debugger Hijack (admin -> SYSTEM)"
            $reason = "IFEO Debugger key. As admin you can plant a debugger that runs at whatever integrity the launching process eventually reaches. Standard admin -> SYSTEM persistence + execution surface."
        }
        $isDirectLead = $true
    }
    $isAeDebugValuePath = ($path -match "(?i)^HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\AeDebug\\(Debugger|Auto)$")
    $isAeDebugKeyAnomaly = (($writableLow -or $writableMed) -and ($path -match "(?i)^HKLM\\SOFTWARE\\(Wow6432Node\\)?Microsoft\\Windows NT\\CurrentVersion\\AeDebug$"))
    if (-not $isDirectLead -and ($isAeDebugValuePath -or $isAeDebugKeyAnomaly)) {
        $exploitPrimitive = "AeDebug"
        if ($writableLow) {
            $severity = "Critical"
            $type = "AeDebug Postmortem Debugger Hijack (ACL anomaly)"
            $reason = "AeDebug Debugger key/value writable to a NON-ADMIN user. Non-default ACL; any crashing process triggers your binary as the postmortem handler."
        } else {
            $severity = "High"
            $type = "AeDebug Postmortem Debugger Hijack (admin -> SYSTEM)"
            $reason = "AeDebug Debugger value. As admin you can install a postmortem debugger that fires on any crash, including SYSTEM service crashes; reliable admin -> SYSTEM technique."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1.9: COM Hijack via HKCU\Software\Classes\CLSID
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(?i)^(HKCU|HKEY_CURRENT_USER|HKU\\[^\\]+)\\Software\\Classes\\(CLSID|Wow6432Node\\CLSID|Interface)\\\{[0-9a-fA-F-]+\}") {
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
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(?i)^(HKCU|HKEY_CURRENT_USER|HKU\\[^\\]+)\\Environment(\\|$)") {
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
    #
    # Gated so that non-privileged existing user-space binaries without a
    # privileged consumer in the trace fall through to Cognitive Queue
    # Branch 4 (PersistenceBinary_NoPrivilegedConsumer), while:
    #   - Any LowPriv/MedIL-writable binary in a high-priv directory
    #   - Any binary touched by a privileged or impersonating process
    #   - Any missing binary (NAME NOT FOUND) in a writable directory
    # fires directly here.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(exe|dll|sys|cpl|ocx|efi|scr|msi|msp|msc|com|hta|jar|xll|wll|xla|drv|tlb|node)$") {
        $isHighPrivDir = ($path -match "(?i)(System32|SysWOW64|Program Files|ProgramData\\[^\\]+\\|\\Windows\\)")
        $shouldFireRule2 = ($isHighPrivDir -and ($writableLow -or $writableMed)) `
            -or ($isPrivilegedAny -and ($writableLow -or $writableMed -or $writableHigh)) `
            -or ($anyImpersonating -and ($writableLow -or $writableMed)) `
            -or ($isNameNotFound -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)))

        if ($shouldFireRule2) {
            if ($isHighPrivDir) {
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
                $reason += " LOADED BY PRIVILEGED PROCESS ($effectiveIntegrity) → direct code execution at that integrity."
            }
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.1: SxS / DotLocal Manifest Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) -and $path -match "\.(manifest|local)$") {
        $severity = "Critical"
        $type = "SxS / DotLocal Manifest Poisoning"
        $exploitPrimitive = "SxS_DotLocal"
        $reason = "Dropping a '.local' directory or '.manifest' file hijacks DLL load order for legitimate applications. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.2: Package / Dependency Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) -and $path -match "(node_modules|site-packages|vendor\\|gems\\|\\.cargo\\registry)") {
        $severity = "Critical"
        $type = "Dependency / Package Subversion"
        $exploitPrimitive = "Dependency_Hijack"
        $reason = "Writable dependency folder. Any library requested by the application can be transparently replaced. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.3: Web Shell / Webroot Planting
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(inetpub\\wwwroot|xampp\\htdocs|tomcat\\webapps|nginx\\html)" -and $path -match "\.(aspx|php|jsp|asmx|html|ashx|asp)$") {
        $severity = "Critical"
        $type = "Web Shell Proxy / Server Planting"
        $exploitPrimitive = "WebShell_Plant"
        $reason = "Writing scripts into a webroot creates a web shell. No privileges needed if the directory is writable."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.4: LNK Shortcut Poisoning + URL/Theme/PIF coercion
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "\.lnk$") {
        $severity = "High"
        $type = "LNK Shortcut Hijacking"
        $exploitPrimitive = "LNK_Hijack"
        $reason = "Writable .lnk shortcut. Modify target to redirect execution; or set Icon to UNC for NTLM coercion (CVE-2025-50154 family). No privileges needed."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "\.url$") {
        $severity = "High"
        $type = ".URL Internet Shortcut NTLM Coercion"
        $exploitPrimitive = "URL_NTLM_Coerce"
        $reason = "Writable '.url' Internet shortcut. CVE-2024-43451 family — 'IconFile=\\\\attacker\\share\\icon.ico' triggers NTLMv2 from any user who interacts with the shortcut (single click, right-click, drag-move). Capture with Responder; relay or crack."
        $isDirectLead = $true
    }
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "\.(theme|themepack|deskthemepack)$") {
        $severity = "High"
        $type = "Theme NTLM Coercion (CVE-2024-21320 family)"
        $exploitPrimitive = "Theme_NTLM_Coerce"
        $reason = "Writable theme file. UNC-pointed 'Wallpaper=' or 'BrandImage=' coerces NTLM auth on theme load. Patched by MSRC; verify mitigation status."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.5: desktop.ini IconResource SMB coercion (Section 8 of addendum)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and $path -match "(?i)\\desktop\.ini$") {
        $severity = "Medium"
        $type = "desktop.ini IconResource Coercion"
        $exploitPrimitive = "DesktopIni_Coerce"
        $reason = "Writable desktop.ini. `[.ShellClassInfo] IconResource=\\\\attacker\\share\\icon.ico` coerces an SMB handshake from any interactive user who renders the parent folder in Explorer. Severity is environment-dependent: HIGH on domain / hybrid-AAD hosts (NTLMv2 captured/relayed), LOW on AAD-only single-account hosts."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 4: Scheduled Task XML (placed BEFORE Rule 3 so \System32\Tasks\...
    # is not shadowed by Rule 3's generic Tasks\ pattern)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(?i)\\(System32|SysWOW64)\\Tasks\\.+$|\\schedule\\taskcache\\tree\\") {
        $exploitPrimitive = "ScheduledTask_Plant"
        if ($writableLow) {
            $severity = "Critical"
            $type = "Scheduled Task Definition Hijack (ACL anomaly)"
            $reason = "Scheduled-task definition writable by a NON-ADMIN user. Default ACL is Admins/SYSTEM only. Non-default ACL; rewriting the XML's '<Command>' lets you piggy-back on the trigger and run as whichever principal the task is configured to run as."
        } else {
            $severity = "High"
            $type = "Scheduled Task Definition Hijack (admin -> SYSTEM)"
            $reason = "Scheduled-task definition. As admin you can rewrite the XML's '<Command>' to run as the task's principal (often SYSTEM). Standard admin -> SYSTEM persistence + execution surface; not an anomaly."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 3: AutoRun / Script Persistence
    # ─────────────────────────────────────────────────────────────────────────
    $isPersistenceLocation = ($path -match "(?i)(Startup|\\CurrentVersion\\Run(Once|OnceEx|Services|ServicesOnce)?(\\|$)|\\Windows\\Tasks\\|wbem\\mof|scripts\\(Startup|Logon|Shutdown|Logoff))")
    $isScriptExt = ($path -match "(?i)\.(bat|ps1|psm1|psd1|vbs|vbe|cmd|wsf|js|jse|wsh)$")
    if (-not $isDirectLead -and ($writableLow -or $writableMed) -and (
        $isPersistenceLocation -or ($isScriptExt -and ($isPrivilegedAny -or $anyImpersonating -or $isNameNotFound))
    )) {
        $severity = "High"
        $type = "AutoRun / Script Persistence"
        $exploitPrimitive = "AutoRun_Persistence"
        $reason = "Writable script file or persistence location. Likely executed on boot/logon or by a privileged/impersonating task. No privileges needed to modify."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 8: Config Poisoning — Structured Detection (placed BEFORE generic
    # Rule 5/6/7 path-redirection rules so privileged reads of .config/.xml/.json
    # by framework hosts classify as Config_Poison rather than SMB_Coercion)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) -and $path -match "\.(config|xml|json|yml|yaml)$") {
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
    # RULE 9: Certificate / Crypto Store Planting (placed BEFORE generic
    # Rule 5/6/7 path-redirection rules so privileged cert reads/writes classify
    # as Cert_Plant rather than SMB_Coercion)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) -and ($path -match "\.(cer|crt|pfx|p12|pem|key|p7b)$" -or
        $path -match "(?i)(Crypto\\Keys|Certificate|PKI|AuthRoot|ROOT\\Certificates|SystemCertificates\\Root)")) {
        $severity = "High"
        $type = "Certificate / Crypto Store Planting"
        $exploitPrimitive = "Cert_Plant"
        $reason = "Writable certificate or crypto store path. Plant trusted root CA to enable MitM, or inject code-signing cert to bypass signature checks. No privileges needed to write."
        if ($isPrivileged) {
            $severity = "Critical"
            $reason += " CONSUMED BY PRIVILEGED PROCESS ($effectiveIntegrity) → system-wide trust manipulation."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 7: Pipe Planting via Path Redirection (placed BEFORE Rule 5 so
    # missing local paths with explicit SQOS levels are not shadowed by Rule 5)
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $isNameNotFound -and $writableLow -and
        ($path -notmatch "^\\\\\.\\pipe\\") -and ($path -match "^[a-zA-Z]:\\") -and ($sqos -ne "NotSpecified")) {
        $severity = "High"
        $type = "Pipe Planting via Path Redirection"
        $exploitPrimitive = "Pipe_Plant_Redirect"
        $reason = "PRIVILEGED PROCESS ($effectiveIntegrity) attempts to open a NON-EXISTENT file path with explicit SQOS. Plant symlink to named pipe → capture connecting client for NTLM relay or token impersonation. Effective principal: $effectivePrincipal."
        if ($sqos -in @("Impersonation","Delegation")) {
            $severity = "Critical"
            $reason += " SQOS=$sqos → allows impersonation-level access. SMB relay AND token capture both viable."
        } elseif ($sqos -eq "Identification") {
            $reason += " SQOS=Identification → impersonation blocked, but SMB relay still works."
        } elseif ($sqos -eq "Anonymous") {
            $severity = "Medium"
            $reason += " SQOS=Anonymous → DoS / timing side-channel only."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 5: SMB / NTLM Coercion via Path Redirection (LPE prompt §3.5)
    #
    # Gating: requires (a) a low-priv writable path — the entire exploit is a
    # low-priv user planting an NTFS junction → drive-letter → \\attacker\share,
    # so admin-only-writable paths can't trigger this primitive; admin already
    # has SYSTEM-equivalent surface elsewhere. (b) a filesystem path — you can't
    # plant an NTFS junction on a registry key.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $opDirection -eq "Read" `
        -and $writableLow -and $isFsPath) {
        $severity = "Critical"
        $type = "SMB / NTLM Coercion Candidate"
        $exploitPrimitive = "SMB_Coercion"
        $reason = "PRIVILEGED PROCESS ($effectiveIntegrity) reads from a user-writable path. Plant NTFS junction → drive-letter → \\\\attacker\\share via the medium-IL chain (LPE prompt §3.5: DefineDosDevice + mklink /j) to capture/relay Net-NTLMv2. Effective principal: $effectivePrincipal."
        if ($isNameNotFound) {
            $reason += " PATH DOES NOT EXIST → trivial to plant junction or pipe-symlink redirect (Pipe_Plant_Redirect) without race."
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
    if (-not $isDirectLead -and ($isPrivileged -and $opDirection -eq "Write" -or $anyPrivWrite) `
        -and $writableLow -and $isFsPath) {
        $severity = "Critical"
        $type = "Arbitrary Write via Oplock+Junction"
        $exploitPrimitive = "Oplock_ArbitraryWrite"
        $reason = "PRIVILEGED PROCESS ($effectiveIntegrity) WRITES to a user-writable path. Set exclusive oplock on directory → swap NTFS junction mid-write → write lands in arbitrary privileged location (System32, drivers folder, Tasks XML). NO SPECIAL PRIVILEGES REQUIRED. Effective principal: $effectivePrincipal."
        if ($path -match "\.(tmp|log|cache|dat|bak|old|etl|wer)$") {
            $reason += " Temp/cache/log file pattern → high likelihood of repeated writes (reliable trigger)."
        }
        if ($anyPrivRead -and $anyPrivWrite) {
            $reason += " BOTH privileged READ and WRITE observed → strong race-window opportunity (TOCTOU between check and consume)."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 10: Registry Path Coercion via REG_LINK
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and ($writableLow -or $writableMed) -and ($path -match "^HKCU" -or $path -match "^HKEY_CURRENT_USER" -or $path -match "^HKU\\" -or $path -match "^HKEY_USERS\\")) {
        if (-not $allOpenLink) {
            $severity = "Critical"
            $type = "Registry Path Coercion Candidate"
            $exploitPrimitive = "Registry_Coercion"
            $reason = "PRIVILEGED PROCESS ($effectiveIntegrity) accesses a user-writable registry key without REG_OPTION_OPEN_LINK. Plant a REG_LINK redirecting elsewhere in the user's hive. NO SPECIAL PRIVILEGES REQUIRED. Effective principal: $effectivePrincipal."
            if ($anyImpersonating) {
                $reason += " Impersonation context observed → consumer is reading USER's hive while running as user — classic CVE-2014-6322 archetype."
            }
            if ($anyOpenLink) {
                $reason += " (Caveat: at least one observed open used REG_OPTION_OPEN_LINK — target an open that omits the flag.)"
                $severity = "High"
            }
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # LOLBin cross-reference (extension-aware)
    # ─────────────────────────────────────────────────────────────────────────
    $extension = if ($path -match '\.[A-Za-z0-9]{1,6}$') { $matches[0].ToLowerInvariant() } else { "" }
    if ($writableLow -or $writableMed -or ($writableHigh -and $isPrivilegedAny)) {
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
    }

    # ─────────────────────────────────────────────────────────────────────────
    # COGNITIVE QUEUE — items that need agent semantic analysis
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead) {
        if ($isFsPath -and ($writableLow -or $writableMed) -and (-not $isPrivilegedAny) -and $path -match "(?i)\.(dll|exe|sys|drv|ocx|cpl|ax|ps1|psm1|psd1|bat|cmd|vbs|js|wsf|hta|jar|war|node|pyd|so)$") {
            # Branch 4 (rev 3.2/3.3): persistence-class binary/script in a
            # writable location with no privileged actor observed in THIS
            # trace. Evaluated before the user-only noise drop so latent
            # persistence/supply-chain binaries are preserved.
            $hint = "Persistence / supply-chain binary candidate. Writable executable or script in a $writableFrom-writable location; no privileged consumer was observed in this trace, but the file may still be loaded later by a privileged process (service startup, scheduled task, AV scan with engine load, dependency resolution) or trigger on user action."
            $hint += " Check: (1) is this binary referenced by a service ImagePath / scheduled-task action / Run key / Startup folder; (2) does a higher-IL process load this directory on demand (DLL search-order, Authenticode-signed loader); (3) for scripts, is this auto-loaded on shell start / user logon / explorer interaction."
            if ($anyWrite -and $anyRead) {
                $hint += " NOTE: BOTH read and write observed → race-window candidate if a privileged consumer joins later."
            } elseif ($opDirection -eq "Write") {
                $hint += " NOTE: Process WRITES this binary → if a privileged consumer loads it before next overwrite, you have a code-exec primitive."
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
                Integrity = $effectiveIntegrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                WritableFrom = $writableFrom
                AnyPrivRead  = $anyPrivRead
                AnyPrivWrite = $anyPrivWrite
                OpenReparsePoint = $openRP
                OpenLink = $openLink
                FilterReason = "PersistenceBinary_NoPrivilegedConsumer"
            })
            continue
        }

        # LPE §9: "user-already-has-it" — when no direct primitive rule matched
        # and the path is not a persistence binary, drop entries where the only
        # consumer is the current user's own session with no privileged or
        # impersonating actor.
        if ($isUserOnly -and (-not $isPrivilegedAny) -and (-not $anyImpersonating)) {
            $dropUserOnly++
            continue
        }

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
                Integrity = $effectiveIntegrity
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
                Integrity = $effectiveIntegrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                AnyPrivRead  = $anyPrivRead
                AnyPrivWrite = $anyPrivWrite
                OpenReparsePoint = $openRP
                OpenLink = $openLink
            })
        } elseif ($isPrivilegedAny -and $isFsPath) {
            $writabilityNote = if ($writableLow) {
                "low-priv-writable"
            } elseif ($writableMed) {
                "admin-writable (medium-IL — UAC_Bypass surface if consumer is auto-elevated)"
            } elseif ($writableHigh) {
                "admin-writable (high-IL only — Admin_To_System surface)"
            } else {
                "not writable from any tracked perspective"
            }
            $hint = "Privileged-actor-on-path candidate (no primitive rule matched). Path is $writabilityNote. Effective principal: $effectivePrincipal. Direction: $opDirection. Worth checking: (1) DLL search-order / KnownDLLs override, (2) ImagePath / ServiceDll in a paired registry key, (3) auto-elevated COM server load, (4) signed-binary side-loading, (5) supply-chain plant if path is a vendor install dir, (6) for UNC: SMB credential exposure / MitM."
            if ($anyWrite -and $anyRead) {
                $hint += " NOTE: BOTH read and write observed → race-window candidate."
            } elseif ($opDirection -eq "Write") {
                $hint += " NOTE: Process WRITES this file → if you can race/redirect, this is an arbitrary-write primitive at the $writableFrom level."
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
                Integrity = $effectiveIntegrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                WritableFrom = $writableFrom
                AnyPrivRead  = $anyPrivRead
                AnyPrivWrite = $anyPrivWrite
                OpenReparsePoint = $openRP
                OpenLink = $openLink
                FilterReason = "PrivilegedActor_NoRuleMatched"
            })
        }
    } else {
        # Severity boost when same path has BOTH privileged Read and Write
        # (race-window candidate per LPE §3.7 oplock chain).
        if ($anyPrivRead -and $anyPrivWrite -and $severity -ne "Critical") {
            $severity = "Critical"
            $reason += " [Race window — privileged READ and WRITE on same path]"
        }

        # Compute escalation category from the writability perspective and the
        # consumer integrity. Drives downstream research-prompt routing.
        $escalationCategory = Get-EscalationCategory `
            -writableFrom $writableFrom `
            -consumerIntegrity $effectiveIntegrity `
            -primitive $exploitPrimitive `
            -anyImpersonating $anyImpersonating
        $promptId = Get-ResearchPromptIdForCategory -category $escalationCategory -primitive $exploitPrimitive

        # Same_Level: writability and consumer at the same effective IL —
        # not an escalation primitive, drop to cognitive queue with hint.
        if ($escalationCategory -eq 'Same_Level') {
            $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Operations = $operations
                Hint = "[Same-level — no escalation] Path is writable by '$writableFrom' and the observed consumer is at the same effective IL. Useful only as a sanity-check or for chained primitives; not a standalone escalation lead."
                TraceFile = (Get-FieldValue $entry "TraceFile")
                Timestamp = (Get-FieldValue $entry "Timestamp")
                Operation = $operation
                Result = $result
                Detail = $detail
                Integrity = $effectiveIntegrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
                EffectivePrincipal = $effectivePrincipal
                WritableFrom = $writableFrom
                IntegrityLabel = $intLabel
                EscalationCategory = $escalationCategory
                FilterReason = "Same_Level"
            })
            continue
        }

        $hardcodedLeads.Add([PSCustomObject]@{
            Severity = $severity
            Type = $type
            ExploitPrimitive = $exploitPrimitive
            EscalationCategory = $escalationCategory
            ResearchPromptId = $promptId
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
            Integrity = $effectiveIntegrity
            HighestIntegrity = $highestIntegrity
            Impersonating = $impersonating
            SqosLevel = $sqos
            OpenReparsePoint = $openRP
            OpenLink = $openLink
            AnyOpenReparsePoint = $anyOpenRP
            AllOpenReparsePoint = $allOpenRP
            AnyOpenLink = $anyOpenLink
            AllOpenLink = $allOpenLink
            AnyPrivRead  = $anyPrivRead
            AnyPrivWrite = $anyPrivWrite
            AnyImpersonating = $anyImpersonating
            # Perspective-aware (rev 3)
            WritableByLowPriv       = $writableLow
            WritableByMediumILAdmin = $writableMed
            WritableByHighILAdmin   = $writableHigh
            WritableFrom            = $writableFrom
            IntegrityLabel          = $intLabel
        })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

$severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4; "Unknown" = 5 }
$sortedLeads = @($hardcodedLeads | Sort-Object { $severityOrder[$_.Severity] })
$cognitiveArr = @($cognitiveQueue)

if ($sortedLeads.Count -eq 0) {
    "[]" | Out-File $hardcodedJsonPath -Encoding UTF8
} else {
    ConvertTo-Json -InputObject $sortedLeads -Depth 4 | Out-File $hardcodedJsonPath -Encoding UTF8
}

if ($cognitiveArr.Count -eq 0) {
    "[]" | Out-File $cognitiveJsonPath -Encoding UTF8
} else {
    ConvertTo-Json -InputObject $cognitiveArr -Depth 4 | Out-File $cognitiveJsonPath -Encoding UTF8
}

$primitiveStats = $hardcodedLeads | Group-Object ExploitPrimitive | Sort-Object Count -Descending
$categoryStats  = $hardcodedLeads | Group-Object EscalationCategory | Sort-Object Count -Descending
$writableFromStats = $hardcodedLeads | Group-Object WritableFrom | Sort-Object Count -Descending

Write-Host ""
Write-Host "[+] Heuristic Analysis Complete." -ForegroundColor Green
Write-Host "    -> High Confidence Leads: $($hardcodedLeads.Count)" -ForegroundColor Green
Write-Host "    -> Pushed to Cognitive Queue: $($cognitiveQueue.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "    False-Positive Filters Applied:" -ForegroundColor Cyan
Write-Host "       Paging-I/O / kernel attribution dropped: $dropPagingIO" -ForegroundColor Gray
Write-Host "       Open Reparse Point always-set demoted:    $dropOpenReparse" -ForegroundColor Gray
Write-Host "       REG_OPTION_OPEN_LINK always-set demoted:  $dropOpenLink"   -ForegroundColor Gray
Write-Host "       User-only-consumer (LPE prompt section 9) dropped: $dropUserOnly" -ForegroundColor Gray
Write-Host "       Benign-readers-only demoted:              $dropBenignReaderOnly" -ForegroundColor Gray
Write-Host ""
Write-Host "    Escalation Category Breakdown:" -ForegroundColor Cyan
foreach ($stat in $categoryStats) {
    Write-Host "       $($stat.Name): $($stat.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "    Writable-From Perspective Breakdown:" -ForegroundColor Cyan
foreach ($stat in $writableFromStats) {
    Write-Host "       $($stat.Name): $($stat.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "    Exploit Primitive Breakdown:" -ForegroundColor Cyan
foreach ($stat in $primitiveStats) {
    Write-Host "       $($stat.Name): $($stat.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "[!] INSTRUCTION: Agent should now ingest '$cognitiveJsonPath' and formulate the final Execution_Leads_Report.md." -ForegroundColor Magenta
