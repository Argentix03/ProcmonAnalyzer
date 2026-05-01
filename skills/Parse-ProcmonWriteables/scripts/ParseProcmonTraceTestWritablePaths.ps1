param (
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = "C:\Users\Argentix\Downloads\BootLogProcMonAllHighPrivFiles.CSV",
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

Write-Host "Calculating total size of CSV feed for progress telemetry..." -ForegroundColor Cyan
$totalLines = 0
try {
    $reader = New-Object System.IO.StreamReader($CsvPath)
    while ($reader.ReadLine() -ne $null) { $totalLines++ }
} finally {
    if ($reader) { $reader.Close() }
}
Write-Host "Total lines to process: $totalLines" -ForegroundColor Cyan

Write-Host "Streaming CSV via TextFieldParser (best-event scoring per canonical path)..." -ForegroundColor Cyan

# Dictionary keyed by CANONICAL path; preserves original Path for display.
$pathProcessMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Hashtable]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:skippedErrors = New-Object System.Collections.Generic.List[PSCustomObject]
$script:skippedSelfTrace = 0
$script:skippedPagingIO  = 0

Add-Type -AssemblyName Microsoft.VisualBasic
$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($CsvPath)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(",")
$parser.HasFieldsEnclosedInQuotes = $true

$headerMap = @{}
if (-not $parser.EndOfData) {
    $headers = $parser.ReadFields()
    for ($i = 0; $i -lt $headers.Length; $i++) {
        $headerMap[$headers[$i].Trim().ToLower()] = $i
    }
}

$idxTime = if ($headerMap.ContainsKey("time of day")) { $headerMap["time of day"] } else { 0 }
$idxProc = if ($headerMap.ContainsKey("process name")) { $headerMap["process name"] } else { 1 }
$idxPid  = if ($headerMap.ContainsKey("pid")) { $headerMap["pid"] } else { -1 }
$idxOp   = if ($headerMap.ContainsKey("operation")) { $headerMap["operation"] } else { 3 }
$idxPath = if ($headerMap.ContainsKey("path")) { $headerMap["path"] } else { 4 }
$idxRes  = if ($headerMap.ContainsKey("result")) { $headerMap["result"] } else { 5 }
$idxDet  = if ($headerMap.ContainsKey("detail")) { $headerMap["detail"] } else { 6 }
$idxInt  = if ($headerMap.ContainsKey("integrity")) { $headerMap["integrity"] } else { -1 }
$idxImp  = if ($headerMap.ContainsKey("impersonating")) { $headerMap["impersonating"] } else { -1 }

$traceFileName = Split-Path $CsvPath -Leaf

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

# Path canonicalization for deduplication purposes only — original path preserved.
function ConvertTo-CanonicalPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $Path }
    $p = $Path
    # \??\X: → X:
    $p = $p -replace '^\\\?\?\\', ''
    # \Device\HarddiskVolume<N>\ → C:\ (best-effort; Native ETW lookup happens upstream)
    $p = $p -replace '^\\Device\\HarddiskVolume\d+', 'C:'
    # Collapse trailing whitespace/separator
    $p = $p.TrimEnd()
    while ($p.Length -gt 3 -and ($p.EndsWith("\") -or $p.EndsWith("/"))) { $p = $p.Substring(0, $p.Length - 1) }
    # Collapse double-separators
    $p = $p -replace '\\\\+', '\'
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
#   * Privileged WRITE > Privileged READ (write-what-where is the strongest primitive)
#   * NAME NOT FOUND > SUCCESS (planting without race condition)
#   * SYSTEM/High > Medium IL
#   * Open Reparse Point present is a NEGATIVE signal but not a kill (LPE §2)
function Get-EventScore {
    param([hashtable]$Evt)
    $s = 0
    $opDir = Get-OperationDirection -Operation $Evt.Operation
    if ($opDir -eq "Write") { $s += 100 }
    if (Test-PrivilegedIntegrity -Integrity $Evt.Integrity) { $s += 50 }
    if ($Evt.Result -match "(?i)NAME NOT FOUND")      { $s += 25 }
    if ($Evt.Result -match "(?i)PATH NOT FOUND")      { $s += 20 }
    if ($Evt.Result -match "(?i)REPARSE")             { $s += 10 }
    if ($Evt.IsPagingIO)        { $s -= 80 }   # demote, but don't drop
    if ($Evt.IsKernelOrCacheManager) { $s -= 30 }
    if ($Evt.OpenReparsePoint)  { $s -= 5 }    # informative not disqualifying
    if ($Evt.OpenLink)          { $s -= 5 }
    if ($Evt.Operation -match "(?i)Load Image") { $s += 40 } # Load Image strong signal
    return $s
}

# Detail-string flag parsing
function Get-DetailFlags {
    param([string]$Detail)
    $flags = @{
        IsPagingIO        = $false
        OpenReparsePoint  = $false
        OpenLink          = $false
        SqosLevel         = "NotSpecified"
        DesiredAccess     = ""
    }
    if ([string]::IsNullOrWhiteSpace($Detail)) { return $flags }

    if ($Detail -match '(?i)Paging\s*I/?O') { $flags.IsPagingIO = $true }
    # Procmon Options field: "Open Reparse Point", "Synchronous IO Non-Alert", etc.
    if ($Detail -match '(?i)Open\s*Reparse\s*Point') { $flags.OpenReparsePoint = $true }
    # Registry symlink open: "Open Link" or "REG_OPTION_OPEN_LINK"
    if ($Detail -match '(?i)Open\s*Link|REG_OPTION_OPEN_LINK|OBJ_OPENLINK') { $flags.OpenLink = $true }
    # SQOS impersonation level
    if ($Detail -match '(?i)Impersonation(?:\s*Level)?:\s*(Impersonation|Delegation|Identification|Anonymous)') {
        $flags.SqosLevel = $matches[1]
    }
    # Desired Access (informational; useful for Load Image / write detection)
    if ($Detail -match '(?i)Desired\s*Access:\s*([^,]+)') {
        $flags.DesiredAccess = $matches[1].Trim()
    }
    return $flags
}

# ── STREAM PARSE ─────────────────────────────────────────────────────────────

$lineCount = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()

while (-not $parser.EndOfData) {
    try {
        $fields = $parser.ReadFields()
        $lineCount++

        if ($fields.Length -lt 5) { continue }

        $processName = if ($idxProc -lt $fields.Length) { $fields[$idxProc] } else { "" }
        $pathRaw     = if ($idxPath -lt $fields.Length) { $fields[$idxPath] } else { "" }

        if ([string]::IsNullOrWhiteSpace($pathRaw)) { continue }

        # Filesystem path or registry hive path
        $isFsPath  = ($pathRaw -match "^[a-zA-Z]:\\") -or ($pathRaw -match "^\\\\")
        $isRegPath = ($pathRaw -match "^HKCU") -or ($pathRaw -match "^HKEY_CURRENT_USER") `
                  -or ($pathRaw -match "^HKU") -or ($pathRaw -match "^HKEY_USERS") `
                  -or ($pathRaw -match "^HKLM") -or ($pathRaw -match "^HKEY_LOCAL_MACHINE") `
                  -or ($pathRaw -match "^HKCR") -or ($pathRaw -match "^HKEY_CLASSES_ROOT")
        if (-not ($isFsPath -or $isRegPath)) { continue }

        if (Test-SelfTraceContamination -Path $pathRaw -ProcessName $processName) {
            $script:skippedSelfTrace++
            continue
        }

        $timeStr   = if ($idxTime -lt $fields.Length) { $fields[$idxTime] } else { "" }
        $opStr     = if ($idxOp -lt $fields.Length)   { $fields[$idxOp] } else { "" }
        $resStr    = if ($idxRes -lt $fields.Length)  { $fields[$idxRes] } else { "" }
        $detailStr = if ($idxDet -lt $fields.Length)  { $fields[$idxDet] } else { "" }
        $integStr  = if ($idxInt -ge 0 -and $idxInt -lt $fields.Length) { $fields[$idxInt] } else { "Unknown" }
        $impStr    = if ($idxImp -ge 0 -and $idxImp -lt $fields.Length) { $fields[$idxImp] } else { "" }

        $detailFlags = Get-DetailFlags -Detail $detailStr
        $isKernelAttrib = $kernelAttribProcs -contains $processName.Trim()

        # Track Paging-I/O drop count (still index it for the analyzer to know
        # the path was hit, but mark it). We do NOT drop the row entirely.
        if ($detailFlags.IsPagingIO) { $script:skippedPagingIO++ }

        $evt = @{
            Time                   = $timeStr
            Operation              = $opStr
            Result                 = $resStr
            Detail                 = $detailStr
            Integrity              = $integStr
            Impersonating          = $impStr
            ProcessName            = $processName
            IsPagingIO             = $detailFlags.IsPagingIO
            OpenReparsePoint       = $detailFlags.OpenReparsePoint
            OpenLink               = $detailFlags.OpenLink
            SqosLevel              = $detailFlags.SqosLevel
            DesiredAccess          = $detailFlags.DesiredAccess
            IsKernelOrCacheManager = $isKernelAttrib
        }

        $canonical = ConvertTo-CanonicalPath -Path $pathRaw

        if (-not $pathProcessMap.ContainsKey($canonical)) {
            $pathProcessMap[$canonical] = @{
                Path        = $pathRaw
                Processes   = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                Operations  = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                BestEvent   = $evt
                BestScore   = Get-EventScore -Evt $evt
                EventCount  = 0
                AnyWrite    = $false
                AnyRead     = $false
                AnyPrivWrite = $false
                AnyPrivRead  = $false
                AnyImpersonating = $false
                AnyOpenReparsePoint = $false
                AnyOpenLink = $false
                AnyPagingIO = $false
                NamePrincipals = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
            }
        }

        $rec = $pathProcessMap[$canonical]
        [void]$rec.Processes.Add($processName)
        [void]$rec.Operations.Add($opStr)
        $rec.EventCount++

        $opDir = Get-OperationDirection -Operation $opStr
        if ($opDir -eq "Write") { $rec.AnyWrite = $true } else { $rec.AnyRead = $true }
        $isPriv = Test-PrivilegedIntegrity -Integrity $integStr
        if ($isPriv -and $opDir -eq "Write") { $rec.AnyPrivWrite = $true }
        if ($isPriv -and $opDir -eq "Read")  { $rec.AnyPrivRead  = $true }
        if (-not [string]::IsNullOrWhiteSpace($impStr) -and $impStr -ne "Unknown") {
            $rec.AnyImpersonating = $true
            [void]$rec.NamePrincipals.Add($impStr)
        }
        if ($detailFlags.OpenReparsePoint) { $rec.AnyOpenReparsePoint = $true }
        if ($detailFlags.OpenLink)         { $rec.AnyOpenLink = $true }
        if ($detailFlags.IsPagingIO)       { $rec.AnyPagingIO = $true }

        $score = Get-EventScore -Evt $evt
        if ($score -gt $rec.BestScore) {
            $rec.BestEvent = $evt
            $rec.BestScore = $score
            # Re-pin display path when the higher-scoring event has a different
            # capitalization / trailing-slash variant so the report shows the
            # form most relevant to the lead.
            $rec.Path = $pathRaw
        }
    } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
        $null = $parser.ReadLine()
        $script:skippedErrors.Add([PSCustomObject]@{ Type = "Parser Error"; Error = "Malformed CSV Line"; Details = $_.Exception.Message })
    } catch {
        $null = $parser.ReadLine()
        $script:skippedErrors.Add([PSCustomObject]@{ Type = "Parser Error"; Error = "Unhandled CSV Row Error"; Details = $_.Exception.Message })
    }

    $thresh = if ($totalLines -gt 0 -and $totalLines -lt 20000) { 100 } else { 20000 }
    if ($lineCount % $thresh -eq 0) {
        Write-Output "[PROGRESS] $lineCount / $totalLines Extracting Target Vectors..."
    }
}
$parser.Close()
$sw.Stop()

$canonicalPaths = [string[]]$pathProcessMap.Keys
$totalCount = $canonicalPaths.Count
Write-Host "Parsed $lineCount lines in $($sw.Elapsed.TotalSeconds.ToString('0.00'))s. $totalCount unique canonical paths." -ForegroundColor Cyan
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
$script:_plantBits = [int]([System.Security.AccessControl.FileSystemRights]::WriteData) -bor `
                     [int]([System.Security.AccessControl.FileSystemRights]::AppendData)

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
    'S-1-5-32-551',     # BUILTIN\Backup Operators
    'S-1-5-19',         # LOCAL SERVICE
    'S-1-5-20'          # NETWORK SERVICE
)
# SYSTEM/TI grants reach paths that even high-IL admin can't write without
# impersonation tricks — irrelevant to all three of our perspectives.
$script:_systemSids = @(
    'S-1-5-18',         # SYSTEM
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

function Get-PathWritability {
    param(
        [Parameter(Mandatory=$true)] [string]$TargetPath,
        [Parameter(Mandatory=$true)] [hashtable]$UserContext
    )

    $r = @{
        WritableByLowPriv       = $false
        WritableByMediumILAdmin = $false
        WritableByHighILAdmin   = $false
        IntegrityLabel          = "Default"
        AclSource               = "none"
    }

    try {
        # Registry — heuristic, no SACL parsing.
        if ($TargetPath -match "^HKLM" -or $TargetPath -match "^HKEY_LOCAL_MACHINE" `
            -or $TargetPath -match "^HKCR" -or $TargetPath -match "^HKEY_CLASSES_ROOT") {
            $r.WritableByHighILAdmin = $true
            $r.IntegrityLabel = "High"
            $r.AclSource = "registry-heuristic"
            return $r
        }
        if ($TargetPath -match "^HKCU" -or $TargetPath -match "^HKEY_CURRENT_USER" `
            -or $TargetPath -match "^HKU\\" -or $TargetPath -match "^HKEY_USERS\\") {
            $r.WritableByLowPriv = $true
            $r.WritableByMediumILAdmin = $true
            $r.WritableByHighILAdmin = $true
            $r.AclSource = "registry-heuristic"
            return $r
        }
        if ($TargetPath -match "^HK") {
            # Other roots (HKCC, HKPD) — assume admin-only.
            $r.WritableByHighILAdmin = $true
            $r.IntegrityLabel = "High"
            $r.AclSource = "registry-heuristic"
            return $r
        }

        # Filesystem: pick the right ACL bearer.
        #
        # Distinction matters: writability of an EXISTING file requires
        # WriteData on the file itself (not on the parent). Walking up to the
        # parent and reading its ACL produces false positives like
        # `C:\pagefile.sys` -> "C:\ has Users:CreateDirectories so pagefile is
        # writable". So:
        #   * If the path exists as a file: read THAT file's ACL. If we can't
        #     (Get-Acl denies because we lack ReadPermissions), bail with
        #     all-false rather than fall back to the parent.
        #   * If the path exists as a directory: read THAT directory's ACL.
        #   * If the path does NOT exist: walk up to the existing ancestor and
        #     use its ACL; that genuinely tells us whether we can plant a new
        #     entry under that name.
        $aclTarget = $null
        $treatAsExistingFile = $false
        if ([System.IO.File]::Exists($TargetPath)) {
            $aclTarget = $TargetPath
            $treatAsExistingFile = $true
            $r.AclSource = "exact-file"
        } elseif ([System.IO.Directory]::Exists($TargetPath)) {
            $aclTarget = $TargetPath
            $r.AclSource = "exact-directory"
        } else {
            $dir = [System.IO.Path]::GetDirectoryName($TargetPath)
            while (-not [string]::IsNullOrWhiteSpace($dir) -and -not [System.IO.Directory]::Exists($dir)) {
                $dir = [System.IO.Path]::GetDirectoryName($dir)
            }
            if ([string]::IsNullOrWhiteSpace($dir)) { return $r }
            $aclTarget = $dir
            $r.AclSource = "ancestor"
        }

        # Tag integrity label by path (heuristic; SACL parsing is expensive
        # and usually denied without SeSecurityPrivilege).
        foreach ($pat in $script:_highILPathPatterns) {
            if ($aclTarget -like ('*' + $pat + '*')) {
                $r.IntegrityLabel = "High"
                break
            }
        }
        # \Windows root itself is High-IL even though most of \Windows\<X>\... isn't.
        if ($r.IntegrityLabel -eq "Default" -and $aclTarget -match '(?i)\\Windows\\?$') {
            $r.IntegrityLabel = "High"
        }

        # Pull DACL. If we can't read it (typical for SYSTEM-only files like
        # pagefile.sys), refuse to claim writability instead of falling
        # through to ancestor-derived heuristics.
        try {
            $acl = Get-Acl -LiteralPath $aclTarget -ErrorAction Stop
        } catch {
            $r.AclSource = $r.AclSource + "-denied"
            return $r
        }
        if ($null -eq $acl) {
            $r.AclSource = $r.AclSource + "-null"
            return $r
        }
        $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

        $allowedLow = $false; $deniedLow = $false
        $allowedMed = $false; $deniedMed = $false
        $allowedHigh = $false; $deniedHigh = $false

        foreach ($rule in $rules) {
            $sid = $rule.IdentityReference.Value
            if ($sid -eq 'S-1-3-0') { continue }                # CREATOR OWNER — see comment above
            if ($script:_systemSids -contains $sid) { continue } # unreachable from our perspectives

            $rights = [int]$rule.FileSystemRights
            if (($rights -band $script:_plantBits) -eq 0) { continue }   # not a plant grant
            $isDeny = ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny)

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
                    $allowedMed = $true; $allowedHigh = $true
                }
                continue
            }

            # Current user's specific SID.
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
            # Other SIDs (specific user accounts, custom groups) — leave alone.
        }

        $r.WritableByLowPriv       = $allowedLow  -and -not $deniedLow
        $r.WritableByMediumILAdmin = $allowedMed  -and -not $deniedMed
        $r.WritableByHighILAdmin   = $allowedHigh -and -not $deniedHigh

        # MIC NW: paths with the High mandatory label refuse writes from
        # tokens at lower IL. LowPriv / MediumIL can't write up.
        if ($r.IntegrityLabel -eq "High" -or $r.IntegrityLabel -eq "System") {
            $r.WritableByLowPriv       = $false
            $r.WritableByMediumILAdmin = $false
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

$activeIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$activePrincipal = New-Object System.Security.Principal.WindowsPrincipal($activeIdentity)
$currentUserName = $activeIdentity.Name
$adminSidObj     = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")

# IsAdminLatent: admin SID is in the token's groups list, even if currently
# filtered to deny-only. WindowsIdentity.Groups returns groups regardless of
# Use=DenyOnly status, so iterating Groups detects split-token admins.
$isAdminLatent = $false
foreach ($g in $activeIdentity.Groups) {
    if ($g.Equals($adminSidObj)) { $isAdminLatent = $true; break }
}
# IsAdminElevated: admin SID is currently active (Use=Allow) in the token.
# IsInRole returns false for deny-only, true for active.
$isAdminElevated = $activePrincipal.IsInRole($adminSidObj)

# Process integrity level via whoami /groups — portable, no P/Invoke.
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

    $writability = Get-PathWritability -TargetPath $displayPath -UserContext $userContext
    $lowestPersp = Get-LowestWritablePerspective -Writability $writability

    # Skip paths writable by NONE of our perspectives (not interesting to any
    # of LPE / UAC bypass / admin-to-SYSTEM).
    if ($lowestPersp -eq "None") { continue }

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

    # User-only-consumed filter: every observed process is the current user's
    # own session and no privileged actor touches the path. The redirect
    # cannot reach anywhere the user couldn't reach already.
    $userOnlyConsumer = (-not $rec.AnyPrivWrite) -and (-not $rec.AnyPrivRead)

    $results.Add([PSCustomObject]@{
        Path                    = $displayPath
        CanonicalPath           = $canonical
        FileExists              = ([System.IO.Directory]::Exists($displayPath) -or [System.IO.File]::Exists($displayPath))
        RelatedProcesses        = $relatedProcesses
        Operations              = $operationsList
        EventCount              = $rec.EventCount
        TraceFile               = $traceFileName
        Timestamp               = $bestEvt.Time
        Operation               = $bestEvt.Operation
        Result                  = $bestEvt.Result
        Detail                  = $bestEvt.Detail
        Integrity               = $bestEvt.Integrity
        Impersonating           = $bestEvt.Impersonating
        BestProcess             = $bestEvt.ProcessName
        DesiredAccess           = $bestEvt.DesiredAccess
        SqosLevel               = $bestEvt.SqosLevel
        IsPagingIO              = [bool]$bestEvt.IsPagingIO
        OpenReparsePoint        = [bool]$bestEvt.OpenReparsePoint
        OpenLink                = [bool]$bestEvt.OpenLink
        IsKernelAttribution     = [bool]$bestEvt.IsKernelOrCacheManager
        AnyWrite                = $rec.AnyWrite
        AnyRead                 = $rec.AnyRead
        AnyPrivWrite            = $rec.AnyPrivWrite
        AnyPrivRead             = $rec.AnyPrivRead
        AnyImpersonating        = $rec.AnyImpersonating
        AnyOpenReparsePoint     = $rec.AnyOpenReparsePoint
        AnyOpenLink             = $rec.AnyOpenLink
        AnyPagingIO             = $rec.AnyPagingIO
        IsUserOnlyConsumer      = $userOnlyConsumer
        # Perspective-aware writability (rev 3)
        WritableByLowPriv       = $writability.WritableByLowPriv
        WritableByMediumILAdmin = $writability.WritableByMediumILAdmin
        WritableByHighILAdmin   = $writability.WritableByHighILAdmin
        WritableFrom            = $lowestPersp
        IntegrityLabel          = $writability.IntegrityLabel
        AclSource               = $writability.AclSource
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

if ($results.Count -gt 0) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $pluginDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptDir))

    $outFolder = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath } else { $pluginDir }
    $jsonPath = Join-Path $outFolder "writable_paths.json"
    $results | ConvertTo-Json -Depth 4 | Out-File $jsonPath -Encoding UTF8
    Write-Host "Exported RAW results to $jsonPath" -ForegroundColor Green

    if ($script:skippedErrors.Count -gt 0) {
        $errJsonPath = Join-Path $outFolder "parsing_errors.json"
        $uniqueErrors = $script:skippedErrors | Group-Object Error | Select-Object Name, Count, @{Name="SampleDetails"; Expression={$_.Group[0].Details}}, @{Name="SamplePath"; Expression={$_.Group[0].Path}}, @{Name="Type"; Expression={$_.Group[0].Type}}
        $uniqueErrors | ConvertTo-Json -Depth 3 | Out-File $errJsonPath -Encoding UTF8
        Write-Host "[!] Logged $($script:skippedErrors.Count) unhandled errors (grouped to $($uniqueErrors.Count) unique patterns) to $errJsonPath" -ForegroundColor Yellow
    }

    if (-not $Silent) {
        $results | Out-GridView -Title "RAW Writable Paths and Associated Processes"
    }

    Write-Host "[!] INSTRUCTION: Writable paths extracted. Agent should invoke 'Analyze-ExecutionLeads' skill now." -ForegroundColor Magenta
}
