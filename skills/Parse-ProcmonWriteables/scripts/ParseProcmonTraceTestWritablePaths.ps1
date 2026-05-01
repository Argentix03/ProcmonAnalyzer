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
#  Parse-ProcmonWriteables (rev 2)
#
#  Purpose: stream a Procmon CSV (or NativeTrace ETW-derived CSV), extract every
#  path the *current standard user* can write to, and emit a structured feed for
#  Analyze-ExecutionLeads.
#
#  Design notes / hardenings vs rev 1:
#   - Best-event selection per path: instead of keeping only the FIRST event we
#     see for a path, score each event so writes-by-privileged with NAME-NOT-FOUND
#     beat reads-by-medium-IL with SUCCESS. Prevents losing a SYSTEM WriteFile
#     that happened to land after a benign Medium-IL ReadFile of the same path.
#   - Capture telemetry-quality flags: IsPagingIO, OpenReparsePoint, OpenLink,
#     IsKernelOrCacheManager. Surfaces the LPE-prompt §2 false-positive classes
#     so the analyzer can drop or down-weight them.
#   - Path canonicalization: strip trailing slashes, normalize `\??\`,
#     `\Device\HarddiskVolume<N>\` and case for dedup. Original Path preserved
#     for display.
#   - Self-trace filtering: skips rows whose Path or Process match the trace
#     pipeline itself (Procmon, tracerpt, our own NativeTrace.ps1), so the
#     report doesn't flag its own captures.
#   - Captures Operations[] (set) so downstream rules can detect Read+Write
#     combos against the same path.
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

# ── PERMISSION TEST ──────────────────────────────────────────────────────────

function Test-SafeWritePermission {
    param(
        [Parameter(Mandatory=$true)]
        [string]$TargetPath,
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.WindowsIdentity]$CurrentUser,
        [Parameter(Mandatory=$true)]
        [System.Security.Principal.WindowsPrincipal]$Principal
    )

    try {
        # Registry — heuristic: HKCU/HKU\<self-SID> is writable to the user;
        # for HKLM/HKCR we don't claim writability (those are admin-only by default).
        if ($TargetPath -match "^HKLM" -or $TargetPath -match "^HKEY_LOCAL_MACHINE" `
            -or $TargetPath -match "^HKCR" -or $TargetPath -match "^HKEY_CLASSES_ROOT") {
            return $false
        }
        if ($TargetPath -match "^HKCU" -or $TargetPath -match "^HKEY_CURRENT_USER" `
            -or $TargetPath -match "^HKU\\" -or $TargetPath -match "^HKEY_USERS\\") {
            return $true
        }

        if ([System.IO.File]::Exists($TargetPath)) {
            try {
                $fs = [System.IO.File]::Open($TargetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $fs.Close()
                return $true
            } catch [System.UnauthorizedAccessException] {
                return $false
            } catch [System.IO.IOException] {
                # File-sharing violation = ACL OK, file just locked
                if ($_.Exception.HResult -eq -2147024864) { return $true }
                return $false
            } catch {
                return $false
            }
        }

        $directoryToTest = $TargetPath
        if (-not [System.IO.Directory]::Exists($directoryToTest)) {
            $directoryToTest = [System.IO.Path]::GetDirectoryName($TargetPath)
            while (-not [string]::IsNullOrWhiteSpace($directoryToTest) -and -not [System.IO.Directory]::Exists($directoryToTest)) {
                $directoryToTest = [System.IO.Path]::GetDirectoryName($directoryToTest)
            }
        }

        if ([System.IO.Directory]::Exists($directoryToTest)) {
            $acl = [System.IO.DirectoryInfo]::new($directoryToTest).GetAccessControl()
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])

            $hasWrite = $false
            $hasDeny  = $false
            foreach ($rule in $rules) {
                $matchesIdentity = $false
                try {
                    if ($CurrentUser.User.Equals($rule.IdentityReference)) { $matchesIdentity = $true }
                    elseif ($Principal.IsInRole($rule.IdentityReference))   { $matchesIdentity = $true }
                } catch { $matchesIdentity = $false }

                if ($matchesIdentity) {
                    # Use AddFile / AppendData / WriteData — any of these is enough to plant.
                    $rights = $rule.FileSystemRights
                    $hasPlant = (
                        (($rights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -ne 0) -or
                        (($rights -band [System.Security.AccessControl.FileSystemRights]::AppendData) -ne 0) -or
                        (($rights -band [System.Security.AccessControl.FileSystemRights]::CreateFiles) -ne 0) -or
                        (($rights -band [System.Security.AccessControl.FileSystemRights]::Modify) -ne 0) -or
                        (($rights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -ne 0)
                    )
                    if ($hasPlant) {
                        if ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Deny) {
                            $hasDeny = $true
                        } elseif ($rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                            $hasWrite = $true
                        }
                    }
                }
            }
            return ($hasWrite -and -not $hasDeny)
        }
        return $false
    } catch {
        $script:skippedErrors.Add([PSCustomObject]@{ Type = "Permission Evaluation Error"; Path = $TargetPath; Error = $_.Exception.Message })
        return $false
    }
}

# ── EXECUTION ────────────────────────────────────────────────────────────────

$counter = 0
$results = New-Object System.Collections.Generic.List[PSCustomObject]
$swTest = [System.Diagnostics.Stopwatch]::StartNew()

$activeIdentity  = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$activePrincipal = New-Object System.Security.Principal.WindowsPrincipal($activeIdentity)
$currentUserName = $activeIdentity.Name

foreach ($canonical in $canonicalPaths) {
    if ($counter % 100 -eq 0 -or $counter -eq $totalCount) {
        Write-Progress -Activity "Testing Permissions" -Status "Testing: $canonical" -PercentComplete (($counter / [Math]::Max(1, $totalCount)) * 100)
        Write-Output "[PROGRESS] $counter / $totalCount Evaluating File/ACL Permissions..."
    }
    $counter++

    $rec = $pathProcessMap[$canonical]
    $displayPath = $rec.Path

    if (Test-SafeWritePermission -TargetPath $displayPath -CurrentUser $activeIdentity -Principal $activePrincipal) {
        $relatedProcesses = ($rec.Processes -join ", ")
        $operationsList   = ($rec.Operations -join ", ")
        $bestEvt = $rec.BestEvent

        # User-only-consumed filter: if EVERY observed process for this path is
        # the current user's own medium-IL session AND there's no privileged
        # actor, the path is "user-already-has-it" (LPE §9 false positive).
        # We still emit it, but tag IsUserOnlyConsumer so the analyzer can
        # downgrade severity rather than drop entirely.
        $userOnlyConsumer = (-not $rec.AnyPrivWrite) -and (-not $rec.AnyPrivRead)

        $results.Add([PSCustomObject]@{
            Path                = $displayPath
            CanonicalPath       = $canonical
            FileExists          = ([System.IO.Directory]::Exists($displayPath) -or [System.IO.File]::Exists($displayPath))
            RelatedProcesses    = $relatedProcesses
            Operations          = $operationsList
            EventCount          = $rec.EventCount
            TraceFile           = $traceFileName
            Timestamp           = $bestEvt.Time
            Operation           = $bestEvt.Operation
            Result              = $bestEvt.Result
            Detail              = $bestEvt.Detail
            Integrity           = $bestEvt.Integrity
            Impersonating       = $bestEvt.Impersonating
            BestProcess         = $bestEvt.ProcessName
            DesiredAccess       = $bestEvt.DesiredAccess
            SqosLevel           = $bestEvt.SqosLevel
            IsPagingIO          = [bool]$bestEvt.IsPagingIO
            OpenReparsePoint    = [bool]$bestEvt.OpenReparsePoint
            OpenLink            = [bool]$bestEvt.OpenLink
            IsKernelAttribution = [bool]$bestEvt.IsKernelOrCacheManager
            AnyWrite            = $rec.AnyWrite
            AnyRead             = $rec.AnyRead
            AnyPrivWrite        = $rec.AnyPrivWrite
            AnyPrivRead         = $rec.AnyPrivRead
            AnyImpersonating    = $rec.AnyImpersonating
            AnyOpenReparsePoint = $rec.AnyOpenReparsePoint
            AnyOpenLink         = $rec.AnyOpenLink
            AnyPagingIO         = $rec.AnyPagingIO
            IsUserOnlyConsumer  = $userOnlyConsumer
        })
    }
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
