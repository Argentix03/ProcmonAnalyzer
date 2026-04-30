param (
    [Parameter(Mandatory=$true)]
    [string]$JsonFeed,
    
    [switch]$Silent
)

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

# Parse SQOS impersonation level from Procmon Detail string
function Get-SqosLevel {
    param([string]$Detail)
    if ([string]::IsNullOrWhiteSpace($Detail)) { return "NotSpecified" }
    if ($Detail -match 'Impersonation:\s*(Impersonation|Delegation|Identification|Anonymous)') {
        return $matches[1]
    }
    return "NotSpecified"  # No SQOS flag = dangerous default for local pipes
}

# Classify the operation direction
function Get-OperationDirection {
    param([string]$Operation)
    $op = if ($Operation) { $Operation.Trim() } else { "" }
    $writeOps = @("WriteFile", "SetDispositionInformationFile", "SetRenameInformationFile",
                  "SetBasicInformationFile", "SetEndOfFileInformationFile", "SetAllocationInformationFile",
                  "WriteConfig", "RegSetValue", "SetSecurityFile")
    $readOps  = @("CreateFile", "ReadFile", "QueryDirectory", "QueryBasicInformationFile",
                  "QueryStandardInformationFile", "QueryNameInformationFile", "Load Image",
                  "QueryOpen", "RegQueryValue", "CreateFileMapping", "RegOpenKey", "RegCreateKey")
    if ($writeOps -contains $op) { return "Write" }
    if ($readOps -contains $op)  { return "Read" }
    # Heuristic fallback
    if ($op -match "(?i)(write|set|create|delete|rename)") { return "Write" }
    return "Read"
}

# Check if integrity indicates a privileged process
function Test-PrivilegedIntegrity {
    param([string]$Integrity)
    $i = if ($Integrity) { $Integrity.Trim().ToLower() } else { "unknown" }
    return ($i -eq "system" -or $i -eq "high" -or $i -eq "protected process")
}

# ═══════════════════════════════════════════════════════════════════════════════
# KNOWN PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

$lolBins = @(
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "csc.exe", "certutil.exe", 
    "powershell.exe", "pwsh.exe", "wmic.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", 
    "cmstp.exe", "cscript.exe", "wscript.exe", "bginfo.exe", "bash.exe", "pcalua.exe", 
    "forfiles.exe", "control.exe", "schtasks.exe", "vssadmin.exe", "bitsadmin.exe", 
    "mavinject.exe", "wuauclt.exe", "netsh.exe", "certreq.exe", "esentutl.exe"
)

# Framework host processes that load config files contextually
$frameworkHosts = @(
    "w3wp.exe", "svchost.exe", "dotnet.exe", "aspnet_compiler.exe",
    "mmc.exe", "dllhost.exe", "wmiprvse.exe", "services.exe",
    "taskhost.exe", "taskhostw.exe", "spoolsv.exe", "lsass.exe"
)

# Config file patterns that have known deserialization/redirect attack surfaces
$exploitableConfigPatterns = @(
    "machine\.config", "web\.config", "app\.config", "applicationHost\.config",
    "\.settings$", "devenv\.exe\.config", "mmc\.exe\.config",
    "assemblyBinding", "runtime"
)

# ═══════════════════════════════════════════════════════════════════════════════
# TRIAGE ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

$hardcodedLeads = New-Object System.Collections.Generic.List[PSCustomObject]
$cognitiveQueue = New-Object System.Collections.Generic.List[PSCustomObject]

Write-Host "[*] Analyzing $($rawData.Count) verifiable paths via heuristic security engine..." -ForegroundColor Gray

foreach ($entry in $rawData) {
    $path      = $entry.Path
    $procs     = $entry.RelatedProcesses
    $operation = if ($entry.Operation) { $entry.Operation } else { "" }
    $result    = if ($entry.Result)    { $entry.Result }    else { "" }
    $detail    = if ($entry.Detail)    { $entry.Detail }    else { "" }
    $integrity = if ($entry.Integrity) { $entry.Integrity } else { "Unknown" }
    $impersonating = if ($entry.Impersonating) { $entry.Impersonating } else { "Unknown" }

    $isDirectLead    = $false
    $severity        = "Low"
    $type            = "Unknown"
    $reason          = ""
    $exploitPrimitive = ""

    $opDirection   = Get-OperationDirection -Operation $operation
    $sqos          = Get-SqosLevel -Detail $detail
    $isPrivileged  = Test-PrivilegedIntegrity -Integrity $integrity
    $isNameNotFound = ($result -match "(?i)NAME NOT FOUND")
    $isPathNotFound = ($result -match "(?i)PATH NOT FOUND")

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 1: Named Pipe Hijacking (literal pipe paths)
    # ─────────────────────────────────────────────────────────────────────────
    if ($path -match "^\\\\\.\\pipe\\") {
        $severity = "Critical"
        $type = "Named Pipe Hijacking / Impersonation"
        $exploitPrimitive = "Pipe_Hijack"
        $reason = "Direct named pipe at a writable endpoint. A low-priv attacker can plant a pipe server here and capture connecting clients."
        if ($isPrivileged) {
            $reason += " PRIVILEGED CLIENT ($integrity) connects -> token material available."
        }
        if ($sqos -eq "NotSpecified" -or $sqos -eq "Impersonation" -or $sqos -eq "Delegation") {
            $reason += " SQOS=$sqos -> impersonation-safe for service accounts, SMB relay viable for standard users."
        } elseif ($sqos -eq "Identification") {
            $severity = "High"
            $reason += " SQOS=Identification -> token query only, no impersonation. Still useful for SMB relay."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2: Binary Planting / DLL Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(exe|dll|sys|cpl|ocx|efi|scr|msi|msp|msc|com|hta|jar|xll|wll|xla|drv)$") {
        if ($path -match "(System32|SysWOW64|Program Files|ProgramData\\[^\\]+\\)") {
            $severity = "Critical"
            $type = "Binary Planting (High Priv Dir)"
            $exploitPrimitive = "Binary_Plant_HighPriv"
            $reason = "Writable executable in a privileged directory. If loaded by a SYSTEM process, attacker gets code execution as SYSTEM with zero special privileges."
        } else {
            $severity = "High"
            $type = "Binary Planting (User Space)"
            $exploitPrimitive = "Binary_Plant_UserSpace"
            $reason = "Writable executable. Prone to DLL search-order hijacking or direct execution. No privileges required to replace."
        }
        if ($isPrivileged) {
            $reason += " LOADED BY PRIVILEGED PROCESS ($integrity) -> direct code execution at that integrity level."
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
        $reason = "Dropping a .local directory or .manifest file hijacks the DLL load order of legitimate applications. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.2: Package / Dependency Hijacking
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(node_modules|site-packages|vendor\\|gems\\)") {
        $severity = "Critical"
        $type = "Dependency / Package Subversion"
        $exploitPrimitive = "Dependency_Hijack"
        $reason = "Writable dependency folder. Any library requested by the application can be transparently replaced. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.3: Web Shell / Webroot Planting
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "(inetpub\\wwwroot|xampp\\htdocs|tomcat\\webapps|nginx\\html)" -and $path -match "\.(aspx|php|jsp|asmx|html|ashx)$") {
        $severity = "Critical"
        $type = "Web Shell Proxy / Server Planting"
        $exploitPrimitive = "WebShell_Plant"
        $reason = "Writing scripts into a webroot creates a web shell. No privileges needed if the directory is writable."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 2.4: LNK Shortcut Poisoning
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.lnk$") {
        $severity = "High"
        $type = "LNK Shortcut Hijacking"
        $exploitPrimitive = "LNK_Hijack"
        $reason = "Writable .lnk shortcut. Modify the target to redirect execution. No privileges needed."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 3: AutoRun / Script Persistence
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($path -match "\.(bat|ps1|vbs|vbe|cmd|wsf)$" -or $path -match "(Startup|Run|Services|Tasks\\|wbem\\mof)")) {
        $severity = "High"
        $type = "AutoRun / Script Persistence"
        $exploitPrimitive = "AutoRun_Persistence"
        $reason = "Writable script file or persistence location. Likely executed on boot/logon. No privileges needed to modify."
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 5: SMB/NTLM Coercion via Path Redirection  ** NEW **
    # A privileged process reads from a user-writable directory.
    # Low-priv attacker plants an NTFS junction redirecting to \\attacker\share.
    # The privileged process follows the redirect and authenticates via NTLM.
    # Attacker captures Net-NTLMv2 hash for cracking or relay.
    # REQUIRES: Nothing. Standard user can create junctions. Kernel follows them.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $opDirection -eq "Read") {
        # A high-integrity process reading from a path we can write = SMB coercion candidate
        $severity = "Critical"
        $type = "SMB / NTLM Coercion Candidate"
        $exploitPrimitive = "SMB_Coercion"
        $reason = "PRIVILEGED PROCESS ($integrity) reads from a user-writable path. Plant NTFS junction -> \\attacker\share to capture Net-NTLMv2 hash. NO SPECIAL PRIVILEGES REQUIRED. Hash can be cracked offline or relayed (ntlmrelayx) to other services for lateral movement."
        if ($isNameNotFound) {
            $reason += " PATH DOES NOT EXIST -> trivial to plant junction without race condition."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 6: Arbitrary Write via Oplock + Junction  ** NEW **
    # A privileged process writes to a user-writable path.
    # Low-priv attacker sets oplock on dir -> when triggered, swaps junction
    # -> privileged write lands in System32 or other protected location.
    # REQUIRES: Nothing. Standard user can set oplocks and create junctions.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $opDirection -eq "Write") {
        $severity = "Critical"
        $type = "Arbitrary Write via Oplock+Junction"
        $exploitPrimitive = "Oplock_ArbitraryWrite"
        $reason = "PRIVILEGED PROCESS ($integrity) WRITES to a user-writable path. Set oplock on directory -> swap junction mid-write -> write lands in arbitrary privileged location (e.g., System32). NO SPECIAL PRIVILEGES REQUIRED. This is a write-what-where primitive."
        if ($path -match "\.(tmp|log|cache|dat|bak|old)$") {
            $reason += " Temp/cache file pattern -> high likelihood of repeated writes (reliable trigger)."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 7: Pipe Planting via Path Redirection  ** NEW **
    # A privileged process opens a FILE path that doesn't exist.
    # Low-priv attacker can plant a symlink from that path to a named pipe.
    # When the privileged process opens the path, it connects to the pipe.
    # Even without SeImpersonatePrivilege, the attacker can:
    #   - Relay the NTLM auth to another service
    #   - Capture token at Identification level (query SIDs/groups)
    #   - Block the service (DoS by holding the pipe)
    # REQUIRES: Nothing for SMB relay variant. SeImpersonatePrivilege for token.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and $isNameNotFound -and 
        ($path -notmatch "^\\\\\.\\pipe\\") -and ($path -match "^[a-zA-Z]:\\")) {
        $severity = "High"
        $type = "Pipe Planting via Path Redirection"
        $exploitPrimitive = "Pipe_Plant_Redirect"
        $reason = "PRIVILEGED PROCESS ($integrity) attempts to open a NON-EXISTENT file path. Plant symlink to named pipe -> capture connecting client for NTLM relay. No special privileges needed for relay path."
        
        # Check SQOS level for severity adjustment
        if ($sqos -eq "NotSpecified" -or $sqos -eq "Impersonation" -or $sqos -eq "Delegation") {
            $severity = "Critical"
            $reason += " SQOS=$sqos -> default allows impersonation-level access. SMB relay AND token capture both viable."
        } elseif ($sqos -eq "Identification") {
            $reason += " SQOS=Identification -> impersonation blocked, but SMB relay still works."
        } elseif ($sqos -eq "Anonymous") {
            $severity = "Medium"
            $reason += " SQOS=Anonymous -> limited exploitation. DoS and timing side-channels only."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 8: Config Poisoning — Structured Detection  ** NEW **
    # Instead of sending all .config/.xml to cognitive queue, detect specific
    # exploitable patterns with actionable guidance.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $path -match "\.(config|xml)$") {
        $isFrameworkHost = $false
        foreach ($fh in $frameworkHosts) {
            if ($procs -match "(?i)\b$fh\b") { $isFrameworkHost = $true; break }
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
                $reason += " .NET config file -> inject <assemblyBinding> redirect to load attacker DLL, or add <machineKey> for ViewState deserialization. No privileges needed."
            } elseif ($path -match "(?i)\.xml$" -and $isFrameworkHost) {
                $reason += " XML consumed by $procs -> test for XXE (XML External Entity) to read local files or trigger SMB auth to \\attacker."
            }
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 10: Registry Path Coercion via REG_LINK  ** NEW **
    # A privileged process accesses a key in HKCU or HKU without REG_OPTION_OPEN_LINK.
    # Attacker can plant a REG_LINK (Registry Symbolic Link) to redirect the 
    # access elsewhere in the hive.
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and $isPrivileged -and ($path -match "^HKCU" -or $path -match "^HKEY_CURRENT_USER" -or $path -match "^HKU" -or $path -match "^HKEY_USERS")) {
        $hasOpenLink = ($detail -match "(?i)Open Link")
        if (-not $hasOpenLink) {
            $severity = "Critical"
            $type = "Registry Path Coercion Candidate"
            $exploitPrimitive = "Registry_Coercion"
            $reason = "PRIVILEGED PROCESS ($integrity) accesses a user-writable registry key ($path) without REG_OPTION_OPEN_LINK. Plant a REG_LINK (Registry Symbolic Link) to redirect this access to an attacker-controlled key. NO SPECIAL PRIVILEGES REQUIRED. Often chains into config poisoning, COM hijacking, or TOCTOU races."
            $isDirectLead = $true
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # RULE 9: Certificate / Crypto Store Planting  ** NEW **
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead -and ($path -match "\.(cer|crt|pfx|p12|pem|key|p7b)$" -or
        $path -match "(?i)(Crypto|Certificate|PKI|AuthRoot|ROOT\\Certificates)")) {
        $severity = "High"
        $type = "Certificate / Crypto Store Planting"
        $exploitPrimitive = "Cert_Plant"
        $reason = "Writable certificate or crypto store path. Plant trusted root CA to enable MitM, or inject code-signing cert to bypass signature checks. No privileges needed to write."
        if ($isPrivileged) {
            $severity = "Critical"
            $reason += " CONSUMED BY PRIVILEGED PROCESS ($integrity) -> system-wide trust manipulation."
        }
        $isDirectLead = $true
    }

    # ─────────────────────────────────────────────────────────────────────────
    # LOLBin cross-reference (severity booster for ANY finding)
    # ─────────────────────────────────────────────────────────────────────────
    foreach ($bin in $lolBins) {
        if ($procs -match "(?i)\b$bin\b") {
            if ($severity -eq "Low") { $severity = "Medium" }
            elseif ($severity -eq "Medium") { $severity = "High" }
            
            if ($isDirectLead) {
                $reason += " -> INTERACTED WITH LOLBIN: $bin (severity escalated)"
            } else {
                $type = "LOLBin Proxy Target"
                $exploitPrimitive = "LOLBin_Proxy"
                $reason = "File queried by $bin. Depending on parsing behavior, this is a native code execution proxy. No privileges needed."
                $isDirectLead = $true
            }
            break
        }
    }

    # ─────────────────────────────────────────────────────────────────────────
    # COGNITIVE QUEUE — for items that need agent semantic analysis
    # ─────────────────────────────────────────────────────────────────────────
    if (-not $isDirectLead) {
        if ($path -match "\.(config|xml|ini|json|yml|yaml|txt|log|db|dat|reg|inf|pol)$" -or $path -match "^HK") {
            $hint = "Requires semantic analysis. "
            if ($isPrivileged) {
                $hint += "HIGH-VALUE: Consumed by $integrity-integrity process. "
                $hint += "Check for: (1) Assembly binding redirects in .NET configs, (2) XXE in XML files, (3) Deserialization sinks, "
                $hint += "(4) SMB coercion via config values pointing to UNC paths, (5) Credential material in plaintext, (6) For registry paths, check for REG_LINK TOCTOU or missing REG_OPTION_OPEN_LINK."
            } else {
                $hint += "Standard-priv context. Check for: deserialization sinks, config-driven code loading, credential harvesting."
            }
            if ($opDirection -eq "Write") {
                $hint += " NOTE: Process WRITES this file -> if you can race/redirect, this is an arbitrary-write primitive."
            }

            $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Hint = $hint
                TraceFile = $entry.TraceFile
                Timestamp = $entry.Timestamp
                Operation = $entry.Operation
                Result = $entry.Result
                Detail = $entry.Detail
                Integrity = $entry.Integrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
            })
        } elseif ($path -match "(System32|Program Files|Windows)") {
             $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Hint = "Highly privileged base directory. Check if the accessed path maps to an environmental override, proxy execution, or symlink redirect opportunity. Direction: $opDirection"
                TraceFile = $entry.TraceFile
                Timestamp = $entry.Timestamp
                Operation = $entry.Operation
                Result = $entry.Result
                Detail = $entry.Detail
                Integrity = $entry.Integrity
                Impersonating = $impersonating
                OperationDirection = $opDirection
                SqosLevel = $sqos
            })
        }
    } else {
        # Directly log known critical primitives
        $hardcodedLeads.Add([PSCustomObject]@{
            Severity = $severity
            Type = $type
            ExploitPrimitive = $exploitPrimitive
            Path = $path
            Processes = $procs
            DetailedReason = $reason
            TraceFile = $entry.TraceFile
            Timestamp = $entry.Timestamp
            Operation = $entry.Operation
            OperationDirection = $opDirection
            Result = $entry.Result
            Detail = $entry.Detail
            Integrity = $entry.Integrity
            Impersonating = $impersonating
            SqosLevel = $sqos
        })
    }
}

# ═══════════════════════════════════════════════════════════════════════════════
# OUTPUT
# ═══════════════════════════════════════════════════════════════════════════════

$hardcodedJsonPath = Join-Path $feedDir "high_confidence_leads.json"
$cognitiveJsonPath = Join-Path $feedDir "cognitive_review_queue.json"

# Sort by severity
$severityOrder = @{ "Critical" = 1; "High" = 2; "Medium" = 3; "Low" = 4; "Unknown" = 5 }
$sortedLeads = $hardcodedLeads | Sort-Object { $severityOrder[$_.Severity] }

$sortedLeads | ConvertTo-Json -Depth 3 | Out-File $hardcodedJsonPath -Encoding UTF8
$cognitiveQueue | ConvertTo-Json -Depth 3 | Out-File $cognitiveJsonPath -Encoding UTF8

# Summary statistics
$primitiveStats = $hardcodedLeads | Group-Object ExploitPrimitive | Sort-Object Count -Descending
Write-Host ""
Write-Host "[+] Heuristic Analysis Complete." -ForegroundColor Green
Write-Host "    -> High Confidence Leads: $($hardcodedLeads.Count)" -ForegroundColor Green
Write-Host "    -> Pushed to Cognitive Queue: $($cognitiveQueue.Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "    Exploit Primitive Breakdown:" -ForegroundColor Cyan
foreach ($stat in $primitiveStats) {
    Write-Host "       $($stat.Name): $($stat.Count)" -ForegroundColor White
}
Write-Host ""
Write-Host "[!] INSTRUCTION: Agent should now ingest '$cognitiveJsonPath' and formulate the final Execution_Leads_Report.md." -ForegroundColor Magenta
