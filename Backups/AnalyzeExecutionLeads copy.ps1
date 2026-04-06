param (
    [Parameter(Mandatory=$true)]
    [string]$JsonFeed
)

$feedDir = Split-Path $JsonFeed
if ([string]::IsNullOrWhiteSpace($feedDir)) { $feedDir = ".\" }

Write-Host "[*] Initiating Advanced Execution Lead Analysis on: $JsonFeed" -ForegroundColor Cyan

if (-not (Test-Path $JsonFeed)) {
    Write-Host "[-] JSON feed not found" -ForegroundColor Red
    exit
}

$rawData = Get-Content $JsonFeed -Raw | ConvertFrom-Json
if (-not $rawData) {
    Write-Host "[!] No data parsed from JSON." -ForegroundColor Yellow
    exit
}

# Advanced heuristic definitions
$lolBins = @(
    "msbuild.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "csc.exe", "certutil.exe", 
    "powershell.exe", "pwsh.exe", "wmic.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe", 
    "cmstp.exe", "cscript.exe", "wscript.exe", "bginfo.exe", "bash.exe", "pcalua.exe", 
    "forfiles.exe", "control.exe", "schtasks.exe"
)

# Lists for the orchestration layer
$hardcodedLeads = New-Object System.Collections.Generic.List[PSCustomObject]
$cognitiveQueue = New-Object System.Collections.Generic.List[PSCustomObject]

Write-Host "[*] Analyzing $($rawData.Count) verifiable paths via heuristic security engine..." -ForegroundColor Gray

foreach ($entry in $rawData) {
    $path = $entry.Path
    $procs = $entry.RelatedProcesses
    $isDirectLead = $false
    $severity = "Low"
    $type = "Unknown"
    $reason = ""

    # 1. High-Impact Primitive: Named Pipes Impersonation
    if ($path -match "^\\\\\.\\pipe\\") {
        $severity = "Critical"
        $type = "Named Pipe Hijacking / Impersonation"
        $reason = "Allows interception of IPC traffic or token duplication from privileged clients connecting to this pipe."
        $isDirectLead = $true
    }
    
    # 2. Binary Planting / Service Execution
    if ($path -match "\.(exe|dll|sys|cpl|ocx|efi|scr)$") {
        if ($path -match "(System32|SysWOW64|Program Files|ProgramData\\[^\\]+\\)") {
            $severity = "Critical"
            $type = "Binary Planting (High Priv Dir)"
            $reason = "Direct hijacking of an executable component inside a historically privileged hierarchy."
        } else {
            $severity = "High"
            $type = "Binary Planting (User Space)"
            $reason = "Writable executable logic. Prone to DLL search order hijacking or direct execution."
        }
        $isDirectLead = $true
    }
    
    # 3. Known Scripting & Persistence locations
    if ($path -match "\.(bat|ps1|vbs|vbe|cmd|wsf)$" -or $path -match "(Startup|Run|Services)") {
        $severity = "High"
        $type = "AutoRun / Script Persistence"
        $reason = "Writable script file or persistence folder hook. Highly likely to be executed seamlessly."
        $isDirectLead = $true
    }
    
    # Cross Reference with LOLBins for immediate upgrade
    foreach ($bin in $lolBins) {
        if ($procs -match "(?i)\b$bin\b") {
            if ($severity -eq "Low") { $severity = "Medium" }
            elseif ($severity -eq "Medium") { $severity = "High" }
            
            if ($isDirectLead) {
                $reason += " -> INTERACTED WITH LOLBIN: $bin (High Risk)"
            } else {
                $type = "LOLBin Proxy Target"
                $reason = "File was queried by $bin. Depending on parsing behavior, this represents a native code execution proxy."
                $isDirectLead = $true
            }
            break
        }
    }

    # 4. Cognitive Processing for Complex/Obscure Data Formats
    # We defer these to the LLM agent to analyze contextually (e.g. deserialization config sinks vs benign text files)
    if (-not $isDirectLead) {
        if ($path -match "\.(config|xml|ini|json|yml|yaml|txt|log|db|dat)$") {
            # Provide it to the cognitive queue since context is required to determine exploitability
            $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Hint = "Requires semantic analysis: Is this application vulnerable to insecure deserialization, arbitrary assembly load via XML, or config redirection?"
            })
        } elseif ($path -match "(System32|Program Files|Windows)") {
             $cognitiveQueue.Add([PSCustomObject]@{
                Path = $path
                Processes = $procs
                Hint = "Highly privileged base directory. Investigate if the accessed file maps to an environmental override or proxy execution."
            })
        }
    } else {
        # Directly log known critical primitives
        $hardcodedLeads.Add([PSCustomObject]@{
            Severity = $severity
            Type = $type
            Path = $path
            Processes = $procs
            DetailedReason = $reason
        })
    }
}

# Output Serialization for the Agent
$hardcodedJsonPath = Join-Path $feedDir "high_confidence_leads.json"
$cognitiveJsonPath = Join-Path $feedDir "cognitive_review_queue.json"

$hardcodedLeads | ConvertTo-Json -Depth 3 | Out-File $hardcodedJsonPath -Encoding UTF8
$cognitiveQueue | ConvertTo-Json -Depth 3 | Out-File $cognitiveJsonPath -Encoding UTF8

Write-Host "[+] Heuristic Analysis Complete." -ForegroundColor Green
Write-Host "    -> High Confidence Leads: $($hardcodedLeads.Count)" -ForegroundColor Green
Write-Host "    -> Pushed to Cognitive Queue for Agent review: $($cognitiveQueue.Count)" -ForegroundColor Yellow
Write-Host "[!] INSTRUCTION: Agent should now ingest '$cognitiveJsonPath' and formulate the final Execution_Leads_Report.md." -ForegroundColor Magenta
