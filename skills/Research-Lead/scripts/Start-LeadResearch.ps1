#requires -Version 5.1
<#
.SYNOPSIS
    Optional final-stage helper that prepares per-lead Execution_Lead_N\
    directories from a high_confidence_leads.json feed, picks the matching
    research prompt for each lead, and stages a manifest.json the research
    agent will fill in.

.DESCRIPTION
    This script DOES NOT execute exploitation steps. It refuses to run unless
    -Confirmed is passed AND the user explicitly acknowledges the destructive
    nature of the downstream research workflow. Its job is to set up the
    workspace; the actual research is done by an agent reading the prompt
    in each lead folder's manifest.

    Every lead's manifest.json contains:
      - The lead record verbatim (from high_confidence_leads.json).
      - The research prompt id / file / absolute path that the agent should
        use as instructions.
      - The selected ExploitPrimitive and its severity.
      - The snapshot reference the user supplied (research must be cleanly
        revertible).

.PARAMETER LeadsJson
    Path to high_confidence_leads.json. Default: project root.

.PARAMETER OutputRoot
    Where to create Execution_Lead_N\ subfolders. Default: project root.

.PARAMETER MinSeverity
    Only stage leads at or above this severity. Default: High.
    Allowed: Critical, High, Medium, Low.

.PARAMETER MaxLeads
    Cap the number of leads staged. Default: 10.

.PARAMETER Snapshot
    Free-text identifier for the VM snapshot the agent will revert to between
    leads (e.g., "Win11-24H2-clean-2026-05-01"). Required when -Confirmed.

.PARAMETER GuiDriver
    Free-text identifier for the GUI-driver MCP being used. Examples:
    "SystemAccessMCP", "Windows-MCP", "ClaudeCodeComputerUse", "manual".
    Required when -Confirmed. Recorded in each manifest so verdicts can
    document which secure-desktop steps were reachable vs manual.

.PARAMETER Confirmed
    Switch. The user has confirmed they have read the destructive-action
    warnings, the target host is a snapshotted VM, and they accept the risk.
    Without this switch the script prints the warning and exits without
    creating any directories.

.EXAMPLE
    # Dry run: print the warning, list candidate leads, no side effects.
    .\Start-LeadResearch.ps1 -LeadsJson ..\..\..\high_confidence_leads.json

.EXAMPLE
    # Stage research for the top 5 Critical leads on a snapshotted Hyper-V VM.
    .\Start-LeadResearch.ps1 `
        -LeadsJson ..\..\..\high_confidence_leads.json `
        -MinSeverity Critical -MaxLeads 5 `
        -Snapshot "Win11-24H2-clean-2026-05-01" `
        -GuiDriver SystemAccessMCP `
        -Confirmed
#>

[CmdletBinding()]
param(
    [string]$LeadsJson,
    [string]$OutputRoot,
    [ValidateSet('Critical','High','Medium','Low')]
    [string]$MinSeverity = 'High',
    [int]$MaxLeads = 10,
    [string]$Snapshot,
    [string]$GuiDriver,
    [switch]$Confirmed
)

# ── Setup ─────────────────────────────────────────────────────────────────────

$scriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = (Resolve-Path (Join-Path $scriptDir '..\..\..')).Path

if ([string]::IsNullOrWhiteSpace($LeadsJson)) {
    $LeadsJson = Join-Path $projectRoot 'high_confidence_leads.json'
}
if ([string]::IsNullOrWhiteSpace($OutputRoot)) {
    $OutputRoot = $projectRoot
}

. (Join-Path $scriptDir 'Get-ResearchPromptForPrimitive.ps1')

# ── Warning gate ──────────────────────────────────────────────────────────────

function Write-Warning-Block {
    Write-Host ""
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host "  RESEARCH IS DESTRUCTIVE  --  DO NOT RUN ON A PRODUCTION HOST" -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Per-lead research will:" -ForegroundColor Yellow
    Write-Host "    * plant NTFS junctions / OM symlinks / REG_LINKs / files / oplocks" -ForegroundColor Gray
    Write-Host "    * attach debuggers and tracers (kd / WinDbg / Procmon / WPR)" -ForegroundColor Gray
    Write-Host "    * disable AV / EDR / firewall to get repeatable PoC behavior" -ForegroundColor Gray
    Write-Host "    * mutate registry / scheduled tasks / services / IFEO / AeDebug" -ForegroundColor Gray
    Write-Host "    * for kernel work, load test-signed / vulnerable drivers and may BSOD" -ForegroundColor Gray
    Write-Host "    * leave artefacts (junctions, REG_LINKs) that survive logoff" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Prerequisites:" -ForegroundColor Yellow
    Write-Host "    * Target is a snapshotted Windows VM with a known-good revert point." -ForegroundColor Gray
    Write-Host "    * Target is NOT the operator's daily-driver workstation." -ForegroundColor Gray
    Write-Host "    * If the trace was captured on the same host, that host MUST itself be" -ForegroundColor Gray
    Write-Host "      a snapshotted VM you control. Otherwise: pick a different target." -ForegroundColor Gray
    Write-Host "    * Engagement scope authorizes destructive testing on this host." -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Optional (recommended) GUI driver MCPs for secure-desktop work:" -ForegroundColor Yellow
    Write-Host "    * SystemAccessMCP -- https://github.com/Argentix03/SystemAccessMCP" -ForegroundColor Gray
    Write-Host "        (the only surveyed option that reaches consent.exe / Winlogon" -ForegroundColor DarkGray
    Write-Host "         via HostHyperV; LPE prompt already references its profiles)" -ForegroundColor DarkGray
    Write-Host "    * Windows-MCP (CursorTouch) -- in-guest user session only" -ForegroundColor Gray
    Write-Host "    * Claude Code Desktop 'Computer use' (built-in 2026, Pro/Max)" -ForegroundColor Gray
    Write-Host "        (in-guest user session only; cannot reach the secure desktop)" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Re-run with -Confirmed once the above is acknowledged." -ForegroundColor Yellow
    Write-Host "================================================================================" -ForegroundColor Yellow
    Write-Host ""
}

# ── Load + filter leads ───────────────────────────────────────────────────────

if (-not (Test-Path $LeadsJson)) {
    Write-Host "[-] Leads file not found: $LeadsJson" -ForegroundColor Red
    exit 1
}

$leads = Get-Content $LeadsJson -Raw | ConvertFrom-Json
if (-not $leads) {
    Write-Host "[!] Empty leads file." -ForegroundColor Yellow
    exit 0
}

$severityRank = @{ 'Critical' = 1; 'High' = 2; 'Medium' = 3; 'Low' = 4 }
$threshold    = $severityRank[$MinSeverity]

$filtered = $leads |
    Where-Object { $severityRank[$_.Severity] -le $threshold } |
    Sort-Object { $severityRank[$_.Severity] }, ExploitPrimitive |
    Select-Object -First $MaxLeads

Write-Host ""
Write-Host "Candidate leads at or above [$MinSeverity] (showing $($filtered.Count) / $($leads.Count)):" -ForegroundColor Cyan
$filtered | Format-Table @{N='Severity';E={$_.Severity};A='Left'},
                         @{N='Primitive';E={$_.ExploitPrimitive};A='Left'},
                         @{N='Path';E={ if ($_.Path.Length -gt 70) { $_.Path.Substring(0,67) + '...' } else { $_.Path } };A='Left'},
                         @{N='Prompt';E={ Get-ResearchPromptForPrimitive -Primitive $_.ExploitPrimitive };A='Left'} |
                         Out-String -Width 200 | Write-Host

# ── Gate ──────────────────────────────────────────────────────────────────────

if (-not $Confirmed) {
    Write-Warning-Block
    Write-Host "[*] Dry run only. No directories were created. No state was changed." -ForegroundColor Cyan
    exit 0
}

if ([string]::IsNullOrWhiteSpace($Snapshot)) {
    Write-Host "[-] -Snapshot is required when -Confirmed is set. Provide the VM snapshot reference." -ForegroundColor Red
    exit 1
}
if ([string]::IsNullOrWhiteSpace($GuiDriver)) {
    Write-Host "[-] -GuiDriver is required when -Confirmed is set. Pass 'SystemAccessMCP' / 'Windows-MCP' / 'ClaudeCodeComputerUse' / 'manual'." -ForegroundColor Red
    exit 1
}

# ── Stage workspace ───────────────────────────────────────────────────────────

$state = [ordered]@{
    StartedUtc        = (Get-Date).ToUniversalTime().ToString('o')
    ProjectRoot       = $projectRoot
    LeadsJson         = $LeadsJson
    Snapshot          = $Snapshot
    GuiDriver         = $GuiDriver
    MinSeverity       = $MinSeverity
    MaxLeads          = $MaxLeads
    Leads             = @()
}

$idx = 0
foreach ($lead in $filtered) {
    $idx++
    $leadDir = Join-Path $OutputRoot ("Execution_Lead_{0}" -f $idx)
    if (-not (Test-Path $leadDir)) { New-Item -ItemType Directory -Force -Path $leadDir | Out-Null }

    $promptFile = Get-ResearchPromptForPrimitive -Primitive $lead.ExploitPrimitive
    $promptAbs  = Join-Path $projectRoot $promptFile

    $manifest = [ordered]@{
        LeadIndex          = $idx
        Severity           = $lead.Severity
        ExploitPrimitive   = $lead.ExploitPrimitive
        Type               = $lead.Type
        Path               = $lead.Path
        Processes          = $lead.Processes
        Operations         = $lead.Operations
        OperationDirection = $lead.OperationDirection
        Result             = $lead.Result
        Integrity          = $lead.Integrity
        Impersonating      = $lead.Impersonating
        SqosLevel          = $lead.SqosLevel
        EffectivePrincipal = $lead.EffectivePrincipal
        OpenReparsePoint   = $lead.OpenReparsePoint
        OpenLink           = $lead.OpenLink
        DetailedReason     = $lead.DetailedReason
        TraceFile          = $lead.TraceFile
        Timestamp          = $lead.Timestamp
        ResearchPrompt     = @{
            File         = $promptFile
            AbsolutePath = $promptAbs
            Exists       = (Test-Path $promptAbs)
        }
        Snapshot           = $Snapshot
        GuiDriver          = $GuiDriver
        Status             = 'staged'
    }

    $manifestPath = Join-Path $leadDir 'manifest.json'
    $manifest | ConvertTo-Json -Depth 6 | Out-File $manifestPath -Encoding UTF8

    $readme = @"
# Execution_Lead_$idx

**Severity:** $($lead.Severity)
**Exploit Primitive:** ``$($lead.ExploitPrimitive)``
**Path:** ``$($lead.Path)``
**Effective Principal:** $($lead.EffectivePrincipal)

## Research instructions

Read the prompt at ``$promptFile`` and follow it verbatim against this lead.
Do not paraphrase — the prompt is the agent's full operating manual.

Required deliverables (per the prompt's section 7 / 10 / 8 depending on family):

- ``VERDICT_<EXPLOITABLE | NOT_EXPLOITABLE | INCONCLUSIVE>_Lead$idx.txt``
- ``Setup_Lead$idx.ps1``, ``Reproduce_Lead$idx.ps1``, ``Restore_Lead$idx.ps1``
- ``Evidence_Lead$idx.txt``
- The actual proof artifact (file, hash string, screenshot, packet capture, etc.)

## Snapshot / GUI driver

- Target snapshot: ``$Snapshot`` -- revert to this before starting and after Restore_Lead$idx.ps1 if needed.
- GUI driver: ``$GuiDriver``
"@
    $readme | Out-File (Join-Path $leadDir 'README.md') -Encoding UTF8

    $state.Leads += [ordered]@{
        Index    = $idx
        Path     = $lead.Path
        Primitive = $lead.ExploitPrimitive
        Severity = $lead.Severity
        Folder   = $leadDir
        Prompt   = $promptFile
        Status   = 'staged'
    }

    Write-Host ("[+] Staged Execution_Lead_{0} -- {1} -- {2}" -f $idx, $lead.Severity, $lead.ExploitPrimitive) -ForegroundColor Green
}

$statePath = Join-Path $OutputRoot '_research_state.json'
($state | ConvertTo-Json -Depth 6) | Out-File $statePath -Encoding UTF8

Write-Host ""
Write-Host "[+] Workspace staged. $($filtered.Count) Execution_Lead_N folders ready." -ForegroundColor Green
Write-Host "[+] State manifest: $statePath" -ForegroundColor Green
Write-Host ""
Write-Host "Next: hand each Execution_Lead_N\manifest.json to a research agent" -ForegroundColor Cyan
Write-Host "      together with the referenced research prompt. The agent should" -ForegroundColor Cyan
Write-Host "      produce the per-lead deliverables listed in README.md." -ForegroundColor Cyan
