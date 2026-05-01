#requires -Version 5.1
<#
.SYNOPSIS
    Returns the research-prompt filename that best matches an ExploitPrimitive
    from Analyze-ExecutionLeads. Mirrors the catalog in ui/server.js.

.DESCRIPTION
    Single source of truth for the primitive -> prompt mapping used by the
    Research-Lead skill. Falls back to LPE_Research_Prompt.md when a primitive
    has no explicit owner. The catalog itself is exposed as $ResearchPromptCatalog
    so callers can also enumerate available prompts.

.PARAMETER Primitive
    The ExploitPrimitive string from a high_confidence_leads.json entry
    (e.g. "Env_Hijack_HKCU", "Oplock_ArbitraryWrite", "AeDebug").

.PARAMETER ProjectRoot
    Optional. If supplied, the function returns the absolute path; otherwise it
    returns just the file name relative to the project root.

.PARAMETER List
    Switch. Returns the full prompt catalog instead of resolving a primitive.

.EXAMPLE
    Get-ResearchPromptForPrimitive -Primitive "Env_Hijack_HKCU"
    # -> "UAC_Bypass_Research_Prompt.md"

.EXAMPLE
    Get-ResearchPromptForPrimitive -List | Format-Table

.NOTES
    Keep this catalog in sync with:
      - ui/server.js (RESEARCH_PROMPTS array)
      - skills/Research-Lead/SKILL.md (section 5 table)
      - skills/Analyze-ExecutionLeads/SKILL.md (Exploitation Primitive Taxonomy)
#>

$ResearchPromptCatalog = @(
    [PSCustomObject]@{
        Id = 'lpe'
        Title = 'LPE (Local Privilege Escalation)'
        File = 'LPE_Research_Prompt.md'
        Primitives = @(
            'SMB_Coercion','Oplock_ArbitraryWrite','Pipe_Plant_Redirect','Pipe_Hijack',
            'Registry_Coercion','Binary_Plant_HighPriv','Binary_Plant_UserSpace',
            'SxS_DotLocal','Dependency_Hijack','Config_Poison','AppExecAlias_Plant',
            'PowerShell_Profile','Electron_AsarTamper'
        )
    },
    [PSCustomObject]@{
        Id = 'uac'
        Title = 'UAC Bypass'
        File = 'UAC_Bypass_Research_Prompt.md'
        Primitives = @('COM_Hijack_HKCU','Env_Hijack_HKCU')
    },
    [PSCustomObject]@{
        Id = 'rce_lateral'
        Title = 'RCE / Lateral Movement'
        File = 'RCE_LateralMovement_Research_Prompt.md'
        Primitives = @('URL_NTLM_Coerce','Theme_NTLM_Coerce','DesktopIni_Coerce','WebShell_Plant','LNK_Hijack','Cert_Plant')
    },
    [PSCustomObject]@{
        Id = 'proxy'
        Title = 'Proxy Execution / LOLBins'
        File = 'ProxyExecution_LOLBin_Research_Prompt.md'
        Primitives = @('LOLBin_Proxy','AutoRun_Persistence')
    },
    [PSCustomObject]@{
        Id = 'admin_kernel'
        Title = 'Admin -> SYSTEM / Kernel'
        File = 'AdminToSystemKernel_Research_Prompt.md'
        Primitives = @('Service_BinaryPath','IFEO_Debugger','AeDebug','ScheduledTask_Plant')
    }
)

function Get-ResearchPromptForPrimitive {
    [CmdletBinding(DefaultParameterSetName = 'ByPrimitive')]
    param(
        [Parameter(ParameterSetName = 'ByPrimitive', Mandatory = $true, Position = 0)]
        [string]$Primitive,

        [Parameter(ParameterSetName = 'ByPrimitive')]
        [string]$ProjectRoot,

        [Parameter(ParameterSetName = 'List', Mandatory = $true)]
        [switch]$List
    )

    if ($PSCmdlet.ParameterSetName -eq 'List') {
        return $ResearchPromptCatalog
    }

    $target = $Primitive.Trim()
    $match  = $ResearchPromptCatalog | Where-Object { $_.Primitives -contains $target } | Select-Object -First 1

    if (-not $match) {
        # Universal default: LPE prompt
        $match = $ResearchPromptCatalog | Where-Object { $_.Id -eq 'lpe' }
    }

    if ([string]::IsNullOrWhiteSpace($ProjectRoot)) {
        return $match.File
    }
    return Join-Path $ProjectRoot $match.File
}

# When dot-sourced (.) this exposes the function and catalog. When run directly,
# expect a primitive on the command line and emit the resolved file name.
if ($MyInvocation.InvocationName -ne '.' -and $args.Count -gt 0) {
    Get-ResearchPromptForPrimitive -Primitive $args[0]
}
