param (
    [Parameter(Mandatory=$false)]
    [string]$CsvPath = "C:\Users\Argentix\Downloads\BootLogProcMonAllHighPrivFiles.CSV",
    [Parameter(Mandatory=$false)]
    [string]$OutputPath,
    [switch]$Silent
)

Write-Host "Calculating total size of CSV feed for progress telemetry..." -ForegroundColor Cyan
# Fast line count using StreamReader
$totalLines = 0
try {
    $reader = New-Object System.IO.StreamReader($CsvPath)
    while ($reader.ReadLine() -ne $null) { $totalLines++ }
} finally {
    if ($reader) { $reader.Close() }
}
Write-Host "Total lines to process: $totalLines" -ForegroundColor Cyan

Write-Host "Streaming CSV to extract paths and mapping to processes using TextFieldParser..." -ForegroundColor Cyan

# Dictionary: Key = Path (String), Value = Hashtable with Processes and FirstEvent metadata
$pathProcessMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Hashtable]' ([System.StringComparer]::OrdinalIgnoreCase)
$script:skippedErrors = New-Object System.Collections.Generic.List[PSCustomObject]

Add-Type -AssemblyName Microsoft.VisualBasic
$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($CsvPath)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(",")
$parser.HasFieldsEnclosedInQuotes = $true

# Read header dynamically
$headerMap = @{}
if (-not $parser.EndOfData) {
    $headers = $parser.ReadFields()
    for ($i = 0; $i -lt $headers.Length; $i++) {
        $headerMap[$headers[$i].Trim().ToLower()] = $i
    }
}

$idxTime = if ($headerMap.ContainsKey("time of day")) { $headerMap["time of day"] } else { 0 }
$idxProc = if ($headerMap.ContainsKey("process name")) { $headerMap["process name"] } else { 1 }
$idxOp   = if ($headerMap.ContainsKey("operation")) { $headerMap["operation"] } else { 3 }
$idxPath = if ($headerMap.ContainsKey("path")) { $headerMap["path"] } else { 4 }
$idxRes  = if ($headerMap.ContainsKey("result")) { $headerMap["result"] } else { 5 }
$idxDet  = if ($headerMap.ContainsKey("detail")) { $headerMap["detail"] } else { 6 }
$idxInt  = if ($headerMap.ContainsKey("integrity")) { $headerMap["integrity"] } else { -1 }
$idxImp  = if ($headerMap.ContainsKey("impersonating")) { $headerMap["impersonating"] } else { -1 }

$traceFileName = Split-Path $CsvPath -Leaf

$lineCount = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()

while (-not $parser.EndOfData) {
    try {
        $fields = $parser.ReadFields()
        $lineCount++
        
        # Procmon exact mapping dynamically
        if ($fields.Length -ge 5) {
            $processName = if ($idxProc -lt $fields.Length) { $fields[$idxProc] } else { "" }
            $path = if ($idxPath -lt $fields.Length) { $fields[$idxPath] } else { "" }
            
            # Simple check for file system path (filters out Registry keys like HKLM\...)
            if (-not [string]::IsNullOrWhiteSpace($path) -and ($path -match "^[a-zA-Z]:\\" -or $path -match "^\\\\")) {
                if (-not $pathProcessMap.ContainsKey($path)) {
                    $firstEvt = [PSCustomObject]@{
                        Time = if ($idxTime -lt $fields.Length) { $fields[$idxTime] } else { "" }
                        Operation = if ($idxOp -lt $fields.Length) { $fields[$idxOp] } else { "" }
                        Result = if ($idxRes -lt $fields.Length) { $fields[$idxRes] } else { "" }
                        Detail = if ($idxDet -lt $fields.Length) { $fields[$idxDet] } else { "" }
                        Integrity = if ($idxInt -ge 0 -and $idxInt -lt $fields.Length) { $fields[$idxInt] } else { "Unknown" }
                        Impersonating = if ($idxImp -ge 0 -and $idxImp -lt $fields.Length) { $fields[$idxImp] } else { "Unknown" }
                    }
                    
                    $pathProcessMap[$path] = @{
                        Processes = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                        FirstEvent = $firstEvt
                    }
                }
                [void]$pathProcessMap[$path].Processes.Add($processName)
            }
        }
    } catch [Microsoft.VisualBasic.FileIO.MalformedLineException] {
        # The parser throws this on bad quotes but does NOT advance the line automatically.
        # We must call ReadLine() to force it forward and prevent an infinite loop.
        $null = $parser.ReadLine()
        $script:skippedErrors.Add([PSCustomObject]@{ Type = "Parser Error"; Error = "Malformed CSV Line"; Details = $_.Exception.Message })
    } catch {
        # Ignore other badly formatted rows gracefully but try to advance
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

$uniquePaths = [string[]]$pathProcessMap.Keys
$totalCount = $uniquePaths.Count
Write-Host "Parsed $lineCount lines in $($sw.Elapsed.TotalSeconds.ToString('0.00'))s. Found $totalCount unique paths." -ForegroundColor Cyan
Write-Host "Starting safe permission tests..." -ForegroundColor Cyan

# 3. 100% SAFE Testing Function (No data destruction)
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
        if ([System.IO.File]::Exists($TargetPath)) {
            # For files, Attempting Write handle is accurate, but we must catch sharing conflicts correctly!
            try {
                $fs = [System.IO.File]::Open($TargetPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $fs.Close()
                return $true
            } catch [System.UnauthorizedAccessException] {
                # Access denied or Read-Only
                return $false
            } catch [System.IO.IOException] {
                # 0x80070020 corresponds to an active File Sharing Violation (-2147024864).
                # This indicates we DO have authorization from Windows security check, but the file is locked / running!
                if ($_.Exception.HResult -eq -2147024864) {
                    return $true
                }
                return $false
            } catch {
                return $false
            }
        }

        # Evaluate Directory writes using ACL instead of randomly dropping .TMP files
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
            $hasDeny = $false

            foreach ($rule in $rules) {
                # Check if rule Identity matches current principal
                if ($CurrentUser.User.Equals($rule.IdentityReference) -or $Principal.IsInRole($rule.IdentityReference)) {
                    $hasWriteData = ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::WriteData) -eq [System.Security.AccessControl.FileSystemRights]::WriteData
                    
                    if ($hasWriteData) {
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

# 4. Execution
$counter = 0
$results = New-Object System.Collections.Generic.List[PSCustomObject]
$swTest = [System.Diagnostics.Stopwatch]::StartNew()

# Pre-fetch security contexts once for massive performance gains
$activeIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$activePrincipal = New-Object System.Security.Principal.WindowsPrincipal($activeIdentity)

foreach ($path in $uniquePaths) {
    if ($counter % 100 -eq 0 -or $counter -eq $totalCount) { 
        Write-Progress -Activity "Testing Permissions" -Status "Testing: $path" -PercentComplete (($counter / $totalCount) * 100)
        Write-Output "[PROGRESS] $counter / $totalCount Evaluating File/ACL Permissions..."
    }
    $counter++

    if (Test-SafeWritePermission -TargetPath $path -CurrentUser $activeIdentity -Principal $activePrincipal) {
        $relatedProcesses = $pathProcessMap[$path].Processes -join ", "
        $evt = $pathProcessMap[$path].FirstEvent

        $results.Add([PSCustomObject]@{
            Path             = $path
            FileExists       = ([System.IO.Directory]::Exists($path) -or [System.IO.File]::Exists($path))
            RelatedProcesses = $relatedProcesses
            TraceFile        = $traceFileName
            Timestamp        = $evt.Time
            Operation        = $evt.Operation
            Result           = $evt.Result
            Detail           = $evt.Detail
            Integrity        = $evt.Integrity
            Impersonating    = $evt.Impersonating
        })
    }
}
Write-Progress -Activity "Testing Permissions" -Completed
$swTest.Stop()

# 5. Results
Write-Host "Process Complete in $($swTest.Elapsed.TotalSeconds.ToString('0.00'))s. $( $results.Count ) writable paths found." -ForegroundColor Green

if ($results.Count -gt 0) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $pluginDir = Split-Path -Parent (Split-Path -Parent (Split-Path -Parent $scriptDir))
    
    $outFolder = if (-not [string]::IsNullOrWhiteSpace($OutputPath)) { $OutputPath } else { $pluginDir }
    $jsonPath = Join-Path $outFolder "writable_paths.json"
    $results | ConvertTo-Json -Depth 3 | Out-File $jsonPath -Encoding UTF8
    Write-Host "Exported RAW results to $jsonPath" -ForegroundColor Green

    if ($script:skippedErrors.Count -gt 0) {
        $errJsonPath = Join-Path $outFolder "parsing_errors.json"
        
        # Deduplicate error messages to avoid massive JSON blooms if the same error hits thousands of times
        $uniqueErrors = $script:skippedErrors | Group-Object Error | Select-Object Name, Count, @{Name="SampleDetails"; Expression={$_.Group[0].Details}}, @{Name="SamplePath"; Expression={$_.Group[0].Path}}, @{Name="Type"; Expression={$_.Group[0].Type}}
        $uniqueErrors | ConvertTo-Json -Depth 3 | Out-File $errJsonPath -Encoding UTF8
        Write-Host "[!] Logged $($script:skippedErrors.Count) unhandled errors (grouped to $($uniqueErrors.Count) unique patterns) to $errJsonPath" -ForegroundColor Yellow
    }

    # Show raw gridview to user as well
    if (-not $Silent) {
        $results | Out-GridView -Title "RAW Writable Paths and Associated Processes"
    }

    # Send instructions for standard Agent processing
    Write-Host "[!] INSTRUCTION: Writable paths extracted. Agent should invoke 'Analyze-ExecutionLeads' skill now." -ForegroundColor Magenta
}