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

# Dictionary: Key = Path (String), Value = Unique Process Names (HashSet)
$pathProcessMap = New-Object 'System.Collections.Generic.Dictionary[string, System.Collections.Generic.HashSet[string]]' ([System.StringComparer]::OrdinalIgnoreCase)

Add-Type -AssemblyName Microsoft.VisualBasic
$parser = New-Object Microsoft.VisualBasic.FileIO.TextFieldParser($CsvPath)
$parser.TextFieldType = [Microsoft.VisualBasic.FileIO.FieldType]::Delimited
$parser.SetDelimiters(",")
$parser.HasFieldsEnclosedInQuotes = $true

# Read header
if (-not $parser.EndOfData) {
    [void]$parser.ReadFields()
}

$lineCount = 0
$sw = [System.Diagnostics.Stopwatch]::StartNew()

while (-not $parser.EndOfData) {
    try {
        $fields = $parser.ReadFields()
        $lineCount++
        
        # Procmon exact mapping: Time(0), Process Name(1), PID(2), Operation(3), Path(4), Result(5), Detail(6)
        if ($fields.Length -ge 5) {
            $processName = $fields[1]
            $path = $fields[4]
            
            # Simple check for file system path (filters out Registry keys like HKLM\...)
            if (-not [string]::IsNullOrWhiteSpace($path) -and ($path -match "^[a-zA-Z]:\\" -or $path -match "^\\\\")) {
                if (-not $pathProcessMap.ContainsKey($path)) {
                    $pathProcessMap[$path] = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
                }
                [void]$pathProcessMap[$path].Add($processName)
            }
        }
    } catch {
        # Ignore badly formatted rows gracefully
    }

    if ($lineCount % 20000 -eq 0) {
        Write-Host "[PROGRESS] $lineCount / $totalLines"
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
    param([string]$TargetPath)

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
            $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
            $rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
            
            $hasWrite = $false
            $hasDeny = $false

            foreach ($rule in $rules) {
                # Check if rule Identity matches current principal
                if ($currentUser.User.Equals($rule.IdentityReference) -or $principal.IsInRole($rule.IdentityReference)) {
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
        return $false
    }
}

# 4. Execution
$counter = 0
$results = New-Object System.Collections.Generic.List[PSCustomObject]
$swTest = [System.Diagnostics.Stopwatch]::StartNew()

foreach ($path in $uniquePaths) {
    if ($counter % 100 -eq 0 -or $counter -eq $totalCount) { 
        Write-Progress -Activity "Testing Permissions" -Status "Testing: $path" -PercentComplete (($counter / $totalCount) * 100)
    }
    $counter++

    if (Test-SafeWritePermission -TargetPath $path) {
        $relatedProcesses = $pathProcessMap[$path] -join ", "

        $results.Add([PSCustomObject]@{
            Path             = $path
            FileExists       = ([System.IO.Directory]::Exists($path) -or [System.IO.File]::Exists($path))
            RelatedProcesses = $relatedProcesses
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

    # Show raw gridview to user as well
    if (-not $Silent) {
        $results | Out-GridView -Title "RAW Writable Paths and Associated Processes"
    }

    # Send instructions for standard Agent processing
    Write-Host "[!] INSTRUCTION: Writable paths extracted. Agent should invoke 'Analyze-ExecutionLeads' skill now." -ForegroundColor Magenta
}