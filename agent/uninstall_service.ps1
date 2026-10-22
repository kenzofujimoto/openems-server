#Requires -RunAsAdministrator
<# Stops the installed service and clears only the openems hosts block.
   Retains protected config, cache and logs for recovery and troubleshooting.
   Does not execute code from the current checkout or delete ProgramData trees.
#>
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedNative {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Native command failed with exit code $LASTEXITCODE" }
}

$cfgDir = Join-Path $env:ProgramData 'openems'
$servicePath = Join-Path $cfgDir 'agent\service.py'
$pythonPathFile = Join-Path $cfgDir 'python-path.txt'
$locationChanged = $false

try {
    if ((-not (Test-Path -LiteralPath $servicePath)) -or (-not (Test-Path -LiteralPath $pythonPathFile))) {
        throw "Protected installed runtime is missing; do not run cleanup from an unrelated checkout"
    }
    foreach ($path in @($cfgDir, (Split-Path -Parent $servicePath), $servicePath, $pythonPathFile)) {
        if (((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Installed paths must not be reparse points"
        }
    }
    $PythonPath = [IO.File]::ReadAllText($pythonPathFile).Trim()
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw "Installed Python runtime is missing" }
    Push-Location (Split-Path -Parent $servicePath)
    $locationChanged = $true
    $managedService = Get-Service -Name 'openems-agent' -ErrorAction SilentlyContinue
    if ($managedService) {
        if ($managedService.Status -ne 'Stopped') {
            Stop-Service -Name 'openems-agent' -ErrorAction Stop
            $managedService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(45))
        }
        Invoke-CheckedNative $PythonPath @('-I', $servicePath, 'remove')
    }
    Invoke-CheckedNative $PythonPath @('-I', $servicePath, 'cleanup-hosts')
    Write-Host "openems-agent removed; its hosts block was cleared. Protected configuration and logs remain at $cfgDir"
}
catch {
    throw "Agent removal failed; inspect service state before retrying. $($_.Exception.Message)"
}
finally {
    if ($locationChanged) { Pop-Location }
}
