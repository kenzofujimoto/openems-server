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

function Assert-ProtectedPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Installed paths must not be reparse points"
    }
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writes = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $acl = Get-Acl -LiteralPath $Path
    # An untrusted owner can rewrite the DACL even without an explicit write grant.
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') -notcontains $owner) {
        throw "Installed runtime must be owned by SYSTEM, Administrators or TrustedInstaller"
    }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (($rule.AccessControlType -eq 'Allow') -and (($rule.FileSystemRights -band $writes) -ne 0) -and ($trusted -notcontains $sid)) {
            throw "Installed runtime must only be writable by SYSTEM, Administrators or TrustedInstaller"
        }
    }
}

$cfgDir = Join-Path $env:ProgramData 'openems'
$servicePath = Join-Path $cfgDir 'agent\service.py'
$pythonPathFile = Join-Path $cfgDir 'python-path.txt'
$locationChanged = $false

try {
    if ((-not (Test-Path -LiteralPath $servicePath)) -or (-not (Test-Path -LiteralPath $pythonPathFile))) {
        throw "Protected installed runtime is missing; do not run cleanup from an unrelated checkout"
    }
    # Removal runs elevated: every file it trusts or executes must be admin-controlled.
    foreach ($path in @($cfgDir, (Split-Path -Parent $servicePath), $servicePath, $pythonPathFile)) {
        Assert-ProtectedPath $path
    }
    $PythonPath = [IO.File]::ReadAllText($pythonPathFile).Trim()
    if (-not (Test-Path -LiteralPath $PythonPath -PathType Leaf)) { throw "Installed Python runtime is missing" }
    Assert-ProtectedPath $PythonPath
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
