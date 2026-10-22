#Requires -RunAsAdministrator
<# Installs from this trusted checkout into protected ProgramData storage.
   Requires a machine-wide Python 3.11+ installation accessible to LocalSystem.
   Example: .\install_service.ps1 -PythonPath C:\Python314\python.exe -Server https://ems.example -Invitation ...
#>
param(
    [Parameter(Mandatory = $true)][string]$PythonPath,
    [string]$Server = "http://localhost:8013",
    [string]$DevId = $env:COMPUTERNAME,
    [string]$Vdom = "Default",
    [ValidateRange(1, 86400)][int]$Interval = 15,
    [string]$Invitation,
    [switch]$AllowInsecureHttp
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-CheckedNative {
    param([string]$FilePath, [string[]]$Arguments)
    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Native command failed with exit code $LASTEXITCODE"
    }
}

function Wait-ManagedService {
    param([string]$Status)
    $managedService = Get-Service -Name "openems-agent" -ErrorAction Stop
    $managedService.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::$Status, [TimeSpan]::FromSeconds(45))
    $managedService.Refresh()
    if ($managedService.Status.ToString() -ne $Status) { throw "Service did not reach required state" }
}

function Assert-ProtectedPath {
    param([string]$Path)
    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Runtime paths must not be reparse points"
    }
    $trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-3-0', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $writes = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    $acl = Get-Acl -LiteralPath $Path
    # An untrusted owner can rewrite the DACL even without an explicit write grant.
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if (@('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464') -notcontains $owner) {
        throw "Python runtime must be owned by SYSTEM, Administrators or TrustedInstaller"
    }
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if (($rule.AccessControlType -eq 'Allow') -and (($rule.FileSystemRights -band $writes) -ne 0) -and ($trusted -notcontains $sid)) {
            throw "Python runtime must only be writable by SYSTEM, Administrators or TrustedInstaller"
        }
    }
}

$sourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$cfgDir = Join-Path $env:ProgramData "openems"
$installedDir = Join-Path $cfgDir "agent"
$servicePath = Join-Path $installedDir "service.py"
$createdService = $false
$createdDirectory = $false
$locationChanged = $false

try {
    if (Get-Service -Name "openems-agent" -ErrorAction SilentlyContinue) {
        throw "Service already exists; uninstall it before installing a replacement"
    }
    if (Test-Path -LiteralPath $cfgDir) {
        throw "ProgramData openems directory already exists; preserve its data and review it before a fresh install"
    }
    $PythonPath = (Resolve-Path -LiteralPath $PythonPath).ProviderPath
    if ($PythonPath -match '\\Users\\' -or $PythonPath -match '\\WindowsApps\\') {
        throw "Use a machine-wide Python installation outside user profiles"
    }
    Assert-ProtectedPath $PythonPath
    $pythonRoot = Split-Path -Parent $PythonPath
    foreach ($runtimePath in @($pythonRoot, (Join-Path $pythonRoot "Lib"), (Join-Path $pythonRoot "Lib\site-packages"), (Join-Path $pythonRoot "DLLs"))) {
        Assert-ProtectedPath $runtimePath
    }
    Invoke-CheckedNative $PythonPath @('-I', '-c', 'import sys; assert sys.version_info >= (3, 11); assert sys.prefix == sys.base_prefix, "A global Python installation is required"')

    New-Item -ItemType Directory -Path $cfgDir -ErrorAction Stop | Out-Null
    $createdDirectory = $true
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $cfgDir -AclObject $security
    New-Item -ItemType Directory -Path $installedDir | Out-Null
    foreach ($name in @('service.py', 'openems_agent.py', 'policy.py', 'blockpage.py', 'requirements.txt', 'uninstall_service.ps1')) {
        $sourcePath = Join-Path $sourceDir $name
        if (((Get-Item -LiteralPath $sourcePath).Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Agent source files must not be reparse points"
        }
        Copy-Item -LiteralPath $sourcePath -Destination (Join-Path $installedDir $name)
    }
    $config = @{
        server = $Server; devid = $DevId; vdom = $Vdom; interval = $Interval
        state_path = (Join-Path $cfgDir 'state.json'); allow_insecure_http = [bool]$AllowInsecureHttp
    }
    if ($Invitation) { $config.invitation = $Invitation }
    $utf8 = New-Object Text.UTF8Encoding($false)
    [IO.File]::WriteAllText((Join-Path $cfgDir 'agent.json'), ($config | ConvertTo-Json -Depth 10), $utf8)
    [IO.File]::WriteAllText((Join-Path $cfgDir 'python-path.txt'), $PythonPath, $utf8)
    Push-Location $installedDir
    $locationChanged = $true
    # Validate before changing global packages or creating a service. Never print config.
    Invoke-CheckedNative $PythonPath @('-I', '-c', 'import sys; sys.path.insert(0, sys.argv[1]); import service; service.load_config(sys.argv[2])', $installedDir, (Join-Path $cfgDir 'agent.json'))
    Invoke-CheckedNative $PythonPath @('-I', '-m', 'pip', 'install', '--disable-pip-version-check', '--only-binary=:all:', '-r', (Join-Path $installedDir 'requirements.txt'))
    $postInstallPath = Join-Path $pythonRoot 'Scripts\pywin32_postinstall.py'
    Assert-ProtectedPath $postInstallPath
    Invoke-CheckedNative $PythonPath @('-I', $postInstallPath, '-install')
    Invoke-CheckedNative $PythonPath @('-I', '-c', 'import win32serviceutil; win32serviceutil.LocatePythonServiceExe()')
    $createdService = $true
    Invoke-CheckedNative $PythonPath @('-I', $servicePath, '--startup', 'auto', 'install')
    Invoke-CheckedNative 'sc.exe' @('failure', 'openems-agent', 'reset=', '86400', 'actions=', 'restart/5000/restart/15000/restart/60000')
    Invoke-CheckedNative 'sc.exe' @('failureflag', 'openems-agent', '1')
    Invoke-CheckedNative $PythonPath @('-I', $servicePath, 'start')
    Wait-ManagedService 'Running'
    Start-Sleep -Seconds 2
    if ((Get-Service -Name 'openems-agent').Status -ne 'Running') { throw "Agent failed immediately after startup" }
    Write-Host "openems-agent is running as LocalSystem with automatic recovery. Logs: $cfgDir\agent.log"
}
catch {
    $failureMessage = $_.Exception.Message
    # Only remove the service created by this attempt. Preserve config/cache and
    # any files on partial failure; never recursively remove ProgramData content.
    if ($createdService) {
        try {
            $managedService = Get-Service -Name 'openems-agent'
            if ($managedService.Status -ne 'Stopped') {
                Stop-Service -Name 'openems-agent' -ErrorAction Stop
                Wait-ManagedService 'Stopped'
            }
            Invoke-CheckedNative $PythonPath @('-I', $servicePath, 'remove')
            Invoke-CheckedNative $PythonPath @('-I', $servicePath, 'cleanup-hosts')
        }
        catch { Write-Warning "Service rollback failed; review openems-agent before retrying" }
    }
    if ($createdDirectory) { Write-Warning "Protected installation data was preserved at $cfgDir" }
    throw "Agent installation failed: $failureMessage"
}
finally {
    if ($locationChanged) { Pop-Location }
}
