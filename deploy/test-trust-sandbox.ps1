param(
    [string]$OutputDirectory = 'C:\openems-results',
    [switch]$SystemPhase,
    [switch]$ProbeEnvironment
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Check observed Sandbox signals without relying on an optional Containers folder.
$executionService = Get-Service -Name 'CExecSvc' -ErrorAction SilentlyContinue
$isSandbox = (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -and
    ($null -ne $executionService) -and ($executionService.Status -eq 'Running')
if ($ProbeEnvironment) {
    Write-Output $isSandbox
    exit 0
}
# Refuse the development host before creating files, tasks or certificates.
if (-not $isSandbox) {
    throw 'This acceptance harness requires Windows Sandbox.'
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Sandbox acceptance requires Administrator rights.'
}

if (-not $SystemPhase) {
    $work = 'C:\openems-acceptance'
    if (Test-Path -LiteralPath $work) { throw 'Acceptance directory already exists; use a fresh Sandbox.' }
    New-Item -ItemType Directory -Path $work | Out-Null
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'openems-agent.exe') -Destination $work
    Copy-Item -LiteralPath $PSCommandPath -Destination (Join-Path $work 'test-trust-sandbox.ps1')
    # SYSTEM writes locally; mapped Sandbox shares belong to the interactive user.
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File C:\openems-acceptance\test-trust-sandbox.ps1 -SystemPhase -OutputDirectory C:\openems-acceptance'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
    $task = 'OpenemsTrustAcceptance'
    try {
        Register-ScheduledTask -TaskName $task -Action $action -User 'SYSTEM' -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $deadline = [DateTime]::UtcNow.AddSeconds(90)
        $resultPath = Join-Path $work 'result.json'
        while (-not (Test-Path -LiteralPath $resultPath)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'SYSTEM acceptance task timed out.' }
            Start-Sleep -Milliseconds 500
        }
        Copy-Item -LiteralPath $resultPath -Destination (Join-Path $OutputDirectory 'result.json')
        $result = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        $result | ConvertTo-Json -Depth 5 | Write-Output
        if (-not $result.passed) { throw 'Trust acceptance failed; inspect result.json.' }
    }
    finally {
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue
    }
    exit 0
}

if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$binary = Join-Path $PSScriptRoot 'openems-agent.exe'
$config = Join-Path $PSScriptRoot 'agent.json'
$authority = Join-Path $PSScriptRoot 'https\authority.json'
$result = [ordered]@{ passed = $false; checks = @(); error = $null }

function Invoke-Agent([string[]]$AgentArguments) {
    $output = & $binary @AgentArguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Agent failed: ' + ($output -join "`n")) }
}

try {
    $baseline = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
    Invoke-Agent @('configure', '--config-path', $config, '--server', 'http://127.0.0.1:1',
        '--devid', 'sandbox-trust-test', '--block-page', '--block-page-https')
    if (Test-Path -LiteralPath $authority) { throw 'Configure created an authority before explicit install.' }
    $result.checks += 'configure does not create authority'
    Invoke-Agent @('install-block-page-trust', '--config', $config)
    $added = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -notin $baseline })
    if ($added.Count -ne 1) { throw 'Explicit installation must add exactly one root.' }
    if (-not (Test-Path -LiteralPath $authority)) { throw 'Protected authority was not persisted.' }
    foreach ($protectedPath in @($authority, (Split-Path -Parent $authority))) {
        $acl = Get-Acl -LiteralPath $protectedPath
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne 'S-1-5-18') {
            throw 'Authority owner is not SYSTEM.'
        }
        if (-not $acl.AreAccessRulesProtected) { throw 'Authority inherits access rules.' }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and $rule.IdentityReference.Value -ne 'S-1-5-18') {
                throw 'Authority grants access to a principal other than SYSTEM.'
            }
        }
    }
    $ownedThumbprint = $added[0].Thumbprint
    $result.checks += 'SYSTEM installs one root; authority owner and protected ACL are SYSTEM-only'
    Invoke-Agent @('install-block-page-trust', '--config', $config)
    $afterRepeat = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
    if ($afterRepeat.Count -ne ($baseline.Count + 1)) { throw 'Repeated installation changed root count.' }
    if ($ownedThumbprint -notin $afterRepeat) { throw 'Repeated installation replaced its root.' }
    $result.checks += 'repeated installation preserves root identity'
    Invoke-Agent @('remove-block-page-trust', '--config', $config)
    if (Test-Path -LiteralPath $authority) { throw 'Removal left the authority file.' }
    $remaining = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
    if (@(Compare-Object -ReferenceObject $baseline -DifferenceObject $remaining).Count -ne 0) {
        throw 'Removal did not restore the original trust roots.'
    }
    $result.checks += 'removal restores original roots and removes authority'
    Invoke-Agent @('remove-block-page-trust', '--config', $config)
    $afterRemovalRepeat = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
    if (@(Compare-Object -ReferenceObject $baseline -DifferenceObject $afterRemovalRepeat).Count -ne 0) {
        throw 'Repeated removal changed unrelated trust roots.'
    }
    $result.checks += 'repeated removal succeeds'
    $result.passed = $true
}
catch {
    $result.error = $_.Exception.Message
}
finally {
    # No private authority, configuration or keys are copied to the host share.
    $temporaryResult = Join-Path $OutputDirectory 'result.tmp'
    $result | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $temporaryResult -Encoding UTF8
    Move-Item -LiteralPath $temporaryResult -Destination (Join-Path $OutputDirectory 'result.json')
}
if (-not $result.passed) { exit 1 }
