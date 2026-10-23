param([string]$OutputDirectory, [string]$Wix = 'wix', [string]$AgentExe, [switch]$Production, [switch]$Plan)
# Builds the MSIs consumed by the Sandbox harnesses. Fault-injection fixtures must never ship;
# -Production builds the package without any test-only define.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Production) {
    $versions = @('0.3.0')
    $fixtures = @('openems-agent.msi')
    $defines = @()
} else {
    $versions = @('0.2.0', '0.2.1', '0.2.2')
    $fixtures = @($versions | ForEach-Object { "openems-agent-$_.msi" })
    $defines = @('FaultInjection=1')
}
if ($Plan) {
    @{ fixtures=$fixtures; defines=$defines } | ConvertTo-Json -Depth 3
    exit 0
}
if (-not $OutputDirectory) { throw 'Pass -OutputDirectory for the Sandbox input folder.' }
$repository = Split-Path -Parent $PSScriptRoot
$source = Join-Path $repository 'agent-rs\installer\openems-agent.wxs'
if (-not $AgentExe) { $AgentExe = Join-Path $repository 'agent-rs\target\release\openems-agent.exe' }
if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) { throw "Agent executable not found: $AgentExe" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
for ($index = 0; $index -lt $versions.Count; $index++) {
    $target = Join-Path $OutputDirectory $fixtures[$index]
    $arguments = @('build', $source, '-arch', 'x64', '-d', ('Version=' + $versions[$index]), '-d', ('AgentExe=' + $AgentExe)) +
        @($defines | ForEach-Object { @('-d', $_) }) + @('-o', $target)
    & $Wix @arguments
    if ($LASTEXITCODE -ne 0) { throw ('wix build failed for ' + $fixtures[$index] + ' with exit code ' + $LASTEXITCODE) }
}
Write-Output ('Built ' + $fixtures.Count + ' package(s) in ' + $OutputDirectory)
