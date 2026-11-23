param([string]$OutputDirectory, [string]$Wix = 'wix', [string]$AgentExe, [switch]$Production, [switch]$Next, [switch]$Plan)
# Builds the MSIs consumed by the Sandbox harnesses. Fault-injection fixtures must never ship;
# -Production builds the package without any test-only define. -Production -Next builds the same
# agent as a later version, so harnesses can upgrade from the current production package.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$repository = Split-Path -Parent $PSScriptRoot
if ($Production) {
    $metadata = Get-Content -LiteralPath (Join-Path $repository 'app\__init__.py') -Raw
    $assignments = [regex]::Matches($metadata, '(?m)^__version__[ \t]*=')
    $versionsInMetadata = [regex]::Matches($metadata, '(?m)^__version__[ \t]*=[ \t]*["'']((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))["''][ \t]*\r?$')
    if ($assignments.Count -ne 1 -or $versionsInMetadata.Count -ne 1) {
        throw 'app.__version__ must declare one literal three-part release version.'
    }
    $productionVersion = [version]$versionsInMetadata[0].Groups[1].Value
}
if ($Production -and $Next) {
    $versions = @('{0}.{1}.{2}' -f $productionVersion.Major, $productionVersion.Minor, ($productionVersion.Build + 1))
    $fixtures = @('openems-agent-next.msi')
    $defines = @()
} elseif ($Production) {
    $versions = @($productionVersion.ToString(3))
    $fixtures = @('openems-agent.msi')
    $defines = @()
} elseif ($Next) {
    throw '-Next requires -Production.'
} else {
    $versions = @('0.2.0', '0.2.1', '0.2.2')
    $fixtures = @($versions | ForEach-Object { "openems-agent-$_.msi" })
    $defines = @('FaultInjection=1')
}
if ($Plan) {
    @{ fixtures=$fixtures; defines=$defines; versions=$versions } | ConvertTo-Json -Depth 3
    exit 0
}
if (-not $OutputDirectory) { throw 'Pass -OutputDirectory for the Sandbox input folder.' }
$source = Join-Path $repository 'agent-rs\installer\openems-agent.wxs'
if (-not $AgentExe) { $AgentExe = Join-Path $repository 'agent-rs\target\release\openems-agent.exe' }
if (-not (Test-Path -LiteralPath $AgentExe -PathType Leaf)) { throw "Agent executable not found: $AgentExe" }
# The session component is built next to the agent (cargo builds both binaries).
$SessionExe = Join-Path (Split-Path -Parent $AgentExe) 'openems-session.exe'
if (-not (Test-Path -LiteralPath $SessionExe -PathType Leaf)) { throw "Session component not found: $SessionExe" }
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
for ($index = 0; $index -lt $versions.Count; $index++) {
    $target = Join-Path $OutputDirectory $fixtures[$index]
    $arguments = @('build', $source, '-arch', 'x64', '-d', ('Version=' + $versions[$index]), '-d', ('AgentExe=' + $AgentExe), '-d', ('SessionExe=' + $SessionExe)) +
        @($defines | ForEach-Object { @('-d', $_) }) + @('-o', $target)
    & $Wix @arguments
    if ($LASTEXITCODE -ne 0) { throw ('wix build failed for ' + $fixtures[$index] + ' with exit code ' + $LASTEXITCODE) }
}
Write-Output ('Built ' + $fixtures.Count + ' package(s) in ' + $OutputDirectory)
