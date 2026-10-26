param([ValidateSet('session', 'locations', 'usb', 'applications')][string]$Phase,
      [string]$OutputDirectory = 'C:\openems-results', [switch]$VerifyOnly)
# Checks the exact final package bytes and stamps only fresh reports from this invocation.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$executionService = Get-Service -Name CExecSvc -ErrorAction SilentlyContinue
if (-not $VerifyOnly -and (-not (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -or $null -eq $executionService -or $executionService.Status -ne 'Running')) {
    throw 'This acceptance wrapper requires Windows Sandbox.'
}
$manifest = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'acceptance-manifest.json') -Raw | ConvertFrom-Json
if ($manifest.phase -ne $Phase) { throw 'The acceptance manifest belongs to another phase.' }
function Get-Sha256([string]$Path) {
    $hash = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($Path)
    try { return -join ($hash.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $stream.Dispose(); $hash.Dispose() }
}
function Write-Report([string]$Path, $Value, [switch]$SharedFolder) {
    $temporary = $Path + '.receipt.tmp'
    try {
        $Value | ConvertTo-Json -Depth 20 | Set-Content -LiteralPath $temporary -Encoding UTF8
        # Receipt publication also targets VSMB and must support an existing report.
        if ($SharedFolder) { Copy-Item -LiteralPath $temporary -Destination $Path -Force }
        else { Move-Item -LiteralPath $temporary -Destination $Path -Force }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
foreach ($file in $manifest.files.PSObject.Properties) {
    if ([IO.Path]::GetFileName($file.Name) -ne $file.Name) { throw 'Manifest paths must be plain file names.' }
    $path = Join-Path $PSScriptRoot $file.Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-Sha256 $path) -ne $file.Value.sha256) {
        throw ('Final acceptance input changed or is missing: ' + $file.Name + '. Rebuild the final packages.')
    }
}
if ([IO.Path]::GetFileName($manifest.harness) -ne $manifest.harness -or
    $null -eq $manifest.files.PSObject.Properties[$manifest.harness]) { throw 'The harness must be a verified file in this package.' }
if ($VerifyOnly) {
    @{ verified=$true; phase=$Phase; source_revision=$manifest.source_revision; executes_harness=$false } | ConvertTo-Json
    exit 0
}
$reports = switch ($Phase) {
    'session' { @('session-phase1.json', 'session-result.json') }
    'locations' { @('locations-result.json') }
    'usb' { @('usb-result.json') }
    'applications' { @('applications-result.json') }
}
$started = [DateTime]::UtcNow
$harness = Join-Path $PSScriptRoot $manifest.harness
$arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $harness) + @($manifest.arguments) + @('-OutputDirectory', $OutputDirectory)
& powershell.exe @arguments
$resultCode = $LASTEXITCODE
foreach ($report in $reports) {
    $path = Join-Path $OutputDirectory $report
    if (-not (Test-Path -LiteralPath $path) -or (Get-Item -LiteralPath $path).LastWriteTimeUtc -lt $started) { continue }
    $value = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    $receipt = @{ source_revision=$manifest.source_revision; packages=$manifest.packages; checked_at=[DateTime]::UtcNow.ToString('o') }
    $value | Add-Member -MemberType NoteProperty -Name package_receipt -Value $receipt -Force
    Write-Report $path $value -SharedFolder
}
exit $resultCode
