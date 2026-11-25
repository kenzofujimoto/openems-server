param([Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$LiteralPath)

# Inspect existing package data only; emit metadata after every read succeeds.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Release-ComObject($Value) {
    if ($null -ne $Value -and [Runtime.InteropServices.Marshal]::IsComObject($Value)) {
        [void][Runtime.InteropServices.Marshal]::FinalReleaseComObject($Value)
    }
}

function Read-MsiStrings($Database, [string]$Query) {
    $view = $null
    $record = $null
    try {
        $view = $Database.OpenView($Query)
        [void]$view.Execute()
        while ($null -ne ($record = $view.Fetch())) {
            [string]$record.StringData(1)
            Release-ComObject $record
            $record = $null
        }
    } finally {
        Release-ComObject $record
        if ($null -ne $view) { [void]$view.Close() }
        Release-ComObject $view
    }
}

function Get-AgentActionsHash($Database) {
    $view = $null
    $record = $null
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $view = $Database.OpenView("SELECT ``Data`` FROM ``Binary`` WHERE ``Name`` = 'AgentActions'")
        [void]$view.Execute()
        $record = $view.Fetch()
        if ($null -eq $record) { throw 'Missing AgentActions binary stream.' }
        $size = $record.DataSize(1)
        if ($size -le 0 -or $size -gt 67108864) { throw 'AgentActions stream size is outside accepted bounds.' }
        $total = 0
        while ($total -lt $size) {
            # msiReadStreamBytes=1: one raw byte per BSTR character; never decode text.
            # https://learn.microsoft.com/en-us/windows/win32/msi/record-readstream
            $chunk = [string]$record.ReadStream(1, [Math]::Min(65536, $size - $total), 1)
            if ($chunk.Length -eq 0) { throw 'Truncated AgentActions binary stream.' }
            $bytes = New-Object byte[] $chunk.Length
            for ($index = 0; $index -lt $chunk.Length; $index++) {
                $bytes[$index] = [byte][int]$chunk[$index]
            }
            [void]$hash.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0)
            $total += $bytes.Length
        }
        [void]$hash.TransformFinalBlock([byte[]]@(), 0, 0)
        ([BitConverter]::ToString($hash.Hash)).Replace('-', '').ToLowerInvariant()
    } finally {
        $hash.Dispose()
        Release-ComObject $record
        if ($null -ne $view) { [void]$view.Close() }
        Release-ComObject $view
    }
}

$installer = $null
$database = $null
try {
    $file = Get-Item -LiteralPath $LiteralPath
    if ($file -isnot [IO.FileInfo]) { throw 'Pass an existing MSI file.' }
    $installer = New-Object -ComObject WindowsInstaller.Installer
    # msiOpenDatabaseModeReadOnly=0: no persistent database changes.
    $database = $installer.OpenDatabase($file.FullName, 0)
    $versions = @(Read-MsiStrings $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'ProductVersion'")
    $upgrades = @(Read-MsiStrings $database "SELECT ``Value`` FROM ``Property`` WHERE ``Property`` = 'UpgradeCode'")
    if ($versions.Count -ne 1 -or $upgrades.Count -ne 1) { throw 'Missing or ambiguous MSI identity.' }
    $actions = @(Read-MsiStrings $database 'SELECT `Action` FROM `CustomAction`' | Sort-Object)
    $properties = @(Read-MsiStrings $database 'SELECT `Property` FROM `Property`' | Sort-Object)
    $digest = Get-AgentActionsHash $database
    # A PowerShell 7 parent can pass module paths incompatible with Windows PowerShell 5.1.
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1')
    $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName
    [ordered]@{
        product_version = $versions[0]
        upgrade_code = $upgrades[0]
        custom_actions = $actions
        properties = $properties
        agent_actions_sha256 = $digest
        signature_status = $signature.Status.ToString()
    } | ConvertTo-Json -Depth 4
} catch {
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
} finally {
    Release-ComObject $database
    Release-ComObject $installer
}
