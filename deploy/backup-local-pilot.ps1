param(
    [string]$OutputDirectory,
    [string]$ExpectedCurrentUserSid,
    [int]$ExpectedSessionId = -1,
    [switch]$Plan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$topics = @('configuration', 'state', 'authority', 'cached_msi', 'agent', 'service', 'hosts', 'dns', 'roots', 'registry')
if ($Plan) {
    [ordered]@{
        mode = 'read_only_preflight'
        destination = 'Documents/OpenEMS-Lab/<run>/private'
        requires = @('same_user_sid', 'same_session', 'administrator', 'new_protected_directory')
        topics = $topics
        host_mutations = @()
        rollback_status = 'not_yet_verified'
    } | ConvertTo-Json -Depth 4
    exit 0
}

function Assert-PilotIdentity([string]$ExpectedSid, [int]$ExpectedSession, [string]$CurrentSid, [int]$CurrentSession, [bool]$Administrator) {
    if (-not $ExpectedSid -or $ExpectedSid -ne $CurrentSid) { throw 'identity_mismatch' }
    if ($ExpectedSession -lt 1 -or $ExpectedSession -ne $CurrentSession) { throw 'session_mismatch' }
    if (-not $Administrator) { throw 'administrator_required' }
}

function Assert-PilotNoReparse([string]$Path) {
    $ancestor = [IO.Path]::GetFullPath($Path)
    while ($ancestor) {
        if ([IO.File]::Exists($ancestor) -or [IO.Directory]::Exists($ancestor)) {
            if (([IO.File]::GetAttributes($ancestor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw 'invalid_output_directory'
            }
        }
        $ancestor = [IO.Path]::GetDirectoryName($ancestor)
    }
}

function Get-PilotDestination([string]$OutputDirectory, [string]$DocumentsDirectory) {
    try {
        if (-not $OutputDirectory -or -not [IO.Path]::IsPathRooted($OutputDirectory) -or -not $DocumentsDirectory) { throw 'invalid_output_directory' }
        $leaf = [IO.Path]::GetFileName($OutputDirectory.TrimEnd('\'))
        if ($leaf -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$' -or $leaf.EndsWith('.') -or $leaf -match '^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(\.|$)') { throw 'invalid_output_directory' }
        $destination = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\')
        $lab = [IO.Path]::GetFullPath([IO.Path]::Combine($DocumentsDirectory, 'OpenEMS-Lab')).TrimEnd('\')
        if (-not [string]::Equals([IO.Path]::GetDirectoryName($destination), $lab, [StringComparison]::OrdinalIgnoreCase)) { throw 'invalid_output_directory' }
        if ([IO.File]::Exists($destination) -or [IO.Directory]::Exists($destination)) { throw 'invalid_output_directory' }
        Assert-PilotNoReparse $destination
    } catch { throw 'invalid_output_directory' }
    $destination
}

function New-PilotPrivateDirectory([string]$Path, [Security.Principal.SecurityIdentifier]$UserSid) {
    if ([IO.File]::Exists($Path) -or [IO.Directory]::Exists($Path)) { throw 'invalid_output_directory' }
    $security = New-Object Security.AccessControl.DirectorySecurity
    $security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($UserSid)
    foreach ($sid in @($UserSid, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')), (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $security.AddAccessRule($rule)
    }
    # Directory creation applies the DACL before any private file can exist.
    (New-Object IO.DirectoryInfo($Path)).Create($security)
}

function Get-PilotHash([IO.Stream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $result = ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant() }
    finally { $hash.Dispose() }
    $result
}

function Copy-PilotFile([string]$Source, [string]$Destination) {
    if (-not [IO.Path]::IsPathRooted($Source)) { throw 'backup_failed' }
    Assert-PilotNoReparse $Source
    $inputStream = $null
    $outputStream = $null
    try {
        $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        $size = $inputStream.Length
        if ($size -gt 67108864) { throw 'backup_failed' }
        $before = Get-PilotHash $inputStream
        $inputStream.Position = 0
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $inputStream.CopyTo($outputStream)
        $outputStream.Dispose()
        $outputStream = $null
        $inputStream.Position = 0
        if ($inputStream.Length -ne $size -or (Get-PilotHash $inputStream) -ne $before) { throw 'source_changed' }
        $copy = [IO.File]::OpenRead($Destination)
        try { if ((Get-PilotHash $copy) -ne $before) { throw 'backup_failed' } }
        finally { $copy.Dispose() }
        $result = [ordered]@{ source = $Source; backup = $Destination; sha256 = $before; bytes = $size }
    } finally {
        if ($null -ne $outputStream) { $outputStream.Dispose() }
        if ($null -ne $inputStream) { $inputStream.Dispose() }
    }
    $result
}

function Test-PilotFilePresent([string]$Path) {
    if (-not [IO.Path]::IsPathRooted($Path)) { throw 'configuration_unreadable' }
    try { $attributes = [IO.File]::GetAttributes($Path) }
    catch [IO.FileNotFoundException] { return $false }
    catch [IO.DirectoryNotFoundException] { return $false }
    if (($attributes -band [IO.FileAttributes]::Directory) -ne 0) { throw 'backup_failed' }
    Assert-PilotNoReparse $Path
    $true
}

function Assert-PilotFilesUnchanged($Files) {
    foreach ($file in $Files) {
        $stream = [IO.File]::Open($file.source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        try {
            if ($stream.Length -ne $file.bytes -or (Get-PilotHash $stream) -ne $file.sha256) { throw 'source_changed' }
        } finally { $stream.Dispose() }
    }
}

function Write-PilotJson([string]$Path, $Value) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 100))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) }
    finally { $stream.Dispose() }
}

function Get-PilotSetting($Config, [string]$Name, [string]$Fallback) {
    $property = $Config.PSObject.Properties[$Name]
    if ($null -eq $property) { $value = $Fallback }
    elseif ($property.Value -is [string] -and $property.Value) { $value = $property.Value }
    else { throw 'configuration_unreadable' }
    $value
}

function Read-PilotRegistryTree($Key) {
    $values = [ordered]@{}
    foreach ($name in $Key.GetValueNames()) {
        $values[$name] = @{ kind = $Key.GetValueKind($name).ToString(); value = $Key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames) }
    }
    $children = [ordered]@{}
    foreach ($name in $Key.GetSubKeyNames()) {
        $child = $Key.OpenSubKey($name, $false)
        try { $children[$name] = Read-PilotRegistryTree $child }
        finally { if ($null -ne $child) { $child.Dispose() } }
    }
    @{ values = $values; children = $children }
}

function Get-PilotRegistrySnapshot {
    $result = [ordered]@{}
    foreach ($hive in @('LocalMachine', 'CurrentUser')) {
        foreach ($view in @('Registry64', 'Registry32')) {
            $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::$hive, [Microsoft.Win32.RegistryView]::$view)
            try {
                foreach ($path in @('SOFTWARE\Policies', 'SYSTEM\CurrentControlSet\Services\openems-agent', 'SYSTEM\CurrentControlSet\Services\USBSTOR')) {
                    $key = $base.OpenSubKey($path, $false)
                    try {
                        $name = $hive + '/' + $view + '/' + $path
                        $result[$name] = if ($null -eq $key) { $null } else { Read-PilotRegistryTree $key }
                    } finally { if ($null -ne $key) { $key.Dispose() } }
                }
            } finally { $base.Dispose() }
        }
    }
    $result
}

function Get-PilotCachedProduct {
    $products = @()
    foreach ($view in @('Registry64', 'Registry32')) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
        try {
            $uninstall = $base.OpenSubKey('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', $false)
            if ($null -ne $uninstall) {
                try {
                    foreach ($name in $uninstall.GetSubKeyNames()) {
                        $key = $uninstall.OpenSubKey($name, $false)
                        try {
                            if ($key.GetValue('DisplayName') -eq 'openems endpoint agent') {
                                $guid = ([guid]$name).ToString('N').ToUpperInvariant()
                                $order = @(7,6,5,4,3,2,1,0,11,10,9,8,15,14,13,12,17,16,19,18,21,20,23,22,25,24,27,26,29,28,31,30)
                                $packed = -join @($order | ForEach-Object { $guid[$_] })
                                $cache = $base.OpenSubKey(('SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products\' + $packed + '\InstallProperties'), $false)
                                try {
                                    if ($null -eq $cache -or -not $cache.GetValue('LocalPackage')) { throw 'cached_msi_unavailable' }
                                    $products += @{ product_code = $name; version = [string]$key.GetValue('DisplayVersion'); local_package = [string]$cache.GetValue('LocalPackage') }
                                } finally { if ($null -ne $cache) { $cache.Dispose() } }
                            }
                        } finally { if ($null -ne $key) { $key.Dispose() } }
                    }
                } finally { $uninstall.Dispose() }
            }
        } finally { $base.Dispose() }
    }
    if ($products.Count -ne 1) { throw 'cached_msi_unavailable' }
    $products[0]
}

function Get-PilotRoots {
    $result = [ordered]@{}
    foreach ($location in @('CurrentUser', 'LocalMachine')) {
        $store = New-Object Security.Cryptography.X509Certificates.X509Store('Root', $location)
        try {
            $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
            $result[$location] = @($store.Certificates | ForEach-Object { @{ thumbprint = $_.Thumbprint; certificate = [Convert]::ToBase64String($_.RawData) } } | Sort-Object { $_.thumbprint })
        } finally { $store.Close() }
    }
    $result
}

$status = 'preflight_failed'
$complete = [ordered]@{}
foreach ($topic in $topics) { $complete[$topic] = $false }
$files = New-Object 'Collections.Generic.List[object]'
$loopback = $false
$snapshotCreated = $false
$rootCounts = @{ current_user = $null; local_machine = $null }
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    Assert-PilotIdentity -ExpectedSid $ExpectedCurrentUserSid -ExpectedSession $ExpectedSessionId -CurrentSid $identity.User.Value -CurrentSession ([Diagnostics.Process]::GetCurrentProcess().SessionId) -Administrator ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
    $status = 'invalid_output_directory'
    $run = Get-PilotDestination -OutputDirectory $OutputDirectory -DocumentsDirectory ([Environment]::GetFolderPath('MyDocuments'))
    $lab = [IO.Path]::GetDirectoryName($run)
    if (-not [IO.Directory]::Exists($lab)) { [void][IO.Directory]::CreateDirectory($lab) }
    New-PilotPrivateDirectory -Path $run -UserSid $identity.User
    $snapshotCreated = $true
    $private = [IO.Path]::Combine($run, 'private')
    New-PilotPrivateDirectory -Path $private -UserSid $identity.User

    $status = 'configuration_unreadable'
    $data = [IO.Path]::Combine([Environment]::GetFolderPath('CommonApplicationData'), 'openems')
    $configRecord = Copy-PilotFile -Source ([IO.Path]::Combine($data, 'agent.json')) -Destination ([IO.Path]::Combine($private, 'agent.json'))
    $files.Add($configRecord)
    $config = [IO.File]::ReadAllText($configRecord.backup) | ConvertFrom-Json
    $origin = Get-PilotSetting $config 'server' ''
    $device = Get-PilotSetting $config 'devid' ''
    $uri = [Uri]$origin
    if (-not $device -or -not $uri.IsAbsoluteUri -or $uri.Scheme -notin @('http', 'https') -or $uri.UserInfo -or $uri.AbsolutePath -ne '/' -or $uri.Query -or $uri.Fragment) { throw 'configuration_unreadable' }
    $loopback = $uri.IsLoopback
    $complete.configuration = $true

    $status = 'backup_failed'
    $state = Get-PilotSetting $config 'state_path' ([IO.Path]::Combine($data, 'state.json'))
    $files.Add((Copy-PilotFile $state ([IO.Path]::Combine($private, 'state.json'))))
    $optionalAbsent = @()
    foreach ($name in @('control-pending.json', 'tamper-pending.json', 'browser-policies.json', 'application-control.json', 'usb-control.json', 'usb-inventory.json', 'uninstall.json', 'session.json')) {
        $source = [IO.Path]::Combine([IO.Path]::GetDirectoryName($state), $name)
        if (Test-PilotFilePresent $source) { $files.Add((Copy-PilotFile $source ([IO.Path]::Combine($private, $name)))) }
        else { $optionalAbsent += $source }
    }
    $complete.state = $true
    $authority = Get-PilotSetting $config 'authority_path' ([IO.Path]::Combine($data, 'https\authority.json'))
    if (Test-PilotFilePresent $authority) { $files.Add((Copy-PilotFile $authority ([IO.Path]::Combine($private, 'authority.json')))) }
    elseif ($null -ne $config.PSObject.Properties['block_page_https'] -and $config.block_page_https) { throw 'backup_failed' }
    else { $optionalAbsent += $authority }
    $complete.authority = $true

    $hosts = Get-PilotSetting $config 'hosts_path' ([IO.Path]::Combine([Environment]::SystemDirectory, 'drivers\etc\hosts'))
    $files.Add((Copy-PilotFile $hosts ([IO.Path]::Combine($private, 'hosts'))))
    if (Test-PilotFilePresent ($hosts + '.openems.bak')) { $files.Add((Copy-PilotFile ($hosts + '.openems.bak') ([IO.Path]::Combine($private, 'hosts.openems.bak')))) }
    $complete.hosts = $true

    $agentDirectory = [IO.Path]::Combine([Environment]::GetFolderPath('ProgramFiles'), 'openems')
    $agent = [IO.Path]::Combine($agentDirectory, 'openems-agent.exe')
    $files.Add((Copy-PilotFile $agent ([IO.Path]::Combine($private, 'openems-agent.exe'))))
    $session = [IO.Path]::Combine($agentDirectory, 'openems-session.exe')
    if (Test-PilotFilePresent $session) { $files.Add((Copy-PilotFile $session ([IO.Path]::Combine($private, 'openems-session.exe')))) }
    $agentVersion = [Diagnostics.FileVersionInfo]::GetVersionInfo($agent).FileVersion
    $complete.agent = $true
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Management\Microsoft.PowerShell.Management.psd1')
    $service = Get-Service -Name 'openems-agent'
    $serviceInfo = @{ status = $service.Status.ToString(); start_type = $service.StartType.ToString() }
    $complete.service = $true

    $roots = Get-PilotRoots
    $rootCounts = @{ current_user = $roots.CurrentUser.Count; local_machine = $roots.LocalMachine.Count }
    Write-PilotJson ([IO.Path]::Combine($private, 'roots.json')) $roots
    $complete.roots = $true
    Write-PilotJson ([IO.Path]::Combine($private, 'registry.json')) (Get-PilotRegistrySnapshot)
    $complete.registry = $true
    Import-Module (Join-Path $PSHOME 'Modules\DnsClient\DnsClient.psd1')
    Import-Module (Join-Path $PSHOME 'Modules\NetSecurity\NetSecurity.psd1')
    $dns = @{
        adapters = @(Get-DnsClientServerAddress | Select-Object InterfaceIndex, InterfaceAlias, AddressFamily, ServerAddresses)
        nrpt = @(Get-DnsClientNrptPolicy -Effective | Select-Object Namespace, NameServers, DnsSecValidationRequired, DnsSecQueryIPsecRequired)
        firewall = @(Get-NetFirewallRule -PolicyStore ActiveStore | Where-Object { $_.DisplayName -like '*openems*' -or $_.Name -like '*openems*' } | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile)
    }
    Write-PilotJson ([IO.Path]::Combine($private, 'dns.json')) $dns
    $complete.dns = $true

    $status = 'cached_msi_unavailable'
    $product = Get-PilotCachedProduct
    $files.Add((Copy-PilotFile $product.local_package ([IO.Path]::Combine($private, 'previous-agent.msi'))))
    $complete.cached_msi = $true
    $status = 'source_changed'
    Assert-PilotFilesUnchanged $files
    foreach ($source in $optionalAbsent) { if (Test-PilotFilePresent $source) { throw 'source_changed' } }
    $status = 'backup_failed'
    Write-PilotJson ([IO.Path]::Combine($private, 'snapshot.json')) @{
        user_sid = $identity.User.Value; session_id = $ExpectedSessionId; server = $origin; device_identity = $device
        config = $config; service = $serviceInfo; agent_version = $agentVersion; product = $product; files = @($files.ToArray())
        absent_optional_files = $optionalAbsent
        captured_at = [DateTime]::UtcNow.ToString('o'); rollback_status = 'not_yet_verified'
    }
    $status = 'backup_complete'
} catch {
    $safe = @('identity_mismatch', 'session_mismatch', 'administrator_required', 'invalid_output_directory', 'source_changed')
    if ($_.Exception.Message -in $safe) { $status = $_.Exception.Message }
}

$passed = $status -eq 'backup_complete'
$report = [ordered]@{
    passed = $passed; status = $status; backup_complete = $passed; snapshot_created = $snapshotCreated
    origin_loopback = $loopback; topics = $complete; file_count = $files.Count; root_counts = $rootCounts
    file_hashes = @($files.ToArray() | ForEach-Object { @{ sha256 = $_.sha256; bytes = $_.bytes } })
    rollback_status = 'not_yet_verified'
}
# Only sanitized status, hashes and counts leave the private snapshot.
$report | ConvertTo-Json -Depth 6
if (-not $passed) { exit 1 }
