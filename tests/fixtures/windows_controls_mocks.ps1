# Child-process fixtures only. Every Windows mutation is replaced before loading an adapter.
$fixture = Get-Content -LiteralPath (Join-Path $script:fixtureRoot 'fixture.json') -Raw | ConvertFrom-Json
$script:fixtureSystemRoot = Join-Path $script:fixtureRoot 'systemroot'
$script:restriction = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
$script:mock = @{disabled=$false;read_only=$false;offline=$false;registry=@{}}
$savedMock = Join-Path $script:fixtureRoot 'mock-state.json'
if (Microsoft.PowerShell.Management\Test-Path -LiteralPath $savedMock) {
    $saved = Get-Content -LiteralPath $savedMock -Raw | ConvertFrom-Json
    foreach ($name in @('disabled','read_only','offline')) { $script:mock[$name] = [bool]$saved.$name }
    foreach ($key in $saved.registry.PSObject.Properties) {
        $values = @{}
        foreach ($value in $key.Value.PSObject.Properties) { $values[$value.Name] = $value.Value }
        $script:mock.registry[$key.Name] = $values
    }
} else {
    foreach ($key in $fixture.registry.PSObject.Properties) {
        $values = @{}
        foreach ($value in $key.Value.PSObject.Properties) { $values[$value.Name] = $value.Value }
        $script:mock.registry[$key.Name] = $values
    }
}
function Trace-Mock([string]$Name, $Detail) {
    @{name=$Name;detail=$Detail} | ConvertTo-Json -Compress -Depth 8 |
        Add-Content -LiteralPath (Join-Path $script:fixtureRoot 'calls.jsonl')
}
function Save-Mock {
    $script:mock | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $script:fixtureRoot 'mock-state.json')
}
function Assert-FixturePath([string]$Path) {
    if (-not [IO.Path]::GetFullPath($Path).StartsWith(($script:fixtureRoot + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'A mock refused a path outside its temporary fixture.'
    }
}
function Set-Acl {
    [CmdletBinding()] param([string]$LiteralPath, $AclObject)
    Assert-FixturePath $LiteralPath
    Trace-Mock 'Set-Acl' $LiteralPath
}
function Test-Path {
    [CmdletBinding()] param([Alias('Path')][string]$LiteralPath, [string]$PathType)
    if ($LiteralPath.StartsWith('HKLM:')) { return $script:mock.registry.ContainsKey($LiteralPath) }
    Microsoft.PowerShell.Management\Test-Path @PSBoundParameters
}
function Get-Item {
    [CmdletBinding()] param([string]$LiteralPath)
    if ($LiteralPath.StartsWith('HKLM:')) {
        if (-not $script:mock.registry.ContainsKey($LiteralPath)) { throw 'Fixture registry key absent.' }
        $key = [pscustomobject]@{values=$script:mock.registry[$LiteralPath]}
        $key | Add-Member -MemberType ScriptMethod -Name GetValue -Value {
            param($Name, $Default)
            if ($this.values.ContainsKey($Name)) { return $this.values[$Name] }
            return $Default
        }
        $key | Add-Member -MemberType ScriptMethod -Name GetValueNames -Value { @($this.values.Keys) }
        return $key
    }
    $item = Microsoft.PowerShell.Management\Get-Item @PSBoundParameters
    [pscustomobject]@{Length=$item.Length;FullName=$item.FullName;PSIsContainer=$false;VersionInfo=[pscustomobject]@{OriginalFilename='fixture.exe';FileVersion='1';ProductName='Fixture'}}
}
function Get-FileHash {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Algorithm)
    Assert-FixturePath $LiteralPath
    $sha=[Security.Cryptography.SHA256]::Create()
    try { [pscustomobject]@{Hash=([BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($LiteralPath)))).Replace('-','')} }
    finally { $sha.Dispose() }
}
function Get-ItemPropertyValue {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Name)
    if (-not $LiteralPath.StartsWith('HKLM:')) { throw 'Unexpected registry fixture path.' }
    if (-not $script:mock.registry.ContainsKey($LiteralPath)) { return $null }
    if (-not $script:mock.registry[$LiteralPath].ContainsKey($Name)) {
        throw [Management.Automation.PSArgumentException]::new('Existing key has no requested value, even with SilentlyContinue.')
    }
    return $script:mock.registry[$LiteralPath][$Name]
}
function New-Item {
    [CmdletBinding()] param([string]$Path,[string]$ItemType,[switch]$Force)
    if ($Path.StartsWith('HKLM:')) {
        if (-not $script:mock.registry.ContainsKey($Path)) { $script:mock.registry[$Path] = @{} }
        Save-Mock
        return
    }
    Assert-FixturePath $Path
    Microsoft.PowerShell.Management\New-Item @PSBoundParameters
}
function New-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Name,$Value,[string]$PropertyType,[switch]$Force)
    if (-not $LiteralPath.StartsWith('HKLM:')) { throw 'Unexpected registry fixture path.' }
    if (-not $script:mock.registry.ContainsKey($LiteralPath)) { $script:mock.registry[$LiteralPath] = @{} }
    $script:mock.registry[$LiteralPath][$Name] = $Value
    Trace-Mock 'New-ItemProperty' @{path=$LiteralPath;name=$Name;value=$Value}
    Save-Mock
}
function Remove-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Name)
    if (-not $LiteralPath.StartsWith('HKLM:')) { throw 'Unexpected registry fixture path.' }
    $script:mock.registry[$LiteralPath].Remove($Name)
    Save-Mock
}
function Remove-Item {
    [CmdletBinding()] param([string]$LiteralPath,[switch]$Force)
    Assert-FixturePath $LiteralPath
    Microsoft.PowerShell.Management\Remove-Item @PSBoundParameters
}
function Copy-Item {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    Assert-FixturePath $Destination
    Trace-Mock 'Copy-Item' @{source=$LiteralPath;destination=$Destination}
    Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
}
function Get-CimInstance {
    [CmdletBinding()] param([string]$ClassName)
    if ($ClassName -ne 'Win32_DiskDrive') { throw 'Unexpected CIM query in fixture.' }
    [pscustomobject]@{PNPDeviceID='USBSTOR\DISK\fixture';Index=1;InterfaceType='USB';SerialNumber=$fixture.wmi_serial;Manufacturer='Fixture';Model='Removable fixture'}
}
function Get-PnpDevice {
    [CmdletBinding()] param([switch]$PresentOnly,[string]$InstanceId)
    [pscustomobject]@{InstanceId='USBSTOR\DISK\fixture';Class='DiskDrive';FriendlyName='Removable fixture'}
}
function Get-PnpDeviceProperty {
    [CmdletBinding()] param([string]$InstanceId,[string]$KeyName)
    $value = switch ($KeyName) {
        'DEVPKEY_Device_Parent' { 'USB\VID_058F&PID_6387\SERIAL' }
        'DEVPKEY_Device_ProblemCode' { if ($script:mock.disabled) { 22 } else { 0 } }
        default { 'Fixture' }
    }
    [pscustomobject]@{Data=$value}
}
function Get-Disk {
    [CmdletBinding()] param([uint32]$Number)
    [pscustomobject]@{Number=1;UniqueId='fixture-usb-id';BusType='USB';IsBoot=[bool]$fixture.boot;IsSystem=[bool]$fixture.boot;IsReadOnly=$script:mock.read_only;IsOffline=$script:mock.offline}
}
function Get-Partition {
    [CmdletBinding()] param([uint32]$DiskNumber)
    [pscustomobject]@{DriveLetter='E'}
}
function Set-Disk {
    [CmdletBinding()] param([Parameter(ValueFromPipeline)]$InputObject,[bool]$IsOffline,[bool]$IsReadOnly)
    process {
        Trace-Mock 'Set-Disk' $PSBoundParameters
        if ($PSBoundParameters.ContainsKey('IsOffline')) {
            if ($fixture.scenario -ne 'legacy_offline' -or $IsOffline) { throw 'Removable media cannot be set to offline.' }
            $script:mock.offline = $false
        } else {
            $script:mock.read_only = $IsReadOnly
        }
        Save-Mock
    }
}
function Disable-PnpDevice {
    [CmdletBinding()] param([string]$InstanceId,[switch]$Confirm)
    if ($InstanceId -ne 'USBSTOR\DISK\fixture') { throw 'Only fixture storage may be disabled.' }
    $script:mock.disabled = $true
    Trace-Mock 'Disable-PnpDevice' $InstanceId
    Save-Mock
}
function Enable-PnpDevice {
    [CmdletBinding()] param([string]$InstanceId,[switch]$Confirm)
    if ($InstanceId -ne 'USBSTOR\DISK\fixture') { throw 'Only fixture storage may be enabled.' }
    $script:mock.disabled = $false
    Trace-Mock 'Enable-PnpDevice' $InstanceId
    Save-Mock
}
function Import-Module {
    [CmdletBinding()] param([string]$Name)
    if ($Name -ne 'ConfigCI') { throw 'Unexpected module import in fixture.' }
}
function Get-NetFirewallRule { throw 'Unexpected firewall operation in a WDAC-only fixture.' }
function New-NetFirewallRule { throw 'Unexpected firewall operation in a WDAC-only fixture.' }
function Set-NetFirewallRule { throw 'Unexpected firewall operation in a WDAC-only fixture.' }
function Remove-NetFirewallRule { throw 'Unexpected firewall operation in a WDAC-only fixture.' }
function Get-WinEvent {
    [CmdletBinding()] param([string]$LogName,[int]$MaxEvents,[string]$FilterXPath,[switch]$Oldest)
    $errorRecord = [Management.Automation.ErrorRecord]::new([InvalidOperationException]::new('No events'), 'NoMatchingEventsFound', [Management.Automation.ErrorCategory]::ObjectNotFound, $null)
    $PSCmdlet.ThrowTerminatingError($errorRecord)
}
function Get-AuthenticodeSignature {
    [CmdletBinding()] param([string]$LiteralPath)
    [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Fixture Publisher'}}
}
function Get-SystemDriver {
    [CmdletBinding()] param([string]$ScanPath,[switch]$UserPEs,[switch]$NoScript,[switch]$NoShadowCopy)
    Assert-FixturePath $ScanPath
    $files=@(Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $ScanPath -File -Filter '*.exe')
    Trace-Mock 'Get-SystemDriver' @{path=$ScanPath;files=@($files | ForEach-Object FullName);user_pes=[bool]$UserPEs;no_script=[bool]$NoScript;no_shadow_copy=[bool]$NoShadowCopy}
    $drivers=New-Object 'Collections.Generic.List[object]'
    if($fixture.scenario -ne 'drivers_empty') {
        foreach($file in $files) {
            $path=if($fixture.scenario -in @('drivers_unrelated','drivers_conflicting')) {Join-Path $script:fixtureRoot 'unrelated.exe'} else {$file.FullName}
            $friendly=if($fixture.scenario -eq 'drivers_conflicting') {$file.FullName} else {$path}
            if($fixture.scenario -eq 'drivers_native_prefix') { $path='\\?\'+$path;$friendly=$path }
            if($fixture.scenario -eq 'drivers_friendly_leaf') { $friendly=$file.Name }
            $drivers.Add([pscustomobject]@{FilePath=$path;FriendlyName=$friendly;UserMode=($fixture.scenario -ne 'drivers_kernel')})
            if($fixture.scenario -eq 'drivers_duplicate') { $drivers.Add([pscustomobject]@{FilePath=$path;FriendlyName=$path;UserMode=$true}) }
        }
    }
    Write-Output -NoEnumerate $drivers
}
function New-CIPolicyRule {
    [CmdletBinding()] param([string]$FilePathRule,[string]$DriverFilePath,[object[]]$DriverFiles=@(),[string]$Level,[string]$SpecificFileNameLevel,[switch]$Deny)
    Trace-Mock 'New-CIPolicyRule' @{level=$Level;legacy_path=$DriverFilePath;file_path_rule=$FilePathRule;driver_paths=@($DriverFiles | ForEach-Object FilePath);driver_user_modes=@($DriverFiles | ForEach-Object UserMode);deny=[bool]$Deny;specific_file_name_level=$SpecificFileNameLevel}
    if ($fixture.scenario -in @('console_noise','console_failure')) { [Console]::Out.WriteLine('"Scan completed successfully"') }
    if ($fixture.scenario -eq 'console_failure') { throw 'Fixture ConfigCI failure.' }
    $rules=New-Object 'Collections.Generic.List[object]'
    if($fixture.scenario -ne 'rules_empty') {
        if($fixture.scenario -eq 'rules_mixed') { $rules.Add([pscustomobject]@{UserMode=$false;Id='kernel-rule'}) }
        $userMode=($fixture.scenario -ne 'rules_kernel' -and ($fixture.scenario -ne 'requires_driver_files' -or $DriverFiles.Count -gt 0 -or $FilePathRule))
        $rules.Add([pscustomobject]@{UserMode=$userMode;Id='fixture-rule'})
    }
    Write-Output -NoEnumerate $rules
}
function Merge-CIPolicy {
    [CmdletBinding()] param([string[]]$PolicyPaths,[string]$OutputFilePath,$Rules)
    $source = Join-Path $script:fixtureSystemRoot 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
    Trace-Mock 'Merge-CIPolicy' @{inputs=$PolicyPaths;output=$OutputFilePath;rule_ids=@($Rules | ForEach-Object Id);user_modes=@($Rules | ForEach-Object UserMode)}
    if ($fixture.scenario -eq 'readonly_template' -and $source -in $PolicyPaths) {
        throw [UnauthorizedAccessException]::new('The system template cannot be opened for writing.')
    }
    [IO.File]::WriteAllText($OutputFilePath, '<SiPolicy><PolicyID>{00000000-0000-0000-0000-000000000000}</PolicyID><BasePolicyID>{00000000-0000-0000-0000-000000000000}</BasePolicyID><VersionEx>1.0.0.0</VersionEx></SiPolicy>')
}
function Set-CIPolicyIdInfo {
    [CmdletBinding()] param([string]$FilePath,[string]$PolicyName,[switch]$ResetPolicyID)
    Trace-Mock 'Set-CIPolicyIdInfo' $PolicyName
}
function Set-RuleOption {
    [CmdletBinding()] param([string]$FilePath,[int]$Option,[switch]$Delete)
    Trace-Mock 'Set-RuleOption' @{option=$Option;delete=[bool]$Delete}
}
function ConvertFrom-CIPolicy {
    [CmdletBinding()] param([string]$XmlFilePath,[string]$BinaryFilePath)
    Assert-FixturePath $BinaryFilePath
    [IO.File]::WriteAllText($BinaryFilePath, 'fixture-policy-binary')
}
