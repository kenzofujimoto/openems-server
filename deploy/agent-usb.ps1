# Embedded agent adapter. Policy is data on stdin, never executable PowerShell source.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$restriction = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions'
$events = @()
function Field($Object, [string]$Name, $Default) {
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}
function Result($Value) { $Value | ConvertTo-Json -Depth 15 -Compress | Write-Output }
function Action($Policy, $Device) {
    if ($Device.class -ne 'storage' -or (Field $Device 'is_boot' $false) -or (Field $Device 'is_system' $false)) { return 'allow' }
    foreach ($rule in @(Field $Policy 'rules' @())) {
        $matches = $true
        foreach ($name in @('class','vid','pid','serial','instance_id')) {
            $wanted = Field $rule $name $null
            if ($null -ne $wanted -and [string]$wanted -ine [string](Field $Device $name '')) { $matches = $false; break }
        }
        if ($matches) { return [string]$rule.action }
    }
    return [string](Field $Policy 'default_action' 'allow')
}
function Rule-Id($Policy, $Device) {
    foreach ($rule in @(Field $Policy 'rules' @())) {
        $matches = $true
        foreach ($name in @('class','vid','pid','serial','instance_id')) {
            $wanted = Field $rule $name $null
            if ($null -ne $wanted -and [string]$wanted -ine [string](Field $Device $name '')) { $matches = $false; break }
        }
        if ($matches) { return [string]$rule.id }
    }
    return 'default'
}
function Protect-File([string]$Path) {
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm('O:SYD:P(A;;FA;;;SY)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Save-State {
    $temporary = $request.state_path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None').Dispose()
        Protect-File $temporary
        [IO.File]::WriteAllText($temporary, ($script:state | ConvertTo-Json -Depth 15 -Compress), (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $request.state_path -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
function Property([string]$Instance, [string]$Key) {
    try { return (Get-PnpDeviceProperty -InstanceId $Instance -KeyName $Key -ErrorAction Stop).Data }
    catch { return $null }
}
function Inventory {
    $output = @()
    $all = @(Get-PnpDevice -PresentOnly -ErrorAction Stop)
    $disks = @(Get-CimInstance Win32_DiskDrive -ErrorAction Stop)
    foreach ($node in $all | Where-Object { $_.InstanceId -like 'USB\VID_*' -or $_.InstanceId -like 'USBSTOR\*' -or $_.Class -eq 'DiskDrive' }) {
        $instance = [string]$node.InstanceId
        $vid = ''; $productId = ''; $serial = ''; $class = 'other'; $letters = @(); $number = $null; $unique = ''; $boot = $false; $system = $false
        $model = [string]$node.FriendlyName; $manufacturer = [string](Property $instance 'DEVPKEY_Device_Manufacturer')
        if ($node.Class -eq 'Keyboard') { $class = 'keyboard' }
        elseif ($node.Class -eq 'Mouse') { $class = 'mouse' }
        elseif ($node.Class -eq 'HIDClass') { $class = 'hid' }
        $ancestor = $instance
        for ($hop = 0; $hop -lt 8 -and $ancestor; $hop++) {
            if ($ancestor -match '(?i)USB\\VID_([0-9A-F]{4})&PID_([0-9A-F]{4})') { $vid = $Matches[1].ToLowerInvariant(); $productId = $Matches[2].ToLowerInvariant(); break }
            $ancestor = [string](Property $ancestor 'DEVPKEY_Device_Parent')
        }
        if ($instance -like 'USBSTOR\*' -or $node.Class -eq 'DiskDrive') {
            $class = 'storage'; $serial = ($instance -split '\\')[-1] -replace '&\d+$',''
            $disk = @($disks | Where-Object { $_.PNPDeviceID -ieq $instance }) | Select-Object -First 1
            # Virtual/internal disks can have no Storage API entry in Sandbox. Require USB evidence first.
            if (-not $vid -and $instance -notlike 'USBSTOR\*' -and ($null -eq $disk -or [string]$disk.InterfaceType -ine 'USB')) { continue }
            if ($null -ne $disk) {
                $candidate = Get-Disk -Number ([uint32]$disk.Index) -ErrorAction Stop
                if ($candidate.BusType -eq 'USB') {
                    $number = [uint32]$candidate.Number; $unique = [string]$candidate.UniqueId
                    $boot = [bool]$candidate.IsBoot; $system = [bool]$candidate.IsSystem
                    # Keep the PnP identity when WMI reports malformed or missing serial data.
                    $wmiSerial = [string]$disk.SerialNumber
                    if ($wmiSerial -notmatch '\p{Cc}') {
                        $wmiSerial = $wmiSerial.Trim()
                        if ($wmiSerial -and $wmiSerial.Length -le 512) { $serial = $wmiSerial }
                    }
                    $manufacturer = [string]$disk.Manufacturer; $model = [string]$disk.Model
                    $letters = @(Get-Partition -DiskNumber $number -ErrorAction Stop | Where-Object DriveLetter | ForEach-Object { [string]$_.DriveLetter + ':' })
                } else { continue }
            }
        }
        $output += [pscustomobject]@{ instance_id=$instance; vid=$vid; pid=$productId; serial=$serial; class=$class; manufacturer=$manufacturer; product=$model
            drive_letters=@($letters); present=$true; first_seen=''; last_seen=''; disk_number=$number; disk_unique_id=$unique; is_boot=$boot; is_system=$system }
        if ($output.Count -ge 512) { break }
    }
    return @($output)
}
function Get-SafeDisk($Entry) {
    if (-not $Entry.unique_id) { throw 'OPENEMS_DISK_ID_REQUIRED' }
    $candidates = @(Get-Disk -ErrorAction Stop | Where-Object { [string]$_.UniqueId -ceq [string]$Entry.unique_id })
    if ($candidates.Count -eq 0) { return $null }
    if ($candidates.Count -ne 1 -or $candidates[0].BusType -ne 'USB' -or $candidates[0].IsBoot -or $candidates[0].IsSystem) { throw 'OPENEMS_UNSAFE_DISK' }
    return $candidates[0]
}
function Restore-Device($Entry) {
    # Re-enable only a storage child that this journal disabled; never a USB parent or hub.
    if ($Entry.instance_id -notmatch '^(?i:USBSTOR\\|SCSI\\DISK)') { throw 'OPENEMS_UNSAFE_INSTANCE' }
    if ($Entry.disabled_by_us) {
        $problem = Property $Entry.instance_id 'DEVPKEY_Device_ProblemCode'
        if ($null -ne $problem -and [int]$problem -eq 22) { Enable-PnpDevice -InstanceId $Entry.instance_id -Confirm:$false -ErrorAction Stop }
        elseif ($null -ne $problem -and [int]$problem -ne 0) { throw 'OPENEMS_EXTERNAL_DEVICE_CHANGE' }
    }
    $disk = Get-SafeDisk $Entry
    if ($null -eq $disk) { throw 'OPENEMS_RECONNECT_USB_FOR_RESTORE' }
    if ([bool]$disk.IsReadOnly -ne [bool]$Entry.original_read_only) {
        if ([bool]$disk.IsReadOnly -ne [bool]$Entry.applied_read_only) { throw 'OPENEMS_EXTERNAL_DISK_CHANGE' }
        $disk | Set-Disk -IsReadOnly ([bool]$Entry.original_read_only) -ErrorAction Stop
    }
    $disk = Get-SafeDisk $Entry
    if ([bool]$disk.IsOffline -ne [bool]$Entry.original_offline) {
        if ([bool]$disk.IsOffline -ne [bool]$Entry.applied_offline) { throw 'OPENEMS_EXTERNAL_DISK_CHANGE' }
        $disk | Set-Disk -IsOffline ([bool]$Entry.original_offline) -ErrorAction Stop
    }
}
function Registry-Value([string]$Path, [string]$Name) {
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return $null }
    # PS 5.1 Get-ItemPropertyValue can terminate even with SilentlyContinue for a missing value.
    return (Get-Item -LiteralPath $Path -ErrorAction Stop).GetValue($Name, $null)
}
function Remove-OwnRestrictions {
    $list = Join-Path $restriction 'DenyInstanceIDs'
    foreach ($entry in @($script:state.entries)) {
        $current = Registry-Value $list $entry.name
        if ($null -ne $current -and [string]$current -cne [string]$entry.value) { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
        if ($null -ne $current) { Remove-ItemProperty -LiteralPath $list -Name $entry.name -ErrorAction Stop }
    }
    $script:state.entries = @()
    foreach ($saved in @($script:state.flags)) {
        $current = Registry-Value $restriction $saved.name
        if ($null -ne $current -and [int]$current -ne 1 -and $current -ne $saved.value) { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
        if ($saved.name -eq 'DenyInstanceIDs' -and (-not $saved.existed -or [int]$saved.value -eq 0) -and (Test-Path -LiteralPath $list)) {
            $remaining = (Get-Item -LiteralPath $list).GetValueNames()
            if (@($remaining).Count) { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
        }
        if ($saved.existed) { New-ItemProperty -LiteralPath $restriction -Name $saved.name -Value $saved.value -PropertyType DWord -Force | Out-Null }
        elseif ($null -ne $current) { Remove-ItemProperty -LiteralPath $restriction -Name $saved.name -ErrorAction Stop }
    }
    $script:state.flags = @()
}
try {
    if ($request.mode -eq 'plan') {
        $changes = @($request.inventory | ForEach-Object { $action = Action $request.policy $_; if ($action -ne 'allow') { @{instance_id=$_.instance_id; action=$action} } })
        Result @{changes=$changes}; exit 0
    }
    if ($request.mode -eq 'inventory') { Result @{inventory=@(Inventory)}; exit 0 }
    if ($request.mode -notin @('apply','cleanup')) { throw 'OPENEMS_INVALID_MODE' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'OPENEMS_SYSTEM_REQUIRED' }
    if (-not [IO.Path]::IsPathRooted([string]$request.state_path)) { throw 'OPENEMS_INVALID_STATE_PATH' }
    if (Test-Path -LiteralPath $request.state_path) {
        $script:state = Get-Content -LiteralPath $request.state_path -Raw | ConvertFrom-Json
        if ($script:state.format -ne 1) { throw 'OPENEMS_INVALID_JOURNAL' }
    } else { $script:state = [pscustomobject]@{format=1; devices=@(); entries=@(); flags=@()} }
    if ($request.mode -eq 'cleanup') {
        foreach ($entry in @($script:state.devices)) { Restore-Device $entry }
        Remove-OwnRestrictions
        Remove-Item -LiteralPath $request.state_path -Force -ErrorAction SilentlyContinue
        Result @{inventory=@(); events=@(); capabilities=@('usb:storage','usb:polling')}; exit 0
    }
    $current = @(Inventory)
    # A disabled storage child can remain present while Win32_DiskDrive no longer reports it.
    foreach ($saved in @($script:state.devices)) {
        $found = @($current | Where-Object { $_.instance_id -ieq $saved.instance_id })
        if ($found.Count -eq 0) {
            $node = Get-PnpDevice -PresentOnly -InstanceId $saved.instance_id -ErrorAction SilentlyContinue
            if ($null -ne $node) { $current += $saved.device }
        }
    }
    $desired = @($current | ForEach-Object { @{device=$_; action=(Action $request.policy $_)} })
    foreach ($entry in @($script:state.devices)) {
        $wanted = @($desired | Where-Object { $_.device.instance_id -ieq $entry.instance_id -and $_.action -ne 'allow' })
        if ($wanted.Count -eq 0 -or $wanted[0].action -ne $entry.action) {
            Restore-Device $entry
            $script:state.devices = @($script:state.devices | Where-Object { $_.instance_id -ine $entry.instance_id })
            Save-State
        }
    }
    $blocked = @($desired | Where-Object { $_.action -eq 'block' })
    foreach ($entry in @($script:state.entries)) {
        if ($entry.value -notin @($blocked | ForEach-Object { $_.device.instance_id })) {
            $listPath = Join-Path $restriction 'DenyInstanceIDs'
            $currentValue = Registry-Value $listPath $entry.name
            if ($null -ne $currentValue -and [string]$currentValue -cne [string]$entry.value) { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
            if ($null -ne $currentValue) { Remove-ItemProperty -LiteralPath $listPath -Name $entry.name -ErrorAction Stop }
            $script:state.entries = @($script:state.entries | Where-Object { $_.name -cne $entry.name }); Save-State
        }
    }
    if ($blocked.Count -eq 0 -and @($script:state.flags).Count) { Remove-OwnRestrictions; Save-State }
    if ($blocked.Count -gt 0 -and @($script:state.flags).Count -eq 0) {
        $flags = @()
        foreach ($name in @('DenyInstanceIDs','DenyInstanceIDsRetroactive')) {
            $value = Registry-Value $restriction $name
            $flags += @{name=$name; existed=($null -ne $value); value=$value}
        }
        $script:state.flags = $flags; Save-State
    }
    $list = Join-Path $restriction 'DenyInstanceIDs'
    foreach ($item in $desired | Where-Object { $_.action -ne 'allow' }) {
        $device = $item.device
        if ($device.instance_id -notmatch '^(?i:USBSTOR\\|SCSI\\DISK)' -or $device.class -ne 'storage') { throw 'OPENEMS_UNSAFE_INSTANCE' }
        $entry = @($script:state.devices | Where-Object { $_.instance_id -ieq $device.instance_id }) | Select-Object -First 1
        if ($null -eq $entry) {
            $candidate = [pscustomobject]@{unique_id=$device.disk_unique_id}
            $disk = Get-SafeDisk $candidate
            if ($null -eq $disk) { throw 'OPENEMS_STORAGE_NOT_READY' }
            $problem = Property $device.instance_id 'DEVPKEY_Device_ProblemCode'
            if ($null -eq $problem -or [int]$problem -ne 0) { throw 'OPENEMS_DEVICE_STATE_UNKNOWN' }
            $entry = [pscustomobject]@{instance_id=$device.instance_id; unique_id=$device.disk_unique_id; original_read_only=[bool]$disk.IsReadOnly
                original_offline=[bool]$disk.IsOffline; applied_read_only=[bool]$disk.IsReadOnly; applied_offline=[bool]$disk.IsOffline
                disabled_by_us=$false; action=$item.action; device=$device}
            $script:state.devices += $entry; Save-State
        }
        if ($item.action -eq 'block') {
            $known = @($script:state.entries | Where-Object { $_.value -ieq $device.instance_id })
            if ($known.Count -eq 0) {
                $names = if (Test-Path -LiteralPath $list) { @((Get-Item -LiteralPath $list).GetValueNames()) } else { @() }
                $slot = 1
                while ([string]$slot -in $names) { $slot++; if ($slot -gt 65535) { throw 'OPENEMS_RESTRICTION_LIST_FULL' } }
                $name = [string]$slot
                $script:state.entries += @{name=$name; value=$device.instance_id}; Save-State
                New-Item -Path $list -Force | Out-Null
                New-ItemProperty -LiteralPath $list -Name $name -Value $device.instance_id -PropertyType String | Out-Null
            }
            New-ItemProperty -LiteralPath $restriction -Name DenyInstanceIDs -Value 1 -PropertyType DWord -Force | Out-Null
            New-ItemProperty -LiteralPath $restriction -Name DenyInstanceIDsRetroactive -Value 1 -PropertyType DWord -Force | Out-Null
            if (-not $entry.disabled_by_us) {
                # Removable media cannot be made offline; restrict and disable only its storage child.
                $entry.disabled_by_us = $true; Save-State
                Disable-PnpDevice -InstanceId $entry.instance_id -Confirm:$false -ErrorAction Stop
                $events += @{kind='usb_block'; detail=$entry.instance_id; rule_id=(Rule-Id $request.policy $device)}
            }
            $problem = Property $entry.instance_id 'DEVPKEY_Device_ProblemCode'
            if ($null -eq $problem -or [int]$problem -ne 22) { throw 'OPENEMS_RESTART_REQUIRED' }
        } else {
            $disk = Get-SafeDisk $entry
            if ($null -eq $disk) { throw 'OPENEMS_STORAGE_NOT_READY' }
            $entry.applied_read_only = $true; Save-State
            if (-not $disk.IsReadOnly) { $disk | Set-Disk -IsReadOnly $true -ErrorAction Stop; $events += @{kind='usb_read_only'; detail=$entry.instance_id; rule_id=(Rule-Id $request.policy $device)} }
            if (-not (Get-SafeDisk $entry).IsReadOnly) { throw 'OPENEMS_STORAGE_VERIFY_FAILED' }
        }
    }
    if (@($script:state.devices).Count -eq 0 -and @($script:state.entries).Count -eq 0) {
        if (@($script:state.flags).Count) { Remove-OwnRestrictions }
        if (Test-Path -LiteralPath $request.state_path) { Remove-Item -LiteralPath $request.state_path -Force }
    } else { Save-State }
    Result @{inventory=@($current); events=@($events); capabilities=@('usb-control:v1','usb:storage','usb:polling')}
} catch {
    $code = if ($_.Exception.Message -match 'OPENEMS_RESTART_REQUIRED') { 'restart_required' } else { 'control_failed' }
    Result @{error=$code}; exit 1
}
