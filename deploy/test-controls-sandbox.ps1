param([ValidateSet('USB', 'Applications')][string]$Kind = 'Applications',
      [string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan,
      [switch]$DisposableVm, [ValidatePattern('^$|^[D-Zd-z]:$')][string]$PhysicalDrive = '')
# All real control mutations run through the production service in a disposable guest.
# Windows Sandbox automation never substitutes a shared folder for a physical USB device.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'openems-agent.msi'
$reportName = $Kind.ToLowerInvariant() + '-result.json'
$origin = if ($Kind -eq 'USB') { 'http://127.0.0.1:18017' } else { 'http://127.0.0.1:18018' }
$applicationGroup = 'openems application control'
$markerPath = 'C:\openems-disposable-vm.txt'
$markerText = 'OPENEMS DISPOSABLE USB ACCEPTANCE'
$totalTimeout = 1800

function ConvertTo-Canonical($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { return $Value.ToString().ToLowerInvariant() }
    if ($Value -is [string]) { return ConvertTo-Json -InputObject $Value -Compress }
    if ($Value -is [Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        return '{' + ((@($keys | ForEach-Object { (ConvertTo-Canonical ([string]$_)) + ':' + (ConvertTo-Canonical $Value[$_]) })) -join ',') + '}'
    }
    if ($Value -is [Collections.IEnumerable]) {
        return '[' + ((@($Value | ForEach-Object { ConvertTo-Canonical $_ })) -join ',') + ']'
    }
    if ($Value -is [pscustomobject]) {
        $fields = @{}
        foreach ($property in $Value.PSObject.Properties) { $fields[$property.Name] = $property.Value }
        return ConvertTo-Canonical $fields
    }
    return [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
}
function New-Assignment($Body, [int]$Version = 1) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $digest = -join ($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Canonical $Body))) | ForEach-Object { $_.ToString('x2') }) }
    finally { $sha.Dispose() }
    return [ordered]@{ vdom='Default'; version=$Version; digest=$digest; body=$Body }
}
function Empty-Body {
    return @{ web_filter=@{ blocked=@() }; app_control=@{ blocked=@(); execution_rules=@(); network_blocked=@() }; usb_control=@{ default_action='allow'; rules=@() } }
}
function Get-Sha256([string]$Path) {
    $hash=[Security.Cryptography.SHA256]::Create()
    $stream=[IO.File]::OpenRead($Path)
    try { return -join ($hash.ComputeHash($stream) | ForEach-Object { $_.ToString('x2') }) }
    finally { $stream.Dispose(); $hash.Dispose() }
}
$baselinePolicy = New-Assignment (Empty-Body)
$usbBody = Empty-Body
$usbBody.usb_control.default_action = 'block'
$usbPolicy = New-Assignment $usbBody
$appBody = Empty-Body
$appBody.app_control.execution_rules = @(@{ id='fixture-hash'; kind='hash'; value=('00' * 32); sample_path='C:\openems-controls-fixture.exe' })
$appPolicy = New-Assignment $appBody
$scenarios = if ($Kind -eq 'USB') {
    @('production installation sends a real inventory; default storage block never changes HID status',
      'cached storage policy is applied again after an offline service restart',
      'physical VM: allow a selected USB by VID, PID and serial, then block its instance',
      'physical VM: read-only permits reading and refuses writing to an owned canary file',
      'physical VM: blocked and read-only events reach the server; release and removal restore the device')
} else {
    @('production installation reports a running fixture in the application inventory',
      'network denied fixture still starts but cannot connect while the control copy can',
      'hash denial prevents execution before the sentinel is written, including a renamed copy',
      'publisher denial prevents a separately signed fixture and renamed copy from executing',
      'policy release and removal restore execution and preserve unrelated firewall and WDAC policies')
}
if ($Plan) {
    @{ kind=$Kind; package=$package; report=$reportName; origin=$origin; scenarios=$scenarios
       policies=@($baselinePolicy, $(if ($Kind -eq 'USB') { $usbPolicy } else { $appPolicy }))
       physical_acceptance_required=($Kind -eq 'USB'); timeout_seconds=$totalTimeout
       vm_marker=@{ path=$markerPath; exact_text=$markerText }; mutates_host=$false } | ConvertTo-Json -Depth 20
    exit 0
}

# This gate precedes every write, task creation, package installation and certificate operation.
$executionService = Get-Service -Name CExecSvc -ErrorAction SilentlyContinue
$sandbox = (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -and $null -ne $executionService -and $executionService.Status -eq 'Running'
$attestedVm = $false
if ($DisposableVm -and (Test-Path -LiteralPath $markerPath -PathType Leaf)) {
    $machine = Get-CimInstance Win32_ComputerSystem
    $virtualModel = ($machine.Model -match 'Virtual Machine|VirtualBox|VMware|KVM|QEMU')
    $attestedVm = $machine.HypervisorPresent -and $virtualModel -and ([IO.File]::ReadAllText($markerPath).Trim() -ceq $markerText)
}
if (-not $sandbox -and -not $attestedVm) { throw 'This acceptance requires Windows Sandbox or an explicitly attested disposable VM.' }
if ($PhysicalDrive -and (-not $attestedVm -or $Kind -ne 'USB')) { throw 'Physical USB acceptance requires an attested disposable VM and Kind USB.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Acceptance requires Administrator rights inside the disposable guest.' }
$inputManifestPath=Join-Path $PSScriptRoot 'acceptance-manifest.json'
$inputManifest=$null
if (Test-Path -LiteralPath $inputManifestPath) {
    $inputManifest=Get-Content -LiteralPath $inputManifestPath -Raw | ConvertFrom-Json
    if ($inputManifest.phase -ne $Kind.ToLowerInvariant()) { throw 'This manifest belongs to a different controls phase.' }
    $names=if ($SystemPhase) { @($package, 'test-controls-sandbox.ps1') } else { @($inputManifest.files.PSObject.Properties | ForEach-Object Name) }
    foreach ($name in $names) {
        if ([IO.Path]::GetFileName($name) -ne $name) { throw 'Manifest entries must be plain file names.' }
        $entry=$inputManifest.files.PSObject.Properties[$name]
        $path=Join-Path $PSScriptRoot $name
        if ($null -eq $entry -or -not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Sha256 $path) -ne $entry.Value.sha256) { throw ('Current acceptance input is missing or modified: ' + $name) }
    }
}
function Write-Json([string]$Path, $Value) {
    $temporary = $Path + '.tmp'
    $Value | ConvertTo-Json -Depth 24 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
if (-not $SystemPhase) {
    try { [IO.File]::Open(('C:\openems-' + $Kind.ToLowerInvariant() + '-acceptance.lock'), 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'This guest already started this acceptance. Use a fresh guest or restore its clean snapshot.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Use a fresh guest without an existing openems installation.' }
    $work = Join-Path 'C:\' ('openems-controls-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work
    $script = Join-Path $work 'test-controls-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    $manifestPath = Join-Path $PSScriptRoot 'acceptance-manifest.json'
    if (Test-Path -LiteralPath $manifestPath) { Copy-Item -LiteralPath $manifestPath -Destination $work }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsControls-' + [Guid]::NewGuid().ToString('N')
    try {
        $extra = if ($DisposableVm) { ' -DisposableVm' } else { '' }
        if ($PhysicalDrive) { $extra += ' -PhysicalDrive ' + $PhysicalDrive }
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -Kind ' + $Kind + ' -OutputDirectory "' + $work + '"' + $extra)
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $resultPath = Join-Path $work $reportName
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        $printed = 0
        while ($true) {
            if ([DateTime]::UtcNow -ge $deadline) { throw ('Acceptance timed out; discard the guest. Partial evidence: ' + $resultPath) }
            $outcome = $null
            if (Test-Path -LiteralPath $resultPath) {
                try { $outcome = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json } catch { }
            }
            if ($null -ne $outcome) {
                Write-Json (Join-Path $OutputDirectory $reportName) $outcome
                if (@($outcome.checks).Count -gt $printed) {
                    $outcome.checks | Select-Object -Skip $printed | ForEach-Object { Write-Host ($_.status + ': ' + $_.name) }
                    $printed = @($outcome.checks).Count
                }
                if ($outcome.status -ne 'running') { break }
            }
            Start-Sleep -Milliseconds 500
        }
        $outcome | ConvertTo-Json -Depth 24 | Write-Output
        if ($outcome.passed) { exit 0 }
        if ($outcome.status -eq 'manual_required') { Write-Host 'Automation finished; manual or hardware acceptance remains. Read pending in the JSON.'; exit 2 }
        throw 'Controls acceptance failed. Evidence and logs remain in the disposable guest.'
    } finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue }
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$work = $PSScriptRoot
$resultPath = Join-Path $OutputDirectory $reportName
$result = [ordered]@{ kind=$Kind; passed=$false; automation_passed=$false; physical_acceptance_pending=($Kind -eq 'USB')
    status='running'; checks=@(); pending=@(); error=$null; cleanup_errors=@(); started_utc=[DateTime]::UtcNow.ToString('o'); package_receipt=$null }
if ($null -ne $inputManifest) {
    $result.package_receipt=@{ source_revision=$inputManifest.source_revision; packages=$inputManifest.packages; checked_at=[DateTime]::UtcNow.ToString('o') }
}
$backend = $null
$installed = $false
$certificate = $null
$canary = $null
$inventoryProcess = $null
$version = 1
$policyFile = Join-Path $work 'policy.json'
$agent = 'C:\Program Files\openems\openems-agent.exe'
$state = 'C:\ProgramData\openems\state.json'
$board = 'C:\ProgramData\openems\session.json'
function Record-Check([string]$Name) {
    $result.checks += @{ name=$Name; status='passed'; at=[DateTime]::UtcNow.ToString('o') }
    Write-Json $resultPath $result
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Message) {
    $until = [DateTime]::UtcNow.AddSeconds($Seconds)
    while ([DateTime]::UtcNow -lt $until) { if (& $Condition) { return }; Start-Sleep -Milliseconds 300 }
    throw $Message
}
function Read-Rows([string]$Name) {
    $path = Join-Path $work $Name
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try {
        $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
        try { $text = (New-Object IO.StreamReader($stream)).ReadToEnd() } finally { $stream.Dispose() }
        return @($text -split "`r?`n" | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
    } catch { return @() }
}
function Publish-Body($Body) {
    $script:version += 1
    $assignment = New-Assignment $Body $script:version
    Write-Json $policyFile $assignment
    return $assignment
}
function Wait-Ack($Assignment) {
    Wait-Until { @(Read-Rows 'ack.log' | Where-Object { $_.version -eq $Assignment.version -and $_.digest -eq $Assignment.digest -and $_.success }).Count -gt 0 } 90 'The service did not successfully apply and ACK this control policy. Inspect agent.log; reboot or an unsupported capability is not a pass.'
}
function Assert-ProductionPackage([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
    $query = $database.OpenView('SELECT `Action` FROM `CustomAction`')
    $query.Execute()
    while ($null -ne ($row = $query.Fetch())) {
        if ($row.StringData(1) -in @('InjectSetupFailure', 'InjectRemovalFailure')) { throw 'A fault-injection MSI is not a production acceptance package.' }
    }
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($query)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($database)
    [void][Runtime.InteropServices.Marshal]::ReleaseComObject($installer)
}
function Invoke-Msi([bool]$Remove) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.msi.log')
    $start.Arguments = $operation + ' "' + (Join-Path $work $package) + '" /qn /norestart /l*v "' + $log + '"'
    if (-not $Remove) { $start.Arguments += ' SERVER=' + $origin + ' INVITATION=sandbox-controls DEVID=sandbox-controls' }
    $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(240000)) { throw 'MSI operation timed out. Discard the guest.' }
        if ($process.ExitCode -ne 0) { throw ('MSI returned ' + $process.ExitCode + '; log ' + $log + '. Reboot-required is not accepted silently.') }
    } finally { $process.Dispose() }
}
function Start-Backend {
    $ready = Join-Path $work 'backend-ready'
    Remove-Item -LiteralPath $ready -ErrorAction SilentlyContinue
    $job = Start-Job -ArgumentList $origin, $work -ScriptBlock {
        param($Origin, $Work)
        $ErrorActionPreference = 'Stop'
        $listener = New-Object Net.HttpListener
        $listener.Prefixes.Add($Origin + '/')
        try {
            $listener.Start(); Set-Content -LiteralPath (Join-Path $Work 'backend-ready') -Value ready
            while ($true) {
                $waiting = $listener.GetContextAsync()
                while (-not $waiting.Wait(500)) { }
                $context = $waiting.Result
                $reader = New-Object IO.StreamReader($context.Request.InputStream, [Text.Encoding]::UTF8)
                try { $upload = $reader.ReadToEnd() } finally { $reader.Dispose() }
                $route = $context.Request.Url.AbsolutePath.Replace('/fct/api/public/v1/', '').Trim('/')
                $answer = @{}; $context.Response.StatusCode = 200
                if ($route -ne 'register' -and $context.Request.Headers['Authorization'] -ne 'Bearer sandbox-fixture-only') {
                    $context.Response.StatusCode = 403
                } else { switch ($route) {
                    'register' { $answer = @{ client_id='sandbox-controls'; device_token='sandbox-fixture-only' } }
                    'config/assigned' { $answer = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json }
                    'config/ack' { Add-Content -LiteralPath (Join-Path $Work 'ack.log') -Value ($upload -replace "`r?`n", ' ') }
                    'inventory' { Add-Content -LiteralPath (Join-Path $Work 'inventory.log') -Value ($upload -replace "`r?`n", ' '); $answer=@{accepted=$true} }
                    'control_events' { Add-Content -LiteralPath (Join-Path $Work 'control-events.log') -Value ($upload -replace "`r?`n", ' '); $answer=@{accepted=1;rejected=0} }
                    'host_tags' { }
                    'messages/pull' { }
                    'refresh' { }
                    'events' { $answer=@{accepted=0;rejected=0} }
                    'tamper' { $answer=@{accepted=0;rejected=0} }
                    default { $context.Response.StatusCode = 404 }
                } }
                $bytes = [Text.Encoding]::UTF8.GetBytes(($answer | ConvertTo-Json -Depth 24 -Compress))
                $context.Response.ContentType='application/json'; $context.Response.ContentLength64=$bytes.Length
                try { $context.Response.OutputStream.Write($bytes,0,$bytes.Length) } finally { $context.Response.Close() }
            }
        } finally { $listener.Close() }
    }
    Wait-Until { if ($job.State -eq 'Failed') { throw 'Fixture backend failed.' }; Test-Path -LiteralPath $ready } 20 'Fixture backend did not start.'
    return $job
}
function Stop-Backend {
    if ($null -ne $script:backend) {
        Stop-Job $script:backend -ErrorAction Stop
        Remove-Job $script:backend -Force -ErrorAction Stop
        $script:backend = $null
    }
}
function Hid-Snapshot {
    return @(Get-PnpDevice -Class Keyboard, Mouse, HIDClass -ErrorAction SilentlyContinue | Select-Object InstanceId, Status)
}
function Assert-HidUnchanged($Before) {
    $after = @(Hid-Snapshot)
    foreach ($device in @($Before | Where-Object Status -EQ 'OK')) {
        if (@($after | Where-Object { $_.InstanceId -eq $device.InstanceId -and $_.Status -eq 'OK' }).Count -ne 1) { throw 'A keyboard, mouse or HID device lost its healthy state.' }
    }
}
function Firewall-Snapshot {
    return @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object Group -NE $applicationGroup | Select-Object Name, Enabled, Direction, Action)
}
function Assert-FirewallPreserved($Before) {
    $after = @(Firewall-Snapshot)
    foreach ($rule in $Before) {
        $match = @($after | Where-Object Name -EQ $rule.Name)
        if ($match.Count -ne 1 -or $match[0].Enabled -ne $rule.Enabled -or $match[0].Direction -ne $rule.Direction -or $match[0].Action -ne $rule.Action) { throw 'An unrelated firewall rule changed.' }
    }
}
function Code-Policies {
    if (-not (Get-Command CiTool.exe -ErrorAction SilentlyContinue)) { throw 'CiTool is unavailable in this guest.' }
    $raw = & CiTool.exe --list-policies -json
    if ($LASTEXITCODE -ne 0) { throw 'Could not list Code Integrity policies.' }
    $listing = $raw | ConvertFrom-Json
    return @($listing.Policies | ForEach-Object PolicyID)
}
function Get-ExecutionBaseline {
    param([string]$ControlKind)
    if ($ControlKind -ne 'Applications') { return @{ available=$false; policies=@(); reason='Not required for USB acceptance.' } }
    try { return @{ available=$true; policies=@(Code-Policies); reason='' } }
    catch { return @{ available=$false; policies=@(); reason=$_.Exception.Message } }
}
function New-Fixture([string]$Path) {
    $typeName = 'OpenemsFixture' + [Guid]::NewGuid().ToString('N')
    $code = @'
using System;
using System.IO;
using System.Net;
using System.Threading;
public static class PLACEHOLDER {
    public static int Main(string[] args) {
        try {
            File.WriteAllText(args[0], "started");
            if (args.Length > 1 && args[1] != "-") {
                ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;
                var request = WebRequest.Create(args[1]); request.Timeout = 8000;
                using (var response = request.GetResponse()) { }
            }
            if (args.Length > 2) Thread.Sleep(Int32.Parse(args[2]));
            return 0;
        } catch (Exception error) { Console.Error.WriteLine(error.GetType().Name); return 31; }
    }
}
'@
    Add-Type -TypeDefinition ($code.Replace('PLACEHOLDER', $typeName)) -OutputAssembly $Path -OutputType ConsoleApplication
}
function Invoke-Fixture([string]$Path, [string]$Sentinel, [string]$Url = '-') {
    Remove-Item -LiteralPath $Sentinel -ErrorAction SilentlyContinue
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Path; $start.Arguments='"' + $Sentinel + '" "' + $Url + '"'; $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    try { $process = [Diagnostics.Process]::Start($start) }
    catch [ComponentModel.Win32Exception] { return @{ exit=-1; native_error=$_.Exception.NativeErrorCode; started=$false } }
    try {
        if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Fixture process timed out.' }
        return @{ exit=$process.ExitCode; native_error=0; started=(Test-Path -LiteralPath $Sentinel) }
    } finally { $process.Dispose() }
}
function Assert-ExecutionDenied([string]$Path) {
    $sentinel = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.started')
    $observed = Invoke-Fixture $Path $sentinel
    if ($observed.started -or $observed.native_error -notin @(577,1260)) {
        throw ('Expected a Windows policy refusal before execution; observed ' + ($observed | ConvertTo-Json -Compress))
    }
}
function Get-UsbDevice([string]$Drive) {
    $rows = @(Read-Rows 'inventory.log')
    if ($rows.Count -eq 0) { return $null }
    $matches = @($rows[-1].usb_devices | Where-Object { $_.present -and @($_.drive_letters) -contains $Drive } | Select-Object -First 1)
    if ($matches.Count -eq 0) { return $null }
    return $matches[0]
}
function Assert-WriteDenied([string]$Path) {
    $denied = $false
    try { [IO.File]::AppendAllText($Path, 'should-not-be-written') } catch [UnauthorizedAccessException] { $denied=$true } catch [IO.IOException] { $denied=$true }
    if (-not $denied) { throw 'The read-only policy allowed a write.' }
}
Write-Json $resultPath $result
try {
    Assert-ProductionPackage ([string](Join-Path $work $package))
    $hidBefore = @(Hid-Snapshot)
    $firewallBefore = @(Firewall-Snapshot)
    $executionBaseline = Get-ExecutionBaseline $Kind
    $codeBefore = @($executionBaseline.policies)
    if ($Kind -eq 'Applications' -and -not $executionBaseline.available) {
        $result.pending += ('Execution acceptance requires working Code Integrity policy enumeration in a supported disposable VM: ' + $executionBaseline.reason)
    }
    $hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsBefore = Get-Sha256 $hosts
    Write-Json $policyFile $baselinePolicy
    if ($Kind -eq 'Applications') {
        # Inventory uploads are deliberately infrequent. Keep this process present before service start.
        $fixture = Join-Path $work 'OpenemsFixture.exe'
        $renamed = Join-Path $work 'RenamedFixture.exe'
        New-Fixture $fixture
        Copy-Item -LiteralPath $fixture -Destination $renamed
        $start = New-Object Diagnostics.ProcessStartInfo
        $start.FileName=$fixture; $start.Arguments='"' + (Join-Path $work 'inventory-started') + '" - 360000'
        $start.UseShellExecute=$false; $start.CreateNoWindow=$true
        $inventoryProcess=[Diagnostics.Process]::Start($start)
    }
    $backend = Start-Backend
    Invoke-Msi $false; $installed=$true
    Wait-Ack $baselinePolicy
    Wait-Until { @(Read-Rows 'inventory.log').Count -gt 0 } 90 'The service did not upload an inventory.'
    Record-Check 'production MSI installed and an authenticated inventory was uploaded'
    if ($null -ne $inventoryProcess) {
        Wait-Until { @(Read-Rows 'inventory.log' | ForEach-Object applications | Where-Object { $_.path -eq $fixture -and $_.running -and $_.sha256 -match '^[0-9a-fA-F]{64}$' }).Count -gt 0 } 30 'The pre-existing running fixture was not inventoried with its path and SHA-256.'
        Record-Check 'the application inventory includes the running fixture with its path and SHA-256'
        if (-not $inventoryProcess.HasExited) { $inventoryProcess.Kill(); $inventoryProcess.WaitForExit() }
        $inventoryProcess.Dispose(); $inventoryProcess=$null
    }
    if ($Kind -eq 'USB') {
        Wait-Ack (Publish-Body $usbBody)
        Assert-HidUnchanged $hidBefore
        Record-Check 'storage block applied without disabling healthy keyboard, mouse or HID devices'
        Stop-Backend
        Restart-Service -Name openems-agent
        Wait-Until { (Get-Service openems-agent).Status -eq 'Running' } 30 'Service did not restart offline.'
        Start-Sleep -Seconds 18
        $cached = Get-Content -LiteralPath $state -Raw | ConvertFrom-Json
        if ($cached.profile.body.usb_control.default_action -ne 'block') { throw 'Offline cache lost the storage block policy.' }
        Assert-HidUnchanged $hidBefore
        Record-Check 'offline restart retained the storage policy and healthy HID devices'
        $backend = Start-Backend
        Wait-Ack (Publish-Body (Empty-Body))
        if ($PhysicalDrive) {
            $PhysicalDrive = $PhysicalDrive.ToUpperInvariant()
            $device = Get-UsbDevice $PhysicalDrive
            if ($null -eq $device -or -not $device.instance_id -or -not $device.serial -or -not $device.vid -or -not $device.pid) { throw 'Select a reported physical USB storage device with VID, PID and serial.' }
            $partition = Get-Partition -DriveLetter $PhysicalDrive.Substring(0,1)
            $disk = Get-Disk -Number $partition.DiskNumber
            if ($disk.BusType -ne 'USB' -or $disk.IsBoot -or $disk.IsSystem) { throw 'The selected drive is not non-system physical USB storage.' }
            $canary = Join-Path ($PhysicalDrive + '\') ('.openems-acceptance-' + [Guid]::NewGuid().ToString('N') + '.txt')
            [IO.File]::WriteAllText($canary, 'openems-owned-canary')
            $body = Empty-Body
            $body.usb_control=@{ default_action='block'; rules=@(@{id='allow-fixture';action='allow';class='storage';vid=$device.vid;pid=$device.pid;serial=$device.serial}) }
            Wait-Ack (Publish-Body $body)
            if ([IO.File]::ReadAllText($canary) -ne 'openems-owned-canary') { throw 'The selected allow exception did not preserve access.' }
            Record-Check 'physical USB allowed by matching VID, PID and serial'
            $body.usb_control=@{default_action='allow';rules=@(@{id='block-fixture';action='block';instance_id=$device.instance_id})}
            Wait-Ack (Publish-Body $body)
            Wait-Until { -not (Test-Path -LiteralPath $canary) } 45 'The selected USB instance remained accessible while blocked.'
            Record-Check 'physical USB instance block prevented access'
            Wait-Ack (Publish-Body (Empty-Body))
            Write-Output 'If the drive does not return, reinsert the selected test USB now.'
            Wait-Until { Test-Path -LiteralPath $canary } 180 'The physical device did not return after release; replug and inspect the guest.'
            $body = Empty-Body
            $body.usb_control=@{default_action='allow';rules=@(@{id='read-only-fixture';action='read_only';instance_id=$device.instance_id})}
            Wait-Ack (Publish-Body $body)
            if ([IO.File]::ReadAllText($canary) -ne 'openems-owned-canary') { throw 'Read-only prevented reading or changed the canary.' }
            Assert-WriteDenied $canary
            Record-Check 'physical read-only policy allowed reading and refused writing'
            Wait-Until { @(Read-Rows 'control-events.log' | ForEach-Object events | Where-Object { $_.kind -eq 'usb_block' }).Count -gt 0 } 60 'A USB block event was not uploaded.'
            Record-Check 'physical USB control event reached the server'
            Wait-Ack (Publish-Body (Empty-Body))
            [IO.File]::AppendAllText($canary, '-released')
            Remove-Item -LiteralPath $canary; $canary=$null
            $result.physical_acceptance_pending=$false
        } else {
            $result.pending += 'Physical USB allow/block/read-only and device replug require an attested disposable Windows VM with USB passthrough. Shared folders are not USB evidence.'
        }
    } else {
        $sentinel = Join-Path $work 'network-started'
        $controlSentinel = Join-Path $work 'control-started'
        $url = 'https://example.org/'
        $baseline = Invoke-Fixture $fixture $sentinel $url
        $control = Invoke-Fixture $renamed $controlSentinel $url
        if ($baseline.exit -ne 0 -or $control.exit -ne 0) { throw 'The external network fixture is not reachable before policy. Retry in a guest with working Internet.' }
        Record-Check 'both independent fixture paths start and reach the external network before policy'
        $body = Empty-Body
        $body.app_control.network_blocked=@($fixture)
        Wait-Ack (Publish-Body $body)
        $denied = Invoke-Fixture $fixture $sentinel $url
        $control = Invoke-Fixture $renamed $controlSentinel $url
        if (-not $denied.started -or $denied.exit -eq 0 -or $control.exit -ne 0) { throw 'App network policy did not isolate the selected path while preserving process launch and the control copy.' }
        Record-Check 'network block kept the selected app runnable while its connection failed and the control copy connected'
        Wait-Ack (Publish-Body (Empty-Body))
        if ((Invoke-Fixture $fixture $sentinel $url).exit -ne 0) { throw 'Removing network policy did not restore connectivity.' }
        Record-Check 'network policy release restored the selected app connection'
        if (-not $executionBaseline.available -or @(Get-Module -ListAvailable ConfigCI).Count -eq 0) {
            $result.pending += 'This guest has no supported CiTool/ConfigCI. Repeat execution acceptance on a supported disposable Windows 11 VM; network acceptance alone is not WDAC acceptance.'
        } else {
            $body = Empty-Body
            $body.app_control.execution_rules=@(@{id='deny-hash';kind='hash';value=(Get-Sha256 $fixture);sample_path=$fixture})
            Wait-Ack (Publish-Body $body)
            Assert-ExecutionDenied $fixture
            Assert-ExecutionDenied $renamed
            Record-Check 'WDAC denied the original hash and renamed copy before their first instruction wrote a sentinel'
            Wait-Ack (Publish-Body (Empty-Body))
            if ((Invoke-Fixture $fixture $sentinel).exit -ne 0) { throw 'Execution did not return after hash policy release.' }
            $publisherFixture = Join-Path $work 'PublisherFixture.exe'
            $publisherCopy = Join-Path $work 'PublisherRenamed.exe'
            New-Fixture $publisherFixture
            $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=Openems Acceptance Fixture' -CertStoreLocation Cert:\LocalMachine\My
            $publicCertificate = Join-Path $work 'fixture.cer'
            Export-Certificate -Cert $certificate -FilePath $publicCertificate | Out-Null
            Import-Certificate -FilePath $publicCertificate -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
            Import-Certificate -FilePath $publicCertificate -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
            $signature = Set-AuthenticodeSignature -LiteralPath $publisherFixture -Certificate $certificate
            if ($signature.Status -ne 'Valid') { throw 'The dedicated fixture signing certificate was not trusted in this guest.' }
            Copy-Item -LiteralPath $publisherFixture -Destination $publisherCopy
            if ((Invoke-Fixture $publisherFixture $sentinel).exit -ne 0) { throw 'The signed fixture did not run before publisher policy.' }
            $body.app_control.execution_rules=@(@{id='deny-publisher';kind='publisher';value=$certificate.Subject;sample_path=$publisherFixture})
            Wait-Ack (Publish-Body $body)
            Assert-ExecutionDenied $publisherFixture
            Assert-ExecutionDenied $publisherCopy
            Record-Check 'WDAC denied only the dedicated test publisher including a renamed signed copy'
            Wait-Ack (Publish-Body (Empty-Body))
            if ((Invoke-Fixture $publisherCopy $sentinel).exit -ne 0) { throw 'Publisher release did not restore execution.' }
            Record-Check 'publisher policy release restored execution'
        }
    }
    Wait-Ack (Publish-Body (Empty-Body))
    Invoke-Msi $true; $installed=$false
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Removal left the agent service.' }
    if (@(Get-NetFirewallRule -Group $applicationGroup -ErrorAction SilentlyContinue).Count -gt 0) { throw 'Removal left application firewall rules.' }
    Assert-FirewallPreserved $firewallBefore
    if ($executionBaseline.available) {
        $codeAfter = @(Code-Policies)
        if (@($codeBefore | Where-Object { $_ -notin $codeAfter }).Count -gt 0) { throw 'An unrelated Code Integrity policy was removed.' }
        if (@($codeAfter | Where-Object { $_ -notin $codeBefore }).Count -gt 0) { throw 'A Code Integrity policy remains after removal; reboot-required is pending, not passed.' }
        Record-Check 'Code Integrity policy ownership restored after removal'
    }
    Assert-HidUnchanged $hidBefore
    if ((Get-Sha256 $hosts) -ne $hostsBefore) { throw 'Removal did not restore hosts.' }
    Record-Check 'MSI removal restored owned controls and preserved unrelated firewall, HID and hosts state'
    $result.automation_passed=$true
    $result.passed=($result.pending.Count -eq 0 -and -not $result.physical_acceptance_pending)
    $result.status=if ($result.passed) { 'passed' } else { 'manual_required' }
} catch {
    $result.error=$_.Exception.Message
    $result.status='failed'
    if ($result.error -match 'reboot|restart.*required|not supported|unsupported') {
        $result.pending += 'Inspect the application-control journal and agent.log in this guest. A required reboot/capability prevents full acceptance; use the documented disposable VM procedure.'
    }
} finally {
    if ($null -ne $inventoryProcess) {
        try { if (-not $inventoryProcess.HasExited) { $inventoryProcess.Kill(); $inventoryProcess.WaitForExit() }; $inventoryProcess.Dispose() }
        catch { $result.cleanup_errors += 'The owned inventory fixture did not stop.' }
    }
    if (-not $installed -and $null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { $installed=$true }
    if ($installed) {
        try {
            if ($null -eq $backend) { $backend=Start-Backend }
            Wait-Ack (Publish-Body (Empty-Body))
            Invoke-Msi $true
        } catch { $result.cleanup_errors += $_.Exception.Message }
    }
    try { Stop-Backend } catch { $result.cleanup_errors += $_.Exception.Message }
    if ($null -ne $certificate) {
        foreach ($store in @('My','Root','TrustedPublisher')) {
            $path='Cert:\LocalMachine\' + $store + '\' + $certificate.Thumbprint
            try { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force } } catch { $result.cleanup_errors += $_.Exception.Message }
        }
    }
    if ($canary -and (Test-Path -LiteralPath $canary)) {
        try { Remove-Item -LiteralPath $canary } catch { $result.cleanup_errors += 'Owned USB canary could not be removed; discard the guest and inspect the test USB.' }
    }
    if ($result.cleanup_errors.Count -gt 0) { $result.passed=$false; $result.status='failed' }
    $result.finished_utc=[DateTime]::UtcNow.ToString('o')
    Write-Json $resultPath $result
}
if ($result.passed) { exit 0 }
if ($result.status -eq 'manual_required') { exit 2 }
exit 1
