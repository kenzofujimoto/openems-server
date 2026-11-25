param([string]$OutputDirectory = '\\vmware-host\Shared Folders\OpenEMSResults',
      [switch]$DisposableVm, [switch]$SystemPhase, [switch]$Plan)
# Production controls run only through the installed service in an attested disposable VM.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$timeoutSeconds = 5400
$reportName = 'catalog-result.json'
$markerPath = 'C:\openems-disposable-vm.txt'
$origin = 'http://127.0.0.1:18019'
$applicationGroup = 'openems application control'

function Field($Object, [string]$Name, $Default, [string]$Type = '') {
    $value = $Default
    if ($null -ne $Object) {
        if ($Object -is [Collections.IDictionary]) {
            if ($Object.Contains($Name)) { $value = $Object[$Name] }
        } else {
            $property = $Object.PSObject.Properties[$Name]
            if ($null -ne $property) { $value = $property.Value }
        }
    }
    # PowerShell equality coerces 0/1 and strings to booleans and numbers. Evidence must retain its JSON type.
    $integer = $value -is [byte] -or $value -is [sbyte] -or $value -is [int16] -or $value -is [uint16] -or
        $value -is [int32] -or $value -is [uint32] -or $value -is [int64] -or $value -is [uint64]
    if (($Type -eq 'boolean' -and $value -isnot [bool]) -or
        ($Type -eq 'integer' -and -not $integer) -or
        ($Type -eq 'number' -and -not ($integer -or $value -is [double] -or $value -is [single] -or $value -is [decimal])) -or
        ($Type -eq 'string' -and $value -isnot [string])) { throw ('Invalid evidence type: ' + $Name) }
    return $value
}
function Assert-DisposableGuest($Machine, [string]$MarkerText, [bool]$OptIn) {
    $hypervisor = Field $Machine 'HypervisorPresent' $false
    if (-not $OptIn -or $hypervisor -isnot [bool] -or -not $hypervisor -or
        [string](Field $Machine 'Model' '') -notmatch 'VMware|VirtualBox|Virtual Machine|KVM|QEMU' -or
        $MarkerText -cne 'OPENEMS DISPOSABLE USB ACCEPTANCE') {
        throw 'Catalog acceptance requires an explicitly attested disposable Windows VM.'
    }
}
function Assert-DeniedExecution($Observation) {
    if ((Field $Observation 'process_created' $null 'boolean') -ne $false -or
        (Field $Observation 'started' $null 'boolean') -ne $false -or
        (Field $Observation 'native_error' 0 'integer') -notin @(577,1260,4551) -or
        (Field $Observation 'exit' 0 'integer') -ne -1) {
        throw 'WDAC evidence must prove a native refusal before process creation and the first sentinel write.'
    }
}
function Assert-HourlyEvidence($Evidence) {
    $elapsed = Field $Evidence 'elapsed_seconds' $null 'number'
    if ($null -eq $elapsed -or $elapsed -isnot [ValueType] -or [double]::IsNaN([double]$elapsed) -or
        [double]::IsInfinity([double]$elapsed) -or [double]$elapsed -lt 3600) { throw 'The real monotonic hour is incomplete.' }
    $started = [DateTimeOffset]::Parse((Field $Evidence 'started_utc' '' 'string'))
    $finished = [DateTimeOffset]::Parse((Field $Evidence 'finished_utc' '' 'string'))
    if (($finished-$started).TotalSeconds -lt 3600) { throw 'The real UTC hour is incomplete.' }
    $before = Field $Evidence 'before' $null
    $after = Field $Evidence 'after' $null
    $version = Field $before 'version' 0 'integer'
    $digest = Field $before 'digest' '' 'string'
    if ($version -lt 1 -or $digest -cnotmatch '^[0-9a-f]{64}$' -or
        (Field $after 'version' 0 'integer') -ne $version -or (Field $after 'digest' '' 'string') -cne $digest) {
        throw 'The assignment changed during the hourly observation.'
    }
    $checkedBefore = [long](Field $before 'optional_checked_at' 0 'integer')
    $checkedAfter = [long](Field $after 'optional_checked_at' 0 'integer')
    if ($checkedBefore -le 0 -or $checkedBefore -lt ($started.ToUnixTimeSeconds()-120) -or
        $checkedBefore -gt $started.ToUnixTimeSeconds() -or $checkedAfter -lt ($checkedBefore+3600) -or
        $checkedAfter -gt $finished.ToUnixTimeSeconds()) { throw 'The natural optional-rule timestamps are inconsistent.' }
    $observations = @(Field $Evidence 'assignment_observations' @())
    if ($observations.Count -lt 2) { throw 'The assignment observation history is incomplete.' }
    foreach ($observation in $observations) {
        if ((Field $observation 'version' 0 'integer') -ne $version -or (Field $observation 'digest' '' 'string') -cne $digest) {
            throw 'An intervening policy push cannot prove local hourly revalidation.'
        }
    }
    $admission = Field $Evidence 'before_admission' $null
    if ((Field $admission 'process_created' $null 'boolean') -ne $true -or
        (Field $admission 'native_error' -1 'integer') -ne 0) { throw 'The later fixture was not admitted before the hour.' }
    Assert-DeniedExecution (Field $Evidence 'after_denial' $null)
}
function Assert-CatalogEvidence($Report, $Manifest) {
    $evidenceFormat = Field $Manifest 'evidence_format' 1 'integer'
    if ($evidenceFormat -notin @(1,2) -or (Field $Report 'evidence_format' 1 'integer') -ne $evidenceFormat) {
        throw 'The catalog evidence format does not match the input manifest.'
    }
    if ((Field $Report 'passed' $null 'boolean') -ne $true -or (Field $Report 'status' '' 'string') -cne 'passed' -or
        (Field $Report 'error' $null) -or @(Field $Report 'cleanup_errors' @()).Count -ne 0 -or
        (Field $Report 'run_id' '' 'string') -cne (Field $Manifest 'run_id' 'missing') -or
        (Field $Report 'source_revision' '' 'string') -cne (Field $Manifest 'source_revision' 'missing')) {
        throw 'The catalog report is incomplete, failed or belongs to another run.'
    }
    $receipt = Field $Report 'package_receipt' $null
    if ((Field $receipt 'source_revision' '' 'string') -cne $Manifest.source_revision -or
        (Field $receipt 'manifest_sha256' '' 'string') -cne (Field $Manifest '_manifest_sha256' 'missing')) {
        throw 'The catalog receipt does not identify this input manifest.'
    }
    $packages = Field $receipt 'packages' $null
    foreach ($package in $Manifest.packages.PSObject.Properties) {
        $received = Field $packages $package.Name $null
        if ((Field $received 'sha256' '' 'string') -cne $package.Value.sha256 -or
            (Field $received 'bytes' -1 'integer') -ne $package.Value.bytes) { throw 'The MSI receipt changed.' }
    }
    $required = @('absent','network','process','wdac','all_absent','hourly','release','cleanup')
    $checks = @(Field $Report 'checks' @())
    if ($checks.Count -ne $required.Count) { throw 'The required catalog evidence is incomplete.' }
    $evidence = @{}
    foreach ($name in $required) {
        $matches = @($checks | Where-Object { (Field $_ 'name' '') -ceq $name })
        if ($matches.Count -ne 1 -or (Field $matches[0] 'status' '') -cne 'passed') { throw 'A required catalog check is missing or failed.' }
        $evidence[$name] = Field $matches[0] 'evidence' $null
        if ($null -eq $evidence[$name]) { throw 'An evidence observation is missing.' }
    }
    foreach ($pair in @(@{check='absent'; policy='absent'}, @{check='all_absent'; policy='later'}, @{check='release'; policy='release'})) {
        $observed = $evidence[$pair.check]
        $expected = Field $Manifest.policies $pair.policy $null
        $assignment = Field $observed 'assignment' $null
        $ack = Field $observed 'ack' $null
        if ((Field $assignment 'version' 0 'integer') -ne $expected.version -or (Field $assignment 'digest' '' 'string') -cne $expected.digest -or
            (Field $ack 'version' 0 'integer') -ne $expected.version -or (Field $ack 'digest' '' 'string') -cne $expected.digest -or
            (Field $ack 'success' $null 'boolean') -ne $true -or (Field $observed 'own_policy_present' $null 'boolean') -ne $false) {
            throw 'Catalog policy delivery, ACK or owned-policy removal was not proved.'
        }
    }
    $network = $evidence.network
    foreach ($phase in @('before','released')) {
        $observation = Field $network $phase $null
        if ((Field $observation 'target_exit' -1 'integer') -ne 0 -or (Field $observation 'control_exit' -1 'integer') -ne 0) { throw 'Network baseline or release failed.' }
    }
    $blocked = Field $network 'blocked' $null
    $target = $Manifest.guest_work_directory + '\' + $Manifest.fixtures.a.file
    $paths = @(Field $network 'firewall_paths' @())
    if ((Field $blocked 'target_process_created' $null 'boolean') -ne $true -or
        (Field $blocked 'target_exit' -1 'integer') -ne 42 -or (Field $blocked 'control_exit' -1 'integer') -ne 0 -or
        (Field $network 'control_has_rule' $null 'boolean') -ne $false -or $paths.Count -ne 2 -or
        @($paths | Where-Object { $_ -ine $target }).Count -ne 0) { throw 'Firewall isolation was not independently proved.' }
    $process = $evidence.process
    if ((Field $process 'target_was_running' $null 'boolean') -ne $true -or (Field $process 'target_exited' $null 'boolean') -ne $true -or
        (Field $process 'control_still_running' $null 'boolean') -ne $true -or (Field $process 'target_pid' 0 'integer') -le 0 -or
        (Field $process 'control_pid' 0 'integer') -le 0 -or $process.target_pid -eq $process.control_pid) { throw 'Process termination or its independent control failed.' }
    if ((Field $evidence.wdac 'policy_enforced' $null 'boolean') -ne $true) { throw 'The owned WDAC policy is not enforced.' }
    Assert-DeniedExecution (Field $evidence.wdac 'original' $null)
    Assert-DeniedExecution (Field $evidence.wdac 'renamed' $null)
    foreach ($name in @('all_absent','cleanup')) {
        $before = @(Field $evidence[$name] 'foreign_before' $null)
        $after = @(Field $evidence[$name] 'foreign_after' $null)
        if ($before.Count -ne $after.Count -or @($before | Where-Object { $_ -notin $after }).Count -ne 0) { throw 'Foreign Code Integrity policies changed.' }
    }
    Assert-HourlyEvidence $evidence.hourly
    if ($evidence.hourly.before.version -ne $Manifest.policies.later.version -or
        $evidence.hourly.before.digest -cne $Manifest.policies.later.digest) { throw 'Hourly evidence belongs to another policy.' }
    if ((Field $evidence.release 'original_exit' -1 'integer') -ne 0 -or (Field $evidence.release 'renamed_exit' -1 'integer') -ne 0 -or
        (Field $evidence.release 'firewall_rule_count' -1 'integer') -ne 0) { throw 'Policy release did not restore both executables.' }
    $cleanup = $evidence.cleanup
    if ((Field $cleanup 'msi_exit' -1 'integer') -ne 0 -or (Field $cleanup 'service_present' $null 'boolean') -ne $false -or
        (Field $cleanup 'watchdog_present' $null 'boolean') -ne $false -or (Field $cleanup 'nrpt_count' -1 'integer') -ne 0 -or
        (Field $cleanup 'owned_firewall_rules' -1 'integer') -ne 0 -or (Field $cleanup 'own_policy_present' $null 'boolean') -ne $false -or
        (Field $cleanup 'fixture_registry_present' $null 'boolean') -ne $false) { throw 'Normal MSI removal or cleanup is incomplete.' }
    if ($evidenceFormat -eq 2) {
        if ((Field $cleanup 'collection_status' '' 'string') -cne 'complete' -or
            @(Field $cleanup 'collection_errors' 'missing').Count -ne 0) { throw 'The cleanup observations are incomplete.' }
        $firewall = Field $cleanup 'firewall' $null
        $before = Field $firewall 'before' $null
        $after = Field $firewall 'after' $null
        $comparison = Compare-FirewallSnapshots $before $after
        if (-not $comparison.preserved -or (Field $firewall 'preserved' $null 'boolean') -ne $true) {
            throw 'An unrelated firewall rule changed or its snapshot is incomplete.'
        }
        $persistedBefore = Field $Report 'firewall_before' $null
        foreach ($property in @('status','at_utc','observed_count','error','truncated')) {
            $expected = Field $before $property $null
            $type = switch ($property) { 'observed_count' { 'integer' } 'truncated' { 'boolean' } 'error' { '' } default { 'string' } }
            if ((Field $persistedBefore $property 'missing' $type) -cne $expected) {
                throw 'The cleanup baseline differs from the persisted preinstallation snapshot.'
            }
        }
        $persistedRules = @(Field $persistedBefore 'rules' 'missing')
        $baselineRules = @(Field $before 'rules' @())
        if ($persistedRules.Count -ne $baselineRules.Count) { throw 'The persisted firewall baseline rule count changed.' }
        for ($index=0; $index -lt $baselineRules.Count; $index++) {
            foreach ($property in @('name','enabled','direction','action')) {
                if ((Field $persistedRules[$index] $property '' 'string') -cne (Field $baselineRules[$index] $property '' 'string')) {
                    throw 'The persisted firewall baseline rule changed.'
                }
            }
        }
        $differences = @(Field $firewall 'differences' 'missing')
        if ($differences.Count -ne $comparison.differences.Count) { throw 'The firewall difference list is inconsistent.' }
        for ($index=0; $index -lt $differences.Count; $index++) {
            $expected = $comparison.differences[$index]
            $observed = $differences[$index]
            if ((Field $observed 'name' '' 'string') -cne $expected.name -or
                (Field $observed 'kind' '' 'string') -cne $expected.kind -or
                @(Field $observed 'fields' 'missing').Count -ne 0) { throw 'The observed firewall difference changed.' }
        }
        $knownAssignments = @{}
        foreach ($name in @('allow','absent','network','network_release','present','later','release')) {
            $assignment = Field $Manifest.policies $name $null
            $knownAssignments[(Field $assignment 'version' 0 'integer')] = Field $assignment 'digest' '' 'string'
        }
        $positiveAcks = @{}
        foreach ($ack in @(Field $Report 'ack_observations' @())) {
            $keys = if ($ack -is [Collections.IDictionary]) { @($ack.Keys) } else { @($ack.PSObject.Properties | ForEach-Object Name) }
            $version = Field $ack 'version' 0 'integer'
            $digest = Field $ack 'digest' '' 'string'
            $success = Field $ack 'success' $null 'boolean'
            $at = Field $ack 'at_utc' '' 'string'
            $kind = Field $ack 'error_kind' 'missing'
            if ($keys.Count -ne 5 -or @($keys | Where-Object { $_ -cnotin @('version','digest','success','at_utc','error_kind') }).Count -ne 0 -or
                -not $knownAssignments.ContainsKey($version) -or $knownAssignments[$version] -cne $digest -or $digest -cnotmatch '^[0-9a-f]{64}$' -or
                $at -cnotmatch '(Z|[+-][0-9]{2}:[0-9]{2})$') { throw 'The catalog ACK observation is invalid.' }
            $null = [DateTimeOffset]::Parse($at)
            if ($success) {
                if ($null -ne $kind) { throw 'A successful ACK carried a failure category.' }
                $positiveAcks[$version] = $true
            } elseif ($kind -isnot [string] -or $kind -cnotin @('ConfigError','PolicyError','StateError','HTTPError','TransportError','LocalError','OSError','unknown')) {
                throw 'The negative ACK category is invalid.'
            }
        }
        if ($positiveAcks.Count -ne 7) { throw 'The catalog ACK history does not prove every assignment succeeded.' }
    }
}
function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
}
function Write-Report([string]$Path, $Value, [switch]$SharedFolder, [switch]$LocalCheckpoint) {
    $temporary = $Path + '.tmp'
    try {
        $Value | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $temporary -Encoding UTF8
        if ($SharedFolder) { Copy-Item -LiteralPath $temporary -Destination $Path -Force }
        elseif ($LocalCheckpoint) {
            # The private checkpoint has one writer. A reader may still hold the previous version.
            try { [IO.File]::Replace($temporary, $Path, [NullString]::Value) }
            catch [IO.FileNotFoundException] { [IO.File]::Move($temporary, $Path) }
        }
        else { Move-Item -LiteralPath $temporary -Destination $Path -Force }
    } finally {
        if ($LocalCheckpoint) { [IO.File]::Delete($temporary) }
        elseif (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
function Read-SnapshotText([string]$Path, [int]$MaximumBytes=4194304) {
    # Read one immutable version while allowing its owner to replace the pathname.
    $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, $share)
    try {
        $length = $stream.Length
        if ($length -gt $MaximumBytes) { throw 'The catalog snapshot exceeds its size limit.' }
        $reader = [IO.BinaryReader]::new($stream)
        $bytes = $reader.ReadBytes([int]$length)
        if ($bytes.Length -ne $length) { throw [IO.IOException]::new('The catalog snapshot ended during reading.') }
    } finally { $stream.Dispose() }
    return [Text.UTF8Encoding]::new($false, $true).GetString($bytes).TrimStart([char]0xFEFF)
}
function Read-CatalogJson([string]$Path, [switch]$AllowMissing) {
    for ($attempt=1; $attempt -le 5; $attempt++) {
        try { $text = Read-SnapshotText $Path; break }
        catch [IO.FileNotFoundException], [IO.DirectoryNotFoundException] {
            if ($attempt -eq 5) {
                if ($AllowMissing) { return $null }
                throw
            }
        }
        catch [IO.IOException], [UnauthorizedAccessException] {
            if ($attempt -eq 5) { throw }
        }
        Start-Sleep -Milliseconds 100
    }
    $snapshot = $text | ConvertFrom-Json
    if ($snapshot -isnot [pscustomobject]) { throw 'The catalog snapshot must contain a JSON object.' }
    return $snapshot
}
function Remove-CatalogTaskIfInactive([string]$TaskName) {
    for ($attempt=0; $attempt -lt 20; $attempt++) {
        try { $task = Get-ScheduledTask -TaskName $TaskName -TaskPath '\' -ErrorAction Stop }
        catch { Write-Warning 'Catalog worker state could not be verified. The task was retained.'; return }
        if ($null -ne $task -and [string]$task.State -ceq 'Ready') {
            Unregister-ScheduledTask -TaskName $TaskName -TaskPath '\' -Confirm:$false -ErrorAction Continue
            return
        }
        Start-Sleep -Milliseconds 250
    }
    Write-Warning 'Catalog worker was not observed inactive. The task was retained.'
}
function Observe-CatalogTask([string]$ResultPath, [string]$SharedPath, $Manifest, [string]$TaskName, [int]$Seconds) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $lastPrinted = ''
    $lastExported = $null
    $readErrors = 0
    while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
        # The report can carry three copies of a large firewall snapshot.
        try { $checkpoint = Read-SnapshotText $ResultPath 33554432; $readErrors = 0 }
        catch [IO.FileNotFoundException] { $checkpoint = $null }
        catch [IO.IOException], [UnauthorizedAccessException] {
            $readErrors++
            if ($readErrors -ge 8) { throw 'Catalog report could not be read. The worker and private report were retained.' }
            $checkpoint = $null
        }
        if ($null -ne $checkpoint -and $checkpoint -cne $lastExported) {
            $outcome = $checkpoint | ConvertFrom-Json
            $status = Field $outcome 'status' '' 'string'
            $receipt = Field $outcome 'package_receipt' $null
            if ((Field $outcome 'run_id' '' 'string') -cne $Manifest.run_id -or
                (Field $outcome 'source_revision' '' 'string') -cne $Manifest.source_revision -or
                (Field $receipt 'manifest_sha256' '' 'string') -cne $Manifest._manifest_sha256 -or
                $status -cnotin @('running','passed','failed')) { throw 'The catalog checkpoint identity is invalid.' }
            if ($status -cne 'running') {
                $finished = [DateTimeOffset]::MinValue
                if (-not [DateTimeOffset]::TryParse((Field $outcome 'finished_utc' '' 'string'), [ref]$finished) -or
                    $finished.Offset -ne [TimeSpan]::Zero) {
                    throw 'The catalog checkpoint is missing its terminal timestamp.'
                }
                if ((Field $outcome 'passed' $null 'boolean') -ne ($status -ceq 'passed')) {
                    throw 'The catalog terminal status is inconsistent.'
                }
            }
            try { Write-Report $SharedPath $outcome -SharedFolder }
            catch { throw 'Catalog report export failed. The worker and private report were retained.' }
            $lastExported = $checkpoint
            $summary = $status + ':' + @($outcome.checks).Count
            if ($summary -cne $lastPrinted) { Write-Host ('Catalog acceptance: ' + $summary); $lastPrinted = $summary }
            if ($status -cne 'running') {
                Remove-CatalogTaskIfInactive $TaskName
                return $outcome
            }
        }
        Start-Sleep -Milliseconds 500
    }
    throw 'Catalog acceptance did not finish; preserve the guest and partial result for recovery.'
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Message) {
    $watch = [Diagnostics.Stopwatch]::StartNew()
    while ($watch.Elapsed.TotalSeconds -lt $Seconds) {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 300
    }
    throw $Message
}
function Read-Rows([string]$Name, [switch]$RequireComplete) {
    $path = Join-Path $script:work $Name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return @() }
    $stream = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
    try { $reader = New-Object IO.StreamReader($stream); try { $text=$reader.ReadToEnd() } finally { $reader.Dispose() } }
    finally { $stream.Dispose() }
    $lines = @($text -split "`r?`n")
    # An append may be in flight; only complete lines are observations.
    if (-not $text.EndsWith("`n") -and $lines.Count) {
        if ($RequireComplete -and $text.Length -gt 0) { throw 'The final observation log contains an incomplete row.' }
        $lines = @($lines | Select-Object -SkipLast 1)
    }
    return @($lines | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Wait-Ack($Assignment) {
    Wait-Until { @(Read-Rows 'ack.log' | Where-Object {
        (Field $_ 'version' 0 'integer') -eq (Field $Assignment 'version' 0 'integer') -and
        (Field $_ 'digest' '' 'string') -ceq (Field $Assignment 'digest' '' 'string') -and
        (Field $_ 'success' $null 'boolean') -eq $true
    }).Count -gt 0 } 90 'The service did not successfully apply and ACK this exact catalog assignment within 90 seconds.'
}

if ($Plan) {
    @{phase='catalog';guest_only=$true;ack_timeout_seconds=90;hourly_wait_seconds=3600;timeout_seconds=$timeoutSeconds
      executes_controls=$false;required_checks=@('absent','network','process','wdac','all_absent','hourly','release','cleanup')} |
        ConvertTo-Json -Depth 8
    exit 0
}

# No staging, task, report, installer or control write is reachable before this gate.
$marker = if (Test-Path -LiteralPath $markerPath -PathType Leaf) { [IO.File]::ReadAllText($markerPath).Trim() } else { '' }
Assert-DisposableGuest (Get-CimInstance Win32_ComputerSystem -ErrorAction Stop) $marker ([bool]$DisposableVm)
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run acceptance as Administrator inside the disposable VM.' }
$manifestPath = Join-Path $PSScriptRoot 'acceptance-manifest.json'
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($manifest.phase -cne 'catalog' -or $manifest.run_id -cnotmatch '^[0-9a-f]{32}$' -or
    $manifest.source_revision -cnotmatch '^[0-9a-f]{40}$' -or
    $manifest.guest_work_directory -cne ('C:\openems-catalog-' + $manifest.run_id)) { throw 'The catalog manifest identity or guest path is invalid.' }
if ((Field $manifest 'evidence_format' 1 'integer') -ne 2) { throw 'This catalog harness requires evidence format 2.' }
$manifest | Add-Member -NotePropertyName '_manifest_sha256' -NotePropertyValue (Get-Sha256 $manifestPath)
foreach ($entry in $manifest.files.PSObject.Properties) {
    $name = $entry.Name
    if ([IO.Path]::GetFileName($name) -cne $name -or $name -in @('.','..') -or $name.Contains(':')) { throw 'Manifest entries must be plain file names.' }
    $path = Join-Path $PSScriptRoot $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-Item -LiteralPath $path).Length -ne $entry.Value.bytes -or
        (Get-Sha256 $path) -cne $entry.Value.sha256) { throw ('Missing or modified catalog input: ' + $name) }
}
foreach ($name in @('test-catalog-sandbox.ps1','openems-agent.msi',$manifest.fixtures.a.file,$manifest.fixtures.a.renamed_file,
                    $manifest.fixtures.b.file,$manifest.fixtures.b.renamed_file)) {
    if ($null -eq $manifest.files.PSObject.Properties[$name]) { throw 'The required catalog input is absent from the manifest.' }
}

if (-not $SystemPhase) {
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Restore the clean guest snapshot before acceptance.' }
    if (Test-Path -LiteralPath $manifest.guest_work_directory) { throw 'This run already has a work directory; preserve evidence and restore a clean snapshot.' }
    $lock = [IO.File]::Open('C:\openems-catalog-acceptance.lock','CreateNew','Write','None'); $lock.Dispose()
    $work = $manifest.guest_work_directory
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    foreach ($entry in $manifest.files.PSObject.Properties) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $entry.Name) -Destination $work }
    Copy-Item -LiteralPath $manifestPath -Destination $work
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $taskName = 'OpenemsCatalog-' + $manifest.run_id
    $scriptPath = Join-Path $work 'test-catalog-sandbox.ps1'
    $action = New-ScheduledTaskAction -Execute (Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe') -Argument (
        '-NoProfile -ExecutionPolicy Bypass -File "' + $scriptPath + '" -SystemPhase -DisposableVm -OutputDirectory "' + $work + '"')
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Seconds ($timeoutSeconds+900))
    Register-ScheduledTask -TaskName $taskName -TaskPath '\' -Action $action -Settings $settings -User SYSTEM -RunLevel Highest | Out-Null
    Start-ScheduledTask -TaskName $taskName -TaskPath '\'
    $outcome = Observe-CatalogTask (Join-Path $work $reportName) (Join-Path $OutputDirectory $reportName) $manifest $taskName ($timeoutSeconds+600)
    if ($outcome.status -ceq 'passed' -and $outcome.passed -eq $true) { Assert-CatalogEvidence $outcome $manifest; exit 0 }
    throw 'Catalog acceptance failed. Preserve the guest and catalog-result.json; do not restore before reviewing cleanup.'
}

if ($identity.User.Value -cne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
if ($PSScriptRoot -cne $manifest.guest_work_directory) { throw 'The SYSTEM worker must run from its verified private staging directory.' }
$script:work = $PSScriptRoot
$resultPath = Join-Path $work $reportName
$policyFile = Join-Path $work 'active-policy.json'
$journalPath = 'C:\ProgramData\openems\application-control.json'
$statePath = 'C:\ProgramData\openems\state.json'
$result = [ordered]@{run_id=$manifest.run_id;source_revision=$manifest.source_revision;status='running';passed=$false
    error=$null;cleanup_errors=@();checks=@();started_utc=[DateTime]::UtcNow.ToString('o');finished_utc=$null
    evidence_format=2;firewall_before=$null;ack_observations=@()
    fixture_probes=@();network_enumeration=$null
    scope='real host catalog API expansion; local fixture transport; installed Windows service'
    package_receipt=@{source_revision=$manifest.source_revision;packages=$manifest.packages;manifest_sha256=$manifest._manifest_sha256}}
$backend = $null
$installed = $false
$msiRemovalExit = $null
$ownedProcesses = New-Object Collections.ArrayList
$registryPaths = @()
$globalWatch = [Diagnostics.Stopwatch]::StartNew()
$codeBefore = @()
$firewallBefore = $null
$hostsBefore = $null
$ownPolicyId = $null

function Record-Check([string]$Name, $Evidence, [string]$Status='passed') {
    $result.checks += @{name=$Name;status=$Status;evidence=$Evidence;at_utc=[DateTime]::UtcNow.ToString('o')}
    Write-Report $resultPath $result -LocalCheckpoint
}
function Read-Journal([switch]$AllowMissing) {
    return Read-CatalogJson $journalPath -AllowMissing:$AllowMissing
}
function Code-Policies {
    $raw = & (Join-Path $env:SystemRoot 'System32\CiTool.exe') --list-policies -json
    if ($LASTEXITCODE -ne 0) { throw 'Code Integrity policy enumeration failed.' }
    return @(($raw | ConvertFrom-Json).Policies)
}
function Own-Policy {
    $journal = Read-Journal -AllowMissing
    if ($null -ne $journal) {
        $script:ownPolicyId = [string]$journal.policy_id
    }
    # Normal MSI removal deletes the journal. Its previously observed GUID still identifies leftovers.
    if (-not $script:ownPolicyId) { return $null }
    if ($script:ownPolicyId -notmatch '^\{[0-9a-fA-F-]{36}\}$') { throw 'The application journal has an invalid owned policy identity.' }
    return @(Code-Policies | Where-Object { ([string]$_.PolicyID).Trim('{}') -ieq ([string]$script:ownPolicyId).Trim('{}') }) | Select-Object -First 1
}
function Foreign-PolicyIds {
    return @(Code-Policies | Where-Object { ([string]$_.PolicyID).Trim('{}') -ine ([string]$script:ownPolicyId).Trim('{}') } | ForEach-Object PolicyID | Sort-Object)
}
function Capture-FirewallSnapshot([ValidateRange(1,10000)][int]$MaximumRules=10000) {
    $snapshot = @{
        status='failed';at_utc=[DateTime]::UtcNow.ToString('o');rules=@()
        error='firewall_query_failed';truncated=$false;observed_count=0
    }
    try {
        $native = @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop |
            Where-Object { $_.Group -ne $applicationGroup })
        $snapshot.observed_count = $native.Count
        $snapshot.error = 'firewall_rule_invalid'
        $snapshot.rules = @($native | Select-Object -First $MaximumRules | ForEach-Object {
            $rule = @{name=[string]$_.Name;enabled=[string]$_.Enabled;direction=[string]$_.Direction;action=[string]$_.Action}
            if ($rule.name -notmatch '\S' -or $rule.enabled -cnotin @('True','False','NotConfigured') -or
                $rule.direction -cnotin @('Inbound','Outbound') -or $rule.action -cnotin @('Allow','Block','NotConfigured')) {
                throw 'The firewall rule has invalid metadata.'
            }
            $rule
        })
        $snapshot.truncated = $snapshot.observed_count -gt $snapshot.rules.Count
        if ($snapshot.truncated) {
            $snapshot.status = 'truncated'
            $snapshot.error = 'firewall_rule_limit'
        } else {
            $snapshot.status = 'complete'
            $snapshot.error = $null
        }
    } catch {
        # Keep only an allowlisted marker. Native diagnostics may include unrelated rule details.
        $snapshot.rules = @()
    }
    return $snapshot
}
function Compare-FirewallSnapshots($Before,$After) {
    function Test-CompleteSnapshot($Snapshot) {
        try {
            if ($null -eq $Snapshot) { return $false }
            $keys = if ($Snapshot -is [Collections.IDictionary]) { @($Snapshot.Keys) } else { @($Snapshot.PSObject.Properties | ForEach-Object Name) }
            if ($keys.Count -ne 6 -or @($keys | Where-Object { $_ -cnotin @('status','at_utc','rules','error','truncated','observed_count') }).Count -ne 0 -or
                (Field $Snapshot 'status' '' 'string') -cne 'complete' -or (Field $Snapshot 'truncated' $null 'boolean') -ne $false -or
                $null -ne (Field $Snapshot 'error' 'missing') -or $Snapshot.rules -isnot [array] -or
                (Field $Snapshot 'observed_count' -1 'integer') -ne $Snapshot.rules.Count) { return $false }
            $at = Field $Snapshot 'at_utc' '' 'string'
            if ($at -cnotmatch '(Z|\+00:00)$') { return $false }
            $null = [DateTimeOffset]::Parse($at)
            foreach ($rule in $Snapshot.rules) {
                if ((Field $rule 'name' '' 'string') -notmatch '\S' -or
                    (Field $rule 'enabled' '' 'string') -cnotin @('True','False','NotConfigured') -or
                    (Field $rule 'direction' '' 'string') -cnotin @('Inbound','Outbound') -or
                    (Field $rule 'action' '' 'string') -cnotin @('Allow','Block','NotConfigured')) { return $false }
            }
            return $true
        } catch { return $false }
    }
    $comparison = @{before=$Before;after=$After;differences=@();preserved=$false}
    if (-not (Test-CompleteSnapshot $Before) -or -not (Test-CompleteSnapshot $After) -or
        [DateTimeOffset]::Parse($After.at_utc) -lt [DateTimeOffset]::Parse($Before.at_utc)) { return $comparison }
    $byName = @{}
    foreach ($rule in $After.rules) {
        if (-not $byName.ContainsKey($rule.name)) { $byName[$rule.name] = @() }
        $byName[$rule.name] += @($rule)
    }
    $previousNames = @{}
    $differences = @(
        foreach ($rule in $Before.rules) {
            $previousNames[$rule.name] = $true
            $sameName = if ($byName.ContainsKey($rule.name)) { @($byName[$rule.name]) } else { @() }
            $sameName = @($sameName | Where-Object { $null -ne $_ })
            if ($sameName.Count -eq 0) { @{name=$rule.name;kind='missing';fields=@()} }
            elseif ($sameName.Count -ne 1) { @{name=$rule.name;kind='duplicate';fields=@()} }
            else {
                $changed = @(foreach ($property in @('enabled','direction','action')) {
                    if ($sameName[0].$property -cne $rule.$property) { $property }
                })
                if ($changed.Count -ne 0) { @{name=$rule.name;kind='changed';fields=$changed} }
            }
        }
        foreach ($rule in $After.rules) {
            if (-not $previousNames.ContainsKey($rule.name)) { @{name=$rule.name;kind='added';fields=@()} }
        }
    )
    $comparison.differences = @($differences | Sort-Object -Property @{Expression={$_.name}},@{Expression={$_.kind}})
    $comparison.preserved = @($differences | Where-Object { $_.kind -cne 'added' }).Count -eq 0
    return $comparison
}
function Assert-FirewallPreserved($Firewall) {
    if (-not $Firewall.preserved) { throw 'An unrelated firewall rule changed or its snapshot is incomplete.' }
}
function Owned-FirewallRules {
    return @(Get-NetFirewallRule -PolicyStore PersistentStore -ErrorAction Stop | Where-Object Group -EQ $applicationGroup)
}
function Collect-CleanupEvidence($Before,$MsiExit,$ForeignBefore,$RegistryPaths) {
    $cleanup = @{
        msi_exit=$MsiExit;service_present=$null;watchdog_present=$null;nrpt_count=$null
        owned_firewall_rules=$null;own_policy_present=$null;foreign_before=@($ForeignBefore)
        foreign_after=$null;fixture_registry_present=$null;firewall=$null
        collection_status='complete';collection_errors=@()
    }
    if ($null -eq $MsiExit) { $cleanup.collection_errors += @{field='msi_exit';error='not_observed'} }
    try {
        $cleanup.service_present = @(Get-Service -ErrorAction Stop | Where-Object Name -EQ 'openems-agent').Count -ne 0
    } catch { $cleanup.collection_errors += @{field='service_present';error='query_failed'} }
    try {
        $cleanup.watchdog_present = @(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -EQ 'openems-agent watchdog').Count -ne 0
    } catch { $cleanup.collection_errors += @{field='watchdog_present';error='query_failed'} }
    try {
        $cleanup.nrpt_count = @(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object Comment -EQ 'openems-agent managed DNS filter').Count
    } catch { $cleanup.collection_errors += @{field='nrpt_count';error='query_failed'} }
    try {
        $cleanup.owned_firewall_rules = @(Owned-FirewallRules).Count
    } catch { $cleanup.collection_errors += @{field='owned_firewall_rules';error='query_failed'} }
    try {
        $cleanup.own_policy_present = $null -ne (Own-Policy)
    } catch { $cleanup.collection_errors += @{field='own_policy_present';error='query_failed'} }
    try {
        $cleanup.foreign_after = @(Foreign-PolicyIds)
    } catch { $cleanup.collection_errors += @{field='foreign_after';error='query_failed'} }
    try {
        $cleanup.fixture_registry_present = @($RegistryPaths | Where-Object { Test-Path -LiteralPath $_ -ErrorAction Stop }).Count -ne 0
    } catch { $cleanup.collection_errors += @{field='fixture_registry_present';error='query_failed'} }
    try {
        $after = Capture-FirewallSnapshot
        $cleanup.firewall = Compare-FirewallSnapshots $Before $after
        if ($null -eq $Before -or $Before.status -cne 'complete' -or $after.status -cne 'complete') {
            $cleanup.collection_errors += @{field='firewall';error='snapshot_incomplete'}
        }
    } catch { $cleanup.collection_errors += @{field='firewall';error='query_failed'} }
    if ($cleanup.collection_errors.Count -ne 0) { $cleanup.collection_status = 'partial' }
    return $cleanup
}
function Publish-Assignment([string]$Name) {
    $assignment = Field $manifest.policies $Name $null
    if ($null -eq $assignment) { throw 'The requested pre-expanded catalog assignment is missing.' }
    Write-Report $policyFile $assignment
    return $assignment
}
function Delivery-Evidence($Assignment) {
    $ack = @(Read-Rows 'ack.log' | Where-Object {
        (Field $_ 'version' 0 'integer') -eq (Field $Assignment 'version' 0 'integer') -and
        (Field $_ 'digest' '' 'string') -ceq (Field $Assignment 'digest' '' 'string') -and
        (Field $_ 'success' $null 'boolean') -eq $true
    }) | Select-Object -Last 1
    if ($null -eq $ack) { throw 'The exact successful ACK is missing.' }
    return @{assignment=@{version=$Assignment.version;digest=$Assignment.digest};ack=@{version=$ack.version;digest=$ack.digest;success=$ack.success};own_policy_present=($null -ne (Own-Policy))}
}
function Assert-ProductionPackage([string]$Path) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $null; $query=$null
    try {
        $database=$installer.GetType().InvokeMember('OpenDatabase','InvokeMethod',$null,$installer,@($Path,0))
        $query=$database.OpenView('SELECT `Action` FROM `CustomAction`'); $query.Execute()
        while ($null -ne ($row=$query.Fetch())) {
            if ($row.StringData(1) -in @('InjectSetupFailure','InjectRemovalFailure')) { throw 'A fault-injection MSI cannot be accepted as production.' }
        }
    } finally {
        foreach ($item in @($query,$database,$installer)) { if ($null -ne $item) { [void][Runtime.InteropServices.Marshal]::ReleaseComObject($item) } }
    }
}
function Invoke-Msi([bool]$Remove) {
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $operation=if ($Remove) { '/x' } else { '/i' }
    $logName=if ($Remove) { 'remove.msi.log' } else { 'install.msi.log' }
    $start.Arguments=$operation + ' "' + (Join-Path $work 'openems-agent.msi') + '" /qn /norestart /l*v "' + (Join-Path $work $logName) + '"'
    if (-not $Remove) { $start.Arguments+=' SERVER=' + $origin + ' INVITATION=catalog-fixture DEVID=catalog-' + $manifest.run_id }
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit(240000)) { throw 'The MSI operation timed out; preserve the guest for recovery.' }
        if ($process.ExitCode -ne 0) { throw ('The MSI operation returned '+$process.ExitCode+'; reboot-required is not a pass.') }
        return $process.ExitCode
    } finally { $process.Dispose() }
}
function Start-Backend {
    $ready=Join-Path $work 'backend-ready'
    $job=Start-Job -ArgumentList $origin,$work,$manifest.run_id -ScriptBlock {
        param($Origin,$Work,$RunId)
        $ErrorActionPreference='Stop'
        $listener=New-Object Net.HttpListener
        $listener.Prefixes.Add($Origin+'/')
        $token=[Guid]::NewGuid().ToString('N')+[Guid]::NewGuid().ToString('N')
        $client='catalog-'+$RunId
        function Ack-Observation($Upload,[string]$AtUtc=[DateTime]::UtcNow.ToString('o')) {
            $version = $Upload.version
            $digest = $Upload.digest
            $success = $Upload.success
            if (($version -isnot [int] -and $version -isnot [long]) -or $version -lt 1 -or
                $digest -isnot [string] -or $digest -cnotmatch '^[0-9a-f]{64}\z' -or $success -isnot [bool]) {
                throw 'The ACK does not identify a valid catalog assignment.'
            }
            $kind = $null
            if (-not $success) {
                $kind = 'unknown'
                $errorProperty = $Upload.PSObject.Properties['error']
                if ($null -ne $errorProperty -and $errorProperty.Value -is [string] -and
                    $errorProperty.Value -cmatch '^enforcement failed: (ConfigError|PolicyError|StateError|HTTPError|TransportError|LocalError|OSError)\z') {
                    $kind = $Matches[1]
                }
            }
            return @{version=$version;digest=$digest;success=$success;at_utc=$AtUtc;error_kind=$kind}
        }
        function Append-Observation([string]$Name,$Value) {
            $bytes=(New-Object Text.UTF8Encoding($false)).GetBytes(($Value | ConvertTo-Json -Depth 20 -Compress)+"`r`n")
            for ($attempt=1; ; $attempt++) {
                try {
                    $stream=[IO.File]::Open((Join-Path $Work $Name),'Append','Write','ReadWrite')
                    try { $stream.Write($bytes,0,$bytes.Length) } finally { $stream.Dispose() }
                    return
                } catch [IO.IOException] { if ($attempt -ge 40) { throw }; Start-Sleep -Milliseconds 50 }
            }
        }
        try {
            $listener.Start(); [IO.File]::WriteAllText((Join-Path $Work 'backend-ready'),'ready')
            while ($true) {
                $context=$listener.GetContext()
                try {
                    $route=$context.Request.Url.AbsolutePath.Replace('/fct/api/public/v1/','').Trim('/')
                    $reader=New-Object IO.StreamReader($context.Request.InputStream,[Text.Encoding]::UTF8)
                    try { $raw=$reader.ReadToEnd() } finally { $reader.Dispose() }
                    $answer=@{}; $context.Response.StatusCode=200
                    if ($route -ne 'register' -and $context.Request.Headers['Authorization'] -cne ('Bearer '+$token)) {
                        $context.Response.StatusCode=403
                    } else { switch ($route) {
                        'register' { $answer=@{client_id=$client;device_token=$token} }
                        'config/assigned' { $answer=Get-Content -LiteralPath (Join-Path $Work 'active-policy.json') -Raw | ConvertFrom-Json }
                        'config/ack' {
                            $upload=$raw | ConvertFrom-Json
                            Append-Observation 'ack.log' (Ack-Observation $upload)
                        }
                        'inventory' {
                            $upload=$raw | ConvertFrom-Json
                            # Only the owned fixture identities are retained; no ambient process inventory leaves the guest.
                            $apps=@($upload.applications | Where-Object { $_.path -like ($Work+'\*') } | Select-Object name,path,sha256,running)
                            Append-Observation 'inventory.log' @{applications=$apps;at_utc=[DateTime]::UtcNow.ToString('o')}
                            $answer=@{accepted=$true}
                        }
                        'control_events' { $answer=@{accepted=1;rejected=0} }
                        'host_tags' { }
                        'messages/pull' { }
                        'refresh' { }
                        'events' { $answer=@{accepted=0;rejected=0} }
                        'tamper' { $answer=@{accepted=0;rejected=0} }
                        default { $context.Response.StatusCode=404 }
                    } }
                    $bytes=[Text.Encoding]::UTF8.GetBytes(($answer | ConvertTo-Json -Depth 32 -Compress))
                    $context.Response.ContentType='application/json'; $context.Response.ContentLength64=$bytes.Length
                    $context.Response.OutputStream.Write($bytes,0,$bytes.Length)
                } catch {
                    # A failed/aborted request is observed without credentials, request bodies or full URLs.
                    try { Append-Observation 'backend-errors.log' @{at_utc=[DateTime]::UtcNow.ToString('o');error_type=$_.Exception.GetType().Name} } catch { }
                    try { $context.Response.StatusCode=500 } catch { }
                } finally { try { $context.Response.Close() } catch { } }
            }
        } finally { $listener.Close() }
    }
    Wait-Until { if ($job.State -eq 'Failed') { throw 'The local catalog backend failed during startup.' }; Test-Path -LiteralPath $ready } 120 'The local catalog backend did not start.'
    return $job
}
function Start-Fixture([string]$Path, [string]$Sentinel, [string]$Url, [int]$HoldMilliseconds) {
    if (Test-Path -LiteralPath $Sentinel) { Remove-Item -LiteralPath $Sentinel }
    $start=New-Object Diagnostics.ProcessStartInfo
    $start.FileName=$Path; $start.Arguments='"'+$Sentinel+'" "'+$Url+'" '+$HoldMilliseconds
    $start.UseShellExecute=$false; $start.CreateNoWindow=$true
    $process=[Diagnostics.Process]::Start($start)
    [void]$ownedProcesses.Add($process)
    return $process
}
function Wait-FixtureStartup([scriptblock]$Observe, [scriptblock]$ElapsedMilliseconds,
                             [scriptblock]$Pause={ Start-Sleep -Milliseconds 300 }, [int]$TimeoutMilliseconds=10000) {
    function Read-StartupSample {
        $sample = @{at_ms=$null;marker_present=$null;process_exited=$null;error_kind=$null}
        try {
            $observed = & $Observe
            if ($observed.marker_present -isnot [bool] -or $observed.process_exited -isnot [bool]) {
                throw 'The fixture observation did not return a definite state.'
            }
            $sample.marker_present = $observed.marker_present
            $sample.process_exited = $observed.process_exited
        } catch {
            $sample.error_kind = 'query_failed'
        }
        $sample.at_ms = & $ElapsedMilliseconds
        return $sample
    }
    $last = $null
    $terminal = $null
    while ((& $ElapsedMilliseconds) -lt $TimeoutMilliseconds) {
        $sample = Read-StartupSample
        if ($sample.at_ms -ge $TimeoutMilliseconds) {
            $terminal = $sample
            break
        }
        if ($null -ne $sample.error_kind) {
            return @{status='unavailable';elapsed_ms=$sample.at_ms;last_in_window=$last;terminal=$sample}
        }
        $last = $sample
        if ($sample.marker_present) {
            return @{status='started';elapsed_ms=$sample.at_ms;last_in_window=$last;terminal=$null}
        }
        if ($sample.process_exited) {
            return @{status='exited';elapsed_ms=$sample.at_ms;last_in_window=$last;terminal=$null}
        }
        $null = & $Pause
    }
    # A completed read outside the window is diagnostic, even when it found the marker.
    if ($null -eq $terminal) { $terminal = Read-StartupSample }
    return @{status='timeout';elapsed_ms=$terminal.at_ms;last_in_window=$last;terminal=$terminal}
}
function Invoke-Fixture([string]$Path, [string]$Url='-', [string]$Phase, [string]$Role) {
    $sentinelId = [Guid]::NewGuid().ToString('N')
    $sentinel = Join-Path $work ($sentinelId+'.started')
    $probe = @{
        phase=$Phase;role=$Role;sentinel_id=$sentinelId;status='launching'
        pid=$null;process_created=$null;native_error=$null
        launch=@{started_utc=$null;finished_utc=$null;elapsed_ms=$null}
        startup=$null;exit_wait=$null;marker_created_utc=$null;marker_metadata_error=$null
    }
    $result.fixture_probes += @($probe)
    try {
        $probe.launch.started_utc = [DateTime]::UtcNow.ToString('o')
        $launchClock = [Diagnostics.Stopwatch]::StartNew()
        try {
            $process = Start-Fixture $Path $sentinel $Url 3000
            $startupClock = [Diagnostics.Stopwatch]::StartNew()
        } catch [ComponentModel.Win32Exception] {
            $probe.status = 'native_refused'
            $probe.native_error = $_.Exception.NativeErrorCode
            $probe.process_created = $false
        } catch {
            $probe.status = 'launch_failed'
            throw 'The owned fixture could not be started.'
        } finally {
            $launchClock.Stop()
            $probe.launch.finished_utc = [DateTime]::UtcNow.ToString('o')
            $probe.launch.elapsed_ms = $launchClock.Elapsed.TotalMilliseconds
        }
        if ($probe.status -ceq 'native_refused') {
            try { $started = Test-Path -LiteralPath $sentinel -ErrorAction Stop }
            catch { throw 'The fixture marker could not be observed after the native refusal.' }
            return @{exit=-1;native_error=$probe.native_error;process_created=$false;started=$started;alive_after_sentinel=$false}
        }
        $probe.process_created = $true
        $probe.native_error = 0
        $probe.pid = $process.Id
        $probe.startup = Wait-FixtureStartup {
            @{marker_present=(Test-Path -LiteralPath $sentinel -ErrorAction Stop);process_exited=$process.HasExited}
        } { $startupClock.Elapsed.TotalMilliseconds }
        if ($probe.startup.status -ceq 'timeout') {
            $probe.status = 'startup_timeout'
            throw 'The fixture did not reach its sentinel.'
        }
        if ($probe.startup.status -ceq 'unavailable') {
            $probe.status = 'startup_unavailable'
            throw 'The fixture startup state could not be observed.'
        }
        $probe.exit_wait = @{elapsed_ms=$null;timed_out=$null;exit_code=$null}
        $exitClock = $null
        try {
            $alive = -not $probe.startup.last_in_window.process_exited -and -not $process.HasExited
            $exitClock = [Diagnostics.Stopwatch]::StartNew()
            $probe.exit_wait.timed_out = -not $process.WaitForExit(15000)
            if (-not $probe.exit_wait.timed_out) { $probe.exit_wait.exit_code = $process.ExitCode }
        } catch {
            $probe.status = 'exit_unavailable'
            throw 'The owned fixture exit state could not be observed.'
        } finally {
            if ($null -ne $exitClock) {
                $exitClock.Stop()
                $probe.exit_wait.elapsed_ms = $exitClock.Elapsed.TotalMilliseconds
            }
        }
        if ($probe.exit_wait.timed_out) {
            $probe.status = 'exit_timeout'
            throw 'The owned fixture exceeded its probe timeout.'
        }
        if ($probe.startup.status -ceq 'exited') {
            $probe.status = 'startup_exited'
            throw 'The owned fixture exited before its sentinel was observed.'
        }
        $probe.status = 'completed'
        return @{exit=$probe.exit_wait.exit_code;native_error=0;process_created=$true;started=$true;alive_after_sentinel=$alive}
    } finally {
        try {
            $markerObserved = $null -ne $probe.startup -and (
                ($null -ne $probe.startup.last_in_window -and $probe.startup.last_in_window.marker_present -eq $true) -or
                ($null -ne $probe.startup.terminal -and $probe.startup.terminal.marker_present -eq $true))
            if ($markerObserved -or (Test-Path -LiteralPath $sentinel -ErrorAction Stop)) {
                $probe.marker_created_utc = (Get-Item -LiteralPath $sentinel -ErrorAction Stop).CreationTimeUtc.ToString('o')
            }
        } catch { $probe.marker_metadata_error = 'query_failed' }
    }
}
function Install-Fixture($Fixture) {
    $path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\OpenemsCatalog-'+$manifest.run_id+'-'+$Fixture.app_id.Replace('.','-')
    if (Test-Path -LiteralPath $path) { throw 'A fixture registration already exists; use a fresh snapshot.' }
    New-Item -Path $path | Out-Null
    $script:registryPaths+=@($path)
    New-ItemProperty -LiteralPath $path -Name DisplayName -Value $Fixture.installed_name -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath $path -Name DisplayIcon -Value (Join-Path $work $Fixture.file) -PropertyType String | Out-Null
    New-ItemProperty -LiteralPath $path -Name DisplayVersion -Value '1.0.0' -PropertyType String | Out-Null
}
function Assignment-Observation {
    $cache=Read-CatalogJson $statePath
    return @{version=$cache.profile.version;digest=$cache.profile.digest}
}
function Hourly-Observation {
    $assignment=Assignment-Observation
    $journal=Read-Journal
    return @{version=$assignment.version;digest=$assignment.digest;optional_checked_at=[long](Field $journal 'optional_checked_at' 0)}
}

Write-Report $resultPath $result -LocalCheckpoint
try {
    Assert-ProductionPackage (Join-Path $work 'openems-agent.msi')
    if (-not (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\CiTool.exe')) -or
        @(Get-Module -ListAvailable ConfigCI).Count -eq 0) { throw 'This guest has no supported CiTool/ConfigCI capability.' }
    $codeBefore=@(Code-Policies | ForEach-Object PolicyID | Sort-Object)
    $firewallBefore=Capture-FirewallSnapshot
    $result.firewall_before=$firewallBefore
    Write-Report $resultPath $result -LocalCheckpoint
    if ($firewallBefore.status -cne 'complete') { throw 'The preinstallation firewall snapshot is incomplete.' }
    if (@(Owned-FirewallRules).Count -ne 0) { throw 'Restore the clean snapshot; owned application firewall rules already exist.' }
    $hostsPath=Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
    $hostsBefore=Get-Sha256 $hostsPath
    $a=Join-Path $work $manifest.fixtures.a.file; $aControl=Join-Path $work $manifest.fixtures.a.renamed_file
    $b=Join-Path $work $manifest.fixtures.b.file; $bControl=Join-Path $work $manifest.fixtures.b.renamed_file
    $assignment=Publish-Assignment 'allow'
    $backend=Start-Backend
    $null=Invoke-Msi $false; $installed=$true
    Wait-Ack $assignment
    # Reference probes must finish before catalog process termination becomes active.
    $url='https://example.org/'
    $network=@{before=@{};blocked=@{};released=@{};firewall_paths=@();control_has_rule=$false}
    $probeA=Invoke-Fixture $a $url -Phase 'network_before' -Role 'target'
    $probeControl=Invoke-Fixture $aControl $url -Phase 'network_before' -Role 'control'
    $network.before=@{target_exit=$probeA.exit;control_exit=$probeControl.exit}
    if ($probeA.exit -ne 0 -or $probeControl.exit -ne 0) { throw 'Both fixture paths must reach the external network before firewall acceptance.' }
    $assignment=Publish-Assignment 'absent'; Wait-Ack $assignment
    $absent=Delivery-Evidence $assignment
    if ($absent.own_policy_present) { throw 'An absent catalog app unexpectedly installed a WDAC policy.' }
    Record-Check 'absent' $absent

    $assignment=Publish-Assignment 'network'; Wait-Ack $assignment
    $enumeration = @{
        status='running';started_utc=[DateTime]::UtcNow.ToString('o');finished_utc=$null
        elapsed_ms=$null;rule_count=$null;filter_count=$null;error_kind=$null
    }
    $result.network_enumeration = $enumeration
    $enumerationClock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $rules = @(Owned-FirewallRules)
        $enumeration.rule_count = $rules.Count
        $filters = @($rules | Get-NetFirewallApplicationFilter -ErrorAction Stop)
        $enumeration.filter_count = $filters.Count
        $network.firewall_paths = @($filters | ForEach-Object Program)
        $network.control_has_rule = @($network.firewall_paths | Where-Object { $_ -ieq $aControl }).Count -gt 0
        $enumeration.status = 'complete'
    } catch {
        $enumeration.status = 'failed'
        $enumeration.error_kind = 'query_failed'
        throw 'The owned network firewall filters could not be enumerated.'
    } finally {
        $enumerationClock.Stop()
        $enumeration.finished_utc = [DateTime]::UtcNow.ToString('o')
        $enumeration.elapsed_ms = $enumerationClock.Elapsed.TotalMilliseconds
    }
    $probeA=Invoke-Fixture $a $url -Phase 'network_blocked' -Role 'target'
    $probeControl=Invoke-Fixture $aControl $url -Phase 'network_blocked' -Role 'control'
    $network.blocked=@{target_process_created=$probeA.process_created;target_exit=$probeA.exit;control_exit=$probeControl.exit}
    if (-not $probeA.alive_after_sentinel -or -not $probeControl.alive_after_sentinel) { throw 'Network probes must remain alive after their sentinel.' }
    $assignment=Publish-Assignment 'network_release'; Wait-Ack $assignment
    $network.released=@{
        target_exit=(Invoke-Fixture $a $url -Phase 'network_release' -Role 'target').exit
        control_exit=(Invoke-Fixture $aControl $url -Phase 'network_release' -Role 'control').exit
    }
    Record-Check 'network' $network

    Install-Fixture $manifest.fixtures.a
    $targetSentinel=Join-Path $work 'target-running.started'; $controlSentinel=Join-Path $work 'control-running.started'
    $targetProcess=Start-Fixture $a $targetSentinel '-' 600000
    $controlProcess=Start-Fixture $aControl $controlSentinel '-' 600000
    Wait-Until { (Test-Path -LiteralPath $targetSentinel) -and (Test-Path -LiteralPath $controlSentinel) } 10 'The target and process control did not start.'
    $processEvidence=@{target_was_running=(-not $targetProcess.HasExited);target_pid=$targetProcess.Id;target_exited=$false
        control_pid=$controlProcess.Id;control_still_running=$false}
    $assignment=Publish-Assignment 'present'; Wait-Ack $assignment
    Wait-Until { $targetProcess.HasExited } 90 'The catalog did not terminate the already-running target process.'
    $processEvidence.target_exited=$targetProcess.HasExited; $processEvidence.control_still_running=-not $controlProcess.HasExited
    Record-Check 'process' $processEvidence
    $policy=Own-Policy
    $wdac=@{
        policy_enforced=($null -ne $policy -and [string]$policy.IsEnforced -ieq 'true')
        original=(Invoke-Fixture $a -Phase 'wdac' -Role 'original')
        renamed=(Invoke-Fixture $aControl -Phase 'wdac' -Role 'renamed')
    }
    Assert-DeniedExecution $wdac.original; Assert-DeniedExecution $wdac.renamed
    if (-not $wdac.policy_enforced) { throw 'The catalog WDAC policy is not enforced.' }
    Record-Check 'wdac' $wdac
    if (-not $controlProcess.HasExited) { $controlProcess.Kill(); $controlProcess.WaitForExit() }

    $assignment=Publish-Assignment 'later'; Wait-Ack $assignment
    $allAbsent=Delivery-Evidence $assignment
    $allAbsent.foreign_before=@($codeBefore); $allAbsent.foreign_after=@(Foreign-PolicyIds)
    if ($allAbsent.own_policy_present) { throw 'A previously applied WDAC policy remained when all optional samples were absent.' }
    Record-Check 'all_absent' $allAbsent
    $hourly=[ordered]@{elapsed_seconds=0.0;started_utc=[DateTime]::UtcNow.ToString('o');finished_utc=$null
        before=(Hourly-Observation);after=$null;assignment_observations=@((Assignment-Observation));before_admission=$null;after_denial=$null}
    $hourWatch=[Diagnostics.Stopwatch]::StartNew()
    Install-Fixture $manifest.fixtures.b
    $admitted=Invoke-Fixture $bControl -Phase 'hourly_before' -Role 'renamed'
    if ($admitted.exit -ne 0 -or -not $admitted.process_created) { throw 'The later fixture was not admitted before natural hourly rechecking.' }
    $hourly.before_admission=@{process_created=$admitted.process_created;native_error=$admitted.native_error}
    $lastMinute=-1
    while ($true) {
        if ($globalWatch.Elapsed.TotalSeconds -ge $timeoutSeconds) { throw 'Catalog acceptance reached its total time limit.' }
        $observation=Assignment-Observation
        if ($observation.version -ne $assignment.version -or $observation.digest -cne $assignment.digest) { throw 'A new policy push interrupted the hourly observation.' }
        $minute=[int][math]::Floor($hourWatch.Elapsed.TotalSeconds/60)
        if ($minute -ne $lastMinute) {
            $hourly.assignment_observations+=@($observation); $lastMinute=$minute
            $result.hourly_progress_seconds=[math]::Floor($hourWatch.Elapsed.TotalSeconds)
            Write-Report $resultPath $result -LocalCheckpoint
        }
        if ($hourWatch.Elapsed.TotalSeconds -ge 3600) {
            $observed=Hourly-Observation
            $policy=Own-Policy
            if ($observed.optional_checked_at -ge ([long]$hourly.before.optional_checked_at+3600) -and
                $null -ne $policy -and [string]$policy.IsEnforced -ieq 'true') {
                $hourly.after=$observed; break
            }
        }
        Start-Sleep -Seconds 5
    }
    $hourly.after_denial=Invoke-Fixture $bControl -Phase 'hourly_after' -Role 'renamed'
    $hourly.elapsed_seconds=$hourWatch.Elapsed.TotalSeconds; $hourly.finished_utc=[DateTime]::UtcNow.ToString('o')
    $hourly.assignment_observations+=@((Assignment-Observation))
    Assert-HourlyEvidence $hourly
    Record-Check 'hourly' $hourly

    $assignment=Publish-Assignment 'release'; Wait-Ack $assignment
    $release=Delivery-Evidence $assignment
    $release.original_exit=(Invoke-Fixture $b -Phase 'release' -Role 'original').exit
    $release.renamed_exit=(Invoke-Fixture $bControl -Phase 'release' -Role 'renamed').exit
    $release.firewall_rule_count=@(Owned-FirewallRules).Count
    Record-Check 'release' $release
} catch {
    $result.error=$_.Exception.Message
} finally {
    foreach ($process in $ownedProcesses) {
        try { if (-not $process.HasExited) { $process.Kill(); $process.WaitForExit() }; $process.Dispose() }
        catch { $result.cleanup_errors+=@('An owned fixture process could not be stopped.') }
    }
    if (-not $installed) {
        try {
            $installed = @(Get-Service -ErrorAction Stop | Where-Object Name -EQ 'openems-agent').Count -ne 0
        } catch { $result.cleanup_errors+=@('The installed service state could not be determined for normal removal.') }
    }
    if ($installed) {
        try {
            if ($null -eq $backend -or $backend.State -ne 'Running') { throw 'The local backend is unavailable for normal release; preserve the guest.' }
            $release=Publish-Assignment 'release'; Wait-Ack $release
            $msiRemovalExit=Invoke-Msi $true; $installed=$false
        } catch { $result.cleanup_errors+=@($_.Exception.Message) }
    }
    foreach ($path in $registryPaths) {
        try { if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Recurse -Force } }
        catch { $result.cleanup_errors+=@('An owned fixture Uninstall registration could not be removed.') }
    }
    if ($null -ne $backend) {
        try { Stop-Job $backend -ErrorAction Stop; Remove-Job $backend -Force -ErrorAction Stop }
        catch { $result.cleanup_errors+=@('The local backend could not be stopped.') }
    }
    try {
        $result.ack_observations = @(Read-Rows 'ack.log' -RequireComplete)
    } catch {
        $result.cleanup_errors+=@('The ACK history could not be collected completely.')
        try { $result.ack_observations = @(Read-Rows 'ack.log') }
        catch { $result.cleanup_errors+=@('The available ACK history could not be read.') }
    }
    $cleanup = Collect-CleanupEvidence $firewallBefore $msiRemovalExit $codeBefore $registryPaths
    $cleanupStatus = 'passed'
    try {
        if ($cleanup.collection_status -cne 'complete') { throw 'The cleanup observations are incomplete.' }
        Assert-FirewallPreserved $cleanup.firewall
        if ($null -ne $hostsBefore -and (Get-Sha256 $hostsPath) -cne $hostsBefore) { throw 'The hosts file was not restored.' }
        if ($cleanup.msi_exit -ne 0 -or $cleanup.service_present -or $cleanup.watchdog_present -or
            $cleanup.nrpt_count -ne 0 -or $cleanup.owned_firewall_rules -ne 0 -or
            $cleanup.own_policy_present -or $cleanup.fixture_registry_present) { throw 'Normal MSI removal or cleanup is incomplete.' }
        if ($cleanup.foreign_before.Count -ne $cleanup.foreign_after.Count -or
            @($cleanup.foreign_before | Where-Object { $_ -notin $cleanup.foreign_after }).Count -ne 0) {
            throw 'Foreign Code Integrity policies changed.'
        }
    } catch {
        $cleanupStatus = 'failed'
        $result.cleanup_errors+=@($_.Exception.Message)
    }
    try { Record-Check 'cleanup' $cleanup $cleanupStatus }
    catch { $result.cleanup_errors+=@('The cleanup checkpoint could not be persisted.') }
    $result.finished_utc=[DateTime]::UtcNow.ToString('o')
    if (-not $result.error -and $result.cleanup_errors.Count -eq 0) {
        $result.passed=$true; $result.status='passed'
        try { Assert-CatalogEvidence $result $manifest }
        catch { $result.passed=$false; $result.status='failed'; $result.error=$_.Exception.Message }
    } else { $result.passed=$false; $result.status='failed' }
    Write-Report $resultPath $result -LocalCheckpoint
}
if ($result.passed) { exit 0 }
exit 1
