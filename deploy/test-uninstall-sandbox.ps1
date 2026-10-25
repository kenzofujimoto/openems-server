param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan, [switch]$SelfTest,
      [string]$MasterKeyFile, [string]$ClientId)
# F5 part 5b acceptance (tamper-protection.md) for the production MSI in Windows Sandbox: one-time
# uninstall codes, the removal release and the offline generator. The SYSTEM phase installs and removes
# the agent repeatedly against a simulated backend that derives the secret from a test-only master key.
# The codes a panel would show come from tools/uninstall_code.py on the host (codes.json).
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packages = @('openems-agent.msi', 'openems-agent-next.msi')
$inputs = @('codes.json', 'master.key')
$origin = 'http://127.0.0.1:18014'
$clientName = 'sandbox-uninstall'
$report = 'uninstall-result.json'
$taskName = 'openems-agent watchdog'
$operationTimeout = 240
$totalTimeout = 3600
$wrongCode = '00000-00000'
$policy = [ordered]@{ vdom='Default'; version=1; digest='4a8ce82a838621f0eea252eb12da8652c5e45e4571392f269b6e3c675d5859ed'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@('tamper.example') } } }
$scenarios = @('install: the agent fetches and confirms the secret, and the server stops handing it out',
               'removal without a code fails, rollback restarts the service and the product stays',
               'removal with a wrong code fails, rollback restarts the service and uninstall_code_rejected is reported',
               'upgrade to a later version needs no code',
               'removal with the server code (counter 1) succeeds, protections are removed and the MSI log never holds the code',
               'after reinstalling with the same registration, a code used again is refused and the next one removes',
               'a release received from the server lets removal pass without a code even with the server stopped',
               'with the server stopped, a code from the agent executable (offline generator) removes the agent',
               'after a forced MSI removal, cleanup without a code fails and cleanup with a code removes the service and protections',
               'a machine without a secret (server without master key) is removed without a code and uninstall_without_secret is reported',
               'after five wrong codes removal is locked: the right code is refused and the product stays')

function Get-Mac([byte[]]$Key, [byte[]]$Message) {
    $hmac = New-Object Security.Cryptography.HMACSHA256 -ArgumentList (,$Key)
    try { return ,$hmac.ComputeHash($Message) } finally { $hmac.Dispose() }
}
function ConvertTo-Hex([byte[]]$Bytes) { return -join ($Bytes | ForEach-Object { $_.ToString('x2') }) }
# Same format as agent/uninstall.py master_key_from_text: UTF-8 text, BOM and surrounding whitespace removed.
function Read-MasterKey([string]$Path) {
    $text = [IO.File]::ReadAllText($Path, (New-Object Text.UTF8Encoding($false)))
    $key = [Text.Encoding]::UTF8.GetBytes($text.TrimStart([char]0xFEFF).Trim())
    if ($key.Length -lt 32) { throw 'The uninstall master key must have at least 32 bytes.' }
    return ,$key
}
# Secret, release token and delivery proof exactly as the server derives them (contract/uninstall-vectors.json).
function Get-UninstallValues([byte[]]$MasterKey, [string]$Client) {
    $utf8 = New-Object Text.UTF8Encoding($false)
    [byte[]]$label = @($utf8.GetBytes('openems-uninstall-v1')) + @([byte]0) + @($utf8.GetBytes($Client))
    $secret = Get-Mac $MasterKey $label
    return [ordered]@{ secret=(ConvertTo-Hex $secret)
                       release=(ConvertTo-Hex (Get-Mac $secret $utf8.GetBytes('openems-release-v1')))
                       delivery_proof=(ConvertTo-Hex (Get-Mac $secret $utf8.GetBytes('openems-secret-delivered-v1'))) }
}

if ($Plan) {
    @{ packages=$packages; inputs=$inputs; origin=$origin; client_id=$clientName; report=$report
       timeout_seconds=$totalTimeout; policy=$policy; scenarios=$scenarios } | ConvertTo-Json -Depth 10
    exit 0
}
if ($SelfTest) {
    Get-UninstallValues (Read-MasterKey $MasterKeyFile) $ClientId | ConvertTo-Json -Compress
    exit 0
}
$executionService = Get-Service -Name CExecSvc -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -or $null -eq $executionService -or $executionService.Status -ne 'Running') {
    throw 'This acceptance harness requires Windows Sandbox.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Sandbox acceptance requires Administrator rights.' }
function Write-Report([string]$Path, $Value) {
    $temporary = $Path + '.tmp'
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
if (-not $SystemPhase) {
    # One run per Sandbox: a second run would collide on the port, the installed product and uninstall.json.
    try { [IO.File]::Open('C:\openems-uninstall-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'An uninstall acceptance run already started in this Sandbox; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-uninstall-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    foreach ($file in $packages + $inputs) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $file) -Destination $work }
    $script = Join-Path $work 'test-uninstall-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsUninstall-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $result = Join-Path $work $report
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        Write-Host 'Uninstall acceptance running (about 25 minutes of installs and removals). Leave this window open.'
        while (-not (Test-Path -LiteralPath $result)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Uninstall acceptance timed out. Close the Sandbox to discard changes.' }
            Start-Sleep -Milliseconds 500
        }
        $value = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $value
        $value | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $value.passed) { throw 'Uninstall acceptance failed; MSI logs remain inside the Sandbox work folder.' }
    }
    finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$result = [ordered]@{ passed=$false; checks=@(); durations=@(); error=$null; last_log=$null }
$work = $PSScriptRoot
$backend = $null
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$policyFile = Join-Path $work 'policy.json'
$uninstallJson = 'C:\ProgramData\openems\uninstall.json'
$installedExe = 'C:\Program Files\openems\openems-agent.exe'
$masterKeyPath = Join-Path $work 'master.key'
$values = Get-UninstallValues (Read-MasterKey $masterKeyPath) $clientName
$codes = Get-Content -LiteralPath (Join-Path $work 'codes.json') -Raw | ConvertFrom-Json
if ($codes.client_id -ne $clientName) { throw 'codes.json was generated for another client_id.' }
function Get-Code([int]$Counter) { return [string]$codes.codes.([string]$Counter) }
function Invoke-Msi([string]$Operation, [string]$Package, [string[]]$Properties) {
    $log = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($Operation, ('"' + (Join-Path $work $Package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
    # Process.Start keeps the handle; Start-Process -PassThru can miss the exit in Windows PowerShell 5.1.
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $start.Arguments = $arguments -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $started = [DateTime]::UtcNow
    $process = [Diagnostics.Process]::Start($start)
    try {
        $finished = $process.WaitForExit($operationTimeout * 1000)
        $result.durations += ('{0} {1}: {2:N0} s' -f $Operation, $Package, ([DateTime]::UtcNow - $started).TotalSeconds)
        $result.last_log = $log
        if (-not $finished) { throw ('MSI operation timed out; close Sandbox. Log: ' + $log) }
        return [pscustomobject]@{ ExitCode=$process.ExitCode; Log=$log }
    } finally { $process.Dispose() }
}
function Install-Agent([string]$Package) {
    $outcome = Invoke-Msi '/i' $Package @('SERVER=' + $origin)
    if ($outcome.ExitCode -ne 0) { throw ('Install failed with ' + $outcome.ExitCode + '. Log: ' + $outcome.Log) }
    Wait-Until { (Get-ServiceProcess) -gt 0 -and (Test-HostsBlocked) } 120 'The installed agent did not start enforcing.'
}
function Remove-Agent([string]$Package, [string]$Code) {
    $properties = @()
    if ($Code) { $properties += ('UNINSTALLCODE=' + $Code) }
    $outcome = Invoke-Msi '/x' $Package $properties
    if ($Code -and (Select-String -LiteralPath $outcome.Log -SimpleMatch $Code -Quiet)) {
        throw ('The MSI log contains the uninstall code: ' + $outcome.Log)
    }
    return $outcome
}
function Assert-RemovalRefused($Outcome) {
    if ($Outcome.ExitCode -eq 0) { throw 'Removal succeeded but should have been refused.' }
    if ($null -eq (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'The refused removal deleted the service.' }
    if (-not (Test-Path -LiteralPath $installedExe)) { throw 'The refused removal deleted the agent executable.' }
    Wait-Until { (Get-ServiceProcess) -gt 0 } 120 'Rollback did not restart the service after the refused removal.'
}
function Assert-Removed($Outcome) {
    if ($Outcome.ExitCode -ne 0) { throw ('Removal failed with ' + $Outcome.ExitCode + '. Log: ' + $Outcome.Log) }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Removed service still exists.' }
    if (Test-Task) { throw 'Removal left the watchdog scheduled task.' }
    if (Test-HostsBlocked) { throw 'Removal left the managed hosts block.' }
}
# Runs the agent executable without PowerShell's native stderr handling (terminating under 'Stop' in 5.1).
function Invoke-Agent([string]$Executable, [string[]]$Arguments) {
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $Executable
    $start.Arguments = ($Arguments | ForEach-Object { if ($_ -match '\s') { '"' + $_ + '"' } else { $_ } }) -join ' '
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    $process = [Diagnostics.Process]::Start($start)
    try {
        $output = $process.StandardOutput.ReadToEndAsync()
        $errors = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($operationTimeout * 1000)) { throw ('Agent command timed out: ' + $Arguments[0]) }
        return [pscustomobject]@{ ExitCode=$process.ExitCode; Output=$output.Result.Trim(); Error=$errors.Result.Trim() }
    } finally { $process.Dispose() }
}
function Get-ServiceProcess {
    $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) { return 0 }
    return [int]$service.ProcessId
}
function Test-HostsBlocked { return [bool](Select-String -LiteralPath $hosts -SimpleMatch 'tamper.example' -Quiet) }
function Test-Task {
    # Under 'Stop', Windows PowerShell 5.1 turns redirected native stderr ("task not found") into an error.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & (Join-Path $env:SystemRoot 'System32\schtasks.exe') '/Query' '/TN' $taskName 2>$null | Out-Null
        return ($LASTEXITCODE -eq 0)
    } finally { $ErrorActionPreference = $previous }
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Failure) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Failure
}
# uninstall.json is SYSTEM-only; this phase runs as SYSTEM. Missing or being replaced: $null.
function Get-State {
    try { return (Get-Content -LiteralPath $uninstallJson -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}
function Test-Armed {
    $state = Get-State
    return ((Test-Path -LiteralPath (Join-Path $work 'backend-acked')) -and $null -ne $state -and $state.acked -and
            $state.client_id -eq $clientName -and $state.secret -eq $values.secret)
}
function Get-ReportedKinds {
    $log = Join-Path $work 'tamper.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $stream = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
    try { $lines = (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`r?`n" } finally { $stream.Dispose() }
    return @($lines | Where-Object { $_ } | ForEach-Object { @(($_ | ConvertFrom-Json).events) } | ForEach-Object { [string]$_.kind })
}
function Wait-Reported([string]$Kind, [int]$Seconds) {
    Wait-Until { $Kind -in @(Get-ReportedKinds) } $Seconds ('The backend did not receive the ' + $Kind + ' tamper event.')
}
function Set-Backend([string]$Name, [bool]$Present) {
    $marker = Join-Path $work ('backend-' + $Name)
    if ($Present) { Set-Content -LiteralPath $marker -Value on } else { Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue }
}
# Simulated EMS backend: assigned policy (with the release token when released), one secret delivery
# closed by the agent's proof, 503 while "disabled" (no master key), and tamper uploads one per line.
function Start-Backend {
    $ready = Join-Path $work 'backend-ready'
    Remove-Item -LiteralPath $ready -ErrorAction SilentlyContinue
    $job = Start-Job -ArgumentList $origin, $work, $clientName, $values.secret, $values.release, $values.delivery_proof -ScriptBlock {
        param($Origin, $Work, $Client, $Secret, $Release, $Proof)
        $ErrorActionPreference = 'Stop'
        $listener = New-Object Net.HttpListener
        $listener.Prefixes.Add($Origin + '/')
        function Read-Body($Context) {
            $reader = New-Object IO.StreamReader($Context.Request.InputStream, [Text.Encoding]::UTF8)
            try { return $reader.ReadToEnd() } finally { $reader.Dispose() }
        }
        function Test-Marker([string]$Name) { return (Test-Path -LiteralPath (Join-Path $Work ('backend-' + $Name))) }
        try {
            $listener.Start()
            Set-Content -LiteralPath (Join-Path $Work 'backend-ready') -Value ready
            while ($true) {
                # Short waits keep Stop-Job effective; a blocking GetContext delays cleanup.
                $pending = $listener.GetContextAsync()
                while (-not $pending.Wait(500)) { }
                $context = $pending.Result
                $path = $context.Request.Url.AbsolutePath
                $context.Response.StatusCode = 200
                $payload = @{}
                switch ($path) {
                    '/fct/api/public/v1/register/' { $payload = @{ client_id=$Client; device_token='sandbox-fixture-only' } }
                    '/fct/api/public/v1/config/assigned/' {
                        $payload = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json
                        if (Test-Marker 'release') { $payload | Add-Member -NotePropertyName uninstall_release -NotePropertyValue $Release }
                    }
                    '/fct/api/public/v1/uninstall_secret/' {
                        if (Test-Marker 'disabled') {
                            $context.Response.StatusCode = 503; $payload = @{ detail='uninstall codes are not configured on this server' }
                        } elseif (Test-Marker 'acked') {
                            $context.Response.StatusCode = 409; $payload = @{ detail='uninstall secret already delivered' }
                        } else { $payload = @{ secret=$Secret } }
                    }
                    '/fct/api/public/v1/uninstall_secret/ack/' {
                        $sent = (Read-Body $context | ConvertFrom-Json).proof
                        if (Test-Marker 'disabled') {
                            $context.Response.StatusCode = 503; $payload = @{ detail='uninstall codes are not configured on this server' }
                        } elseif ($sent -eq $Proof) {
                            Set-Content -LiteralPath (Join-Path $Work 'backend-acked') -Value on; $payload = @{ ok=$true }
                        } else { $context.Response.StatusCode = 403; $payload = @{ detail='delivery proof does not match' } }
                    }
                    '/fct/api/public/v1/tamper/' {
                        $upload = Read-Body $context
                        try { Add-Content -LiteralPath (Join-Path $Work 'tamper.log') -Value ($upload -replace "`r?`n", ' ') } catch { }
                        $payload = @{ accepted=0; rejected=0 }
                    }
                    '/fct/api/public/v1/events/' { $payload = @{ accepted=0; rejected=0 } }
                    '/fct/api/public/v1/messages/pull/' { }
                    '/fct/api/public/v1/refresh/' { }
                    '/fct/api/public/v1/config/ack/' { }
                    '/fct/api/public/v1/host_tags/' { }
                    default { $context.Response.StatusCode = 404 }
                }
                $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
                $context.Response.ContentType = 'application/json'; $context.Response.ContentLength64 = $bytes.Length
                try { $context.Response.OutputStream.Write($bytes, 0, $bytes.Length) } finally { $context.Response.Close() }
            }
        } finally { $listener.Close() }
    }
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath $ready)) {
        if ($job.State -eq 'Failed' -or [DateTime]::UtcNow -ge $deadline) { throw 'Simulated EMS backend failed to start.' }
        Start-Sleep -Milliseconds 200
    }
    return $job
}
function Stop-Backend {
    if ($null -ne $script:backend) {
        Stop-Job $script:backend -ErrorAction Continue
        Remove-Job $script:backend -Force -ErrorAction Continue
        $script:backend = $null
    }
}
function Assert-ProductionPackage([string]$Path) {
    # The test-only FaultInjection build adds these actions; the production package must not contain them.
    # COM late binding rejects PSObject-wrapped strings (DISP_E_TYPEMISMATCH), so $Path stays a plain string.
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $database = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Path, 0))
    $query = "SELECT Action FROM CustomAction WHERE Action='InjectSetupFailure' OR Action='InjectRemovalFailure'"
    $view = $database.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $database, @($query))
    try {
        $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
        if ($null -ne $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)) {
            throw 'Package contains fault-injection actions; build it with tools/build-msi-fixtures.ps1 -Production.'
        }
    } finally { $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null }
}

try {
    if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
    $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 18014)
    try { $probe.Start() } finally { $probe.Stop() }
    foreach ($package in $packages) { Assert-ProductionPackage ([string](Join-Path $work $package)) }
    if (-not (Get-Code 1) -or -not (Get-Code 4)) { throw 'codes.json lacks the counters this run uses.' }
    $policy | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding UTF8
    $backend = Start-Backend

    Install-Agent $packages[0]
    Wait-Until { Test-Armed } 120 'The agent did not store and confirm its uninstall secret.'
    $result.checks += $scenarios[0]

    Assert-RemovalRefused (Remove-Agent $packages[0] '')
    $result.checks += $scenarios[1]

    Assert-RemovalRefused (Remove-Agent $packages[0] $wrongCode)
    Wait-Reported 'uninstall_code_rejected' 30
    $result.checks += $scenarios[2]

    Install-Agent $packages[1]
    $result.checks += $scenarios[3]

    Assert-Removed (Remove-Agent $packages[1] (Get-Code 1))
    $result.checks += $scenarios[4]

    Install-Agent $packages[0]
    if (-not (Test-Armed)) { throw 'The reinstalled agent lost its uninstall secret.' }
    Assert-RemovalRefused (Remove-Agent $packages[0] (Get-Code 1))
    Assert-Removed (Remove-Agent $packages[0] (Get-Code 2))
    $result.checks += $scenarios[5]

    Install-Agent $packages[0]
    Set-Backend 'release' $true
    Wait-Until { $state = Get-State; $null -ne $state -and $state.release -eq $values.release } 90 'The agent did not store the release.'
    Stop-Backend
    Assert-Removed (Remove-Agent $packages[0] '')
    Set-Backend 'release' $false
    $backend = Start-Backend
    $result.checks += $scenarios[6]

    Install-Agent $packages[0]
    Stop-Backend
    $next = [int](Get-State).last_used + 1
    $generated = Invoke-Agent $installedExe @('uninstall-code', '--master-key-file', $masterKeyPath, '--client-id', $clientName, '--counter', [string]$next)
    if ($generated.ExitCode -ne 0) { throw ('The agent executable did not generate a code: ' + $generated.Error) }
    if ($generated.Output -ne (Get-Code $next)) { throw 'The agent executable and tools/uninstall_code.py disagree on the code.' }
    Assert-Removed (Remove-Agent $packages[0] $generated.Output)
    $backend = Start-Backend
    $result.checks += $scenarios[7]

    # A forced MSI removal leaves the service and protections behind: an administrative extract gives the
    # executable without registering the product, and install-service recreates that state.
    $forced = 'C:\openems-forced'
    $extract = Invoke-Msi '/a' $packages[0] @('TARGETDIR=' + $forced)
    if ($extract.ExitCode -ne 0) { throw ('Administrative extract failed with ' + $extract.ExitCode) }
    $forcedExe = (Get-ChildItem -LiteralPath $forced -Recurse -Filter 'openems-agent.exe' | Select-Object -First 1).FullName
    $configured = Invoke-Agent $forcedExe @('configure', '--server', $origin, '--devid', $env:COMPUTERNAME)
    if ($configured.ExitCode -ne 0) { throw ('configure failed: ' + $configured.Error) }
    $serviceInstalled = Invoke-Agent $forcedExe @('install-service', '--start')
    if ($serviceInstalled.ExitCode -ne 0) { throw ('install-service failed: ' + $serviceInstalled.Error) }
    Wait-Until { (Get-ServiceProcess) -gt 0 -and (Test-HostsBlocked) -and (Test-Task) } 120 'The forced-removal agent did not start enforcing.'
    $refused = Invoke-Agent $forcedExe @('cleanup')
    if ($refused.ExitCode -eq 0 -or $null -eq (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'cleanup without a code removed the agent.' }
    $code = Get-Code ([int](Get-State).last_used + 1)
    $cleaned = Invoke-Agent $forcedExe @('cleanup', '--uninstall-code', $code)
    if ($cleaned.ExitCode -ne 0) { throw ('cleanup with a code failed: ' + $cleaned.Error) }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'cleanup left the service.' }
    if (Test-Task) { throw 'cleanup left the watchdog scheduled task.' }
    if (Test-HostsBlocked) { throw 'cleanup left the managed hosts block.' }
    $result.checks += $scenarios[8]

    Set-Backend 'disabled' $true
    Remove-Item -LiteralPath $uninstallJson -Force
    Install-Agent $packages[0]
    Start-Sleep -Seconds 40
    if (Test-Path -LiteralPath $uninstallJson) { throw 'The agent stored a secret although the server has no master key.' }
    Assert-Removed (Remove-Agent $packages[0] '')
    Wait-Reported 'uninstall_without_secret' 30
    $result.checks += $scenarios[9]

    Set-Backend 'disabled' $false
    Set-Backend 'acked' $false
    Install-Agent $packages[0]
    Wait-Until { Test-Armed } 120 'The agent did not store and confirm a new uninstall secret.'
    for ($attempt = 1; $attempt -le 5; $attempt++) { Assert-RemovalRefused (Remove-Agent $packages[0] $wrongCode) }
    $state = Get-State
    if ($null -eq $state.locked_until) { throw 'Five wrong codes did not lock removal.' }
    Assert-RemovalRefused (Remove-Agent $packages[0] (Get-Code ([int]$state.last_used + 1)))
    if ([int](Get-State).last_used -ne [int]$state.last_used) { throw 'A locked removal consumed a code.' }
    $result.checks += $scenarios[10]
    $result.passed = $true
} catch { $result.error = $_.Exception.Message }
finally {
    Stop-Backend
    Write-Report (Join-Path $OutputDirectory $report) $result
}
if (-not $result.passed) { exit 1 }
