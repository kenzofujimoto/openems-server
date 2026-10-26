param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# F6 production acceptance. Only the location definitions change: the Sandbox network stays intact.
# Real adapter addresses/gateway MACs drive the installed agent's decision, including offline restart.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Export-Diagnostics {
    param([string]$Source, [string]$Destination, [string]$AgentLog = 'C:\ProgramData\openems\agent.log')
    $target = Join-Path $Destination ('locations-diagnostics-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Filter '*.log' -File |
        Copy-Item -Destination $target -Force
    if (Test-Path -LiteralPath $AgentLog) {
        Copy-Item -LiteralPath $AgentLog -Destination (Join-Path $target 'agent.log') -Force
    }
}
$package = 'openems-agent.msi'
$origin = 'http://127.0.0.1:18016'
$report = 'locations-result.json'
$domain = 'example.org'
$operationTimeout = 240
$totalTimeout = 1200
$outside = [ordered]@{ vdom='Default'; version=1; digest='3e7d60464d0fee890f535cd52a550bc58ebd1a312451e72cf545b7e6ca09e2f8'
                       body=[ordered]@{ web_filter=[ordered]@{ blocked=@('example.org') } } }
$inside = [ordered]@{ vdom='Office'; version=1; digest='438ba0c11d3c7fe4f7255b3c137af7b0b6634823b8c8e928d94d822de2277c53'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@() } } }
$scenarios = @('outside policy blocks through system DNS after production installation',
               'real CIDR and gateway MAC select the inside policy and permit the domain',
               'ACK identifies the inside policy and location; the session notice announces entry',
               'same CIDR with a different gateway MAC selects outside within one synchronization cycle',
               'ACK identifies the outside policy and an empty location; the session notice announces departure',
               'offline service restart preserves the outside policy and cached definitions',
               'matching definitions select inside again and offline restart still uses local signals',
               'removal restores hosts and unrelated NRPT rules and leaves working upstream DNS')
if ($Plan) {
    @{ package=$package; origin=$origin; report=$report; timeout_seconds=$totalTimeout
       outside=$outside; inside=$inside; scenarios=$scenarios } | ConvertTo-Json -Depth 12
    exit 0
}
# All mutations are below this gate, including directory creation and the SYSTEM task.
$executionService = Get-Service -Name CExecSvc -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -or $null -eq $executionService -or $executionService.Status -ne 'Running') {
    throw 'This acceptance harness requires Windows Sandbox.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Sandbox acceptance requires Administrator rights.' }
function Write-Report([string]$Path, $Value) {
    $temporary = $Path + '.tmp'
    $Value | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}
if (-not $SystemPhase) {
    try { [IO.File]::Open('C:\openems-locations-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A locations acceptance run already started; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-locations-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work
    $script = Join-Path $work 'test-locations-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsLocations-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $resultPath = Join-Path $work $report
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        Write-Host 'Locations acceptance running as SYSTEM. Leave this window open.'
        while (-not (Test-Path -LiteralPath $resultPath)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Locations acceptance timed out. Close Sandbox to discard changes.' }
            Start-Sleep -Milliseconds 500
        }
        $outcome = Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $outcome
        $outcome | ConvertTo-Json -Depth 12 | Write-Output
        if (-not $outcome.passed) { throw ('Locations acceptance failed. Logs remain in ' + $work + '.') }
    } finally {
        try { Export-Diagnostics -Source $work -Destination $OutputDirectory }
        catch { Write-Warning ('Could not export acceptance diagnostics: ' + $_.Exception.Message) }
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue
    }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$work = $OutputDirectory
$policyFile = Join-Path $work 'policy.json'
$board = 'C:\ProgramData\openems\session.json'
$stateFile = 'C:\ProgramData\openems\state.json'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$comment = 'openems-agent managed DNS filter'
$result = [ordered]@{ passed=$false; checks=@(); durations=@(); transitions=@(); signals=$null; error=$null }
$backend = $null
function Record-Check([int]$Index) {
    $result.checks += $scenarios[$Index]
    Write-Report (Join-Path $work 'locations-progress.json') $result
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Failure) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Failure
}
function Get-ServiceProcess {
    $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) { return 0 }
    return [int]$service.ProcessId
}
function Get-NrptNames { return @(Get-DnsClientNrptRule | ForEach-Object Name | Sort-Object) }
function Get-ManagedRules { return @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $comment }) }
function Resolve-System {
    Clear-DnsClientCache
    try {
        return @(Resolve-DnsName -Name $domain -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
            Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
    } catch { return @() }
}
function Test-Blocked {
    $addresses = @(Resolve-System)
    return $addresses.Count -eq 1 -and $addresses[0] -eq '0.0.0.0'
}
function Test-Upstream {
    $addresses = @(Resolve-System)
    return $addresses.Count -gt 0 -and @($addresses | Where-Object { $_ -in @('0.0.0.0', '127.0.0.1') }).Count -eq 0
}
function Get-LocalSignals {
    $routes = @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 |
        Where-Object { $_.NextHop -ne '0.0.0.0' } | Sort-Object RouteMetric)
    foreach ($route in $routes) {
        $addresses = @(Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 |
            Where-Object { $_.AddressState -eq 'Preferred' -and $_.IPAddress -notlike '169.254.*' })
        if ($addresses.Count -eq 0) { continue }
        # The agent reads ARP/ND passively; benign traffic ensures the gateway has a neighbor entry.
        & (Join-Path $env:SystemRoot 'System32\PING.EXE') -n 1 -w 1000 $route.NextHop | Out-Null
        $neighbors = @(Get-NetNeighbor -InterfaceIndex $route.InterfaceIndex -IPAddress $route.NextHop -ErrorAction SilentlyContinue |
            Where-Object { $_.LinkLayerAddress -match '^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$' -and $_.LinkLayerAddress -ne '00-00-00-00-00-00' })
        if ($neighbors.Count -eq 0) { continue }
        return @{ cidr=([string]$addresses[0].IPAddress + '/' + [string]$addresses[0].PrefixLength)
                  gateway_mac=[string]$neighbors[0].LinkLayerAddress; gateway=[string]$route.NextHop }
    }
    return $null
}
function Set-LocationPolicy([bool]$Matches) {
    $mac = if ($Matches) { [string]$result.signals.gateway_mac } else { '02-00-00-00-00-01' }
    $normalizedReal = ([string]$result.signals.gateway_mac).Replace('-', '').Replace(':', '').ToLowerInvariant()
    if (-not $Matches -and $mac.Replace('-', '') -eq $normalizedReal) { $mac = '02-00-00-00-00-02' }
    $assignment = [ordered]@{ vdom=$outside.vdom; version=$outside.version; digest=$outside.digest; body=$outside.body
        locations=@(@{ id='sandbox-office'; name='Sandbox Office'; cidrs=@($result.signals.cidr)
                       gateway_macs=@($mac); dns_suffixes=@(); public_cidrs=@(); probe=$null; assignment=$inside }) }
    Write-Report $policyFile $assignment
    return $mac
}
function Test-CachedGateway([string]$Mac) {
    try {
        $saved = Get-Content -LiteralPath $stateFile -Raw | ConvertFrom-Json
        return @($saved.profile.locations | Where-Object { $_.id -eq 'sandbox-office' -and $_.gateway_macs -contains $Mac }).Count -eq 1
    } catch { return $false }
}
function Get-Notices {
    try { return @((Get-Content -LiteralPath $board -Raw | ConvertFrom-Json).notices) }
    catch { return @() }
}
function Get-Acks {
    $log = Join-Path $work 'ack.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $stream = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
    try { $lines = (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`r?`n" } finally { $stream.Dispose() }
    return @($lines | Where-Object { $_ } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Test-Ack([string]$Vdom, [string]$Location, [int]$After) {
    $rows = @(Get-Acks | Select-Object -Skip $After)
    return @($rows | Where-Object { $_.success -eq $true -and $_.vdom -eq $Vdom -and $_.location -eq $Location }).Count -gt 0
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
            $listener.Start()
            Set-Content -LiteralPath (Join-Path $Work 'backend-ready') -Value ready
            while ($true) {
                $pending = $listener.GetContextAsync()
                while (-not $pending.Wait(500)) { }
                $context = $pending.Result
                $reader = New-Object IO.StreamReader($context.Request.InputStream, [Text.Encoding]::UTF8)
                try { $upload = $reader.ReadToEnd() } finally { $reader.Dispose() }
                $path = $context.Request.Url.AbsolutePath.Replace('/fct/api/public/v1/', '').Trim('/')
                $payload = @{}; $context.Response.StatusCode = 200
                switch ($path) {
                    'register' { $payload = @{ client_id='sandbox-locations'; device_token='sandbox-fixture-only' } }
                    'config/assigned' { $payload = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json }
                    'config/ack' { Add-Content -LiteralPath (Join-Path $Work 'ack.log') -Value ($upload -replace "`r?`n", ' ') }
                    'host_tags' { }
                    'messages/pull' { }
                    'refresh' { }
                    'events' { $payload = @{ accepted=0; rejected=0 } }
                    'tamper' { $payload = @{ accepted=0; rejected=0 } }
                    default { $context.Response.StatusCode = 404 }
                }
                $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 12 -Compress))
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
function Stop-Backend($Job) {
    Stop-Job $Job -ErrorAction Stop
    Remove-Job $Job -Force -ErrorAction Stop
    Wait-Until { @(Get-NetTCPConnection -State Listen -LocalPort 18016 -ErrorAction SilentlyContinue).Count -eq 0 } 15 'Simulated backend is still listening after stop.'
}
function Assert-ProductionPackage([string]$Path) {
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
function Invoke-Msi([bool]$Remove, [string[]]$Properties) {
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($operation, ('"' + (Join-Path $work $package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = Join-Path $env:SystemRoot 'System32\msiexec.exe'
    $start.Arguments = $arguments -join ' '; $start.UseShellExecute = $false; $start.CreateNoWindow = $true
    $started = [DateTime]::UtcNow
    $process = [Diagnostics.Process]::Start($start)
    try {
        if (-not $process.WaitForExit($operationTimeout * 1000)) { throw ('MSI operation timed out; discard Sandbox. Log: ' + $log) }
        $result.durations += ('{0}: {1:N0} s' -f $operation, ([DateTime]::UtcNow - $started).TotalSeconds)
        if ($process.ExitCode -ne 0) { throw ('Unexpected MSI exit code ' + $process.ExitCode + '. Log: ' + $log) }
    } finally { $process.Dispose() }
}
try {
    if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
    foreach ($port in @(53, 18016)) {
        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    Wait-Until { Test-Upstream } 60 'Upstream DNS cannot resolve example.org before installation; enable Sandbox networking.'
    Wait-Until { $result.signals = Get-LocalSignals; $null -ne $result.signals } 60 'No active IPv4 adapter and resolved gateway MAC found.'
    Assert-ProductionPackage ([string](Join-Path $work $package))
    $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
    $baselineRules = @(Get-NrptNames)
    $wrongMac = Set-LocationPolicy $false
    $backend = Start-Backend
    Invoke-Msi $false @('SERVER=' + $origin, 'DNSFILTER=1')
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked) } 120 'The outside policy did not block through system DNS.'
    $config = Get-Content -LiteralPath 'C:\ProgramData\openems\agent.json' -Raw | ConvertFrom-Json
    $transitionLimit = [int]$config.interval + 10
    Record-Check 0

    $beforeAck = @(Get-Acks).Count
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $rightMac = Set-LocationPolicy $true
    Wait-Until { Test-Upstream } $transitionLimit 'The real CIDR and gateway MAC did not select the inside policy within one cycle.'
    $result.transitions += @{ direction='inside'; elapsed_seconds=$watch.Elapsed.TotalSeconds; limit_seconds=$transitionLimit }
    Record-Check 1
    Wait-Until { Test-Ack 'Office' 'sandbox-office' $beforeAck } 30 'ACK did not identify the inside policy and location.'
    Wait-Until { @(Get-Notices | Where-Object { $_.text -like 'Rede da empresa*' }).Count -gt 0 } 30 'Session notice did not announce office entry.'
    Record-Check 2

    $beforeAck = @(Get-Acks).Count
    $beforeNotice = @(Get-Notices | ForEach-Object id | Measure-Object -Maximum).Maximum
    $watch.Restart()
    $wrongMac = Set-LocationPolicy $false
    Wait-Until { Test-Blocked } $transitionLimit 'The same CIDR with a mismatched gateway did not return to the outside policy within one cycle.'
    $result.transitions += @{ direction='outside'; elapsed_seconds=$watch.Elapsed.TotalSeconds; limit_seconds=$transitionLimit }
    Record-Check 3
    Wait-Until { Test-Ack 'Default' '' $beforeAck } 30 'ACK did not identify the outside policy and empty location.'
    Wait-Until { @(Get-Notices | Where-Object { $_.id -gt $beforeNotice -and $_.text -like 'Fora da rede da empresa*' }).Count -gt 0 } 30 'Session notice did not announce office departure.'
    Record-Check 4

    Wait-Until { Test-CachedGateway $wrongMac } 30 'Outside policy did not persist its network definitions.'
    Stop-Backend $backend; $backend = $null
    $previous = Get-ServiceProcess
    Restart-Service -Name openems-agent
    Wait-Until { $current = Get-ServiceProcess; $current -gt 0 -and $current -ne $previous -and (Test-Blocked) } 90 'Offline restart did not preserve the outside policy.'
    Record-Check 5

    $rightMac = Set-LocationPolicy $true
    $backend = Start-Backend
    Wait-Until { (Test-Upstream) -and (Test-CachedGateway $rightMac) } 120 'The agent did not recover the inside policy after reconnecting.'
    Stop-Backend $backend; $backend = $null
    $previous = Get-ServiceProcess
    Restart-Service -Name openems-agent
    Wait-Until { $current = Get-ServiceProcess; $current -gt 0 -and $current -ne $previous -and (Test-Upstream) } 90 'Offline restart did not reselect the inside policy from local signals.'
    Record-Check 6

    Invoke-Msi $true @()
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Removal left the service.' }
    if (@(Get-ManagedRules).Count -ne 0) { throw 'Removal left managed NRPT rules.' }
    if ((@($baselineRules) -join ',') -ne (@(Get-NrptNames) -join ',')) { throw 'Removal changed unrelated NRPT rules.' }
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) { throw 'Removal did not restore hosts.' }
    if (-not (Test-Upstream)) { throw 'Upstream DNS did not work after removal.' }
    Record-Check 7
    $result.passed = $true
} catch { $result.error = $_.Exception.Message }
finally {
    if ($null -ne $backend) { Stop-Job $backend -ErrorAction Continue; Remove-Job $backend -Force -ErrorAction Continue }
    Write-Report (Join-Path $OutputDirectory $report) $result
}
if (-not $result.passed) { exit 1 }
