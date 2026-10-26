param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# F5 part 5c acceptance (session-component.md) for the production MSI in Windows Sandbox, in two phases:
# phase 1 checks the session component and leaves the service disabled in the registry; the operator then
# restarts the Sandbox from inside it and runs the same command again for phase 2.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
function Export-Diagnostics {
    param([string]$Source, [string]$Destination, [string]$AgentLog = 'C:\ProgramData\openems\agent.log')
    $target = Join-Path $Destination ('session-diagnostics-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss-fff'))
    New-Item -ItemType Directory -Path $target -Force | Out-Null
    Get-ChildItem -LiteralPath $Source -Filter '*.log' -File |
        Copy-Item -Destination $target -Force
    if (Test-Path -LiteralPath $AgentLog) {
        Copy-Item -LiteralPath $AgentLog -Destination (Join-Path $target 'agent.log') -Force
    }
}
$packages = @('openems-agent.msi', 'openems-agent-next.msi')
$origin = 'http://127.0.0.1:18015'
$stateDirectory = 'C:\openems-session'
$reports = @('session-phase1.json', 'session-result.json')
$component = 'openems-session.exe'
$application = 'openems-test-app.exe'
$serviceKey = 'HKLM:\SYSTEM\CurrentControlSet\Services\openems-agent'
$operationTimeout = 240
$totalTimeout = 1500
$policy = [ordered]@{ vdom='Default'; version=1; digest='fb002d429fb6fe0c4029c55f61ca6bab872ce0e77b0cff0e7e2dccfaf6f48da3'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@('tamper.example') }
                                       app_control=[ordered]@{ blocked=@($application) } } }
$phase1 = @('after install the session component runs in the user session',
            'a killed component is opened again by the service',
            'a closed application reaches the session board as a notice',
            'upgrade with the component open needs no reboot and reopens it',
            'the service is disabled in the registry and stopped before the reboot')
$phase2 = @('after reboot the scheduled watchdog restores automatic start, starts the service and reports it',
            'after reboot the session component runs in the user session again',
            'removal closes the component and deletes its executable')
if ($Plan) {
    @{ packages=$packages; origin=$origin; state_directory=$stateDirectory; reports=$reports; timeout_seconds=$totalTimeout
       policy=$policy; phase1=$phase1; phase2=$phase2 } | ConvertTo-Json -Depth 10
    exit 0
}
$executionService = Get-Service -Name CExecSvc -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -or $null -eq $executionService -or $executionService.Status -ne 'Running') {
    throw 'This acceptance harness requires Windows Sandbox.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Sandbox acceptance requires Administrator rights.' }
function Write-Report([string]$Path, $Value, [switch]$SharedFolder) {
    $temporary = $Path + '.tmp'
    try {
        $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
        # VSMB shared folders cannot atomically replace an existing destination with Move-Item.
        if ($SharedFolder) { Copy-Item -LiteralPath $temporary -Destination $Path -Force }
        else { Move-Item -LiteralPath $temporary -Destination $Path -Force }
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
$marker = Join-Path $stateDirectory 'phase1.json'
$phase = if (Test-Path -LiteralPath $marker) { 2 } else { 1 }
$reportName = $reports[$phase - 1]
if (-not $SystemPhase) {
    # One run per boot: a second run would collide on the port and the installed product.
    $lock = 'C:\openems-session-boot-' + $bootTime.ToString('yyyyMMddHHmmss') + '.lock'
    try { [IO.File]::Open($lock, 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A session run already started in this Sandbox boot; wait for its result.' }
    if ($phase -eq 1) {
        if (Test-Path -LiteralPath $stateDirectory) { throw 'A previous phase 1 did not pass; use a fresh Sandbox.' }
        New-Item -ItemType Directory -Path $stateDirectory | Out-Null
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        Set-Acl -LiteralPath $stateDirectory -AclObject $acl
        foreach ($package in $packages) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $stateDirectory }
    }
    Remove-Item -LiteralPath (Join-Path $stateDirectory $reportName) -ErrorAction SilentlyContinue
    $script = Join-Path $stateDirectory 'test-session-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script -Force
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsSession-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $stateDirectory + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $report = Join-Path $stateDirectory $reportName
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        Write-Host ('Session acceptance phase ' + $phase + ' running. Leave this window open.')
        while (-not (Test-Path -LiteralPath $report)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Session acceptance timed out. Close the Sandbox to discard changes.' }
            Start-Sleep -Milliseconds 500
        }
        $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $reportName) $result -SharedFolder
        $result | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $result.passed) { throw ('Session phase ' + $phase + ' failed; logs remain in ' + $stateDirectory + '.') }
        if ($phase -eq 1) { Write-Output 'Phase 1 passed. Restart the Sandbox now (Start > Power > Restart), then run RUN-SESSION-TEST.cmd again.' }
    }
    finally {
        try { Export-Diagnostics -Source $stateDirectory -Destination $OutputDirectory }
        catch { Write-Warning ('Could not export acceptance diagnostics: ' + $_.Exception.Message) }
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue
    }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$result = [ordered]@{ phase=$phase; passed=$false; checks=@(); durations=@(); error=$null }
$backend = $null
$work = $stateDirectory
$policyFile = Join-Path $work 'policy.json'
$board = 'C:\ProgramData\openems\session.json'
$installedComponent = 'C:\Program Files\openems\' + $component
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
        if (-not $finished) { throw ('MSI operation timed out; close Sandbox. Log: ' + $log) }
        # 3010 means the files were in use and Windows wants a reboot: the component must never cause it.
        if ($process.ExitCode -eq 3010) { throw ('MSI asked for a reboot (3010); a file stayed in use. Log: ' + $log) }
        if ($process.ExitCode -ne 0) { throw ('Unexpected MSI exit code: ' + $process.ExitCode + '. Log: ' + $log) }
    } finally { $process.Dispose() }
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
function Get-StartMode {
    $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
    if ($null -eq $service) { return '' }
    return [string]$service.StartMode
}
# The Sandbox user's desktop session: the one that runs explorer.exe.
function Get-UserSession {
    $explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue | Where-Object { $_.SessionId -ne 0 })
    if ($explorer.Count -eq 0) { return -1 }
    return [int]$explorer[0].SessionId
}
function Get-ComponentIds {
    $session = Get-UserSession
    return @(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($component)) -ErrorAction SilentlyContinue |
        Where-Object { $_.SessionId -eq $session } | ForEach-Object Id)
}
function Get-Board {
    try { return (Get-Content -LiteralPath $board -Raw -ErrorAction Stop | ConvertFrom-Json) } catch { return $null }
}
function Get-ReportedKinds {
    $log = Join-Path $work 'tamper.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $stream = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
    try { $lines = (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`r?`n" } finally { $stream.Dispose() }
    return @($lines | Where-Object { $_ } | ForEach-Object { @(($_ | ConvertFrom-Json).events) } | ForEach-Object { [string]$_.kind })
}
# Simulated EMS backend: assigned policy and tamper uploads recorded one per line; no uninstall codes.
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
                # Short waits keep Stop-Job effective; a blocking GetContext delays cleanup.
                $pending = $listener.GetContextAsync()
                while (-not $pending.Wait(500)) { }
                $context = $pending.Result
                $path = $context.Request.Url.AbsolutePath
                $context.Response.StatusCode = 200
                $payload = @{}
                switch ($path) {
                    '/fct/api/public/v1/register/' { $payload = @{ client_id='sandbox-session'; device_token='sandbox-fixture-only' } }
                    '/fct/api/public/v1/config/assigned/' { $payload = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json }
                    '/fct/api/public/v1/tamper/' {
                        $reader = New-Object IO.StreamReader($context.Request.InputStream, [Text.Encoding]::UTF8)
                        try { $upload = $reader.ReadToEnd() } finally { $reader.Dispose() }
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

try {
    if ($phase -eq 1) {
        if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, 18015)
        try { $probe.Start() } finally { $probe.Stop() }
        foreach ($package in $packages) { Assert-ProductionPackage ([string](Join-Path $work $package)) }
        if ((Get-UserSession) -lt 1) { throw 'No interactive user session found (explorer.exe).' }
        $policy | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding UTF8
        $backend = Start-Backend

        Invoke-Msi '/i' $packages[0] @('SERVER=' + $origin)
        Wait-Until { (Get-ServiceProcess) -gt 0 } 120 'The service did not start.'
        Wait-Until { @(Get-ComponentIds).Count -eq 1 } 60 'The session component did not start in the user session.'
        $result.checks += $phase1[0]

        $first = @(Get-ComponentIds)[0]
        Stop-Process -Id $first -Force
        Wait-Until { $ids = @(Get-ComponentIds); $ids.Count -eq 1 -and $ids[0] -ne $first } 45 'The killed component was not opened again.'
        $result.checks += $phase1[1]

        $dummy = Join-Path $work $application
        Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\PING.EXE') -Destination $dummy
        $victim = Start-Process -FilePath $dummy -ArgumentList @('-n', '300', '127.0.0.1') -PassThru -WindowStyle Hidden
        Wait-Until { $victim.HasExited } 60 'The blocked application was not closed.'
        Wait-Until {
            $state = Get-Board
            $null -ne $state -and @($state.notices | Where-Object { $_.kind -eq 'app_closed' -and $_.text -like ('*' + $application + '*') }).Count -ge 1
        } 30 'The closed application did not reach the session board.'
        $result.checks += $phase1[2]

        Invoke-Msi '/i' $packages[1] @()
        Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ComponentIds).Count -eq 1 } 90 'The upgraded agent did not reopen the component.'
        $result.checks += $phase1[3]

        # With SYSTEM rights (or ownership taken) the start type can be changed in the registry directly.
        Set-ItemProperty -LiteralPath $serviceKey -Name Start -Value 4
        & (Join-Path $env:SystemRoot 'System32\sc.exe') stop openems-agent | Out-Null
        Wait-Until { (Get-ServiceProcess) -eq 0 } 60 'The service did not stop.'
        Set-ItemProperty -LiteralPath $serviceKey -Name Start -Value 4
        Set-Content -LiteralPath $marker -Value (@{ stopped_at=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json)
        $result.checks += $phase1[4]
    } else {
        $policy | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding UTF8
        $backend = Start-Backend
        Wait-Until { (Get-ServiceProcess) -gt 0 -and (Get-StartMode) -eq 'Auto' } 420 'After reboot the watchdog did not restore and start the service.'
        Wait-Until { 'service_started_by_watchdog' -in @(Get-ReportedKinds) } 420 'The backend did not receive service_started_by_watchdog.'
        $result.checks += $phase2[0]

        if ((Get-UserSession) -lt 1) { throw 'No interactive user session found after reboot (explorer.exe).' }
        Wait-Until { @(Get-ComponentIds).Count -eq 1 } 60 'After reboot the session component did not start.'
        $result.checks += $phase2[1]

        Invoke-Msi '/x' $packages[1] @()
        if (@(Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($component)) -ErrorAction SilentlyContinue).Count) { throw 'Removal left the session component running.' }
        if (Test-Path -LiteralPath $installedComponent) { throw 'Removal left the session component executable.' }
        if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Removal left the service.' }
        $result.checks += $phase2[2]
    }
    $result.passed = $true
} catch { $result.error = $_.Exception.Message }
finally {
    if ($null -ne $backend) { Stop-Job $backend -ErrorAction Continue; Remove-Job $backend -Force -ErrorAction Continue }
    Write-Report (Join-Path $OutputDirectory $reportName) $result
}
if (-not $result.passed) { exit 1 }
