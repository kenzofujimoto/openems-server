param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# Two-phase service resilience acceptance for the production MSI. Phase 1 runs on a fresh Sandbox;
# phase 2 runs after the operator restarts the Sandbox from inside it.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'openems-agent.msi'
$origin = 'http://127.0.0.1:18013'
$stateDirectory = 'C:\openems-resilience'
$reports = @('resilience-phase1.json', 'resilience-result.json')
# Unsigned packages can wait ~2 min on Windows Installer signature checks inside Sandbox.
$operationTimeout = 240
$totalTimeout = 1200
$offlineSeconds = 60
$resyncTimeout = 360
$phase1 = @('production install without fault-injection actions serves trusted HTTPS',
            'killed agent process is restarted by service recovery',
            'offline backend keeps cached enforcement and agent resynchronizes after return')
$phase2 = @('after reboot the service starts and enforces cached policy with backend offline',
            'production removal restores original trust and hosts')
if ($Plan) {
    @{ package=$package; origin=$origin; state_directory=$stateDirectory; reports=$reports; timeout_seconds=$totalTimeout
       operation_timeout_seconds=$operationTimeout; phase1=$phase1; phase2=$phase2 } | ConvertTo-Json -Depth 5
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
$bootTime = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
$marker = Join-Path $stateDirectory 'phase1.json'
$phase = if (Test-Path -LiteralPath $marker) { 2 } else { 1 }
$reportName = $reports[$phase - 1]
if (-not $SystemPhase) {
    # One run per boot: Sandbox can repeat LogonCommand, and a second run would collide on ports.
    $lock = 'C:\openems-resilience-boot-' + $bootTime.ToString('yyyyMMddHHmmss') + '.lock'
    try { [IO.File]::Open($lock, 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A resilience run already started in this Sandbox boot; wait for its result.' }
    if ($phase -eq 1) {
        if (Test-Path -LiteralPath $stateDirectory) { throw 'A previous phase 1 did not pass; use a fresh Sandbox.' }
        New-Item -ItemType Directory -Path $stateDirectory | Out-Null
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
        Set-Acl -LiteralPath $stateDirectory -AclObject $acl
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $stateDirectory
    }
    Remove-Item -LiteralPath (Join-Path $stateDirectory $reportName) -ErrorAction SilentlyContinue
    $script = Join-Path $stateDirectory 'test-resilience-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script -Force
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsResilience-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $stateDirectory + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $report = Join-Path $stateDirectory $reportName
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        while (-not (Test-Path -LiteralPath $report)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Resilience acceptance timed out. Close the Sandbox to discard changes.' }
            Start-Sleep -Milliseconds 500
        }
        $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $reportName) $result
        $result | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $result.passed) { throw ('Resilience phase ' + $phase + ' failed; private logs remain inside Sandbox.') }
        if ($phase -eq 1) { Write-Output 'Phase 1 passed. Restart the Sandbox (Start > Power > Restart), then run RUN-RESILIENCE-TEST.cmd again.' }
    }
    finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$result = [ordered]@{ phase=$phase; passed=$false; checks=@(); durations=@(); unrelated_roots_added=@(); error=$null; cleanup_errors=@() }
$backend = $null
$config = 'C:\ProgramData\openems\agent.json'
$authority = 'C:\ProgramData\openems\https\authority.json'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$requests = Join-Path $stateDirectory 'requests.log'
function Invoke-Msi([bool]$Remove, [string[]]$Properties) {
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $stateDirectory ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($operation, ('"' + (Join-Path $stateDirectory $package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
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
        $result.durations += ('{0} {1}: {2:N0} s' -f $operation, $package, ([DateTime]::UtcNow - $started).TotalSeconds)
        if (-not $finished) { throw ('MSI operation timed out; close Sandbox. Log: ' + $log) }
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
function Get-Roots { return @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint | Sort-Object) }
function Get-ManagedRoot {
    # authority.json keeps the root DER as a byte array; the private key stays DPAPI-protected.
    $saved = Get-Content -LiteralPath $authority -Raw | ConvertFrom-Json
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[byte[]]$saved.root)
    try { return $certificate.Thumbprint } finally { $certificate.Dispose() }
}
# Windows may add its own roots during a run, so only the managed root and the baseline are asserted.
function Assert-Trust([string]$Managed, $Baseline, [bool]$Trusted) {
    $current = Get-Roots
    if (@($Baseline | Where-Object { $_ -notin $current }).Count) { throw 'A pre-existing trust root was removed.' }
    if (($Managed -in $current) -ne $Trusted) { throw ('Managed root trusted state should be ' + $Trusted + '.') }
}
function Get-ServiceProcess {
    $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
    if ($null -eq $service -or $service.State -ne 'Running' -or $service.ProcessId -le 0) { return 0 }
    return [int]$service.ProcessId
}
# Returns the service PID once its own listener serves the trusted TLS page for the cached block.
function Wait-Healthy([int]$NotProcess = 0, [int]$Seconds = 60) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $processId = Get-ServiceProcess
        if ($processId -gt 0 -and $processId -ne $NotProcess) {
            $owned = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue | Where-Object OwningProcess -eq $processId)
            if ($owned.Count -and (Get-Content -LiteralPath $hosts -Raw).Contains('example.com')) {
                $client = New-Object Net.Sockets.TcpClient
                $tls = $null
                try {
                    $client.Connect('127.0.0.1', 443)
                    $tls = New-Object Net.Security.SslStream($client.GetStream(), $false)
                    $tls.ReadTimeout = 5000; $tls.WriteTimeout = 5000
                    $tls.AuthenticateAsClient('example.com')
                    $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n")
                    $tls.Write($request, 0, $request.Length)
                    $reader = New-Object IO.StreamReader($tls)
                    if ($reader.ReadToEnd().Contains('<title>Acesso bloqueado</title>')) { return $processId }
                } catch { } finally { if ($null -ne $tls) { $tls.Dispose() }; $client.Dispose() }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Service did not provide a trusted TLS block page from its own listener.'
}
function Start-Backend {
    $ready = Join-Path $stateDirectory 'backend-ready'
    Remove-Item -LiteralPath $ready -ErrorAction SilentlyContinue
    $job = Start-Job -ArgumentList $origin, $stateDirectory -ScriptBlock {
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
                # A missed line only delays detection; the agent retries every interval.
                try { Add-Content -LiteralPath (Join-Path $Work 'requests.log') -Value $path } catch { }
                $payload = @{}; $context.Response.StatusCode = 200
                switch ($path) {
                    '/fct/api/public/v1/register/' { $payload = @{ client_id='sandbox-resilience'; device_token='sandbox-fixture-only' } }
                    '/fct/api/public/v1/config/assigned/' { $payload = @{ vdom='Default'; version=1; digest='a14e792ed37e48755b1a793e203e4532bbcd4eba11e569751f8cede812040ebb'; body=@{ web_filter=@{ blocked=@('example.com') } } } }
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
function Stop-Backend($Job) {
    Stop-Job $Job -ErrorAction Continue
    Remove-Job $Job -Force -ErrorAction Continue
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    while (@(Get-NetTCPConnection -State Listen -LocalPort 18013 -ErrorAction SilentlyContinue).Count) {
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Simulated backend is still listening after stop.' }
        Start-Sleep -Milliseconds 200
    }
}
function Get-RequestCount([string]$Path) {
    if (-not (Test-Path -LiteralPath $requests)) { return 0 }
    # Shared read so the backend job can keep appending.
    $stream = [IO.File]::Open($requests, 'Open', 'Read', 'ReadWrite')
    try { $lines = (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`r?`n" } finally { $stream.Dispose() }
    return @($lines | Where-Object { $_ -eq $Path }).Count
}
$baselineRoots = $null
$managedRoot = $null
try {
    if ($phase -eq 1) {
        if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
        if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
        foreach ($port in @(80, 443, 18013)) {
            $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
            try { $probe.Start() } finally { $probe.Stop() }
        }
        Assert-ProductionPackage ([string](Join-Path $stateDirectory $package))
        $baselineRoots = Get-Roots
        $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
        $backend = Start-Backend
        Invoke-Msi $false @('SERVER=' + $origin, 'BLOCKPAGEHTTPS=1')
        $processId = Wait-Healthy
        $managedRoot = Get-ManagedRoot
        if ($managedRoot -in $baselineRoots) { throw 'Managed root was already trusted before installation.' }
        Assert-Trust $managedRoot $baselineRoots $true
        $result.checks += $phase1[0]

        Stop-Process -Id $processId -Force
        $processId = Wait-Healthy -NotProcess $processId -Seconds 90
        $result.checks += $phase1[1]

        Stop-Backend $backend
        $backend = $null
        Start-Sleep -Seconds $offlineSeconds
        if ((Wait-Healthy -Seconds 30) -ne $processId) { throw 'Agent process changed while the backend was offline.' }
        $before = Get-RequestCount '/fct/api/public/v1/config/assigned/'
        $backend = Start-Backend
        $deadline = [DateTime]::UtcNow.AddSeconds($resyncTimeout)
        while ((Get-RequestCount '/fct/api/public/v1/config/assigned/') -le $before) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Agent did not resynchronize after the backend returned.' }
            Start-Sleep -Seconds 1
        }
        Wait-Healthy | Out-Null
        $result.checks += $phase1[2]

        # Phase 2 must prove offline startup from cache, so the backend stays down across the restart.
        Stop-Backend $backend
        $backend = $null
        @{ boot_time=$bootTime.ToString('o'); managed_root=$managedRoot; baseline_roots=$baselineRoots; baseline_hosts=$baselineHosts
           authority_hash=(Get-FileHash -LiteralPath $authority).Hash } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $marker -Encoding UTF8
        $result.passed = $true
    } else {
        $saved = Get-Content -LiteralPath $marker -Raw | ConvertFrom-Json
        $baselineRoots = @($saved.baseline_roots)
        $managedRoot = $saved.managed_root
        $savedBoot = [DateTime]::Parse([string]$saved.boot_time, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind)
        if ($bootTime -le $savedBoot.ToUniversalTime()) { throw 'Sandbox was not restarted since phase 1.' }
        if (@(Get-NetTCPConnection -State Listen -LocalPort 18013 -ErrorAction SilentlyContinue).Count) { throw 'Backend port is in use; phase 2 requires it offline.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
        if ($null -eq $service -or $service.StartMode -ne 'Auto') { throw 'Service is missing or not configured for automatic start.' }
        Wait-Healthy -Seconds 120 | Out-Null
        Assert-Trust $managedRoot $baselineRoots $true
        if ((Get-FileHash -LiteralPath $authority).Hash -ne $saved.authority_hash) { throw 'Reboot changed private authority.' }
        $result.checks += $phase2[0]

        Invoke-Msi $true @()
        if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Uninstalled service still exists.' }
        Assert-Trust $managedRoot $baselineRoots $false
        if ((Get-FileHash -LiteralPath $hosts).Hash -ne $saved.baseline_hosts) { throw 'Uninstall did not restore hosts.' }
        $result.checks += $phase2[1]
        $result.passed = $true
    }
} catch { $result.error = $_.Exception.Message }
finally {
    if ($null -ne $baselineRoots) {
        $result.unrelated_roots_added = @(Get-Roots | Where-Object { $_ -notin $baselineRoots -and $_ -ne $managedRoot })
    }
    if ($null -ne $backend) { Stop-Job $backend -ErrorAction Continue; Remove-Job $backend -Force -ErrorAction Continue }
    Write-Report (Join-Path $OutputDirectory $reportName) $result
}
if (-not $result.passed) { exit 1 }
