param(
    [string]$OutputDirectory = 'C:\openems-results',
    [switch]$SystemPhase,
    [switch]$Plan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$origin = 'http://127.0.0.1:18013'
$blocked = @{
    vdom = 'Default'; version = 1
    body = @{ web_filter = @{ blocked = @('example.com') } }
    digest = 'a14e792ed37e48755b1a793e203e4532bbcd4eba11e569751f8cede812040ebb'
}
$release = @{ vdom = 'Default'; version = 0; digest = ''; body = $null; unassigned = $true }
if ($Plan) {
    @{ origin = $origin; blocked_assignment = $blocked; release_assignment = $release } | ConvertTo-Json -Depth 8
    exit 0
}

$executionService = Get-Service -Name 'CExecSvc' -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath 'C:\Users\WDAGUtilityAccount') -or
    $null -eq $executionService -or $executionService.Status -ne 'Running') {
    throw 'This acceptance harness requires Windows Sandbox.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Sandbox acceptance requires Administrator rights.'
}

function Write-Report([string]$Path, $Value) {
    $temporary = $Path + '.tmp'
    $Value | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $temporary -Encoding UTF8
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Test-LocalTls([string]$ServerName) {
    $socket = New-Object Net.Sockets.TcpClient
    $tls = $null
    try {
        $socket.Connect('127.0.0.1', 443)
        $socket.ReceiveTimeout = 5000
        $socket.SendTimeout = 5000
        # No validation callback: use Windows trust and hostname validation.
        $tls = New-Object Net.Security.SslStream($socket.GetStream(), $false)
        $tls.ReadTimeout = 5000
        $tls.WriteTimeout = 5000
        $tls.AuthenticateAsClient($ServerName)
        $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $ServerName`r`nConnection: close`r`n`r`n")
        $tls.Write($request, 0, $request.Length)
        $reader = New-Object IO.StreamReader($tls)
        $response = $reader.ReadToEnd()
        if (-not $response.Contains('<title>Acesso bloqueado</title>')) { throw 'TLS response is not the block page.' }
        return $true
    }
    catch { return $false }
    finally {
        if ($null -ne $tls) { $tls.Dispose() }
        $socket.Dispose()
    }
}

if (-not $SystemPhase) {
    $work = Join-Path 'C:\' ('openems-browser-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'openems-agent.exe') -Destination $work
    $workScript = Join-Path $work 'test-https-browser-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $workScript
    $task = 'OpenemsBrowser-' + [Guid]::NewGuid().ToString('N')
    $arguments = '-NoProfile -ExecutionPolicy Bypass -File "' + $workScript + '" -SystemPhase -OutputDirectory "' + $work + '"'
    $readyPath = Join-Path $work 'ready.json'
    $finalPath = Join-Path $work 'browser-result.json'
    try {
        $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        Register-ScheduledTask -TaskName $task -Action $action -User 'SYSTEM' -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $deadline = [DateTime]::UtcNow.AddSeconds(60)
        while (-not (Test-Path -LiteralPath $readyPath)) {
            if (Test-Path -LiteralPath $finalPath) { throw (Get-Content -LiteralPath $finalPath -Raw) }
            if ([DateTime]::UtcNow -ge $deadline) { throw 'HTTPS preparation timed out.' }
            Start-Sleep -Milliseconds 250
        }
        $tlsAccepted = $false
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while ([DateTime]::UtcNow -lt $deadline -and -not $tlsAccepted) {
            $tlsAccepted = Test-LocalTls 'example.com'
            if (-not $tlsAccepted) { Start-Sleep -Milliseconds 500 }
        }
        if (-not $tlsAccepted) { throw 'Trusted TLS block page failed.' }
        if (Test-LocalTls 'allowed.invalid') { throw 'Unblocked SNI unexpectedly received a trusted block page.' }
        Write-Report (Join-Path $OutputDirectory 'browser-ready.json') @{ trusted_tls = $true; origin = $origin; simulated_policy = $true }
        $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
        if (-not (Test-Path -LiteralPath $edge)) { throw 'Edge executable not found.' }
        Start-Process -FilePath $edge -ArgumentList '--inprivate', 'https://example.com/' | Out-Null
        $answer = Read-Host 'Does Edge show the RSM page without a certificate warning? Type YES or NO, then Enter'
        if ($answer -ne 'YES') { throw 'Browser acceptance was not confirmed.' }
        Set-Content -LiteralPath (Join-Path $work 'revoke') -Value 'release'
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath (Join-Path $work 'release-acknowledged'))) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Agent did not acknowledge applying the released policy.' }
            Start-Sleep -Milliseconds 250
        }
        if (Test-LocalTls 'example.com') { throw 'Revoked domain still receives the block page.' }
        $ready = Get-Content -LiteralPath $readyPath -Raw | ConvertFrom-Json
        Get-Process -Id $ready.agent_pid -ErrorAction Stop | Out-Null
        $connection = New-Object Net.Sockets.TcpClient
        try { $connection.Connect('127.0.0.1', 443) } finally { $connection.Dispose() }
        $http = [Net.WebRequest]::Create('http://127.0.0.1/')
        $http.Proxy = $null
        $http.Timeout = 5000
        $httpResponse = $http.GetResponse()
        try {
            $reader = New-Object IO.StreamReader($httpResponse.GetResponseStream())
            if (-not $reader.ReadToEnd().Contains('<title>Acesso bloqueado</title>')) { throw 'Agent HTTP listener is not healthy.' }
        }
        finally { $httpResponse.Close() }
        Write-Report (Join-Path $work 'observations.json') @{ trusted_tls = $true; edge_confirmed = $true; revocation = $true }
    }
    finally {
        Set-Content -LiteralPath (Join-Path $work 'stop') -Value 'cleanup'
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $finalPath) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 250 }
        if (Test-Path -LiteralPath $finalPath) {
            Copy-Item -LiteralPath $finalPath -Destination (Join-Path $OutputDirectory 'browser-result.json')
            Get-Content -LiteralPath $finalPath -Raw | Write-Output
        }
        else { Write-Warning 'Cleanup did not report completion. Close this Sandbox to discard its trust and hosts changes.' }
        Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue
    }
    $final = Get-Content -LiteralPath $finalPath -Raw | ConvertFrom-Json
    if (-not $final.passed) { throw 'Browser acceptance failed; inspect browser-result.json.' }
    exit 0
}

if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$binary = Join-Path $PSScriptRoot 'openems-agent.exe'
$config = Join-Path $PSScriptRoot 'agent.json'
$agentProcess = $null
$listener = $null
$beforeRoots = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
$hostsPath = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$beforeHostsHash = (Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash
$result = [ordered]@{ passed = $false; simulated_policy = $true; checks = @(); error = $null; cleanup_errors = @() }
function Invoke-Agent([string[]]$AgentArguments) {
    $output = & $binary @AgentArguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw ('Agent failed: ' + ($output -join "`n")) }
}
try {
    foreach ($port in @(80, 443, 18013)) {
        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    Invoke-Agent @('configure', '--config-path', $config, '--server', $origin, '--devid', 'sandbox-browser',
        '--block-page', '--block-page-https', '--interval', '1')
    Invoke-Agent @('install-block-page-trust', '--config', $config)
    $listener = New-Object Net.HttpListener
    $listener.Prefixes.Add($origin + '/')
    $listener.Start()
    $agentProcess = Start-Process -FilePath $binary -ArgumentList 'run', '--config', $config -PassThru -WindowStyle Hidden `
        -RedirectStandardOutput (Join-Path $PSScriptRoot 'agent.stdout.log') -RedirectStandardError (Join-Path $PSScriptRoot 'agent.stderr.log')
    Write-Report (Join-Path $PSScriptRoot 'ready.json') @{ ready = $true; agent_pid = $agentProcess.Id }
    $deadline = [DateTime]::UtcNow.AddMinutes(10)
    $pending = $listener.GetContextAsync()
    while (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'stop'))) {
        if ($agentProcess.HasExited) { throw 'Native agent exited; inspect local agent logs.' }
        if ([DateTime]::UtcNow -ge $deadline) { throw 'Browser acceptance exceeded ten minutes.' }
        if (-not $pending.Wait(100)) { continue }
        $context = $pending.Result
        $path = $context.Request.Url.AbsolutePath
        $context.Response.StatusCode = 200
        $payload = @{}
        switch ($path) {
            '/fct/api/public/v1/register/' { $payload = @{ client_id = 'sandbox-browser'; device_token = 'sandbox-fixture-only' } }
            '/fct/api/public/v1/config/assigned/' {
                if (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'revoke')) {
                    $payload = $release
                    Set-Content -LiteralPath (Join-Path $PSScriptRoot 'release-served') -Value 'sent'
                }
                else { $payload = $blocked }
            }
            '/fct/api/public/v1/messages/pull/' { $payload = @{} }
            '/fct/api/public/v1/refresh/' { $payload = @{} }
            '/fct/api/public/v1/config/ack/' {
                $reader = New-Object IO.StreamReader($context.Request.InputStream)
                try { $ack = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
                if ($ack.version -eq 0 -and $ack.digest -eq '' -and $ack.success -eq $true) {
                    Set-Content -LiteralPath (Join-Path $PSScriptRoot 'release-acknowledged') -Value 'applied'
                }
                $payload = @{}
            }
            '/fct/api/public/v1/host_tags/' { $payload = @{} }
            default { $context.Response.StatusCode = 404; $payload = @{ detail = 'Unknown fixture route' } }
        }
        $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress))
        $context.Response.ContentType = 'application/json'
        $context.Response.ContentLength64 = $bytes.Length
        try { $context.Response.OutputStream.Write($bytes, 0, $bytes.Length) } finally { $context.Response.Close() }
        $pending = $listener.GetContextAsync()
    }
    $observations = Get-Content -LiteralPath (Join-Path $PSScriptRoot 'observations.json') -Raw | ConvertFrom-Json
    if ($agentProcess.HasExited) { throw 'Agent exited before acceptance completed.' }
    if (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'release-acknowledged'))) { throw 'No successful release acknowledgement.' }
    if ((Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash -ne $beforeHostsHash) { throw 'Policy release did not restore the original hosts file.' }
    if (-not ($observations.trusted_tls -and $observations.edge_confirmed -and $observations.revocation)) {
        throw 'Missing browser or revocation confirmation.'
    }
    $result.checks += 'Windows trust validates the blocked-domain TLS page without bypass'
    $result.checks += 'Edge page confirmed by the operator'
    $result.checks += 'Live simulated policy release revokes the block page without restarting the agent'
    $result.passed = $true
}
catch { $result.error = $_.Exception.Message }
finally {
    try {
        if ($null -ne $agentProcess -and -not $agentProcess.HasExited) {
            Stop-Process -Id $agentProcess.Id -Force
            $agentProcess.WaitForExit(5000) | Out-Null
        }
    }
    catch { $result.cleanup_errors += $_.Exception.Message; $result.passed = $false }
    try { if ($null -ne $listener) { $listener.Close() } }
    catch { $result.cleanup_errors += $_.Exception.Message; $result.passed = $false }
    foreach ($command in @('cleanup-hosts', 'remove-block-page-trust')) {
        try { Invoke-Agent @($command, '--config', $config) }
        catch { $result.cleanup_errors += $_.Exception.Message; $result.passed = $false }
    }
    $afterRoots = @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint)
    if (@(Compare-Object -ReferenceObject $beforeRoots -DifferenceObject $afterRoots).Count -ne 0) {
        $result.cleanup_errors += 'Trust roots differ from baseline.'; $result.passed = $false
    }
    if ((Get-FileHash -LiteralPath $hostsPath -Algorithm SHA256).Hash -ne $beforeHostsHash) {
        $result.cleanup_errors += 'Hosts file differs from baseline.'; $result.passed = $false
    }
    Write-Report (Join-Path $PSScriptRoot 'browser-result.json') $result
}
if (-not $result.passed) { exit 1 }
