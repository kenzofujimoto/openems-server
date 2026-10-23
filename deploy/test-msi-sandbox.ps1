param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$fixtures = @('openems-agent-0.2.0.msi', 'openems-agent-0.2.1.msi', 'openems-agent-0.2.2.msi')
$origin = 'http://127.0.0.1:18013'
# Unsigned fixtures can wait ~2 min on signature checks when the Sandbox has no network.
$operationTimeout = 240
$totalTimeout = 1500
if ($Plan) {
    @{ fixtures=$fixtures; origin=$origin; report='msi-result.json'; timeout_seconds=$totalTimeout; operation_timeout_seconds=$operationTimeout
       scenarios=@('fresh HTTPS installation', 'identity-preserving upgrade', 'failed upgrade rollback', 'failed removal rollback', 'successful removal') } | ConvertTo-Json -Depth 5
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
    $work = Join-Path 'C:\' ('openems-msi-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    foreach ($fixture in $fixtures) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $fixture) -Destination $work }
    $script = Join-Path $work 'test-msi-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsMsi-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $report = Join-Path $work 'msi-result.json'
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        while (-not (Test-Path -LiteralPath $report)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'MSI acceptance timed out. Close the Sandbox to discard changes.' }
            Start-Sleep -Milliseconds 500
        }
        $result = Get-Content -LiteralPath $report -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory 'msi-result.json') $result
        $result | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $result.passed) { throw 'MSI acceptance failed; private logs remain inside Sandbox.' }
    }
    finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$result = [ordered]@{ passed=$false; checks=@(); durations=@(); error=$null; cleanup_errors=@() }
$backend = $null
$config = 'C:\ProgramData\openems\agent.json'
$authority = 'C:\ProgramData\openems\https\authority.json'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
function Invoke-Msi([string]$Package, [bool]$Remove, [string[]]$Properties, [int]$Expected) {
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $PSScriptRoot ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($operation, ('"' + (Join-Path $PSScriptRoot $Package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
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
        $result.durations += ('{0} {1}: {2:N0} s' -f $operation, $Package, ([DateTime]::UtcNow - $started).TotalSeconds)
        if (-not $finished) { throw ('MSI operation timed out; close Sandbox. Log: ' + $log) }
        if ($process.ExitCode -ne $Expected) { throw ('Unexpected MSI exit code: ' + $process.ExitCode + '; expected ' + $Expected + '. Log: ' + $log) }
    } finally { $process.Dispose() }
}
function Get-Roots { return @(Get-ChildItem Cert:\LocalMachine\Root | ForEach-Object Thumbprint | Sort-Object) }
function Assert-Roots($Expected) {
    if (@(Compare-Object @($Expected) @(Get-Roots)).Count) { throw 'Trust roots differ from expected baseline.' }
}
function Wait-Healthy {
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
        if ($null -ne $service -and $service.State -eq 'Running' -and $service.ProcessId -gt 0) {
            $owned = @(Get-NetTCPConnection -State Listen -LocalPort 443 -ErrorAction SilentlyContinue | Where-Object OwningProcess -eq $service.ProcessId)
            if ($owned.Count -and (Get-Content -LiteralPath $hosts -Raw).Contains('example.com')) {
                $client = New-Object Net.Sockets.TcpClient
                $tls = $null
                try {
                    $client.Connect('127.0.0.1',443)
                    $tls = New-Object Net.Security.SslStream($client.GetStream(), $false)
                    $tls.ReadTimeout=5000; $tls.WriteTimeout=5000
                    $tls.AuthenticateAsClient('example.com')
                    $request=[Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: example.com`r`nConnection: close`r`n`r`n")
                    $tls.Write($request,0,$request.Length)
                    $reader=New-Object IO.StreamReader($tls)
                    if ($reader.ReadToEnd().Contains('<title>Acesso bloqueado</title>')) { return }
                } catch { } finally { if($null -ne $tls){$tls.Dispose()}; $client.Dispose() }
            }
        }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Service did not provide a trusted TLS block page from its own listener.'
}
try {
    if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
    foreach ($port in @(80,443,18013)) {
        $probe=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback,$port)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    $baselineRoots=Get-Roots
    $baselineHosts=(Get-FileHash -LiteralPath $hosts).Hash
    $backend=Start-Job -ArgumentList $origin,$PSScriptRoot -ScriptBlock {
        param($Origin,$Work)
        $ErrorActionPreference='Stop'
        $listener=New-Object Net.HttpListener
        $listener.Prefixes.Add($Origin+'/')
        try {
            $listener.Start()
            Set-Content -LiteralPath (Join-Path $Work 'backend-ready') -Value ready
            while ($true) {
                # Short waits keep Stop-Job effective; a blocking GetContext delays cleanup.
                $pending=$listener.GetContextAsync()
                while (-not $pending.Wait(500)) { }
                $context=$pending.Result
                $payload=@{}; $context.Response.StatusCode=200
                switch ($context.Request.Url.AbsolutePath) {
                    '/fct/api/public/v1/register/' { $payload=@{client_id='sandbox-msi';device_token='sandbox-fixture-only'} }
                    '/fct/api/public/v1/config/assigned/' { $payload=@{vdom='Default';version=1;digest='a14e792ed37e48755b1a793e203e4532bbcd4eba11e569751f8cede812040ebb';body=@{web_filter=@{blocked=@('example.com')}}} }
                    '/fct/api/public/v1/messages/pull/' { }
                    '/fct/api/public/v1/refresh/' { }
                    '/fct/api/public/v1/config/ack/' { }
                    '/fct/api/public/v1/host_tags/' { }
                    default { $context.Response.StatusCode=404 }
                }
                $bytes=[Text.Encoding]::UTF8.GetBytes(($payload|ConvertTo-Json -Depth 8 -Compress))
                $context.Response.ContentType='application/json';$context.Response.ContentLength64=$bytes.Length
                try {$context.Response.OutputStream.Write($bytes,0,$bytes.Length)} finally {$context.Response.Close()}
            }
        } finally {$listener.Close()}
    }
    $deadline=[DateTime]::UtcNow.AddSeconds(15)
    while (-not (Test-Path -LiteralPath (Join-Path $PSScriptRoot 'backend-ready'))) {
        if ($backend.State -eq 'Failed' -or [DateTime]::UtcNow -ge $deadline) { throw 'Simulated EMS backend failed to start.' }
        Start-Sleep -Milliseconds 200
    }
    Invoke-Msi $fixtures[0] $false @('SERVER=http://127.0.0.1:18013','BLOCKPAGEHTTPS=1') 0
    Wait-Healthy
    $savedConfig=Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    if (-not ($savedConfig.block_page -and $savedConfig.block_page_https)) { throw 'HTTPS did not imply HTTP.' }
    $savedRoots=Get-Roots
    if (@($savedRoots | Where-Object {$_ -notin $baselineRoots}).Count -ne 1) { throw 'Installation must add one root.' }
    $authorityHash=(Get-FileHash -LiteralPath $authority).Hash
    $result.checks+='fresh HTTPS install trusts one root and serves TLS from the running service'
    Invoke-Msi $fixtures[1] $false @() 0
    Wait-Healthy
    $upgradeConfig=Get-Content -LiteralPath $config -Raw | ConvertFrom-Json
    foreach ($field in @('devid','device_token','server','block_page','block_page_https')) {
        if ($savedConfig.$field -ne $upgradeConfig.$field) {throw 'Upgrade changed registration or configuration.'}
    }
    Assert-Roots $savedRoots
    if ((Get-FileHash -LiteralPath $authority).Hash -ne $authorityHash) {throw 'Upgrade replaced private authority.'}
    $result.checks+='upgrade without SERVER preserves identity, trust, hosts and running service'
    Invoke-Msi $fixtures[2] $false @('FAIL_SETUP=1') 1603
    Wait-Healthy
    Assert-Roots $savedRoots
    if ((Get-FileHash -LiteralPath $authority).Hash -ne $authorityHash) {throw 'Failed upgrade changed authority.'}
    $result.checks+='failed upgrade restores existing service and trust'
    Invoke-Msi $fixtures[1] $true @('FAIL_REMOVAL=1') 1603
    Wait-Healthy
    Assert-Roots $savedRoots
    if ((Get-FileHash -LiteralPath $authority).Hash -ne $authorityHash) {throw 'Failed removal changed authority.'}
    $result.checks+='failed removal restores private authority, trust, hosts and running service'
    Invoke-Msi $fixtures[1] $true @() 0
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) {throw 'Uninstalled service still exists.'}
    Assert-Roots $baselineRoots
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) {throw 'Uninstall did not restore hosts.'}
    $result.checks+='successful removal restores original trust and hosts and removes service'
    $result.passed=$true
} catch { $result.error=$_.Exception.Message }
finally {
    if ($null -ne $backend) { Stop-Job $backend -ErrorAction Continue; Remove-Job $backend -Force -ErrorAction Continue }
    Write-Report (Join-Path $OutputDirectory 'msi-result.json') $result
}
if (-not $result.passed) {exit 1}
