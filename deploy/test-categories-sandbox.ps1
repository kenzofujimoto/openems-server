param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# F2 slice 4 acceptance for the production MSI in Windows Sandbox with networking enabled. The
# simulated backend publishes a "games" category built by app/categories.py (files in .\categories);
# the agent must download it, block through system DNS, honour allowed, report blocks to the
# block log, name the category on the block page, and keep blocking offline.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'openems-agent.msi'
$origin = 'http://127.0.0.1:18013'
$report = 'categories-result.json'
$comment = 'openems-agent managed DNS filter'
$operationTimeout = 240
$totalTimeout = 1500
$fixtureDomains = @('steampowered.com', 'steamcommunity.com')
# Normalized body, as the server publishes it (blocked is always present).
$policy = [ordered]@{ vdom='Default'; version=1; digest='ae85c2efc6cb6934577f8097cf877e2e64b263b8143832ab2b9b61c308e1bb4e'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@(); blocked_categories=@('games'); allowed=@('store.steampowered.com') } } }
# The Sandbox DNS proxy resolves through the host; these must resolve normally before install.
$forwardedNames = @('api.steampowered.com', 'steamcommunity.com', 'store.steampowered.com', 'example.org')
$scenarios = @('production install downloads the games category and blocks it through system DNS',
               'allowed exception and unlisted names resolve upstream',
               'blocked answers reach the server block log with their category',
               'the category is cached in the protected data directory with its published digest',
               'with the backend offline, a service restart keeps blocking from the cache',
               'Edge shows the block page naming the Jogos category for steamcommunity.com, confirmed by the operator',
               'removal restores NRPT rules, trust and hosts')
if ($Plan) {
    @{ package=$package; origin=$origin; report=$report; timeout_seconds=$totalTimeout; policy=$policy
       fixture_domains=$fixtureDomains; forwarded_names=$forwardedNames; scenarios=$scenarios } | ConvertTo-Json -Depth 10
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
    # One run per Sandbox: a second run would collide on ports and the installed product.
    try { [IO.File]::Open('C:\openems-categories-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A category acceptance run already started in this Sandbox; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-dns-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'categories') -Destination $work -Recurse
    $script = Join-Path $work 'test-categories-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsCategories-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $result = Join-Path $work $report
        $ready = Join-Path $work 'edge-ready'
        $answer = Join-Path $work 'edge-answer'
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        while (-not (Test-Path -LiteralPath $result)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Category acceptance timed out. Close the Sandbox to discard changes.' }
            if ((Test-Path -LiteralPath $ready) -and -not (Test-Path -LiteralPath $answer)) {
                $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
                Start-Process -FilePath $edge -ArgumentList @('--inprivate', 'https://steamcommunity.com/')
                Write-Host 'Edge opened https://steamcommunity.com/ (category games). Wait until the page finishes loading.'
                $reply = Read-Host 'Does Edge show the RSM block page with "Categoria: Jogos" and no certificate warning? Type YES or NO, then Enter'
                Set-Content -LiteralPath $answer -Value $reply.Trim().ToUpperInvariant()
            }
            Start-Sleep -Milliseconds 500
        }
        $value = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $value
        $value | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $value.passed) { throw 'Category acceptance failed; private logs remain inside Sandbox.' }
    }
    finally { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction Continue }
    exit 0
}
if ($identity.User.Value -ne 'S-1-5-18') { throw 'SystemPhase requires SYSTEM.' }
$result = [ordered]@{ passed=$false; checks=@(); durations=@(); unrelated_roots_added=@(); error=$null; cleanup_errors=@() }
$work = $PSScriptRoot
$backend = $null
$authority = 'C:\ProgramData\openems\https\authority.json'
$hosts = Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
$policyFile = Join-Path $work 'policy.json'
$requests = Join-Path $work 'requests.log'
function Invoke-Msi([bool]$Remove, [string[]]$Properties) {
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($operation, ('"' + (Join-Path $work $package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
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
    $saved = Get-Content -LiteralPath $authority -Raw | ConvertFrom-Json
    $certificate = New-Object Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,[byte[]]$saved.root)
    try { return $certificate.Thumbprint } finally { $certificate.Dispose() }
}
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
# PowerShell unrolls returned arrays (one item becomes a scalar, none becomes $null): callers wrap in @().
function Get-NrptNames { return @(Get-DnsClientNrptRule | ForEach-Object Name | Sort-Object) }
function Get-ManagedRules { return @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $comment }) }
function Assert-ManagedRule {
    $rules = @(Get-ManagedRules)
    if ($rules.Count -ne 1) { throw ('Expected exactly one managed NRPT rule, found ' + $rules.Count + '.') }
    $rule = $rules[0]
    if (@($rule.Namespace) -notcontains '.') { throw 'Managed NRPT rule does not cover the root namespace.' }
    if (@(@($rule.NameServers) | Where-Object { $_ -notin @('127.0.0.1', '::1') }).Count -or -not (@($rule.NameServers) -contains '127.0.0.1')) {
        throw 'Managed NRPT rule must point only at loopback resolvers.'
    }
}
# System path: no -Server, so the DNS client applies NRPT. The cache is cleared before every check.
function Resolve-System([string]$Name, [string]$Type = 'A') {
    Clear-DnsClientCache
    try {
        return @(Resolve-DnsName -Name $Name -Type $Type -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
            Where-Object { [string]$_.Type -eq $Type } | ForEach-Object { [string]$_.IPAddress })
    } catch { return @() }
}
function Test-Blocked([string]$Name, [string]$Type = 'A') {
    $expected = if ($Type -eq 'AAAA') { '::1' } else { '127.0.0.1' }
    $addresses = @(Resolve-System $Name $Type)
    return ($addresses.Count -eq 1 -and $addresses[0] -eq $expected)
}
function Test-Upstream([string]$Name) {
    $addresses = @(Resolve-System $Name)
    return ($addresses.Count -gt 0 -and -not @($addresses | Where-Object { $_ -in @('127.0.0.1', '0.0.0.0') }).Count)
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Failure) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Failure
}
function Test-TlsPage([string]$Name) {
    $client = New-Object Net.Sockets.TcpClient
    $tls = $null
    try {
        $client.Connect('127.0.0.1', 443)
        $tls = New-Object Net.Security.SslStream($client.GetStream(), $false)
        $tls.ReadTimeout = 5000; $tls.WriteTimeout = 5000
        $tls.AuthenticateAsClient($Name)
        $request = [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: $Name`r`nConnection: close`r`n`r`n")
        $tls.Write($request, 0, $request.Length)
        return (New-Object IO.StreamReader($tls)).ReadToEnd().Contains('<title>Acesso bloqueado</title>')
    } catch { return $false } finally { if ($null -ne $tls) { $tls.Dispose() }; $client.Dispose() }
}
function Set-Policy($Assignment) { $Assignment | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding UTF8 }
# Simulated EMS backend, plus the category routes served from .\categories (manifest.json and
# <id>-<digest>.bin, exactly as app/categories.py publishes them).
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
                try { Add-Content -LiteralPath (Join-Path $Work 'requests.log') -Value $path } catch { }
                $bytes = $null; $type = 'application/json'; $context.Response.StatusCode = 200
                $payload = @{}
                switch ($path) {
                    '/fct/api/public/v1/register/' { $payload = @{ client_id='sandbox-categories'; device_token='sandbox-fixture-only' } }
                    '/fct/api/public/v1/config/assigned/' { $payload = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json }
                    '/fct/api/public/v1/categories/' {
                        $bytes = [IO.File]::ReadAllBytes((Join-Path $Work 'categories\manifest.json'))
                    }
                    '/fct/api/public/v1/categories/file/' {
                        $id = [string]$context.Request.QueryString['id']; $digest = [string]$context.Request.QueryString['digest']
                        $file = Join-Path $Work ('categories\' + $id + '-' + $digest + '.bin')
                        if ($id -match '^[a-z]+$' -and $digest -match '^[0-9a-f]{64}$' -and (Test-Path -LiteralPath $file)) {
                            $bytes = [IO.File]::ReadAllBytes($file); $type = 'application/octet-stream'
                        } else { $context.Response.StatusCode = 404 }
                    }
                    '/fct/api/public/v1/messages/pull/' { }
                    '/fct/api/public/v1/refresh/' { }
                    '/fct/api/public/v1/config/ack/' { }
                    '/fct/api/public/v1/host_tags/' { }
                    '/fct/api/public/v1/events/' {
                        # One upload per line, for the block log checks.
                        $reader = New-Object IO.StreamReader($context.Request.InputStream, [Text.Encoding]::UTF8)
                        try { $upload = $reader.ReadToEnd() } finally { $reader.Dispose() }
                        try { Add-Content -LiteralPath (Join-Path $Work 'events.log') -Value ($upload -replace "`r?`n", ' ') } catch { }
                        $payload = @{ accepted=0; rejected=0 }
                    }
                    default { $context.Response.StatusCode = 404 }
                }
                if ($null -eq $bytes) { $bytes = [Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Depth 8 -Compress)) }
                $context.Response.ContentType = $type; $context.Response.ContentLength64 = $bytes.Length
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
function Get-ReportedRows {
    $log = Join-Path $work 'events.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    $stream = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite')
    try { $lines = (New-Object IO.StreamReader($stream)).ReadToEnd() -split "`r?`n" } finally { $stream.Dispose() }
    return @($lines | Where-Object { $_ } | ForEach-Object { @(($_ | ConvertFrom-Json).events) })
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
    if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
    foreach ($port in @(53, 80, 443, 18013)) {
        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    foreach ($name in $forwardedNames) {
        # A freshly opened Sandbox may still be bringing its network up: retry before blaming the host.
        Wait-Until { Test-Upstream $name } 60 ('Host DNS already filters or cannot resolve ' + $name + '; enable Sandbox networking and remove host filtering for it.')
    }
    $manifest = Get-Content -LiteralPath (Join-Path $work 'categories\manifest.json') -Raw | ConvertFrom-Json
    $games = @($manifest.categories | Where-Object { $_.id -eq 'games' })
    if ($games.Count -ne 1) { throw 'Fixture manifest must publish exactly one games category.' }
    $gamesDigest = [string]$games[0].digest
    Assert-ProductionPackage ([string](Join-Path $work $package))
    $baselineRoots = Get-Roots
    $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
    $baselineRules = @(Get-NrptNames)
    Set-Policy $policy
    $backend = Start-Backend

    Invoke-Msi $false @('SERVER=' + $origin, 'BLOCKPAGEHTTPS=1', 'DNSFILTER=1')
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'api.steampowered.com') } 120 'The games category did not reach system DNS answers.'
    if ((Get-RequestCount '/fct/api/public/v1/categories/file/') -lt 1) { throw 'The agent never downloaded the category file.' }
    $managedRoot = Get-ManagedRoot
    $result.checks += $scenarios[0]

    if (-not (Test-Blocked 'steamcommunity.com')) { throw 'steamcommunity.com is in the category but was not blocked.' }
    if (-not (Test-Upstream 'store.steampowered.com')) { throw 'The allowed exception did not resolve upstream.' }
    if (-not (Test-Upstream 'example.org')) { throw 'An unlisted name did not resolve upstream.' }
    $result.checks += $scenarios[1]

    Wait-Until { @(Get-ReportedRows | Where-Object { $_.domain -eq 'api.steampowered.com' -and $_.reason -eq 'category' -and $_.category -eq 'games' }).Count -gt 0 } 60 'The block log upload did not reach the backend.'
    $reported = @(Get-ReportedRows)
    if (@($reported | Where-Object { $_.domain -in @('store.steampowered.com', 'example.org') }).Count) { throw 'An allowed or unlisted name was reported as blocked.' }
    if (@($reported | Where-Object { $_.count -lt 1 -or $_.hour -notmatch '^\d{4}-\d{2}-\d{2}T\d{2}:00:00Z$' }).Count) { throw 'A block log row is not an hourly aggregate.' }
    $result.checks += $scenarios[2]

    $cached = 'C:\ProgramData\openems\categories\games-' + $gamesDigest + '.bin'
    if (-not (Test-Path -LiteralPath $cached)) { throw 'The category was not cached in the data directory.' }
    if ((Get-FileHash -LiteralPath $cached -Algorithm SHA256).Hash.ToLowerInvariant() -ne $gamesDigest) { throw 'The cached category does not match its digest.' }
    $result.checks += $scenarios[3]

    Stop-Backend $backend
    $backend = $null
    $processId = Get-ServiceProcess
    Restart-Service -Name openems-agent
    Wait-Until { $current = Get-ServiceProcess; $current -gt 0 -and $current -ne $processId -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'api.steampowered.com') } 90 'After an offline restart the cached category did not block.'
    if (@(Get-NetTCPConnection -State Listen -LocalPort 18013 -ErrorAction SilentlyContinue).Count) { throw 'The backend was not offline during the restart check.' }
    $result.checks += $scenarios[4]

    Set-Content -LiteralPath (Join-Path $work 'edge-ready') -Value ready
    $edgeAnswer = Join-Path $work 'edge-answer'
    Wait-Until { Test-Path -LiteralPath $edgeAnswer } 600 'Operator did not answer the Edge check.'
    if ((Get-Content -LiteralPath $edgeAnswer -Raw).Trim() -ne 'YES') { throw 'The block page for steamcommunity.com was not confirmed in Edge.' }
    $result.checks += $scenarios[5]

    Invoke-Msi $true @()
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Uninstalled service still exists.' }
    if (@(Get-ManagedRules).Count) { throw 'Removal left the managed NRPT rule.' }
    if ((@($baselineRules) -join ',') -ne (@(Get-NrptNames) -join ',')) { throw 'Removal changed unrelated NRPT rules.' }
    Assert-Trust $managedRoot $baselineRoots $false
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) { throw 'Uninstall did not restore hosts.' }
    if (-not (Test-Upstream 'steamcommunity.com')) { throw 'DNS did not work after removal.' }
    $result.checks += $scenarios[6]
    $result.passed = $true
} catch { $result.error = $_.Exception.Message }
finally {
    if ($null -ne $baselineRoots) {
        $result.unrelated_roots_added = @(Get-Roots | Where-Object { $_ -notin $baselineRoots -and $_ -ne $managedRoot })
    }
    if ($null -ne $backend) { Stop-Job $backend -ErrorAction Continue; Remove-Job $backend -Force -ErrorAction Continue }
    Write-Report (Join-Path $OutputDirectory $report) $result
}
if (-not $result.passed) { exit 1 }
