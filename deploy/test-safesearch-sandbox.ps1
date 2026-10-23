param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan, [string]$PlanNow)
# F2 slice 2 acceptance for the production MSI in Windows Sandbox with networking enabled: forced
# SafeSearch CNAMEs, an open and a closed schedule window, Google SafeSearch confirmed in Edge, a
# policy change that must flush cached answers, and removal. System resolution never uses -Server.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'openems-agent.msi'
$origin = 'http://127.0.0.1:18013'
$report = 'safesearch-result.json'
$comment = 'openems-agent managed DNS filter'
$operationTimeout = 240
$totalTimeout = 1500
$days = @('sun', 'mon', 'tue', 'wed', 'thu', 'fri', 'sat')  # indexed by [DayOfWeek]
$safeHosts = [ordered]@{ 'www.google.com'='forcesafesearch.google.com'; 'www.youtube.com'='restrict.youtube.com'
                         'www.bing.com'='strict.bing.com'; 'duckduckgo.com'='safe.duckduckgo.com' }
# The Sandbox DNS proxy resolves through the host; these must resolve normally before install.
$forwardedNames = @('iana.org', 'example.net', 'example.org')
$scenarios = @('open schedule window blocks through system DNS while a closed one does not',
               'search engines resolve through a CNAME to their enforced SafeSearch host',
               'Google search in Edge shows SafeSearch locked on, confirmed by the operator',
               'policy change flushes cached answers without restarting the service',
               'removal restores NRPT rules, trust and hosts')

# Python json.dumps(sort_keys=True, separators=(',', ':')) for the ASCII values used here.
function ConvertTo-Canonical($Value) {
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [bool]) { if ($Value) { return 'true' } else { return 'false' } }
    if ($Value -is [int] -or $Value -is [long]) { return [string]$Value }
    if ($Value -is [string]) { return '"' + $Value.Replace('\', '\\').Replace('"', '\"') + '"' }
    if ($Value -is [Collections.IDictionary]) {
        [string[]]$keys = @($Value.Keys)
        [Array]::Sort($keys, [StringComparer]::Ordinal)
        return '{' + (($keys | ForEach-Object { (ConvertTo-Canonical $_) + ':' + (ConvertTo-Canonical $Value[$_]) }) -join ',') + '}'
    }
    return '[' + ((@($Value) | ForEach-Object { ConvertTo-Canonical $_ }) -join ',') + ']'
}
function New-Assignment([int]$Version, $Body) {
    $sha = [Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes((ConvertTo-Canonical $Body))) } finally { $sha.Dispose() }
    return [ordered]@{ vdom='Default'; version=$Version; digest=(($hash | ForEach-Object { $_.ToString('x2') }) -join ''); body=$Body }
}
# Bodies are in normalized form (blocked always present), as the server publishes them.
# Windows are relative to now in UTC: one open all of today, one only on tomorrow's weekday.
function Build-Policies([DateTime]$NowUtc) {
    if ($NowUtc.TimeOfDay -ge [TimeSpan]::FromMinutes(23 * 60 + 40)) { throw 'Too close to midnight UTC; run again after 00:00 UTC.' }
    $today = $days[[int]$NowUtc.DayOfWeek]
    $other = $days[([int]$NowUtc.DayOfWeek + 1) % 7]
    $safe = [ordered]@{ engines=@('google', 'bing', 'youtube', 'duckduckgo') }
    $first = [ordered]@{ web_filter=[ordered]@{ blocked=@(); safe_search=$safe; timezone='UTC'; scheduled=@(
        [ordered]@{ blocked=@('*.iana.org'); days=@($today); from='00:00'; to='23:59' },
        [ordered]@{ blocked=@('example.net'); days=@($other); from='00:00'; to='23:59' }) } }
    $second = [ordered]@{ web_filter=[ordered]@{ blocked=@(); safe_search=$safe; timezone='UTC'; scheduled=@(
        [ordered]@{ blocked=@('*.iana.org', 'example.net'); days=@($today); from='00:00'; to='23:59' }) } }
    return @((New-Assignment 1 $first), (New-Assignment 2 $second))
}
if ($Plan) {
    $now = if ($PlanNow) { [DateTime]::Parse($PlanNow, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AdjustToUniversal) } else { [DateTime]::UtcNow }
    @{ package=$package; origin=$origin; report=$report; timeout_seconds=$totalTimeout; policies=(Build-Policies $now)
       forwarded_names=$forwardedNames; safe_hosts=$safeHosts; scenarios=$scenarios } | ConvertTo-Json -Depth 10
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
    try { [IO.File]::Open('C:\openems-safesearch-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A SafeSearch acceptance run already started in this Sandbox; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-dns-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work
    $script = Join-Path $work 'test-safesearch-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsSafeSearch-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $result = Join-Path $work $report
        $ready = Join-Path $work 'edge-ready'
        $answer = Join-Path $work 'edge-answer'
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        while (-not (Test-Path -LiteralPath $result)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'SafeSearch acceptance timed out. Close the Sandbox to discard changes.' }
            if ((Test-Path -LiteralPath $ready) -and -not (Test-Path -LiteralPath $answer)) {
                $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
                Start-Process -FilePath $edge -ArgumentList @('--inprivate', 'https://www.google.com/search?q=safesearch')
                Write-Host 'Edge opened a Google search. Accept or dismiss any consent screen, then look at the SafeSearch setting.'
                $reply = Read-Host 'Does Google show SafeSearch as on and locked (it cannot be turned off)? Type YES or NO, then Enter'
                Set-Content -LiteralPath $answer -Value $reply.Trim().ToUpperInvariant()
            }
            Start-Sleep -Milliseconds 500
        }
        $value = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $value
        $value | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $value.passed) { throw 'SafeSearch acceptance failed; private logs remain inside Sandbox.' }
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
                $payload = @{}; $context.Response.StatusCode = 200
                switch ($context.Request.Url.AbsolutePath) {
                    '/fct/api/public/v1/register/' { $payload = @{ client_id='sandbox-dns'; device_token='sandbox-fixture-only' } }
                    # The harness swaps policy.json to change the assignment while the service runs.
                    '/fct/api/public/v1/config/assigned/' { $payload = Get-Content -LiteralPath (Join-Path $Work 'policy.json') -Raw | ConvertFrom-Json }
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
# CNAME targets in the system answer for an A query; the cache is cleared first.
function Get-SafeAnswer([string]$Name) {
    Clear-DnsClientCache
    try {
        $records = @(Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop)
    } catch { return @{ cnames=@(); addresses=@() } }
    return @{ cnames=@($records | Where-Object { [string]$_.Type -eq 'CNAME' } | ForEach-Object { ([string]$_.NameHost).TrimEnd('.').ToLowerInvariant() })
              addresses=@($records | Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress }) }
}
# Same system path, but keeps the DNS client cache: proves the agent itself flushed stale answers.
function Resolve-Cached([string]$Name) {
    try {
        return @(Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
            Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
    } catch { return @() }
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
    $endpoint = New-Object Net.IPEndPoint([Net.IPAddress]::Loopback, 53)
    $udp = New-Object Net.Sockets.UdpClient -ArgumentList $endpoint
    $udp.Dispose()
    foreach ($name in $forwardedNames) {
        if (-not (Test-Upstream $name)) {
            throw ('Host DNS already filters or cannot resolve ' + $name + '; enable Sandbox networking and remove host filtering for it.')
        }
    }
    foreach ($name in $safeHosts.Keys) {
        $before = Get-SafeAnswer $name
        if (@($before.addresses).Count -eq 0) { throw ('Search engine ' + $name + ' does not resolve before installation; enable Sandbox networking.') }
        if (@($before.cnames) -contains $safeHosts[$name]) {
            throw ('Host DNS already enforces SafeSearch for ' + $name + '; the check would prove nothing.')
        }
    }
    Assert-ProductionPackage ([string](Join-Path $work $package))
    $policies = Build-Policies ([DateTime]::UtcNow)
    $baselineRoots = Get-Roots
    $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
    $baselineRules = @(Get-NrptNames)
    Set-Policy $policies[0]
    $backend = Start-Backend

    Invoke-Msi $false @('SERVER=' + $origin, 'BLOCKPAGEHTTPS=1', 'DNSFILTER=1')
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'a.b.iana.org') } 120 'Open schedule window did not block through system DNS.'
    Assert-ManagedRule
    if (-not (Test-Upstream 'example.net')) { throw 'Closed schedule window blocked a name.' }
    $managedRoot = Get-ManagedRoot
    $result.checks += $scenarios[0]

    foreach ($name in $safeHosts.Keys) {
        $answer = Get-SafeAnswer $name
        if (-not (@($answer.cnames) -contains $safeHosts[$name])) { throw ($name + ' was not rewritten to ' + $safeHosts[$name] + '.') }
        if (@($answer.addresses).Count -eq 0 -or @($answer.addresses | Where-Object { $_ -in @('127.0.0.1', '0.0.0.0') }).Count) {
            throw ($name + ' did not resolve to the SafeSearch host addresses.')
        }
    }
    $result.checks += $scenarios[1]

    Set-Content -LiteralPath (Join-Path $work 'edge-ready') -Value ready
    $edgeAnswer = Join-Path $work 'edge-answer'
    Wait-Until { Test-Path -LiteralPath $edgeAnswer } 600 'Operator did not answer the Edge check.'
    if ((Get-Content -LiteralPath $edgeAnswer -Raw).Trim() -ne 'YES') { throw 'Google SafeSearch was not confirmed locked in Edge.' }
    $result.checks += $scenarios[2]

    Clear-DnsClientCache
    if (@(Resolve-Cached 'example.net').Count -eq 0 -or (Test-Blocked 'example.net')) { throw 'example.net did not resolve upstream before the change.' }
    if (@(Resolve-Cached 'example.net') -contains '127.0.0.1') { throw 'Cached answer was not the upstream one.' }
    $processId = Get-ServiceProcess
    Set-Policy $policies[1]
    Wait-Until { $cached = @(Resolve-Cached 'example.net'); $cached.Count -eq 1 -and $cached[0] -eq '127.0.0.1' } 120 'Policy change left a stale cached answer.'
    if ((Get-ServiceProcess) -ne $processId) { throw 'Policy change restarted the service.' }
    $result.checks += $scenarios[3]

    Invoke-Msi $true @()
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Uninstalled service still exists.' }
    if (@(Get-ManagedRules).Count) { throw 'Removal left the managed NRPT rule.' }
    if ((@($baselineRules) -join ',') -ne (@(Get-NrptNames) -join ',')) { throw 'Removal changed unrelated NRPT rules.' }
    Assert-Trust $managedRoot $baselineRoots $false
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) { throw 'Uninstall did not restore hosts.' }
    if (@((Get-SafeAnswer 'www.google.com').cnames) -contains 'forcesafesearch.google.com') { throw 'SafeSearch rewrite survived removal.' }
    $result.checks += $scenarios[4]
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
