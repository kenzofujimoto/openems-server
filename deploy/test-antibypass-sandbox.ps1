param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# F2 slice 3 acceptance for the production MSI in Windows Sandbox with networking enabled. Probes
# run from this PowerShell process (never the agent): direct DNS to the adapter resolver, DoT and
# DoH by address must fail while the system resolver keeps working through the agent.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$package = 'openems-agent.msi'
$origin = 'http://127.0.0.1:18013'
$report = 'antibypass-result.json'
$comment = 'openems-agent managed DNS filter'
$operationTimeout = 240
$totalTimeout = 1500
$dohProbe = '1.1.1.1'
$policy = [ordered]@{ vdom='Default'; version=1; digest='f62e2cdf1c57d70bdd6691035c96d1c37c1a5365dd9448e8f656e521f8b0ce12'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@('*.iana.org'); allowed=@('www.iana.org') } } }
$browserPolicies = @(
    @{ key='SOFTWARE\Policies\Google\Chrome'; name='DnsOverHttpsMode'; value='off' },
    @{ key='SOFTWARE\Policies\Microsoft\Edge'; name='DnsOverHttpsMode'; value='off' },
    @{ key='SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; name='Enabled'; value=0 },
    @{ key='SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS'; name='Locked'; value=1 },
    @{ key='SOFTWARE\Policies\Mozilla\Firefox\Certificates'; name='ImportEnterpriseRoots'; value=1 })
$scenarios = @('production install with ANTIBYPASS keeps system DNS working through the agent',
               'direct DNS from other programs to the adapter resolver is blocked',
               'DoT and DoH by address are blocked while ordinary HTTPS works',
               'DoH service names get NXDOMAIN from the local resolver',
               'browser DoH policies are written to HKLM',
               'Edge shows secure DNS managed off and the block page, confirmed by the operator',
               'killed process keeps the filters and service recovery restores resolution',
               'graceful stop removes filters and the NRPT rule; start restores them',
               'removal restores filters, NRPT, browser policies, trust and hosts')
if ($Plan) {
    @{ package=$package; origin=$origin; report=$report; timeout_seconds=$totalTimeout; policy=$policy; doh_probe=$dohProbe
       browser_policies=$browserPolicies; scenarios=$scenarios } | ConvertTo-Json -Depth 10
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
    try { [IO.File]::Open('C:\openems-antibypass-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'An anti-bypass acceptance run already started in this Sandbox; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-dns-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work
    $script = Join-Path $work 'test-antibypass-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsAntiBypass-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $result = Join-Path $work $report
        $ready = Join-Path $work 'edge-ready'
        $answer = Join-Path $work 'edge-answer'
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        while (-not (Test-Path -LiteralPath $result)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Anti-bypass acceptance timed out. Close the Sandbox to discard changes.' }
            if ((Test-Path -LiteralPath $ready) -and -not (Test-Path -LiteralPath $answer)) {
                $edge = Join-Path ${env:ProgramFiles(x86)} 'Microsoft\Edge\Application\msedge.exe'
                Start-Process -FilePath $edge -ArgumentList @('--inprivate', 'edge://settings/privacy', 'https://a.b.iana.org/')
                Write-Host 'Edge opened two tabs. In the settings tab, find "Use secure DNS"; the other tab should show the RSM block page.'
                $reply = Read-Host 'Is secure DNS turned off and managed by your organization, AND does the block page show? Type YES or NO, then Enter'
                Set-Content -LiteralPath $answer -Value $reply.Trim().ToUpperInvariant()
            }
            Start-Sleep -Milliseconds 500
        }
        $value = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $value
        $value | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $value.passed) { throw 'Anti-bypass acceptance failed; private logs remain inside Sandbox.' }
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
# A DNS query sent from this process (not the agent); returns the reply rcode or $null when blocked.
function Send-RawDns([string]$Server, [string]$Name) {
    $udp = New-Object Net.Sockets.UdpClient([Net.Sockets.AddressFamily]::InterNetwork)
    try {
        $udp.Client.ReceiveTimeout = 2500
        $bytes = New-Object Collections.Generic.List[byte]
        $bytes.AddRange([byte[]](0x51, 0x7a, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))
        foreach ($label in $Name.Split('.')) {
            $bytes.Add([byte]$label.Length)
            $bytes.AddRange([Text.Encoding]::ASCII.GetBytes($label))
        }
        $bytes.AddRange([byte[]](0x00, 0x00, 0x01, 0x00, 0x01))
        $packet = $bytes.ToArray()
        [void]$udp.Send($packet, $packet.Length, $Server, 53)
        $remote = New-Object Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $reply = $udp.Receive([ref]$remote)
        if ($reply.Length -lt 4 -or $reply[0] -ne 0x51 -or $reply[1] -ne 0x7a) { return $null }
        return [int]($reply[3] -band 0x0F)
    } catch { return $null } finally { $udp.Dispose() }
}
function Test-Tcp([string]$Address, [int]$Port) {
    $client = New-Object Net.Sockets.TcpClient
    try { return $client.ConnectAsync($Address, $Port).Wait(3000) -and $client.Connected } catch { return $false } finally { $client.Dispose() }
}
# First adapter DNS server that answers a raw query from this process; some adapters list dead ones.
function Get-AdapterResolver {
    $servers = @(Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } |
        ForEach-Object ServerAddresses | Where-Object { $_ -notlike '127.*' })
    foreach ($server in $servers) {
        if ((Send-RawDns ([string]$server) 'example.org') -eq 0) { return [string]$server }
    }
    throw 'Direct DNS to an adapter resolver must be reachable before installation; open the Sandbox with networking enabled.'
}
function Get-PolicyValue([string]$Key, [string]$Name) {
    $item = Get-ItemProperty -LiteralPath ('HKLM:\' + $Key) -Name $Name -ErrorAction SilentlyContinue
    if ($null -eq $item) { return $null }
    return $item.$Name
}
function Test-Bypass {
    # $true when every bypass probe fails from this process.
    return ($null -eq (Send-RawDns $resolver 'example.org')) -and -not (Test-Tcp $dohProbe 853) -and -not (Test-Tcp $dohProbe 443)
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
    $resolver = Get-AdapterResolver
    # A block proves nothing unless the same probe worked before the agent existed.
    if (-not (Test-Tcp $dohProbe 443)) { throw ('TCP ' + $dohProbe + ':443 must be reachable before installation.') }
    if (-not (Test-Tcp $dohProbe 853)) { throw ('TCP ' + $dohProbe + ':853 must be reachable before installation.') }
    if (-not (Test-Upstream 'dns.google')) { throw 'dns.google must be reachable before installation.' }
    if (-not (Test-Upstream 'example.org')) { throw 'example.org must be reachable before installation.' }
    foreach ($setting in $browserPolicies) {
        if ($null -ne (Get-PolicyValue $setting.key $setting.name)) { throw ('Browser policy ' + $setting.key + '\' + $setting.name + ' already exists; use a fresh Sandbox.') }
    }
    Assert-ProductionPackage ([string](Join-Path $work $package))
    $baselineRoots = Get-Roots
    $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
    $baselineRules = @(Get-NrptNames)
    Set-Policy $policy
    $backend = Start-Backend

    Invoke-Msi $false @('SERVER=' + $origin, 'BLOCKPAGEHTTPS=1', 'DNSFILTER=1', 'ANTIBYPASS=1')
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'a.b.iana.org') } 120 'Service did not route system DNS to the local resolver.'
    Assert-ManagedRule
    if (-not (Test-Upstream 'example.org')) { throw 'System DNS stopped resolving allowed names through the agent.' }
    $managedRoot = Get-ManagedRoot
    $result.checks += $scenarios[0]

    Wait-Until { $null -eq (Send-RawDns $resolver 'example.org') } 30 ('Direct DNS to ' + $resolver + ' still answers other programs.')
    $result.checks += $scenarios[1]

    if (Test-Tcp $dohProbe 853) { throw ('DoT to ' + $dohProbe + ' is still reachable.') }
    if (Test-Tcp $dohProbe 443) { throw ('DoH to ' + $dohProbe + ' is still reachable.') }
    $ordinary = @(Resolve-System 'example.org')
    if ($ordinary.Count -eq 0 -or -not (Test-Tcp $ordinary[0] 443)) { throw 'Ordinary HTTPS to example.org was blocked.' }
    $result.checks += $scenarios[2]

    if ((Send-RawDns '127.0.0.1' 'dns.google') -ne 3) { throw 'dns.google did not get NXDOMAIN from the local resolver.' }
    if ((Send-RawDns '127.0.0.1' 'mozilla.cloudflare-dns.com') -ne 3) { throw 'mozilla.cloudflare-dns.com did not get NXDOMAIN.' }
    $result.checks += $scenarios[3]

    foreach ($setting in $browserPolicies) {
        $actual = Get-PolicyValue $setting.key $setting.name
        if ([string]$actual -ne [string]$setting.value) { throw ('Browser policy ' + $setting.key + '\' + $setting.name + ' is ' + $actual + '.') }
    }
    $result.checks += $scenarios[4]

    Set-Content -LiteralPath (Join-Path $work 'edge-ready') -Value ready
    $edgeAnswer = Join-Path $work 'edge-answer'
    Wait-Until { Test-Path -LiteralPath $edgeAnswer } 600 'Operator did not answer the Edge check.'
    if ((Get-Content -LiteralPath $edgeAnswer -Raw).Trim() -ne 'YES') { throw 'Edge secure DNS policy or block page was not confirmed.' }
    $result.checks += $scenarios[5]

    $processId = Get-ServiceProcess
    Stop-Process -Id $processId -Force
    Wait-Until { $null -eq (Get-Process -Id $processId -ErrorAction SilentlyContinue) } 10 'Killed agent process did not exit.'
    if (-not (Test-Bypass)) { throw 'Bypass became possible while the agent was not running.' }
    Assert-ManagedRule
    Wait-Until { $current = Get-ServiceProcess; $current -gt 0 -and $current -ne $processId -and (Test-Blocked 'a.b.iana.org') } 90 'Service recovery did not restore resolution.'
    if (-not (Test-Bypass)) { throw 'Bypass is possible after recovery.' }
    $result.checks += $scenarios[6]

    Stop-Service -Name openems-agent
    if (@(Get-ManagedRules).Count) { throw 'Graceful stop left the managed NRPT rule.' }
    if ((Send-RawDns $resolver 'example.org') -ne 0) { throw 'Graceful stop left the DNS filters.' }
    if (-not (Test-Upstream 'example.org')) { throw 'DNS did not work after the agent handed it back.' }
    Start-Service -Name openems-agent
    Wait-Until { @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'a.b.iana.org') -and (Test-Bypass) } 90 'Service start did not restore the rule and filters.'
    $result.checks += $scenarios[7]

    Invoke-Msi $true @()
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Uninstalled service still exists.' }
    if (@(Get-ManagedRules).Count) { throw 'Removal left the managed NRPT rule.' }
    if ((@($baselineRules) -join ',') -ne (@(Get-NrptNames) -join ',')) { throw 'Removal changed unrelated NRPT rules.' }
    if ((Send-RawDns $resolver 'example.org') -ne 0 -or -not (Test-Tcp $dohProbe 443)) { throw 'Removal left network filters.' }
    foreach ($setting in $browserPolicies) {
        if ($null -ne (Get-PolicyValue $setting.key $setting.name)) { throw ('Removal left browser policy ' + $setting.key + '\' + $setting.name + '.') }
    }
    Assert-Trust $managedRoot $baselineRoots $false
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) { throw 'Uninstall did not restore hosts.' }
    $result.checks += $scenarios[8]
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
