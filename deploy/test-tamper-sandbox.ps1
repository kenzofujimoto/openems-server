param([string]$OutputDirectory = 'C:\openems-results', [switch]$SystemPhase, [switch]$Plan)
# F5 part 5a acceptance (tamper-protection.md) for the production MSI in Windows Sandbox with networking.
# The SYSTEM phase installs, tampers like an attacker with SYSTEM rights and waits for repairs and
# tamper events at the simulated backend. SYSTEM may do anything, so permission checks run in the
# operator's administrator session and as a standard user created inside the Sandbox.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$packages = @('openems-agent-previous.msi', 'openems-agent.msi', 'openems-agent-next.msi')
$origin = 'http://127.0.0.1:18013'
$report = 'tamper-result.json'
$comment = 'openems-agent managed DNS filter'
$taskName = 'openems-agent watchdog'
$operationTimeout = 240
$totalTimeout = 2700
$policy = [ordered]@{ vdom='Default'; version=1; digest='4a8ce82a838621f0eea252eb12da8652c5e45e4571392f269b6e3c675d5859ed'
                      body=[ordered]@{ web_filter=[ordered]@{ blocked=@('tamper.example') } } }
$tamperKinds = @('dns_rule_restored', 'browser_policy_restored', 'service_config_restored', 'watchdog_restored',
                 'unexpected_exit', 'service_started_by_watchdog')
$scenarios = @('upgrade from the previous release applies the restricted service permissions and the watchdog scheduled task',
               'a standard user cannot stop, reconfigure or delete the service, edit agent.json or write to the program folder',
               'an administrator cannot stop, reconfigure or delete the service',
               'a deleted NRPT rule is recreated and reported',
               'a changed browser policy is reapplied and reported',
               'removed recovery actions and a reset service DACL are restored and reported',
               'a deleted watchdog scheduled task is recreated and reported',
               'a killed service is restarted by recovery and the unexpected exit is reported',
               'a disabled and stopped service is started again by the scheduled watchdog and reported',
               'upgrade to a later version works with the restricted permissions',
               'removal deletes the scheduled task and restores NRPT rules, browser policies, trust and hosts')
if ($Plan) {
    @{ packages=$packages; origin=$origin; report=$report; timeout_seconds=$totalTimeout; policy=$policy
       tamper_kinds=$tamperKinds; scenarios=$scenarios } | ConvertTo-Json -Depth 10
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
# Exit code of sc.exe from this session: 5 is ERROR_ACCESS_DENIED.
function Invoke-Sc([string[]]$Arguments) {
    & (Join-Path $env:SystemRoot 'System32\sc.exe') @Arguments | Out-Null
    return $LASTEXITCODE
}
# Runs in the operator's (administrator) session: what an administrator and a standard user can do.
function Test-Permissions([string]$Work) {
    $outcome = [ordered]@{}
    $outcome.admin_stop = Invoke-Sc @('stop', 'openems-agent')
    $outcome.admin_config = Invoke-Sc @('config', 'openems-agent', 'start=', 'disabled')
    $outcome.admin_delete = Invoke-Sc @('delete', 'openems-agent')
    $name = 'oemsstd' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    # Random test password, kept in memory only and discarded with the account and the Sandbox.
    $bytes = New-Object byte[] 24
    $generator = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $generator.GetBytes($bytes) } finally { $generator.Dispose() }
    $secret = ConvertTo-SecureString ([Convert]::ToBase64String($bytes) + 'aA1!') -AsPlainText -Force
    $probe = Join-Path $env:PUBLIC ('openems-std-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $probe | Out-Null
    $agentJson = 'C:\ProgramData\openems\agent.json'
    $before = (Get-FileHash -LiteralPath $agentJson).Hash
    $commands = @('@echo off',
                  'sc.exe stop openems-agent >nul 2>&1', 'echo user_stop=%errorlevel%>>"%~dp0result.txt"',
                  'sc.exe config openems-agent start= disabled >nul 2>&1', 'echo user_config=%errorlevel%>>"%~dp0result.txt"',
                  'sc.exe delete openems-agent >nul 2>&1', 'echo user_delete=%errorlevel%>>"%~dp0result.txt"',
                  '(echo x)>>"C:\ProgramData\openems\agent.json" 2>nul', 'echo user_agent_json=%errorlevel%>>"%~dp0result.txt"',
                  'copy /y nul "C:\Program Files\openems\probe.txt" >nul 2>&1', 'echo user_program_files=%errorlevel%>>"%~dp0result.txt"')
    Set-Content -LiteralPath (Join-Path $probe 'probe.cmd') -Value $commands -Encoding ASCII
    New-LocalUser -Name $name -Password $secret -AccountNeverExpires -Description 'openems acceptance standard user' | Out-Null
    try {
        Add-LocalGroupMember -Group 'Users' -Member $name
        $credential = New-Object Management.Automation.PSCredential(($env:COMPUTERNAME + '\' + $name), $secret)
        Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\cmd.exe') -ArgumentList @('/c', ('"' + (Join-Path $probe 'probe.cmd') + '"')) `
            -Credential $credential -WorkingDirectory $probe -WindowStyle Hidden -Wait
    } finally { Remove-LocalUser -Name $name -ErrorAction Continue }
    $resultFile = Join-Path $probe 'result.txt'
    if (Test-Path -LiteralPath $resultFile) {
        foreach ($line in Get-Content -LiteralPath $resultFile) {
            $key, $value = $line.Trim() -split '=', 2
            $outcome[$key] = [int]$value
        }
    }
    $outcome.agent_json_unchanged = ((Get-FileHash -LiteralPath $agentJson).Hash -eq $before)
    $outcome.program_files_probe_absent = -not (Test-Path -LiteralPath 'C:\Program Files\openems\probe.txt')
    $outcome | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $Work 'permissions-result.json') -Encoding UTF8
}
if (-not $SystemPhase) {
    # One run per Sandbox: a second run would collide on ports and the installed product.
    try { [IO.File]::Open('C:\openems-tamper-acceptance.lock', 'CreateNew', 'Write', 'None').Dispose() }
    catch { throw 'A tamper acceptance run already started in this Sandbox; wait for its result or use a fresh Sandbox.' }
    $work = Join-Path 'C:\' ('openems-tamper-' + [Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $work | Out-Null
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)')
    Set-Acl -LiteralPath $work -AclObject $acl
    foreach ($package in $packages) { Copy-Item -LiteralPath (Join-Path $PSScriptRoot $package) -Destination $work }
    $script = Join-Path $work 'test-tamper-sandbox.ps1'
    Copy-Item -LiteralPath $PSCommandPath -Destination $script
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    $task = 'OpenemsTamper-' + [Guid]::NewGuid().ToString('N')
    try {
        $action = New-ScheduledTaskAction -Execute powershell.exe -Argument ('-NoProfile -ExecutionPolicy Bypass -File "' + $script + '" -SystemPhase -OutputDirectory "' + $work + '"')
        Register-ScheduledTask -TaskName $task -Action $action -User SYSTEM -RunLevel Highest | Out-Null
        Start-ScheduledTask -TaskName $task
        $result = Join-Path $work $report
        $ready = Join-Path $work 'permissions-ready'
        $answer = Join-Path $work 'permissions-result.json'
        $deadline = [DateTime]::UtcNow.AddSeconds($totalTimeout)
        Write-Host 'Tamper acceptance running (about 20 minutes, mostly waiting for the 5-minute watchdog). Leave this window open.'
        while (-not (Test-Path -LiteralPath $result)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'Tamper acceptance timed out. Close the Sandbox to discard changes.' }
            if ((Test-Path -LiteralPath $ready) -and -not (Test-Path -LiteralPath $answer)) {
                Write-Host 'Checking what an administrator and a standard user can do to the service...'
                Test-Permissions $work
            }
            Start-Sleep -Milliseconds 500
        }
        $value = Get-Content -LiteralPath $result -Raw | ConvertFrom-Json
        Write-Report (Join-Path $OutputDirectory $report) $value
        $value | ConvertTo-Json -Depth 8 | Write-Output
        if (-not $value.passed) { throw 'Tamper acceptance failed; private logs remain inside Sandbox.' }
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
$edgePolicy = 'HKLM:\SOFTWARE\Policies\Microsoft\Edge'
function Invoke-Msi([string]$Package, [bool]$Remove, [string[]]$Properties) {
    $operation = if ($Remove) { '/x' } else { '/i' }
    $log = Join-Path $work ([Guid]::NewGuid().ToString('N') + '.log')
    $arguments = @($operation, ('"' + (Join-Path $work $Package) + '"'), '/qn', '/norestart', '/l*v', ('"' + $log + '"')) + $Properties
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
function Get-StartMode {
    $service = Get-CimInstance Win32_Service -Filter "Name='openems-agent'"
    if ($null -eq $service) { return '' }
    return [string]$service.StartMode
}
# PowerShell unrolls returned arrays (one item becomes a scalar, none becomes $null): callers wrap in @().
function Get-NrptNames { return @(Get-DnsClientNrptRule | ForEach-Object Name | Sort-Object) }
function Get-ManagedRules { return @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq $comment }) }
# System path: no -Server, so the DNS client applies NRPT. The cache is cleared before every check.
function Test-Blocked([string]$Name) {
    Clear-DnsClientCache
    try {
        $addresses = @(Resolve-DnsName -Name $Name -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop |
            Where-Object { [string]$_.Type -eq 'A' } | ForEach-Object { [string]$_.IPAddress })
    } catch { return $false }
    return ($addresses.Count -eq 1 -and $addresses[0] -eq '127.0.0.1')
}
function Wait-Until([scriptblock]$Condition, [int]$Seconds, [string]$Failure) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if (& $Condition) { return }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw $Failure
}
# Trustee -> sorted two-letter rights, from the service DACL as Windows reports it.
function Get-ServiceAces {
    $sddl = (& (Join-Path $env:SystemRoot 'System32\sc.exe') sdshow openems-agent | Where-Object { $_ -match 'D:' }) -join ''
    $dacl = ($sddl -split 'S:')[0]
    $aces = @{}
    foreach ($match in [regex]::Matches($dacl, '\(A;[^;]*;([A-Z]*);[^;]*;[^;]*;([^)]*)\)')) {
        $letters = $match.Groups[1].Value
        $aces[$match.Groups[2].Value] = (@(for ($index = 0; $index -lt $letters.Length; $index += 2) { $letters.Substring($index, 2) }) | Sort-Object) -join ','
    }
    return $aces
}
function Test-RestrictedDacl {
    $aces = Get-ServiceAces
    $expected = @{ SY='CC,CR,DC,DT,LC,LO,RC,RP,SD,SW,WD,WO,WP'; BA='CC,LC,LO,RC,RP,SW'; AU='CC,LC,LO,RC,SW' }
    if ($aces.Count -ne $expected.Count) { return $false }
    foreach ($trustee in $expected.Keys) { if ($aces[$trustee] -ne $expected[$trustee]) { return $false } }
    return $true
}
function Test-Task {
    & (Join-Path $env:SystemRoot 'System32\schtasks.exe') '/Query' '/TN' $taskName 2>$null | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function Test-Recovery {
    $text = (& (Join-Path $env:SystemRoot 'System32\sc.exe') qfailure openems-agent) -join "`n"
    return ([regex]::Matches($text, 'RESTART').Count -ge 3)
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
function Set-Policy($Assignment) { $Assignment | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $policyFile -Encoding UTF8 }
# Simulated EMS backend: assigned policy, and tamper uploads recorded one per line.
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
                    '/fct/api/public/v1/register/' { $payload = @{ client_id='sandbox-tamper'; device_token='sandbox-fixture-only' } }
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
$baselineRoots = $null
$managedRoot = $null
try {
    if (Test-Path -LiteralPath 'C:\ProgramData\openems') { throw 'A fresh Sandbox is required: openems data already exists.' }
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'A fresh Sandbox is required: service already exists.' }
    foreach ($port in @(53, 80, 443, 18013)) {
        $probe = New-Object Net.Sockets.TcpListener([Net.IPAddress]::Loopback, $port)
        try { $probe.Start() } finally { $probe.Stop() }
    }
    foreach ($package in $packages) { Assert-ProductionPackage ([string](Join-Path $work $package)) }
    $baselineRoots = Get-Roots
    $baselineHosts = (Get-FileHash -LiteralPath $hosts).Hash
    $baselineRules = @(Get-NrptNames)
    $baselineEdge = (Get-ItemProperty -LiteralPath $edgePolicy -Name DnsOverHttpsMode -ErrorAction SilentlyContinue)
    Set-Policy $policy
    $backend = Start-Backend

    Invoke-Msi $packages[0] $false @('SERVER=' + $origin, 'BLOCKPAGEHTTPS=1', 'DNSFILTER=1', 'ANTIBYPASS=1')
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'tamper.example') } 120 'The previous release did not start filtering.'
    Invoke-Msi $packages[1] $false @()
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'tamper.example') } 120 'The upgraded agent did not resume filtering.'
    if (-not (Test-RestrictedDacl)) { throw ('Service DACL is not the restricted one: ' + ((Get-ServiceAces).GetEnumerator() | ForEach-Object { $_.Key + '=' + $_.Value }) -join ' ') }
    Wait-Until { Test-Task } 90 'The watchdog scheduled task was not created.'
    $managedRoot = Get-ManagedRoot
    $result.checks += $scenarios[0]

    Set-Content -LiteralPath (Join-Path $work 'permissions-ready') -Value ready
    $permissionsFile = Join-Path $work 'permissions-result.json'
    Wait-Until { Test-Path -LiteralPath $permissionsFile } 300 'The operator session did not report the permission checks.'
    $permissions = Get-Content -LiteralPath $permissionsFile -Raw | ConvertFrom-Json
    foreach ($key in @('user_stop', 'user_config', 'user_delete')) {
        if ($null -eq $permissions.PSObject.Properties[$key] -or $permissions.$key -ne 5) { throw ('Standard user was not denied: ' + $key + '=' + $permissions.PSObject.Properties[$key].Value) }
    }
    foreach ($key in @('user_agent_json', 'user_program_files')) {
        if ($null -eq $permissions.PSObject.Properties[$key] -or $permissions.$key -eq 0) { throw ('Standard user write succeeded: ' + $key) }
    }
    if (-not $permissions.agent_json_unchanged -or -not $permissions.program_files_probe_absent) { throw 'A standard user changed the agent files.' }
    $result.checks += $scenarios[1]
    foreach ($key in @('admin_stop', 'admin_config', 'admin_delete')) {
        if ($permissions.$key -ne 5) { throw ('Administrator was not denied: ' + $key + '=' + $permissions.$key) }
    }
    if ((Get-ServiceProcess) -le 0 -or (Get-StartMode) -ne 'Auto') { throw 'The service changed during the permission checks.' }
    $result.checks += $scenarios[2]

    Get-ManagedRules | ForEach-Object { Remove-DnsClientNrptRule -Name $_.Name -Force }
    Wait-Until { @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'tamper.example') } 45 'The deleted NRPT rule was not recreated.'
    Wait-Reported 'dns_rule_restored' 60
    $result.checks += $scenarios[3]

    Set-ItemProperty -LiteralPath $edgePolicy -Name DnsOverHttpsMode -Value 'automatic'
    Wait-Until { (Get-ItemProperty -LiteralPath $edgePolicy -Name DnsOverHttpsMode).DnsOverHttpsMode -eq 'off' } 90 'The changed browser policy was not reapplied.'
    Wait-Reported 'browser_policy_restored' 60
    $result.checks += $scenarios[4]

    Invoke-Sc @('failure', 'openems-agent', 'reset=', '0', 'actions=', '""') | Out-Null
    Wait-Until { Test-Recovery } 45 'Removed recovery actions were not restored.'
    Invoke-Sc @('sdset', 'openems-agent', 'D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)') | Out-Null
    Wait-Until { Test-RestrictedDacl } 45 'The reset service DACL was not restored.'
    Wait-Reported 'service_config_restored' 60
    $result.checks += $scenarios[5]

    & (Join-Path $env:SystemRoot 'System32\schtasks.exe') '/Delete' '/TN' $taskName '/F' | Out-Null
    Wait-Until { Test-Task } 120 'The deleted watchdog task was not recreated.'
    Wait-Reported 'watchdog_restored' 60
    $result.checks += $scenarios[6]

    $processId = Get-ServiceProcess
    Stop-Process -Id $processId -Force
    Wait-Until { $current = Get-ServiceProcess; $current -gt 0 -and $current -ne $processId } 90 'Recovery did not restart the killed service.'
    Wait-Reported 'unexpected_exit' 60
    $result.checks += $scenarios[7]

    # With SYSTEM rights (or ownership taken) the service can be disabled and stopped; the scheduled
    # watchdog, which runs every 5 minutes, must put it back.
    Invoke-Sc @('config', 'openems-agent', 'start=', 'disabled') | Out-Null
    Invoke-Sc @('stop', 'openems-agent') | Out-Null
    Wait-Until { (Get-ServiceProcess) -eq 0 } 60 'The service did not stop for the watchdog check.'
    Wait-Until { (Get-ServiceProcess) -gt 0 -and (Get-StartMode) -eq 'Auto' } 420 'The scheduled watchdog did not restore the service.'
    Wait-Reported 'service_started_by_watchdog' 90
    $result.checks += $scenarios[8]

    Invoke-Msi $packages[2] $false @()
    Wait-Until { (Get-ServiceProcess) -gt 0 -and @(Get-ManagedRules).Count -eq 1 -and (Test-Blocked 'tamper.example') } 120 'The later version did not resume filtering.'
    if (-not (Test-RestrictedDacl)) { throw 'The later version lost the restricted service DACL.' }
    $result.checks += $scenarios[9]

    Invoke-Msi $packages[2] $true @()
    if ($null -ne (Get-Service openems-agent -ErrorAction SilentlyContinue)) { throw 'Uninstalled service still exists.' }
    if (Test-Task) { throw 'Removal left the watchdog scheduled task.' }
    if (@(Get-ManagedRules).Count) { throw 'Removal left the managed NRPT rule.' }
    if ((@($baselineRules) -join ',') -ne (@(Get-NrptNames) -join ',')) { throw 'Removal changed unrelated NRPT rules.' }
    $edgeNow = Get-ItemProperty -LiteralPath $edgePolicy -Name DnsOverHttpsMode -ErrorAction SilentlyContinue
    if (($null -eq $baselineEdge) -ne ($null -eq $edgeNow)) { throw 'Removal did not restore the browser policy.' }
    Assert-Trust $managedRoot $baselineRoots $false
    if ((Get-FileHash -LiteralPath $hosts).Hash -ne $baselineHosts) { throw 'Uninstall did not restore hosts.' }
    $result.checks += $scenarios[10]
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
