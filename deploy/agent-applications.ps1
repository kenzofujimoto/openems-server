# Embedded adapter. All selectors arrive as JSON data on stdin; no policy text is evaluated.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = New-Object Text.UTF8Encoding($false)
[Console]::OutputEncoding = New-Object Text.UTF8Encoding($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$group = 'openems application control'
$events = @()
function Field($Object, [string]$Name, $Default) {
    if ($null -eq $Object) { return $Default }
    $property = $Object.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    return $property.Value
}
function Result($Value) { $Value | ConvertTo-Json -Depth 12 -Compress | Write-Output }
function Protect-File([string]$Path) {
    $acl = New-Object Security.AccessControl.FileSecurity
    $acl.SetSecurityDescriptorSddlForm('O:SYD:P(A;;FA;;;SY)')
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Save-State {
    $temporary = $request.state_path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Open($temporary, 'CreateNew', 'Write', 'None').Dispose()
        Protect-File $temporary
        [IO.File]::WriteAllText($temporary, ($script:state | ConvertTo-Json -Depth 12 -Compress), (New-Object Text.UTF8Encoding($false)))
        Move-Item -LiteralPath $temporary -Destination $request.state_path -Force
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Force }
    }
}
function Get-Application([string]$Path, [bool]$Running, [string]$Name, [string]$Version) {
    $hash = ''; $publisher = ''; $valid = $false; $original = ''
    if ($Path -and (Test-Path -LiteralPath $Path -PathType Leaf)) {
        try {
            $item = Get-Item -LiteralPath $Path -ErrorAction Stop
            if ($item.Length -le 536870912) {
                $hash = (Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
                $signature = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
                $valid = $signature.Status -eq 'Valid'
                if ($valid -and $null -ne $signature.SignerCertificate) { $publisher = $signature.SignerCertificate.Subject }
            }
            $original = [string]$item.VersionInfo.OriginalFilename
            if (-not $Version) { $Version = [string]$item.VersionInfo.FileVersion }
            if (-not $Name) { $Name = [string]$item.VersionInfo.ProductName }
        } catch {
            # Inaccessible/racing processes remain in inventory with unknown cryptographic identity.
            $hash = ''; $publisher = ''; $valid = $false
        }
    }
    if (-not $Name) { $Name = [IO.Path]::GetFileName($Path) }
    return [pscustomobject]@{name=$Name; path=$Path; sha256=$hash; publisher=$publisher; version=$Version; running=$Running; signature_valid=$valid; original_name=$original}
}
function Inventory {
    $byPath = @{}
    foreach ($process in @(Get-CimInstance Win32_Process -ErrorAction Stop)) {
        $path = [string]$process.ExecutablePath
        if (-not $path -or -not $path.EndsWith('.exe', [StringComparison]::OrdinalIgnoreCase)) { continue }
        $key = $path.ToLowerInvariant()
        if (-not $byPath.ContainsKey($key)) { $byPath[$key] = Get-Application $path $true ([string]$process.Name) '' }
        if ($byPath.Count -ge 384) { break }
    }
    foreach ($root in @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
        if (-not (Test-Path -LiteralPath $root)) { continue }
        foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction Stop)) {
            $entry = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            $name = [string](Field $entry 'DisplayName' '')
            if (-not $name) { continue }
            $icon = [string](Field $entry 'DisplayIcon' '')
            $path = ''
            if ($icon -match '^"([^"]+\.exe)"') { $path = $Matches[1] }
            elseif ($icon -match '^(.+\.exe)(?:,\s*-?\d+)?$') { $path = $Matches[1] }
            $version = [string](Field $entry 'DisplayVersion' '')
            $id = if ($path) { $path.ToLowerInvariant() } else { 'installed:' + $key.PSChildName }
            if (-not $byPath.ContainsKey($id)) { $byPath[$id] = Get-Application $path $false $name $version }
            if ($byPath.Count -ge 512) { break }
        }
        if ($byPath.Count -ge 512) { break }
    }
    return @($byPath.Values | Sort-Object path,name | Select-Object -First 512)
}
function Protected-Image([string]$Name) {
    return $Name -match '^(?i:openems-agent|openems-session|services|lsass|svchost|winlogon|csrss|smss|powershell|citool)\.exe$'
}
function Safe-Path([string]$Path) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $Path -match '[*?"<>|%\x00-\x1f\x7f]' -or $Path.Substring(2).Contains(':')) { throw 'OPENEMS_UNSAFE_PATH' }
    foreach ($part in ($Path.Substring(3) -split '[\\/]')) {
        if ($part -in @('.','..') -or $part.EndsWith('.') -or $part.EndsWith(' ')) { throw 'OPENEMS_UNSAFE_PATH' }
    }
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith(($env:SystemRoot.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) { throw 'OPENEMS_PROTECTED_COMPONENT' }
    if (Protected-Image ([IO.Path]::GetFileName($full))) { throw 'OPENEMS_PROTECTED_COMPONENT' }
    return $full
}
function Resolve-Samples($Policy) {
    $inventory = $null; $resolved = @(); $copied = 0; $sampleDirectory = $null
    foreach ($rule in @(Field $Policy 'execution_rules' @())) {
        if ($rule.kind -eq 'path') { $resolved += @{id=$rule.id; kind=$rule.kind; value=(Safe-Path $rule.value); sample_path=$null}; continue }
        $sample = [string](Field $rule 'sample_path' '')
        if (-not $sample) {
            if ($null -eq $inventory) { $inventory = @(Inventory) }
            $found = @($inventory | Where-Object {
                ($rule.kind -eq 'hash' -and $_.sha256 -ieq $rule.value) -or
                ($rule.kind -eq 'publisher' -and $_.signature_valid -and $_.publisher -ieq $rule.value) -or
                ($rule.kind -eq 'name' -and $_.original_name -ieq $rule.value)
            }) | Select-Object -First 1
            if ($null -ne $found) { $sample = $found.path }
        }
        if (-not $sample) { throw 'OPENEMS_SAMPLE_REQUIRED' }
        $sample = Safe-Path $sample
        if (-not (Test-Path -LiteralPath $sample -PathType Leaf)) { throw 'OPENEMS_SAMPLE_REQUIRED' }
        $copied += (Get-Item -LiteralPath $sample -ErrorAction Stop).Length
        if ($copied -gt 134217728) { throw 'OPENEMS_SAMPLE_SIZE_LIMIT' }
        # Work on a protected copy so later user writes cannot change which image is denied.
        if ($null -eq $sampleDirectory) {
            $sampleDirectory = Join-Path $script:directory ('samples-' + [guid]::NewGuid().ToString('N'))
            New-Item -ItemType Directory -Path $sampleDirectory | Out-Null
            $acl = New-Object Security.AccessControl.DirectorySecurity
            $acl.SetSecurityDescriptorSddlForm('O:SYD:P(A;OICI;FA;;;SY)')
            Set-Acl -LiteralPath $sampleDirectory -AclObject $acl
        }
        $copy = Join-Path $sampleDirectory ([guid]::NewGuid().ToString('N') + '.exe')
        [IO.File]::Open($copy, 'CreateNew', 'Write', 'None').Dispose(); Protect-File $copy
        Copy-Item -LiteralPath $sample -Destination $copy -Force
        $actual = Get-Application $copy $false '' ''
        if (Protected-Image $actual.original_name) { throw 'OPENEMS_PROTECTED_COMPONENT' }
        if ($rule.kind -eq 'hash' -and $actual.sha256 -ine $rule.value) { throw 'OPENEMS_SAMPLE_MISMATCH' }
        if ($rule.kind -eq 'publisher' -and (-not $actual.signature_valid -or $actual.publisher -ine $rule.value -or $actual.publisher -match '(?i)microsoft')) { throw 'OPENEMS_SAMPLE_MISMATCH' }
        if ($rule.kind -eq 'name' -and (-not $actual.original_name -or $actual.original_name -ine $rule.value)) { throw 'OPENEMS_SAMPLE_MISMATCH' }
        $resolved += @{id=$rule.id; kind=$rule.kind; value=$rule.value; sample_path=$copy}
    }
    return @($resolved)
}
function Driver-MatchesSample($Driver, [string]$Sample) {
    $matched = $false
    foreach ($name in @('FilePath','FriendlyName')) {
        $path = [string](Field $Driver $name '')
        if ($path.StartsWith('\\?\')) { $path = $path.Substring(4) }
        if ([string]::Equals($path, $Sample, [StringComparison]::OrdinalIgnoreCase)) { $matched = $true }
        elseif ([IO.Path]::IsPathRooted($path)) { return $false }
    }
    return $matched
}
function Assert-PrivateHashPolicy([string]$Path) {
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit; $settings.XmlResolver = $null
    $reader = [Xml.XmlReader]::Create($Path, $settings)
    $xml = New-Object Xml.XmlDocument
    $xml.XmlResolver = $null
    try { $xml.Load($reader) } finally { $reader.Dispose() }
    $ns = New-Object Xml.XmlNamespaceManager($xml.NameTable)
    $ns.AddNamespace('ci', 'urn:schemas-microsoft-com:sipolicy')
    $rules = @($xml.SelectNodes('/ci:SiPolicy/ci:FileRules/*', $ns))
    if ($rules.Count -eq 0) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    $ids = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($rule in $rules) {
        $id = $rule.GetAttribute('ID')
        if ($rule.LocalName -cne 'Deny' -or -not $id -or -not $ids.Add($id) -or
            $rule.GetAttribute('Hash') -cnotmatch '^(?:[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64})$') { throw 'OPENEMS_INVALID_HASH_POLICY' }
        foreach ($attribute in $rule.Attributes) {
            if ($attribute.Name -cnotin @('ID','FriendlyName','Hash')) { throw 'OPENEMS_INVALID_HASH_POLICY' }
        }
    }
    if ($xml.SelectNodes('//ci:Signer|//ci:AllowedSigner|//ci:DeniedSigner|//ci:FileAttrib|//ci:Allow', $ns).Count) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    $refs = @($xml.SelectNodes('/ci:SiPolicy/ci:SigningScenarios/ci:SigningScenario[@Value="12"]/ci:ProductSigners/ci:FileRulesRef/ci:FileRuleRef', $ns))
    if ($refs.Count -ne $ids.Count -or $xml.SelectNodes('//ci:FileRuleRef', $ns).Count -ne $refs.Count) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($reference in $refs) {
        $id = $reference.GetAttribute('RuleID')
        if (-not $ids.Contains($id) -or -not $seen.Add($id)) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    }
    $options = @($xml.SelectNodes('/ci:SiPolicy/ci:Rules/ci:Rule/ci:Option', $ns) | ForEach-Object InnerText)
    if ('Enabled:UMCI' -cnotin $options) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    foreach ($option in $options) {
        if ($option -cnotin @('Enabled:UMCI','Enabled:Audit Mode','Enabled:Unsigned System Integrity Policy',
            'Enabled:Advanced Boot Options Menu','Disabled:Script Enforcement','Required:Enforce Store Applications')) { throw 'OPENEMS_INVALID_HASH_POLICY' }
    }
}
function Policies {
    $citool = Join-Path $env:SystemRoot 'System32\CiTool.exe'
    if (-not (Test-Path -LiteralPath $citool)) { throw 'OPENEMS_UNSUPPORTED_WDAC' }
    $output = & $citool --list-policies -json
    if ($LASTEXITCODE -ne 0) { throw 'OPENEMS_WDAC_QUERY_FAILED' }
    return @(($output | ConvertFrom-Json).Policies)
}
function Own-Policy {
    return @(Policies | Where-Object { ([string]$_.PolicyID).Trim('{}') -ieq ([string]$script:state.policy_id).Trim('{}') }) | Select-Object -First 1
}
function Remove-Wdac {
    if (-not $script:state.wdac_owned) { return }
    $owned = Own-Policy
    if ($null -ne $owned) {
        if ([string]$owned.FriendlyName -cne 'openems application control') { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
        & (Join-Path $env:SystemRoot 'System32\CiTool.exe') --remove-policy $script:state.policy_id -json | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'OPENEMS_WDAC_REMOVE_FAILED' }
        if ($null -ne (Own-Policy)) { throw 'OPENEMS_RESTART_REQUIRED' }
    }
    $script:state.wdac_owned = $false; $script:state.execution_digest = ''; Save-State
}
function Check-Firewall($Entry) {
    $existing = Get-NetFirewallRule -PolicyStore PersistentStore -Name $Entry.name -ErrorAction SilentlyContinue
    if ($null -eq $existing) { return $null }
    $application = $existing | Get-NetFirewallApplicationFilter -ErrorAction Stop
    if ([string]$existing.Group -cne $group -or [string]$application.Program -ine [string]$Entry.path -or [string]$existing.Direction -ine [string]$Entry.direction -or [string]$existing.Action -ne 'Block') { throw 'OPENEMS_EXTERNAL_FIREWALL_CHANGE' }
    return $existing
}
function Remove-Firewall($Entry) {
    $existing = Check-Firewall $Entry
    if ($null -ne $existing) { $existing | Remove-NetFirewallRule -ErrorAction Stop }
}
function Block-Event([string]$Text, [string]$PolicyId) {
    $settings = New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null; $settings.MaxCharactersInDocument = 65536
    $reader = [Xml.XmlReader]::Create((New-Object IO.StringReader($Text)), $settings)
    try {
        $document = New-Object Xml.XmlDocument
        $document.XmlResolver = $null; $document.Load($reader)
    } finally { $reader.Dispose() }
    if ([int]$document.Event.System.EventID -ne 3077) { return $null }
    $data = @{}
    foreach ($field in @($document.Event.EventData.Data)) { $data[[string]$field.Name] = [string]$field.'#text' }
    if (-not $data.ContainsKey('PolicyGUID') -or ([string]$data.PolicyGUID).Trim('{}') -ine $PolicyId.Trim('{}')) { return $null }
    $target = if ($data.ContainsKey('FileName')) { [string]$data.FileName } else { 'blocked executable (path unavailable)' }
    $target = $target -replace '[\x00-\x1f\x7f]',''
    if ($target.Length -gt 512) { $target = $target.Substring(0,512) }
    return @{kind='app_block'; detail=$target; rule_id=$PolicyId.Trim('{}')}
}
function Execution-Events {
    if (-not $script:state.wdac_owned) { return @() }
    $cursor = [uint64](Field $script:state 'last_record_id' 0)
    try {
        $records = @(Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -FilterXPath ('*[System[EventID=3077 and EventRecordID > ' + $cursor + ']]') -MaxEvents 100 -Oldest -ErrorAction Stop)
    } catch {
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw }
        return @()
    }
    $blocked = @()
    foreach ($record in $records) {
        $event = Block-Event $record.ToXml() $script:state.policy_id
        if ($null -ne $event) { $blocked += $event }
        $cursor = [math]::Max($cursor, [uint64]$record.RecordId)
    }
    $script:state | Add-Member -NotePropertyName last_record_id -NotePropertyValue $cursor -Force
    Save-State
    return @($blocked)
}
try {
    if ($request.mode -eq 'inventory') { Result @{inventory=@(Inventory)}; exit 0 }
    if ($request.mode -eq 'plan') {
        $rules = @(Field $request.policy 'execution_rules' @())
        Result @{execution_rules=$rules; network_blocked=@(Field $request.policy 'network_blocked' @()); requires_system=$true}; exit 0
    }
    if ($request.mode -eq 'event-plan') { Result @{events=@(Block-Event $request.xml $request.policy_id | Where-Object { $null -ne $_ })}; exit 0 }
    if ($request.mode -eq 'path-plan') { Result @{paths=@($request.paths | ForEach-Object { Safe-Path $_ })}; exit 0 }
    if ($request.mode -notin @('apply','cleanup')) { throw 'OPENEMS_INVALID_MODE' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'OPENEMS_SYSTEM_REQUIRED' }
    if (-not [IO.Path]::IsPathRooted([string]$request.state_path)) { throw 'OPENEMS_INVALID_STATE_PATH' }
    if (Test-Path -LiteralPath $request.state_path) {
        $script:state = Get-Content -LiteralPath $request.state_path -Raw | ConvertFrom-Json
        if ($script:state.format -ne 1 -or [string]$script:state.policy_id -notmatch '^\{[A-Fa-f0-9-]{36}\}$') { throw 'OPENEMS_INVALID_JOURNAL' }
    } else {
        $cursor = 0
        try { $cursor = (Get-WinEvent -LogName 'Microsoft-Windows-CodeIntegrity/Operational' -MaxEvents 1 -ErrorAction Stop).RecordId }
        catch { if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { throw } }
        $script:state = [pscustomobject]@{format=1; policy_id=([guid]::NewGuid().ToString('B')); wdac_owned=$false; execution_digest=''; version=0; firewall=@(); last_record_id=$cursor}
    }
    if ($request.mode -eq 'cleanup') {
        Remove-Wdac
        foreach ($entry in @($script:state.firewall)) { Remove-Firewall $entry }
        Remove-Item -LiteralPath $request.state_path -Force -ErrorAction SilentlyContinue
        Result @{inventory=@();events=@();capabilities=@('app-control:network')}; exit 0
    }
    $execution = @(Field $request.policy 'execution_rules' @())
    $network = @(Field $request.policy 'network_blocked' @())
    # No persistent writes when an unsupported execution policy cannot be applied at all.
    if ($execution.Count) { $null = @(Policies); Import-Module ConfigCI -ErrorAction Stop }
    Save-State
    $script:directory = Join-Path (Split-Path -Parent $request.state_path) ('app-control-' + $script:state.policy_id.Trim('{}'))
    if (-not (Test-Path -LiteralPath $script:directory)) {
        New-Item -ItemType Directory -Path $script:directory | Out-Null
        $acl = New-Object Security.AccessControl.DirectorySecurity
        $acl.SetSecurityDescriptorSddlForm('O:SYD:P(A;OICI;FA;;;SY)')
        Set-Acl -LiteralPath $script:directory -AclObject $acl
    }
    if ($execution.Count -eq 0) { Remove-Wdac }
    else {
        $serialized = ConvertTo-Json -InputObject $execution -Depth 8 -Compress
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $digest = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($serialized)))).Replace('-','').ToLowerInvariant() }
        finally { $hasher.Dispose() }
        $active = Own-Policy
        if (-not ($script:state.execution_digest -eq $digest -and $null -ne $active -and ([string]$active.IsEnforced -ieq 'true'))) {
            if ($null -ne $active -and (-not $script:state.wdac_owned -or [string]$active.FriendlyName -cne 'openems application control')) { throw 'OPENEMS_EXTERNAL_POLICY_CHANGE' }
            $samples = @(Resolve-Samples $request.policy)
            $consoleOut = [Console]::Out
            try {
                # ConfigCI writes directly to Console.Out, outside PowerShell's redirectable streams.
                [Console]::SetOut([IO.TextWriter]::Null)
                $imageSamples = @($samples | Where-Object { $_.kind -ne 'path' })
                $singleHash = $samples.Count -eq 1 -and $samples[0].kind -eq 'hash'
                $directPolicy = $null
                $drivers = @()
                if ($singleHash) {
                    # This bounded route was validated against the DriverFiles-generated deny policy.
                    $directPolicy = Join-Path $script:directory ('hash-' + [guid]::NewGuid().ToString('N') + '.xml')
                    # Hash rules need no external catalog discovery; normal sample signature checks remain above.
                    $catalog = Join-Path $script:directory ('catalog-' + [guid]::NewGuid().ToString('N'))
                    New-Item -ItemType Directory -Path $catalog | Out-Null
                    $acl = New-Object Security.AccessControl.DirectorySecurity
                    $acl.SetSecurityDescriptorSddlForm('O:SYD:P(A;OICI;FA;;;SY)')
                    Set-Acl -LiteralPath $catalog -AclObject $acl
                    New-CIPolicy -ScanPath (Split-Path -Parent $samples[0].sample_path) -FilePath $directPolicy -UserPEs -Level Hash -Deny -NoScript -NoShadowCopy -MultiplePolicyFormat -PathToCatroot $catalog -ErrorAction Stop | Out-Null
                    Protect-File $directPolicy
                    Assert-PrivateHashPolicy $directPolicy
                    # Preserve the existing adapter's scope; New-CIPolicy adds this option by default.
                    Set-RuleOption -FilePath $directPolicy -Option 12 -Delete -ErrorAction Stop
                } elseif ($imageSamples.Count) {
                    # Enumerate only this request's verified private copies, never the system or old samples.
                    $scanPath = Split-Path -Parent $imageSamples[0].sample_path
                    $drivers = @(foreach ($container in @(Get-SystemDriver -ScanPath $scanPath -UserPEs -NoScript -NoShadowCopy -ErrorAction Stop)) {
                        foreach ($driver in $container) { $driver }
                    })
                }
                $deny = @()
                $ruleSamples = @()
                if (-not $singleHash) { $ruleSamples = $samples }
                foreach ($rule in $ruleSamples) {
                    $matching = @()
                    if ($rule.kind -ne 'path') {
                        $matching = @($drivers | Where-Object { $_.UserMode -eq $true -and (Driver-MatchesSample $_ $rule.sample_path) })
                        if ($matching.Count -ne 1) { throw 'OPENEMS_USER_MODE_SAMPLE_REQUIRED' }
                    }
                    $generated = switch ($rule.kind) {
                        'path' { New-CIPolicyRule -FilePathRule $rule.value -Deny -ErrorAction Stop }
                        'hash' { New-CIPolicyRule -DriverFiles $matching -Level Hash -Deny -ErrorAction Stop }
                        'publisher' { New-CIPolicyRule -DriverFiles $matching -Level Publisher -Deny -ErrorAction Stop }
                        'name' { New-CIPolicyRule -DriverFiles $matching -Level FileName -SpecificFileNameLevel OriginalFileName -Deny -ErrorAction Stop }
                        default { throw 'OPENEMS_INVALID_RULE' }
                    }
                    $userRules = @($generated | Where-Object UserMode)
                    if ($userRules.Count -eq 0) { throw 'OPENEMS_NO_USER_MODE_RULE' }
                    $deny += $userRules
                }
                $xmlPath = Join-Path $script:directory 'policy.xml'
                $binaryPath = Join-Path $script:directory ($script:state.policy_id + '.cip')
                $template = Join-Path $env:SystemRoot 'schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml'
                if (-not (Test-Path -LiteralPath $template)) { throw 'OPENEMS_UNSUPPORTED_WDAC' }
                # Merge-CIPolicy opens its input for writing. Never pass the protected Windows template.
                $allow = Join-Path $script:directory 'allow-all.xml'
                Copy-Item -LiteralPath $template -Destination $allow -Force
                Protect-File $allow
                if ($singleHash) { Merge-CIPolicy -PolicyPaths @($allow,$directPolicy) -OutputFilePath $xmlPath -ErrorAction Stop | Out-Null }
                else { Merge-CIPolicy -PolicyPaths $allow -OutputFilePath $xmlPath -Rules $deny -ErrorAction Stop | Out-Null }
                Set-CIPolicyIdInfo -FilePath $xmlPath -PolicyName 'openems application control' -ResetPolicyID -ErrorAction Stop | Out-Null
                Set-RuleOption -FilePath $xmlPath -Option 0 -ErrorAction Stop
                Set-RuleOption -FilePath $xmlPath -Option 3 -Delete -ErrorAction Stop
                foreach ($option in @(6,11,16)) { Set-RuleOption -FilePath $xmlPath -Option $option -ErrorAction Stop }
                [xml]$xml = Get-Content -LiteralPath $xmlPath -Raw
                $xml.SiPolicy.PolicyID = $script:state.policy_id; $xml.SiPolicy.BasePolicyID = $script:state.policy_id
                $script:state.version = [int]$script:state.version + 1
                $xml.SiPolicy.VersionEx = '1.0.' + [math]::Floor($script:state.version / 65536) + '.' + ($script:state.version % 65536)
                $xml.Save($xmlPath)
                ConvertFrom-CIPolicy -XmlFilePath $xmlPath -BinaryFilePath $binaryPath -ErrorAction Stop | Out-Null
            } finally {
                [Console]::SetOut($consoleOut)
            }
            # Ownership intent is durable before CiTool can change the system.
            $script:state.wdac_owned = $true; Save-State
            & (Join-Path $env:SystemRoot 'System32\CiTool.exe') --update-policy $binaryPath -json | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'OPENEMS_WDAC_DEPLOY_FAILED' }
            $active = Own-Policy
            if ($null -eq $active -or [string]$active.IsEnforced -ine 'true') { throw 'OPENEMS_RESTART_REQUIRED' }
            $script:state.execution_digest = $digest; Save-State
            $events += @{kind='app_control_applied'; detail='execution policy applied'; rule_id='execution-policy'}
        }
    }
    $desired = @()
    foreach ($path in $network) {
        $path = Safe-Path $path
        $hasher = [Security.Cryptography.SHA256]::Create()
        try { $hash = ([BitConverter]::ToString($hasher.ComputeHash([Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())))).Replace('-','').Substring(0,20) }
        finally { $hasher.Dispose() }
        foreach ($direction in @('Inbound','Outbound')) {
            $name = 'openems-app-' + $script:state.policy_id.Trim('{}') + '-' + $hash + '-' + $direction
            $entry = [pscustomobject]@{name=$name;path=$path;direction=$direction}
            $known = @($script:state.firewall | Where-Object { $_.name -ceq $name })
            if ($known.Count -eq 0) {
                if ($null -ne (Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction SilentlyContinue)) { throw 'OPENEMS_FIREWALL_COLLISION' }
                $script:state.firewall += $entry; Save-State
            }
            $existing = Check-Firewall $entry
            if ($null -eq $existing) {
                New-NetFirewallRule -PolicyStore PersistentStore -Name $name -DisplayName 'openems application network block' -Group $group -Direction $direction -Program $path -Action Block -Enabled True -Profile Any -ErrorAction Stop | Out-Null
                $events += @{kind='app_network_policy'; detail=('network block policy applied: ' + $path); rule_id='network-policy'}
            } elseif ([string]$existing.Enabled -ine 'true') { $existing | Set-NetFirewallRule -Enabled True -ErrorAction Stop }
            $verified = Check-Firewall $entry
            if ($null -eq $verified -or [string]$verified.Enabled -ine 'true') { throw 'OPENEMS_FIREWALL_VERIFY_FAILED' }
            $desired += $entry
        }
    }
    foreach ($entry in @($script:state.firewall)) {
        if ($entry.name -notin @($desired | ForEach-Object name)) { Remove-Firewall $entry }
    }
    $script:state.firewall = @($desired)
    if ($script:state.wdac_owned) { $events += @(Execution-Events) }
    if ($script:state.wdac_owned -or $desired.Count) { Save-State }
    else { Remove-Item -LiteralPath $request.state_path -Force -ErrorAction SilentlyContinue }
    $capabilities = @('app-control:network')
    if (Test-Path -LiteralPath (Join-Path $env:SystemRoot 'System32\CiTool.exe')) { $capabilities += 'app-control:wdac' }
    Result @{inventory=@();events=@($events);capabilities=$capabilities}
} catch {
    $code = if ($_.Exception.Message -match 'OPENEMS_RESTART_REQUIRED') { 'restart_required' } elseif ($_.Exception.Message -match 'OPENEMS_UNSUPPORTED') { 'unsupported' } else { 'control_failed' }
    Result @{error=$code}; exit 1
}
