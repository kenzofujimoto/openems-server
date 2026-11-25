function ConvertTo-BrowserRootTraceThumbprints {
    param([string[]]$Thumbprints)

    if ($Thumbprints.Count -lt 1 -or $Thumbprints.Count -gt 16) { throw 'Invalid trace thumbprint count.' }
    $normalized = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($thumbprint in $Thumbprints) {
        if ($thumbprint -notmatch '^[0-9A-Fa-f]{40}$' -or -not $normalized.Add($thumbprint.ToUpperInvariant())) {
            throw 'Invalid or duplicate trace thumbprint.'
        }
    }
    return @($normalized | Sort-Object)
}

function Read-BrowserRootProcmonCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][string]$LiteralPath,
        [Parameter(Mandatory=$true)][string[]]$Thumbprints,
        [ValidateRange(1,1048576)][int]$MaxRows = 1048576,
        [ValidateRange(1,134217728)][long]$MaxBytes = 134217728
    )

    $targets = @(ConvertTo-BrowserRootTraceThumbprints $Thumbprints)
    $file = Get-Item -LiteralPath $LiteralPath -ErrorAction Stop
    if ($file -isnot [IO.FileInfo] -or $file.Attributes.HasFlag([IO.FileAttributes]::ReparsePoint)) {
        throw 'Procmon CSV must be a regular file.'
    }
    if ($file.Length -gt $MaxBytes) { throw 'Procmon CSV exceeded the byte limit.' }

    Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
    $encoding = [Text.UTF8Encoding]::new($false, $true)
    $reader = [Microsoft.VisualBasic.FileIO.TextFieldParser]::new($file.FullName, $encoding, $true)
    $writes = [Collections.Generic.List[object]]::new()
    $scanned = 0
    try {
        $reader.SetDelimiters(',')
        $reader.HasFieldsEnclosedInQuotes = $true
        $reader.TrimWhiteSpace = $false
        $header = $reader.ReadFields()
        if ($null -eq $header -or $header.Count -gt 32) { throw 'Invalid Procmon CSV header.' }
        $columns = @{}
        for ($column = 0; $column -lt $header.Count; $column++) {
            $name = $header[$column]
            if ([string]::IsNullOrWhiteSpace($name) -or $columns.ContainsKey($name)) {
                throw 'Procmon CSV header is blank or ambiguous.'
            }
            $columns.Add($name, $column)
        }
        foreach ($name in @('Time of Day','Process Name','PID','Operation','Path','Result','Detail')) {
            if (-not $columns.ContainsKey($name)) { throw "Procmon CSV header is missing $name." }
        }

        $registryPattern = '^(?<hive>HKLM|HKEY_LOCAL_MACHINE|HKCU|HKEY_CURRENT_USER|(?:HKU|HKEY_USERS)\\S-[0-9-]+)' +
            '\\Software\\(?:(?:Policies\\)?Microsoft\\SystemCertificates|Microsoft\\EnterpriseCertificates)' +
            '\\(?<store>Root|AuthRoot)\\Certificates\\(?<hash>[0-9A-Fa-f]{40})(?<value>\\[^\\]+)?$'
        $timeFormats = @('H:mm:ss.FFFFFFF','h:mm:ss.FFFFFFF tt','H:mm:ss','h:mm:ss tt')
        while (-not $reader.EndOfData) {
            if ($scanned -ge $MaxRows) { throw 'Procmon CSV exceeded the row limit.' }
            try { $fields = $reader.ReadFields() }
            catch { throw 'Procmon CSV contains a malformed row.' }
            $scanned++
            if ($null -eq $fields -or $fields.Count -ne $header.Count) { throw 'Procmon CSV contains a malformed row.' }

            $operation = $fields[$columns['Operation']]
            if ($fields[$columns['Result']] -cne 'SUCCESS' -or $operation -cnotin @('RegSetValue','RegCreateKey')) { continue }
            $path = $fields[$columns['Path']]
            if ($path.Length -gt 2048 -or $path -notmatch $registryPattern) { continue }
            $thumbprint = $Matches['hash'].ToUpperInvariant()
            if ($thumbprint -cnotin $targets) { continue }
            $registryScope = 'user'
            if ($Matches['hive'] -in @('HKLM','HKEY_LOCAL_MACHINE')) { $registryScope = 'local_machine' }
            $store = $Matches['store'].ToLowerInvariant()
            $writeKind = 'value_set'
            if ($operation -ceq 'RegCreateKey') {
                if ($Matches.ContainsKey('value') -or
                    $fields[$columns['Detail']] -notmatch '\bDisposition:\s*REG_CREATED_NEW_KEY\b') { continue }
                $writeKind = 'key_created'
            }
            $process = $fields[$columns['Process Name']]
            $pidText = $fields[$columns['PID']]
            [uint32]$processId = 0
            if ($process -notmatch '^[^\\/:*?"<>|\p{C}]{1,260}$' -or [string]::IsNullOrWhiteSpace($process) -or
                $pidText -notmatch '^[0-9]{1,10}$' -or -not [uint32]::TryParse($pidText,[ref]$processId) -or $processId -eq 0) {
                throw 'Procmon write has an invalid process identity.'
            }
            $timeOfDay = $fields[$columns['Time of Day']]
            $normalizedTime = $timeOfDay.Replace(',', '.')
            $timestamp = [datetime]::MinValue
            if ($normalizedTime.Length -gt 32 -or -not [datetime]::TryParseExact($normalizedTime, [string[]]$timeFormats,
                [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::AllowWhiteSpaces, [ref]$timestamp)) {
                throw 'Procmon write has an invalid time-of-day timestamp.'
            }
            if ($writes.Count -ge 512) { throw 'Procmon CSV exceeded the target write limit.' }
            $writes.Add([ordered]@{
                process_name=$process;pid=$processId;operation=$operation;registry_path=$path
                registry_scope=$registryScope;store=$store;thumbprint=$thumbprint;write_kind=$writeKind
                time_of_day=$timeOfDay;time_of_day_ticks=$timestamp.TimeOfDay.Ticks
                time_of_day_iso=$timestamp.ToString('HH:mm:ss.fffffff',[Globalization.CultureInfo]::InvariantCulture)
            })
        }
    }
    finally { $reader.Dispose() }
    return [ordered]@{rows_scanned=$scanned;writes=$writes.ToArray()}
}

function Get-BrowserRootCapi2PayloadXml {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text) -or $Text.Length -gt 262144) {
        throw 'CAPI2 event XML is empty or exceeds its limit.'
    }
    $settings = [Xml.XmlReaderSettings]::new()
    $settings.DtdProcessing = [Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver = $null
    $settings.MaxCharactersInDocument = 262144
    $source = [IO.StringReader]::new($Text)
    $reader = $null
    try {
        $reader = [Xml.XmlReader]::Create($source, $settings)
        $document = [Xml.XmlDocument]::new()
        $document.XmlResolver = $null
        $document.Load($reader)
        if ($document.DocumentElement.LocalName -cne 'Event' -or
            $document.DocumentElement.NamespaceURI -cne 'http://schemas.microsoft.com/win/2004/08/events/event') {
            throw 'Missing Windows Event root.'
        }
        $payloadNodes = $document.DocumentElement.SelectNodes('./*[local-name()="UserData" or local-name()="EventData"]')
        return (@($payloadNodes | ForEach-Object OuterXml) -join '')
    }
    catch { throw 'Invalid CAPI2 event XML.' }
    finally {
        if ($null -ne $reader) { $reader.Dispose() }
        $source.Dispose()
    }
}

function Select-BrowserRootCapi2Events {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][object[]]$Events,
        [Parameter(Mandatory=$true)][DateTimeOffset]$WindowStart,
        [Parameter(Mandatory=$true)][DateTimeOffset]$WindowEnd,
        [Parameter(Mandatory=$true)][string[]]$Thumbprints,
        [string[]]$Subjects = @()
    )

    if ($WindowEnd -le $WindowStart -or ($WindowEnd - $WindowStart).TotalMinutes -gt 30) {
        throw 'Invalid CAPI2 event window.'
    }
    if ($Events.Count -gt 500) { throw 'CAPI2 export exceeded the event limit.' }
    $targets = @(ConvertTo-BrowserRootTraceThumbprints $Thumbprints)
    if ($Subjects.Count -gt 16) { throw 'CAPI2 subject count exceeded its limit.' }
    foreach ($subject in $Subjects) {
        if ($subject -notmatch '^[^,\p{C}]{1,256}$' -or [string]::IsNullOrWhiteSpace($subject)) {
            throw 'Invalid CAPI2 subject to match.'
        }
    }
    $records = [Collections.Generic.List[object]]::new()
    foreach ($event in $Events) {
        if ($null -eq $event -or $event.LogName -cne 'Microsoft-Windows-CAPI2/Operational' -or
            $event.ProviderName -cne 'Microsoft-Windows-CAPI2') { throw 'Unexpected CAPI2 event channel.' }
        if ($event.TimeCreated -isnot [datetime]) { throw 'Invalid CAPI2 event timestamp.' }
        $time = $event.TimeCreated.ToUniversalTime()
        if ($time -lt $WindowStart.UtcDateTime -or $time -gt $WindowEnd.UtcDateTime) { continue }
        if ($event.RecordId -le 0 -or $event.Id -le 0 -or
            ($null -ne $event.ProcessId -and $event.ProcessId -lt 0) -or
            ($null -ne $event.ThreadId -and $event.ThreadId -lt 0)) {
            throw 'Invalid CAPI2 event metadata.'
        }
        $xml = Get-BrowserRootCapi2PayloadXml $event.ToXml()
        $matchedThumbprints = @($targets | Where-Object { $xml -match ('(?<![0-9A-F])' + $_ + '(?![0-9A-F])') })
        $matchedSubjects = @($Subjects | Where-Object {
            $xml -match ('(?<![\p{L}\p{N}_-])' + [regex]::Escape($_) + '(?=\s*(?:[,<"&]|$))')
        })
        $records.Add([ordered]@{
            timestamp_utc=$time.ToString('o');record_id=$event.RecordId;event_id=$event.Id
            pid=$event.ProcessId;thread_id=$event.ThreadId
            matched_thumbprints=$matchedThumbprints;matched_subjects=$matchedSubjects
        })
    }
    return [ordered]@{
        window_start_utc=$WindowStart.UtcDateTime.ToString('o');window_end_utc=$WindowEnd.UtcDateTime.ToString('o')
        events_scanned=$records.Count;events=@($records | Sort-Object { $_.timestamp_utc }, { $_.record_id })
    }
}
