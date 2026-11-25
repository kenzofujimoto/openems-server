function ConvertTo-BrowserTrustSnapshot {
    param([AllowEmptyCollection()][object[]]$Thumbprints)
    if ($Thumbprints.Count -gt 512) { throw 'Trust snapshot exceeds its bounded limit.' }
    $unique = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($thumbprint in $Thumbprints) {
        if ($thumbprint -isnot [string] -or $thumbprint -notmatch '^[0-9a-fA-F]{40}$') {
            throw 'Malformed trust thumbprint.'
        }
        if (-not $unique.Add($thumbprint.ToUpperInvariant())) { throw 'Duplicate trust thumbprint.' }
    }
    return @($unique | Sort-Object)
}

function Start-BrowserTrustBaseline {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$AssertGuest,
        [Parameter(Mandatory=$true)][scriptblock]$WarmupTls,
        [Parameter(Mandatory=$true)][scriptblock]$VerifyRuntimes,
        [Parameter(Mandatory=$true)][scriptblock]$ReadRoots,
        [Parameter(Mandatory=$true)][scriptblock]$WriteEvidence
    )
    & $AssertGuest | Out-Null
    & $WarmupTls | Out-Null
    & $VerifyRuntimes | Out-Null
    $before = @(ConvertTo-BrowserTrustSnapshot -Thumbprints @(& $ReadRoots))
    & $WriteEvidence ([ordered]@{phase='before';at_utc=[DateTime]::UtcNow.ToString('o');thumbprints=$before}) | Out-Null
    return $before
}

function Complete-BrowserTrustBaseline {
    param(
        [Parameter(Mandatory=$true)][scriptblock]$AssertGuest,
        [AllowEmptyCollection()][string[]]$Baseline,
        [Parameter(Mandatory=$true)][scriptblock]$ReadRoots,
        [Parameter(Mandatory=$true)][scriptblock]$OwnedRootPresent,
        [Parameter(Mandatory=$true)][scriptblock]$WriteEvidence
    )
    & $AssertGuest | Out-Null
    $before = @(ConvertTo-BrowserTrustSnapshot -Thumbprints $Baseline)
    $snapshotRecord = [ordered]@{
        phase='after';at_utc=[DateTime]::UtcNow.ToString('o');before=$before;after=@()
        added=@();removed=@();owned_root_present=$null;passed=$false;error_category=$null
    }
    try {
        $after = @(ConvertTo-BrowserTrustSnapshot -Thumbprints @(& $ReadRoots))
        $snapshotRecord.after = $after
        $snapshotRecord.added = @($after | Where-Object { $_ -cnotin $before })
        $snapshotRecord.removed = @($before | Where-Object { $_ -cnotin $after })
        $owned = & $OwnedRootPresent
        if ($owned -isnot [bool]) { throw 'Owned-root observation must be boolean.' }
        $snapshotRecord.owned_root_present = $owned
        $snapshotRecord.passed = $snapshotRecord.added.Count -eq 0 -and $snapshotRecord.removed.Count -eq 0 -and -not $owned
    }
    catch {
        $snapshotRecord.error_category = 'SnapshotUnavailable'
        & $WriteEvidence $snapshotRecord | Out-Null
        throw
    }
    & $WriteEvidence $snapshotRecord | Out-Null
    if (-not $snapshotRecord.passed) { throw 'Trust roots differ from baseline or an owned root remains.' }
}

function ConvertTo-BrowserTrustSession {
    param($Session)
    if ($null -eq $Session -or $Session.active -isnot [bool] -or -not $Session.active -or
        $Session.sid -isnot [string] -or $Session.sid.Length -gt 184 -or
        $Session.session_id -notmatch '^[1-9][0-9]{0,9}$' -or [uint64]$Session.session_id -gt [uint32]::MaxValue) {
        throw 'An active interactive session is required.'
    }
    $sid = [Security.Principal.SecurityIdentifier]::new($Session.sid)
    return [ordered]@{sid=$sid.Value;session_id=[uint32]$Session.session_id;active=$true}
}

function New-BrowserTrustStoreCheckpoint {
    param([AllowEmptyCollection()][object[]]$Certificates, $PreviousStore, $BaselineStore)

    $thumbprints = @(ConvertTo-BrowserTrustSnapshot -Thumbprints @($Certificates | ForEach-Object Thumbprint))
    $roots = @(foreach ($certificate in $Certificates) {
        if ($certificate.Subject -isnot [string] -or $certificate.Subject.Length -gt 1024) {
            throw 'Malformed trust root subject.'
        }
        [ordered]@{thumbprint=$certificate.Thumbprint.ToUpperInvariant();subject=$certificate.Subject}
    })
    $storeCheckpoint = [ordered]@{
        thumbprints=$thumbprints
        roots=@($roots | Sort-Object { $_.thumbprint })
        owned_roots=@($roots | Where-Object { $_.subject -cmatch '^CN=OpenEMS local block page [0-9a-f]{16}$' } |
            ForEach-Object thumbprint | Sort-Object)
        added=@();removed=@();added_from_baseline=@();removed_from_baseline=@()
    }
    if ($null -ne $PreviousStore) {
        $storeCheckpoint.added = @($thumbprints | Where-Object { $_ -cnotin $PreviousStore.thumbprints })
        $storeCheckpoint.removed = @($PreviousStore.thumbprints | Where-Object { $_ -cnotin $thumbprints })
    }
    if ($null -ne $BaselineStore) {
        $storeCheckpoint.added_from_baseline = @($thumbprints | Where-Object { $_ -cnotin $BaselineStore.thumbprints })
        $storeCheckpoint.removed_from_baseline = @($BaselineStore.thumbprints | Where-Object { $_ -cnotin $thumbprints })
    }
    return $storeCheckpoint
}

function Add-BrowserTrustCheckpoint {
    param(
        [Parameter(Mandatory=$true)][AllowEmptyCollection()][Collections.Specialized.OrderedDictionary]$Timeline,
        [Parameter(Mandatory=$true)][string]$Phase,
        [Parameter(Mandatory=$true)][scriptblock]$ReadSession,
        [Parameter(Mandatory=$true)][scriptblock]$ReadRoots,
        [Parameter(Mandatory=$true)][scriptblock]$WriteEvidence
    )

    $checkpointPhases = @('baseline', 'ready', 'after_chrome', 'after_firefox', 'before_removal', 'after_removal')
    $phaseIndex = [Array]::IndexOf($checkpointPhases, $Phase)
    if ($phaseIndex -lt 0) { throw 'Unknown trust checkpoint phase.' }

    $previousCheckpoint = $null
    $lastIndex = -1
    foreach ($recordedPhase in $Timeline.Keys) {
        $index = [Array]::IndexOf($checkpointPhases, $recordedPhase)
        if ($index -le $lastIndex -or $index -ge $phaseIndex) { throw 'Trust checkpoints are out of order.' }
        $lastIndex = $index
        if ($Timeline[$recordedPhase].passed -eq $true) { $previousCheckpoint = $Timeline[$recordedPhase] }
    }
    $missing = @($checkpointPhases | Select-Object -First $phaseIndex | Where-Object {
        -not $Timeline.Contains($_) -or $Timeline[$_].passed -ne $true
    })
    $baselineCheckpoint = $null
    if ($Timeline.Contains('baseline') -and $Timeline['baseline'].passed -eq $true) {
        $baselineCheckpoint = $Timeline['baseline']
    }

    $checkpoint = [ordered]@{
        phase=$Phase;at_utc=[DateTime]::UtcNow.ToString('o');session=$null;stores=[ordered]@{}
        missing_phases=$missing;owned_root_present=$null;passed=$false;error_category='SessionUnavailable'
    }
    try {
        $identityBefore = ConvertTo-BrowserTrustSession (& $ReadSession)
        $checkpoint.session = $identityBefore
        if ($null -ne $previousCheckpoint -and ($identityBefore.sid -cne $previousCheckpoint.session.sid -or
                $identityBefore.session_id -ne $previousCheckpoint.session.session_id)) {
            $checkpoint.error_category = 'SessionChanged'
            throw 'Interactive session differs from the previous trust checkpoint.'
        }

        $checkpoint.error_category = 'SnapshotUnavailable'
        $storeCheckpoints = [ordered]@{}
        $rootPresent = $false
        $baselineDiffers = $false
        foreach ($rootStoreName in @('LocalMachine', 'CurrentUser')) {
            $previousStore = $null
            $baselineStore = $null
            if ($null -ne $previousCheckpoint) { $previousStore = $previousCheckpoint.stores.$rootStoreName }
            if ($null -ne $baselineCheckpoint) { $baselineStore = $baselineCheckpoint.stores.$rootStoreName }
            $storeCheckpoint = New-BrowserTrustStoreCheckpoint -Certificates @(& $ReadRoots $rootStoreName) `
                -PreviousStore $previousStore -BaselineStore $baselineStore
            $storeCheckpoints[$rootStoreName] = $storeCheckpoint
            $rootPresent = $rootPresent -or $storeCheckpoint.owned_roots.Count -ne 0
            $baselineDiffers = $baselineDiffers -or $storeCheckpoint.added_from_baseline.Count -ne 0 -or
                $storeCheckpoint.removed_from_baseline.Count -ne 0
        }

        $checkpoint.error_category = 'SessionUnavailable'
        $identityAfter = ConvertTo-BrowserTrustSession (& $ReadSession)
        if ($identityBefore.sid -cne $identityAfter.sid -or $identityBefore.session_id -ne $identityAfter.session_id) {
            $checkpoint.error_category = 'SessionChanged'
            throw 'Interactive session changed during the trust checkpoint.'
        }
        $checkpoint.stores = $storeCheckpoints
        $checkpoint.owned_root_present = $rootPresent
        $checkpoint.error_category = $null
        $checkpoint.passed = $Phase -cne 'after_removal' -or
            ($missing.Count -eq 0 -and -not $rootPresent -and -not $baselineDiffers)
    }
    finally {
        $Timeline.Add($Phase, $checkpoint)
        try { & $WriteEvidence $checkpoint | Out-Null }
        catch {
            $Timeline.Remove($Phase)
            throw
        }
    }
    return $checkpoint
}
