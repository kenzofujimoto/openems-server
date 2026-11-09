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
