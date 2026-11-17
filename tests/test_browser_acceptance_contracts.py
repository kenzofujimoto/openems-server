"""Pure browser contracts and mocked trust bookkeeping; no host endpoint operations."""

from __future__ import annotations

import base64
import os
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
TRUST = ROOT / "deploy/browser_acceptance_trust.ps1"


def test_browser_document_and_context_contracts():
    node = shutil.which("node")
    assert node, "Node is required for the browser acceptance contracts"
    result = subprocess.run(
        [node, "--test", str(ROOT / "tests/browser_acceptance_contract.test.mjs")],
        capture_output=True, text=True, encoding="utf-8", timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _trust_case(body):
    assert TRUST.is_file(), "the pure trust bookkeeping helper is required"
    powershell = shutil.which("powershell.exe")
    assert powershell, "Windows PowerShell 5.1 is required for the mocked contracts"
    source = r"""
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$path='__TRUST__'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($path,[ref]$tokens,[ref]$errors)
if ($errors.Count -ne 0) { throw 'Invalid helper syntax' }
if ($null -ne $ast.BeginBlock -or $null -ne $ast.ProcessBlock -or $null -ne $ast.ParamBlock -or $ast.UsingStatements.Count -ne 0) { throw 'Function-only helper required' }
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -isnot [Management.Automation.Language.FunctionDefinitionAst]) { throw 'Function-only helper required' }
}
. $path
function Assert-Equal($Expected,$Actual) {
    if (($Expected | ConvertTo-Json -Compress -Depth 10) -cne ($Actual | ConvertTo-Json -Compress -Depth 10)) {
        throw 'Mock contract mismatch'
    }
}
function Assert-Throws([scriptblock]$Action) {
    $caught=$false
    try { & $Action | Out-Null } catch { $caught=$true }
    if (-not $caught) { throw 'Expected rejection' }
}
$a='A'*40; $b='B'*40
__BODY__
'mocked contract passed'
""".replace("__TRUST__", str(TRUST).replace("'", "''")).replace("__BODY__", body)
    encoded = base64.b64encode(source.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "mocked contract passed" in result.stdout


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell contracts")
@pytest.mark.parametrize("case", [
    r"""
$calls=[Collections.Generic.List[string]]::new()
$baseline=Start-BrowserTrustBaseline -AssertGuest {$calls.Add('guard')} -WarmupTls {$calls.Add('tls')} -VerifyRuntimes {$calls.Add('signature')} -ReadRoots {$calls.Add('roots'); @($b,$a)} -WriteEvidence {param($v) $calls.Add('write'); Assert-Equal @($a,$b) $v.thumbprints}
Assert-Equal @('guard','tls','signature','roots','write') @($calls)
Assert-Equal @($a,$b) @($baseline)
Assert-Throws { Start-BrowserTrustBaseline -AssertGuest {} -WarmupTls {} -VerifyRuntimes {} -ReadRoots {@($a)} -WriteEvidence {throw 'Export failed'} }
""",
    r"""
$calls=[Collections.Generic.List[string]]::new()
Assert-Throws { Start-BrowserTrustBaseline -AssertGuest {throw 'Wrong guest'} -WarmupTls {$calls.Add('tls')} -VerifyRuntimes {$calls.Add('signature')} -ReadRoots {@($a)} -WriteEvidence {$calls.Add('write')} }
Assert-Equal 0 $calls.Count
Assert-Throws { Start-BrowserTrustBaseline -AssertGuest {} -WarmupTls {throw 'TLS failed'} -VerifyRuntimes {$calls.Add('signature')} -ReadRoots {@($a)} -WriteEvidence {$calls.Add('write')} }
Assert-Equal 0 $calls.Count
Assert-Throws { Start-BrowserTrustBaseline -AssertGuest {} -WarmupTls {} -VerifyRuntimes {throw 'Invalid signature'} -ReadRoots {$calls.Add('roots'); @($a)} -WriteEvidence {$calls.Add('write')} }
Assert-Equal 0 $calls.Count
""",
    r"""
foreach ($bad in @(@($a,$a),@('bad'),@(('A'*41)),@(1..513 | ForEach-Object {$a}))) {
    Assert-Throws { ConvertTo-BrowserTrustSnapshot -Thumbprints $bad }
}
Assert-Equal @($a,$b) @(ConvertTo-BrowserTrustSnapshot -Thumbprints @($b.ToLowerInvariant(),$a))
Assert-Equal @() @(ConvertTo-BrowserTrustSnapshot -Thumbprints @())
""",
    r"""
$evidence=[Collections.Generic.List[object]]::new()
Complete-BrowserTrustBaseline -AssertGuest {} -Baseline @($a,$b) -ReadRoots {@($b,$a)} -OwnedRootPresent {$false} -WriteEvidence {param($v) $evidence.Add($v)}
Assert-Equal 1 $evidence.Count
Assert-Equal @() @($evidence[0].added)
Assert-Equal @() @($evidence[0].removed)
Assert-Equal $true $evidence[0].passed
""",
    r"""
$evidence=[Collections.Generic.List[object]]::new()
Assert-Throws { Complete-BrowserTrustBaseline -AssertGuest {} -Baseline @($a) -ReadRoots {@($b)} -OwnedRootPresent {$false} -WriteEvidence {param($v) $evidence.Add($v)} }
Assert-Equal 1 $evidence.Count
Assert-Equal @($b) @($evidence[0].added)
Assert-Equal @($a) @($evidence[0].removed)
Assert-Equal $false $evidence[0].passed
""",
    r"""
$evidence=[Collections.Generic.List[object]]::new()
Assert-Throws { Complete-BrowserTrustBaseline -AssertGuest {} -Baseline @($a) -ReadRoots {@($a)} -OwnedRootPresent {$true} -WriteEvidence {param($v) $evidence.Add($v)} }
Assert-Equal $true $evidence[0].owned_root_present
Assert-Equal $false $evidence[0].passed
Assert-Throws { Complete-BrowserTrustBaseline -AssertGuest {} -Baseline @($a) -ReadRoots {@($a)} -OwnedRootPresent {$false} -WriteEvidence {throw 'Export failed'} }
""",
    r"""
$evidence=[Collections.Generic.List[object]]::new()
Assert-Throws { Complete-BrowserTrustBaseline -AssertGuest {} -Baseline @($a) -ReadRoots {throw 'Store unavailable'} -OwnedRootPresent {$false} -WriteEvidence {param($v) $evidence.Add($v)} }
Assert-Equal 1 $evidence.Count
Assert-Equal $false $evidence[0].passed
Assert-Equal 'SnapshotUnavailable' $evidence[0].error_category
""",
])
def test_browser_trust_bookkeeping_with_inert_boundaries(case):
    _trust_case(case)


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell contracts")
@pytest.mark.parametrize("case", [
    pytest.param(r"""
Register-Checkpoint baseline
$c='C'*40
$stores.LocalMachine += @{Thumbprint=$c; Subject='CN=OpenEMS local block page 0123456789abcdef'}
Register-Checkpoint ready
Assert-Equal @($c) @($timeline.ready.stores.LocalMachine.owned_roots)
Assert-Equal @($c) @($timeline.ready.stores.LocalMachine.added)
$persisted=($timeline | ConvertTo-Json -Depth 10) | ConvertFrom-Json
$timeline=[ordered]@{}
foreach ($record in $persisted.PSObject.Properties) { $timeline[$record.Name]=$record.Value }
$stores.LocalMachine=@(@{Thumbprint=$a.ToLowerInvariant(); Subject='CN=Machine'})
Register-Checkpoint after_chrome
Register-Checkpoint after_firefox
Register-Checkpoint before_removal
Register-Checkpoint after_removal
Assert-Equal @(0,0,0,0) @(
    $timeline.after_removal.stores.LocalMachine.added_from_baseline.Count
    $timeline.after_removal.stores.LocalMachine.removed_from_baseline.Count
    $timeline.after_removal.stores.CurrentUser.added_from_baseline.Count
    $timeline.after_removal.stores.CurrentUser.removed_from_baseline.Count
)
Assert-Equal @($c) @($timeline.after_chrome.stores.LocalMachine.removed)
Assert-Equal @('baseline','ready','after_chrome','after_firefox','before_removal','after_removal') @($evidence | ForEach-Object phase)
Assert-Equal $true $evidence[5].passed
""", id="exact-match-after-persisted-checkpoints"),
    pytest.param(r"""
Register-ThroughBeforeRemoval
$stores.LocalMachine=@()
$stores.CurrentUser+=@{Thumbprint=('C'*40); Subject='CN=Foreign'}
Register-Checkpoint after_removal
Assert-Equal @($a) @($evidence[5].stores.LocalMachine.removed_from_baseline)
Assert-Equal @(('C'*40)) @($evidence[5].stores.CurrentUser.added_from_baseline)
Assert-Equal $false $evidence[5].passed
""", id="strict-independent-store-diff"),
    pytest.param(r"""
$stores.CurrentUser=@(@{Thumbprint=$b; Subject='CN=OpenEMS local block page 0123456789abcdef'})
Register-ThroughBeforeRemoval
Register-Checkpoint after_removal
Assert-Equal @() @($evidence[5].stores.CurrentUser.added_from_baseline)
Assert-Equal $true $evidence[5].owned_root_present
Assert-Equal $false $evidence[5].passed
""", id="owned-root-fails-even-without-drift"),
    pytest.param(r"""
$liveSession.active=$false
Assert-Throws { Register-Checkpoint baseline }
Assert-Equal 0 $storeReads.Count
Assert-Equal 1 $evidence.Count
Assert-Equal 'SessionUnavailable' $evidence[0].error_category
""", id="inactive-session-rejects-before-reads"),
    pytest.param(r"""
Register-Checkpoint baseline
$liveSession.session_id=2
Assert-Throws { Register-Checkpoint ready }
Assert-Equal 2 $storeReads.Count
Assert-Equal 'SessionChanged' $evidence[1].error_category
$liveSession.session_id=1
$readRoots={param($store) $liveSession.sid='S-1-5-21-999-200-300-1001'; $stores[$store]}
Assert-Throws { Register-Checkpoint after_chrome }
Assert-Equal 'SessionChanged' $evidence[2].error_category
""", id="session-replacement-between-checkpoints-and-during-read"),
    pytest.param(r"""
Register-Checkpoint baseline
Register-Checkpoint ready
Register-Checkpoint after_chrome
Register-Checkpoint before_removal
Assert-Throws { Register-Checkpoint after_firefox }
Register-Checkpoint after_removal
Assert-Equal $false $timeline.after_removal.passed
Assert-Equal @('after_firefox') @($timeline.after_removal.missing_phases)
Assert-Equal 5 $evidence.Count
""", id="preserve-cleanup-evidence-after-browser-step-omitted"),
    pytest.param(r"""
Register-Checkpoint baseline
$readRoots={param($store) if ($store -eq 'CurrentUser') { throw 'Unavailable' }; $stores[$store]}
Assert-Throws { Register-Checkpoint ready }
$readRoots={param($store) $stores[$store]}
Register-Checkpoint after_chrome
Register-Checkpoint after_firefox
Register-Checkpoint before_removal
Register-Checkpoint after_removal
Assert-Equal 'SnapshotUnavailable' $timeline.ready.error_category
Assert-Equal @('ready') @($timeline.after_removal.missing_phases)
Assert-Equal $false $timeline.after_removal.passed
""", id="failed-store-read-invalidates-complete-timeline"),
])
def test_browser_trust_timeline_with_inert_boundaries(case):
    _trust_case(r"""
$timeline=[ordered]@{}
$evidence=[Collections.Generic.List[object]]::new()
$storeReads=[Collections.Generic.List[string]]::new()
$liveSession=[ordered]@{sid='S-1-5-21-100-200-300-1001'; session_id=1; active=$true}
$stores=@{
    LocalMachine=@(@{Thumbprint=$a; Subject='CN=Machine'})
    CurrentUser=@(@{Thumbprint=$b; Subject='CN=User'})
}
$readRoots={param($store) $storeReads.Add($store); $stores[$store]}
function Register-Checkpoint([string]$requestedPhase) {
    Add-BrowserTrustCheckpoint -Timeline $timeline -Phase $requestedPhase -ReadSession {$liveSession} `
        -ReadRoots $readRoots -WriteEvidence {param($record) $evidence.Add($record)} | Out-Null
}
function Register-ThroughBeforeRemoval {
    foreach ($requestedPhase in @('baseline','ready','after_chrome','after_firefox','before_removal')) {
        Register-Checkpoint $requestedPhase
    }
}
""" + case)
