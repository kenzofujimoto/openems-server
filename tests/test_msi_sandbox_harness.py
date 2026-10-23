"""Safe entry-point contracts for real MSI acceptance in Windows Sandbox."""
import json
import os
from pathlib import Path
import subprocess
import pytest

SCRIPT = Path(__file__).resolve().parents[1] / 'deploy/test-msi-sandbox.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')

def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args], capture_output=True, text=True, timeout=30)

def test_msi_plan_declares_all_transaction_scenarios():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['fixtures'] == ['openems-agent-0.2.0.msi', 'openems-agent-0.2.1.msi', 'openems-agent-0.2.2.msi']
    assert plan['origin'] == 'http://127.0.0.1:18013'
    assert plan['report'] == 'msi-result.json'
    assert len(plan['scenarios']) == 5
    assert plan['timeout_seconds'] == 1500
    assert plan['operation_timeout_seconds'] == 240

def test_msi_refuses_host_before_any_writes(tmp_path):
    result = run('-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []

def test_msi_harness_parses():
    command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:HARNESS,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Error;exit 1}'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env={**os.environ, 'HARNESS':str(SCRIPT)}, capture_output=True, text=True, timeout=30)
    assert SCRIPT.exists()
    assert result.returncode == 0, result.stderr

WXS = Path(__file__).resolve().parents[1] / 'agent-rs/installer/openems-agent.wxs'
BUILDER = Path(__file__).resolve().parents[1] / 'tools/build-msi-fixtures.ps1'

def test_fault_injection_exists_only_in_fixture_builds():
    text = WXS.read_text(encoding='utf-8')
    start, end = text.index('<?ifdef FaultInjection ?>'), text.index('<?endif?>')
    guarded, outside = text[start:end], text[:start] + text[end:]
    for name in ('FAIL_SETUP', 'FAIL_REMOVAL', 'InjectSetupFailure', 'InjectRemovalFailure'):
        assert name in guarded
        assert name not in outside, f'{name} must not ship in production MSIs'
    assert 'Execute="deferred"' in guarded and 'Impersonate="no"' in guarded
    assert 'After="StartServices"' in guarded and 'After="RemoveFiles"' in guarded

def test_fixture_builder_matches_harness_fixtures():
    result = subprocess.run(['powershell.exe', '-NoProfile', '-File', str(BUILDER), '-Plan'], capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['fixtures'] == json.loads(run('-Plan').stdout)['fixtures']
    assert plan['defines'] == ['FaultInjection=1']

def test_msi_wait_keeps_process_handle():
    # Start-Process -PassThru loses the handle in Windows PowerShell 5.1: exits go unnoticed.
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'Start-Process -FilePath msiexec' not in text
    assert 'UseShellExecute = $false' in text

def test_msi_backend_stays_interruptible_and_reports_durations():
    # A blocking GetContext() kept Stop-Job waiting until the agent's first request.
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'GetContextAsync()' in text and '.GetContext()' not in text
    assert 'durations' in text

def test_msi_tracks_exact_managed_root_instead_of_counting():
    # Windows may add its own roots during a run; only the agent root is ours.
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'Installation must add one root' not in text
    assert 'function Get-ManagedRoot' in text and 'X509Certificate2' in text
    assert 'unrelated_roots_added' in text

def test_msi_harness_runs_once_per_sandbox():
    # Sandbox can repeat LogonCommand; a second run collides with the first run's ports.
    text = SCRIPT.read_text(encoding='utf-8')
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
    assert text.index('requires Windows Sandbox') < text.index("'CreateNew'")
