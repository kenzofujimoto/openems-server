"""Safe entry-point contracts for service resilience acceptance in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-resilience-sandbox.ps1'
BUILDER = ROOT / 'tools/build-msi-fixtures.ps1'
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != 'nt', reason='Windows harness')]

def run(script, *args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), *args], capture_output=True, text=True, timeout=30, check=False)

def test_resilience_plan_declares_both_phases():
    result = run(SCRIPT, '-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['package'] == 'openems-agent.msi'
    assert plan['origin'] == 'http://127.0.0.1:18013'
    assert plan['state_directory'] == 'C:\\openems-resilience'
    assert plan['reports'] == ['resilience-phase1.json', 'resilience-result.json']
    assert len(plan['phase1']) == 3 and len(plan['phase2']) == 2
    assert plan['timeout_seconds'] >= 900

def test_resilience_refuses_host_before_any_writes(tmp_path):
    result = run(SCRIPT, '-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []

def test_resilience_harness_parses():
    command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:HARNESS,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Error;exit 1}'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env={**os.environ, 'HARNESS': str(SCRIPT)}, capture_output=True, text=True, timeout=30, check=False)
    assert SCRIPT.exists()
    assert result.returncode == 0, result.stderr

def test_resilience_uses_production_package_without_fault_injection():
    text = SCRIPT.read_text(encoding='utf-8')
    # The harness must prove the installed package cannot inject failures.
    assert 'InjectSetupFailure' in text and 'CustomAction' in text
    assert 'FAIL_SETUP' not in text and 'FAIL_REMOVAL' not in text
    result = run(BUILDER, '-Plan', '-Production')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['fixtures'] == ['openems-agent.msi'] and plan['defines'] == []

def test_resilience_runs_once_per_boot_and_detects_reboot():
    text = SCRIPT.read_text(encoding='utf-8')
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
    assert text.index('requires Windows Sandbox') < text.index("'CreateNew'")
    assert 'LastBootUpTime' in text

def test_package_check_passes_plain_strings_to_com():
    # A PSObject-wrapped Join-Path result makes WindowsInstaller.OpenDatabase fail with DISP_E_TYPEMISMATCH.
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'function Assert-ProductionPackage([string]$Path)' in text
    assert 'Assert-ProductionPackage ([string](Join-Path $stateDirectory $package))' in text
