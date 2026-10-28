"""Safe entry-point contracts for anti-bypass acceptance in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-antibypass-sandbox.ps1'
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != 'nt', reason='Windows harness')]


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=30, check=False)


def test_plan_uses_a_signed_policy_and_declares_scenarios():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    policy = plan['policy']
    assert policy['digest'] == policy_digest(validate_policy(policy['body']))
    assert plan['report'] == 'antibypass-result.json'
    assert len(plan['scenarios']) >= 7
    assert plan['doh_probe'] in ('1.1.1.1', '8.8.8.8')


def test_harness_refuses_host_before_any_writes(tmp_path):
    result = run('-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_harness_parses():
    command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:HARNESS,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Error;exit 1}'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env={**os.environ, 'HARNESS': str(SCRIPT)},
                            capture_output=True, text=True, timeout=30, check=False)
    assert SCRIPT.exists()
    assert result.returncode == 0, result.stderr


def test_harness_probes_from_a_non_agent_process_and_checks_browser_policies():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'ANTIBYPASS=1' in text and 'DNSFILTER=1' in text
    assert 'function Send-RawDns' in text and 'function Test-Tcp' in text
    for key in (r'SOFTWARE\Policies\Google\Chrome', r'SOFTWARE\Policies\Microsoft\Edge',
                r'SOFTWARE\Policies\Mozilla\Firefox\DNSOverHTTPS', r'SOFTWARE\Policies\Mozilla\Firefox\Certificates'):
        assert key in text
    # Every blocked probe must first be shown to work before installation.
    assert 'reachable before installation' in text
    assert text.index('reachable before installation') < text.index('Invoke-Msi $false')
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
