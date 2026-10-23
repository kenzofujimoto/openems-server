"""Safe entry-point contracts for DNS filter acceptance in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-dns-sandbox.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args], capture_output=True, text=True, timeout=30)


def test_dns_plan_uses_valid_signed_policies_and_declares_scenarios():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['package'] == 'openems-agent.msi'
    assert plan['report'] == 'dns-result.json'
    assert plan['origin'] == 'http://127.0.0.1:18013'
    first, second = plan['policies']
    for policy in (first, second):
        assert policy['digest'] == policy_digest(validate_policy(policy['body']))
    assert first['body']['web_filter'] == {'blocked': ['*.example.com'], 'allowed': ['www.example.com']}
    assert second['version'] > first['version']
    assert len(plan['scenarios']) >= 6
    assert plan['timeout_seconds'] >= 900


def test_dns_harness_refuses_host_before_any_writes(tmp_path):
    result = run('-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_dns_harness_parses():
    command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:HARNESS,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Error;exit 1}'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env={**os.environ, 'HARNESS': str(SCRIPT)}, capture_output=True, text=True, timeout=30)
    assert SCRIPT.exists()
    assert result.returncode == 0, result.stderr


def test_dns_harness_checks_the_system_path_and_exact_rule():
    text = SCRIPT.read_text(encoding='utf-8')
    # System resolution must go through NRPT, so -Server must never be used for the system checks.
    assert 'Resolve-DnsName' in text and '-NoHostsFile' in text
    assert 'Get-DnsClientNrptRule' in text and 'openems-agent managed DNS filter' in text
    assert 'DNSFILTER=1' in text and 'BLOCKPAGEHTTPS=1' in text
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
    assert text.index('requires Windows Sandbox') < text.index("'CreateNew'")
