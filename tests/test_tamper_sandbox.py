"""Safe entry-point contracts for tamper protection acceptance (phase 5a) in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-tamper-sandbox.ps1'
BUILDER = ROOT / 'tools/build-msi-fixtures.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(script, *args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(script), *args],
                          capture_output=True, text=True, timeout=30, check=False)


def test_plan_covers_every_acceptance_criterion():
    result = run(SCRIPT, '-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    policy = plan['policy']
    assert policy['body'] == validate_policy(policy['body']) and policy['digest'] == policy_digest(policy['body'])
    # Upgrade from the released package, then to a later one, so both directions see the restricted DACL.
    assert plan['packages'] == ['openems-agent-previous.msi', 'openems-agent.msi', 'openems-agent-next.msi']
    assert plan['report'] == 'tamper-result.json'
    text = ' '.join(plan['scenarios'])
    for topic in ('standard user', 'administrator', 'NRPT', 'browser policy', 'recovery', 'scheduled task',
                  'killed', 'disabled', 'upgrade', 'removal'):
        assert topic in text, topic
    assert set(plan['tamper_kinds']) == {'dns_rule_restored', 'browser_policy_restored', 'service_config_restored',
                                         'watchdog_restored', 'unexpected_exit', 'service_started_by_watchdog'}


def test_harness_refuses_host_before_any_writes(tmp_path):
    result = run(SCRIPT, '-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_harness_parses():
    command = '$t=$null;$e=$null;[System.Management.Automation.Language.Parser]::ParseFile($env:HARNESS,[ref]$t,[ref]$e)|Out-Null;if($e.Count){$e|Out-String|Write-Error;exit 1}'
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', command], env={**os.environ, 'HARNESS': str(SCRIPT)},
                            capture_output=True, text=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr


def test_harness_checks_permissions_from_unprivileged_and_administrator_sessions():
    text = SCRIPT.read_text(encoding='utf-8')
    # SYSTEM may do anything: permission checks run in the operator's administrator session and as a
    # standard user created inside the Sandbox, with a random password that is never written down.
    assert 'permissions-ready' in text and 'permissions-result.json' in text
    assert 'New-LocalUser' in text and 'RandomNumberGenerator' in text and 'Remove-LocalUser' in text
    # Group names are localized (Usuários on a Portuguese Windows): use the well-known SID.
    assert "Add-LocalGroupMember -SID 'S-1-5-32-545'" in text and "-Group 'Users'" not in text
    # sc.exe output is localized too: recovery actions are read from the registry, not parsed text.
    assert 'FailureActions' in text and 'qfailure' not in text
    assert '-Credential' in text
    for probe in ("'stop'", "'config'", "'delete'", 'agent.json', 'Program Files\\openems'):
        assert probe in text, probe
    assert 'Get-ServiceAces' in text and 'sdshow' in text


def test_harness_tampers_like_an_attacker_and_waits_for_repair():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'Remove-DnsClientNrptRule' in text
    assert 'DnsOverHttpsMode' in text
    assert 'sc.exe failure openems-agent reset= 0 actions= ""' in text or "'failure', 'openems-agent'" in text
    assert "schtasks.exe" in text and "'/Delete'" in text
    assert 'Stop-Process -Id' in text
    assert "'start=', 'disabled'" in text
    # The scheduled watchdog runs every 5 minutes: allow one full period plus margin.
    assert 'Wait-Until' in text and ' 420 ' in text
    assert "'/fct/api/public/v1/tamper/'" in text and 'tamper.log' in text


def test_harness_uses_production_packages_and_one_run_per_sandbox():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
    assert 'ANTIBYPASS=1' in text and 'DNSFILTER=1' in text


def test_builder_makes_the_next_package_for_the_upgrade_check():
    result = run(BUILDER, '-Plan', '-Production', '-Next')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan['fixtures'] == ['openems-agent-next.msi'] and plan['defines'] == []
    assert plan['versions'] == ['0.4.1']
    production = json.loads(run(BUILDER, '-Plan', '-Production').stdout)
    assert production['fixtures'] == ['openems-agent.msi'] and production['versions'] == ['0.4.0']
