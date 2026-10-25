"""Safe entry-point contracts for the session component and reboot acceptance (phase 5c) in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-session-sandbox.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=60, check=False)


def test_plan_covers_both_phases():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    policy = plan['policy']
    assert policy['body'] == validate_policy(policy['body']) and policy['digest'] == policy_digest(policy['body'])
    assert policy['body']['app_control']['blocked'] == ['openems-test-app.exe']
    assert plan['packages'] == ['openems-agent.msi', 'openems-agent-next.msi']
    assert plan['reports'] == ['session-phase1.json', 'session-result.json']
    first, second = ' '.join(plan['phase1']), ' '.join(plan['phase2'])
    for topic in ('user session', 'killed component', 'closed application', 'upgrade', 'disabled in the registry'):
        assert topic in first, topic
    for topic in ('after reboot', 'watchdog', 'component', 'removal'):
        assert topic in second, topic


def test_harness_refuses_host_before_any_writes(tmp_path):
    result = run('-OutputDirectory', str(tmp_path))
    assert result.returncode != 0
    assert 'requires Windows Sandbox' in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_harness_parses():
    command = ('$errors = $null; [System.Management.Automation.PSParser]::Tokenize((Get-Content -Raw -LiteralPath $args[0]), '
               '[ref]$errors) | Out-Null; if ($errors.Count) { $errors | ForEach-Object Message; exit 1 }')
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', f"& {{ {command} }} '{SCRIPT}'"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr


def test_harness_checks_the_component_in_the_interactive_session_and_the_registry_attack():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'openems-session.exe' in text and 'explorer.exe' in text and 'SessionId' in text
    assert "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\openems-agent'" in text and '-Name Start' in text
    assert '3010' in text, 'an upgrade asking for a reboot fails the check'
    assert 'service_started_by_watchdog' in text and 'tamper.log' in text
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert 'PING.EXE' in text and 'openems-test-app.exe' in text
    assert 'Restart the Sandbox' in text
