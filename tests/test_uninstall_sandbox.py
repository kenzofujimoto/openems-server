"""Safe entry-point contracts for the uninstall code acceptance (phase 5b) in Windows Sandbox."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-uninstall-sandbox.ps1'
VECTORS = json.loads((ROOT / 'contract/uninstall-vectors.json').read_text(encoding='utf-8'))
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args],
                          capture_output=True, text=True, encoding='utf-8', timeout=60, check=False)


def test_plan_covers_every_acceptance_criterion():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    policy = plan['policy']
    assert policy['body'] == validate_policy(policy['body']) and policy['digest'] == policy_digest(policy['body'])
    assert plan['packages'] == ['openems-agent.msi', 'openems-agent-next.msi']
    assert plan['inputs'] == ['codes.json', 'master.key']
    assert plan['report'] == 'uninstall-result.json'
    text = ' '.join(plan['scenarios'])
    for topic in ('confirms the secret', 'without a code', 'wrong code', 'rollback', 'upgrade', 'server code',
                  'used again', 'release', 'server stopped', 'agent executable', 'cleanup', 'without a secret',
                  'locked'):
        assert topic in text, topic


def test_self_test_reproduces_the_shared_vectors(tmp_path):
    key = tmp_path / 'master.key'
    key.write_text(VECTORS['master_key'] + '\n', encoding='utf-8')
    for case in VECTORS['secrets']:
        result = run('-SelfTest', '-MasterKeyFile', str(key), '-ClientId', case['client_id'])
        assert result.returncode == 0, result.stderr
        values = json.loads(result.stdout)
        assert values == {'secret': case['secret'], 'release': case['release'],
                          'delivery_proof': case['delivery_proof']}, case['client_id']


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


def test_simulated_backend_delivers_once_and_publishes_releases():
    text = SCRIPT.read_text(encoding='utf-8')
    for route in ("'/fct/api/public/v1/uninstall_secret/'", "'/fct/api/public/v1/uninstall_secret/ack/'",
                  "'/fct/api/public/v1/config/assigned/'", "'/fct/api/public/v1/tamper/'"):
        assert route in text, route
    assert '409' in text and '503' in text and '403' in text
    assert 'uninstall_release' in text and 'tamper.log' in text


def test_harness_uses_production_packages_offline_codes_and_one_run_per_sandbox():
    text = SCRIPT.read_text(encoding='utf-8')
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
    # Codes the panel would show come from tools/uninstall_code.py on the host; the offline scenario
    # uses the agent executable inside the Sandbox.
    assert 'codes.json' in text and "'uninstall-code'" in text and '--master-key-file' in text
    # A forced removal is simulated by an administrative extract and install-service, then cleanup.
    assert "'/a'" in text and "'install-service'" in text and "'cleanup'" in text
    assert 'UNINSTALLCODE=' in text
    # The code given to msiexec must not appear in its verbose log.
    assert 'MSI log contains the uninstall code' in text


def test_package_builder_writes_the_key_codes_and_profile(tmp_path):
    output, results = tmp_path / 'uninstall-input', tmp_path / 'results'
    built = subprocess.run([sys.executable, str(ROOT / 'tools/build_uninstall_sandbox.py'), '--output', str(output),
                            '--results', str(results)], capture_output=True, text=True, timeout=120, check=False)
    assert built.returncode == 0, built.stderr
    assert {path.name for path in output.iterdir()} == {'codes.json', 'master.key', 'test-uninstall-sandbox.ps1',
                                                         'RUN-UNINSTALL-TEST.cmd'}
    assert (output / 'master.key').read_text(encoding='utf-8').strip() == VECTORS['master_key']
    codes = json.loads((output / 'codes.json').read_text(encoding='utf-8'))
    from agent.uninstall import code, derive_secret
    secret = derive_secret(VECTORS['master_key'].encode(), 'sandbox-uninstall')
    assert codes == {'client_id': 'sandbox-uninstall', 'codes': {str(n): code(secret, n) for n in range(1, 21)}}
    profile = (tmp_path / 'uninstall.wsb').read_text(encoding='utf-8')
    assert str(output) in profile and str(results) in profile and '<ReadOnly>true</ReadOnly>' in profile
