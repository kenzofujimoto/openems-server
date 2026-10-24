"""Safe entry-point contracts for web category acceptance in Windows Sandbox."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-categories-sandbox.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=30, check=False)


def test_plan_uses_a_normalized_signed_category_policy():
    result = run('-Plan')
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    policy = plan['policy']
    assert policy['body'] == validate_policy(policy['body']), 'published bodies are already normalized'
    assert policy['digest'] == policy_digest(policy['body'])
    assert policy['body']['web_filter']['blocked_categories'] == ['games']
    assert plan['fixture_domains'] == ['steampowered.com', 'steamcommunity.com']
    assert plan['report'] == 'categories-result.json'
    assert len(plan['scenarios']) >= 5
    # Slice 4b: the block log reaches the server and the page names the category.
    assert any('block log' in scenario for scenario in plan['scenarios'])
    assert any('Jogos' in scenario for scenario in plan['scenarios'])


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


def test_harness_serves_published_files_and_proves_offline_use():
    text = SCRIPT.read_text(encoding='utf-8')
    # The backend serves the manifest and files built by app/categories.py, by id and digest.
    assert '/fct/api/public/v1/categories/' in text and '/fct/api/public/v1/categories/file/' in text
    assert "'categories'" in text and 'manifest.json' in text
    assert 'Restart-Service' in text and 'Stop-Backend' in text
    assert 'Host DNS already filters' in text
    # The simulated backend records block log uploads; the allowed name must never be reported.
    assert "'/fct/api/public/v1/events/'" in text and 'events.log' in text
    assert "'store.steampowered.com'" in text and 'was reported as blocked' in text
    assert 'Categoria: Jogos' in text
    # A freshly opened Sandbox may still be bringing its network up: retry before blaming the host.
    assert 'Wait-Until { Test-Upstream $name } 60' in text
    assert 'Assert-ProductionPackage ([string](Join-Path' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
