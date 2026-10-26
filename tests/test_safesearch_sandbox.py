"""Safe entry-point contracts for SafeSearch and schedule acceptance in Windows Sandbox."""
import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

from agent.policy import (
    DAYS,
    domain_blocked_at,
    policy_digest,
    safe_search_target,
    validate_policy,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'deploy/test-safesearch-sandbox.ps1'
pytestmark = pytest.mark.skipif(os.name != 'nt', reason='Windows harness')


def run(*args):
    return subprocess.run(['powershell.exe', '-NoProfile', '-File', str(SCRIPT), *args],
                          capture_output=True, text=True, timeout=30, check=False)


@pytest.mark.parametrize('now', ['2026-10-26T12:00:00Z', '2026-10-25T23:30:00Z', '2026-10-31T00:10:00Z'])
def test_plan_builds_signed_policies_whose_windows_match_now(now):
    result = run('-Plan', '-PlanNow', now)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    instant = datetime.fromisoformat(now)
    first, second = plan['policies']
    for policy in (first, second):
        # PowerShell builds the canonical JSON itself; Python must agree on the digest.
        assert policy['digest'] == policy_digest(validate_policy(policy['body']))
    web = validate_policy(first['body'])['web_filter']
    assert web['timezone'] == 'UTC'
    assert domain_blocked_at('a.iana.org', web, instant), 'first window must be open now'
    assert not domain_blocked_at('example.net', web, instant), 'second window must be closed now'
    assert DAYS[instant.astimezone(ZoneInfo('UTC')).weekday()] not in web['scheduled'][1]['days']
    assert domain_blocked_at('example.net', validate_policy(second['body'])['web_filter'], instant)
    assert second['version'] > first['version']
    for name, target in [('www.google.com', 'forcesafesearch.google.com'), ('www.youtube.com', 'restrict.youtube.com'),
                         ('www.bing.com', 'strict.bing.com'), ('duckduckgo.com', 'safe.duckduckgo.com')]:
        assert safe_search_target(name, web) == target
    assert plan['report'] == 'safesearch-result.json'


def test_plan_refuses_a_time_too_close_to_midnight():
    result = run('-Plan', '-PlanNow', '2026-10-26T23:58:30Z')
    assert result.returncode != 0
    assert 'midnight' in result.stderr


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


def test_harness_checks_safe_hosts_cache_flush_and_preflight():
    text = SCRIPT.read_text(encoding='utf-8')
    for host in ('forcesafesearch.google.com', 'restrict.youtube.com', 'strict.bing.com', 'safe.duckduckgo.com'):
        assert host in text
    assert 'DNSFILTER=1' in text and 'Assert-ProductionPackage ([string](Join-Path' in text
    assert 'Host DNS already filters' in text and 'Host DNS already enforces SafeSearch' in text
    # The cache-flush check must not clear the cache itself.
    assert 'function Resolve-Cached' in text
    assert "'CreateNew'" in text and 'already started in this Sandbox' in text
