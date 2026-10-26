"""Contracts for the isolated browser acceptance scenario."""

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy/test-https-browser-sandbox.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Sandbox harness")


def test_browser_plan_uses_valid_policy_and_explicit_release(tmp_path):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-File", str(SCRIPT), "-Plan"],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assignment = plan["blocked_assignment"]
    canonical = json.dumps(assignment["body"], sort_keys=True, separators=(",", ":"))
    assert assignment["digest"] == hashlib.sha256(canonical.encode()).hexdigest()
    assert assignment["body"]["web_filter"]["blocked"] == ["example.com"]
    assert plan["release_assignment"] == {"vdom": "Default", "version": 0, "digest": "", "body": None, "unassigned": True}
    assert plan["origin"] == "http://127.0.0.1:18013"


def test_browser_harness_refuses_host_without_writes(tmp_path):
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-File", str(SCRIPT), "-OutputDirectory", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode != 0
    assert "requires Windows Sandbox" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_browser_harness_powershell_syntax():
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$env:OPENEMS_BROWSER_HARNESS,[ref]$tokens,[ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        env={**os.environ, "OPENEMS_BROWSER_HARNESS": str(SCRIPT)},
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert SCRIPT.is_file()
    assert result.returncode == 0, result.stderr
