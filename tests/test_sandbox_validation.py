"""Safety contracts for the disposable Windows trust acceptance harness."""

import os
from pathlib import Path
import shutil
import subprocess

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "deploy/test-trust-sandbox.ps1"


def test_sandbox_acceptance_harness_exists():
    assert SCRIPT.is_file()


@pytest.mark.skipif(os.name != "nt", reason="PowerShell Windows host guard")
def test_harness_refuses_the_development_host_before_writing(tmp_path):
    assert SCRIPT.is_file()
    shell = shutil.which("powershell.exe")
    assert shell
    result = subprocess.run(
        [shell, "-NoProfile", "-File", str(SCRIPT), "-OutputDirectory", str(tmp_path)],
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode != 0
    assert "requires Windows Sandbox" in result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="PowerShell parser")
def test_harness_has_valid_powershell_syntax():
    assert SCRIPT.is_file()
    command = (
        "$tokens=$null; $errors=$null; "
        "[System.Management.Automation.Language.Parser]::ParseFile("
        "$env:OPENEMS_HARNESS, [ref]$tokens, [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | Out-String | Write-Error; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", command],
        env={**os.environ, "OPENEMS_HARNESS": str(SCRIPT)},
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
