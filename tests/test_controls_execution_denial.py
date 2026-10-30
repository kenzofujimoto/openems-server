"""Test only the refusal classifier; never run the controls harness on the host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")]


@pytest.mark.parametrize("code,started,accepted", [
    (577, False, True), (1260, False, True), (4551, False, True),
    (577, True, False), (1260, True, False), (4551, True, False),
    (0, True, False), (0, False, False),
    *[(code, False, False) for code in (2, 5, 193, 4550, 4552, 4553, 4556, 4557, 4558, 4559, 4580)],
])
def test_execution_refusal_requires_a_known_policy_code_and_no_start(tmp_path, code, started, accepted):
    outcome = tmp_path / "outcome.json"
    outcome.write_text(json.dumps({"native_error": code, "started": started, "exit": 0 if code == 0 else -1}))
    driver = tmp_path / "pure-denial-classifier.ps1"
    driver.write_text(r"""param([string]$Source,[string]$InputPath,[string]$WorkDirectory)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Harness source did not parse.' }
$definition=$tree.Find({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Assert-ExecutionDenied'},$true)
if($null -eq $definition) { throw 'Required classifier missing.' }
# Load this definition only; no top-level harness code or real fixture process.
. ([scriptblock]::Create($definition.Extent.Text))
$script:fixtureOutcome=Get-Content -LiteralPath $InputPath -Raw | ConvertFrom-Json
$script:fixtureCalls=0;$script:sentinelInsideWork=$false
$work=$WorkDirectory
function Invoke-Fixture([string]$Path,[string]$Sentinel) {
    $script:fixtureCalls++
    $script:sentinelInsideWork=([IO.Path]::GetDirectoryName($Sentinel) -ceq $work -and $Sentinel.EndsWith('.started'))
    return $script:fixtureOutcome
}
$accepted=$false
try { Assert-ExecutionDenied (Join-Path $work 'not-a-real-program.exe');$accepted=$true }
catch { if($_.Exception.Message -notlike 'Expected a Windows policy refusal before execution*') { throw } }
[ordered]@{accepted=$accepted;calls=$script:fixtureCalls;sentinel_inside_work=$script:sentinelInsideWork;engine=$PSVersionTable.PSVersion.Major} | ConvertTo-Json -Compress
""", encoding="utf-8-sig")
    result = subprocess.run([
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(driver),
        "-Source", str(ROOT / "deploy/test-controls-sandbox.ps1"),
        "-InputPath", str(outcome), "-WorkDirectory", str(tmp_path),
    ], capture_output=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout.lstrip("\ufeff"))
    assert observed == {"accepted": accepted, "calls": 1, "sentinel_inside_work": True, "engine": 5}
    assert not list(tmp_path.glob("*.started"))
