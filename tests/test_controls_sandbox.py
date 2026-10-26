"""Safe contracts for desktop controls acceptance; never apply policies to this host."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/test-controls-sandbox.ps1"


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell shared-folder publication contract")
@pytest.mark.parametrize("script_name,writer", [
    ("test-controls-sandbox.ps1", "Write-Json"),
    ("test-session-sandbox.ps1", "Write-Report"),
    ("test-locations-sandbox.ps1", "Write-Report"),
    ("invoke-final-acceptance.ps1", "Write-Report"),
])
@pytest.mark.parametrize("shared_folder", [True, False])
def test_report_updates_support_shared_folder_replace_without_changing_local_atomic_writes(
    tmp_path, script_name, writer, shared_folder,
):
    command = r"""
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$tokens=$null;$errors=$null
$tree=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
$writer=$args[1]
$definition=$tree.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $writer},$true)
if ($null -eq $definition) { throw 'Missing report writer' }
# Define only the trusted function AST: never run the Sandbox harness itself on this host.
. ([scriptblock]::Create($definition.Extent.Text))
$global:moves=0;$global:copies=0
$global:shared=$args[3] -eq 'True'
function Move-Item {
    param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    $global:moves++
    if ($global:shared -and (Test-Path -LiteralPath $Destination)) { throw 'VSMB: Cannot create a file when that file already exists.' }
    Microsoft.PowerShell.Management\Move-Item @PSBoundParameters
}
function Copy-Item {
    param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    $global:copies++
    Microsoft.PowerShell.Management\Copy-Item @PSBoundParameters
}
$path=Join-Path $args[2] 'result.json'
if ($global:shared) {
    & $writer $path @{version=1} -SharedFolder
    & $writer $path @{version=2} -SharedFolder
} else {
    & $writer $path @{version=1}
    & $writer $path @{version=2}
}
@{moves=$global:moves;copies=$global:copies;report=(Get-Content -LiteralPath $path -Raw|ConvertFrom-Json)}|ConvertTo-Json -Depth 5 -Compress
"""
    script = ROOT / "deploy" / script_name
    result = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                             f"& {{ {command} }} '{script}' '{writer}' '{tmp_path}' '{shared_folder}'"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["report"] == {"version": 2}
    assert observed["moves"] == (0 if shared_folder else 2)
    assert observed["copies"] == (2 if shared_folder else 0)
    assert {path.name for path in tmp_path.iterdir()} == {"result.json"}


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell harness contract")
@pytest.mark.parametrize("phase", ["session", "locations"])
def test_failed_installation_exports_logs_without_copying_configuration(tmp_path, phase):
    source, destination = tmp_path / "guest", tmp_path / "results"
    source.mkdir()
    (source / "install.log").write_text("Return value 3", encoding="utf-8")
    (source / "agent.json").write_text("private configuration", encoding="utf-8")
    agent_log = tmp_path / "agent.log"
    agent_log.write_text("service diagnostic", encoding="utf-8")
    script = ROOT / f"deploy/test-{phase}-sandbox.ps1"
    command = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$tree=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
$definition=$tree.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Export-Diagnostics'},$true)
if ($null -eq $definition) { throw 'Missing diagnostic export' }
& $definition.Body.GetScriptBlock() $args[1] $args[2] $args[3]
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                             f"& {{ {command} }} '{script}' '{source}' '{destination}' '{agent_log}'"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    exported = list(destination.glob("**/*.log"))
    assert {item.name for item in exported} == {"install.log", "agent.log"}
    assert not list(destination.glob("**/*.json"))
    text = script.read_text(encoding="utf-8")
    assert "finally {\n        try { Export-Diagnostics" in text


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell harness contract")
@pytest.mark.parametrize("kind,unavailable,calls,available", [
    ("USB", True, 0, False), ("Applications", True, 1, False),
    ("Applications", False, 1, True),
])
def test_execution_baseline_is_optional_without_fabricating_wdac_acceptance(kind, unavailable, calls, available):
    command = r"""
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$tree=[System.Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
$definition=$tree.Find({param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-ExecutionBaseline'},$true)
if ($null -eq $definition) { throw 'Missing execution-capability baseline' }
$global:ciCalls=0
$global:ciUnavailable=$args[2] -eq 'True'
function global:Code-Policies {
    $global:ciCalls++
    if ($global:ciUnavailable) { throw 'Could not list Code Integrity policies.' }
    return @('foreign-policy')
}
$argsForTest=@($args[1],$args[2])
$baseline=& $definition.Body.GetScriptBlock() $argsForTest[0]
@{baseline=$baseline;calls=$global:ciCalls}|ConvertTo-Json -Depth 5 -Compress
"""
    result = subprocess.run(["powershell.exe", "-NoProfile", "-Command",
                             f"& {{ {command} }} '{SCRIPT}' '{kind}' '{unavailable}'"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout)
    assert observed["calls"] == calls, observed
    assert observed["baseline"]["available"] is available
    assert observed["baseline"]["policies"] == (["foreign-policy"] if available else [])
    if kind == "Applications" and unavailable:
        assert "Could not list" in observed["baseline"]["reason"]


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["powershell.exe", "-NoProfile", "-File", str(SCRIPT), *arguments],
                          capture_output=True, text=True, timeout=60, check=False)


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell harness contract")
@pytest.mark.parametrize("kind", ["USB", "Applications"])
def test_plan_has_verified_policies_and_never_accepts_unobserved_hardware(kind):
    result = run("-Kind", kind, "-Plan")
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["kind"] == kind and plan["package"] == "openems-agent.msi"
    for assignment in plan["policies"]:
        assert assignment["body"] == validate_policy(assignment["body"])
        assert assignment["digest"] == policy_digest(assignment["body"])
    scenarios = " ".join(plan["scenarios"])
    if kind == "USB":
        assert plan["physical_acceptance_required"] is True
        assert plan["policies"][1]["body"]["usb_control"]["default_action"] == "block"
        assert all("usb" not in assignment["body"] for assignment in plan["policies"])
        for topic in ("HID", "offline", "physical", "read-only", "allow", "block"):
            assert topic in scenarios
    else:
        assert plan["physical_acceptance_required"] is False
        for topic in ("hash", "renamed", "publisher", "network", "control copy", "removal"):
            assert topic in scenarios


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell harness contract")
@pytest.mark.parametrize("kind", ["USB", "Applications"])
def test_host_is_refused_before_writes_even_with_system_or_vm_flags(tmp_path, kind):
    result = run("-Kind", kind, "-SystemPhase", "-DisposableVm", "-OutputDirectory", str(tmp_path))
    assert result.returncode != 0
    assert "requires Windows Sandbox or an explicitly attested disposable VM" in result.stderr
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell harness contract")
def test_controls_harness_and_final_wrapper_parse():
    for script in (SCRIPT, ROOT / "deploy/invoke-final-acceptance.ps1"):
        assert script.is_file()
        command = ("$tokens=$null;$errors=$null;[System.Management.Automation.Language.Parser]::ParseFile("
                   " $args[0],[ref]$tokens,[ref]$errors)|Out-Null;if($errors.Count){$errors|ForEach-Object Message;exit 1}")
        result = subprocess.run(["powershell.exe", "-NoProfile", "-Command", f"& {{ {command} }} '{script}'"],
                                capture_output=True, text=True, timeout=60, check=False)
        assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize("kind", ["usb", "applications"])
def test_builder_copies_the_real_harness_and_keeps_start_manual(tmp_path, kind):
    output, results = tmp_path / f"{kind}-input", tmp_path / "results"
    result = subprocess.run([sys.executable, str(ROOT / "tools/build_controls_sandbox.py"), "--kind", kind,
                             "--output", str(output), "--results", str(results)],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    assert (output / SCRIPT.name).read_bytes() == SCRIPT.read_bytes()
    launcher = (output / f"RUN-{kind.upper()}-TEST.cmd").read_text(encoding="ascii")
    assert f"-Kind {kind.capitalize()}" in launcher
    profile = (tmp_path / f"{kind}.wsb").read_text(encoding="utf-8")
    assert "<ReadOnly>true</ReadOnly>" in profile and "<LogonCommand>" not in profile


def test_final_builder_plan_covers_every_pending_phase_without_launching_sandbox():
    result = subprocess.run([sys.executable, str(ROOT / "tools/build_final_acceptance.py"), "--plan"],
                            capture_output=True, text=True, timeout=60, check=False)
    assert result.returncode == 0, result.stderr
    plan = json.loads(result.stdout)
    assert plan["phases"] == ["session", "locations", "usb", "applications"]
    assert plan["packages"] == ["openems-agent.msi", "openems-agent-next.msi"]
    assert plan["launches_sandbox"] is False
    assert plan["fresh_build"] is True


def test_pending_physical_usb_cannot_be_summarized_as_a_complete_acceptance(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    report = tmp_path / "usb-result.json"
    report.write_text(json.dumps({"passed": False, "automation_passed": True,
                                  "physical_acceptance_pending": True, "status": "manual_required"}), encoding="utf-8")
    summary = summarize_results([report])
    assert summary["passed"] is False
    assert summary["pending"] == ["usb-result.json"]


def test_missing_or_invalid_report_never_counts_as_passed(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    broken = tmp_path / "broken.json"
    broken.write_text("{partial", encoding="utf-8")
    summary = summarize_results([tmp_path / "missing.json", broken])
    assert summary["passed"] is False
    assert set(summary["pending"]) == {"missing.json", "broken.json"}


def test_a_malformed_receipt_is_pending_instead_of_crashing_the_summary(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    report = tmp_path / "applications-result.json"
    report.write_text(json.dumps({"passed": True, "package_receipt": "wrong-type"}), encoding="utf-8")
    summary = summarize_results([report], {"source_revision": "current", "packages": {}})
    assert summary["passed"] is False and summary["pending"] == [report.name]


def test_success_from_another_build_never_accepts_the_current_build(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    report = tmp_path / "session-result.json"
    report.write_text(json.dumps({"passed": True, "package_receipt": {
        "source_revision": "old", "packages": {"openems-agent.msi": {"sha256": "old"}},
    }}), encoding="utf-8")
    summary = summarize_results([report], {"source_revision": "current", "packages": {}})
    assert summary["accepted"] == [] and summary["pending"] == [report.name]


@pytest.mark.parametrize("extra", [{"cleanup_errors": ["rule remained"]}, {"error": "failed"}, {"status": "failed"}])
def test_a_success_flag_cannot_hide_failure_or_incomplete_cleanup(tmp_path, extra):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    report = tmp_path / "applications-result.json"
    report.write_text(json.dumps({"passed": True, **extra}), encoding="utf-8")
    summary = summarize_results([report])
    assert summary["passed"] is False and summary["failed"] == [report.name]


def test_usb_success_requires_an_explicit_completed_physical_acceptance(tmp_path):
    sys.path.insert(0, str(ROOT / "tools"))
    from build_final_acceptance import summarize_results

    report = tmp_path / "usb-result.json"
    report.write_text(json.dumps({"passed": True, "automation_passed": True}), encoding="utf-8")
    summary = summarize_results([report])
    assert summary["passed"] is False and summary["pending"] == [report.name]


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell manifest verification")
def test_wrapper_verifies_bytes_without_executing_the_harness_and_refuses_tampering(tmp_path):
    import hashlib
    import shutil

    wrapper = tmp_path / "invoke-final-acceptance.ps1"
    shutil.copyfile(ROOT / "deploy/invoke-final-acceptance.ps1", wrapper)
    harness = tmp_path / "test-controls-sandbox.ps1"
    harness.write_text("throw 'verification must never execute this harness'", encoding="utf-8")
    package = tmp_path / "openems-agent.msi"
    package.write_bytes(b"test-package-not-an-installer")
    files = {path.name: {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}
             for path in (wrapper, harness, package)}
    (tmp_path / "acceptance-manifest.json").write_text(json.dumps({
        "phase": "usb", "source_revision": "current", "files": files,
        "harness": harness.name, "arguments": ["-Kind", "USB"], "packages": {package.name: files[package.name]},
    }), encoding="utf-8")
    command = ["powershell.exe", "-NoProfile", "-File", str(wrapper), "-Phase", "usb", "-VerifyOnly"]
    verified = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert verified.returncode == 0, verified.stderr
    assert json.loads(verified.stdout)["verified"] is True
    package.write_bytes(b"modified")
    refused = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    assert refused.returncode != 0 and "input changed or is missing" in refused.stderr
