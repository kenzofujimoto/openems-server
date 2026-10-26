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
