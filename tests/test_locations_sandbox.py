"""Safe contracts for F6 acceptance; destructive steps execute only in Windows Sandbox."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from agent.policy import policy_digest, validate_policy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/test-locations-sandbox.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Windows Sandbox harness contracts")


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-File", str(SCRIPT), *args],
        capture_output=True, text=True, timeout=60, check=False,
    )


def test_plan_pins_the_inside_and_outside_policies_and_network_acceptance():
    result = run("-Plan")
    assert result.returncode == 0, result.stdout + result.stderr
    plan = json.loads(result.stdout)
    for policy in (plan["outside"], plan["inside"]):
        assert policy["body"] == validate_policy(policy["body"])
        assert policy["digest"] == policy_digest(policy["body"])
    assert plan["outside"]["body"]["web_filter"]["blocked"] == ["example.org"]
    assert plan["inside"]["body"]["web_filter"]["blocked"] == []
    assert plan["package"] == "openems-agent.msi"
    assert plan["report"] == "locations-result.json"
    for topic in ("outside", "CIDR and gateway MAC", "same CIDR", "ACK", "session notice", "offline", "restart", "removal"):
        assert topic in " ".join(plan["scenarios"]), topic


def test_harness_refuses_host_before_creating_any_files(tmp_path):
    result = run("-OutputDirectory", str(tmp_path))
    assert result.returncode != 0
    assert "requires Windows Sandbox" in result.stderr
    assert list(tmp_path.iterdir()) == []


def test_harness_parses_in_windows_powershell():
    assert SCRIPT.is_file()
    command = (
        "$errors = $null; [System.Management.Automation.PSParser]::Tokenize("
        "(Get-Content -Raw -LiteralPath $args[0]), [ref]$errors) | Out-Null; "
        "if ($errors.Count) { $errors | ForEach-Object Message; exit 1 }"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", f"& {{ {command} }} '{SCRIPT}'"],
        capture_output=True, text=True, timeout=60, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_harness_observes_real_signals_system_dns_and_the_applied_profile():
    text = SCRIPT.read_text(encoding="utf-8")
    for expected in ("Get-NetRoute", "Get-NetIPAddress", "Get-NetNeighbor", "InterfaceIndex", "PrefixLength",
                     "Resolve-DnsName", "-NoHostsFile", "Clear-DnsClientCache", "Restart-Service",
                     "Assert-ProductionPackage", "'config/ack'", "ack.log", "session.json",
                     "gateway_macs", "sandbox-office", "Stop-Backend", "$baselineHosts", "$baselineRules"):
        assert expected in text, expected
    assert "Get-Content -LiteralPath $board" in text
    assert "Set-Net" not in text and "New-Net" not in text, "simulate locations without changing the host network"


def test_package_builder_copies_harness_and_writes_a_manual_read_only_profile(tmp_path):
    output, results = tmp_path / "locations-input", tmp_path / "results"
    result = subprocess.run(
        [sys.executable, str(ROOT / "tools/build_locations_sandbox.py"), "--output", str(output),
         "--results", str(results)], capture_output=True, text=True, timeout=120, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert {path.name for path in output.iterdir()} == {"test-locations-sandbox.ps1", "RUN-LOCATIONS-TEST.cmd"}
    assert (output / SCRIPT.name).read_bytes() == SCRIPT.read_bytes()
    launcher = (output / "RUN-LOCATIONS-TEST.cmd").read_text(encoding="ascii")
    assert "C:\\openems-input\\test-locations-sandbox.ps1" in launcher
    profile = (tmp_path / "locations.wsb").read_text(encoding="utf-8")
    assert str(output) in profile and str(results) in profile
    assert "<ReadOnly>true</ReadOnly>" in profile
    assert "<Networking>Enable</Networking>" in profile
    assert "<LogonCommand>" not in profile
