"""Native diagnostics validate device/app decisions without applying system policies."""

from __future__ import annotations

import json
import os
import subprocess
import time

import pytest


def invoke(native, *arguments, timeout=90):
    return subprocess.run([str(native), *map(str, arguments)], capture_output=True, text=True,
                          encoding="utf-8", timeout=timeout, check=False)


def _mock_timed_native(monkeypatch, duration):
    calls = []

    def run(command, **options):
        calls.append((command, options))
        if duration > options["timeout"]:
            raise subprocess.TimeoutExpired(command, options["timeout"])
        return subprocess.CompletedProcess(command, 0, json.dumps({
            "collected_at": "2026-11-09T00:00:00Z", "applications": [], "usb_devices": [],
        }), "")

    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_inventory_accepts_existing_background_budget_without_running_native(monkeypatch, tmp_path):
    calls = _mock_timed_native(monkeypatch, duration=121)
    test_native_inventory_reports_bounded_read_only_snapshot_without_control_journals(
        "mock-native", tmp_path, lambda *_: None,
    )
    assert calls[0][1]["timeout"] == 2 * 600 + 60


def test_short_native_commands_keep_their_ninety_second_limit(monkeypatch):
    calls = _mock_timed_native(monkeypatch, duration=91)
    with pytest.raises(subprocess.TimeoutExpired) as error:
        invoke("mock-native", "controls-plan")
    assert error.value.timeout == 90
    assert calls[0][1]["timeout"] == 90


def test_inventory_still_fails_after_its_bounded_background_budget(monkeypatch, tmp_path):
    calls = _mock_timed_native(monkeypatch, duration=1261)
    with pytest.raises(subprocess.TimeoutExpired) as error:
        test_native_inventory_reports_bounded_read_only_snapshot_without_control_journals(
            "mock-native", tmp_path, lambda *_: None,
        )
    assert error.value.timeout == 2 * 600 + 60
    assert calls[0][1]["timeout"] == 2 * 600 + 60


def test_native_control_plan_keeps_hid_and_boot_disks_allowed_without_system_changes(native, tmp_path):
    policy = tmp_path / "policy.json"
    inventory = tmp_path / "inventory.json"
    policy.write_text(json.dumps({"usb_control": {"default_action": "block"}, "app_control": {
        "network_blocked": [r"C:\Apps\example.exe"],
    }}), encoding="utf-8")
    inventory.write_text(json.dumps({"usb_devices": [
        {"instance_id": "keyboard", "class": "hid"},
        {"instance_id": "external", "class": "storage"},
        {"instance_id": "boot", "class": "storage", "is_boot": True},
    ], "applications": []}), encoding="utf-8")
    before = set(tmp_path.iterdir())
    result = invoke(native, "controls-plan", "--policy", policy, "--inventory", inventory)
    assert result.returncode == 0, result.stderr
    planned = json.loads(result.stdout)
    assert {item["instance_id"]: item["action"] for item in planned["usb_decisions"]} == {
        "keyboard": "allow", "external": "block", "boot": "allow",
    }
    assert planned["policy"]["usb_control"]["rules"] == []
    assert planned["network_blocked"] == [r"C:\Apps\example.exe"]
    assert set(tmp_path.iterdir()) == before, "planning must not create journals or cache files"


def test_native_control_plan_rejects_unverified_publisher_samples(native, tmp_path):
    policy, inventory = tmp_path / "policy.json", tmp_path / "inventory.json"
    policy.write_text(json.dumps({"app_control": {"execution_rules": [
        {"id": "publisher", "kind": "publisher", "value": "Example Publisher", "sample_path": r"C:\Apps\one.exe"},
    ]}}), encoding="utf-8")
    inventory.write_text(json.dumps({"applications": [{
        "name": "one", "path": r"C:\Apps\one.exe", "publisher": "Example Publisher", "signature_valid": False,
    }]}), encoding="utf-8")
    result = invoke(native, "controls-plan", "--policy", policy, "--inventory", inventory)
    assert result.returncode != 0
    assert "verified local sample" in result.stderr


@pytest.mark.windows_only
@pytest.mark.skipif(os.name != "nt", reason="native Windows inventory")
def test_native_inventory_reports_bounded_read_only_snapshot_without_control_journals(native, tmp_path, record_property):
    # Applications and USB inventory each have an existing 600-second background budget.
    timeout = 2 * 600 + 60
    started = time.monotonic()
    try:
        result = invoke(native, "inventory", "--state-path", tmp_path / "state.json", timeout=timeout)
    finally:
        record_property("native_inventory_elapsed_seconds", round(time.monotonic() - started, 3))
        record_property("native_inventory_timeout_seconds", timeout)
    assert result.returncode == 0, result.stderr
    snapshot = json.loads(result.stdout)
    assert set(snapshot) == {"collected_at", "applications", "usb_devices"}
    assert len(snapshot["applications"]) <= 2000 and len(snapshot["usb_devices"]) <= 512
    assert not (tmp_path / "usb-control.json").exists()
    assert not (tmp_path / "application-control.json").exists()
