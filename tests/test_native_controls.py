"""Native diagnostics validate device/app decisions without applying system policies."""

from __future__ import annotations

import json
import os
import subprocess

import pytest


def invoke(native, *arguments):
    return subprocess.run([str(native), *map(str, arguments)], capture_output=True, text=True,
                          encoding="utf-8", timeout=90, check=False)


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
def test_native_inventory_reports_bounded_read_only_snapshot_without_control_journals(native, tmp_path):
    result = invoke(native, "inventory", "--state-path", tmp_path / "state.json")
    assert result.returncode == 0, result.stderr
    snapshot = json.loads(result.stdout)
    assert set(snapshot) == {"collected_at", "applications", "usb_devices"}
    assert len(snapshot["applications"]) <= 2000 and len(snapshot["usb_devices"]) <= 512
    assert not (tmp_path / "usb-control.json").exists()
    assert not (tmp_path / "application-control.json").exists()
