"""Run embedded adapters in PowerShell 5.1 with all Windows mutations mocked."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MOCKS = ROOT / "tests" / "fixtures" / "windows_controls_mocks.ps1"
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
REGISTRY = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
INSTANCE = r"USBSTOR\DISK\fixture"
IDENTITY = "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")]


def fixture_environment(tmp_path, *, scenario="normal", registry=None, boot=False, wmi_serial="SERIAL"):
    configuration = {"scenario": scenario, "registry": registry or {}, "boot": boot, "wmi_serial": wmi_serial}
    (tmp_path / "fixture.json").write_text(json.dumps(configuration), encoding="utf-8")
    system = tmp_path / "systemroot"
    templates = system / "schemas/CodeIntegrity/ExamplePolicies"
    templates.mkdir(parents=True)
    (templates / "AllowAll.xml").write_text("<system-template>unchanged</system-template>", encoding="utf-8")
    (system / "System32").mkdir()
    # The test copy changes the command name to a .ps1; the real CiTool can never be invoked.
    (system / "System32/Mock-CiTool.ps1").write_text(
        r"""param([Parameter(ValueFromRemainingArguments=$true)][string[]]$Arguments)
$file=Join-Path $PSScriptRoot '..\..\active-policy.json'
switch($Arguments[0]) {
    '--list-policies' {
        $policies=@()
        if(Test-Path -LiteralPath $file){$policies=@(Get-Content -LiteralPath $file -Raw | ConvertFrom-Json)}
        @{Policies=$policies}|ConvertTo-Json -Depth 6 -Compress
    }
    '--update-policy' {
        $id=[IO.Path]::GetFileNameWithoutExtension($Arguments[1])
        @{PolicyID=$id;FriendlyName='openems application control';IsEnforced=$true}|ConvertTo-Json|Set-Content -LiteralPath $file
    }
    '--remove-policy' { [IO.File]::Delete($file) }
    default { throw 'Unexpected mock CiTool operation.' }
}
$global:LASTEXITCODE=0
""",
        encoding="utf-8",
    )
    return tmp_path


def invoke_adapter(directory, kind, request, *, simulate_system=True):
    source = (ROOT / "deploy" / f"agent-{kind}.ps1").read_text(encoding="utf-8")
    assert source.count(IDENTITY) == 1, "Review the identity seam if the production guard changes"
    if simulate_system:
        # Substitution is confined to a temporary test copy. Production has no bypass switch.
        source = source.replace(IDENTITY, "'S-1-5-18'")
    source = source.replace("$env:SystemRoot", "$script:fixtureSystemRoot")
    source = source.replace("CiTool.exe", "Mock-CiTool.ps1")
    prefix = "$script:fixtureRoot='" + str(directory).replace("'", "''") + "'\n"
    script = directory / f"{kind}-test-copy.ps1"
    script.write_text(prefix + MOCKS.read_text(encoding="utf-8") + "\n" + source, encoding="utf-8")
    return subprocess.run(
        [str(POWERSHELL), "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script)],
        input=json.dumps(request), capture_output=True, text=True, encoding="utf-8", timeout=90, check=False,
    )


def calls(directory):
    path = directory / "calls.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8-sig").splitlines()] if path.exists() else []


def wdac_request(directory, rule_kind="path"):
    sample = directory / "fixture.exe"
    sample.write_bytes(b"fixture image; never executable")
    values = {"path": str(sample), "hash": hashlib.sha256(sample.read_bytes()).hexdigest(),
              "publisher": "CN=Fixture Publisher", "name": "fixture.exe"}
    return {"mode": "apply", "state_path": str(directory / "application-control.json"), "policy": {
        "execution_rules": [{"id": "fixture", "kind": rule_kind, "value": values[rule_kind], "sample_path": str(sample)}],
        "network_blocked": [],
    }}


def usb_request(directory, mode="apply", action="block"):
    return {"mode": mode, "state_path": str(directory / "usb-control.json"),
            "policy": {"default_action": action, "rules": []}}


def assert_success(result):
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads(result.stdout)


def test_mocked_wdac_success_and_cleanup_preserve_the_json_contract(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    assert_success(invoke_adapter(directory, "applications", request))
    assert (directory / "active-policy.json").exists()
    assert_success(invoke_adapter(directory, "applications", {**request, "mode": "cleanup"}))
    assert not (directory / "active-policy.json").exists()
    assert not Path(request["state_path"]).exists()


def test_wdac_merge_uses_a_private_copy_of_the_system_template(tmp_path):
    directory = fixture_environment(tmp_path, scenario="readonly_template")
    template = directory / "systemroot/schemas/CodeIntegrity/ExamplePolicies/AllowAll.xml"
    original = template.read_bytes()
    result = assert_success(invoke_adapter(directory, "applications", wdac_request(directory)))
    assert "app-control:wdac" in result["capabilities"]
    merge = next(call["detail"] for call in calls(directory) if call["name"] == "Merge-CIPolicy")
    assert all(Path(path) != template for path in merge["inputs"])
    assert all(Path(path).parent == Path(merge["output"]).parent for path in merge["inputs"])
    assert template.read_bytes() == original


@pytest.mark.parametrize("rule_kind", ["path", "hash", "publisher", "name"])
def test_configci_console_output_does_not_corrupt_adapter_json(tmp_path, rule_kind):
    directory = fixture_environment(tmp_path, scenario="console_noise")
    result = assert_success(invoke_adapter(directory, "applications", wdac_request(directory, rule_kind)))
    assert any(event["kind"] == "app_control_applied" for event in result["events"])


def test_configci_failure_restores_console_output_for_the_error_json(tmp_path):
    directory = fixture_environment(tmp_path, scenario="console_failure")
    result = invoke_adapter(directory, "applications", wdac_request(directory))
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "control_failed"}


@pytest.mark.parametrize("kind", ["hash", "publisher", "name"])
def test_wdac_uses_verified_explicit_user_pe_driver_files(tmp_path, kind):
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    request = wdac_request(directory, kind)
    assert_success(invoke_adapter(directory, "applications", request))
    scan = next(call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver")
    assert scan["user_pes"] and scan["no_script"] and scan["no_shadow_copy"]
    assert len(scan["files"]) == 1
    assert Path(scan["files"][0]) != Path(request["policy"]["execution_rules"][0]["sample_path"])
    assert Path(scan["files"][0]).parent == Path(scan["path"])
    assert Path(scan["path"]).parent.parent == directory
    generated = next(call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicyRule")
    assert generated["driver_paths"] == scan["files"]
    assert generated["driver_user_modes"] == [True]
    assert generated["legacy_path"] == ""
    assert generated["deny"] is True
    assert generated["level"] == {"hash": "Hash", "publisher": "Publisher", "name": "FileName"}[kind]
    if kind == "name":
        assert generated["specific_file_name_level"] == "OriginalFileName"


def test_wdac_scans_only_current_copies_once_for_multiple_rules(tmp_path):
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    request = wdac_request(directory, "hash")
    outside = directory / "unrelated.exe"
    outside.write_bytes(b"unrelated image must not enter the scan")
    request["policy"]["execution_rules"].append({
        "id": "second", "kind": "hash", "sample_path": str(outside),
        "value": hashlib.sha256(outside.read_bytes()).hexdigest(),
    })
    assert_success(invoke_adapter(directory, "applications", request))
    scans = [call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver"]
    assert len(scans) == 1
    assert len(scans[0]["files"]) == 2
    assert all(Path(path).parent == Path(scans[0]["path"]) for path in scans[0]["files"])
    assert str(outside) not in scans[0]["files"]
    assert {Path(path).read_bytes() for path in scans[0]["files"]} == {
        b"fixture image; never executable", outside.read_bytes(),
    }


@pytest.mark.parametrize("scenario", ["drivers_native_prefix", "drivers_friendly_leaf"])
def test_wdac_driver_aliases_still_resolve_to_the_exact_private_copy(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "hash")))
    scan = next(call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver")
    generated = next(call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicyRule")
    assert [path.removeprefix("\\\\?\\") for path in generated["driver_paths"]] == scan["files"]


@pytest.mark.parametrize("scenario", ["drivers_empty", "drivers_kernel", "drivers_unrelated", "drivers_duplicate", "drivers_conflicting"])
def test_wdac_rejects_missing_kernel_or_ambiguous_user_pe_samples(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "hash"))
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "control_failed"}
    assert not (directory / "active-policy.json").exists()
    assert not any(call["name"] in {"New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))


@pytest.mark.parametrize("scenario", ["rules_empty", "rules_kernel"])
def test_wdac_rejects_empty_or_kernel_only_generated_rules(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "hash"))
    assert result.returncode == 1
    assert not (directory / "active-policy.json").exists()
    assert not any(call["name"] == "Merge-CIPolicy" for call in calls(directory))


def test_wdac_collection_output_keeps_real_user_rules_without_mutating_kernel_rules(tmp_path):
    directory = fixture_environment(tmp_path, scenario="rules_mixed")
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "hash")))
    merge = next(call["detail"] for call in calls(directory) if call["name"] == "Merge-CIPolicy")
    assert merge["rule_ids"] == ["fixture-rule"]
    assert merge["user_modes"] == [True]


def test_wdac_path_rule_does_not_require_a_user_pe_scan(tmp_path):
    directory = fixture_environment(tmp_path)
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "path")))
    assert not any(call["name"] == "Get-SystemDriver" for call in calls(directory))


def test_wdac_mismatched_hash_is_rejected_before_user_pe_enumeration(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    request["policy"]["execution_rules"][0]["value"] = "00" * 32
    result = invoke_adapter(directory, "applications", request)
    assert result.returncode == 1
    assert not any(call["name"] in {"Get-SystemDriver", "New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))


def test_removable_usb_block_uses_pnp_without_setting_disk_offline(tmp_path):
    directory = fixture_environment(tmp_path, registry={REGISTRY: {"DenyInstanceIDs": 0, "DenyInstanceIDsRetroactive": 0}})
    result = assert_success(invoke_adapter(directory, "usb", usb_request(directory)))
    assert any(event["kind"] == "usb_block" for event in result["events"])
    assert any(call["name"] == "Disable-PnpDevice" for call in calls(directory))
    assert not any(call["name"] == "Set-Disk" for call in calls(directory))
    state = json.loads((directory / "usb-control.json").read_text(encoding="utf-8"))
    assert state["devices"][0]["disabled_by_us"] is True
    assert state["devices"][0]["applied_offline"] is False


def test_usb_apply_handles_an_existing_restrictions_key_without_values(tmp_path):
    directory = fixture_environment(tmp_path, registry={REGISTRY: {}})
    result = assert_success(invoke_adapter(directory, "usb", usb_request(directory)))
    assert any(event["kind"] == "usb_block" for event in result["events"])


@pytest.mark.parametrize("mode", ["cleanup", "apply"])
def test_usb_removes_owned_journal_when_registry_values_are_already_absent(tmp_path, mode):
    directory = fixture_environment(tmp_path, registry={REGISTRY: {}, REGISTRY + r"\DenyInstanceIDs": {}})
    state = {"format": 1, "devices": [], "entries": [{"name": "1", "value": INSTANCE}],
             "flags": [{"name": name, "existed": False, "value": None}
                       for name in ("DenyInstanceIDs", "DenyInstanceIDsRetroactive")]}
    (directory / "usb-control.json").write_text(json.dumps(state), encoding="utf-8")
    assert_success(invoke_adapter(directory, "usb", usb_request(directory, mode, "allow")))
    assert not (directory / "usb-control.json").exists()


def test_usb_release_preserves_external_restrictions_and_restores_owned_device(tmp_path):
    external = REGISTRY + r"\DenyInstanceIDs"
    directory = fixture_environment(tmp_path, registry={
        REGISTRY: {"DenyInstanceIDs": 1, "DenyInstanceIDsRetroactive": 0}, external: {"1": "EXTERNAL-DEVICE"},
    })
    assert_success(invoke_adapter(directory, "usb", usb_request(directory)))
    assert_success(invoke_adapter(directory, "usb", usb_request(directory, "cleanup")))
    state = json.loads((directory / "mock-state.json").read_text(encoding="utf-8-sig"))
    assert state["disabled"] is False
    assert state["registry"][external] == {"1": "EXTERNAL-DEVICE"}
    assert state["registry"][REGISTRY] == {"DenyInstanceIDs": 1, "DenyInstanceIDsRetroactive": 0}
    assert not (directory / "usb-control.json").exists()


@pytest.mark.parametrize("kind", ["usb", "applications"])
def test_production_system_guard_still_rejects_unprivileged_apply(tmp_path, kind):
    directory = fixture_environment(tmp_path)
    request = usb_request(directory) if kind == "usb" else wdac_request(directory)
    result = invoke_adapter(directory, kind, request, simulate_system=False)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"error": "control_failed"}
    assert not Path(request["state_path"]).exists()
    assert calls(directory) == []


def test_usb_boot_storage_never_reaches_a_mutating_mock(tmp_path):
    directory = fixture_environment(tmp_path, boot=True)
    assert_success(invoke_adapter(directory, "usb", usb_request(directory)))
    assert not any(call["name"] in {"Set-Disk", "Disable-PnpDevice", "New-ItemProperty"}
                   for call in calls(directory))


def test_usb_read_only_and_cleanup_restore_the_original_writable_state(tmp_path):
    directory = fixture_environment(tmp_path)
    request = usb_request(directory, action="allow")
    request["policy"]["rules"] = [{"id": "read-only", "action": "read_only", "instance_id": INSTANCE}]
    result = assert_success(invoke_adapter(directory, "usb", request))
    assert any(event["kind"] == "usb_read_only" for event in result["events"])
    assert_success(invoke_adapter(directory, "usb", usb_request(directory, "cleanup")))
    state = json.loads((directory / "mock-state.json").read_text(encoding="utf-8-sig"))
    assert state["read_only"] is False
    assert state["disabled"] is False
    assert not (directory / "usb-control.json").exists()


def test_usb_cleanup_still_restores_an_offline_disk_from_an_old_journal(tmp_path):
    directory = fixture_environment(tmp_path, scenario="legacy_offline")
    mock = {"disabled": True, "read_only": False, "offline": True, "registry": {}}
    (directory / "mock-state.json").write_text(json.dumps(mock), encoding="utf-8")
    journal = {"format": 1, "entries": [], "flags": [], "devices": [{
        "instance_id": INSTANCE, "unique_id": "fixture-usb-id", "disabled_by_us": True,
        "original_read_only": False, "applied_read_only": False,
        "original_offline": False, "applied_offline": True,
    }]}
    (directory / "usb-control.json").write_text(json.dumps(journal), encoding="utf-8")
    assert_success(invoke_adapter(directory, "usb", usb_request(directory, "cleanup")))
    restored = json.loads((directory / "mock-state.json").read_text(encoding="utf-8-sig"))
    assert restored["disabled"] is False
    assert restored["offline"] is False
    assert not (directory / "usb-control.json").exists()


@pytest.mark.parametrize(("wmi_serial", "expected"), [
    pytest.param("\x031", "fixture", id="wmi-control-prefix"),
    pytest.param("SER\x7fIAL", "fixture", id="wmi-control-middle"),
    pytest.param("\x80SERIAL", "fixture", id="wmi-c1-control"),
    pytest.param("\nSERIAL", "fixture", id="wmi-newline-must-not-be-stripped"),
    pytest.param("X" * 513, "fixture", id="wmi-oversized"),
    pytest.param("   ", "fixture", id="wmi-whitespace-only"),
    pytest.param(None, "fixture", id="wmi-null"),
    pytest.param("", "fixture", id="wmi-empty"),
    pytest.param("VALID-SERIAL", "VALID-SERIAL", id="valid-wmi-preserved"),
    pytest.param("  VALID-SERIAL  ", "VALID-SERIAL", id="valid-wmi-padding-trimmed"),
])
def test_usb_inventory_serial_remains_usable_as_a_policy_selector(tmp_path, wmi_serial, expected):
    directory = fixture_environment(tmp_path, wmi_serial=wmi_serial)
    result = assert_success(invoke_adapter(directory, "usb", {"mode": "inventory"}))
    assert result["inventory"][0]["serial"] == expected
    assert calls(directory) == [], "serial selection must not mutate Windows state"
