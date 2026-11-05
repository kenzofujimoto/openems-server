"""Run embedded adapters in PowerShell 5.1 with all Windows mutations mocked."""

from __future__ import annotations

from copy import deepcopy

import hashlib
import json
import os
import subprocess
from pathlib import Path
import xml.etree.ElementTree as ET

import pytest

ROOT = Path(__file__).resolve().parents[1]
MOCKS = ROOT / "tests" / "fixtures" / "windows_controls_mocks.ps1"
DUAL_SCENARIO_XML = ROOT / "tests/fixtures/wdac-dual-scenario-hash.xml"
CI_NAMESPACE = "urn:schemas-microsoft-com:sipolicy"
CI = {"ci": CI_NAMESPACE}
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
REGISTRY = r"HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions"
INSTANCE = r"USBSTOR\DISK\fixture"
IDENTITY = "[Security.Principal.WindowsIdentity]::GetCurrent().User.Value"
APP_DIAGNOSTIC_STAGES = {
    "app_request", "app_journal", "app_inventory", "app_wdac_query", "app_sample_discovery",
    "app_wdac_generate", "app_wdac_apply", "app_wdac_verify", "app_wdac_remove", "app_firewall",
    "app_execution_events",
}
PRIVATE_EXCEPTION = "synthetic-private-diagnostic-marker"
pytestmark = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1")]


def fixture_environment(tmp_path, *, scenario="normal", registry=None, boot=False, wmi_serial="SERIAL", generated_policy=None):
    configuration = {"scenario": scenario, "registry": registry or {}, "boot": boot, "wmi_serial": wmi_serial,
                     "generated_policy": generated_policy is not None}
    if generated_policy is not None:
        (tmp_path / "generated-policy.xml").write_bytes(generated_policy)
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


def invoke_adapter(directory, kind, request, *, simulate_system=True, mock_override=""):
    source = (ROOT / "deploy" / f"agent-{kind}.ps1").read_text(encoding="utf-8")
    assert source.count(IDENTITY) == 1, "Review the identity seam if the production guard changes"
    if simulate_system:
        # Substitution is confined to a temporary test copy. Production has no bypass switch.
        source = source.replace(IDENTITY, "'S-1-5-18'")
    source = source.replace("$env:SystemRoot", "$script:fixtureSystemRoot")
    source = source.replace("CiTool.exe", "Mock-CiTool.ps1")
    prefix = "$script:fixtureRoot='" + str(directory).replace("'", "''") + "'\n"
    script = directory / f"{kind}-test-copy.ps1"
    script.write_text(prefix + MOCKS.read_text(encoding="utf-8") + "\n" + mock_override + "\n" + source, encoding="utf-8")
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


def assert_app_error(result, category):
    assert result.returncode == 1, (result.stdout, result.stderr)
    response = json.loads(result.stdout)
    assert response["error"] == category
    assert response.keys() <= {"error", "diagnostic"}, response
    if "diagnostic" in response:
        diagnostic = response["diagnostic"]
        assert isinstance(diagnostic, dict), diagnostic
        assert diagnostic.keys() == {"stage", "os_code"}, diagnostic
        assert diagnostic["stage"] in APP_DIAGNOSTIC_STAGES, diagnostic
        code = diagnostic["os_code"]
        assert code is None or (type(code) is int and -(2**31) <= code < 2**31), diagnostic
    return response


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
    assert_app_error(result, "control_failed")


APP_FAILURE_MOCKS = {
    "generate": r"""
function New-CIPolicyRule {
    [CmdletBinding()] param([string]$FilePathRule,[switch]$Deny)
    [Console]::Out.WriteLine('__PRIVATE__')
    Trace-Mock 'InjectedAppFailure' 'generate'
    throw __EXCEPTION__
}
""",
    "firewall": r"""
$script:injectedFirewallReads = 0
function Get-NetFirewallRule {
    [CmdletBinding()] param([string]$PolicyStore,[string]$Name)
    $script:injectedFirewallReads++
    if ($script:injectedFirewallReads -eq 1) { return $null }
    Trace-Mock 'InjectedAppFailure' 'firewall'
    throw __EXCEPTION__
}
function Get-NetFirewallApplicationFilter { throw 'Unexpected application filter query.' }
""",
    "journal": r"""
function Move-Item {
    [CmdletBinding()] param([string]$LiteralPath,[string]$Destination,[switch]$Force)
    Assert-FixturePath $LiteralPath
    Assert-FixturePath $Destination
    Trace-Mock 'InjectedAppFailure' 'journal'
    throw __EXCEPTION__
}
""",
    "sample": r"""
$script:injectedSignatureReads = 0
function Get-AuthenticodeSignature {
    [CmdletBinding()] param([string]$LiteralPath)
    Assert-FixturePath $LiteralPath
    $script:injectedSignatureReads++
    if ($script:injectedSignatureReads -eq 1) {
        return [pscustomobject]@{Status='Valid';SignatureType='Authenticode';
            SignerCertificate=[pscustomobject]@{Subject='CN=Fixture Publisher'}}
    }
    Trace-Mock 'InjectedAppFailure' 'sample'
    throw __EXCEPTION__
}
""",
}


@pytest.mark.parametrize("boundary,exception,stage,code", [
    ("generate", "[ComponentModel.Win32Exception]::new(5, '__PRIVATE__')", "app_wdac_generate", 5),
    ("firewall", "[ComponentModel.Win32Exception]::new(5, '__PRIVATE__')", "app_firewall", 5),
    # HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION), represented as a signed .NET Int32.
    ("journal", "[IO.IOException]::new('__PRIVATE__', -2147024864)", "app_journal", 32),
    ("sample", "[InvalidOperationException]::new('__PRIVATE__ Win32 5')", "app_sample_discovery", None),
    # E_FAIL is an HRESULT without a Win32 facility.
    ("generate", "[Runtime.InteropServices.COMException]::new('__PRIVATE__', -2147467259)",
     "app_wdac_generate", None),
])
def test_application_adapter_emits_only_closed_stage_and_observed_system_code(tmp_path, boundary, exception, stage, code):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "publisher" if boundary == "sample" else "path")
    if boundary == "firewall":
        request["policy"]["execution_rules"] = []
        request["policy"]["network_blocked"] = [str(directory / "fixture.exe")]
    override = APP_FAILURE_MOCKS[boundary].replace("__EXCEPTION__", exception).replace("__PRIVATE__", PRIVATE_EXCEPTION)

    result = invoke_adapter(directory, "applications", request, mock_override=override)

    assert {"name": "InjectedAppFailure", "detail": boundary} in calls(directory)
    assert PRIVATE_EXCEPTION not in result.stdout + result.stderr
    assert str(directory) not in result.stdout + result.stderr
    response = assert_app_error(result, "control_failed")
    assert response == {"error": "control_failed", "diagnostic": {"stage": stage, "os_code": code}}
    assert not (directory / "active-policy.json").exists()


def test_application_adapter_preserves_restart_required_with_verify_diagnostic(tmp_path):
    directory = fixture_environment(tmp_path)
    tool = directory / "systemroot/System32/Mock-CiTool.ps1"
    mock = tool.read_text(encoding="utf-8")
    assert mock.count("IsEnforced=$true") == 1
    tool.write_text(mock.replace("IsEnforced=$true", "IsEnforced=$false"), encoding="utf-8")

    result = invoke_adapter(directory, "applications", wdac_request(directory))

    assert assert_app_error(result, "restart_required") == {
        "error": "restart_required", "diagnostic": {"stage": "app_wdac_verify", "os_code": None},
    }
    assert json.loads((directory / "active-policy.json").read_text(encoding="utf-8-sig"))["IsEnforced"] is False


def test_application_adapter_preserves_unsupported_without_inventing_system_code(tmp_path):
    directory = fixture_environment(tmp_path)
    (directory / "systemroot/System32/Mock-CiTool.ps1").unlink()
    request = wdac_request(directory)

    result = invoke_adapter(directory, "applications", request)

    response = assert_app_error(result, "unsupported")
    assert response.get("diagnostic", {}).get("stage") in APP_DIAGNOSTIC_STAGES, response
    assert response["diagnostic"]["os_code"] is None
    assert not Path(request["state_path"]).exists()


@pytest.mark.parametrize("kind", ["publisher", "name"])
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
    assert not any(call["name"] == "New-CIPolicy" for call in calls(directory))
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
    assert not any(call["name"] == "New-CIPolicy" for call in calls(directory))
    assert {Path(path).read_bytes() for path in scans[0]["files"]} == {
        b"fixture image; never executable", outside.read_bytes(),
    }


@pytest.mark.parametrize("scenario", ["drivers_native_prefix", "drivers_friendly_leaf"])
def test_wdac_driver_aliases_still_resolve_to_the_exact_private_copy(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "publisher")))
    scan = next(call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver")
    generated = next(call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicyRule")
    assert [path.removeprefix("\\\\?\\") for path in generated["driver_paths"]] == scan["files"]


@pytest.mark.parametrize("scenario", ["drivers_empty", "drivers_kernel", "drivers_unrelated", "drivers_duplicate", "drivers_conflicting"])
def test_wdac_rejects_missing_kernel_or_ambiguous_user_pe_samples(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "publisher"))
    assert_app_error(result, "control_failed")
    assert not (directory / "active-policy.json").exists()
    assert not any(call["name"] in {"New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))


@pytest.mark.parametrize("scenario", ["rules_empty", "rules_kernel"])
def test_wdac_rejects_empty_or_kernel_only_generated_rules(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "publisher"))
    assert result.returncode == 1
    assert not (directory / "active-policy.json").exists()
    assert not any(call["name"] == "Merge-CIPolicy" for call in calls(directory))


def test_wdac_collection_output_keeps_real_user_rules_without_mutating_kernel_rules(tmp_path):
    directory = fixture_environment(tmp_path, scenario="rules_mixed")
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "publisher")))
    merge = next(call["detail"] for call in calls(directory) if call["name"] == "Merge-CIPolicy")
    assert merge["rule_ids"] == ["fixture-rule"]
    assert merge["user_modes"] == [True]


def test_wdac_path_rule_does_not_require_a_user_pe_scan(tmp_path):
    directory = fixture_environment(tmp_path)
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "path")))
    assert not any(call["name"] == "Get-SystemDriver" for call in calls(directory))
    assert not any(call["name"] == "New-CIPolicy" for call in calls(directory))
    assert not list(directory.glob("app-control-*/catalog-*"))


def test_wdac_mismatched_hash_is_rejected_before_user_pe_enumeration(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    request["policy"]["execution_rules"][0]["value"] = "00" * 32
    result = invoke_adapter(directory, "applications", request)
    assert result.returncode == 1
    assert not any(call["name"] in {"Get-SystemDriver", "New-CIPolicy", "New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))


def test_wdac_single_hash_scans_only_its_verified_private_copy_without_driver_enumeration(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    assert_success(invoke_adapter(directory, "applications", request))
    direct = next(call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicy")
    assert direct["level"] == "Hash" and direct["deny"]
    assert direct["user_pes"] and direct["no_script"] and direct["no_shadow_copy"] and direct["multiple_policy"]
    assert len(direct["files"]) == 1
    assert Path(direct["files"][0]) != Path(request["policy"]["execution_rules"][0]["sample_path"])
    assert Path(direct["files"][0]).read_bytes() == b"fixture image; never executable"
    assert Path(direct["files"][0]).parent == Path(direct["scan_path"])
    assert Path(direct["scan_path"]).parent.parent == directory
    assert not any(call["name"] in {"Get-SystemDriver", "New-CIPolicyRule"} for call in calls(directory))
    merge = next(call["detail"] for call in calls(directory) if call["name"] == "Merge-CIPolicy")
    assert len(merge["inputs"]) == 2
    assert direct["output"] in merge["inputs"]
    assert all(Path(path).parent == Path(merge["output"]).parent for path in merge["inputs"])


def test_wdac_single_hash_uses_fresh_empty_system_private_catalogs_without_changing_windows(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    assert_success(invoke_adapter(directory, "applications", request))
    request["policy"]["execution_rules"][0]["id"] = "updated-hash-rule"
    assert_success(invoke_adapter(directory, "applications", request))
    generated = [call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicy"]
    assert len(generated) == 2
    paths = [Path(call["catalog_path"]) for call in generated]
    assert all(path.is_absolute() and path.is_dir() for path in paths)
    assert paths[0] != paths[1]
    for path, call in zip(paths, generated, strict=True):
        assert path.parent == Path(call["scan_path"]).parent
        assert call["catalog_files"] == [] and not list(path.iterdir())
        assert not path.is_relative_to(directory / "systemroot")
        descriptors = [entry["detail"] for entry in calls(directory)
                       if entry["name"] == "Set-AclDescriptor" and entry["detail"]["path"] == str(path)]
        assert len(descriptors) == 1
        assert descriptors[0]["owner_sid"] == "S-1-5-18" and descriptors[0]["protected"]
        assert len(descriptors[0]["rules"]) == 1
        assert descriptors[0]["rules"][0]["sid"] == "S-1-5-18"
        assert descriptors[0]["rules"][0]["type"] == "Allow"
        assert "FullControl" in descriptors[0]["rules"][0]["rights"]
        assert "ContainerInherit" in descriptors[0]["rules"][0]["inheritance"]
        assert "ObjectInherit" in descriptors[0]["rules"][0]["inheritance"]
    signatures = [call["detail"]["path"] for call in calls(directory) if call["name"] == "Get-AuthenticodeSignature"]
    assert signatures == [call["files"][0] for call in generated]
    mutations = [call["detail"] for call in calls(directory) if call["name"] == "Set-Acl"]
    assert not any(Path(path).is_relative_to(directory / "systemroot") for path in mutations)


def test_wdac_hash_still_refuses_a_failed_signature_query_before_catalog_generation(tmp_path):
    directory = fixture_environment(tmp_path, scenario="signature_failure")
    result = invoke_adapter(directory, "applications", wdac_request(directory, "hash"))
    assert_app_error(result, "control_failed")
    assert any(call["name"] == "Get-AuthenticodeSignature" for call in calls(directory))
    assert not any(call["name"] == "New-CIPolicy" for call in calls(directory))
    assert not (directory / "active-policy.json").exists()


def test_wdac_direct_hash_preserves_enforced_options_and_real_deny_references(tmp_path):
    directory = fixture_environment(tmp_path)
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "hash")))
    conversion = next(call["detail"] for call in calls(directory) if call["name"] == "ConvertFrom-CIPolicy")
    assert conversion["deny_count"] == conversion["user_deny_refs"] == 4
    assert conversion["kernel_deny_refs"] == 0
    assert "Enabled:UMCI" in conversion["options"]
    assert "Enabled:Update Policy No Reboot" in conversion["options"]
    assert "Enabled:Audit Mode" not in conversion["options"]
    assert "Required:Enforce Store Applications" not in conversion["options"]
    options = [call["detail"] for call in calls(directory) if call["name"] == "Set-RuleOption"]
    assert any(option["option"] == 12 and option["delete"] for option in options)


def scenario_nodes(root):
    scenarios = root.find("ci:SigningScenarios", CI)
    user = next(row for row in scenarios if row.attrib["Value"] == "12")
    kernel = next(row for row in scenarios if row.attrib["Value"] == "131")
    user_refs = user.find("ci:ProductSigners/ci:FileRulesRef", CI)
    kernel_refs = kernel.find("ci:ProductSigners/ci:FileRulesRef", CI)
    return scenarios, user, kernel, user_refs, kernel_refs


def mutate_valid_policy(root, change):
    rules = root.find("ci:FileRules", CI)
    scenarios, _, _, user_refs, kernel_refs = scenario_nodes(root)
    if change == "renamed_ids":
        ids = {row.attrib["ID"]: "arbitrary-rule-" + str(index) for index, row in enumerate(rules)}
        for row in rules:
            row.set("ID", ids[row.attrib["ID"]])
        for row in root.findall(".//ci:FileRuleRef", CI):
            row.set("RuleID", ids[row.attrib["RuleID"]])
    elif change == "reordered":
        rules[:] = list(reversed(rules))
        scenarios[:] = list(reversed(scenarios))
        user_refs[:] = list(reversed(user_refs))
        kernel_refs[:] = list(reversed(kernel_refs))
    else:
        return False
    return True


def mutate_scenario_references(root, change):
    rules = root.find("ci:FileRules", CI)
    scenarios, user, kernel, user_refs, kernel_refs = scenario_nodes(root)
    if change == "kernel_only":
        scenarios.remove(user)
        user_ids = {row.attrib["RuleID"] for row in user_refs}
        rules[:] = [row for row in rules if row.attrib["ID"] not in user_ids]
    elif change == "duplicate_user_scenario":
        scenarios.append(deepcopy(user))
    elif change == "duplicate_kernel_scenario":
        scenarios.append(deepcopy(kernel))
    elif change == "unknown_scenario":
        kernel.set("Value", "999")
    elif change == "extra_scenario":
        extra = ET.SubElement(scenarios, "{" + CI_NAMESPACE + "}SigningScenario", {"Value": "999"})
        ET.SubElement(extra, "{" + CI_NAMESPACE + "}ProductSigners")
    elif change == "shared_reference":
        kernel_refs[0].set("RuleID", user_refs[0].attrib["RuleID"])
    elif change == "orphan_reference":
        kernel_refs[0].set("RuleID", "unknown-rule")
    elif change == "duplicate_reference":
        kernel_refs[1].set("RuleID", kernel_refs[0].attrib["RuleID"])
    elif change == "out_of_path_reference":
        row = kernel_refs[0]
        kernel_refs.remove(row)
        root.append(row)
    elif change == "three_references_per_scenario":
        for container in (user_refs, kernel_refs):
            reference = container[-1]
            container.remove(reference)
            rules.remove(next(row for row in rules if row.attrib["ID"] == reference.attrib["RuleID"]))
    else:
        return False
    return True


def mutate_hash_rules(root, change):
    rules = root.find("ci:FileRules", CI)
    if change == "duplicate_rule_id":
        rules[1].set("ID", rules[0].attrib["ID"])
    elif change == "allow_rule":
        ET.SubElement(rules, "{" + CI_NAMESPACE + "}Allow", {"ID": "EXTRA", "FileName": "*"})
    elif change == "signer":
        ET.SubElement(root.find("ci:Signers", CI), "{" + CI_NAMESPACE + "}Signer", {"ID": "EXTRA", "Name": "Other publisher"})
    elif change == "file_attribute":
        ET.SubElement(rules, "{" + CI_NAMESPACE + "}FileAttrib", {"ID": "EXTRA", "FileName": "*"})
    elif change == "invalid_hash":
        rules[0].set("Hash", "not-a-hash")
    elif change == "non_equivalent_hash":
        rules[0].set("Hash", "F" * 40)
    elif change == "same_hash_set_different_multiplicity":
        values = [rules[0].attrib["Hash"], rules[1].attrib["Hash"], rules[2].attrib["Hash"]]
        for row, value in zip(list(rules)[:4], [values[0], values[1], values[1], values[2]], strict=True):
            row.set("Hash", value)
            row.set("FriendlyName", "fixture.exe Hash")
        for row, value in zip(list(rules)[4:], [values[0], values[0], values[1], values[2]], strict=True):
            row.set("Hash", value)
            row.set("FriendlyName", "fixture.exe Hash")
    elif change == "non_equivalent_friendly_name":
        rules[0].set("FriendlyName", "other.exe Hash Sha1")
    else:
        return False
    return True


def mutate_policy_schema(root, change):
    rules = root.find("ci:FileRules", CI)
    _, _, _, _, kernel_refs = scenario_nodes(root)
    if change == "foreign_namespace_element":
        ET.SubElement(root, "{urn:unexpected}Extra")
    elif change == "foreign_namespace_attribute":
        rules[0].set("{urn:unexpected}Extra", "not allowed")
    elif change == "unexpected_element":
        ET.SubElement(root, "{" + CI_NAMESPACE + "}Unexpected")
    elif change == "unexpected_attribute":
        kernel_refs[0].set("Extra", "not allowed")
    elif change == "unexpected_root_attribute":
        root.set("Unexpected", "not allowed")
    elif change == "hvci_nonzero":
        root.find("ci:HvciOptions", CI).text = "1"
    elif change == "hvci_non_numeric":
        root.find("ci:HvciOptions", CI).text = "unexpected"
    elif change == "missing_umci":
        options = root.find("ci:Rules", CI)
        options.remove(next(row for row in options if row.find("ci:Option", CI).text == "Enabled:UMCI"))
    elif change == "unknown_option":
        row = ET.SubElement(root.find("ci:Rules", CI), "{" + CI_NAMESPACE + "}Rule")
        ET.SubElement(row, "{" + CI_NAMESPACE + "}Option").text = "Enabled:Unexpected"
    else:
        return False
    return True


def dual_scenario_policy(change="original"):
    """Mutate inert, byte-verified VM XML; no fixture executable is ever loaded."""
    # Restore ConfigCI's original BOM/CRLF format after Git's checkout newline conversion.
    fixture_text = DUAL_SCENARIO_XML.read_bytes().decode("utf-8-sig").replace("\r\n", "\n")
    original = b"\xef\xbb\xbf" + fixture_text.replace("\n", "\r\n").encode("utf-8")
    assert hashlib.sha256(original).hexdigest() == "24457a4c42a42d444809fb64820b126b1d639be6d93e5f3a314a2d9488fca36b"
    if change == "original":
        return original
    if change == "dtd_entity":
        value = original.decode("utf-8-sig").replace("?>", '?>\n<!DOCTYPE SiPolicy [<!ENTITY marker "fixture">]>', 1)
        return value.replace('FriendlyName="', 'FriendlyName="&marker;').encode("utf-8")
    ET.register_namespace("", CI_NAMESPACE)
    root = ET.fromstring(original)  # noqa: S314 - exact digest-pinned inert XML, never external data
    mutators = (mutate_valid_policy, mutate_scenario_references, mutate_hash_rules, mutate_policy_schema)
    if not any(mutate(root, change) for mutate in mutators):
        raise AssertionError("unknown XML mutation: " + change)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def user_mode_denies(policy):
    root = ET.fromstring(policy)  # noqa: S314 - generated only by the digest-pinned test fixture mutators
    rules = {row.attrib["ID"]: row for row in root.find("ci:FileRules", CI)}
    references = root.findall('ci:SigningScenarios/ci:SigningScenario[@Value="12"]/ci:ProductSigners/ci:FileRulesRef/ci:FileRuleRef', CI)
    return sorted((row.attrib["RuleID"], rules[row.attrib["RuleID"]].attrib["Hash"],
                   rules[row.attrib["RuleID"]].attrib.get("FriendlyName", "")) for row in references)


@pytest.mark.parametrize("change", ["original", "renamed_ids", "reordered"])
def test_wdac_dual_scenario_hash_policy_preserves_only_the_exact_user_mode_denies(tmp_path, change):
    generated = dual_scenario_policy(change)
    directory = fixture_environment(tmp_path, generated_policy=generated)
    result = assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "hash")))
    before_merge = next(call["detail"] for call in calls(directory) if call["name"] == "PreMerge-HashPolicy")
    assert before_merge["kernel_scenarios"] == before_merge["kernel_product_signers"] == 1
    assert before_merge["kernel_reference_containers"] == 0, "Microsoft's schema forbids an empty FileRulesRef container"
    conversion = next(call["detail"] for call in calls(directory) if call["name"] == "ConvertFrom-CIPolicy")
    assert conversion["deny_count"] == conversion["user_deny_refs"] == 4
    assert conversion["kernel_deny_refs"] == 0
    observed = sorted((row["id"], row["hash"], row["friendly_name"]) for row in conversion["user_deny_rules"])
    assert observed == user_mode_denies(generated)
    assert "app-control:wdac" in result["capabilities"]
    assert "Enabled:UMCI" in conversion["options"]
    assert "Enabled:Update Policy No Reboot" in conversion["options"]
    assert "Enabled:Audit Mode" not in conversion["options"]
    assert "Required:Enforce Store Applications" not in conversion["options"]
    assert (directory / "generated-policy.xml").read_bytes() == generated


def test_normalized_real_hash_policy_matches_microsoft_schema_before_any_merge(tmp_path):
    schema = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "schemas/CodeIntegrity/cipolicy.xsd"
    assert schema.is_file(), "Windows must provide its Code Integrity XML schema for this contract"
    generated = dual_scenario_policy()
    policy = tmp_path / "private-hash.xml"
    policy.write_bytes(generated)
    driver = tmp_path / "xml-schema-contract.ps1"
    driver.write_text(r'''param([string]$Source,[string]$Policy,[string]$Schema)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$errors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'The source must parse before selecting XML helpers.' }
foreach ($name in @('Assert-PrivateHashPolicy','Normalize-PrivateHashPolicy')) {
    $functions=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq $name},$true))
    if ($functions.Count -ne 1) { throw 'Expected one selected XML helper.' }
    # Only XML helper definitions are loaded. The adapter top-level and ConfigCI never execute.
    $commands=@($functions[0].FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))
    foreach ($command in $commands) {
        if ($command.GetCommandName() -notin @('New-Object','Where-Object','ForEach-Object','Assert-PrivateHashPolicy')) { throw 'A selected XML helper gained an unexpected command.' }
    }
    . ([scriptblock]::Create($functions[0].Extent.Text))
}
$settings=New-Object Xml.XmlReaderSettings
$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
$schemas=New-Object Xml.Schema.XmlSchemaSet;$schemas.XmlResolver=$null
$schemaReader=[Xml.XmlReader]::Create($Schema,$settings)
try { [void]$schemas.Add('urn:schemas-microsoft-com:sipolicy',$schemaReader) } finally { $schemaReader.Dispose() }
$schemas.Compile()
function Schema-Errors([string]$Path) {
    $reader=[Xml.XmlReader]::Create($Path,$settings)
    $xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null
    try { $xml.Load($reader) } finally { $reader.Dispose() }
    $xml.Schemas=$schemas
    $script:messages=New-Object 'Collections.Generic.List[string]'
    $handler=[Xml.Schema.ValidationEventHandler]{ param($sender,$event) [void]$script:messages.Add($event.Message) }
    $xml.Validate($handler)
    return @($script:messages.ToArray())
}
$originalErrors=@(Schema-Errors $Policy)
Normalize-PrivateHashPolicy $Policy
Assert-PrivateHashPolicy $Policy
$normalizedErrors=@(Schema-Errors $Policy)
$reader=[Xml.XmlReader]::Create($Policy,$settings)
$xml=New-Object Xml.XmlDocument;$xml.XmlResolver=$null
try { $xml.Load($reader) } finally { $reader.Dispose() }
$ns=New-Object Xml.XmlNamespaceManager($xml.NameTable);$ns.AddNamespace('ci','urn:schemas-microsoft-com:sipolicy')
@{original_schema_errors=$originalErrors;normalized_schema_errors=$normalizedErrors
  kernel_scenarios=$xml.SelectNodes('/ci:SiPolicy/ci:SigningScenarios/ci:SigningScenario[@Value="131"]',$ns).Count
  kernel_product_signers=$xml.SelectNodes('/ci:SiPolicy/ci:SigningScenarios/ci:SigningScenario[@Value="131"]/ci:ProductSigners',$ns).Count
  kernel_reference_containers=$xml.SelectNodes('/ci:SiPolicy/ci:SigningScenarios/ci:SigningScenario[@Value="131"]/ci:ProductSigners/ci:FileRulesRef',$ns).Count
  deny_count=$xml.SelectNodes('/ci:SiPolicy/ci:FileRules/ci:Deny',$ns).Count}|ConvertTo-Json -Depth 6 -Compress
''', encoding="utf-8-sig")
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(driver),
                             "-Source", str(ROOT / "deploy/agent-applications.ps1"), "-Policy", str(policy),
                             "-Schema", str(schema)], capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, (result.stdout, result.stderr)
    observed = json.loads(result.stdout.lstrip("\ufeff"))
    assert observed["original_schema_errors"] == [], observed
    assert observed["normalized_schema_errors"] == [], observed
    assert observed["kernel_scenarios"] == observed["kernel_product_signers"] == 1
    assert observed["kernel_reference_containers"] == 0
    assert observed["deny_count"] == 4
    assert user_mode_denies(policy.read_bytes()) == user_mode_denies(generated)


@pytest.mark.parametrize("change", [
    "kernel_only", "duplicate_user_scenario", "duplicate_kernel_scenario", "unknown_scenario", "extra_scenario",
    "shared_reference", "orphan_reference", "duplicate_reference", "out_of_path_reference", "duplicate_rule_id",
    "foreign_namespace_element", "foreign_namespace_attribute", "unexpected_element", "unexpected_attribute",
    "unexpected_root_attribute", "allow_rule", "signer", "file_attribute", "invalid_hash", "non_equivalent_hash",
    "same_hash_set_different_multiplicity", "non_equivalent_friendly_name", "missing_umci", "unknown_option",
    "three_references_per_scenario", "dtd_entity", "hvci_nonzero", "hvci_non_numeric",
])
def test_wdac_dual_scenario_rejects_invalid_or_non_equivalent_input_without_rewriting_it(tmp_path, change):
    generated = dual_scenario_policy(change)
    directory = fixture_environment(tmp_path, generated_policy=generated)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "hash"))
    assert_app_error(result, "control_failed")
    generated_call = next(call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicy")
    assert Path(generated_call["output"]).read_bytes() == generated
    assert not any(call["name"] in {"Merge-CIPolicy", "ConvertFrom-CIPolicy"} for call in calls(directory))
    assert not (directory / "active-policy.json").exists()


@pytest.mark.parametrize("scenario", [
    "policy_empty", "policy_kernel", "policy_unreferenced", "policy_bad_hash", "policy_allow",
    "policy_signer", "policy_duplicate_id", "policy_non_hash", "policy_extra_reference",
    "policy_missing_umci", "policy_bad_namespace", "policy_malformed",
])
def test_wdac_direct_hash_rejects_invalid_or_widened_xml_before_merge_or_loading(tmp_path, scenario):
    directory = fixture_environment(tmp_path, scenario=scenario)
    result = invoke_adapter(directory, "applications", wdac_request(directory, "hash"))
    assert_app_error(result, "control_failed")
    assert not (directory / "active-policy.json").exists()
    assert not any(call["name"] == "Merge-CIPolicy" for call in calls(directory))


def _private_catalog(directory, scan):
    path = Path(scan["catalog_path"])
    assert path.is_absolute() and path.is_dir() and scan["catalog_files"] == [] and not list(path.iterdir())
    assert path.parent == Path(scan["path"]).parent and not path.is_relative_to(directory / "systemroot")
    descriptors = [entry["detail"] for entry in calls(directory)
                   if entry["name"] == "Set-AclDescriptor" and entry["detail"]["path"] == str(path)]
    assert len(descriptors) == 1 and descriptors[0]["owner_sid"] == "S-1-5-18" and descriptors[0]["protected"]
    assert [rule["sid"] for rule in descriptors[0]["rules"]] == ["S-1-5-18"]
    return path


@pytest.mark.parametrize("kind", ["publisher", "name"])
def test_wdac_driver_scan_uses_a_fresh_empty_private_catalog_for_embedded_signatures(tmp_path, kind):
    # The system catalog root took 51 s to scan in the acceptance guest and exceeded the adapter limit.
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    request = wdac_request(directory, kind)
    assert_success(invoke_adapter(directory, "applications", request))
    request["policy"]["execution_rules"][0]["id"] = "updated-rule"
    assert_success(invoke_adapter(directory, "applications", request))
    scans = [call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver"]
    assert len(scans) == 2
    paths = [_private_catalog(directory, scan) for scan in scans]
    assert paths[0] != paths[1]


def test_wdac_catalog_signed_publisher_keeps_the_system_catalog_root(tmp_path):
    # A catalog-only signature has no embedded signer; an empty catalog root would lose the publisher.
    directory = fixture_environment(tmp_path, scenario="catalog_signed")
    assert_success(invoke_adapter(directory, "applications", wdac_request(directory, "publisher")))
    scan = next(call["detail"] for call in calls(directory) if call["name"] == "Get-SystemDriver")
    assert scan["catalog_path"] in (None, "")
    assert not list(directory.glob("app-control-*/catalog-*"))


def test_wdac_mixed_rules_keep_the_driver_file_route(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "hash")
    request["policy"]["execution_rules"].append({
        "id": "path", "kind": "path", "value": str(directory / "fixture.exe"),
    })
    assert_success(invoke_adapter(directory, "applications", request))
    assert any(call["name"] == "Get-SystemDriver" for call in calls(directory))
    assert not any(call["name"] == "New-CIPolicy" for call in calls(directory))


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
    if kind == "applications":
        assert_app_error(result, "control_failed")
    else:
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


def test_present_only_rule_without_a_local_sample_succeeds_without_deploying_wdac(tmp_path):
    directory = fixture_environment(tmp_path)
    request = wdac_request(directory, "publisher")
    request["policy"]["execution_rules"] = [{"id": "catalog-absent", "kind": "publisher", "value": "CN=Absent Vendor",
                                             "sample_path": str(directory / "absent.exe"), "if_present": True}]
    assert_success(invoke_adapter(directory, "applications", request))
    assert not any(call["name"] in {"Get-SystemDriver", "New-CIPolicy", "New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))
    assert not (directory / "active-policy.json").exists()


def test_present_only_rules_keep_the_present_sample_and_strict_rules_still_fail(tmp_path):
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    request = wdac_request(directory, "publisher")
    request["policy"]["execution_rules"][0]["if_present"] = True
    request["policy"]["execution_rules"].append({"id": "catalog-absent", "kind": "publisher", "value": "CN=Absent Vendor",
                                                 "sample_path": str(directory / "absent.exe"), "if_present": True})
    assert_success(invoke_adapter(directory, "applications", request))
    generated = [call["detail"] for call in calls(directory) if call["name"] == "New-CIPolicyRule"]
    assert len(generated) == 1 and generated[0]["level"] == "Publisher"
    (tmp_path / "strict").mkdir()
    strict = fixture_environment(tmp_path / "strict")
    request = wdac_request(strict, "publisher")
    request["policy"]["execution_rules"][0]["sample_path"] = str(strict / "absent.exe")
    result = invoke_adapter(strict, "applications", request)
    assert_app_error(result, "control_failed")


def test_present_only_rules_are_rechecked_hourly_so_later_installs_get_denied(tmp_path):
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    request = wdac_request(directory, "publisher")
    later = directory / "later.exe"
    request["policy"]["execution_rules"] = [{"id": "catalog-later", "kind": "publisher", "value": "CN=Fixture Publisher",
                                             "sample_path": str(later), "if_present": True}]
    assert_success(invoke_adapter(directory, "applications", request))
    later.write_bytes(b"installed later; never executable")
    assert_success(invoke_adapter(directory, "applications", request))
    assert not any(call["name"] == "New-CIPolicyRule" for call in calls(directory)), "a fresh check must not redo heavy work"
    journal = directory / "application-control.json"
    state = json.loads(journal.read_text(encoding="utf-8-sig"))
    state["optional_checked_at"] = 0
    journal.write_text(json.dumps(state), encoding="utf-8")
    assert_success(invoke_adapter(directory, "applications", request))
    assert [call["detail"]["level"] for call in calls(directory) if call["name"] == "New-CIPolicyRule"] == ["Publisher"]
    assert (directory / "active-policy.json").exists()


def test_catalog_rules_are_skipped_where_windows_has_no_application_control(tmp_path):
    # Windows Home has no CiTool/ConfigCI: catalog process and network controls must still apply.
    directory = fixture_environment(tmp_path, scenario="requires_driver_files")
    (directory / "systemroot/System32/Mock-CiTool.ps1").unlink()
    request = wdac_request(directory, "publisher")
    request["policy"]["execution_rules"][0]["if_present"] = True
    result = assert_success(invoke_adapter(directory, "applications", request))
    assert "app-control:wdac" not in result["capabilities"]
    assert not any(call["name"] in {"Get-SystemDriver", "New-CIPolicy", "New-CIPolicyRule", "Merge-CIPolicy"} for call in calls(directory))
    (tmp_path / "strict-home").mkdir()
    strict = fixture_environment(tmp_path / "strict-home")
    (strict / "systemroot/System32/Mock-CiTool.ps1").unlink()
    refused = invoke_adapter(strict, "applications", wdac_request(strict, "publisher"))
    assert_app_error(refused, "unsupported")
