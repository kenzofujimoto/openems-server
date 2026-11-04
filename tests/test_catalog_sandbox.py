"""Catalog acceptance contracts; never execute endpoint controls on this host.

Builder tests use inert PE/MSI bytes and the real in-process server API. Windows
tests extract pure validators or isolated orchestration with mocked boundaries,
or request the harness's read-only plan. The harness top-level never runs here.
"""

from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from agent.policy import policy_digest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/test-catalog-sandbox.ps1"
BUILDER = ROOT / "tools/build_catalog_acceptance.py"
POWERSHELL = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
REVISION = "a" * 40
RUN_ID = "0123456789abcdef0123456789abcdef"
NOW = datetime(2026, 11, 2, 16, 0, tzinfo=UTC)
CASES = ("allow", "absent", "network", "network_release", "present", "later", "release")
CHECKS = ("absent", "network", "process", "wdac", "all_absent", "hourly", "release", "cleanup")
WINDOWS = [pytest.mark.windows_only, pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell 5.1 contracts")]


def record(path):
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "bytes": path.stat().st_size}


@pytest.fixture
def builder(monkeypatch):
    class LazyBuilder:
        """Defer import until the test body, including for package-dependent tests."""

        module = None

        def __getattr__(self, name):
            if self.module is None:
                assert BUILDER.is_file(), "the catalog acceptance builder has not been implemented"
                monkeypatch.syspath_prepend(str(ROOT / "tools"))
                spec = importlib.util.spec_from_file_location("catalog_acceptance_builder_under_test", BUILDER)
                assert spec is not None and spec.loader is not None
                module = importlib.util.module_from_spec(spec)
                monkeypatch.setitem(sys.modules, spec.name, module)
                spec.loader.exec_module(module)
                monkeypatch.setattr(module, "revision", lambda: REVISION)

                def compile_inert_fixture(path, type_name):
                    path = Path(path)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"MZ\0inert test fixture; never executable\0" + str(type_name).encode())

                monkeypatch.setattr(module, "compile_fixture", compile_inert_fixture)
                self.module = module
            return getattr(self.module, name)

    return LazyBuilder()


@pytest.fixture
def source_package(tmp_path):
    source = tmp_path / "source"
    packages = source / "final-msi"
    packages.mkdir(parents=True)
    records = {}
    for name in ("openems-agent.msi", "openems-agent-next.msi"):
        path = packages / name
        path.write_bytes(b"inert MSI test bytes; never installed: " + name.encode())
        records[name] = record(path)
    (source / "acceptance-manifest.json").write_text(json.dumps({
        "source_revision": REVISION, "packages": records, "phases": {},
    }), encoding="utf-8")
    return source


@pytest.fixture
def package(builder, source_package, tmp_path):
    output = tmp_path / "catalog-input"

    def prepare():
        manifest = builder.build(source_package, output, run_id=RUN_ID, now=NOW)
        return output, manifest

    return prepare


def test_builder_uses_real_api_and_expander_for_the_delivered_policies(builder, source_package, tmp_path, monkeypatch):
    import app.api
    from starlette.testclient import TestClient

    calls = []
    expansions = []
    real_request = TestClient.request
    real_expand = app.api.expand_catalog

    def observed_request(client, method, url, *args, **kwargs):
        calls.append((str(method).upper(), str(url)))
        return real_request(client, method, url, *args, **kwargs)

    def observed_expand(actions, applications, catalog):
        applications = list(applications)
        result = real_expand(actions, applications, catalog)
        expansions.append((deepcopy(actions), deepcopy(applications), deepcopy(result)))
        return result

    monkeypatch.setattr(TestClient, "request", observed_request)
    monkeypatch.setattr(app.api, "expand_catalog", observed_expand)
    manifest = builder.build(source_package, tmp_path / "catalog-input", run_id=RUN_ID, now=NOW)
    assert any(method == "POST" and "/fct/api/public/v1/inventory/" in path for method, path in calls)
    assert any(method == "POST" and "/api/v1/profiles/" in path for method, path in calls)
    assert expansions, "the actual API must call the actual catalog expansion implementation"
    for key in ("absent", "present", "later"):
        controls = manifest["policies"][key]["body"]["app_control"]
        assert any(result["rules"] == controls["execution_rules"] for _, _, result in expansions)
    assert any(result["network"] == manifest["policies"]["network"]["body"]["app_control"]["network_blocked"]
               for _, _, result in expansions)


def test_policy_sequence_separates_firewall_from_termination_and_keeps_real_digests(package):
    _, manifest = package()
    policies = manifest["policies"]
    versions = [policies[key]["version"] for key in CASES]
    assert versions == sorted(set(versions)) and len(versions) == len(CASES)
    for assignment in policies.values():
        assert assignment["digest"] == policy_digest(assignment["body"])
    network = policies["network"]["body"]["app_control"]
    assert network["blocked"] == [] and network["execution_rules"] == []
    assert len(network["network_blocked"]) == 1
    present = policies["present"]["body"]["app_control"]
    assert len(present["blocked"]) == 1 and present["network_blocked"] == []
    for key in ("absent", "present", "later"):
        rules = policies[key]["body"]["app_control"]["execution_rules"]
        assert len(rules) == 1
        assert rules[0]["if_present"] is True and rules[0]["id"].startswith("catalog-")
        assert rules[0]["kind"] == "hash" and "sample_path" not in rules[0]
    assert policies["absent"]["body"] == policies["present"]["body"]
    assert policies["later"]["body"]["app_control"]["execution_rules"] != present["execution_rules"]
    for key in ("allow", "network_release", "release"):
        controls = policies[key]["body"]["app_control"]
        assert controls["blocked"] == controls["network_blocked"] == controls["execution_rules"] == []


def test_package_binds_fixture_bytes_catalog_scope_and_every_delivered_file(builder, package):
    output, manifest = package()
    assert manifest["phase"] == "catalog" and manifest["source_revision"] == REVISION
    assert manifest["run_id"] == RUN_ID
    assert manifest["guest_work_directory"] == "C:\\openems-catalog-" + RUN_ID
    assert set(manifest["fixtures"]) == {"a", "b"}
    for fixture in manifest["fixtures"].values():
        image = output / fixture["file"]
        renamed = output / fixture["renamed_file"]
        assert image.name != renamed.name and image.read_bytes() == renamed.read_bytes()
        assert fixture["sha256"] == record(image)["sha256"]
        assert "openems" in fixture["installed_name"].lower(), "fixtures must identify themselves honestly"
    assert SCRIPT.name in manifest["files"]
    for name, expected in manifest["files"].items():
        assert Path(name).name == name and record(output / name) == expected
    proof = manifest["expansion_proof"]
    assert proof["synthetic_catalog"] is True and proof["real_server_api"] is True
    assert proof["guest_transport"] == "powershell_fixture"
    assert proof["real_server_network_e2e"] is False
    verified = builder.verify_package(output, expected_revision=REVISION)
    assert verified["_manifest_sha256"] == record(output / "acceptance-manifest.json")["sha256"]


@pytest.mark.parametrize("invalid", ["", "..", "../escape", "C:\\outside", "f" * 31, "G" * 32, "f" * 33])
def test_builder_refuses_unsafe_run_ids_before_creating_output(builder, source_package, tmp_path, invalid):
    output = tmp_path / "must-not-exist"
    with pytest.raises((ValueError, RuntimeError)):
        builder.build(source_package, output, run_id=invalid, now=NOW)
    assert not output.exists()


@pytest.mark.parametrize("mismatch", ["revision", "msi_bytes", "msi_size", "missing_package"])
def test_builder_refuses_stale_or_changed_source_packages(builder, source_package, tmp_path, mismatch):
    manifest_path = source_package / "acceptance-manifest.json"
    receipt = json.loads(manifest_path.read_text(encoding="utf-8"))
    image = source_package / "final-msi/openems-agent.msi"
    if mismatch == "revision":
        receipt["source_revision"] = "b" * 40
    elif mismatch == "msi_bytes":
        image.write_bytes(b"changed bytes")
    elif mismatch == "msi_size":
        receipt["packages"][image.name]["bytes"] += 1
    else:
        image.unlink()
    manifest_path.write_text(json.dumps(receipt), encoding="utf-8")
    output = tmp_path / "must-not-exist"
    with pytest.raises((ValueError, RuntimeError, OSError)):
        builder.build(source_package, output, run_id=RUN_ID, now=NOW)
    assert not output.exists()


@pytest.mark.parametrize("mismatch", ["file_bytes", "file_size", "missing_file", "revision", "run_id", "traversal"])
def test_package_verifier_refuses_tampered_missing_or_misbound_inputs(builder, package, mismatch):
    output, manifest = package()
    path = output / "acceptance-manifest.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    fixture_name = manifest["fixtures"]["a"]["file"]
    if mismatch == "file_bytes":
        (output / fixture_name).write_bytes(b"tampered")
    elif mismatch == "file_size":
        value["files"][fixture_name]["bytes"] += 1
    elif mismatch == "missing_file":
        (output / SCRIPT.name).unlink()
    elif mismatch == "revision":
        value["source_revision"] = "b" * 40
    elif mismatch == "run_id":
        value["run_id"] = "b" * 32
    else:
        value["files"]["../outside.exe"] = value["files"][fixture_name]
    path.write_text(json.dumps(value), encoding="utf-8")
    with pytest.raises((ValueError, RuntimeError, OSError)):
        builder.verify_package(output, expected_revision=REVISION)


def denial():
    return {"native_error": 4551, "process_created": False, "started": False, "exit": -1}


def hourly():
    return {
        "elapsed_seconds": 3602.0, "started_utc": "2026-11-02T16:00:00Z", "finished_utc": "2026-11-02T17:00:02Z",
        "before": {"version": 6, "digest": "c" * 64, "optional_checked_at": 1793635200},
        "after": {"version": 6, "digest": "c" * 64, "optional_checked_at": 1793638802},
        "assignment_observations": [{"version": 6, "digest": "c" * 64}, {"version": 6, "digest": "c" * 64}],
        "before_admission": {"process_created": True, "native_error": 0}, "after_denial": denial(),
    }


def report_for(manifest):
    def ack_case(name):
        assignment = {key: manifest["policies"][name][key] for key in ("version", "digest")}
        return {"assignment": assignment, "ack": {**assignment, "success": True}}

    guest = manifest["guest_work_directory"]
    target = guest + "\\" + manifest["fixtures"]["a"]["file"]
    later = hourly()
    identity = {key: manifest["policies"]["later"][key] for key in ("version", "digest")}
    later["before"].update(identity)
    later["after"].update(identity)
    later["assignment_observations"] = [dict(identity), dict(identity)]
    evidence = {
        "absent": {**ack_case("absent"), "own_policy_present": False},
        "network": {"before": {"target_exit": 0, "control_exit": 0},
                    "blocked": {"target_process_created": True, "target_exit": 42, "control_exit": 0},
                    "released": {"target_exit": 0, "control_exit": 0},
                    "firewall_paths": [target, target], "control_has_rule": False},
        "process": {"target_was_running": True, "target_pid": 123, "target_exited": True,
                    "control_pid": 456, "control_still_running": True},
        "wdac": {"policy_enforced": True, "original": denial(), "renamed": denial()},
        "all_absent": {**ack_case("later"), "own_policy_present": False,
                       "foreign_before": ["foreign-policy"], "foreign_after": ["foreign-policy"]},
        "hourly": later,
        "release": {**ack_case("release"), "original_exit": 0, "renamed_exit": 0,
                    "own_policy_present": False, "firewall_rule_count": 0},
        "cleanup": {"msi_exit": 0, "service_present": False, "watchdog_present": False, "nrpt_count": 0,
                    "owned_firewall_rules": 0, "own_policy_present": False, "fixture_registry_present": False,
                    "foreign_before": ["foreign-policy"], "foreign_after": ["foreign-policy"]},
    }
    return {"run_id": manifest["run_id"], "source_revision": manifest["source_revision"],
            "status": "passed", "passed": True, "error": None, "cleanup_errors": [],
            "package_receipt": {"source_revision": manifest["source_revision"], "packages": manifest["packages"],
                                "manifest_sha256": manifest["_manifest_sha256"]},
            "checks": [{"name": name, "status": "passed", "evidence": evidence[name]} for name in CHECKS]}


REPORT_MUTATIONS = (
    ("empty_evidence", ("checks", 0, "evidence"), {}),
    ("renamed_started", ("checks", 3, "evidence", "renamed", "process_created"), True),
    ("wdac_sentinel", ("checks", 3, "evidence", "original", "started"), True),
    ("wdac_other_error", ("checks", 3, "evidence", "original", "native_error"), 5),
    ("target_still_alive", ("checks", 2, "evidence", "target_exited"), False),
    ("control_killed", ("checks", 2, "evidence", "control_still_running"), False),
    ("network_not_started", ("checks", 1, "evidence", "blocked", "target_process_created"), False),
    ("both_network_fail", ("checks", 1, "evidence", "blocked", "control_exit"), 42),
    ("wrong_network_exit", ("checks", 1, "evidence", "blocked", "target_exit"), -1),
    ("wrong_firewall_path", ("checks", 1, "evidence", "firewall_paths"), ["C:\\wrong.exe", "C:\\wrong.exe"]),
    ("policy_not_removed", ("checks", 4, "evidence", "own_policy_present"), True),
    ("foreign_policy_removed", ("checks", 4, "evidence", "foreign_after"), []),
    ("hour_early", ("checks", 5, "evidence", "elapsed_seconds"), 3599.9),
    ("hour_new_push", ("checks", 5, "evidence", "after", "version"), 99),
    ("hour_checked_at_unchanged", ("checks", 5, "evidence", "after", "optional_checked_at"), 1793635200),
    ("hour_checked_at_forged", ("checks", 5, "evidence", "before", "optional_checked_at"), 0),
    ("release_failed", ("checks", 6, "evidence", "original_exit"), 42),
    ("msi_failed", ("checks", 7, "evidence", "msi_exit"), 1603),
    ("service_left", ("checks", 7, "evidence", "service_present"), True),
    ("watchdog_left", ("checks", 7, "evidence", "watchdog_present"), True),
    ("nrpt_left", ("checks", 7, "evidence", "nrpt_count"), 1),
    ("firewall_left", ("checks", 7, "evidence", "owned_firewall_rules"), 1),
    ("registry_left", ("checks", 7, "evidence", "fixture_registry_present"), True),
    ("msi_exit_boolean", ("checks", 7, "evidence", "msi_exit"), False),
    ("network_exit_boolean", ("checks", 1, "evidence", "before", "target_exit"), False),
    ("release_exit_boolean", ("checks", 6, "evidence", "original_exit"), False),
    ("firewall_count_boolean", ("checks", 6, "evidence", "firewall_rule_count"), False),
    ("service_nonboolean", ("checks", 7, "evidence", "service_present"), 0),
    ("policy_enforced_nonboolean", ("checks", 3, "evidence", "policy_enforced"), "true"),
    ("process_created_nonboolean", ("checks", 3, "evidence", "original", "process_created"), 0),
    ("sentinel_nonboolean", ("checks", 3, "evidence", "original", "started"), 0),
    ("control_alive_nonboolean", ("checks", 2, "evidence", "control_still_running"), 1),
    ("future_checked_at", ("checks", 5, "evidence", "after", "optional_checked_at"), 1793638880),
)
SEMANTIC_CHANGES = ("none", *(name for name, _, _ in REPORT_MUTATIONS), "missing_check")
SCALAR_CHANGES = ("none", *(name for name, _, _ in REPORT_MUTATIONS
                           if name.endswith(("boolean", "nonboolean")) or name == "future_checked_at"))


def mutated_report(report, change):
    changed = deepcopy(report)
    if change == "none":
        return changed
    if change == "missing_check":
        changed["checks"].pop()
        return changed
    _, path, value = next(mutation for mutation in REPORT_MUTATIONS if mutation[0] == change)
    target = changed
    for part in path[:-1]:
        target = target[part]
    target[path[-1]] = deepcopy(value)
    return changed


@pytest.mark.parametrize("change", ["none", "run_id", "revision", "receipt", "manifest_hash", "partial", "error", "cleanup", "running"])
def test_report_summary_never_accepts_stale_partial_or_unclean_runs(builder, package, change):
    output, _ = package()
    manifest = builder.verify_package(output, expected_revision=REVISION)
    report = report_for(manifest)
    if change == "run_id":
        report["run_id"] = "b" * 32
    elif change == "revision":
        report["source_revision"] = "b" * 40
    elif change == "receipt":
        report["package_receipt"]["packages"] = {}
    elif change == "manifest_hash":
        report["package_receipt"]["manifest_sha256"] = "b" * 64
    elif change == "partial":
        report["checks"].pop()
    elif change == "error":
        report["error"] = "fixture failed"
    elif change == "cleanup":
        report["cleanup_errors"] = ["normal MSI removal failed"]
    elif change == "running":
        report["status"] = "running"
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is (change == "none"), summary
    assert bool(summary["errors"]) is (change != "none"), summary


@pytest.mark.parametrize("change", SEMANTIC_CHANGES)
def test_host_summary_independently_rejects_contradictory_evidence_despite_passed_flags(builder, package, change):
    output, _ = package()
    manifest = builder.verify_package(output, expected_revision=REVISION)
    report = mutated_report(report_for(manifest), change)
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is (change == "none"), summary
    assert bool(summary["errors"]) is (change != "none"), summary


@pytest.mark.parametrize("change", SCALAR_CHANGES)
def test_host_verifier_refuses_boolean_exit_codes_coerced_flags_and_future_checked_at(builder, change):
    # Exercise the evaluator directly: a missing guest harness cannot mask a
    # validator regression behind an unrelated package-construction failure.
    manifest = {
        "run_id": RUN_ID, "source_revision": REVISION, "_manifest_sha256": "d" * 64,
        "guest_work_directory": "C:\\openems-catalog-" + RUN_ID, "fixtures": {"a": {"file": "a.exe"}},
        "packages": {"openems-agent.msi": {"sha256": "e" * 64, "bytes": 1}},
        "policies": {name: {"version": index + 1, "digest": "c" * 64} for index, name in enumerate(CASES)},
    }
    report = mutated_report(report_for(manifest), change)
    summary = builder.summarize_report(report, manifest)
    assert summary["passed"] is (change == "none"), summary
    assert bool(summary["errors"]) is (change != "none"), summary


PURE_DRIVER = r"""param([string]$Source,[string]$DataPath,[string]$ExpressionPath,[string]$Names)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=New-Object Text.UTF8Encoding($false)
$tokens=$null;$parseErrors=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($Source,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count) { throw 'Catalog harness did not parse.' }
foreach($name in (@('Field') + @($Names -split ','))) {
    $matches=@($tree.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name},$true))
    if($name -eq 'Field' -and $matches.Count -eq 0) { continue }
    if($matches.Count -ne 1) { throw ('Expected one pure helper: '+$name) }
    # Only the selected definition is loaded. Never execute the harness top-level.
    . ([scriptblock]::Create($matches[0].Extent.Text))
}
$script:writeAttempts=0
function New-Item { $script:writeAttempts++;throw 'Forbidden host mutation: New-Item' }
function Set-Content { $script:writeAttempts++;throw 'Forbidden host mutation: Set-Content' }
function Set-ItemProperty { $script:writeAttempts++;throw 'Forbidden host mutation: Set-ItemProperty' }
function Remove-Item { $script:writeAttempts++;throw 'Forbidden host mutation: Remove-Item' }
function Copy-Item { $script:writeAttempts++;throw 'Forbidden host mutation: Copy-Item' }
function Start-Process { $script:writeAttempts++;throw 'Forbidden host process' }
function Register-ScheduledTask { $script:writeAttempts++;throw 'Forbidden host task' }
function Start-ScheduledTask { $script:writeAttempts++;throw 'Forbidden host task start' }
function New-NetFirewallRule { $script:writeAttempts++;throw 'Forbidden host firewall' }
function Set-NetFirewallRule { $script:writeAttempts++;throw 'Forbidden host firewall' }
function Remove-NetFirewallRule { $script:writeAttempts++;throw 'Forbidden host firewall' }
function Get-CimInstance { throw 'A pure predicate must use its observation, not inspect this host.' }
function Start-Sleep { throw 'Unit tests must not wait for a real acceptance interval.' }
$fixtureData=Get-Content -LiteralPath $DataPath -Raw | ConvertFrom-Json
$script:deadline=$null
function Read-Rows([string]$Name) { return @($fixtureData.rows) }
function Wait-Until([scriptblock]$Condition,[int]$Seconds,[string]$Message) {
    $script:deadline=$Seconds
    if(-not (& $Condition)) { throw $Message }
}
$accepted=$false;$failure=$null
try { $null=& ([scriptblock]::Create((Get-Content -LiteralPath $ExpressionPath -Raw)));$accepted=$true }
catch { $failure=$_.Exception.Message }
@{accepted=$accepted;failure=$failure;deadline=$script:deadline;writes=$script:writeAttempts;engine=$PSVersionTable.PSVersion.Major}|ConvertTo-Json -Depth 10 -Compress
"""


def pure(tmp_path, functions, expression, data):
    assert SCRIPT.is_file(), "the catalog guest harness has not been implemented"
    data_path = tmp_path / "observations.json"
    expression_path = tmp_path / "expression.ps1"
    driver = tmp_path / "pure-driver.ps1"
    data_path.write_text(json.dumps(data), encoding="utf-8")
    expression_path.write_text(expression, encoding="utf-8-sig")
    driver.write_text(PURE_DRIVER, encoding="utf-8-sig")
    result = subprocess.run([
        str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(driver), "-Source", str(SCRIPT),
        "-DataPath", str(data_path), "-ExpressionPath", str(expression_path), "-Names", ",".join(functions),
    ], capture_output=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    observed = json.loads(result.stdout.lstrip("\ufeff"))
    assert observed["engine"] == 5 and observed["writes"] == 0, observed
    return observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("corrupt_initial_allow", [False, True])
def test_network_reference_probes_are_isolated_from_catalog_process_termination(package, tmp_path, corrupt_initial_allow):
    _, manifest = package()
    # Execute only the actual orchestration statements between allow and network.
    # All external boundaries are mocks; even the fixture bytes are inert.
    expression = r"""
$main=@($tree.FindAll({param($node)
    $node -is [Management.Automation.Language.TryStatementAst] -and
    $node.Body.Statements.Count -gt 0 -and
    $node.Body.Statements[0].Extent.Text.TrimStart().StartsWith('Assert-ProductionPackage ')
},$true))
if($main.Count -ne 1){throw 'Expected exactly one acceptance body.'}
$statements=@($main[0].Body.Statements)
$starts=@(for($index=0;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text.Contains("Publish-Assignment 'allow'")){$index}
})
$ends=@(for($index=0;$index -lt $statements.Count;$index++){
    if($statements[$index].Extent.Text.Contains("Publish-Assignment 'network'")){$index}
})
if($starts.Count -ne 1 -or $ends.Count -ne 1 -or $ends[0] -le $starts[0]){throw 'Invalid isolated stage boundaries.'}
$selected=@($statements[$starts[0]..($ends[0]-1)])
$allowed=@('Publish-Assignment','Start-Backend','Invoke-Msi','Wait-Ack','Delivery-Evidence','Record-Check','Invoke-Fixture')
foreach($statement in $selected){
    foreach($command in @($statement.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true))){
        if($command.GetCommandName() -notin $allowed){throw 'Unexpected command in isolated stage.'}
    }
    if(@($statement.FindAll({param($node)
        $node -is [Management.Automation.Language.InvokeMemberExpressionAst] -or
        $node -is [Management.Automation.Language.FunctionDefinitionAst]
    },$true)).Count){throw 'Unexpected method or function definition in isolated stage.'}
}
$manifest=$fixtureData.manifest
$a='C:\inert\'+$manifest.fixtures.a.file
$aControl='C:\inert\'+$manifest.fixtures.a.renamed_file
$script:active=$null
$script:referenceCalls=@()
function Publish-Assignment([string]$Name){
    $chosen=$manifest.policies.$Name
    if($Name -ceq 'allow' -and $fixtureData.corrupt_initial_allow){$chosen=$manifest.policies.absent}
    $script:active=$chosen
    return $chosen
}
function Start-Backend { return [pscustomobject]@{State='Running'} }
function Invoke-Msi([bool]$Remove){if($Remove){throw 'Unexpected removal in reference stage.'};return 0}
function Wait-Ack($Assignment){
    if($Assignment.version -ne $script:active.version -or $Assignment.digest -cne $script:active.digest){throw 'Mock assignment ACK mismatch.'}
}
function Delivery-Evidence($Assignment){return @{own_policy_present=$false}}
function Record-Check([string]$Name,$Evidence){if($Name -cne 'absent'){throw 'Unexpected recorded check.'}}
function Invoke-Fixture([string]$Path,[string]$Url){
    if($Url -cne 'https://example.org/'){throw 'Unexpected reference endpoint.'}
    $controls=$script:active.body.app_control
    $blocked=@($controls.blocked) -contains [IO.Path]::GetFileName($Path)
    $script:referenceCalls+=@(@{path=$Path;version=$script:active.version;digest=$script:active.digest
        process_rules=@($controls.blocked).Count;execution_rules=@($controls.execution_rules).Count
        network_rules=@($controls.network_blocked).Count})
    # Model an enforcement tick while the target is alive; no host process starts.
    return @{exit=$(if($blocked){1}else{0});process_created=$true;alive_after_sentinel=(-not $blocked)}
}
. ([scriptblock]::Create(($selected | ForEach-Object {$_.Extent.Text}) -join "`n"))
if($script:referenceCalls.Count -ne 2){throw 'Both reference paths must be observed.'}
if($script:referenceCalls[0].path -cne $a -or $script:referenceCalls[1].path -cne $aControl){throw 'Wrong reference paths.'}
foreach($call in $script:referenceCalls){
    if($call.version -ne $manifest.policies.allow.version -or $call.digest -cne $manifest.policies.allow.digest -or
       $call.process_rules -ne 0 -or $call.execution_rules -ne 0 -or $call.network_rules -ne 0){
        throw 'A reference probe ran while a catalog restriction was active.'
    }
}
"""
    observed = pure(tmp_path, ["Wait-Ack"], expression,
                    {"manifest": manifest, "corrupt_initial_allow": corrupt_initial_allow})
    assert observed["accepted"] is (not corrupt_initial_allow), observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("model,hypervisor,marker,opt_in,accepted", [
    ("VMware20,1", True, "OPENEMS DISPOSABLE USB ACCEPTANCE", True, True),
    ("Dell Physical Workstation", True, "OPENEMS DISPOSABLE USB ACCEPTANCE", True, False),
    ("VMware20,1", False, "OPENEMS DISPOSABLE USB ACCEPTANCE", True, False),
    ("VMware20,1", "false", "OPENEMS DISPOSABLE USB ACCEPTANCE", True, False),
    ("VMware20,1", True, "wrong marker", True, False),
    ("VMware20,1", True, "OPENEMS DISPOSABLE USB ACCEPTANCE", False, False),
])
def test_guest_gate_refuses_physical_or_unattested_targets_without_writes(tmp_path, model, hypervisor, marker, opt_in, accepted):
    data = {"machine": {"Model": model, "HypervisorPresent": hypervisor}, "marker": marker, "opt_in": opt_in}
    observed = pure(tmp_path, ["Assert-DisposableGuest"],
                    "Assert-DisposableGuest $fixtureData.machine $fixtureData.marker ([bool]$fixtureData.opt_in)", data)
    assert observed["accepted"] is accepted, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("code,created,sentinel,accepted", [
    (577, False, False, True), (1260, False, False, True), (4551, False, False, True),
    (4551, True, False, False), (4551, False, True, False), (0, True, False, False),
    (0, False, False, False), (5, False, False, False), (193, False, False, False), (4550, False, False, False),
    (4551, 0, False, False), (4551, False, 0, False),
])
def test_wdac_requires_kernel_refusal_before_process_creation_and_sentinel(tmp_path, code, created, sentinel, accepted):
    observation = {"native_error": code, "process_created": created, "started": sentinel, "exit": -1}
    observed = pure(tmp_path, ["Assert-DeniedExecution"], "Assert-DeniedExecution $fixtureData", observation)
    assert observed["accepted"] is accepted, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("change", ["none", "early_monotonic", "early_utc", "changed_version", "changed_digest",
                                   "hidden_push", "unchanged_checked_at", "forged_checked_at", "no_admission", "kill_instead"])
def test_hourly_recheck_requires_real_time_stable_assignment_and_new_native_denial(tmp_path, change):
    evidence = hourly()
    if change == "early_monotonic":
        evidence["elapsed_seconds"] = 3599.9
    elif change == "early_utc":
        evidence["finished_utc"] = "2026-11-02T16:59:59Z"
    elif change == "changed_version":
        evidence["after"]["version"] += 1
    elif change == "changed_digest":
        evidence["after"]["digest"] = "d" * 64
    elif change == "hidden_push":
        evidence["assignment_observations"].insert(1, {"version": 7, "digest": "d" * 64})
    elif change == "unchanged_checked_at":
        evidence["after"]["optional_checked_at"] = evidence["before"]["optional_checked_at"]
    elif change == "forged_checked_at":
        evidence["before"]["optional_checked_at"] = 0
    elif change == "no_admission":
        evidence["before_admission"]["process_created"] = False
    elif change == "kill_instead":
        evidence["after_denial"] = {"native_error": 0, "process_created": True, "started": False, "exit": -1}
    observed = pure(tmp_path, ["Assert-DeniedExecution", "Assert-HourlyEvidence"],
                    "Assert-HourlyEvidence $fixtureData", evidence)
    assert observed["accepted"] is (change == "none"), observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("change", ["none", "negative", "different_version", "different_digest", "unrelated_success",
                                   "numeric_success", "string_success", "string_version"])
def test_ack_deadline_stays_ninety_seconds_and_only_matching_success_satisfies_it(tmp_path, change):
    assignment = {"version": 6, "digest": "a" * 64}
    ack = {**assignment, "success": True}
    if change == "negative":
        ack["success"] = False
    elif change == "different_version":
        ack["version"] = 7
    elif change == "different_digest":
        ack["digest"] = "b" * 64
    elif change == "unrelated_success":
        ack = {"version": 8, "digest": "b" * 64, "success": True}
    elif change == "numeric_success":
        ack["success"] = 1
    elif change == "string_success":
        ack["success"] = "True"
    elif change == "string_version":
        ack["version"] = "6"
    observed = pure(tmp_path, ["Wait-Ack"], "Wait-Ack $fixtureData.assignment",
                    {"assignment": assignment, "rows": [ack]})
    assert observed["deadline"] == 90 and observed["accepted"] is (change == "none"), observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("change", SEMANTIC_CHANGES)
def test_catalog_acceptance_requires_each_observed_effect_and_normal_clean_removal(builder, package, tmp_path, change):
    output, _ = package()
    manifest = builder.verify_package(output, expected_revision=REVISION)
    report = mutated_report(report_for(manifest), change)
    observed = pure(tmp_path, ["Assert-DeniedExecution", "Assert-HourlyEvidence", "Assert-CatalogEvidence"],
                    "Assert-CatalogEvidence $fixtureData.report $fixtureData.manifest", {"report": report, "manifest": manifest})
    assert observed["accepted"] is (change == "none"), observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("journal_exists,owned_policy_exists", [(False, True), (False, False), (True, True)])
@pytest.mark.parametrize("listed_braces", [False, True])
def test_cached_wdac_identity_is_checked_even_after_removal_deletes_its_journal(
        tmp_path, journal_exists, owned_policy_exists, listed_braces):
    owned = "{11111111-1111-1111-1111-111111111111}"
    foreign = "{22222222-2222-2222-2222-222222222222}"
    listed_owned = owned if listed_braces else owned.strip("{}")
    policies = [{"PolicyID": foreign, "IsEnforced": True}]
    if owned_policy_exists:
        policies.append({"PolicyID": listed_owned, "IsEnforced": True})
    data = {"journal_exists": journal_exists, "journal": {"policy_id": owned},
            "cached_id": owned, "policies": policies, "expected_id": listed_owned if owned_policy_exists else ""}
    expression = r"""
$global:policyProbeData=$fixtureData
$script:journalPath='C:\not-a-real-test-journal.json'
$script:ownPolicyId=$fixtureData.cached_id
function global:Test-Path([string]$LiteralPath) { return [bool]$global:policyProbeData.journal_exists }
function global:Read-Journal { return $global:policyProbeData.journal }
function global:Code-Policies { return @($global:policyProbeData.policies) }
$observed=Own-Policy
$actual=if($null -eq $observed){''}else{[string]$observed.PolicyID}
if($actual -cne $fixtureData.expected_id){throw 'An owned WDAC policy was hidden by a missing journal.'}
"""
    observed = pure(tmp_path, ["Own-Policy"], expression, data)
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
@pytest.mark.parametrize("listed_braces", [False, True])
def test_foreign_wdac_snapshot_excludes_cached_owned_identity_in_either_citool_format(tmp_path, listed_braces):
    owned = "{11111111-1111-1111-1111-111111111111}"
    foreign = "22222222-2222-2222-2222-222222222222"
    data = {"cached_id": owned, "policies": [{"PolicyID": foreign},
            {"PolicyID": owned if listed_braces else owned.strip("{}")}], "expected_foreign": [foreign]}
    expression = r"""
$global:policyProbeData=$fixtureData
$script:ownPolicyId=$fixtureData.cached_id
function global:Code-Policies { return @($global:policyProbeData.policies) }
$observed=@(Foreign-PolicyIds)
if($observed.Count -ne 1 -or $observed[0] -cne $fixtureData.expected_foreign[0]) {
    throw 'The owned WDAC policy was incorrectly classified as foreign.'
}
"""
    observed = pure(tmp_path, ["Foreign-PolicyIds"], expression, data)
    assert observed["accepted"] is True, observed


@WINDOWS[0]
@WINDOWS[1]
def test_harness_parses_and_read_only_plan_does_not_start_controls_or_create_output(tmp_path):
    assert SCRIPT.is_file(), "the catalog guest harness has not been implemented"
    output = tmp_path / "must-not-exist"
    result = subprocess.run([str(POWERSHELL), "-NoProfile", "-NonInteractive", "-File", str(SCRIPT),
                             "-Plan", "-OutputDirectory", str(output)],
                            capture_output=True, encoding="utf-8", timeout=30, check=False)
    assert result.returncode == 0, result.stdout + result.stderr
    plan = json.loads(result.stdout.lstrip("\ufeff"))
    assert plan["phase"] == "catalog" and plan["guest_only"] is True
    assert plan["ack_timeout_seconds"] == 90 and plan["hourly_wait_seconds"] >= 3600
    assert plan["timeout_seconds"] > plan["hourly_wait_seconds"]
    assert plan["executes_controls"] is False and set(plan["required_checks"]) == set(CHECKS)
    assert not output.exists()
